"""Business logic.

All state transitions live here, so there is exactly one code path that can
move a swap out of PENDING regardless of whether the trigger was a real
Africa's Talking callback, the browser simulator, the timeout sweep, or a
fraud-team override.
"""

import datetime
import logging
import secrets

from flask import current_app
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .extensions import db
from .models import (
    AuditEvent,
    ConsentSession,
    DecisionSource,
    NotificationLog,
    Swap,
    SwapStatus,
    encrypt_phone,
    hash_phone,
    mask_phone,
    utcnow,
)

log = logging.getLogger(__name__)


class SwapError(Exception):
    """Raised for policy violations (rate limits, invalid state)."""


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def record_audit(event_type, actor, swap_id=None, detail=None):
    """Append an audit row. Never flushed on its own — the caller commits,
    so the audit row and the state change it describes land in the same
    transaction or neither does."""
    db.session.add(
        AuditEvent(
            swap_id=swap_id, event_type=event_type, actor=actor, detail=detail
        )
    )


# ---------------------------------------------------------------------------
# Creating swaps
# ---------------------------------------------------------------------------

def check_agent_rate_limit(agent):
    """A bribed or compromised agent spamming swap requests is itself a
    fraud signal. Cap it, and record the breach rather than failing
    silently."""
    limit = current_app.config["AGENT_SWAP_RATE_LIMIT"]
    window = current_app.config["AGENT_SWAP_RATE_WINDOW_SECONDS"]
    since = utcnow() - datetime.timedelta(seconds=window)

    recent = db.session.scalar(
        select(db.func.count(Swap.id)).where(
            Swap.agent_pk == agent.id, Swap.created_at >= since
        )
    )
    if recent >= limit:
        record_audit(
            "RATE_LIMIT_EXCEEDED",
            actor=agent.agent_code,
            detail=f"{recent} swaps in the last {window}s (limit {limit})",
        )
        db.session.commit()
        raise SwapError(
            "This agent has exceeded the permitted swap-request rate. "
            "The attempt has been logged for fraud review."
        )


def generate_pin():
    """Cryptographically random 4-digit PIN.

    NOTE: in a real deployment SwapGuard would verify the subscriber's
    EXISTING line PIN via the telco, not mint one. A PIN issued by us and
    delivered over the same SMS channel an attacker may already control
    adds little. This exists so the prototype can demonstrate the second
    factor end to end; see docs for the production replacement.
    """
    return f"{secrets.randbelow(10000):04d}"


def create_swap(phone, agent, pin=None):
    """Create a PENDING swap. Never auto-approves."""
    check_agent_rate_limit(agent)

    from werkzeug.security import generate_password_hash

    pin = pin or generate_pin()
    timeout = current_app.config["CONSENT_TIMEOUT_SECONDS"]
    now = utcnow()

    swap = Swap(
        phone_hash=hash_phone(phone),
        phone_ciphertext=encrypt_phone(phone),
        phone_masked=mask_phone(phone),
        agent_pk=agent.id,
        status=SwapStatus.PENDING,
        created_at=now,
        expires_at=now + datetime.timedelta(seconds=timeout),
        pin_hash=generate_password_hash(pin),
    )
    db.session.add(swap)
    db.session.flush()  # assign swap.id before the audit row references it

    record_audit(
        "SWAP_INITIATED",
        actor=agent.agent_code,
        swap_id=swap.id,
        detail=f"phone={swap.phone_masked} timeout={timeout}s",
    )
    db.session.commit()
    return swap, pin


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------

def find_pending_swap_for_phone(phone):
    expire_stale_swaps()
    return db.session.scalar(
        select(Swap)
        .where(Swap.phone_hash == hash_phone(phone), Swap.status == SwapStatus.PENDING)
        .order_by(Swap.created_at.desc())
        .limit(1)
    )


def get_swap(swap_id):
    expire_stale_swaps()
    return db.session.get(Swap, swap_id)


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------

def apply_decision(swap, decision, source, actor):
    """Single source of truth for leaving PENDING.

    Returns True if this call changed state, False if the swap had already
    been decided — which is what makes retried callbacks safe.
    """
    if swap.status != SwapStatus.PENDING:
        return False

    swap.status = SwapStatus.ALLOWED if decision == "allow" else SwapStatus.BLOCKED
    swap.decision_source = source
    swap.decided_at = utcnow()

    record_audit(
        f"SWAP_{swap.status.value}",
        actor=actor,
        swap_id=swap.id,
        detail=f"source={source.value}",
    )
    db.session.commit()
    return True


def verify_pin(swap, candidate, actor="subscriber"):
    """Check a PIN attempt. On too many failures the swap fails CLOSED.

    Returns (ok: bool, locked_out: bool).
    """
    from werkzeug.security import check_password_hash

    if swap.status != SwapStatus.PENDING:
        return False, False

    if swap.pin_hash and check_password_hash(swap.pin_hash, candidate):
        record_audit("PIN_VERIFIED", actor=actor, swap_id=swap.id)
        db.session.commit()
        return True, False

    swap.pin_attempts += 1
    max_attempts = current_app.config["MAX_PIN_ATTEMPTS"]
    record_audit(
        "PIN_FAILED",
        actor=actor,
        swap_id=swap.id,
        detail=f"attempt {swap.pin_attempts}/{max_attempts}",
    )

    if swap.pin_attempts >= max_attempts:
        swap.status = SwapStatus.BLOCKED
        swap.decision_source = DecisionSource.PIN_LOCKOUT
        swap.decided_at = utcnow()
        record_audit("SWAP_BLOCKED", actor="system", swap_id=swap.id,
                     detail="PIN attempt limit exceeded")
        db.session.commit()
        return False, True

    db.session.commit()
    return False, False


# ---------------------------------------------------------------------------
# Fail-closed timeout sweep
# ---------------------------------------------------------------------------

def expire_stale_swaps():
    """Auto-BLOCK every PENDING swap whose consent window has lapsed.

    Two things changed from the prototype:

    1. The query is indexed and bounded (status + expires_at) instead of
       iterating every swap ever created.
    2. Rows are locked with FOR UPDATE SKIP LOCKED on Postgres, so the
       scheduled worker and a concurrent web request can never both decide
       the same swap and write two conflicting audit trails.

    Still safe to call from read paths, but the scheduled job in tasks.py
    is what guarantees it runs even when nobody is browsing — the
    prototype's version only fired on page load, so an expired swap could
    sit PENDING indefinitely on a quiet night.
    """
    now = utcnow()
    stmt = select(Swap).where(
        Swap.status == SwapStatus.PENDING, Swap.expires_at <= now
    )

    # SQLite (dev/test) has no SKIP LOCKED; it serialises writes anyway.
    if db.session.bind and db.session.bind.dialect.name == "postgresql":
        stmt = stmt.with_for_update(skip_locked=True)

    stale = db.session.scalars(stmt).all()
    if not stale:
        return 0

    for swap in stale:
        swap.status = SwapStatus.BLOCKED
        swap.decision_source = DecisionSource.TIMEOUT
        swap.decided_at = now
        swap.auto_expired = True
        record_audit(
            "SWAP_BLOCKED",
            actor="system",
            swap_id=swap.id,
            detail="consent window elapsed with no response (fail-closed)",
        )

    db.session.commit()
    log.info("fail-closed sweep blocked %d expired swap(s)", len(stale))
    return len(stale)


# ---------------------------------------------------------------------------
# Sessions (idempotency)
# ---------------------------------------------------------------------------

def touch_session(session_id, swap, channel="USSD"):
    """Record or refresh a USSD session. The unique constraint on
    session_id means a retried callback reuses the existing row instead of
    forking a second consent flow."""
    existing = db.session.scalar(
        select(ConsentSession).where(ConsentSession.session_id == session_id)
    )
    if existing:
        existing.last_seen_at = utcnow()
        db.session.commit()
        return existing

    cs = ConsentSession(session_id=session_id, swap_id=swap.id, channel=channel)
    db.session.add(cs)
    try:
        db.session.commit()
    except IntegrityError:
        # Concurrent duplicate callback won the race; fall back to its row.
        db.session.rollback()
        return db.session.scalar(
            select(ConsentSession).where(ConsentSession.session_id == session_id)
        )
    return cs


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

def send_consent_nudge(swap, pin):
    """Tell the subscriber a swap is pending and how to respond.

    The PIN is included ONLY when running in simulated mode, so the demo is
    self-contained. With real credentials configured the PIN is never sent
    over SMS — that would hand the second factor to anyone who has already
    compromised the channel.
    """
    code = current_app.config["USSD_SERVICE_CODE"]
    timeout = current_app.config["CONSENT_TIMEOUT_SECONDS"]
    api_key = current_app.config.get("AT_API_KEY")
    simulated = not bool(api_key)

    body = (
        f"SwapGuard: a SIM swap was requested on your line by agent "
        f"{swap.agent.agent_code}. Dial {code} to allow or block it. "
        f"No response within {timeout}s blocks it automatically."
    )
    if simulated:
        body += f" [DEMO ONLY — PIN {pin}; never sent by SMS in production]"

    entry = NotificationLog(
        swap_id=swap.id,
        phone_masked=swap.phone_masked,
        channel="SMS",
        body=body,
        simulated=simulated,
    )

    if not simulated:
        try:
            import africastalking

            africastalking.initialize(current_app.config["AT_USERNAME"], api_key)
            africastalking.SMS.send(body, [_to_e164(swap.phone_plaintext())])
        except Exception as exc:  # noqa: BLE001 - surfaced to the operator
            entry.error = str(exc)
            log.exception("SMS nudge failed for swap %s", swap.id)

    db.session.add(entry)
    record_audit(
        "NUDGE_SENT",
        actor="system",
        swap_id=swap.id,
        detail=f"simulated={simulated}",
    )
    db.session.commit()
    return entry


def _to_e164(local_phone):
    return f"+254{local_phone.lstrip('0')}"


def to_local(at_phone):
    """+254712345678 / 254712345678 -> 0712345678."""
    digits = (at_phone or "").lstrip("+")
    if digits.startswith("254") and len(digits) == 12:
        return "0" + digits[3:]
    return at_phone


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def compute_stats(agent=None):
    """Pass `agent` to scope every number to that agent's own swaps."""
    expire_stale_swaps()
    q = select(Swap.status, db.func.count(Swap.id))
    if agent is not None:
        q = q.where(Swap.agent_pk == agent.id)
    counts = dict(db.session.execute(q.group_by(Swap.status)).all())
    allowed = counts.get(SwapStatus.ALLOWED, 0)
    blocked = counts.get(SwapStatus.BLOCKED, 0)
    pending = counts.get(SwapStatus.PENDING, 0)
    total = allowed + blocked + pending

    t_q = select(db.func.count(Swap.id)).where(Swap.auto_expired.is_(True))
    if agent is not None:
        t_q = t_q.where(Swap.agent_pk == agent.id)
    timed_out = db.session.scalar(t_q) or 0

    return {
        "total": total,
        "pending": pending,
        "allowed": allowed,
        "blocked": blocked,
        "timed_out": timed_out,
        "approval_rate": round(allowed / total * 100) if total else 0,
        "block_rate": round(blocked / total * 100) if total else 0,
        # False-block rate needs ground truth we don't have in a prototype,
        # but the metric is stubbed here because it is the number that
        # decides whether this control is deployable at national scale.
        "timeout_share": round(timed_out / total * 100) if total else 0,
    }
