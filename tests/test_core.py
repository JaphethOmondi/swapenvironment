"""Tests for the behaviours that must never regress.

These exist because every one of them is a claim the pitch deck makes to a
board. If a test here fails, a slide is now false.
"""

import datetime

import pytest
from cryptography.fernet import Fernet

from swapguard import create_app
from swapguard.extensions import db
from swapguard.models import (
    Agent,
    AgentRole,
    AuditEvent,
    DecisionSource,
    Swap,
    SwapStatus,
    utcnow,
)
from swapguard.services import (
    apply_decision,
    create_swap,
    expire_stale_swaps,
    find_pending_swap_for_phone,
    send_consent_nudge,
    verify_pin,
)


@pytest.fixture
def app():
    app = create_app("testing")
    app.config["PHONE_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
    app.config["PHONE_PEPPER"] = "test-pepper"
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def agent(app):
    a = Agent(agent_code="AG007", display_name="Test Agent", role=AgentRole.AGENT)
    a.set_password("pw")
    db.session.add(a)
    db.session.commit()
    return a


# ---------------------------------------------------------------------------
# Persistence — the whole point of this refactor
# ---------------------------------------------------------------------------

def test_swap_persists_to_database(app, agent):
    swap, pin = create_swap("0712345678", agent)
    assert swap.id is not None
    # Re-query rather than reusing the object, proving it is really stored.
    fetched = db.session.get(Swap, swap.id)
    assert fetched.status == SwapStatus.PENDING
    assert fetched.agent.agent_code == "AG007"


def test_phone_is_never_stored_in_plaintext(app, agent):
    swap, _ = create_swap("0712345678", agent)
    row = db.session.execute(
        db.text("SELECT phone_ciphertext, phone_masked, phone_hash FROM swaps WHERE id=:i"),
        {"i": swap.id},
    ).one()
    ciphertext, masked, phash = row
    assert "0712345678" not in ciphertext
    assert masked == "0712***678"
    assert "0712345678" not in phash
    # But it must still round-trip for sending the SMS.
    assert swap.phone_plaintext() == "0712345678"


def test_lookup_by_phone_works_without_plaintext_query(app, agent):
    create_swap("0712345678", agent)
    found = find_pending_swap_for_phone("0712345678")
    assert found is not None
    assert find_pending_swap_for_phone("0799999999") is None


# ---------------------------------------------------------------------------
# Fail-closed policy
# ---------------------------------------------------------------------------

def test_expired_swap_fails_closed_to_blocked(app, agent):
    swap, _ = create_swap("0712345678", agent)
    swap.expires_at = utcnow() - datetime.timedelta(seconds=1)
    db.session.commit()

    n = expire_stale_swaps()
    assert n == 1

    db.session.refresh(swap)
    assert swap.status == SwapStatus.BLOCKED
    assert swap.auto_expired is True
    assert swap.decision_source == DecisionSource.TIMEOUT


def test_timeout_never_results_in_allowed(app, agent):
    """The single most important invariant in the system."""
    for _ in range(20):
        swap, _ = create_swap("0712345678", agent)
        swap.expires_at = utcnow() - datetime.timedelta(seconds=1)
        db.session.commit()
        expire_stale_swaps()
        db.session.refresh(swap)
        assert swap.status != SwapStatus.ALLOWED


def test_sweep_is_idempotent(app, agent):
    swap, _ = create_swap("0712345678", agent)
    swap.expires_at = utcnow() - datetime.timedelta(seconds=1)
    db.session.commit()

    assert expire_stale_swaps() == 1
    assert expire_stale_swaps() == 0  # nothing left to do


# ---------------------------------------------------------------------------
# Decision state machine
# ---------------------------------------------------------------------------

def test_decision_is_idempotent(app, agent):
    swap, _ = create_swap("0712345678", agent)
    assert apply_decision(swap, "block", DecisionSource.USSD, "subscriber") is True
    # A retried Africa's Talking callback must not re-decide.
    assert apply_decision(swap, "allow", DecisionSource.USSD, "subscriber") is False
    db.session.refresh(swap)
    assert swap.status == SwapStatus.BLOCKED


def test_decided_swap_cannot_be_reopened(app, agent):
    swap, _ = create_swap("0712345678", agent)
    apply_decision(swap, "allow", DecisionSource.USSD, "subscriber")
    swap.expires_at = utcnow() - datetime.timedelta(seconds=1)
    db.session.commit()
    expire_stale_swaps()
    db.session.refresh(swap)
    # The timeout sweep must not touch an already-decided swap.
    assert swap.status == SwapStatus.ALLOWED


# ---------------------------------------------------------------------------
# PIN second factor
# ---------------------------------------------------------------------------

def test_correct_pin_verifies(app, agent):
    swap, pin = create_swap("0712345678", agent)
    ok, locked = verify_pin(swap, pin)
    assert ok is True and locked is False


def test_pin_lockout_fails_closed(app, agent):
    swap, pin = create_swap("0712345678", agent)
    wrong = "0000" if pin != "0000" else "1111"

    for _ in range(app.config["MAX_PIN_ATTEMPTS"] - 1):
        ok, locked = verify_pin(swap, wrong)
        assert ok is False and locked is False

    ok, locked = verify_pin(swap, wrong)
    assert ok is False and locked is True

    db.session.refresh(swap)
    assert swap.status == SwapStatus.BLOCKED
    assert swap.decision_source == DecisionSource.PIN_LOCKOUT


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------

def test_audit_row_written_for_every_transition(app, agent):
    swap, _ = create_swap("0712345678", agent)
    apply_decision(swap, "block", DecisionSource.USSD, "subscriber")

    types = [
        e.event_type
        for e in db.session.scalars(
            db.select(AuditEvent).where(AuditEvent.swap_id == swap.id)
        )
    ]
    assert "SWAP_INITIATED" in types
    assert "SWAP_BLOCKED" in types


def test_audit_events_cannot_be_updated(app, agent):
    create_swap("0712345678", agent)
    event = db.session.scalars(db.select(AuditEvent).limit(1)).one()
    event.actor = "tampered"
    with pytest.raises(RuntimeError, match="append-only"):
        db.session.commit()
    db.session.rollback()


def test_audit_events_cannot_be_deleted(app, agent):
    create_swap("0712345678", agent)
    event = db.session.scalars(db.select(AuditEvent).limit(1)).one()
    db.session.delete(event)
    with pytest.raises(RuntimeError, match="append-only"):
        db.session.commit()
    db.session.rollback()


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def test_agent_rate_limit_enforced(app, agent):
    from swapguard.services import SwapError

    app.config["AGENT_SWAP_RATE_LIMIT"] = 3
    for _ in range(3):
        create_swap("0712345678", agent)

    with pytest.raises(SwapError, match="rate"):
        create_swap("0712345678", agent)

    # The breach itself must be recorded for fraud review.
    types = [e.event_type for e in db.session.scalars(db.select(AuditEvent))]
    assert "RATE_LIMIT_EXCEEDED" in types


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

def test_simulated_nudge_records_masked_number_only(app, agent):
    swap, pin = create_swap("0712345678", agent)
    entry = send_consent_nudge(swap, pin)
    assert entry.simulated is True
    assert entry.phone_masked == "0712***678"
    assert "0712345678" not in entry.body


def test_pin_not_sent_when_real_sms_configured(app, agent):
    app.config["AT_API_KEY"] = "fake-key-to-force-real-path"
    swap, pin = create_swap("0712345678", agent)
    entry = send_consent_nudge(swap, pin)
    # Send will fail (no real SDK creds) but the body must never carry the PIN.
    assert pin not in entry.body
    assert "DEMO ONLY" not in entry.body


# ---------------------------------------------------------------------------
# Timezone handling (regression)
# ---------------------------------------------------------------------------

def test_datetimes_are_timezone_aware_after_reload(app, agent):
    """Regression: SQLite drops tzinfo on write, so a value stored as aware
    came back naive and every comparison against utcnow() raised TypeError —
    including the fail-closed expiry check. UTCDateTime normalises on read."""
    swap, _ = create_swap("0712345678", agent)
    swap_id = swap.id
    db.session.expunge_all()  # force a genuine reload from storage

    reloaded = db.session.get(Swap, swap_id)
    assert reloaded.expires_at.tzinfo is not None
    assert reloaded.created_at.tzinfo is not None
    # The property that actually broke in the browser.
    assert isinstance(reloaded.seconds_left, int)
    assert reloaded.seconds_left > 0
# ---------------------------------------------------------------------------
# Role-based access control
# ---------------------------------------------------------------------------

def _make(code, role):
    a = Agent(agent_code=code, display_name=code, role=role)
    a.set_password("pw")
    db.session.add(a)
    db.session.commit()
    return a


def _login(client, code):
    return client.post("/login", data={"agent_code": code, "password": "pw"})


@pytest.fixture
def rbac(app):
    ag1 = _make("AG1", AgentRole.AGENT)
    ag2 = _make("AG2", AgentRole.AGENT)
    an = _make("AN1", AgentRole.ANALYST)
    ad = _make("AD1", AgentRole.ADMIN)
    s1, _ = create_swap("0712345678", ag1)
    s2, _ = create_swap("0722345678", ag2)
    return dict(ag1=ag1, ag2=ag2, an=an, ad=ad, s1=s1.id, s2=s2.id)


def test_agent_can_initiate_but_analyst_and_admin_cannot(app, rbac):
    for code, expected in (("AG1", 302), ("AN1", 403), ("AD1", 403)):
        c = app.test_client()
        _login(c, code)
        r = c.post("/agent", data={"phone": "0733345678"})
        assert r.status_code == expected, code


def test_agent_sees_only_own_swaps(app, rbac):
    c = app.test_client()
    _login(c, "AG1")
    html = c.get("/dashboard").get_data(as_text=True)
    assert "0712***678" in html and "0722***678" not in html
    assert c.get(f"/swap/{rbac['s1']}/initiated").status_code == 200
    assert c.get(f"/swap/{rbac['s2']}/initiated").status_code == 404


def test_analyst_and_admin_see_all_swaps(app, rbac):
    for code in ("AN1", "AD1"):
        c = app.test_client()
        _login(c, code)
        html = c.get("/dashboard").get_data(as_text=True)
        assert "0712***678" in html and "0722***678" in html
        assert c.get(f"/swap/{rbac['s2']}/initiated").status_code == 200


def test_agent_stats_are_scoped(app, rbac):
    from swapguard.services import compute_stats
    assert compute_stats(rbac["ag1"])["total"] == 1
    assert compute_stats()["total"] == 2


def test_agent_cannot_use_simulator_or_audit(app, rbac):
    c = app.test_client()
    _login(c, "AG1")
    assert c.get(f"/ussd-sim/{rbac['s1']}").status_code == 403
    assert c.post(f"/ussd-sim/{rbac['s1']}/step", data={"text": ""}).status_code == 403
    assert c.get("/audit").status_code == 403


def test_denied_access_is_audited(app, rbac):
    c = app.test_client()
    _login(c, "AN1")
    c.post("/agent", data={"phone": "0733345678"})
    ev = db.session.query(AuditEvent).filter_by(event_type="ACCESS_DENIED").one()
    assert ev.actor == "AN1"
