"""Database models.

Replaces the prototype's in-memory `swaps = []`, `SMS_LOG = []` and
`_swap_counter` globals. Those could not survive a restart and actively
broke under more than one worker process, since each worker kept its own
copy of the counter and the list.

Privacy design (Kenya Data Protection Act 2019):
  * `phone_hash` is a keyed HMAC used for equality lookups. It is what we
    index and query on, so the plaintext number never needs to appear in a
    WHERE clause or a query log.
  * `phone_ciphertext` is a Fernet-encrypted copy, decrypted only at the
    moment we need to actually send an SMS.
  * `phone_masked` (0712***678) is what the UI and logs display, so an
    operator with dashboard access never sees full subscriber numbers.
"""

import datetime
import enum
import hashlib
import hmac

from flask import current_app
from flask_login import UserMixin
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    TypeDecorator,
    event,
)
from sqlalchemy.orm import relationship

from .extensions import db


def utcnow():
    """Timezone-aware UTC. Naive datetimes silently compare wrong across
    DST and across servers in different zones, which for a fail-closed
    timeout means either premature blocks or, worse, late ones."""
    return datetime.datetime.now(datetime.timezone.utc)


class UTCDateTime(TypeDecorator):
    """Always hand back timezone-aware UTC datetimes.

    Postgres TIMESTAMPTZ preserves the offset, but SQLite (used for dev and
    tests) silently drops it, so a value written as aware comes back naive.
    Comparing the two raises TypeError — and the place that comparison
    happens is the fail-closed expiry check, which is the last thing that
    should blow up or, worse, be skipped. Normalising here means the rest
    of the codebase can assume aware datetimes everywhere.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.timezone.utc)
        return value.astimezone(datetime.timezone.utc)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=datetime.timezone.utc)
        return value.astimezone(datetime.timezone.utc)


class SwapStatus(enum.Enum):
    PENDING = "PENDING"
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"


class DecisionSource(enum.Enum):
    USSD = "USSD"            # subscriber responded on their handset
    TIMEOUT = "TIMEOUT"      # fail-closed sweep
    PIN_LOCKOUT = "PIN_LOCKOUT"  # too many wrong PIN attempts
    ADMIN = "ADMIN"          # manual fraud-team override


class AgentRole(enum.Enum):
    AGENT = "AGENT"
    ANALYST = "ANALYST"
    ADMIN = "ADMIN"


# ---------------------------------------------------------------------------
# Phone handling
# ---------------------------------------------------------------------------

def hash_phone(phone):
    """Keyed hash for lookups. HMAC (not bare SHA-256) so that an attacker
    who obtains the database cannot brute-force the small Kenyan phone
    number space without also obtaining the pepper."""
    pepper = current_app.config["PHONE_PEPPER"].encode()
    return hmac.new(pepper, phone.encode(), hashlib.sha256).hexdigest()


def mask_phone(phone):
    """0712345678 -> 0712***678. Safe for dashboards, logs and screenshots."""
    if len(phone) < 7:
        return "***"
    return f"{phone[:4]}***{phone[-3:]}"


def _fernet():
    from cryptography.fernet import Fernet

    key = current_app.config.get("PHONE_ENCRYPTION_KEY")
    if not key:
        return None
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt_phone(phone):
    f = _fernet()
    if f is None:
        # Dev fallback only. ProdConfig refuses to boot without a key, so
        # this branch cannot be reached in production.
        return phone
    return f.encrypt(phone.encode()).decode()


def decrypt_phone(ciphertext):
    f = _fernet()
    if f is None:
        return ciphertext
    return f.decrypt(ciphertext.encode()).decode()


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------

class Agent(UserMixin, db.Model):
    """Replaces the hardcoded AGENTS list and the dropdown that let anyone
    act as anyone. Insider fraud is a documented SIM-swap vector, so agent
    identity has to be authenticated, not self-asserted."""

    __tablename__ = "agents"

    id = db.Column(Integer, primary_key=True)
    agent_code = db.Column(String(32), unique=True, nullable=False, index=True)
    display_name = db.Column(String(120), nullable=False)
    password_hash = db.Column(String(255), nullable=False)
    role = db.Column(Enum(AgentRole), nullable=False, default=AgentRole.AGENT)
    is_active = db.Column(Boolean, nullable=False, default=True)
    mfa_secret = db.Column(String(64), nullable=True)
    created_at = db.Column(UTCDateTime, nullable=False, default=utcnow)
    last_login_at = db.Column(UTCDateTime, nullable=True)

    swaps = relationship("Swap", back_populates="agent")

    def set_password(self, raw):
        from werkzeug.security import generate_password_hash

        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        from werkzeug.security import check_password_hash

        return check_password_hash(self.password_hash, raw)

    def __repr__(self):
        return f"<Agent {self.agent_code}>"


class Swap(db.Model):
    __tablename__ = "swaps"

    id = db.Column(Integer, primary_key=True)

    phone_hash = db.Column(String(64), nullable=False)
    phone_ciphertext = db.Column(Text, nullable=False)
    phone_masked = db.Column(String(20), nullable=False)

    agent_pk = db.Column(Integer, ForeignKey("agents.id"), nullable=False)
    agent = relationship("Agent", back_populates="swaps")

    status = db.Column(
        Enum(SwapStatus), nullable=False, default=SwapStatus.PENDING, index=True
    )
    decision_source = db.Column(Enum(DecisionSource), nullable=True)

    created_at = db.Column(UTCDateTime, nullable=False, default=utcnow)
    expires_at = db.Column(UTCDateTime, nullable=False)
    decided_at = db.Column(UTCDateTime, nullable=True)

    auto_expired = db.Column(Boolean, nullable=False, default=False)
    pin_attempts = db.Column(Integer, nullable=False, default=0)
    pin_hash = db.Column(String(255), nullable=True)

    sessions = relationship("ConsentSession", back_populates="swap")

    __table_args__ = (
        # The timeout sweep queries exactly this pair; without the composite
        # index it degrades into a full scan as the table grows.
        Index("ix_swaps_status_expires", "status", "expires_at"),
        # Pending-swap lookup by caller on every USSD callback.
        Index("ix_swaps_phone_status", "phone_hash", "status"),
        CheckConstraint("pin_attempts >= 0", name="ck_swaps_pin_attempts_nonneg"),
    )

    @property
    def is_pending(self):
        return self.status == SwapStatus.PENDING

    @property
    def seconds_left(self):
        if not self.is_pending:
            return 0
        delta = (self.expires_at - utcnow()).total_seconds()
        return max(0, int(delta))

    def phone_plaintext(self):
        """Decrypt on demand. Call this only where the real number is
        genuinely needed (sending an SMS) — never for display."""
        return decrypt_phone(self.phone_ciphertext)

    def __repr__(self):
        return f"<Swap {self.id} {self.phone_masked} {self.status.value}>"


class ConsentSession(db.Model):
    """One row per USSD session. The unique constraint on session_id is what
    makes retried Africa's Talking callbacks idempotent: a retry maps to the
    same session rather than starting a second, parallel consent flow."""

    __tablename__ = "consent_sessions"

    id = db.Column(Integer, primary_key=True)
    session_id = db.Column(String(128), unique=True, nullable=False, index=True)
    swap_id = db.Column(Integer, ForeignKey("swaps.id"), nullable=False)
    swap = relationship("Swap", back_populates="sessions")

    channel = db.Column(String(16), nullable=False, default="USSD")
    created_at = db.Column(UTCDateTime, nullable=False, default=utcnow)
    last_seen_at = db.Column(UTCDateTime, nullable=False, default=utcnow)


class NotificationLog(db.Model):
    """Replaces the in-memory SMS_LOG. Stores the masked number and whether
    the send was real or simulated; never stores the PIN."""

    __tablename__ = "notification_log"

    id = db.Column(Integer, primary_key=True)
    swap_id = db.Column(Integer, ForeignKey("swaps.id"), nullable=True)
    phone_masked = db.Column(String(20), nullable=False)
    channel = db.Column(String(16), nullable=False, default="SMS")
    body = db.Column(Text, nullable=False)
    simulated = db.Column(Boolean, nullable=False, default=True)
    error = db.Column(Text, nullable=True)
    created_at = db.Column(UTCDateTime, nullable=False, default=utcnow)


class AuditEvent(db.Model):
    """Append-only. This table is the evidentiary record behind the
    'documented reasonable steps' argument in the pitch — if a row can be
    edited or deleted after the fact, it is not evidence. Updates and
    deletes are blocked at the ORM level below, and by a database trigger
    in the Postgres migration."""

    __tablename__ = "audit_events"

    id = db.Column(Integer, primary_key=True)
    swap_id = db.Column(Integer, ForeignKey("swaps.id"), nullable=True, index=True)
    event_type = db.Column(String(48), nullable=False, index=True)
    actor = db.Column(String(64), nullable=False)  # agent_code, 'subscriber', 'system'
    detail = db.Column(Text, nullable=True)
    created_at = db.Column(
        UTCDateTime, nullable=False, default=utcnow, index=True
    )

    def __repr__(self):
        return f"<AuditEvent {self.event_type} swap={self.swap_id}>"


@event.listens_for(AuditEvent, "before_update", propagate=True)
def _block_audit_update(mapper, connection, target):
    raise RuntimeError(
        "audit_events is append-only: updating an audit row would destroy the "
        "evidentiary value of the log."
    )


@event.listens_for(AuditEvent, "before_delete", propagate=True)
def _block_audit_delete(mapper, connection, target):
    raise RuntimeError(
        "audit_events is append-only: deleting an audit row would destroy the "
        "evidentiary value of the log."
    )
