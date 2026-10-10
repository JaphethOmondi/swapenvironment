"""Authentication wiring.

Replaces the prototype's agent-ID dropdown, which let any visitor act as
any agent — unacceptable when insider collusion is a documented SIM-swap
attack vector.
"""

from functools import wraps

from flask import abort, request
from flask_login import LoginManager, current_user

from .extensions import db
from .models import Agent, AgentRole
from .services import record_audit

login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.session_protection = "strong"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Agent, int(user_id))


def role_required(*roles):
    """Separation of duties: the person who initiates a swap should not be
    the person who can review or override the audit trail."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if current_user.role not in roles:
                # A denied attempt is itself a fraud signal; keep the evidence.
                record_audit(
                    "ACCESS_DENIED",
                    actor=current_user.agent_code,
                    detail=f"{request.method} {request.path} role={current_user.role.value}",
                )
                db.session.commit()
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


ANALYST_OR_ADMIN= (AgentRole.ANALYST, AgentRole.ADMIN)
AGENT_ONLY = (AgentRole.AGENT,)


def sees_all_swaps(user):
    """Only reviewers get the global view. Agents are scoped to their own."""
    return user.role in ANALYST_OR_ADMIN
