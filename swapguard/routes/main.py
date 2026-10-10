"""Home and audit dashboard."""

from flask import Blueprint, render_template
from flask_login import login_required
from sqlalchemy import select
from flask_login import current_user

from ..auth import ANALYST_OR_ADMIN, role_required, sees_all_swaps
from ..extensions import db
from ..models import AuditEvent, Swap
from ..services import compute_stats

bp = Blueprint("main", __name__)


@bp.route("/")
@login_required
def home():
    scope = None if sees_all_swaps(current_user) else current_user
    return render_template("home.html", stats=compute_stats(scope))


@bp.route("/dashboard")
@login_required
def dashboard():
    scope = None if sees_all_swaps(current_user) else current_user
    stats = compute_stats(scope)
    q = select(Swap).order_by(Swap.created_at.desc()).limit(50)
    if scope is not None:
        q = q.where(Swap.agent_pk == scope.id)
    swaps = db.session.scalars(q).all()
    return render_template("dashboard.html", stats=stats, swaps=swaps)

@bp.route("/audit")
@login_required
@role_required(*ANALYST_OR_ADMIN)
def audit():
    """Full append-only audit trail. Restricted to analysts and admins:
    the agent who initiates swaps should not also be the person reviewing
    the record of them."""
    events = db.session.scalars(
        select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(200)
    ).all()
    return render_template("audit.html", events=events)
