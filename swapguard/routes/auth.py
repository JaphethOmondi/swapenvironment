"""Login / logout."""

from flask import Blueprint, redirect, render_template, request, url_for
from flask_login import login_required, login_user, logout_user
from sqlalchemy import select

from ..extensions import db
from ..models import Agent, utcnow
from ..services import record_audit

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        code = (request.form.get("agent_code") or "").strip()
        password = request.form.get("password") or ""

        agent = db.session.scalar(select(Agent).where(Agent.agent_code == code))

        # Same message and same work for unknown-agent and wrong-password so
        # the form cannot be used to enumerate valid agent codes.
        if agent and agent.is_active and agent.check_password(password):
            login_user(agent)
            agent.last_login_at = utcnow()
            record_audit("AGENT_LOGIN", actor=agent.agent_code)
            db.session.commit()
            return redirect(request.args.get("next") or url_for("main.home"))

        if agent:
            record_audit("AGENT_LOGIN_FAILED", actor=code)
            db.session.commit()
        error = "Invalid agent code or password."

    return render_template("login.html", error=error)


@bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))
