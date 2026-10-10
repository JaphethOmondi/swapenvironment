"""Agent portal: initiate a swap."""

import re

from flask import (
    Blueprint, current_app, redirect, render_template, request, url_for
)
from flask_login import current_user, login_required
from sqlalchemy import select

from ..extensions import db
from ..models import NotificationLog
from ..services import SwapError, create_swap, get_swap, send_consent_nudge
from ..auth import AGENT_ONLY, role_required, sees_all_swaps

bp = Blueprint("agent", __name__)

PHONE_RE = re.compile(r"^0(7|1)\d{8}$")


@bp.route("/agent", methods=["GET", "POST"])
@login_required
@role_required(*AGENT_ONLY)
def portal():
    error = None
    phone = None

    if request.method == "POST":
        phone = (request.form.get("phone") or "").strip()

        # Server-side validation: the prototype relied on the HTML pattern
        # attribute alone, which a direct POST bypasses entirely.
        if not PHONE_RE.match(phone):
            error = "Enter a valid Safaricom number, e.g. 0712345678."
        else:
            try:
                swap, pin = create_swap(phone, current_user)
                send_consent_nudge(swap, pin)
                # POST/redirect/GET so a refresh cannot duplicate the swap.
                return redirect(url_for("agent.initiated", swap_id=swap.id))
            except SwapError as exc:
                error = str(exc)

    return render_template("agent.html", error=error, phone=phone)


@bp.route("/swap/<int:swap_id>/initiated")
@login_required
def initiated(swap_id):
    swap = get_swap(swap_id)
       # 404 (not 403) for someone else's swap so IDs can't be enumerated.
    if not swap or (not sees_all_swaps(current_user) and swap.agent_pk != current_user.id):
        return render_template("404.html"), 404
        return render_template("404.html"), 404

    nudge = db.session.scalar(
        select(NotificationLog)
        .where(NotificationLog.swap_id == swap.id)
        .order_by(NotificationLog.created_at.desc())
        .limit(1)
    )
    return render_template(
        "swap_initiated.html",
        swap=swap,
        nudge=nudge,
        ussd_code=current_app.config["USSD_SERVICE_CODE"],
    )
