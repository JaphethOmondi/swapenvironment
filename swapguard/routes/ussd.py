"""Africa's Talking USSD callback, plus a browser simulator for demos.

Menu flow (AT sends the full accumulated keypress string in `text`):

    ""        -> show Allow / Block menu
    "1"       -> chose Allow  -> prompt for PIN
    "2"       -> chose Block  -> prompt for PIN
    "1*1234"  -> verify PIN, then apply the decision

The PIN step means possession of the handset that dialled in is not, by
itself, enough to approve a swap.
"""

import ipaddress
import logging

from flask import Blueprint, abort, current_app, render_template, request
from flask_login import login_required
from ..auth import ANALYST_OR_ADMIN, role_required 

from ..services import (
    DecisionSource,
    apply_decision,
    find_pending_swap_for_phone,
    get_swap,
    to_local,
    touch_session,
    verify_pin,
)

bp = Blueprint("ussd", __name__)
log = logging.getLogger(__name__)


def _client_ip():
    """Behind a reverse proxy the real client is the first X-Forwarded-For
    entry. Only trust this header if your proxy overwrites it — otherwise a
    caller can forge it."""
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or ""


def _verify_source():
    """Allowlist Africa's Talking callback IPs.

    The prototype's /ussd endpoint trusted any POST, which meant anyone who
    found the URL could forge a subscriber decision — including an ALLOW.
    An empty allowlist disables the check for local development only.
    """
    raw = (current_app.config.get("AT_ALLOWED_IPS") or "").strip()
    if not raw:
        if not current_app.debug and not current_app.testing:
            log.warning("AT_ALLOWED_IPS is empty in a non-debug environment; "
                        "the USSD callback is unauthenticated.")
        return

    client = _client_ip()
    try:
        addr = ipaddress.ip_address(client)
    except ValueError:
        abort(403)

    for net in raw.split(","):
        net = net.strip()
        if not net:
            continue
        try:
            if addr in ipaddress.ip_network(net, strict=False):
                return
        except ValueError:
            continue

    log.warning("rejected USSD callback from unauthorised IP %s", client)
    abort(403)


def _handle(session_id, phone, text):
    """Pure menu logic, shared by the real callback and the simulator so
    there is only one implementation to reason about or get wrong."""
    steps = [s for s in text.split("*")] if text else []

    swap = find_pending_swap_for_phone(phone)
    if not swap:
        return "END No pending SIM swap request was found for this number."

    touch_session(session_id, swap)

    # Step 0 — present the decision.
    if not steps:
        return (
            f"CON A SIM swap was requested on your line by agent "
            f"{swap.agent.agent_code} at "
            f"{swap.created_at.strftime('%Y-%m-%d %H:%M')}.\n"
            f"If this was not you, choose Block.\n"
            f"1. Allow this swap\n"
            f"2. Block and report fraud"
        )

    choice = steps[0].strip()
    if choice not in ("1", "2"):
        return "END Invalid selection. Dial in again and choose 1 or 2."

    # Step 1 — decision captured, now require the PIN.
    if len(steps) == 1:
        action = "ALLOW" if choice == "1" else "BLOCK"
        remaining = current_app.config["MAX_PIN_ATTEMPTS"] - swap.pin_attempts
        return (
            f"CON To confirm {action}, enter your 4-digit SwapGuard PIN.\n"
            f"({remaining} attempt(s) remaining — the request is blocked if "
            f"they run out.)"
        )

    # Step 2 — verify the PIN and commit the decision.
    if len(steps) == 2:
        pin = steps[1].strip()
        ok, locked_out = verify_pin(swap, pin)

        if locked_out:
            return ("END Too many incorrect PIN attempts. This SIM swap has "
                    "been BLOCKED and flagged for review.")
        if not ok:
            remaining = current_app.config["MAX_PIN_ATTEMPTS"] - swap.pin_attempts
            return (f"END Incorrect PIN. {remaining} attempt(s) remaining. "
                    f"Dial {current_app.config['USSD_SERVICE_CODE']} to retry.")

        decision = "allow" if choice == "1" else "block"
        changed = apply_decision(
            swap, decision, source=DecisionSource.USSD, actor="subscriber"
        )
        if not changed:
            # Retry or double-dial after the swap was already resolved.
            return "END This request has already been resolved."

        if decision == "allow":
            return ("END This SIM swap has been ALLOWED. If this was not you, "
                    "contact Safaricom immediately.")
        return "END This SIM swap has been BLOCKED and reported as fraud."

    return "END Session error. Please dial in again."


@bp.route("/ussd", methods=["POST"])
def callback():
    _verify_source()
    session_id = request.form.get("sessionId", "")
    # NOTE: phoneNumber comes from the gateway, not the caller, but it is
    # still only used to look up an EXISTING pending swap — it can never
    # create authority on its own.
    phone = to_local(request.form.get("phoneNumber", ""))
    text = (request.form.get("text") or "").strip()

    body = _handle(session_id, phone, text)
    return body, 200, {"Content-Type": "text/plain"}


@bp.route("/ussd-sim/<int:swap_id>")
@login_required
@role_required(*ANALYST_OR_ADMIN)
def simulator(swap_id):
    swap = get_swap(swap_id)
    if not swap:
        return render_template("404.html"), 404
    return render_template(
        "ussd_sim.html",
        swap=swap,
        ussd_code=current_app.config["USSD_SERVICE_CODE"],
    )


@bp.route("/ussd-sim/<int:swap_id>/step", methods=["POST"])
@login_required
@role_required(*ANALYST_OR_ADMIN)
def simulator_step(swap_id):
    """Drives the same _handle() the real gateway hits, using the swap's own
    number as the caller ID — so the demo exercises production logic rather
    than a parallel mock that can drift out of sync."""
    swap = get_swap(swap_id)
    if not swap:
        abort(404)
    text = request.form.get("text", "")
    body = _handle(f"sim-{swap_id}", swap.phone_plaintext(), text)
    return body, 200, {"Content-Type": "text/plain"}
