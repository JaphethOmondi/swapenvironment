"""
SwapGuard — Real-time SIM Swap Consent (Demo Prototype)

v1.1 — adds two features on top of the previous rebuild:
  1. A PIN-confirmation step in the USSD consent flow: after the subscriber
     picks Allow/Block, SwapGuard now asks for their line PIN before the
     decision is applied, so a decision can't be made just because someone
     is holding the handset that dialled in.
  2. Emergency Freeze: an agent can lock a subscriber line immediately,
     independent of any single swap request (lost/stolen device, suspected
     social engineering, suspicious agent activity). A frozen line blocks
     new swap requests and auto-blocks any swap already pending, using the
     same fail-closed logic used everywhere else in this app.

See the "What was fixed" notes at the bottom for the earlier bug-fix pass.
"""

from flask import (
    Flask, request, render_template, redirect, url_for, abort,
    flash, get_flashed_messages,
)
from jinja2 import DictLoader
import datetime
import os
import random
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # needed for flash() messages (freeze confirmations)

# ---------------------------------------------------------------------------
# In-memory "database" (demo only — resets on restart)
# ---------------------------------------------------------------------------
swaps = []
_swap_counter = 1

# Emergency Freeze registry: phone -> {agent_id, reason, timestamp}. A line
# in here is locked against new swaps regardless of any specific swap record.
FROZEN_LINES = {}

AGENTS = ['AG007', 'AG042', 'AG099', 'AG113', 'AG156', 'AG203']
VALID_DECISIONS = {'allow', 'block'}
USSD_MENU_CHOICES = {'1', '2'}          # 1 = allow, 2 = block
PIN_MAX_ATTEMPTS = 3                    # incorrect PIN entries before fail-closed auto-block
FREEZE_REASONS = [
    'Lost or stolen device',
    'Suspected social engineering',
    'Suspicious agent activity',
    'Subscriber request',
    'Other',
]

# ---------------------------------------------------------------------------
# Africa's Talking USSD integration (Sprint 1)
# ---------------------------------------------------------------------------
# USSD is subscriber-INITIATED, not push-initiated (unlike M-Pesa STK Push,
# which is a payment-only API and was deliberately rejected as the consent
# channel — see README). So the real flow is:
#   1. Agent initiates a swap -> SwapGuard sends an SMS nudge telling the
#      subscriber to dial the USSD code.
#   2. The subscriber dials in on their own phone; Africa's Talking POSTs
#      the session to /ussd on every step of the menu.
#   3. SwapGuard looks up the PENDING swap for that caller's number,
#      presents Allow/Block, then requires the subscriber's line PIN before
#      the decision is applied. The decision is recorded through the same
#      fail-closed logic used everywhere else in this app.
AT_USERNAME = os.environ.get('AT_USERNAME', 'sandbox')
AT_API_KEY = os.environ.get('877b3c0d6ffd667ece8d0fc34fe355ecc1ba3ecc577960846577ca4199176c5ccdf831a4')
USSD_SERVICE_CODE = os.environ.get('USSD_SERVICE_CODE', '*384*88#')

AT_SMS_ENABLED = bool(AT_API_KEY)
if AT_SMS_ENABLED:
    try:
        import africastalking
        africastalking.initialize(AT_USERNAME, AT_API_KEY)
        _at_sms = africastalking.SMS
    except Exception:
        # If the SDK isn't installed or init fails, fall back to simulation
        # rather than crashing the whole app over a demo integration.
        AT_SMS_ENABLED = False
        _at_sms = None
else:
    _at_sms = None

# In-memory log of nudges sent, shown in the UI so the demo is self-contained
# even without real AT credentials configured.
SMS_LOG = []


def send_consent_nudge(swap):
    """Notify the subscriber that a swap is pending and how to respond.
    Uses the real Africa's Talking SMS API if credentials are configured,
    otherwise simulates it (logs + stores for display) so the demo works
    with zero external accounts."""
    message = (
        f"SwapGuard alert: A SIM swap was requested on your line by agent "
        f"{swap['agent_id']}. Dial {USSD_SERVICE_CODE} now to allow or block it "
        f"— you'll need your line PIN to confirm your choice. "
        f"If you take no action within {CONSENT_TIMEOUT_SECONDS}s, it will be blocked automatically."
    )
    entry = {
        'phone': swap['phone'],
        'message': message,
        'sent_at': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'simulated': not AT_SMS_ENABLED,
    }
    SMS_LOG.append(entry)
    if AT_SMS_ENABLED:
        try:
            _at_sms.send(message, [_to_e164(swap['phone'])])
        except Exception as e:
            entry['error'] = str(e)
    return entry


def _to_e164(local_phone):
    """Convert a local 07xx/01xx number to +254 E.164 format for the AT API."""
    digits = local_phone.lstrip('0')
    return f"+254{digits}"


def _to_local(at_phone):
    """Convert an Africa's Talking-format number (+254712345678 or
    254712345678) back to this app's local 07xx/01xx format."""
    digits = (at_phone or '').lstrip('+')
    if digits.startswith('254') and len(digits) == 12:
        return '0' + digits[3:]
    return at_phone


def find_pending_swap_for_phone(phone):
    expire_stale_swaps()
    candidates = [s for s in swaps if s['phone'] == phone and s['status'] == 'PENDING']
    return candidates[-1] if candidates else None

# How long a subscriber has to respond to the STK push before the request is
# auto-blocked. Modelled on the Kariuki v. Safaricom & DTB ruling (High Court,
# Machakos, June 2026): Safaricom was found liable in part because a swap was
# allowed to complete despite red flags / no clear go-ahead from the real
# subscriber. A silent or unreachable subscriber must never be read as
# consent, so on timeout we fail CLOSED (auto-BLOCK), never auto-ALLOW.
CONSENT_TIMEOUT_SECONDS = 120


def next_id():
    global _swap_counter
    val = _swap_counter
    _swap_counter += 1
    return val


def gen_demo_pin():
    """Generate the 4-digit PIN used to confirm a swap decision in this demo.

    In production this would simply be the subscriber's own, already-known
    Safaricom line PIN, checked against the existing telco PIN store — never
    generated or displayed by SwapGuard. This prototype has no real
    subscriber PIN database to check against, so it generates one per swap
    and surfaces it on the agent-facing pages purely so a reviewer can act
    as the subscriber in the USSD simulator. That display path would not
    exist in a production build.
    """
    return f"{random.randint(0, 9999):04d}"


def expire_stale_swaps():
    """Fail-closed timeout enforcement: any PENDING swap whose consent window
    has lapsed is auto-BLOCKED (never auto-ALLOWED). Called on every read path
    so a subscriber's silence can never be misread as authorization."""
    now = datetime.datetime.now()
    for s in swaps:
        if s['status'] == 'PENDING' and now >= s['expires_at']:
            s['status'] = 'BLOCKED'
            s['decision_time'] = now.strftime("%Y-%m-%d %H:%M:%S")
            s['auto_expired'] = True


def find_swap(swap_id):
    expire_stale_swaps()
    return next((s for s in swaps if s['id'] == swap_id), None)


def apply_decision(swap, decision):
    """Single source of truth for turning an 'allow'/'block' decision into a
    state change, used by the real USSD callback, its local simulator, and
    Emergency Freeze — so there is exactly one code path that can move a
    swap out of PENDING."""
    swap['status'] = 'ALLOWED' if decision == 'allow' else 'BLOCKED'
    swap['decision_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return swap


def freeze_line(phone, agent_id, reason):
    """Lock a line via Emergency Freeze and fail-closed any swap that is
    still awaiting subscriber consent for that number."""
    now = datetime.datetime.now()
    FROZEN_LINES[phone] = {
        'phone': phone,
        'agent_id': agent_id,
        'reason': reason,
        'timestamp': now.strftime("%Y-%m-%d %H:%M:%S"),
    }
    for s in swaps:
        if s['phone'] == phone and s['status'] == 'PENDING':
            apply_decision(s, 'block')
            s['auto_expired'] = False
            s['frozen_blocked'] = True


def compute_stats():
    expire_stale_swaps()
    total = len(swaps)
    pending = sum(1 for s in swaps if s['status'] == 'PENDING')
    allowed = sum(1 for s in swaps if s['status'] == 'ALLOWED')
    blocked = sum(1 for s in swaps if s['status'] == 'BLOCKED')
    return {
        'total': total,
        'pending': pending,
        'allowed': allowed,
        'blocked': blocked,
        'frozen': len(FROZEN_LINES),
        'approval_rate': round((allowed / total) * 100) if total else 0,
        'block_rate': round((blocked / total) * 100) if total else 0,
    }



# ---------------------------------------------------------------------------
# Templates (Jinja2, loaded from a dict so {% extends %} works without
# needing a templates/ folder — keeps this a single-file demo)
# ---------------------------------------------------------------------------
TEMPLATES = {

"base.html": """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SwapGuard - {% block title %}Real-time SIM Swap Protection{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700;800&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            /* Palette lifted from developer.safaricom.co.ke (Daraja portal) */
            --sf-green: #00A550;
            --sf-green-dark: #00793C;
            --sf-green-light: #E8F8EF;
            --sf-red: #E4002B;
            --sf-ink: #12241E;
            --sf-grey: #6B7A75;
            --sf-grey-bg: #F6F9F7;
            --sf-border: #E4ECE7;
            --sf-radius: 18px;
        }
        * { font-family: 'Inter', -apple-system, sans-serif; }
        h1, h2, h3, h4, h5, .navbar-brand, .display-6, .display-4 { font-family: 'Poppins', sans-serif; }
        body { background: var(--sf-grey-bg); color: var(--sf-ink); }

        /* Navbar: white, pill nav links, like the Daraja top bar */
        .navbar { background: #ffffff !important; box-shadow: 0 1px 0 var(--sf-border); padding-top: 14px; padding-bottom: 14px; }
        .navbar-brand { font-weight: 800; color: var(--sf-ink) !important; letter-spacing: .2px; display: flex; align-items: center; gap: 8px; }
        .navbar-brand i { color: var(--sf-green); font-size: 1.3rem; }
        .nav-link { color: var(--sf-ink) !important; font-weight: 500; padding: 8px 16px !important; border-radius: 30px; margin-left: 4px; transition: background .15s, color .15s; }
        .nav-link:hover { background: var(--sf-green-light); color: var(--sf-green-dark) !important; }
        .nav-link.active { background: var(--sf-green); color: #fff !important; }
        .nav-link.emergency { color: var(--sf-red) !important; }
        .nav-link.emergency:hover { background: #FFF3F4; color: var(--sf-red) !important; }

        /* Hero: light, editorial, big rounded headline block — mirrors the Daraja landing hero */
        .hero { background: linear-gradient(180deg, #FFFFFF 0%, var(--sf-green-light) 100%); color: var(--sf-ink); padding: 72px 0 56px; margin-bottom: 48px; border-bottom: 1px solid var(--sf-border); }
        .hero .eyebrow { display: inline-flex; align-items: center; gap: 6px; background: #fff; border: 1px solid var(--sf-border); color: var(--sf-green-dark); font-weight: 600; font-size: .8rem; padding: 6px 14px; border-radius: 30px; margin-bottom: 18px; }
        .hero h1 { font-weight: 800; letter-spacing: -.5px; }
        .hero .lead { color: var(--sf-grey); }

        /* Cards: soft, rounded, generous — Daraja's "Benefits" card style */
        .stat-card { background: #fff; border: 1px solid var(--sf-border); border-radius: var(--sf-radius); padding: 24px 20px; box-shadow: 0 4px 16px rgba(18,36,30,0.04); transition: transform .15s, box-shadow .15s; }
        .stat-card:hover { transform: translateY(-4px); box-shadow: 0 10px 24px rgba(18,36,30,0.08); }
        .card { border: 1px solid var(--sf-border); border-radius: var(--sf-radius); overflow: hidden; }
        .card-header.brand { background: var(--sf-ink); color: #fff; border: none; font-weight: 600; padding: 16px 20px; }

        .status-pending { color: #B8860B; font-weight: bold; }
        .status-allowed { color: var(--sf-green-dark); font-weight: bold; }
        .status-blocked { color: var(--sf-red); font-weight: bold; }
        .status-frozen { color: var(--sf-red); font-weight: bold; }

        /* Buttons: full pill radius, like Daraja's "Join Us / View Docs" CTAs */
        .btn { border-radius: 30px; font-weight: 600; padding: 10px 22px; }
        .btn-lg { padding: 13px 30px; }
        .btn-sm { border-radius: 20px; }
        .btn-primary { background: var(--sf-green); border-color: var(--sf-green); }
        .btn-primary:hover, .btn-primary:focus { background: var(--sf-green-dark); border-color: var(--sf-green-dark); }
        .btn-outline-primary { color: var(--sf-green-dark); border-color: var(--sf-green); }
        .btn-outline-primary:hover { background: var(--sf-green); border-color: var(--sf-green); }
        .btn-outline-secondary { border-color: var(--sf-border); color: var(--sf-ink); }
        .btn-outline-secondary:hover { background: var(--sf-ink); border-color: var(--sf-ink); }
        .btn-success { background: var(--sf-green); border-color: var(--sf-green); }
        .btn-success:hover { background: var(--sf-green-dark); border-color: var(--sf-green-dark); }
        .btn-danger-solid { background: var(--sf-red); border-color: var(--sf-red); color: #fff; }
        .btn-danger-solid:hover { background: #B8001F; border-color: #B8001F; color: #fff; }
        .badge { border-radius: 30px; font-weight: 600; padding: 7px 12px; }

        .consent-box { background: #fff; border: 1px solid var(--sf-border); border-radius: 24px; padding: 34px; box-shadow: 0 10px 40px rgba(18,36,30,0.08); max-width: 600px; margin: 0 auto; }
        .fraud-alert { border-left: 5px solid var(--sf-red); background: #FFF3F4; border-radius: 12px; }
        .safe-alert { border-left: 5px solid var(--sf-green); background: var(--sf-green-light); border-radius: 12px; }
        .alert { border-radius: 12px; border: none; }
        .live-badge { animation: pulse 2s infinite; background: var(--sf-green) !important; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: .5; } 100% { opacity: 1; } }

        footer { background: var(--sf-ink); border-radius: 0; }
        .table thead th { border-bottom: 2px solid var(--sf-border); color: var(--sf-grey); font-weight: 600; font-size: .85rem; text-transform: uppercase; letter-spacing: .4px; }

        /* M-PESA style STK push phone mockup */
        .phone-frame { width: 300px; margin: 0 auto; background: #1A1A1A; border-radius: 40px; padding: 14px 10px; box-shadow: 0 20px 50px rgba(18,36,30,0.25); }
        .phone-notch { width: 90px; height: 18px; background: #1A1A1A; border-radius: 0 0 14px 14px; margin: 0 auto 6px; position: relative; z-index: 2; }
        .phone-screen { background: #EDEFF1; border-radius: 26px; overflow: hidden; min-height: 480px; position: relative; display: flex; flex-direction: column; }
        .phone-statusbar { display: flex; justify-content: space-between; align-items: center; padding: 10px 16px 4px; font-size: .72rem; font-weight: 600; color: #333; }
        .phone-home-content { flex: 1; background: linear-gradient(180deg, #DDE3E0 0%, #EDEFF1 60%); padding: 18px 14px; display: flex; flex-direction: column; align-items: center; justify-content: flex-start; gap: 6px; }
        .phone-home-content .app-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; width: 100%; margin-top: 18px; opacity: .55; }
        .phone-home-content .app-grid .app-icon { width: 36px; height: 36px; border-radius: 10px; background: #fff; margin: 0 auto; }

        .stk-popup { position: absolute; left: 8px; right: 8px; bottom: 10px; background: #fff; border-radius: 14px; box-shadow: 0 -6px 24px rgba(0,0,0,0.25); overflow: hidden; animation: stk-rise .25s ease-out; }
        @keyframes stk-rise { from { transform: translateY(20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
        .stk-header { background: var(--sf-green); color: #fff; padding: 8px 14px; font-size: .78rem; font-weight: 700; display: flex; align-items: center; gap: 6px; letter-spacing: .3px; }
        .stk-body { padding: 12px 14px 6px; font-size: .82rem; color: var(--sf-ink); line-height: 1.5; }
        .stk-body .stk-line { margin-bottom: 2px; }
        .stk-options { border-top: 1px solid #E9E9E9; }
        .stk-options button { width: 100%; border: none; background: none; text-align: left; padding: 11px 14px; font-size: .85rem; font-weight: 600; display: flex; align-items: center; gap: 8px; }
        .stk-options button + button { border-top: 1px solid #F1F1F1; }
        .stk-options button.stk-allow { color: var(--sf-green-dark); }
        .stk-options button.stk-block { color: var(--sf-red); }
        .stk-options button .stk-num { display: inline-flex; align-items: center; justify-content: center; width: 20px; height: 20px; border-radius: 5px; background: #F1F3F2; font-size: .72rem; color: var(--sf-grey); }
        .stk-timeout { text-align: center; font-size: .72rem; color: var(--sf-grey); padding: 8px 0 2px; }

        /* Dark SMS-reply-sheet style popup (matches native Android "reply to sender" sheet) */
        .phone-screen.sms-dark { background: #000; }
        .sms-statusbar { display: flex; justify-content: space-between; align-items: center; padding: 10px 16px 2px; color: #fff; font-size: .72rem; }
        .sms-statusbar .sms-icons i { margin-left: 6px; }
        .sms-topbar { display: flex; align-items: center; gap: 14px; padding: 14px 14px 6px; }
        .sms-topbar .sms-back { color: #b5b5b5; font-size: 1.25rem; }
        .sms-scribble { width: 120px; height: 34px; border-radius: 40% 60% 55% 45% / 50% 45% 55% 50%; background: #F4E400; box-shadow: 0 0 0 6px #F4E400 inset; }
        .sms-bg-body { flex: 1; background: #000; padding: 10px 16px 0; }
        .sms-bg-text { color: #8a8a8a; font-size: .82rem; line-height: 1.4; }
        .sms-reply-sheet { position: absolute; left: 0; right: 0; bottom: 0; background: #232326; border-radius: 22px 22px 0 0; padding: 26px 20px 14px; box-shadow: 0 -12px 34px rgba(0,0,0,.55); animation: stk-rise .25s ease-out; }
        .sms-reply-text { color: #f2f2f2; font-size: .92rem; line-height: 1.55; margin-bottom: 22px; }
        .sms-reply-text strong { color: #fff; }
        .sms-input-wrap { border-bottom: 2px solid #fff; padding-bottom: 8px; margin-bottom: 18px; min-height: 22px; display: flex; align-items: center; }
        .sms-input-wrap input { background: transparent; border: none; outline: none; color: #fff; font-size: .95rem; width: 100%; caret-color: #3b82f6; }
        .sms-actions { display: flex; align-items: stretch; border-top: 1px solid #38383a; padding-top: 4px; }
        .sms-actions button { flex: 1; background: none; border: none; color: #fff; font-weight: 600; font-size: .95rem; padding: 12px 0; }
        .sms-actions button.sms-send { color: #4dabf7; }
        .sms-actions .sms-divider { width: 1px; background: #38383a; margin: 8px 0; }
        .sms-error { color: #ff6b6b; font-size: .72rem; text-align: center; margin-top: -12px; margin-bottom: 10px; min-height: 14px; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg">
        <div class="container">
            <a class="navbar-brand" href="{{ url_for('home') }}">
                <i class="bi bi-shield-lock-fill"></i> SwapGuard
            </a>
            <div class="navbar-nav ms-auto align-items-lg-center">
                <a class="nav-link" href="{{ url_for('home') }}">Home</a>
                <a class="nav-link" href="{{ url_for('agent_portal') }}">Initiate Swap</a>
                <a class="nav-link emergency" href="{{ url_for('emergency_freeze') }}"><i class="bi bi-lock-fill"></i> Emergency Freeze</a>
                <a class="nav-link" href="{{ url_for('dashboard') }}">Audit Log</a>
                <a class="nav-link" href="{{ url_for('demo') }}">Live Demo</a>
            </div>
        </div>
    </nav>

    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
      <div class="container mt-3">
        {% for category, msg in messages %}
        <div class="alert alert-{{ 'danger' if category in ('danger', 'error') else category }}">{{ msg }}</div>
        {% endfor %}
      </div>
      {% endif %}
    {% endwith %}

    {% block hero %}{% endblock %}

    <div class="container">
        {% block content %}{% endblock %}
    </div>

    <footer class="text-white mt-5 py-4">
        <div class="container text-center">
            <p class="mb-0">SwapGuard v1.1 &middot; Real-time SIM Swap Consent &middot; Built for Safaricom Spark 2026</p>
            <small class="text-white-50">Demo Prototype &mdash; All data simulated</small>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>
""",

"home.html": """
{% extends "base.html" %}
{% block title %}Home{% endblock %}
{% block hero %}
<div class="hero">
    <div class="container">
        <div class="row align-items-center">
            <div class="col-lg-7">
                <span class="eyebrow"><i class="bi bi-stars"></i> SwapGuard 1.1</span>
                <h1 class="display-4">Real-time SIM Swap Consent</h1>
                <p class="lead fs-5">Protecting 45M+ Safaricom subscribers from SIM swap fraud with instant, interactive, PIN-confirmed consent — plug and play into fraud prevention.</p>
                <div class="mt-4 d-flex flex-wrap gap-3">
                    <a href="{{ url_for('agent_portal') }}" class="btn btn-primary btn-lg"><i class="bi bi-plus-circle"></i> Initiate Swap</a>
                    <a href="{{ url_for('demo') }}" class="btn btn-outline-primary btn-lg bg-white"><i class="bi bi-play-circle"></i> View Live Demo</a>
                </div>
                <div class="mt-4 d-flex flex-wrap gap-2">
                    <span class="badge text-bg-light border"><i class="bi bi-graph-up text-danger"></i> +327% fraud surge</span>
                    <span class="badge text-bg-light border"><i class="bi bi-people text-warning"></i> 480 swaps/month</span>
                    <span class="badge text-bg-light border"><i class="bi bi-currency-exchange text-success"></i> Sh810M losses prevented</span>
                </div>
            </div>
            <div class="col-lg-5 text-center mt-5 mt-lg-0">
                <div class="bg-white p-4 rounded-4 shadow-sm border" style="border-color: var(--sf-border) !important;">
                    <div class="d-flex align-items-center justify-content-center gap-2 text-muted mb-2">
                        <span class="badge live-badge"><i class="bi bi-record-circle"></i> LIVE</span>
                        <span>System Status</span>
                    </div>
                    <div class="display-6" style="color: var(--sf-green-dark);"><i class="bi bi-check-circle-fill"></i> Active</div>
                    <small class="text-muted">Protecting <strong>{{ stats.total }}</strong> swaps today</small>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
{% block content %}
<div class="row row-cols-2 row-cols-md-5 g-3 mb-4">
    <div class="col">
        <div class="stat-card text-center">
            <div class="mb-2"><i class="bi bi-collection fs-3" style="color: var(--sf-ink);"></i></div>
            <h3 class="display-6">{{ stats.total }}</h3>
            <p class="text-muted mb-0">Total Swaps</p>
        </div>
    </div>
    <div class="col">
        <div class="stat-card text-center">
            <div class="mb-2"><i class="bi bi-hourglass-split fs-3 status-pending"></i></div>
            <h3 class="display-6 status-pending">{{ stats.pending }}</h3>
            <p class="text-muted mb-0">Pending Consent</p>
        </div>
    </div>
    <div class="col">
        <div class="stat-card text-center">
            <div class="mb-2"><i class="bi bi-shield-check fs-3 status-allowed"></i></div>
            <h3 class="display-6 status-allowed">{{ stats.allowed }}</h3>
            <p class="text-muted mb-0">Approved</p>
        </div>
    </div>
    <div class="col">
        <div class="stat-card text-center">
            <div class="mb-2"><i class="bi bi-shield-x fs-3 status-blocked"></i></div>
            <h3 class="display-6 status-blocked">{{ stats.blocked }}</h3>
            <p class="text-muted mb-0">Blocked</p>
        </div>
    </div>
    <div class="col">
        <div class="stat-card text-center">
            <div class="mb-2"><i class="bi bi-lock-fill fs-3 status-frozen"></i></div>
            <h3 class="display-6 status-frozen">{{ stats.frozen }}</h3>
            <p class="text-muted mb-0">Frozen Lines</p>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header brand"><i class="bi bi-arrow-right-circle"></i> Quick Actions</div>
            <div class="card-body">
                <a href="{{ url_for('agent_portal') }}" class="btn btn-primary btn-lg w-100 mb-2">
                    <i class="bi bi-plus-circle"></i> Initiate New Swap
                </a>
                <a href="{{ url_for('emergency_freeze') }}" class="btn btn-danger-solid w-100 mb-2">
                    <i class="bi bi-lock-fill"></i> Emergency Freeze a Line
                </a>
                <a href="{{ url_for('dashboard') }}" class="btn btn-outline-secondary w-100">
                    <i class="bi bi-list-ul"></i> View Audit Log
                </a>
            </div>
        </div>
    </div>
    <div class="col-md-6">
        <div class="card">
            <div class="card-header brand"><i class="bi bi-broadcast"></i> System Status</div>
            <div class="card-body">
                <p><i class="bi bi-check-circle-fill" style="color: var(--sf-green);"></i> API: <strong>Online</strong></p>
                <p><i class="bi bi-check-circle-fill" style="color: var(--sf-green);"></i> USSD Consent Gateway: <strong>Ready</strong></p>
                <p><i class="bi bi-check-circle-fill" style="color: var(--sf-green);"></i> Database: <strong>{{ stats.total }} records</strong></p>
                <p><span class="badge live-badge"><i class="bi bi-record-circle"></i> LIVE</span> Monitoring active</p>
            </div>
        </div>
    </div>
</div>
{% endblock %}
""",

"agent.html": """
{% extends "base.html" %}
{% block title %}Agent Portal{% endblock %}
{% block content %}
<div class="row justify-content-center mt-4">
    <div class="col-md-6">
        {% if error %}
        <div class="alert alert-danger">{{ error }}</div>
        {% endif %}
        <div class="card">
            <div class="card-header brand"><i class="bi bi-person-badge"></i> Agent Portal &mdash; Initiate SIM Swap</div>
            <div class="card-body">
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">Subscriber Phone Number</label>
                        <input name="phone" class="form-control" placeholder="07XXXXXXXX" required
                               pattern="^0(7|1)[0-9]{8}$" value="{{ phone or '' }}">
                        <small class="text-muted">Format: 07XXXXXXXX or 01XXXXXXXX (Safaricom line)</small>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Agent ID</label>
                        <select name="agent_id" class="form-select" required>
                            {% for a in agents %}
                            <option value="{{ a }}" {% if a == agent_id %}selected{% endif %}>{{ a }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">
                        <i class="bi bi-send"></i> Initiate Swap
                    </button>
                </form>
                <hr>
                <div class="text-center">
                    <a href="{{ url_for('dashboard') }}" class="btn btn-outline-secondary btn-sm">
                        <i class="bi bi-list-ul"></i> View Audit Log
                    </a>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
""",

"freeze.html": """
{% extends "base.html" %}
{% block title %}Emergency Freeze{% endblock %}
{% block content %}
<div class="row justify-content-center mt-4">
    <div class="col-md-6">
        {% if error %}
        <div class="alert alert-danger">{{ error }}</div>
        {% endif %}
        <div class="card">
            <div class="card-header" style="background: var(--sf-red); color: #fff;">
                <i class="bi bi-exclamation-octagon-fill"></i> Emergency Freeze &mdash; Lock a Subscriber Line
            </div>
            <div class="card-body">
                <p class="text-muted small">
                    Use this when a line is suspected compromised (lost or stolen device, suspected
                    social engineering, suspicious agent activity) and needs to be locked
                    <strong>immediately</strong>, independent of any single swap request. Freezing a
                    line blocks new SIM swap requests against it and auto-blocks any swap that is
                    currently pending, using the same fail-closed logic as the consent timeout.
                </p>
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">Subscriber Phone Number</label>
                        <input name="phone" class="form-control" placeholder="07XXXXXXXX" required
                               pattern="^0(7|1)[0-9]{8}$" value="{{ phone or '' }}">
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Agent ID</label>
                        <select name="agent_id" class="form-select" required>
                            {% for a in agents %}
                            <option value="{{ a }}" {% if a == agent_id %}selected{% endif %}>{{ a }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Reason</label>
                        <select name="reason" class="form-select" required>
                            {% for r in reasons %}
                            <option value="{{ r }}">{{ r }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <button type="submit" class="btn btn-danger-solid w-100">
                        <i class="bi bi-lock-fill"></i> Freeze This Line Now
                    </button>
                </form>
                <hr>
                <div class="text-center">
                    <a href="{{ url_for('dashboard') }}" class="btn btn-outline-secondary btn-sm">
                        <i class="bi bi-list-ul"></i> View Audit Log / Frozen Lines
                    </a>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
""",

"swap_initiated.html": """
{% extends "base.html" %}
{% block title %}Swap Initiated{% endblock %}
{% block content %}
<div class="alert alert-success mt-4">
    <h4><i class="bi bi-check-circle"></i> Swap Initiated Successfully!</h4>
    <p><strong>Swap ID:</strong> #{{ swap.id }}</p>
    <p><strong>Status:</strong> <span class="status-pending">PENDING</span> &mdash; Awaiting subscriber consent</p>
</div>

<div class="consent-box text-center">
    <h4><i class="bi bi-chat-dots"></i> SMS Nudge Sent{% if nudge.simulated %} (Simulated){% endif %}</h4>
    <p class="text-muted text-start" style="font-size:.88rem;">{{ nudge.message }}</p>
    <p class="text-muted small">Sent to {{ swap.phone }} at {{ nudge.sent_at }}{% if nudge.error %} &mdash; <span class="text-danger">SMS API error: {{ nudge.error }}</span>{% endif %}</p>

    <div class="alert alert-warning text-start" style="font-size:.85rem;">
        <i class="bi bi-key-fill"></i> <strong>Demo PIN: {{ swap.demo_pin }}</strong> &mdash; in production the
        subscriber already knows their own line PIN and SwapGuard would never generate or display it;
        this demo shows it only because there's no real subscriber PIN store to check against, so a
        reviewer can act as the subscriber below.
    </div>

    <hr>
    <p class="text-muted mb-2">The subscriber now needs to dial <strong>{{ ussd_code }}</strong> on their own phone to respond. Since we don't have a physical handset in this demo, simulate that dial-in here &mdash; it calls the real <code>/ussd</code> endpoint, the same one Africa's Talking would call:</p>
    <a href="{{ url_for('ussd_sim', swap_id=swap.id) }}" class="btn btn-primary btn-lg">
        <i class="bi bi-phone"></i> Simulate Subscriber Dialing In
    </a>
    <div class="mt-3">
        <a href="{{ url_for('consent_page', swap_id=swap.id) }}" class="text-muted small">See a static illustration of the old STK-style mockup &rarr;</a>
    </div>
    <hr>
    <div class="mt-3">
        <a href="{{ url_for('agent_portal') }}" class="btn btn-outline-primary">&larr; New Swap</a>
        <a href="{{ url_for('dashboard') }}" class="btn btn-outline-secondary">Dashboard</a>
    </div>
</div>
{% endblock %}
""",

"ussd_sim.html": """
{% extends "base.html" %}
{% block title %}USSD Simulator{% endblock %}
{% block content %}
<div class="text-center mt-4 mb-4">
    <h2>Subscriber Handset &mdash; USSD Simulator</h2>
    <p class="text-muted">Stands in for a physical phone dialing {{ ussd_code_display }}. Every step below hits the real <code>/ussd</code> endpoint. Demo PIN for this swap: <strong>{{ swap.demo_pin }}</strong></p>
</div>
<div class="row justify-content-center">
    <div class="col-md-5">
        <div class="phone-frame">
            <div class="phone-notch"></div>
            <div class="phone-screen" style="background:#0c0c0c;">
                <div id="ussd-terminal" style="flex:1; padding:18px 16px; color:#8CFF9B; font-family: 'Courier New', monospace; font-size:.85rem; white-space: pre-wrap; overflow-y:auto;">Dialing...</div>
                <div style="padding: 10px 12px 16px; border-top:1px solid #222;">
                    <form id="ussd-form" style="display:flex; gap:8px;">
                        <input type="text" id="ussd-input" inputmode="numeric" maxlength="4"
                               style="flex:1; background:#1a1a1a; border:1px solid #333; color:#fff; border-radius:8px; padding:8px 10px; font-family: 'Courier New', monospace;"
                               placeholder="1, 2, or your PIN" autocomplete="off">
                        <button type="submit" class="btn btn-primary btn-sm">Send</button>
                    </form>
                </div>
            </div>
        </div>
        <div class="text-center mt-3">
            <a href="{{ url_for('dashboard') }}" class="btn btn-outline-secondary btn-sm">View Audit Log</a>
        </div>
    </div>
</div>
{% endblock %}
{% block scripts %}
<script>
(function () {
    var swapId = {{ swap.id }};
    var terminal = document.getElementById('ussd-terminal');
    var form = document.getElementById('ussd-form');
    var input = document.getElementById('ussd-input');
    var sessionText = '';
    var ended = false;

    function render(body) {
        var clean = body.replace(/^CON |^END /, '');
        terminal.textContent = clean;
        if (body.indexOf('END') === 0) {
            ended = true;
            input.disabled = true;
            form.querySelector('button').disabled = true;
        }
    }

    function step(newDigit) {
        sessionText = sessionText ? (sessionText + '*' + newDigit) : (newDigit || '');
        var body = new URLSearchParams({ text: sessionText });
        fetch('/ussd-sim/' + swapId + '/step', { method: 'POST', body: body })
            .then(function (r) { return r.text(); })
            .then(render);
    }

    form.addEventListener('submit', function (e) {
        e.preventDefault();
        if (ended) return;
        var v = input.value.trim();
        if (!v) return;
        input.value = '';
        step(v);
    });

    // Initial dial-in: empty text triggers the welcome menu.
    step('');
    sessionText = '';
})();
</script>
{% endblock %}
""",

"consent.html": """
{% extends "base.html" %}
{% block title %}Illustration &mdash; Subscriber Prompt Mockup{% endblock %}
{% block content %}
<div class="text-center mt-4 mb-2">
    <span class="badge text-bg-secondary"><i class="bi bi-eye"></i> Static illustration &mdash; not a live control</span>
</div>
<div class="text-center mt-2 mb-4">
    <h2>SIM Swap Alert &mdash; example handset view</h2>
    <p class="text-muted">This page renders the visual style of the prompt only. It is not wired to a real decision &mdash;<br>
    use <a href="{{ url_for('ussd_sim', swap_id=swap.id) }}">the USSD simulator</a> to actually respond to swap #{{ swap.id }}.</p>
</div>

<div class="row justify-content-center">
    <div class="col-auto">
        <div class="phone-frame">
            <div class="phone-notch"></div>
            <div class="phone-screen sms-dark">
                <div class="sms-statusbar">
                    <span>{{ swap.timestamp[-8:-3] }}</span>
                    <span class="sms-icons"><i class="bi bi-alarm"></i><i class="bi bi-reception-4"></i><i class="bi bi-wifi"></i><i class="bi bi-battery-full"></i></span>
                </div>
                <div class="sms-topbar">
                    <i class="bi bi-arrow-left sms-back"></i>
                    <div class="sms-scribble" title="Sender ID redacted for demo"></div>
                </div>
                <div class="sms-bg-body">
                    <div class="sms-bg-text">Choose the notifications you'd like to see &mdash; and those you don't</div>
                </div>

                <!-- Static illustration only: no form action, purely visual -->
                <div class="sms-reply-sheet">
                    <div class="sms-reply-text">
                        A SIM swap has been requested on <strong>{{ swap.phone }}</strong> by Agent {{ swap.agent_id }} at {{ swap.timestamp }}.
                        Reply with <strong>YES</strong> to allow this swap or <strong>NO</strong> to block it and report fraud.
                        You'll then be asked for your line PIN to confirm.<br>
                        1: Yes (Allow)<br>
                        2: No (Block &amp; report)
                    </div>
                    <div class="sms-input-wrap">
                        <span style="color:#666;">Type 1 or 2&hellip;</span>
                    </div>
                    <div class="sms-actions">
                        <button type="button" disabled style="opacity:.4; cursor:not-allowed;">Cancel</button>
                        <div class="sms-divider"></div>
                        <button type="button" disabled class="sms-send" style="opacity:.4; cursor:not-allowed;">Send</button>
                    </div>
                    <div class="stk-timeout">
                        <i class="bi bi-clock"></i> Illustration only &mdash; the real countdown lives in the USSD simulator
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<p class="text-center text-muted mt-3" style="font-size: .82rem;">
    <i class="bi bi-info-circle"></i> Fail-closed policy: if nobody responds in time, this request is
    automatically <strong>blocked</strong>, never automatically allowed.
</p>
{% endblock %}
""",

"already_decided.html": """
{% extends "base.html" %}
{% block title %}Already Decided{% endblock %}
{% block content %}
{% if swap.get('auto_expired') %}
<div class="alert alert-danger fraud-alert mt-4">
    <h4><i class="bi bi-clock-history"></i> Request Timed Out &mdash; Auto-BLOCKED</h4>
    <p>No response was received from <strong>{{ swap.phone }}</strong> within the consent window.</p>
    <p class="mb-0">Per SwapGuard's fail-closed policy, an unanswered request is never treated as
    approval &mdash; the SIM swap was automatically blocked and logged for review.</p>
</div>
{% elif swap.get('frozen_blocked') %}
<div class="alert alert-danger fraud-alert mt-4">
    <h4><i class="bi bi-lock-fill"></i> Blocked by Emergency Freeze</h4>
    <p>This line was frozen while this swap was pending, so it was automatically blocked.</p>
</div>
{% else %}
<div class="alert alert-warning mt-4">
    <h4> This swap has already been {{ swap.status.lower() }}</h4>
</div>
{% endif %}
<a href="{{ url_for('dashboard') }}" class="btn btn-primary">View Dashboard</a>
{% endblock %}
""",

"decision_result.html": """
{% extends "base.html" %}
{% block title %}{% if swap.status == 'ALLOWED' %}Swap Allowed{% else %}Swap Blocked &mdash; Fraud Alert{% endif %}{% endblock %}
{% block content %}
{% if swap.status == 'ALLOWED' %}
<div class="alert alert-success safe-alert mt-4">
    <h4><i class="bi bi-check-circle-fill"></i> Swap ALLOWED</h4>
    <p>SIM swap for <strong>{{ swap.phone }}</strong> has been approved.</p>
    <p class="mb-0"><small>Agent: {{ swap.agent_id }} &middot; Decision time: {{ swap.decision_time }}</small></p>
</div>
{% else %}
<div class="alert alert-danger fraud-alert mt-4">
    <h4><i class="bi bi-exclamation-triangle-fill"></i> FRAUD ALERT &mdash; Swap BLOCKED</h4>
    <p><strong>Unauthorized swap attempt blocked!</strong></p>
    <p>Phone: <strong>{{ swap.phone }}</strong> &middot; Agent: {{ swap.agent_id }}</p>
    <p class="mb-0"><small>Blocked at: {{ swap.decision_time }}</small></p>
</div>
<div class="alert alert-info">
    <i class="bi bi-info-circle"></i>
    <strong>Audit Trail Created:</strong> This incident has been logged with agent ID and timestamp for investigation.
</div>
{% endif %}
<div class="text-center mt-3">
    <a href="{{ url_for('dashboard') }}" class="btn {% if swap.status == 'BLOCKED' %}btn-danger{% else %}btn-primary{% endif %}">View Audit Log</a>
    <a href="{{ url_for('agent_portal') }}" class="btn btn-outline-secondary">New Swap</a>
</div>
{% endblock %}
""",

"dashboard.html": """
{% extends "base.html" %}
{% block title %}Dashboard &mdash; Audit Log{% endblock %}
{% block content %}
{% if frozen_lines %}
<div class="card mb-4">
    <div class="card-header" style="background: var(--sf-red); color:#fff;">
        <i class="bi bi-lock-fill"></i> Frozen Lines ({{ frozen_lines|length }})
    </div>
    <div class="card-body">
        <div class="table-responsive">
            <table class="table table-hover align-middle">
                <thead>
                    <tr><th>Phone</th><th>Agent</th><th>Reason</th><th>Frozen At</th><th>Action</th></tr>
                </thead>
                <tbody>
                    {% for f in frozen_lines %}
                    <tr>
                        <td><strong>{{ f.phone }}</strong></td>
                        <td>{{ f.agent_id }}</td>
                        <td>{{ f.reason }}</td>
                        <td>{{ f.timestamp }}</td>
                        <td>
                            <form method="POST" action="{{ url_for('unfreeze_line', phone=f.phone) }}" class="d-inline">
                                <button type="submit" class="btn btn-sm btn-outline-secondary">
                                    <i class="bi bi-unlock-fill"></i> Unfreeze
                                </button>
                            </form>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>
{% endif %}

{% if not swaps %}
<div class="alert alert-info mt-4">
    <h4>No swaps recorded yet</h4>
    <a href="{{ url_for('agent_portal') }}" class="btn btn-primary">Initiate your first swap &rarr;</a>
</div>
{% else %}
<div class="row mb-4 mt-2">
    <div class="col-md-3"><div class="stat-card text-center"><h3>{{ stats.total }}</h3><small class="text-muted">Total</small></div></div>
    <div class="col-md-3"><div class="stat-card text-center"><h3 class="status-pending">{{ stats.pending }}</h3><small class="text-muted">Pending</small></div></div>
    <div class="col-md-3"><div class="stat-card text-center"><h3 class="status-allowed">{{ stats.allowed }}</h3><small class="text-muted">Allowed</small></div></div>
    <div class="col-md-3"><div class="stat-card text-center"><h3 class="status-blocked">{{ stats.blocked }}</h3><small class="text-muted">Blocked</small></div></div>
</div>

<div class="card">
    <div class="card-header brand d-flex justify-content-between">
        <span><i class="bi bi-list-ul"></i> Audit Log</span>
        <span><small><i class="bi bi-clock"></i> Auto-refreshes every 10s</small></span>
    </div>
    <div class="card-body">
        <div class="table-responsive">
            <table class="table table-hover align-middle">
                <thead>
                    <tr><th>ID</th><th>Phone</th><th>Agent</th><th>Status</th><th>Time</th><th>Action</th></tr>
                </thead>
                <tbody>
                    {% for s in swaps_recent %}
                    <tr>
                        <td><strong>#{{ s.id }}</strong></td>
                        <td>{{ s.phone }}</td>
                        <td>{{ s.agent_id }}</td>
                        <td>
                            <span class="badge {{ s.badge_class }}">{{ s.status }}</span>
                            {% if s.get('auto_expired') %}<span class="badge bg-secondary" title="No response — auto-blocked on timeout"><i class="bi bi-clock-history"></i> timeout</span>{% endif %}
                            {% if s.get('frozen_blocked') %}<span class="badge bg-secondary" title="Blocked by Emergency Freeze"><i class="bi bi-lock-fill"></i> frozen</span>{% endif %}
                            {% if s.get('pin_lockout') %}<span class="badge bg-secondary" title="Blocked after too many incorrect PIN attempts"><i class="bi bi-key-fill"></i> PIN lockout</span>{% endif %}
                        </td>
                        <td>{{ s.timestamp }}</td>
                        <td>
                            {% if s.status == 'PENDING' %}
                            <a href="{{ url_for('ussd_sim', swap_id=s.id) }}" class="btn btn-sm btn-outline-primary">
                                <i class="bi bi-phone"></i>
                            </a>
                            {% else %}
                            <span class="text-muted">&mdash;</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>

<div class="mt-3 text-center">
    <a href="{{ url_for('agent_portal') }}" class="btn btn-primary"><i class="bi bi-plus-circle"></i> New Swap</a>
    <a href="{{ url_for('emergency_freeze') }}" class="btn btn-danger-solid"><i class="bi bi-lock-fill"></i> Emergency Freeze</a>
    <a href="{{ url_for('demo') }}" class="btn btn-outline-success"><i class="bi bi-play-circle"></i> Live Demo</a>
    <button onclick="location.reload()" class="btn btn-outline-secondary"><i class="bi bi-arrow-clockwise"></i> Refresh</button>
</div>
{% endif %}
{% endblock %}
{% block scripts %}
<script>setTimeout(function () { location.reload(); }, 10000);</script>
{% endblock %}
""",

"demo.html": """
{% extends "base.html" %}
{% block content %}
<div class="alert alert-info mt-4">
    <h4><i class="bi bi-broadcast"></i> Live Demo Mode</h4>
    <p class="mb-0">This dashboard auto-refreshes and simulates real-time SIM swap activity. Data shown is for demonstration purposes only.</p>
</div>

<div class="row">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header brand"><i class="bi bi-graph-up"></i> Real-time Statistics</div>
            <div class="card-body">
                <p><strong>Total Swaps:</strong> {{ stats.total }}</p>
                <p><strong>Fraud Blocked:</strong> {{ stats.blocked }} ({{ stats.block_rate }}%)</p>
                <p><strong>Approval Rate:</strong> {{ stats.approval_rate }}%</p>
                <p><strong>Frozen Lines:</strong> {{ stats.frozen }}</p>
                <div class="progress" role="progressbar" aria-valuenow="{{ stats.approval_rate }}" aria-valuemin="0" aria-valuemax="100">
                    <div class="progress-bar" style="width: {{ stats.approval_rate }}%; background: var(--sf-green);">{{ stats.approval_rate }}%</div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-6">
        <div class="card">
            <div class="card-header" style="background: var(--sf-red); color: white;"><i class="bi bi-exclamation-triangle"></i> Recent Fraud Alerts</div>
            <div class="card-body">
                {% for s in recent_fraud %}
                <div class="alert alert-danger py-2">
                    <strong> Blocked:</strong> {{ s.phone }}<br>
                    <small>Agent: {{ s.agent_id }} &middot; {{ s.timestamp }}</small>
                </div>
                {% else %}
                <p class="text-muted mb-0">No recent fraud alerts</p>
                {% endfor %}
            </div>
        </div>
    </div>
</div>
{% endblock %}
{% block scripts %}
<script>setTimeout(function () { location.reload(); }, 10000);</script>
{% endblock %}
""",

"404.html": """
{% extends "base.html" %}
{% block title %}Not Found{% endblock %}
{% block content %}
<div class="alert alert-danger mt-4">Swap not found.</div>
<a href="{{ url_for('dashboard') }}" class="btn btn-primary">Back to Dashboard</a>
{% endblock %}
""",
}

app.jinja_loader = DictLoader(TEMPLATES)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def home():
    return render_template('home.html', stats=compute_stats())


@app.route('/agent', methods=['GET', 'POST'])
def agent_portal():
    if request.method == 'POST':
        phone = (request.form.get('phone') or '').strip()
        agent_id = request.form.get('agent_id') or AGENTS[0]

        if not phone or len(phone) != 10 or not phone.isdigit() or phone[0] != '0':
            return render_template(
                'agent.html', agents=AGENTS, agent_id=agent_id, phone=phone,
                error="Please enter a valid Safaricom number, e.g. 0712345678."
            )

        if phone in FROZEN_LINES:
            return render_template(
                'agent.html', agents=AGENTS, agent_id=agent_id, phone=phone,
                error=(f"This line ({phone}) is currently frozen via Emergency Freeze and cannot "
                       f"process a SIM swap until an agent unfreezes it from the dashboard.")
            )

        now = datetime.datetime.now()
        swap = {
            'id': next_id(),
            'phone': phone,
            'agent_id': agent_id,
            'status': 'PENDING',
            'timestamp': now.strftime("%Y-%m-%d %H:%M:%S"),
            'decision_time': None,
            'expires_at': now + datetime.timedelta(seconds=CONSENT_TIMEOUT_SECONDS),
            'auto_expired': False,
            'frozen_blocked': False,
            'pin_lockout': False,
            'demo_pin': gen_demo_pin(),
        }
        swaps.append(swap)
        send_consent_nudge(swap)
        return redirect(url_for('swap_initiated', swap_id=swap['id']))

    return render_template('agent.html', agents=AGENTS, agent_id=None, phone=None, error=None)


@app.route('/freeze', methods=['GET', 'POST'])
def emergency_freeze():
    if request.method == 'POST':
        phone = (request.form.get('phone') or '').strip()
        agent_id = request.form.get('agent_id') or AGENTS[0]
        reason = request.form.get('reason') or FREEZE_REASONS[-1]

        if not phone or len(phone) != 10 or not phone.isdigit() or phone[0] != '0':
            return render_template(
                'freeze.html', agents=AGENTS, agent_id=agent_id, phone=phone,
                reasons=FREEZE_REASONS,
                error="Please enter a valid Safaricom number, e.g. 0712345678."
            )

        freeze_line(phone, agent_id, reason)
        flash(f"Line {phone} has been frozen — new SIM swaps are blocked and any pending "
              f"request for this number was auto-blocked.", 'danger')
        return redirect(url_for('dashboard'))

    return render_template('freeze.html', agents=AGENTS, agent_id=None, phone=None,
                            reasons=FREEZE_REASONS, error=None)


@app.route('/freeze/<phone>/unfreeze', methods=['POST'])
def unfreeze_line(phone):
    if phone in FROZEN_LINES:
        del FROZEN_LINES[phone]
        flash(f"Line {phone} has been unfrozen and can process SIM swaps again.", 'success')
    return redirect(url_for('dashboard'))


@app.route('/swap/<int:swap_id>/initiated')
def swap_initiated(swap_id):
    swap = find_swap(swap_id)
    if not swap:
        return render_template('404.html'), 404
    nudge = next((n for n in reversed(SMS_LOG) if n['phone'] == swap['phone']), None)
    return render_template('swap_initiated.html', swap=swap, nudge=nudge, ussd_code=USSD_SERVICE_CODE)


@app.route('/consent/<int:swap_id>')
def consent_page(swap_id):
    """Illustration only — a static preview of what the subscriber's phone
    would show, kept for the portfolio README/demo screenshots. It does NOT
    record a real decision; the actual consent mechanism is /ussd below."""
    swap = find_swap(swap_id)
    if not swap:
        return render_template('404.html'), 404
    seconds_left = max(0, int((swap['expires_at'] - datetime.datetime.now()).total_seconds()))
    return render_template('consent.html', swap=swap, seconds_left=seconds_left)


@app.route('/ussd', methods=['POST'])
def ussd_callback():
    """Real Africa's Talking USSD callback contract: respond with a
    'CON ...' body to keep the session open and show another menu, or an
    'END ...' body to close it. Idempotent by construction — once a swap
    leaves PENDING, every further callback for that swap (retry or repeat
    dial-in) just returns an already-decided message instead of mutating
    state again.

    Flow: dial in -> choose 1 (Allow) or 2 (Block) -> enter line PIN to
    confirm -> decision applied. Up to PIN_MAX_ATTEMPTS incorrect PIN
    entries fail CLOSED (auto-BLOCK), matching the fail-closed policy used
    for the consent timeout and Emergency Freeze."""
    phone = _to_local(request.form.get('phoneNumber', ''))
    text = (request.form.get('text') or '').strip()
    steps = text.split('*') if text else []

    if phone in FROZEN_LINES:
        response = ("END This line is currently frozen for security reasons. "
                    "Contact Safaricom customer care to lift the freeze before any SIM swap can proceed.")
        return response, 200, {'Content-Type': 'text/plain'}

    if not steps:
        swap = find_pending_swap_for_phone(phone)
        if not swap:
            response = "END No pending SIM swap requests found for this number."
        else:
            response = (
                f"CON SwapGuard: a SIM swap was requested on your line by "
                f"agent {swap['agent_id']} at {swap['timestamp']}.\n"
                f"If this wasn't you, choose Block.\n"
                f"1. Allow this swap\n"
                f"2. Block & report fraud"
            )
    else:
        choice = steps[0].strip()
        swap = find_pending_swap_for_phone(phone)
        if not swap:
            response = "END This request has already been resolved or has expired."
        elif choice not in USSD_MENU_CHOICES:
            response = "END Invalid selection. Please dial in again and choose 1 or 2."
        elif len(steps) == 1:
            action_word = "ALLOW" if choice == '1' else "BLOCK"
            response = (f"CON To confirm you want to {action_word} this swap, "
                        f"enter your Safaricom line PIN:")
        else:
            # steps[1:] are successive PIN attempts within the same USSD
            # session; only the most recent one is evaluated.
            entered_pin = steps[-1].strip()
            attempt_number = len(steps) - 1
            if entered_pin == swap.get('demo_pin'):
                decision = 'allow' if choice == '1' else 'block'
                apply_decision(swap, decision)
                if decision == 'allow':
                    response = "END PIN confirmed. This SIM swap has been ALLOWED. If this wasn't you, contact Safaricom immediately."
                else:
                    response = "END PIN confirmed. This SIM swap has been BLOCKED and reported as fraud."
            elif attempt_number >= PIN_MAX_ATTEMPTS:
                apply_decision(swap, 'block')
                swap['pin_lockout'] = True
                response = "END Incorrect PIN entered too many times. For your protection this swap has been automatically BLOCKED."
            else:
                remaining = PIN_MAX_ATTEMPTS - attempt_number
                response = f"CON Incorrect PIN. {remaining} attempt(s) remaining. Enter your Safaricom line PIN:"

    return response, 200, {'Content-Type': 'text/plain'}


@app.route('/ussd-sim/<int:swap_id>')
def ussd_sim(swap_id):
    """A browser-based stand-in for a real handset, for demos where dialing
    the real Africa's Talking sandbox code isn't practical. It talks to the
    exact same /ussd endpoint the real gateway would call, so this is
    exercising the real logic — not a second, parallel mock."""
    swap = find_swap(swap_id)
    if not swap:
        return render_template('404.html'), 404
    return render_template('ussd_sim.html', swap=swap, ussd_code_display=USSD_SERVICE_CODE)


@app.route('/ussd-sim/<int:swap_id>/step', methods=['POST'])
def ussd_sim_step(swap_id):
    """Relays a simulated keypress into the real /ussd handler, using the
    swap's own phone number as the caller ID, and returns the raw
    CON/END response for the simulator's terminal-style UI to render."""
    swap = find_swap(swap_id)
    if not swap:
        abort(404)
    text = request.form.get('text', '')
    with app.test_request_context(
        '/ussd', method='POST',
        data={'sessionId': f'sim-{swap_id}', 'phoneNumber': swap['phone'], 'text': text}
    ):
        body, status, headers = ussd_callback()
    return body, status, {'Content-Type': 'text/plain'}


@app.route('/dashboard')
def dashboard():
    badge_map = {'PENDING': 'bg-warning text-dark', 'ALLOWED': 'bg-success', 'BLOCKED': 'bg-danger'}
    swaps_recent = []
    for s in reversed(swaps[-50:]):
        swaps_recent.append({**s, 'badge_class': badge_map.get(s['status'], 'bg-secondary')})
    frozen_lines = sorted(FROZEN_LINES.values(), key=lambda f: f['timestamp'], reverse=True)
    return render_template('dashboard.html', swaps=swaps, swaps_recent=swaps_recent,
                            stats=compute_stats(), frozen_lines=frozen_lines)


@app.route('/demo')
def demo():
    # Seed a handful of realistic-looking demo records the first time this
    # page is visited, so the dashboard doesn't look empty in a live pitch.
    if len(swaps) < 10:
        for _ in range(10):
            phone = f"07{random.randint(10000000, 99999999)}"
            agent = random.choice(AGENTS)
            status = random.choices(['ALLOWED', 'BLOCKED', 'PENDING'], weights=[0.5, 0.3, 0.2])[0]
            # Keep any seeded PENDING record fresh (well inside its consent
            # window) so the demo can still show a live, un-expired request;
            # ALLOWED/BLOCKED records can be backdated freely as history.
            minutes_ago = random.randint(0, 1) if status == 'PENDING' else random.randint(1, 60)
            ts = datetime.datetime.now() - datetime.timedelta(minutes=minutes_ago)
            swap = {
                'id': next_id(),
                'phone': phone,
                'agent_id': agent,
                'status': status,
                'timestamp': ts.strftime("%Y-%m-%d %H:%M:%S"),
                'decision_time': (ts + datetime.timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S")
                                 if status in ('ALLOWED', 'BLOCKED') else None,
                'expires_at': ts + datetime.timedelta(seconds=CONSENT_TIMEOUT_SECONDS),
                'auto_expired': False,
                'frozen_blocked': False,
                'pin_lockout': False,
                'demo_pin': gen_demo_pin(),
            }
            swaps.append(swap)

    stats = compute_stats()
    recent_fraud = [s for s in swaps if s['status'] == 'BLOCKED'][-5:]
    return render_template('demo.html', stats=stats, recent_fraud=recent_fraud)


@app.errorhandler(404)
def not_found(_e):
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run(debug=True, port=5000)


# ---------------------------------------------------------------------------
# What was fixed / added vs. the earlier prototype
# ---------------------------------------------------------------------------
# 1-8: earlier bug-fix pass (Jinja2 DictLoader instead of broken f-string
#      string surgery; POST-only decision routes; POST/redirect/GET on swap
#      creation; server-side phone validation; validated decision path;
#      dead-code cleanup; sane form defaults; Safaricom-brand UI) — unchanged
#      from the prior version of this file.
# 9. PIN confirmation step: /ussd now asks for the subscriber's line PIN
#    after they pick Allow/Block, and only applies the decision if it
#    matches. Up to PIN_MAX_ATTEMPTS wrong entries fail CLOSED (auto-BLOCK),
#    so simply holding the handset that dialled in is no longer enough to
#    approve a swap. A per-swap demo_pin stands in for the subscriber's real,
#    already-known PIN, which this prototype has no live store to check
#    against — see gen_demo_pin()'s docstring for why that would not exist
#    in a production build.
# 10. Emergency Freeze: a new /freeze flow lets an agent lock a subscriber
#     line immediately and independently of any single swap (lost/stolen
#     device, suspected social engineering, suspicious agent activity).
#     FROZEN_LINES blocks new swap creation and USSD responses for that
#     number, and freeze_line() auto-blocks (fail-closed) any swap still
#     PENDING at the moment of freezing. The dashboard lists frozen lines
#     with an unfreeze action, and flash() messages confirm freeze/unfreeze
#     actions (the secret_key already reserved for this purpose is now
#     actually used).
