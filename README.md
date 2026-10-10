# SwapGuard — persistent build

Subscriber-in-the-loop consent control for SIM swap requests. This is the
refactor of the single-file prototype onto a real database, with
authentication, migrations, an append-only audit trail and a scheduled
fail-closed sweep.

## What changed from the prototype

| Prototype | Now | Why |
|---|---|---|
| `swaps = []`, `SMS_LOG = []` in memory | Postgres tables via SQLAlchemy | State survived neither a restart nor a second worker |
| `_swap_counter` global | database primary key | Two workers produced duplicate IDs |
| Agent chosen from a dropdown | authenticated accounts, hashed passwords, roles | Insider collusion is a documented SIM-swap vector; agent identity cannot be self-asserted |
| `expire_stale_swaps()` on page load | scheduled worker every 10s | An expired swap could sit PENDING indefinitely with no traffic |
| Phone numbers stored plainly | HMAC lookup hash + Fernet ciphertext + masked display | Kenya DPA 2019; a dashboard operator should never see full numbers |
| No audit table | append-only `audit_events`, ORM guards + Postgres trigger | The "documented reasonable steps" claim needs evidence that cannot be edited |
| `/ussd` trusted any POST | source IP allowlist | Anyone who found the URL could forge an ALLOW |
| Phone validated in HTML only | server-side regex | A direct POST bypassed the check entirely |
| No tests | 17 tests on the invariants | Every one maps to a claim the pitch makes |
| `app.run(debug=True, host='192.168.2.101')` | app factory + Gunicorn | Debug mode exposes a Python console on any traceback |

## Local setup

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
flask --app run gen-keys          # paste the three secrets into .env

export DATABASE_URL="sqlite:///dev.db"   # Postgres for anything real
alembic upgrade head
flask --app run create-agent AG007 yourpassword --role ADMIN

python run.py                     # http://127.0.0.1:5000
python worker.py                  # second terminal: fail-closed sweep
```

Windows PowerShell uses `$env:DATABASE_URL="sqlite:///dev.db"` instead of
`export`.

### Demo path

1. Sign in as `AG007`
2. Initiate Swap → any number like `0712345678`
3. The simulated SMS nudge shows a demo PIN (never sent by SMS once real
   credentials are configured)
4. Simulate subscriber dialling in → choose `1`/`2` → enter the PIN
5. Audit Trail shows every transition with actor and timestamp

To demonstrate fail-closed: initiate a swap and wait out the window
without responding. The worker blocks it automatically.

## Production

```bash
docker compose up --build
```

Runs Postgres, the web app behind Gunicorn, and the sweep worker as
separate processes, applying migrations on boot.

### Before going live

- [ ] `FLASK_ENV=production` (refuses to boot without real secrets)
- [ ] Postgres, not SQLite — SQLite has no `SKIP LOCKED`, so concurrent
      sweeps cannot be made safe
- [ ] Secrets in a vault, not `.env`
- [ ] `AT_ALLOWED_IPS` populated with Africa's Talking's real ranges
- [ ] TLS terminated upstream; HSTS is already set by the app
- [ ] Automated Postgres backups, **and a tested restore**
- [ ] Sentry or equivalent for error reporting
- [ ] Alerting on: pending-swap backlog, timeout share, per-agent swap rate
- [ ] ODPC registration as a data controller/processor
- [ ] Documented retention policy for `swaps` vs `audit_events`

## Known limitations

These are real and belong in any honest presentation of this work.

**No enforcement.** SwapGuard cannot actually stop a SIM swap. The
provisioning layer (HLR) is inside the telco's core network and no public
API exposes it. This system demonstrates the consent and audit layer that
would sit in front of it given a partnership.

**The PIN is a demo construct.** `generate_pin()` mints a PIN and, in
simulated mode, includes it in the SMS. In production the second factor
must be the subscriber's existing telco credential verified by the telco —
a PIN we issue over a channel an attacker may already control adds little.

**Consent phishing is unsolved.** An attacker who talks the subscriber into
approving the prompt defeats this control entirely. Showing the requesting
agent ID helps; it does not fix social engineering.

**The availability paradox.** Fail-closed at national scale means a
SwapGuard outage halts every legitimate SIM replacement too. A real
deployment needs a documented degradation policy — likely fail-closed only
for high-risk swaps, with enhanced manual verification otherwise.

**False blocks have victims.** Kenya's post-fraud KYC tightening already
produced cases of legitimate customers unable to replace a SIM. Track the
timeout share on the dashboard as a first-class metric, not an afterthought.
