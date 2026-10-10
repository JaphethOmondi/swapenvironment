"""Background fail-closed sweep.

In the prototype, expire_stale_swaps() only ran when somebody loaded a
page. That meant an expired swap could sit PENDING indefinitely on a quiet
night — the exact window an attacker wants. This process guarantees the
sweep runs on a fixed interval regardless of traffic.

Run as a separate process alongside the web workers:
    python worker.py

Or, if you prefer not to run another process, use cron against the CLI:
    * * * * * cd /app && flask --app run sweep
(cron's one-minute floor is coarser than the consent window, so the
dedicated worker is preferred in production.)
"""

import logging
import os
import signal
import sys

from apscheduler.schedulers.blocking import BlockingScheduler

from swapguard import create_app
from swapguard.services import expire_stale_swaps

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
)
log = logging.getLogger("swapguard.worker")

INTERVAL = int(os.environ.get("SWEEP_INTERVAL_SECONDS", "10"))

app = create_app()
scheduler = BlockingScheduler()


@scheduler.scheduled_job("interval", seconds=INTERVAL, id="fail_closed_sweep",
                         max_instances=1, coalesce=True)
def sweep():
    with app.app_context():
        try:
            n = expire_stale_swaps()
            if n:
                log.info("fail-closed sweep blocked %d expired swap(s)", n)
        except Exception:
            # Never let one bad cycle kill the scheduler — a dead sweeper
            # means swaps silently stop expiring.
            log.exception("sweep cycle failed")


def shutdown(signum, _frame):
    log.info("shutting down on signal %s", signum)
    scheduler.shutdown(wait=False)
    sys.exit(0)


signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)

if __name__ == "__main__":
    log.info("starting fail-closed sweep every %ss", INTERVAL)
    scheduler.start()
