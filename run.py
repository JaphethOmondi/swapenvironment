"""Development entrypoint.

Production runs Gunicorn against `wsgi:app` instead — never this file, and
never with debug=True (debug mode exposes an interactive Python console to
anyone who can trigger a traceback).
"""

from swapguard import create_app

app = create_app()

if __name__ == "__main__":
    # 127.0.0.1, not a hardcoded LAN IP: the prototype's 192.168.2.101 only
    # bound on one specific machine and failed everywhere else.
    app.run(host="127.0.0.1", port=5000, debug=True)
