"""Application factory.

The prototype created a module-level `app` and ran it with
`app.run(debug=True, ...)`. That is unusable in production: debug mode
exposes an interactive Python console to anyone who can trigger a
traceback, and a module-level app makes testing against multiple configs
impossible. This factory builds a fresh, configured app per environment.
"""

import logging

from flask import Flask, render_template

from .config import get_config
from .extensions import db


def create_app(config_name=None):
    app = Flask(__name__)
    app.config.from_object(get_config(config_name))

    logging.basicConfig(
        level=logging.INFO,
        format='{"ts":"%(asctime)s","level":"%(levelname)s",'
               '"logger":"%(name)s","msg":"%(message)s"}',
    )

    db.init_app(app)

    from .auth import login_manager
    login_manager.init_app(app)

    from .routes.main import bp as main_bp
    from .routes.auth import bp as auth_bp
    from .routes.agent import bp as agent_bp
    from .routes.ussd import bp as ussd_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(agent_bp)
    app.register_blueprint(ussd_bp)

    register_cli(app)

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("404.html"), 404

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        if not app.debug:
            resp.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return resp

    return app


def register_cli(app):
    import click

    @app.cli.command("init-db")
    def init_db():
        """Create tables directly. Use Alembic migrations in production;
        this is for a fast local start."""
        db.create_all()
        click.echo("Tables created.")

    @app.cli.command("create-agent")
    @click.argument("agent_code")
    @click.argument("password")
    @click.option("--role", default="AGENT",
                  type=click.Choice(["AGENT", "ANALYST", "ADMIN"]))
    @click.option("--name", default=None)
    def create_agent(agent_code, password, role, name):
        """Create an authenticated agent account."""
        from .models import Agent, AgentRole

        if db.session.query(Agent).filter_by(agent_code=agent_code).first():
            click.echo(f"Agent {agent_code} already exists.")
            return
        agent = Agent(
            agent_code=agent_code,
            display_name=name or agent_code,
            role=AgentRole[role],
        )
        agent.set_password(password)
        db.session.add(agent)
        db.session.commit()
        click.echo(f"Created agent {agent_code} with role {role}.")

    @app.cli.command("sweep")
    def sweep():
        """Run the fail-closed timeout sweep once (for cron)."""
        from .services import expire_stale_swaps

        n = expire_stale_swaps()
        click.echo(f"Blocked {n} expired swap(s).")

    @app.cli.command("gen-keys")
    def gen_keys():
        """Print freshly generated secrets for your .env file."""
        import secrets as _s
        from cryptography.fernet import Fernet

        click.echo(f"SECRET_KEY={_s.token_hex(32)}")
        click.echo(f"PHONE_PEPPER={_s.token_hex(32)}")
        click.echo(f"PHONE_ENCRYPTION_KEY={Fernet.generate_key().decode()}")
