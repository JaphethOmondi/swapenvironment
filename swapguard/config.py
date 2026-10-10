"""Environment-driven configuration.

Nothing secret is hardcoded here. Every value comes from the environment,
with development-only fallbacks that are deliberately obvious (and refused
outright in production via _require()).
"""

import os


def _require(name):
    """Fetch a mandatory setting, failing loudly at boot rather than
    silently running insecurely in production."""
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"{name} must be set in the environment. Refusing to start: "
            "a missing secret in production is a security failure, not a default."
        )
    return value


class BaseConfig:
    # --- Core Flask ---
    # SECRET_KEY must be stable across restarts and across workers, otherwise
    # every deploy silently logs all agents out and multi-worker setups
    # reject each other's sessions.
    SECRET_KEY = os.environ.get("89e2f8b7406b1cc9105c88a9c82e328a138d821b5bcbbb9d7c54abc9239af205", "dev-only-insecure-key")

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        # Recycle before typical cloud-Postgres idle timeouts, and verify the
        # connection is alive before handing it to a request.
        "pool_pre_ping": True,
        "pool_recycle": 280,
    }

    # --- Consent policy ---
    # How long a subscriber has to respond before the request fails CLOSED.
    CONSENT_TIMEOUT_SECONDS = int(os.environ.get("CONSENT_TIMEOUT_SECONDS", "120"))
    # Wrong-PIN attempts allowed before the swap is blocked outright.
    MAX_PIN_ATTEMPTS = int(os.environ.get("MAX_PIN_ATTEMPTS", "3"))
    # Per-agent throttle: a compromised or bribed agent spamming swap
    # requests is itself a fraud signal worth capping and alerting on.
    AGENT_SWAP_RATE_LIMIT = int(os.environ.get("AGENT_SWAP_RATE_LIMIT", "20"))
    AGENT_SWAP_RATE_WINDOW_SECONDS = int(
        os.environ.get("AGENT_SWAP_RATE_WINDOW_SECONDS", "3600")
    )

    # --- Personal data protection (Kenya DPA 2019) ---
    # PHONE_PEPPER salts the lookup hash; PHONE_ENCRYPTION_KEY encrypts the
    # recoverable copy we need in order to actually send the SMS nudge.
    PHONE_PEPPER = os.environ.get("908690564dbd3f246fbec802b2405959d5f015152f2a6505bf6adead665177c8", "dev-only-pepper")
    PHONE_ENCRYPTION_KEY = os.environ.get("49BQPA2jnLJaHCeTzRhTzOTmNUcsDANmJfyNypXw7bo=")

    # --- Telco integration ---
    AT_USERNAME = os.environ.get("AT_USERNAME", "sandbox")
    AT_API_KEY = os.environ.get("AT_API_KEY", "")
    USSD_SERVICE_CODE = os.environ.get("USSD_SERVICE_CODE", "*384*88#")
    # Comma-separated CIDR ranges permitted to POST to /ussd. Empty disables
    # the check (dev only) — see routes/ussd.py.
    AT_ALLOWED_IPS = os.environ.get("AT_ALLOWED_IPS", "")

    # --- Retention ---
    # Decided swaps move to cold storage after this long; audit events are
    # kept longer because they are the legal-defensibility record.
    SWAP_ARCHIVE_AFTER_DAYS = int(os.environ.get("SWAP_ARCHIVE_AFTER_DAYS", "90"))


class DevConfig(BaseConfig):
    DEBUG = True
    # SQLite by default so a new contributor can run tests with zero setup.
    # Production is Postgres — the SQLAlchemy models are identical either way.
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///swapguard_dev.db"
    )


class TestConfig(BaseConfig):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    CONSENT_TIMEOUT_SECONDS = 2
    WTF_CSRF_ENABLED = False


class ProdConfig(BaseConfig):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PREFERRED_URL_SCHEME = "https"

    def __init__(self):
        # Evaluated at instantiation so a misconfigured production deploy
        # crashes at boot instead of running with dev fallbacks.
        self.SECRET_KEY = _require("SECRET_KEY")
        self.PHONE_PEPPER = _require("PHONE_PEPPER")
        self.PHONE_ENCRYPTION_KEY = _require("PHONE_ENCRYPTION_KEY")
        raw_url = _require("DATABASE_URL")
        # Heroku-style URLs use the deprecated postgres:// prefix.
        if raw_url.startswith("postgres://"):
            raw_url = raw_url.replace("postgres://", "postgresql://", 1)
        self.SQLALCHEMY_DATABASE_URI = raw_url


CONFIGS = {"development": DevConfig, "testing": TestConfig, "production": ProdConfig}


def get_config(name=None):
    name = name or os.environ.get("FLASK_ENV", "development")
    cfg = CONFIGS.get(name, DevConfig)
    # ProdConfig validates in __init__, so it must be instantiated.
    return cfg() if name == "production" else cfg
