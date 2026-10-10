"""Alembic environment, wired to the Flask app factory."""

from logging.config import fileConfig

from alembic import context

from swapguard import create_app
from swapguard.extensions import db
import swapguard.models  # noqa: F401 - registers models on db.metadata

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

app = create_app()
app.app_context().push()

config.set_main_option(
    "sqlalchemy.url", app.config["SQLALCHEMY_DATABASE_URI"].replace("%", "%%")
)
target_metadata = db.metadata


def run_migrations_offline():
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    connectable = db.engine
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            render_as_batch=True,  # SQLite needs batch mode for ALTER
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
