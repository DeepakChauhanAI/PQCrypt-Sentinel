from logging.config import fileConfig
import sys
import os
from pathlib import Path

from sqlalchemy.engine import Connection
from sqlalchemy import create_engine
from alembic import context

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

_backend_dir = str(Path(__file__).resolve().parent.parent)
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

try:
    from app.models.models import Base

    target_metadata = Base.metadata
except ImportError:
    target_metadata = None

DATABASE_URL = config.get_main_option(
    "sqlalchemy.url",
    "postgresql://pqcrypt:pqcrypt@localhost:5432/pqcrypt",
)


def run_migrations_offline() -> None:
    context.configure(
        url=DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = config.attributes.get("connection")
    if connectable is None:
        connectable = create_engine(DATABASE_URL)
    if hasattr(connectable, "connect"):
        with connectable.connect() as connection:
            context.configure(connection=connection, target_metadata=target_metadata)
            with context.begin_transaction():
                context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
