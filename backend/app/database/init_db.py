"""Upgrade the database without dropping existing DAST data."""

from pathlib import Path

from alembic.config import Config

from alembic import command

if __name__ == "__main__":
    backend_root = Path(__file__).resolve().parents[2]
    configuration = Config(backend_root / "alembic.ini")
    command.upgrade(configuration, "head")
    print("DAST database migrations are at head.")
