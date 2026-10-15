from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import DeclarativeBase, Session

from app.core.config import get_settings


class Base(DeclarativeBase):
    pass


@lru_cache
def get_engine() -> Engine:
    url = get_settings().database_url
    if not url:
        raise RuntimeError("Configure DATABASE_URL no arquivo .env.")
    kwargs = {"check_same_thread": False} if url.startswith("sqlite") else {"connect_timeout": 5}
    return create_engine(url, pool_pre_ping=True, connect_args=kwargs)


def get_db() -> Iterator[Session]:
    with Session(get_engine()) as session:
        yield session
