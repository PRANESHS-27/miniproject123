"""SQLAlchemy engine, session, and declarative base."""

from collections.abc import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings


class Base(DeclarativeBase):
    """SQLAlchemy declarative base."""


# ``sqlite`` covers ``sqlite://``, ``sqlite:///`` and ``sqlite+pysqlite://``
# (the SQLAlchemy 2.x recommended driver spec). Using a tuple prefix-match
# also rejects accidental capitalisation (``SQLITE://``) which would
# otherwise bypass the SQLite-specific connect_args.
_is_sqlite = settings.database_url.startswith(("sqlite",))

_connect_args: dict = {}
_engine_kwargs: dict = {}
if _is_sqlite:
    _connect_args = {"check_same_thread": False, "timeout": 30.0}
    # StaticPool is only needed for :memory: SQLite to preserve state across connections.
    # For file-based SQLite, omitting StaticPool allows concurrent connections with WAL.
    if ":memory:" in settings.database_url:
        from sqlalchemy.pool import StaticPool
        _engine_kwargs["poolclass"] = StaticPool

engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    connect_args=_connect_args,
    **_engine_kwargs,
)

if _is_sqlite:
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):
        try:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.execute("PRAGMA cache_size=-64000")
            cursor.execute("PRAGMA temp_store=MEMORY")
            cursor.execute("PRAGMA mmap_size=268435456")
            cursor.close()
        except Exception:
            pass


SessionLocal = sessionmaker(
    bind=engine, autocommit=False, autoflush=False, expire_on_commit=False
)


def get_db() -> Iterator[Session]:
    """FastAPI dependency that yields a database session.

    Rolls back any in-flight transaction when the request handler raises,
    so the connection returned to the pool isn't left in an aborted
    state. Without this, a single 5xx leaves the pool dirty until the
    next GC.
    """
    db = SessionLocal()
    try:
        yield db
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        raise
    finally:
        db.close()
