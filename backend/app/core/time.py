"""UTC-aware datetime helpers for ORM columns.

SQLite strips tzinfo on storage, so a naive ``datetime`` written and
read back can't carry its offset. This module provides two pieces:

* ``utcnow_naive()`` — the default value for DateTime columns. Returns
  a *naive* ``datetime`` in UTC (so SQLite round-trips cleanly), but
  callers who need to render it should treat it as UTC.
* ``UtcDateTime`` — a SQLAlchemy ``TypeDecorator`` that wraps
  ``DateTime``. On write it strips tzinfo (so the value is stored as
  plain UTC). On read it re-attaches ``tzinfo=timezone.utc`` so the
  returned value is timezone-aware and ``isoformat()`` emits the
  ``+00:00`` suffix the frontend needs to render in local time.

Without the suffix, ``new Date('2026-08-13T10:20:29')`` in the browser
is parsed as *local* time and the user sees the wrong clock.

Why a decorator instead of a TZ-aware column type that Postgres would
also store?  Because we want to work on SQLite (the default in
``.env``) and Postgres identically, and SQLite's native ``DateTime``
is text — adding tzinfo at the Python boundary keeps the on-disk
representation identical across engines.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.types import DateTime, TypeDecorator


def utcnow_naive() -> datetime:
    """Return the current UTC time as a *naive* ``datetime``.

    Use as the ``default`` for any DateTime column that should record
    a wall-clock time. Stripping tzinfo makes SQLite happy; readers
    of these columns (via :class:`UtcDateTime`) will re-attach UTC.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


class UtcDateTime(TypeDecorator):
    """A DateTime that round-trips through SQLite as plain UTC.

    * **Bind (write)**: drops ``tzinfo`` so storage is naive UTC.
    * **Result (read)**: re-attaches ``tzinfo=timezone.utc`` so the
      returned value is timezone-aware.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):  # noqa: D401
        if value is None:
            return None
        if isinstance(value, datetime):
            if value.tzinfo is not None:
                # Convert to UTC and drop tzinfo for storage.
                value = value.astimezone(timezone.utc).replace(tzinfo=None)
            return value
        return value

    def process_result_value(self, value, dialect):  # noqa: D401
        if value is None:
            return None
        if isinstance(value, datetime) and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
