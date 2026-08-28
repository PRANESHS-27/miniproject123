"""In-process IP-based rate limiter for the auth endpoints.

Hardening 24c — protect ``/api/auth/login`` against credential
brute-force. We deliberately avoid ``slowapi``/``limits`` to keep the
dependency surface small; for a college project on a single-process
FastAPI worker, an in-process counter is sufficient.

Behaviour:

  * Configurable via ``LOGIN_RATE_LIMIT_PER_MINUTE`` (default 5).
  * Counter is keyed on client IP. ``X-Forwarded-For`` is honoured only
    when the immediate connection is loopback (we trust the proxy in
    that case; otherwise we don't trust client-supplied headers).
  * Window is 60 s, sliding. When the limit is exceeded, the limiter
    records a ``rate_limited`` row in ``login_audit`` and returns 429.
  * Successful logins do **not** reset the counter (so a tight
    brute-force against a valid user still gets blocked); only
    *non-rate-limited* responses decrement a small budget. We keep the
    logic simple: a fixed window per IP, regardless of outcome.

This module is deliberately framework-agnostic — it doesn't import
FastAPI. Callers call :func:`check_login` and react to the boolean.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Deque, Tuple


class _SlidingWindow:
    """Lock-protected deque of timestamps; pop entries older than the
    window on every check."""

    __slots__ = ("window_seconds", "max_events", "_lock", "_buckets")

    def __init__(self, window_seconds: int, max_events: int) -> None:
        self.window_seconds = window_seconds
        self.max_events = max_events
        self._lock = threading.Lock()
        self._buckets: dict[str, Deque[float]] = defaultdict(deque)

    def hit(self, key: str, now: float | None = None) -> Tuple[bool, int]:
        """Record an event for ``key``. Returns ``(allowed, remaining)``.

        ``remaining`` is the number of events still permitted in the
        current window *after* this hit. ``0`` means the limit was just
        reached; ``-1`` means it was already exceeded.
        """
        now = now if now is not None else time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            bucket = self._buckets[key]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self.max_events:
                # Don't append — refusing doesn't change the bucket size.
                return False, -1
            bucket.append(now)
            remaining = self.max_events - len(bucket)
            return True, remaining

    def reset(self, key: str) -> None:
        with self._lock:
            self._buckets.pop(key, None)


_login_window: _SlidingWindow | None = None
_window_lock = threading.Lock()


def _login_window_singleton(per_minute: int) -> _SlidingWindow:
    """Lazy-init the singleton so tests can monkey-patch the limit."""
    global _login_window
    with _window_lock:
        if _login_window is None or _login_window.max_events != per_minute:
            _login_window = _SlidingWindow(
                window_seconds=60, max_events=per_minute
            )
        return _login_window


def reset_for_tests() -> None:
    """Drop all rate-limit state. Tests call this in setup."""
    global _login_window
    with _window_lock:
        _login_window = None


def check_login(ip: str | None, per_minute: int) -> Tuple[bool, int]:
    """Check whether a login attempt from ``ip`` is allowed.

    Returns ``(allowed, remaining)``. ``ip=None`` (no client info) is
    bucketed under ``"unknown"`` so the limiter still applies.
    """
    window = _login_window_singleton(per_minute)
    return window.hit(ip or "unknown")