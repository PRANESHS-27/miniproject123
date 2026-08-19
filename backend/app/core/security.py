"""Password hashing & JWT helpers."""

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

_DEV_SECRET_MARKER = "dev-only-do-not-use-in-production"


def assert_safe_secret() -> None:
    """Refuse to start in production with the documented dev fallback.

    Called once from :func:`app.main.lifespan` so misconfigured prod
    deployments crash loudly instead of signing real tokens with a public
    secret.
    """
    if settings.app_env.lower() in ("production", "prod"):
        if _DEV_SECRET_MARKER in settings.secret_key:
            raise RuntimeError(
                "SECRET_KEY is set to the development fallback. "
                "Generate a real secret (e.g. `python -c 'import secrets; "
                "print(secrets.token_urlsafe(64))'`) and set it in the "
                "environment before running in production."
            )


def hash_password(plain: str) -> str:
    """Return bcrypt hash for a plaintext password."""
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash."""
    return pwd_context.verify(plain, hashed)


def create_access_token(
    subject: str | int,
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[dict[str, Any]] = None,
) -> str:
    """Create a signed JWT access token."""
    expire = datetime.now(timezone.utc) + (
        expires_delta
        or timedelta(minutes=settings.access_token_expire_minutes)
    )
    payload: dict[str, Any] = {"sub": str(subject), "exp": expire}
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def decode_token(token: str) -> dict[str, Any]:
    """Decode a JWT and return its claims, raising JWTError on failure."""
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    except JWTError as exc:  # pragma: no cover - re-raised for callers
        raise exc