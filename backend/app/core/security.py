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


# Insecure dev fallback for ADMIN_PASSWORD. We refuse to seed a bootstrap
# admin with this value when the deployment is anything stricter than
# pure development. Mirrors the ``_DEV_SECRET_MARKER`` pattern.
_DEV_ADMIN_PASSWORD_MARKER = "Admin@123"


def assert_safe_admin_password() -> None:
    """Refuse to seed the bootstrap admin with a known dev password.

    Hardening 24a — the single most common deployment mistake is shipping
    a system with a publicly documented credential. This guard runs
    inside ``_bootstrap_admin`` before any DB write.

    The check fires when:
      * ``APP_ENV`` is anything other than ``development`` / ``dev``
      * OR the operator explicitly set ``REQUIRE_ADMIN_PASSWORD=true``

    In those cases the password must not equal the documented dev fallback.
    """
    is_dev = settings.app_env.lower() in ("development", "dev")
    if is_dev and not settings.require_admin_password:
        return
    if settings.admin_password == _DEV_ADMIN_PASSWORD_MARKER:
        raise RuntimeError(
            "ADMIN_PASSWORD is set to the documented dev fallback "
            "('Admin@123'). Set a real password in the environment (e.g. "
            "`export ADMIN_PASSWORD=$(python -c 'import secrets; "
            "print(secrets.token_urlsafe(24))')`) before booting in a "
            "non-development environment."
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
    token_type: str = "access",
) -> str:
    """Create a signed JWT access or refresh token.

    The ``token_type`` claim lets the refresh endpoint refuse access
    tokens (and vice versa) — a refresh token presented as an access
    token would otherwise pass the signature check and be accepted by
    the bearer dependency.
    """
    if token_type == "refresh":
        expires_delta = expires_delta or timedelta(
            minutes=settings.refresh_token_expire_minutes
        )
    else:
        expires_delta = expires_delta or timedelta(
            minutes=settings.access_token_expire_minutes
        )
    expire = datetime.now(timezone.utc) + expires_delta
    payload: dict[str, Any] = {
        "sub": str(subject),
        "exp": expire,
        "typ": token_type,
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def create_refresh_token(
    subject: str | int,
    extra_claims: Optional[dict[str, Any]] = None,
) -> str:
    """Issue a long-lived refresh token. Pair with a short access token."""
    return create_access_token(
        subject=subject, extra_claims=extra_claims, token_type="refresh"
    )


def decode_token_with_type(
    token: str, expected_type: str
) -> dict[str, Any]:
    """Decode ``token`` and require its ``typ`` claim to match ``expected_type``.

    Raises ``JWTError`` on bad signature/expiry/type mismatch. We don't
    reuse :func:`decode_token` here because that function is intentionally
    type-agnostic for the bearer dependency.
    """
    payload = jwt.decode(
        token, settings.secret_key, algorithms=[settings.algorithm]
    )
    actual = payload.get("typ", "access")
    if actual != expected_type:
        raise JWTError(
            f"Expected token type '{expected_type}', got '{actual}'"
        )
    return payload


def decode_token(token: str) -> dict[str, Any]:
    """Decode a JWT and return its claims, raising JWTError on failure."""
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    except JWTError as exc:  # pragma: no cover - re-raised for callers
        raise exc