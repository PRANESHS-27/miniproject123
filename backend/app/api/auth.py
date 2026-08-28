"""Authentication routes: register, login, /me, refresh."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from jose import JWTError
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.rate_limit import check_login
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token_with_type,
    hash_password,
    verify_password,
)
from app.db import get_db
from app.models import (
    LoginAudit,
    Role,
    TIER_INSTITUTION_ADMIN,
    TIER_SUPER_ADMIN,
    User,
    role_tier,
)
from app.schemas.auth import LoginRequest, Token, UserCreate, UserOut

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _role_value(r) -> str:
    return r.value if hasattr(r, "value") else str(r)


def _client_meta(request: Request) -> tuple[str | None, str | None]:
    """Best-effort extraction of (ip, user_agent) for audit logging.

    ``X-Forwarded-For`` is honoured only when ``request.client.host`` is
    loopback (i.e. we're behind a trusted proxy); otherwise we'd trust
    a client-supplied header, which is the same as trusting the client.
    """
    ip: str | None = None
    if request.client and request.client.host:
        ip = request.client.host
        if ip in ("127.0.0.1", "::1") and request.headers.get("x-forwarded-for"):
            ip = request.headers["x-forwarded-for"].split(",")[0].strip()
    ua = request.headers.get("user-agent")
    return ip, (ua[:512] if ua else None)


def _audit(
    db: Session,
    *,
    username: str,
    outcome: str,
    request: Request,
    user_id: int | None = None,
) -> None:
    """Append a row to ``login_audit``. Never raises — auditing is a
    best-effort observability feature, not a security control."""
    ip, ua = _client_meta(request)
    db.add(LoginAudit(
        username=username,
        outcome=outcome,
        ip=ip,
        user_agent=ua,
        user_id=user_id,
    ))
    try:
        db.commit()
    except Exception:
        db.rollback()


@router.post("/register", response_model=Token, status_code=201)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    """Create a new user.

    - If this is the **first** user, the role is forced to SUPER_ADMIN
      regardless of what the request said. This is the only path that
      seeds a super-admin from a registration.
    - For every subsequent registration, self-promotion to any
      **privileged** tier (SUPER_ADMIN, INSTITUTION_ADMIN) is denied
      from an unauthenticated request. Operators must create those via
      ``/api/admin/users`` once the bootstrap admin is signed in.
    """
    if db.query(User).filter_by(username=payload.username).first():
        raise HTTPException(409, "Username already exists")
    if db.query(User).filter_by(email=payload.email).first():
        raise HTTPException(409, "Email already exists")

    requested = payload.role or Role.VIEWER
    is_first_user = db.query(User).count() == 0
    if is_first_user:
        role = Role.SUPER_ADMIN
    else:
        role = requested
        requested_tier = role_tier(role)
        if requested_tier in {TIER_SUPER_ADMIN, TIER_INSTITUTION_ADMIN}:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "Self-registration as a privileged user is not allowed. "
                    "Ask an existing institution admin or super admin."
                ),
            )

    user = User(
        username=payload.username,
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role=role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # RBAC 22 — include ``institution_id`` in the JWT so the frontend
    # can display "you're acting on behalf of Institution X" without an
    # extra /me round-trip. The claim is informational; the
    # authoritative value is ``user.institution_id`` (re-fetched from
    # the DB by ``get_current_user`` on every request).
    extra = {
        "role": _role_value(user.role),
        "username": user.username,
        "institution_id": user.institution_id,
    }
    access = create_access_token(subject=user.id, extra_claims=extra)
    refresh = create_refresh_token(subject=user.id, extra_claims=extra)
    return Token(
        access_token=access,
        refresh_token=refresh,
        user=UserOut.model_validate(user),
    )


@router.post("/login", response_model=Token)
def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Validate credentials and return access + refresh tokens.

    Security hardening 24b — every attempt is audited. We *do* log
    failed attempts: missing the username entirely from the audit log
    would leave blind spots during an incident response.

    Hardening 24c — rate-limited per client IP. Exceeding the limit
    returns 429 and writes a ``rate_limited`` audit row but reveals no
    information about whether the credentials were valid.
    """
    client_ip, _ = _client_meta(request)
    per_minute = settings.login_rate_limit_per_minute
    if per_minute > 0:
        allowed, remaining = check_login(client_ip, per_minute)
        if not allowed:
            _audit(
                db,
                username=payload.username,
                outcome="rate_limited",
                request=request,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    "Too many login attempts. Try again in a minute."
                ),
                headers={"Retry-After": "60"},
            )

    user = db.query(User).filter_by(username=payload.username).one_or_none()

    if not user:
        _audit(
            db,
            username=payload.username,
            outcome="unknown_user",
            request=request,
        )
        # Generic message — never reveal whether the username exists.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    if not verify_password(payload.password, user.hashed_password):
        _audit(
            db,
            username=payload.username,
            outcome="bad_password",
            request=request,
            user_id=user.id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    if not user.is_active:
        _audit(
            db,
            username=payload.username,
            outcome="disabled",
            request=request,
            user_id=user.id,
        )
        raise HTTPException(403, "User is disabled")

    _audit(
        db,
        username=payload.username,
        outcome="success",
        request=request,
        user_id=user.id,
    )

    extra = {
        "role": _role_value(user.role),
        "username": user.username,
        "institution_id": user.institution_id,
    }
    access = create_access_token(subject=user.id, extra_claims=extra)
    refresh = create_refresh_token(subject=user.id, extra_claims=extra)
    return Token(
        access_token=access,
        refresh_token=refresh,
        user=UserOut.model_validate(user),
    )


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/refresh", response_model=Token)
def refresh(payload: RefreshRequest, request: Request, db: Session = Depends(get_db)):
    """Exchange a valid refresh token for a fresh access + refresh pair.

    Hardening 24b — short-lived access tokens + long-lived refresh
    tokens. The refresh token carries the same claims as the access
    token (``sub`` / ``role`` / ``username``) so the new access token
    doesn't require a fresh DB lookup, but we *do* verify the user is
    still active to prevent a revoked account from staying logged in.
    """
    try:
        claims = decode_token_with_type(payload.refresh_token, "refresh")
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    user_id = claims.get("sub")
    if not user_id or not str(user_id).isdigit():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token claims",
        )

    user = db.query(User).filter_by(id=int(user_id)).one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer exists",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    extra = {
        "role": _role_value(user.role),
        "username": user.username,
        "institution_id": user.institution_id,
    }
    new_access = create_access_token(subject=user.id, extra_claims=extra)
    new_refresh = create_refresh_token(subject=user.id, extra_claims=extra)
    return Token(
        access_token=new_access,
        refresh_token=new_refresh,
        user=UserOut.model_validate(user),
    )


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    """Return the authenticated user's profile."""
    return current_user