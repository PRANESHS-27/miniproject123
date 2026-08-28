"""FastAPI dependencies."""

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.core.permissions import is_super_admin
from app.core.security import decode_token
from app.db import get_db
from app.models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Decode JWT and return the user. Raises 401 on failure."""
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    disabled_exc = HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Account is disabled. Contact an administrator.",
    )
    try:
        payload = decode_token(token)
        user_id = payload.get("sub")
        if not user_id:
            raise credentials_exc
        # ``int(True) == 1`` and ``int('1.0') == 1`` are Python quirks that
        # we want to reject — only accept integer-shaped strings.
        if not str(user_id).isdigit():
            raise credentials_exc
        user = db.query(User).filter_by(id=int(user_id)).one_or_none()
        if not user:
            raise credentials_exc
        if not user.is_active:
            raise disabled_exc
        return user
    except JWTError:
        raise credentials_exc


def require_admin(user: User = Depends(get_current_user)) -> User:
    """Restrict a route to admins.

    The previous implementation re-used ``require_role`` by calling
    ``checker(user=user)``, but the inner ``_checker`` only declares
    ``current_user`` as a kwarg (it gets the user from ``Depends``,
    not from the caller). That call raised ``TypeError: ... got an
    unexpected keyword argument 'user'`` on every admin-only route.
    We do the role check inline here instead so admin routes stop
    500-ing.
    """
    from app.core.permissions import role_value

    if role_value(user) != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires the admin role.",
        )
    return user


# Local admin guard retained for the rare case where ``require_admin``
# is called outside FastAPI's Depends machinery.
def _is_admin(user: User) -> bool:
    role = user.role.value if hasattr(user.role, "value") else str(user.role)
    return role == "admin"


# Re-export the centralised permission dependency factory. Other modules
# historically imported it from this module; keep the import path stable.
from app.core.permissions import require_permission  # noqa: E402


def get_tenant_context(
    request: Request,
    user: User = Depends(get_current_user),
) -> int | None:
    """Resolve the institution id to scope this request to.

    Rules (per RBAC 22 decision):

      * ``SUPER_ADMIN`` + ``X-Institution-Id`` header → use that int.
      * ``SUPER_ADMIN`` + no header → ``None`` (no filter — see all).
      * Anyone else → ``user.institution_id``. The header is ignored.

    A non-integer header value is a 400 (the operator can't typo a
    request and accidentally see cross-tenant data).

    Side effect: also sets the per-request ContextVar so service-layer
    code that doesn't have direct access to ``ctx`` (e.g.
    ``cve_index.refresh``) can read the same value via
    :func:`app.db.tenant.current_institution_id`. ``anyio`` / FastAPI's
    sync ``run_in_threadpool`` runs each request in its own context, so
    the ContextVar is naturally request-scoped without manual reset.
    """
    from app.db.tenant import set_current_institution_id

    if is_super_admin(user):
        header_val = request.headers.get("X-Institution-Id")
        if not header_val:
            ctx: int | None = None
        else:
            try:
                ctx = int(header_val)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail="X-Institution-Id header must be an integer",
                )
        set_current_institution_id(ctx)
        return ctx
    # Non-super-admin — header ignored, always pinned to caller's institution.
    set_current_institution_id(user.institution_id)
    return user.institution_id