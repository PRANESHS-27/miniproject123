"""FastAPI dependencies."""

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.orm import Session

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
    """Restrict a route to admins. Delegates to the central matrix."""
    from app.core.permissions import require_role
    # Re-use the central matrix so a single role-name rename touches
    # only one place. We still expose ``require_admin`` here for
    # backwards compatibility with existing routes.
    checker = require_role("admin")
    return checker(user=user)


# Local admin guard retained for the rare case where ``require_admin``
# is called outside FastAPI's Depends machinery.
def _is_admin(user: User) -> bool:
    role = user.role.value if hasattr(user.role, "value") else str(user.role)
    return role == "admin"


# Re-export the centralised permission dependency factory. Other modules
# historically imported it from this module; keep the import path stable.
from app.core.permissions import require_permission  # noqa: E402