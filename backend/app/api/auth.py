"""Authentication routes: register, login, /me."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.security import create_access_token, hash_password, verify_password
from app.db import get_db
from app.models import Role, User
from app.schemas.auth import LoginRequest, Token, UserCreate, UserOut

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _role_value(r) -> str:
    return r.value if hasattr(r, "value") else str(r)


@router.post("/register", response_model=Token, status_code=201)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    """Create a new user.

    - If this is the **first** user, the role is forced to admin regardless
      of what the request said.
    - For every subsequent registration, the requested role must be valid;
      self-promotion to ``admin`` from an unauthenticated request is denied
      (admins must create other admins via ``/api/admin/users``).
    """
    if db.query(User).filter_by(username=payload.username).first():
        raise HTTPException(409, "Username already exists")
    if db.query(User).filter_by(email=payload.email).first():
        raise HTTPException(409, "Email already exists")

    requested = payload.role or Role.VIEWER
    is_first_user = db.query(User).count() == 0
    if is_first_user:
        role = Role.ADMIN
    else:
        role = requested
        if role == Role.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Self-registration as admin is not allowed. Ask an existing admin.",
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

    token = create_access_token(
        subject=user.id,
        extra_claims={"role": _role_value(user.role), "username": user.username},
    )
    return Token(access_token=token, user=UserOut.model_validate(user))


@router.post("/login", response_model=Token)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    """Validate credentials and return a JWT."""
    user = db.query(User).filter_by(username=payload.username).one_or_none()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    if not user.is_active:
        raise HTTPException(403, "User is disabled")

    token = create_access_token(
        subject=user.id,
        extra_claims={"role": _role_value(user.role), "username": user.username},
    )
    return Token(access_token=token, user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    """Return the authenticated user's profile."""
    return current_user
