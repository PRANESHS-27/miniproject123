"""Admin user-management routes.

All endpoints require an authenticated admin. The matrix is enforced via
``require_permission("user", "manage")`` so a future role-based split
(e.g. an "operator" role) just adds itself to ``PERMISSIONS``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.permissions import require_permission
from app.core.security import hash_password
from app.db import get_db
from app.models import Role, User
from app.schemas.auth import UserOut

router = APIRouter(prefix="/api/admin/users", tags=["admin"])


class UserCreateAdmin(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: str = Field(min_length=3, max_length=255)
    full_name: Optional[str] = None
    password: str = Field(min_length=8)
    role: Role = Role.VIEWER
    is_active: bool = True


class UserUpdateAdmin(BaseModel):
    role: Optional[Role] = None
    is_active: Optional[bool] = None
    full_name: Optional[str] = None


@router.get("", response_model=None)
def list_users(
    db: Session = Depends(get_db),
    _: bool = Depends(require_permission("user", "manage")),  # type: ignore[arg-type]
    q: Optional[str] = Query(None, description="Username/email substring"),
    limit: int = Query(100, ge=1, le=500),
):
    from sqlalchemy import func, or_

    query = db.query(User)
    if q:
        like = f"%{q.lower()}%"
        query = query.filter(
            or_(
                func.lower(User.username).like(like),
                func.lower(User.email).like(like),
            )
        )
    rows = query.order_by(User.created_at.desc()).limit(limit).all()
    return [UserOut.model_validate(r) for r in rows]


@router.post("", response_model=UserOut, status_code=201)
def create_user(
    payload: UserCreateAdmin,
    db: Session = Depends(get_db),
    admin=Depends(require_permission("user", "manage")),
):
    """Admin creates a user (any role, including admin)."""
    if db.query(User).filter_by(username=payload.username).first():
        raise HTTPException(409, "Username already exists")
    if db.query(User).filter_by(email=payload.email).first():
        raise HTTPException(409, "Email already exists")

    user = User(
        username=payload.username,
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role=payload.role,
        is_active=payload.is_active,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    payload: UserUpdateAdmin,
    db: Session = Depends(get_db),
    admin=Depends(require_permission("user", "manage")),
):
    user = db.query(User).filter_by(id=user_id).one_or_none()
    if not user:
        raise HTTPException(404, "User not found")

    # Last-admin guard: don't let an admin demote themselves if they're the
    # only admin — that would lock the operator out.
    if payload.role is not None and payload.role != Role.ADMIN and user.role == Role.ADMIN:
        other_admins = (
            db.query(User)
            .filter(User.role == Role.ADMIN, User.id != user.id, User.is_active.is_(True))
            .count()
        )
        if other_admins == 0:
            raise HTTPException(
                status_code=400,
                detail="Cannot demote the last active admin.",
            )

    # Same guard for deactivate.
    if payload.is_active is False and user.role == Role.ADMIN and user.is_active:
        other_admins = (
            db.query(User)
            .filter(User.role == Role.ADMIN, User.id != user.id, User.is_active.is_(True))
            .count()
        )
        if other_admins == 0:
            raise HTTPException(
                status_code=400,
                detail="Cannot deactivate the last active admin.",
            )

    data = payload.model_dump(exclude_unset=True)
    for k, v in data.items():
        setattr(user, k, v)
    db.commit()
    db.refresh(user)
    return user


@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin=Depends(require_permission("user", "manage")),
):
    user = db.query(User).filter_by(id=user_id).one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    if user.id == admin.id:
        raise HTTPException(400, "Refusing to delete the currently signed-in admin.")
    # Last-admin guard.
    if user.role == Role.ADMIN:
        other_admins = (
            db.query(User)
            .filter(User.role == Role.ADMIN, User.id != user.id, User.is_active.is_(True))
            .count()
        )
        if other_admins == 0:
            raise HTTPException(400, "Cannot delete the last active admin.")
    db.delete(user)
    db.commit()
    return {"status": "ok", "user_id": user_id}