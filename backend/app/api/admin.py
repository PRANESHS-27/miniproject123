"""Admin user-management routes.

All endpoints require an authenticated user with the ``user.manage``
permission (INSTITUTION_ADMIN tier or above). The matrix is enforced
via ``require_permission`` so a future role-based split just adds itself
to ``PERMISSIONS``.

The 4-tier role model (RBAC 23) — ``SUPER_ADMIN``, ``INSTITUTION_ADMIN``,
``SECURITY_ANALYST``, ``VIEWER`` — is enforced on creation and update:

  * Only ``SUPER_ADMIN`` can grant or modify the ``SUPER_ADMIN`` tier.
  * ``INSTITUTION_ADMIN`` can grant ``INSTITUTION_ADMIN`` /
    ``SECURITY_ANALYST`` / ``VIEWER`` but not ``SUPER_ADMIN``.
  * Self-demotion is allowed but blocked if it would leave the system
    with zero privileged users.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_tenant_context
from app.core.logging_config import get_logger
from app.core.permissions import (
    is_super_admin,
    require_permission,
    user_tier,
)
from app.core.security import hash_password
from app.db import get_db
from app.db.tenant import tenant_filter
from app.models import (
    DEFAULT_INSTITUTION_ID,
    Role,
    TIER_INSTITUTION_ADMIN,
    TIER_SUPER_ADMIN,
    User,
    role_tier,
)
from app.schemas.auth import UserOut

log = get_logger("admin")

router = APIRouter(prefix="/api/admin/users", tags=["admin"])


# Roles considered "privileged" — they can manage users. Both
# INSTITUTION_ADMIN and its legacy alias ADMIN qualify.
_PRIVILEGED_ROLES = [
    Role.SUPER_ADMIN,
    Role.INSTITUTION_ADMIN,
    Role.ADMIN,  # legacy alias → institution_admin tier
]


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


def _assert_can_grant_role(actor: User, target_role: Role) -> None:
    """Refuse to grant SUPER_ADMIN unless the actor is SUPER_ADMIN."""
    if role_tier(target_role) == TIER_SUPER_ADMIN and not is_super_admin(actor):
        raise HTTPException(
            status_code=403,
            detail="Granting the SUPER_ADMIN role requires a SUPER_ADMIN actor.",
        )


@router.get("", response_model=None)
def list_users(
    db: Session = Depends(get_db),
    _: User = Depends(require_permission("user", "manage")),  # type: ignore[arg-type]
    ctx: int | None = Depends(get_tenant_context),
    q: Optional[str] = Query(None, description="Username/email substring"),
    limit: int = Query(100, ge=1, le=500),
):
    """List users visible to the caller.

    RBAC 22 — INSTITUTION_ADMIN sees only users in their own institution;
    SUPER_ADMIN sees all (or one institution if ``X-Institution-Id``
    header was sent).
    """
    from sqlalchemy import func, or_

    query = tenant_filter(db.query(User), User, ctx=ctx)
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
    actor: User = Depends(require_permission("user", "manage")),  # type: ignore[arg-type]
    ctx: int | None = Depends(get_tenant_context),
):
    """Admin creates a user (any role up to actor's tier).

    RBAC 22 — the new user is placed in the caller's institution unless
    the actor is SUPER_ADMIN with an ``X-Institution-Id`` header
    targeting a different one. SUPER_ADMIN without a header creates
    into the default Acme institution (with a warning logged).
    """
    _assert_can_grant_role(actor, payload.role)

    if db.query(User).filter_by(username=payload.username).first():
        raise HTTPException(409, "Username already exists")
    if db.query(User).filter_by(email=payload.email).first():
        raise HTTPException(409, "Email already exists")

    # Resolve target institution.
    if ctx is not None:
        target_inst = ctx
    else:
        # SUPER_ADMIN without a header — fall back to default institution.
        if is_super_admin(actor):
            log.warning(
                "Super admin '%s' created user without X-Institution-Id header; "
                "defaulting to institution_id=%d.",
                actor.username,
                DEFAULT_INSTITUTION_ID,
            )
            target_inst = DEFAULT_INSTITUTION_ID
        else:
            # Non-super-admin without ctx — impossible by construction
            # (``get_tenant_context`` always returns user.institution_id
            # for non-super-admin), but be defensive.
            target_inst = actor.institution_id

    user = User(
        username=payload.username,
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role=payload.role,
        is_active=payload.is_active,
        institution_id=target_inst,
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
    actor: User = Depends(require_permission("user", "manage")),  # type: ignore[arg-type]
    ctx: int | None = Depends(get_tenant_context),
):
    user = tenant_filter(db.query(User).filter_by(id=user_id), User, ctx=ctx).one_or_none()
    if not user:
        raise HTTPException(404, "User not found")

    if payload.role is not None:
        _assert_can_grant_role(actor, payload.role)

    # Last-privileged-user guard. Counts privileged users within the
    # caller's tenant scope (so an INSTITUTION_ADMIN's demotion is only
    # blocked if their institution would become admin-less).
    user_tier_now = user_tier(user)
    is_priv_now = user_tier_now in {TIER_INSTITUTION_ADMIN, TIER_SUPER_ADMIN}

    will_lose_priv = False
    if is_priv_now:
        if payload.role is not None and role_tier(payload.role) not in {
            TIER_INSTITUTION_ADMIN,
            TIER_SUPER_ADMIN,
        }:
            will_lose_priv = True
        elif payload.is_active is False and user.is_active:
            will_lose_priv = True

    if will_lose_priv:
        priv_q = db.query(User).filter(
            User.id != user.id,
            User.is_active.is_(True),
            User.role.in_(_PRIVILEGED_ROLES),
        )
        priv_q = tenant_filter(priv_q, User, ctx=ctx)
        other_priv = priv_q.count()
        if other_priv == 0:
            raise HTTPException(
                status_code=400,
                detail="Cannot demote or deactivate the last privileged user.",
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
    actor: User = Depends(require_permission("user", "manage")),  # type: ignore[arg-type]
    ctx: int | None = Depends(get_tenant_context),
):
    user = tenant_filter(db.query(User).filter_by(id=user_id), User, ctx=ctx).one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    if user.id == actor.id:
        raise HTTPException(400, "Refusing to delete the currently signed-in user.")
    # Last-privileged-user guard (tenant-scoped).
    if role_tier(user.role) in {TIER_INSTITUTION_ADMIN, TIER_SUPER_ADMIN}:
        priv_q = db.query(User).filter(
            User.id != user.id,
            User.is_active.is_(True),
            User.role.in_(_PRIVILEGED_ROLES),
        )
        priv_q = tenant_filter(priv_q, User, ctx=ctx)
        other_priv = priv_q.count()
        if other_priv == 0:
            raise HTTPException(400, "Cannot delete the last privileged user.")
    db.delete(user)
    db.commit()
    return {"status": "ok", "user_id": user_id}
