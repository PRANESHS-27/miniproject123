"""Institutions / multi-tenancy management API router."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import (
    get_current_user,
    get_tenant_context,
    require_permission,
    require_super_admin,
)
from app.db import get_db
from app.models import (
    DEFAULT_INSTITUTION_ID,
    Institution,
    Role,
    User,
    role_tier,
    TIER_SUPER_ADMIN,
)

router = APIRouter(prefix="/api/institutions", tags=["institutions"])


class InstitutionCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    slug: str = Field(..., min_length=2, max_length=64)
    settings: Optional[dict[str, Any]] = None


class InstitutionUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=128)
    settings: Optional[dict[str, Any]] = None
    is_active: Optional[bool] = None


@router.get("")
def list_institutions(
    db: Session = Depends(get_db),
    user: User = Depends(require_super_admin),
) -> list[dict[str, Any]]:
    """List all institutions (Super-Admin only)."""
    rows = db.query(Institution).order_by(Institution.id).all()
    return [
        {
            "id": inst.id,
            "name": inst.name,
            "slug": inst.slug,
            "is_active": inst.is_active,
            "settings": inst.settings or {},
            "created_at": inst.created_at.isoformat() if inst.created_at else None,
        }
        for inst in rows
    ]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_institution(
    payload: InstitutionCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_super_admin),
) -> dict[str, Any]:
    """Create a new institution tenant (Super-Admin only)."""
    clean_slug = payload.slug.strip().lower()
    if db.query(Institution).filter_by(slug=clean_slug).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Institution slug '{clean_slug}' already exists",
        )

    inst = Institution(
        name=payload.name.strip(),
        slug=clean_slug,
        settings=payload.settings or {},
        is_active=True,
    )
    db.add(inst)
    db.commit()
    db.refresh(inst)
    return {
        "id": inst.id,
        "name": inst.name,
        "slug": inst.slug,
        "is_active": inst.is_active,
        "settings": inst.settings or {},
        "created_at": inst.created_at.isoformat() if inst.created_at else None,
    }


@router.get("/current")
def get_current_institution(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    ctx: int | None = Depends(get_tenant_context),
) -> dict[str, Any]:
    """Get the current institution context for the active user."""
    inst_id = ctx or user.institution_id or DEFAULT_INSTITUTION_ID
    inst = db.query(Institution).filter_by(id=inst_id).first()
    if not inst:
        raise HTTPException(status_code=404, detail="Institution not found")
    return {
        "id": inst.id,
        "name": inst.name,
        "slug": inst.slug,
        "is_active": inst.is_active,
        "settings": inst.settings or {},
        "created_at": inst.created_at.isoformat() if inst.created_at else None,
    }


@router.get("/{inst_id}")
def get_institution(
    inst_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Retrieve institution by ID. Restricted to super-admins or members of that institution."""
    if role_tier(user.role) != TIER_SUPER_ADMIN and user.institution_id != inst_id:
        raise HTTPException(status_code=403, detail="Forbidden: cannot access another institution")

    inst = db.query(Institution).filter_by(id=inst_id).first()
    if not inst:
        raise HTTPException(status_code=404, detail="Institution not found")
    return {
        "id": inst.id,
        "name": inst.name,
        "slug": inst.slug,
        "is_active": inst.is_active,
        "settings": inst.settings or {},
        "created_at": inst.created_at.isoformat() if inst.created_at else None,
    }


@router.patch("/{inst_id}")
def update_institution(
    inst_id: int,
    payload: InstitutionUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("user", "manage")),
) -> dict[str, Any]:
    """Update institution settings. Permitted for super-admins or institution admins."""
    if role_tier(user.role) != TIER_SUPER_ADMIN and user.institution_id != inst_id:
        raise HTTPException(status_code=403, detail="Forbidden: cannot edit another institution")

    inst = db.query(Institution).filter_by(id=inst_id).first()
    if not inst:
        raise HTTPException(status_code=404, detail="Institution not found")

    if payload.name is not None:
        inst.name = payload.name.strip()
    if payload.settings is not None:
        merged = dict(inst.settings or {})
        merged.update(payload.settings)
        inst.settings = merged
    if payload.is_active is not None and role_tier(user.role) == TIER_SUPER_ADMIN:
        inst.is_active = payload.is_active

    db.commit()
    db.refresh(inst)
    return {
        "id": inst.id,
        "name": inst.name,
        "slug": inst.slug,
        "is_active": inst.is_active,
        "settings": inst.settings or {},
        "created_at": inst.created_at.isoformat() if inst.created_at else None,
    }
