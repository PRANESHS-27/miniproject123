"""Role-based access control helpers — 4-tier institutional model.

The matrix lives in :data:`PERMISSIONS` so it's easy to audit. We use
route decorators (``require_permission``) plus a coarse-grained
``require_role`` for admin-only routes, rather than scattering role
checks throughout the codebase.

Tier hierarchy (top → bottom):

  SUPER_ADMIN
    └─ INSTITUTION_ADMIN
          └─ SECURITY_ANALYST
                └─ VIEWER

A higher tier implicitly grants all lower-tier permissions because of
:func:`_expand_with_inheritance` — the matrix only lists the **minimum**
tier, the function adds every tier below it. Adding a new permission
is therefore one line per (resource, action).
"""

from __future__ import annotations

from functools import wraps
from typing import Iterable

from fastapi import HTTPException, status

from app.models import (
    Role,
    SECURITY_ANALYST,
    TIER_INSTITUTION_ADMIN,
    TIER_SECURITY_ANALYST,
    TIER_SUPER_ADMIN,
    TIER_VIEWER,
    User,
    role_tier,
)


# ----- Permission matrix ---------------------------------------------------
# Each row is a (resource, action) tuple → the *minimum* tier required.
# Lower tiers do NOT have the permission; higher tiers + every tier
# in between (via the inheritance expansion) DO have it.
PERMISSIONS: dict[tuple[str, str], set[str]] = {
    # Dashboard / read-only data — every authenticated user.
    ("dashboard", "read"):          {TIER_VIEWER},
    ("vulnerability", "read"):      {TIER_VIEWER},
    ("asset", "read"):              {TIER_VIEWER},
    ("asset_finding", "read"):      {TIER_VIEWER},
    ("cve_match", "read"):          {TIER_VIEWER},
    ("search_log", "read"):         {TIER_VIEWER},
    ("finding", "read"):            {TIER_VIEWER},
    ("ai", "ask"):                  {TIER_VIEWER},

    # Analyst-tier (and above).
    ("asset", "scan"):              {TIER_SECURITY_ANALYST},
    ("asset_finding", "resolve"):   {TIER_SECURITY_ANALYST},
    ("finding", "update"):          {TIER_SECURITY_ANALYST},
    ("finding", "accept_risk"):     {TIER_SECURITY_ANALYST},
    ("report", "generate"):         {TIER_SECURITY_ANALYST},

    # Institution-admin tier (and above).
    ("asset", "create"):            {TIER_INSTITUTION_ADMIN},
    ("asset", "update"):            {TIER_INSTITUTION_ADMIN},
    ("asset", "delete"):            {TIER_INSTITUTION_ADMIN},
    ("sync", "trigger"):            {TIER_INSTITUTION_ADMIN},
    ("user", "manage"):             {TIER_INSTITUTION_ADMIN},

    # Super-admin only — cross-tenant operations.
    ("institution", "manage"):      {TIER_SUPER_ADMIN},
}


# Tier ordering — used by the inheritance expansion. Lower index ==
# lower privilege. Every higher-index tier inherits everything from
# lower tiers.
_TIER_ORDER = [
    TIER_VIEWER,
    TIER_SECURITY_ANALYST,
    TIER_INSTITUTION_ADMIN,
    TIER_SUPER_ADMIN,
]


def _expand_with_inheritance(allowed: set[str]) -> set[str]:
    """Expand ``allowed`` so every tier above each one is also allowed.

    Example: ``{TIER_VIEWER}`` becomes ``{TIER_VIEWER,
    TIER_SECURITY_ANALYST, TIER_INSTITUTION_ADMIN, TIER_SUPER_ADMIN}``.
    """
    out: set[str] = set()
    for tier in allowed:
        if tier not in _TIER_ORDER:
            out.add(tier)
            continue
        idx = _TIER_ORDER.index(tier)
        out.update(_TIER_ORDER[idx:])
    return out


# Pre-expand the matrix once at import time so runtime checks are O(1).
_EFFECTIVE_PERMISSIONS: dict[tuple[str, str], set[str]] = {
    key: _expand_with_inheritance(allowed)
    for key, allowed in PERMISSIONS.items()
}


def role_value(user: User) -> str:
    """Return the role as a plain string regardless of enum version.

    Prefer :func:`role_tier` for permission checks — this returns the raw
    enum value (e.g. ``"admin"``) which is only useful for logging.
    """
    return user.role.value if hasattr(user.role, "value") else str(user.role)


def user_tier(user: User) -> str:
    """Return the canonical tier name for the user (for the matrix)."""
    return role_tier(user.role)


def has_permission(user: User, resource: str, action: str) -> bool:
    allowed = _EFFECTIVE_PERMISSIONS.get((resource, action))
    if not allowed:
        # Unknown resource — fail closed.
        return False
    return user_tier(user) in allowed


def require_permission(resource: str, action: str):
    """FastAPI dependency factory — returns 403 when the user can't."""
    from fastapi import Depends
    from app.api.deps import get_current_user

    def _checker(current_user: User = Depends(get_current_user)):
        if not has_permission(current_user, resource, action):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"This action requires a higher privilege. "
                    f"Your role: {user_tier(current_user)}."
                ),
            )
        return current_user

    return _checker


def require_role(*roles: str):
    """Restrict a route to a fixed list of roles / tier names.

    Accepts both enum member names (``Role.ADMIN.name``) and tier
    names (``TIER_INSTITUTION_ADMIN``) — internally everything is
    normalised via :func:`role_tier`.
    """
    from fastapi import Depends
    from app.api.deps import get_current_user

    allowed: set[str] = {role_tier(r) for r in roles}

    def _checker(current_user: User = Depends(get_current_user)):
        if user_tier(current_user) not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires one of: {sorted(allowed)}.",
            )
        return current_user

    return _checker


def is_super_admin(user: User) -> bool:
    """True for ``super_admin`` tier. Useful for cross-tenant queries."""
    return user_tier(user) == TIER_SUPER_ADMIN