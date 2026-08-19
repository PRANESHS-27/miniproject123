"""Role-based access control helpers.

The matrix lives in ``PERMISSIONS`` so it's easy to audit. We use route
decorators (``require_permission``) plus a coarse-grained ``require_role``
for admin-only routes, rather than scattering role checks throughout the
codebase.
"""

from __future__ import annotations

from functools import wraps
from typing import Iterable

from fastapi import HTTPException, status

from app.models import Role, User


# ----- Permission matrix ---------------------------------------------------
# Each row is a (resource, action) tuple. The set contains every role
# allowed to perform that action. ``viewer`` is read-only by default —
# dashboard / search / assets / CVE detail. ``analyst`` adds scan / AI /
# finding resolve. ``admin`` is everything.
PERMISSIONS: dict[tuple[str, str], set[str]] = {
    # Dashboard / read-only data
    ("dashboard", "read"):     {"admin", "analyst", "viewer"},
    ("vulnerability", "read"): {"admin", "analyst", "viewer"},
    ("asset", "read"):         {"admin", "analyst", "viewer"},
    ("asset_finding", "read"): {"admin", "analyst", "viewer"},
    ("cve_match", "read"):     {"admin", "analyst", "viewer"},
    ("search_log", "read"):    {"admin", "analyst", "viewer"},

    # Analyst-level mutations
    ("asset", "scan"):         {"admin", "analyst"},
    ("asset_finding", "resolve"): {"admin", "analyst"},
    ("ai", "ask"):             {"admin", "analyst", "viewer"},
    ("report", "generate"):    {"admin"},

    # Admin-only
    ("asset", "create"):       {"admin"},
    ("asset", "update"):       {"admin"},
    ("asset", "delete"):       {"admin"},
    ("sync", "trigger"):       {"admin"},
    ("user", "manage"):        {"admin"},
}


def role_value(user: User) -> str:
    """Return the role as a plain string regardless of enum version."""
    return user.role.value if hasattr(user.role, "value") else str(user.role)


def has_permission(user: User, resource: str, action: str) -> bool:
    allowed = PERMISSIONS.get((resource, action))
    if not allowed:
        # Unknown resource — fail closed.
        return False
    return role_value(user) in allowed


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
                    f"Your role: {role_value(current_user)}."
                ),
            )
        return current_user

    return _checker


def require_role(*roles: str):
    """Restrict a route to a fixed list of roles. ``require_admin`` is
    sugar for ``require_role('admin')``."""
    from fastapi import Depends
    from app.api.deps import get_current_user

    allowed: set[str] = set(roles)

    def _checker(current_user: User = Depends(get_current_user)):
        if role_value(current_user) not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires one of: {sorted(allowed)}.",
            )
        return current_user

    return _checker