"""Per-request tenant context.

RBAC 22 / tenant isolation. Every tenant-scoped query needs to be
filtered by ``institution_id``. The filter is derived from:

  * the authenticated user's ``institution_id`` (everyone except
    ``SUPER_ADMIN``), or
  * the ``X-Institution-Id`` request header (only honoured for
    ``SUPER_ADMIN``; otherwise ignored).

This module provides:

  * a :class:`contextvars.ContextVar` for the *resolved* institution id
    so service-layer code (e.g. ``cve_index.refresh``) can read it
    without threading it through every function signature;
  * :func:`tenant_filter` — a one-call helper that applies the right
    WHERE / JOIN for a given SQLAlchemy model.

The ContextVar defaults to ``None``, which means "no filter" — the
super-admin cross-tenant path. ``get_tenant_context`` (in
``app/api/deps.py``) is the FastAPI dependency that resolves the
context for a request and returns the value; routers that want to
propagate to service-layer code call ``set_current_institution_id``
inside a ``try/finally`` with the reset token.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Optional

from sqlalchemy.orm import Query

from app.models import Asset

# Default ``None`` — "no filter" — is also the super-admin-without-header
# path. Service-layer code MUST treat ``None`` as "see everything".
_current_institution_id: ContextVar[Optional[int]] = ContextVar(
    "current_institution_id", default=None
)


def set_current_institution_id(value: Optional[int]) -> object:
    """Set the current request's institution id. Returns a reset token
    that MUST be passed to :func:`reset_current_institution_id` in a
    ``try/finally`` so per-request isolation is preserved even when the
    handler raises."""
    return _current_institution_id.set(value)


def reset_current_institution_id(token: object) -> None:
    _current_institution_id.reset(token)


def current_institution_id() -> Optional[int]:
    """Return the current institution id, or ``None`` if no filter."""
    return _current_institution_id.get()


def tenant_filter(
    query: Query,
    model,
    ctx: Optional[int] = None,
    asset_joined: bool = False,
) -> Query:
    """Apply WHERE/JOIN for institution scoping.

    Three modes:

    * **No context** (``None``) — super-admin with no header. Query is
      returned unchanged so the caller sees rows from every institution.
    * **Own-column** — model has its own ``institution_id`` column
      (User, Asset, Institution). Adds ``WHERE model.institution_id = ctx``.
    * **Via-Asset** — model is reachable via ``asset_id``
      (AssetTechnology, AssetFinding, AssetScan, AssetCveMatch,
      Finding). JOINs through Asset and adds ``WHERE assets.institution_id
      = ctx``. Pass ``asset_joined=True`` if the query already references
      ``Asset`` (e.g. via ``outerjoin(Asset, ...)``); this skips the JOIN
      to avoid ``ambiguous column name`` SQL errors.

    ``ctx`` is taken from the argument if supplied (preferred — avoids
    races between concurrent requests), otherwise from the per-request
    ContextVar set by ``set_current_institution_id``.
    """
    if ctx is None:
        ctx = _current_institution_id.get()
    if ctx is None:
        return query
    if hasattr(model, "institution_id"):
        return query.filter(model.institution_id == ctx)
    if asset_joined:
        return query.filter(Asset.institution_id == ctx)
    return query.join(Asset, Asset.id == model.asset_id).filter(
        Asset.institution_id == ctx
    )
