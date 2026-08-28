"""Pydantic schemas for the Risk Engine Finding workflow.

A Finding is the engine's primary output — one row per (asset, CVE)
pair the engine has produced a risk score for. Findings are the unit
the UI works with on the Findings page and the unit the dashboard
counts.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------
class FindingUpdate(BaseModel):
    """Patch payload for an analyst working a finding.

    All fields are optional. The router enforces the state machine
    (open → in_progress → verified → resolved, plus accepted_risk as a
    terminal state that requires a non-empty ``notes`` field).
    """

    status: Optional[str] = None
    assigned_to_id: Optional[int] = None
    due_date: Optional[datetime] = None
    notes: Optional[str] = None

    @field_validator("status")
    @classmethod
    def _check_status(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        u = v.strip().lower()
        if u not in {"open", "in_progress", "verified", "resolved", "accepted_risk"}:
            raise ValueError(
                f"status must be one of open/in_progress/verified/resolved/accepted_risk (got {v!r})"
            )
        return u


class AcceptRiskRequest(BaseModel):
    """Terminal-state payload: a finding is being consciously accepted
    as a known risk instead of remediated. Requires a reason so the
    decision is auditable."""

    reason: str = Field(min_length=1, max_length=2000)


# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset_id: int
    vulnerability_cve_id: str
    technology_id: Optional[int] = None

    risk_score: int
    risk_label: str
    risk_contributions: Optional[dict] = None

    status: str
    assigned_to_id: Optional[int] = None
    due_date: Optional[datetime] = None
    notes: Optional[str] = None
    source: str

    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None

    # Optional join fields populated by the router for list/detail
    # responses so the UI does not have to do N+1 GETs.
    asset_label: Optional[str] = None
    asset_url: Optional[str] = None
    cve_title: Optional[str] = None
    cve_severity: Optional[str] = None
    cve_cvss_v3_score: Optional[float] = None
    assigned_to_username: Optional[str] = None


class FindingListResponse(BaseModel):
    items: list[FindingOut]
    total: int
    page: int
    page_size: int


class FindingStats(BaseModel):
    """Counts the dashboard / Findings page filter bar consumes."""

    total: int = 0
    by_label: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    by_asset: list[dict] = Field(default_factory=list)
    # The dashboard headline: how many findings are open AND scored
    # HIGH or CRITICAL — the "act on these today" queue.
    open_high_or_critical: int = 0
    kev_open: int = 0
