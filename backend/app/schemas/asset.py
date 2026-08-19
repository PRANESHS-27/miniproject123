"""Pydantic schemas for the asset-driven monitoring feature."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------
class AssetCreate(BaseModel):
    label: str = Field(min_length=1, max_length=128)
    url: str = Field(min_length=4, max_length=512)
    env: str = Field(default="production")
    tags: list[str] = Field(default_factory=list)

    @field_validator("env")
    @classmethod
    def _check_env(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if v not in {"production", "staging", "development"}:
            # Surface the bad value rather than silently coercing to
            # "production" — silent coercion makes typos invisible.
            raise ValueError(
                f"env must be one of production/staging/development (got {v!r})"
            )
        return v

    @field_validator("url")
    @classmethod
    def _canonicalise_url(cls, v: str) -> str:
        u = (v or "").strip().rstrip("/")
        if not (u.startswith("http://") or u.startswith("https://")):
            u = "https://" + u
        # After prepending the scheme, re-parse to confirm the result is
        # a valid http(s) URL. Rejects payloads like ``javascript:...``,
        # ``file:///etc/passwd`` or ``data:...`` that the simple prefix
        # check alone would accept and turn into nonsense.
        from urllib.parse import urlparse
        parsed = urlparse(u)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"URL must be a valid http(s) URL: {v!r}")
        return u


class AssetUpdate(BaseModel):
    label: Optional[str] = None
    url: Optional[str] = None
    env: Optional[str] = None
    is_active: Optional[bool] = None
    tags: Optional[list[str]] = None

    @field_validator("url")
    @classmethod
    def _canonicalise_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        u = v.strip().rstrip("/")
        if not (u.startswith("http://") or u.startswith("https://")):
            u = "https://" + u
        from urllib.parse import urlparse
        parsed = urlparse(u)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"URL must be a valid http(s) URL: {v!r}")
        return u


# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
class AssetTechnologyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    vendor: str
    product: str
    version: Optional[str] = None
    source: str
    confidence: float
    detected_at: datetime


class AssetFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    finding_type: str
    severity: str
    title: str
    details: Optional[dict] = None
    remediation: Optional[str] = None
    discovered_at: datetime
    resolved_at: Optional[datetime] = None
    last_seen_at: datetime


class AssetScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset_id: int
    started_at: datetime
    finished_at: Optional[datetime] = None
    items_found: int
    inserted_count: int = 0
    re_seen_count: int = 0
    closed_count: int = 0
    technologies_detected: int
    cves_matched: int
    status: str
    error: Optional[str] = None
    triggered_by: str


class AssetCveMatchOut(BaseModel):
    cve_id: str
    matched_at: datetime
    technology_vendor: Optional[str] = None
    technology_product: Optional[str] = None
    cve_severity: Optional[str] = None
    cve_cvss_v3_score: Optional[float] = None
    cve_title: Optional[str] = None


class AssetListItem(BaseModel):
    # NOTE: do NOT enable ``from_attributes`` — ``open_findings_count``,
    # ``critical_findings_count`` and ``cves_matched_count`` are computed
    # properties built by ``_asset_to_list_item``, not ORM columns.
    # Pydantic would otherwise try to read them off the Asset and crash.
    id: int
    label: str
    url: str
    env: str
    is_active: bool
    tags: Optional[list] = None
    created_at: datetime
    last_scanned_at: Optional[datetime] = None
    last_scan_status: Optional[str] = None
    open_findings_count: int = 0
    critical_findings_count: int = 0
    cves_matched_count: int = 0


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    label: str
    url: str
    env: str
    is_active: bool
    tags: Optional[list] = None
    created_at: datetime
    last_scanned_at: Optional[datetime] = None
    last_scan_status: Optional[str] = None
    technologies: list[AssetTechnologyOut] = Field(default_factory=list)
    open_findings_count: int = 0
    critical_findings_count: int = 0
    cves_matched_count: int = 0


class AssetStats(BaseModel):
    total_assets: int = 0
    active_assets: int = 0
    open_findings: int = 0
    critical_findings: int = 0
    cves_affecting_us: int = 0
    assets_with_critical: int = 0
    findings_by_type: dict[str, int] = Field(default_factory=dict)
    tech_distribution_top: list[dict] = Field(default_factory=list)


class AssetFindingResolve(BaseModel):
    resolved: bool = True


class ScanTriggerResponse(BaseModel):
    status: str = "started"
    job: str
    asset_id: int
    message: str = ""