"""SQLAlchemy ORM models."""

import enum
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.core.time import UtcDateTime, utcnow_naive
from app.db.session import Base


class Role(str, enum.Enum):
    """User role for RBAC — 4-tier institutional model.

    Tier hierarchy (top → bottom):

      SUPER_ADMIN
        └─ INSTITUTION_ADMIN
              └─ SECURITY_ANALYST
                    └─ VIEWER

    Backward compatibility: the existing ``admin`` / ``analyst`` /
    ``viewer`` string values are preserved. ``SUPER_ADMIN`` and
    ``INSTITUTION_ADMIN`` are new values. ``SECURITY_ANALYST`` is the
    canonical name for the analyst tier; it shares the wire value
    ``"analyst"`` with the legacy ``ANALYST`` member, but the legacy
    member is what the enum exposes on the wire for already-stored
    user rows. :func:`normalize_role` maps both to the same canonical
    tier for permission checks.
    """

    SUPER_ADMIN = "super_admin"
    INSTITUTION_ADMIN = "institution_admin"
    ANALYST = "analyst"  # legacy wire value
    SECURITY_ANALYST = "security_analyst"  # canonical wire value
    VIEWER = "viewer"
    # Legacy "admin" — wire value preserved for backward compatibility.
    # Semantically equal to INSTITUTION_ADMIN; ``normalize_role`` maps.
    ADMIN = "admin"


# Canonical tier names for permission checks. The string is what the
# permissions matrix uses; it does not have to match a Role enum member.
TIER_SUPER_ADMIN = "super_admin"
TIER_INSTITUTION_ADMIN = "institution_admin"
TIER_SECURITY_ANALYST = "security_analyst"  # canonical for "analyst"
TIER_VIEWER = "viewer"

# Map of Role enum value → canonical tier name.
_ROLE_TO_TIER: dict[str, str] = {
    Role.SUPER_ADMIN.value: TIER_SUPER_ADMIN,
    Role.INSTITUTION_ADMIN.value: TIER_INSTITUTION_ADMIN,
    Role.ADMIN.value: TIER_INSTITUTION_ADMIN,  # legacy alias
    Role.ANALYST.value: TIER_SECURITY_ANALYST,
    Role.SECURITY_ANALYST.value: TIER_SECURITY_ANALYST,
    Role.VIEWER.value: TIER_VIEWER,
}


def role_tier(role_or_value) -> str:
    """Return the canonical tier name for a Role (or its string value).

    Used by the permission matrix so the matrix keys are tier names,
    not enum members, which means a future role split (e.g. ``auditor``)
    can be slotted in by adding a row to ``_ROLE_TO_TIER`` instead of
    touching every entry of the matrix.
    """
    val = role_or_value.value if hasattr(role_or_value, "value") else str(role_or_value)
    return _ROLE_TO_TIER.get(val, val)


# Backward-compatibility alias for new-code imports. ``Role.ANALYST``
# remains the canonical name; ``SECURITY_ANALYST`` is the friendly alias
# used in the new permission matrix / frontend.
SECURITY_ANALYST = "security_analyst"  # canonical tier name (matches TIER_*)


class Severity(str, enum.Enum):
    """CVSS severity buckets."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class AssetCriticality(str, enum.Enum):
    """Operator-declared business criticality of an asset.

    Drives the Risk Engine weight — see :mod:`app.services.risk`. The
    string values must match the constants the RiskScorer accepts
    (``LOW`` / ``MEDIUM`` / ``HIGH`` / ``CRITICAL``).
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingStatus(str, enum.Enum):
    """Lifecycle states of a (CVE, asset) finding.

    State machine: ``open`` is the only state created by the engine. An
    analyst moves it to ``in_progress`` when remediation starts,
    ``verified`` once the patch is confirmed, and ``resolved`` on
    closure. ``accepted_risk`` is a terminal state that requires a
    reason (stored on ``Finding.notes``).
    """

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    VERIFIED = "verified"
    RESOLVED = "resolved"
    ACCEPTED_RISK = "accepted_risk"


class FindingRiskLabel(str, enum.Enum):
    """Cached risk label — the engine produces ``INFO`` / ``LOW`` /
    ``MEDIUM`` / ``HIGH`` / ``CRITICAL``. We store the string rather
    than the score's bucketing logic so the UI can group by it without
    re-running the scorer."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ===========================================================================
# Tenancy
# ===========================================================================
# Every ``User`` and ``Asset`` row belongs to exactly one institution.
# CVE/Vulnerability and NVD/KEV SyncRun rows are global (cross-tenant by
# definition) and carry no institution_id.
#
# ``server_default=text("1")`` on the FK columns is the single decision
# that keeps the 151 existing test fixtures green — it backfills the
# default Acme institution on INSERTs that don't specify it, so existing
# ``User(username=..., role=..., ...)`` calls in tests continue to
# succeed without edits.

# ID assigned to the bootstrap institution. Idempotent at boot via
# ``_bootstrap_default_institution`` in app/main.py.
DEFAULT_INSTITUTION_ID = 1


class Institution(Base):
    """A tenant — one institution per row.

    RBAC 22 / institution isolation. Every User and Asset belongs to an
    institution; the data layer filters tenant-scoped queries by
    ``institution_id``. ``SUPER_ADMIN`` retains cross-tenant reach via
    the ``X-Institution-Id`` request header; everyone else is
    hard-isolated to their own institution.
    """

    __tablename__ = "institutions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    # Free-form per-tenant knobs (rate limits, AI providers, etc.).
    settings: Mapped[dict | None] = mapped_column(JSON)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow_naive, nullable=False)

    users: Mapped[list["User"]] = relationship(back_populates="institution")
    assets: Mapped[list["Asset"]] = relationship(back_populates="institution")


# ===========================================================================
# Users & Audit
# ===========================================================================
class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str | None] = mapped_column(String(128))
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.VIEWER)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow_naive)

    # RBAC 22 — every user belongs to exactly one institution.
    # ``server_default=text("1")`` lets existing test fixtures construct
    # ``User(...)`` without specifying ``institution_id`` and still
    # attach to the default Acme institution.
    institution_id: Mapped[int] = mapped_column(
        ForeignKey("institutions.id"),
        nullable=False,
        index=True,
        server_default=text(str(DEFAULT_INSTITUTION_ID)),
    )

    search_logs: Mapped[list["SearchLog"]] = relationship(back_populates="user")
    # Reverse of Asset.owner — needed so the back-populate reference above
    # resolves cleanly. ``cascade="all, delete-orphan"`` would orphan
    # SearchLogs on user deletion; we keep ``search_logs`` nullable so
    # user deletion is allowed (logs survive with ``user_id=NULL``).
    owned_assets: Mapped[list["Asset"]] = relationship(
        back_populates="owner", foreign_keys="Asset.owner_id"
    )
    institution: Mapped["Institution"] = relationship(back_populates="users")


class SearchLog(Base):
    __tablename__ = "search_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    query: Mapped[str] = mapped_column(Text)
    result_count: Mapped[int] = mapped_column(Integer, default=0)
    source: Mapped[str] = mapped_column(String(32), default="sql")  # sql | rag
    created_at: Mapped[datetime] = mapped_column(
        UtcDateTime, default=utcnow_naive, index=True
    )

    user: Mapped[User | None] = relationship(back_populates="search_logs")


class LoginAudit(Base):
    """One row per login attempt (success or failure).

    Security hardening 24b — a security incident response starts with
    "who logged in, when, from where, and was it successful". This table
    is append-only: we never delete or modify rows. We do not store the
    password or its hash (obviously) — just enough metadata to support
    both forensic queries and the rate-limit cache.

    The ``outcome`` column is one of: ``success`` | ``bad_password`` |
    ``unknown_user`` | ``disabled`` | ``rate_limited`` | ``error``.
    """

    __tablename__ = "login_audit"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    username: Mapped[str] = mapped_column(String(64), index=True)
    outcome: Mapped[str] = mapped_column(String(32), index=True)
    ip: Mapped[str | None] = mapped_column(String(64), index=True)
    user_agent: Mapped[str | None] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(
        UtcDateTime, default=utcnow_naive, index=True
    )

    user: Mapped[User | None] = relationship()


# ===========================================================================
# Vulnerabilities
# ===========================================================================
class Vulnerability(Base):
    """A single CVE / vulnerability record."""

    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    title: Mapped[str | None] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    published: Mapped[datetime | None] = mapped_column(UtcDateTime, index=True)
    last_modified: Mapped[datetime | None] = mapped_column(UtcDateTime)

    cvss_v3_score: Mapped[float | None] = mapped_column(Float, index=True)
    cvss_v3_vector: Mapped[str | None] = mapped_column(String(128))
    cvss_v2_score: Mapped[float | None] = mapped_column(Float)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity), default=Severity.UNKNOWN, index=True
    )

    # JSON fields keep the schema flexible for NVD's evolving payload
    affected_products: Mapped[list | None] = mapped_column(JSON)
    references: Mapped[list | None] = mapped_column(JSON)
    cwe_ids: Mapped[list | None] = mapped_column(JSON)

    # CISA KEV flags
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    kev_due_date: Mapped[datetime | None] = mapped_column(UtcDateTime)
    kev_added_at: Mapped[datetime | None] = mapped_column(UtcDateTime)

    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow_naive)
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime, default=utcnow_naive, onupdate=utcnow_naive
    )

    __table_args__ = (
        Index("ix_vuln_severity_published", "severity", "published"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "cve_id": self.cve_id,
            "title": self.title,
            "description": self.description,
            "published": self.published.isoformat() if self.published else None,
            "last_modified": self.last_modified.isoformat()
            if self.last_modified
            else None,
            "cvss_v3_score": self.cvss_v3_score,
            "cvss_v3_vector": self.cvss_v3_vector,
            "severity": self.severity.value if self.severity else None,
            "affected_products": self.affected_products or [],
            "references": self.references or [],
            "cwe_ids": self.cwe_ids or [],
            "in_kev": self.in_kev,
            "kev_due_date": self.kev_due_date.isoformat() if self.kev_due_date else None,
        }


class SyncRun(Base):
    """Audit row for each scheduler fetch — handy for ops dashboards."""

    __tablename__ = "sync_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(32))  # nvd | kev
    started_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow_naive)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    items_fetched: Mapped[int] = mapped_column(Integer, default=0)
    items_inserted: Mapped[int] = mapped_column(Integer, default=0)
    items_updated: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), default="running")
    error: Mapped[str | None] = mapped_column(Text)


# ===========================================================================
# Asset-driven monitoring
# ===========================================================================
class FindingType(str, enum.Enum):
    """Type of finding a scanner emits."""

    TLS = "tls"
    HEADER = "header"
    ADMIN_PATH = "admin_path"
    JS_LIB = "js_lib"
    CVE = "cve"


class SeverityLevel(str, enum.Enum):
    """Severity scale for asset findings — independent of CVE Severity so
    they can evolve separately."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class Asset(Base):
    """A company-owned website we monitor."""

    __tablename__ = "assets"

    # RBAC 22 — URL is unique per institution (not globally). Two
    # institutions can host the same URL.
    __table_args__ = (
        Index(
            "ux_assets_institution_url",
            "institution_id",
            "url",
            unique=True,
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    label: Mapped[str] = mapped_column(String(128))
    url: Mapped[str] = mapped_column(String(512))
    env: Mapped[str] = mapped_column(String(32), default="production")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    tags: Mapped[list | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow_naive)
    last_scanned_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    last_scan_status: Mapped[str | None] = mapped_column(String(32))

    # RBAC 22 — every asset belongs to exactly one institution. The
    # composite unique ``(institution_id, url)`` replaces the global
    # ``Asset.url`` unique — same-tenant dupes still 409, but two
    # institutions can legitimately host the same URL. See
    # ``_apply_schema_patches`` in app/main.py for the migration.
    institution_id: Mapped[int] = mapped_column(
        ForeignKey("institutions.id"),
        nullable=False,
        index=True,
        server_default=text(str(DEFAULT_INSTITUTION_ID)),
    )

    # Risk Engine inputs. Both default to the conservative end (LOW
    # criticality, no internet exposure) so an existing asset that has
    # not been triaged does not silently inflate the dashboard.
    criticality: Mapped[AssetCriticality] = mapped_column(
        Enum(AssetCriticality),
        default=AssetCriticality.LOW,
        index=True,
    )
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    technologies: Mapped[list["AssetTechnology"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    findings: Mapped[list["AssetFinding"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    scans: Mapped[list["AssetScan"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    cve_matches: Mapped[list["AssetCveMatch"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    # Reverse relationship to the User who owns this asset. Previously
    # only the FK existed, so ``asset.owner`` raised at runtime.
    owner: Mapped["User | None"] = relationship(
        "User", foreign_keys=[owner_id], back_populates="owned_assets"
    )
    institution: Mapped["Institution"] = relationship(back_populates="assets")


class AssetTechnology(Base):
    """A single detected tech on an asset — the bridge to NVD CPEs."""

    __tablename__ = "asset_technologies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    vendor: Mapped[str] = mapped_column(String(128), index=True)
    product: Mapped[str] = mapped_column(String(128), index=True)
    version: Mapped[str | None] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(32))  # header|meta|cookie|path|js|cert
    confidence: Mapped[float] = mapped_column(Float, default=0.8)
    detected_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow_naive)

    asset: Mapped[Asset] = relationship(back_populates="technologies")


class AssetFinding(Base):
    """One observation by a scanner. Idempotent on (asset, type, title)."""

    __tablename__ = "asset_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    finding_type: Mapped[FindingType] = mapped_column(Enum(FindingType), index=True)
    severity: Mapped[SeverityLevel] = mapped_column(
        Enum(SeverityLevel), default=SeverityLevel.UNKNOWN, index=True
    )
    title: Mapped[str] = mapped_column(String(256))
    details: Mapped[dict | None] = mapped_column(JSON)
    remediation: Mapped[str | None] = mapped_column(Text)
    discovered_at: Mapped[datetime] = mapped_column(
        UtcDateTime, default=utcnow_naive, index=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    last_seen_at: Mapped[datetime] = mapped_column(
        UtcDateTime, default=utcnow_naive, onupdate=utcnow_naive
    )

    asset: Mapped[Asset] = relationship(back_populates="findings")


class AssetScan(Base):
    """One scan run for one asset — mirrors SyncRun shape."""

    __tablename__ = "asset_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    started_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow_naive)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    items_found: Mapped[int] = mapped_column(Integer, default=0)
    # New counters — added to surface the per-scan dedup breakdown so the
    # UI can show "0 new · 6 re-seen · 0 closed" instead of just "6".
    inserted_count: Mapped[int] = mapped_column(Integer, default=0)
    re_seen_count: Mapped[int] = mapped_column(Integer, default=0)
    closed_count: Mapped[int] = mapped_column(Integer, default=0)
    technologies_detected: Mapped[int] = mapped_column(Integer, default=0)
    cves_matched: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), default="running")
    error: Mapped[str | None] = mapped_column(Text)
    triggered_by: Mapped[str] = mapped_column(String(32), default="manual")
    scan_profile: Mapped[str] = mapped_column(String(64), default="web_standard")
    raw_output: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    asset: Mapped[Asset] = relationship(back_populates="scans")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "asset_id": self.asset_id,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "items_found": self.items_found,
            "inserted_count": self.inserted_count,
            "re_seen_count": self.re_seen_count,
            "closed_count": self.closed_count,
            "technologies_detected": self.technologies_detected,
            "cves_matched": self.cves_matched,
            "status": self.status,
            "error": self.error,
            "triggered_by": self.triggered_by,
            "scan_profile": self.scan_profile,
            "raw_output": self.raw_output or {},
        }


class AssetCveMatch(Base):
    """Joins asset -> CVE via the technology that bridged them."""

    __tablename__ = "asset_cve_matches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    # Add FK to vulnerabilities so a CVE row deletion cascades to the
    # asset matches. Without it, deleting a CVE leaves dangling rows.
    cve_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("vulnerabilities.cve_id", ondelete="CASCADE"),
        index=True,
    )
    technology_id: Mapped[int | None] = mapped_column(
        ForeignKey("asset_technologies.id", ondelete="CASCADE")
    )
    matched_at: Mapped[datetime] = mapped_column(
        UtcDateTime, default=utcnow_naive, index=True
    )

    asset: Mapped[Asset] = relationship(back_populates="cve_matches")


# ===========================================================================
# Findings (Risk Engine output)
# ===========================================================================
class Finding(Base):
    """One (CVE, asset) risk record produced by the Risk Engine.

    A Finding is created when an :class:`AssetCveMatch` is detected
    (or backfilled) and carries the institutional risk score, a state
    for the remediation workflow, and an optional owner. Findings are
    separate from :class:`AssetFinding` so the Risk Engine output can
    evolve independently from the raw scanner findings (admin path
    probes, missing headers, etc.).
    """

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    # Use the CVE id (text) rather than a surrogate int so the FK stays
    # stable across NVD re-ingestions. Cascades on CVE deletion.
    vulnerability_cve_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("vulnerabilities.cve_id", ondelete="CASCADE"),
        index=True,
    )
    # The technology that originally bridged the asset to the CVE. Kept
    # for explainability — analysts see "Apache 2.4.49 on moodle.college
    # is why this matches CVE-2021-41773". Nullable: backfilled findings
    # from older scans may not have a row in asset_technologies.
    technology_id: Mapped[int | None] = mapped_column(
        ForeignKey("asset_technologies.id", ondelete="SET NULL")
    )

    # Risk Engine output ----------------------------------------------------
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    risk_label: Mapped[FindingRiskLabel] = mapped_column(
        Enum(FindingRiskLabel),
        default=FindingRiskLabel.INFO,
        index=True,
    )
    # Cache the per-factor contributions so the UI can render "Why is
    # this CRITICAL?" without re-running the scorer at read time.
    risk_contributions: Mapped[dict | None] = mapped_column(JSON)

    # Remediation workflow --------------------------------------------------
    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus),
        default=FindingStatus.OPEN,
        index=True,
    )
    assigned_to_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    due_date: Mapped[datetime | None] = mapped_column(UtcDateTime)
    notes: Mapped[str | None] = mapped_column(Text)
    # The matcher that produced this row. ``scan`` for the asset scanner,
    # ``sync`` for the NVD/KEV refresh, ``backfill`` for the one-shot
    # migration from ``asset_cve_matches``. Helps us tell the operator
    # "this finding first appeared after a scan" vs "after a sync".
    source: Mapped[str] = mapped_column(String(32), default="scan")

    # Timestamps ------------------------------------------------------------
    created_at: Mapped[datetime] = mapped_column(
        UtcDateTime, default=utcnow_naive, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime, default=utcnow_naive, onupdate=utcnow_naive
    )
    resolved_at: Mapped[datetime | None] = mapped_column(UtcDateTime)

    # Relationships ---------------------------------------------------------
    asset: Mapped[Asset] = relationship()
    assigned_to: Mapped["User | None"] = relationship(foreign_keys=[assigned_to_id])

    __table_args__ = (
        # One open finding per (asset, CVE). Closed/accepted findings do
        # not block a re-detection — they stay as a history row, and a
        # new row is created on the next match. Enforced at the service
        # layer rather than as a partial unique index because SQLite's
        # UNIQUE support is finicky with WHERE clauses.
        Index("ix_finding_asset_cve_status", "asset_id", "vulnerability_cve_id", "status"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "asset_id": self.asset_id,
            "vulnerability_cve_id": self.vulnerability_cve_id,
            "technology_id": self.technology_id,
            "risk_score": self.risk_score,
            "risk_label": self.risk_label.value if self.risk_label else None,
            "risk_contributions": self.risk_contributions or {},
            "status": self.status.value if self.status else None,
            "assigned_to_id": self.assigned_to_id,
            "due_date": self.due_date.isoformat() if self.due_date else None,
            "notes": self.notes,
            "source": self.source,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }


# ===========================================================================
# Alerts & Audit Logging
# ===========================================================================
class Alert(Base):
    """Institutional alert for high-priority security findings."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    institution_id: Mapped[int] = mapped_column(
        ForeignKey("institutions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        server_default=text(str(DEFAULT_INSTITUTION_ID)),
    )
    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True
    )
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=True, index=True
    )
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="HIGH", index=True)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    is_dismissed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow_naive, index=True)

    institution: Mapped["Institution"] = relationship()
    asset: Mapped["Asset | None"] = relationship()
    finding: Mapped["Finding | None"] = relationship()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "institution_id": self.institution_id,
            "asset_id": self.asset_id,
            "finding_id": self.finding_id,
            "title": self.title,
            "message": self.message,
            "severity": self.severity,
            "is_read": self.is_read,
            "is_dismissed": self.is_dismissed,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AuditLog(Base):
    """Unified security audit log."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    institution_id: Mapped[int | None] = mapped_column(
        ForeignKey("institutions.id", ondelete="CASCADE"), nullable=True, index=True
    )
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    actor_username: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    resource_type: Mapped[str] = mapped_column(String(64), index=True)
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    outcome: Mapped[str] = mapped_column(String(32), default="success")
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow_naive, index=True)

    user: Mapped["User | None"] = relationship()
    institution: Mapped["Institution | None"] = relationship()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "institution_id": self.institution_id,
            "user_id": self.user_id,
            "actor_username": self.actor_username,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "ip": self.ip,
            "details": self.details or {},
            "outcome": self.outcome,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }