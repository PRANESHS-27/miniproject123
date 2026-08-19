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
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.core.time import UtcDateTime, utcnow_naive
from app.db.session import Base


class Role(str, enum.Enum):
    """User role for RBAC."""

    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Severity(str, enum.Enum):
    """CVSS severity buckets."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


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

    search_logs: Mapped[list["SearchLog"]] = relationship(back_populates="user")
    # Reverse of Asset.owner — needed so the back-populate reference above
    # resolves cleanly. ``cascade="all, delete-orphan"`` would orphan
    # SearchLogs on user deletion; we keep ``search_logs`` nullable so
    # user deletion is allowed (logs survive with ``user_id=NULL``).
    owned_assets: Mapped[list["Asset"]] = relationship(
        back_populates="owner", foreign_keys="Asset.owner_id"
    )


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

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    label: Mapped[str] = mapped_column(String(128))
    url: Mapped[str] = mapped_column(String(512), unique=True)
    env: Mapped[str] = mapped_column(String(32), default="production")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    tags: Mapped[list | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow_naive)
    last_scanned_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    last_scan_status: Mapped[str | None] = mapped_column(String(32))

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

    asset: Mapped[Asset] = relationship(back_populates="scans")


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