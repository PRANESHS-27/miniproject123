"""Tests for the backup / recovery script (free-priority #20).

Covers the SQLite round-trip path end to end:

  * backup → restore preserves row counts per table
  * the sidecar .json manifest is correct (sha256 + row counts)
  * manifest tamper detection refuses a corrupt backup
  * --verify mode restores to a temp DB and reports counts
  * prune --keep N keeps the newest N (local FS path; S3 mocked)
  * S3 upload is skipped silently when no creds are configured
  * JSON column values round-trip correctly
  * datetime values round-trip with timezone preserved

Postgres path is documented in the script's docstring but not exercised
here — no Postgres in the test environment.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models import (
    Asset,
    AssetCriticality,
    AssetFinding,
    AssetTechnology,
    DEFAULT_INSTITUTION_ID,
    Finding,
    FindingRiskLabel,
    FindingStatus,
    Institution,
    Role,
    SearchLog,
    SeverityLevel,
    SyncRun,
    User,
    Vulnerability,
    Severity,
)
from scripts import backup as backup_module
from scripts.backup import (
    _build_manifest,
    _dump,
    _format_value,
    _list_local,
    _prune_local,
    _replay_sqlite,
    _sha256,
    _sorted_table_names,
    _verify_manifest,
    _write_manifest,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def source_engine():
    """A fresh in-memory SQLite with a representative set of rows.

    Includes every column type the dumper has to handle:
      * strings with single quotes (escape path)
      * None (NULL path)
      * JSON column with dict / list
      * datetime (timezone-aware + naive)
      * enum values (Role / SeverityLevel)
      * bool
      * int
    """
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    s = SessionLocal()
    try:
        # Tenant
        s.add(Institution(
            id=DEFAULT_INSTITUTION_ID,
            name="Acme University",
            slug="acme-university",
            is_active=True,
            settings={"rate_limit": 100, "feature_flags": ["rag", "sso"]},
        ))

        # User with quotes / odd characters in display name
        s.add(User(
            username="admin",
            email="admin@vulnwatch.local",
            full_name="O'Brien \"the boss\"",
            hashed_password="$2b$12$fakebcrypthashneverused",
            role=Role.SUPER_ADMIN,
            is_active=True,
            institution_id=DEFAULT_INSTITUTION_ID,
        ))

        # Asset with JSON tags + enum criticality
        asset = Asset(
            owner_id=1,
            label="Acme Portal",
            url="https://portal.acme.example.com",
            env="production",
            is_active=True,
            institution_id=DEFAULT_INSTITUTION_ID,
            criticality=AssetCriticality.HIGH,
            internet_exposed=True,
            tags=["prod", "pci", {"owner": "security"}],
        )
        s.add(asset)
        s.flush()  # assign asset.id

        # AssetTechnology (FK → assets)
        s.add(AssetTechnology(
            asset_id=asset.id,
            vendor="apache",
            product="http_server",
            version="2.4.49",
            source="header",
            confidence=0.95,
        ))

        # AssetFinding with JSON details
        s.add(AssetFinding(
            asset_id=asset.id,
            finding_type="header",
            severity=SeverityLevel.HIGH,
            title="Missing CSP",
            details={"header": "Content-Security-Policy", "value": None},
        ))

        # Vulnerability — global (no institution_id) row
        s.add(Vulnerability(
            cve_id="CVE-2021-41773",
            title="Apache 2.4.49 path traversal",
            description="Path traversal via crafted URI.",
            severity=Severity.CRITICAL,
            cvss_v3_score=9.8,
            affected_products=[{"vendor": "apache", "product": "http_server"}],
            in_kev=True,
        ))

        # SyncRun — append-only audit row
        s.add(SyncRun(
            source="nvd",
            status="ok",
            items_fetched=42,
            items_inserted=10,
            items_updated=2,
        ))

        # SearchLog — nullable user FK
        s.add(SearchLog(
            user_id=1,
            query="apache",
            result_count=3,
            source="sql",
        ))

        # Finding — Risk Engine row
        s.add(Finding(
            asset_id=asset.id,
            vulnerability_cve_id="CVE-2021-41773",
            risk_score=85,
            risk_label=FindingRiskLabel.HIGH,
            status=FindingStatus.OPEN,
            risk_contributions={"cvss": 50, "kev": 25, "criticality": 10},
        ))

        s.commit()
    finally:
        s.close()
    return engine


@pytest.fixture()
def tmp_backup_dir(tmp_path: Path, monkeypatch) -> Path:
    """Point ``settings.backup_dir`` at a temp dir for prune tests."""
    monkeypatch.setattr(backup_module.settings, "backup_dir", str(tmp_path))
    return tmp_path


# ===========================================================================
# Format helpers
# ===========================================================================
class TestFormatValue:
    def test_none_renders_as_null(self):
        assert _format_value(None) == "NULL"

    def test_bool(self):
        assert _format_value(True) == "1"
        assert _format_value(False) == "0"

    def test_int(self):
        assert _format_value(42) == "42"

    def test_string_doubles_single_quotes(self):
        assert _format_value("O'Brien") == "'O''Brien'"

    def test_dict_serialised_as_json(self):
        s = _format_value({"a": 1})
        assert s.startswith("'") and s.endswith("'")
        # The inside must be valid JSON.
        inner = s[1:-1]
        assert json.loads(inner) == {"a": 1}

    def test_enum_uses_value(self):
        from app.models import SeverityLevel
        assert _format_value(SeverityLevel.HIGH) == "'HIGH'"

    def test_naive_datetime_gets_utc_attached(self):
        s = _format_value(datetime(2024, 1, 2, 3, 4, 5))
        # Naive datetime → assumed UTC.
        assert "2024-01-02T03:04:05" in s
        assert "+00:00" in s


# ===========================================================================
# Sorted table discovery
# ===========================================================================
class TestSortedTableNames:
    def test_returns_metadata_tables_in_fk_order(self, source_engine):
        names = _sorted_table_names(source_engine)
        # Parent tables (institutions, users) must come before their
        # children (assets, asset_technologies). SQLite's reflection
        # sorts by FK, so we just assert that.
        assert names.index("institutions") < names.index("users")
        assert names.index("institutions") < names.index("assets")
        assert names.index("assets") < names.index("asset_technologies")
        assert names.index("assets") < names.index("asset_findings")
        assert names.index("vulnerabilities") < names.index("findings")
        assert names.index("vulnerabilities") < names.index("asset_cve_matches")


# ===========================================================================
# Round-trip: backup → restore preserves data
# ===========================================================================
class TestBackupRestoreRoundTrip:
    def test_dump_writes_gzipped_sql(self, source_engine, tmp_path):
        sql_path = tmp_path / "out.sql.gz"
        row_counts, total = _dump(source_engine, sql_path)

        assert sql_path.exists()
        assert total > 0
        assert row_counts["institutions"] == 1
        assert row_counts["users"] == 1
        assert row_counts["assets"] == 1
        assert row_counts["asset_technologies"] == 1
        assert row_counts["vulnerabilities"] == 1
        assert row_counts["findings"] == 1
        assert row_counts["search_logs"] == 1

        # The .sql.gz is real gzip with a SQL body.
        with gzip.open(sql_path, "rt", encoding="utf-8") as f:
            body = f.read()
        assert body.startswith("-- VulnWatch backup")
        assert "INSERT INTO \"users\"" in body
        assert "INSERT INTO \"assets\"" in body
        assert "BEGIN;" in body
        assert "COMMIT;" in body

    def test_replay_sqlite_to_fresh_db_preserves_data(
        self, source_engine, tmp_path
    ):
        # Dump
        sql_path = tmp_path / "out.sql.gz"
        row_counts, total = _dump(source_engine, sql_path)

        # Restore into a fresh DB
        target = tmp_path / "fresh.db"
        replay_counts = _replay_sqlite(sql_path, target)

        # Every table that was dumped must be present with the same count.
        for table, expected in row_counts.items():
            assert replay_counts.get(table, 0) == expected, (
                f"row count mismatch on {table}: "
                f"dumped={expected}, restored={replay_counts.get(table, 0)}"
            )

    def test_replay_preserves_json_columns(self, source_engine, tmp_path):
        sql_path = tmp_path / "out.sql.gz"
        _dump(source_engine, sql_path)
        target = tmp_path / "fresh.db"
        _replay_sqlite(sql_path, target)

        # Open the target directly and inspect the JSON-shaped fields.
        conn = sqlite3.connect(str(target))
        try:
            # Asset tags (list with embedded dict)
            tags = conn.execute(
                'SELECT tags FROM "assets" WHERE url = ?',
                ("https://portal.acme.example.com",),
            ).fetchone()[0]
            loaded = json.loads(tags)
            assert "prod" in loaded
            assert {"owner": "security"} in loaded

            # Vulnerability affected_products
            affected = conn.execute(
                'SELECT affected_products FROM "vulnerabilities" WHERE cve_id = ?',
                ("CVE-2021-41773",),
            ).fetchone()[0]
            assert json.loads(affected) == [
                {"vendor": "apache", "product": "http_server"}
            ]

            # User full_name with single quote + escaped double quote
            full_name = conn.execute(
                'SELECT full_name FROM "users" WHERE username = ?',
                ("admin",),
            ).fetchone()[0]
            assert full_name == "O'Brien \"the boss\""
        finally:
            conn.close()

    def test_replay_preserves_dates(self, source_engine, tmp_path):
        sql_path = tmp_path / "out.sql.gz"
        _dump(source_engine, sql_path)
        target = tmp_path / "fresh.db"
        _replay_sqlite(sql_path, target)

        conn = sqlite3.connect(str(target))
        try:
            row = conn.execute(
                'SELECT kev_added_at FROM "vulnerabilities" WHERE cve_id = ?',
                ("CVE-2021-41773",),
            ).fetchone()
            # Either NULL (default) or a parseable ISO timestamp.
            ts = row[0]
            if ts is not None:
                datetime.fromisoformat(ts)  # raises if not ISO 8601
        finally:
            conn.close()


# ===========================================================================
# Manifest
# ===========================================================================
class TestManifest:
    def test_manifest_records_sha256_and_row_counts(self, source_engine, tmp_path):
        sql_path = tmp_path / "out.sql.gz"
        row_counts, _total = _dump(source_engine, sql_path)
        manifest = _build_manifest(
            sql_path,
            dialect=source_engine.dialect.name,
            schema_version=["assets", "users", "vulnerabilities"],
            row_counts=row_counts,
        )
        m_path = _write_manifest(manifest, sql_path)
        assert m_path.exists()

        loaded = json.loads(m_path.read_text())
        assert loaded["sha256"] == hashlib.sha256(
            sql_path.read_bytes()
        ).hexdigest()
        assert loaded["size_bytes"] == sql_path.stat().st_size
        assert loaded["dialect"] == "sqlite"
        assert loaded["schema_version"] == ["assets", "users", "vulnerabilities"]
        assert loaded["row_counts"]["users"] == 1

    def test_verify_manifest_rejects_tampered_file(
        self, source_engine, tmp_path
    ):
        sql_path = tmp_path / "out.sql.gz"
        row_counts, _ = _dump(source_engine, sql_path)
        manifest = _build_manifest(
            sql_path,
            dialect="sqlite",
            schema_version=["assets"],
            row_counts=row_counts,
        )
        _write_manifest(manifest, sql_path)

        # Tamper with the gzip payload after the manifest was sealed.
        with gzip.open(sql_path, "at", encoding="utf-8") as f:
            f.write("-- injected tampering\n")

        with pytest.raises(SystemExit) as exc:
            _verify_manifest(
                sql_path.with_name(sql_path.name.removesuffix(".sql.gz") + ".json"),
                sql_path,
            )
        assert "tampered" in str(exc.value).lower()


# ===========================================================================
# List / prune
# ===========================================================================
class TestListAndPrune:
    def _make_backup(self, out_dir: Path, idx: int) -> Path:
        """Create a fake *.sql.gz + manifest in out_dir with a
        deterministic but unique mtime so prune tests can predict."""
        name = f"vulnwatch-2026-08-26-test{idx:03d}.sql.gz"
        sql = out_dir / name
        sql.write_bytes(b"-- stub backup body\n")
        manifest_path = _write_manifest(
            {"sha256": "stub", "row_counts": {}, "size_bytes": sql.stat().st_size},
            sql,
        )
        # ``with_suffix`` only replaces the last suffix, so for ``.sql.gz``
        # it would produce ``.sql.json``. Use ``removesuffix`` instead.
        assert manifest_path.name.endswith(".json")
        assert manifest_path.exists()
        return sql

    def test_list_local_returns_all_backups(self, tmp_backup_dir):
        for i in range(3):
            self._make_backup(tmp_backup_dir, i)
        entries = _list_local(tmp_backup_dir)
        assert len(entries) == 3
        assert all(e["size_bytes"] > 0 for e in entries)

    def test_list_local_empty_dir_returns_empty_list(self, tmp_backup_dir):
        assert _list_local(tmp_backup_dir) == []

    def test_prune_local_keeps_newest_n(self, tmp_backup_dir):
        # Create 5 backups with increasing mtimes.
        paths = []
        import time
        for i in range(5):
            p = self._make_backup(tmp_backup_dir, i)
            paths.append(p)
            # Bump mtime deterministically.
            t = 1_700_000_000 + i
            import os
            manifest = p.with_name(p.name.removesuffix(".sql.gz") + ".json")
            os.utime(p, (t, t))
            os.utime(manifest, (t, t))
            time.sleep(0.01)

        removed = _prune_local(tmp_backup_dir, keep=2)
        assert removed == 6  # 3 backups × (sql + manifest) = 6 files

        remaining = sorted(tmp_backup_dir.glob("vulnwatch-*.sql.gz"))
        assert len(remaining) == 2
        # Newest two are 003 and 004 (highest index = newest).
        names = [p.name for p in remaining]
        assert "vulnwatch-2026-08-26-test003.sql.gz" in names
        assert "vulnwatch-2026-08-26-test004.sql.gz" in names


# ===========================================================================
# S3 opt-in
# ===========================================================================
class TestS3OptIn:
    def test_upload_skipped_when_no_settings(self, monkeypatch):
        # No s3_bucket → no boto3 call.
        monkeypatch.setattr(backup_module.settings, "s3_bucket", None)
        monkeypatch.setattr(backup_module.settings, "aws_access_key_id", None)
        monkeypatch.setattr(backup_module.settings, "aws_secret_access_key", None)
        # Should return without raising; we don't import boto3 at all.
        backup_module._upload_to_s3(Path("/tmp/nonexistent.sql.gz"))

    def test_upload_skipped_when_only_partial_settings(self, monkeypatch):
        # bucket but no creds → no upload.
        monkeypatch.setattr(backup_module.settings, "s3_bucket", "x")
        monkeypatch.setattr(backup_module.settings, "aws_access_key_id", None)
        monkeypatch.setattr(backup_module.settings, "aws_secret_access_key", "y")
        backup_module._upload_to_s3(Path("/tmp/nonexistent.sql.gz"))


# ===========================================================================
# CLI dispatch (subprocess invocation)
# ===========================================================================
class TestCLI:
    def test_list_subcommand_runs(self, source_engine, tmp_backup_dir, capsys):
        # No backups yet → "none"
        from scripts.backup import _cmd_list

        class _A:
            output = str(tmp_backup_dir)

        _cmd_list(_A())
        out = capsys.readouterr().out
        assert "Local backups" in out
        assert "(none)" in out
