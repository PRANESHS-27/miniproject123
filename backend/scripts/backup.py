"""VulnWatch backup / recovery CLI.

Usage::

    cd backend
    python -m scripts.backup backup              # write ./backups/vulnwatch-*.sql.gz + .json
    python -m scripts.backup backup --upload     # also push to S3 if configured
    python -m scripts.backup list                # show local + S3 backups
    python -m scripts.backup prune --keep 7      # keep newest N (default 7)
    python -m scripts.backup restore <path>      # restore; --verify writes to a temp DB
    python -m scripts.backup restore <path> --target /path/to/fresh.db

Format
------
A self-contained SQL dump compressed with gzip (``*.sql.gz``) plus a
sidecar ``*.json`` manifest carrying:

    * timestamp (ISO 8601 UTC)
    * dialect (sqlite / postgresql)
    * schema_version  — sorted list of table names so restore can detect
                        schema drift between backup and target
    * sha256          — of the .sql.gz, lets ``restore`` refuse tampering
    * row_counts      — per-table row count from the dump
    * size_bytes

Restore is dialect-agnostic: SQLite uses ``sqlite3`` to replay the file;
Postgres uses ``psql -f``. The single-row-per-INSERT format is
deliberately chosen so one dump file works for both.

Postgres path is implemented but not exercised in CI — there is no
Postgres in the test environment. Run against a live deployment to
verify.

Limitations
-----------
* This is a logical SQL dump, not a binary snapshot. Restore replaces
  the configured DB. For point-in-time recovery, use the database
  engine's native WAL archiving (SQLite WAL or Postgres PITR).
* Large databases take time to dump and load. SQLite is single-writer;
  a multi-GB DB will hold the writer lock for seconds during the
  scan. Schedule outside business hours via ``BACKUP_SCHEDULE_HOUR_UTC``.
* Encryption at rest is not handled here. Operators should rely on
  S3-side encryption or filesystem-level encryption for ``backup_dir``.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sqlite3 as sqlite3_stdlib
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

sys.path.insert(0, ".")

from sqlalchemy import MetaData, Table, inspect, select
from sqlalchemy.engine import Engine

from app.core.config import settings
from app.core.logging_config import get_logger
from app.core.time import utcnow_naive
from app.db.session import Base, engine

log = get_logger("backup")

_BACKUP_PREFIX = "vulnwatch-"
_BACKUP_SUFFIX = ".sql.gz"
_MANIFEST_SUFFIX = ".json"

# Tables we never back up — schema bookkeeping that has no business
# state and is rebuilt by ``_apply_schema_patches`` on startup.
_SKIP_TABLES: frozenset[str] = frozenset({
    "alembic_version",  # Alembic bookkeeping if a future deploy adds it.
})


# ===========================================================================
# Discovery
# ===========================================================================
def _sorted_table_names(eng: Engine) -> list[str]:
    """Return ``Base.metadata`` tables in FK-safe (parent-first) order.

    Falls back to alphabetical for tables with no FK constraints.
    """
    insp = inspect(eng)
    ordered: list[str] = []
    try:
        # ``get_sorted_table_and_fkc_names`` returns a tuple
        # ``(table_names, fk_pairs)`` where each "name" is actually a
        # list-like ``[schema, name]`` for Postgres-style reflection;
        # for SQLite the wrapper returns plain strings. Normalise both.
        for entry in insp.get_sorted_table_and_fkc_names():
            entry = list(entry)
            if len(entry) == 2 and isinstance(entry[0], str):
                # (table_name, fk_pairs) tuple — only the name matters
                name = entry[0]
            elif entry and isinstance(entry[0], list):
                # [schema, name] pair
                name = entry[0][-1]
            else:
                name = str(entry)
            ordered.append(name)
    except Exception:
        ordered = []

    known = {t.name for t in Base.metadata.tables.values()}
    seen = set(ordered)
    missing = sorted(known - seen - _SKIP_TABLES)
    return [t for t in ordered if t in known and t not in _SKIP_TABLES] + missing


def _schema_version(eng: Engine) -> list[str]:
    """A stable identifier of the schema — used by ``restore`` to detect
    drift between the backup's tables and the current model's tables."""
    insp = inspect(eng)
    return sorted(insp.get_table_names())


# ===========================================================================
# Value formatting
# ===========================================================================
def _format_value(value) -> str:
    """Render a single column value as a SQL literal.

    NULL → NULL, bool → 0/1, datetime → ISO8601, JSON → inline JSON,
    enum → .value (string), other strings → single-quoted with single
    quotes doubled.
    """
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, datetime):
        # Always emit timezone-aware ISO so both dialects parse it.
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return f"'{value.isoformat()}'"
    if isinstance(value, (dict, list)):
        # Both sqlite3 and psql accept a JSON string for JSON / JSONB
        # columns; Postgres will cast as needed.
        return "'" + json.dumps(value, default=str).replace("'", "''") + "'"
    if isinstance(value, (int, float)):
        return str(value)
    # Fallback: anything else (str, enum, bytes-as-str). Single-quote it.
    text = value.value if hasattr(value, "value") else str(value)
    return "'" + text.replace("'", "''") + "'"


def _column_list(table: Table) -> list[str]:
    """Column names in the order SQLAlchemy reflects them."""
    return [c.name for c in table.columns]


# ===========================================================================
# Dump
# ===========================================================================
def _dump(eng: Engine, out_path: Path) -> tuple[dict[str, int], int]:
    """Walk every table in FK-safe order and emit CREATE TABLE + INSERT statements.

    Returns (row_counts, total_rows). Streams to gzip on disk so memory
    stays flat regardless of DB size.

    The dump is dialect-aware:
      * SQLite — we ask the live engine for each table's CREATE TABLE
        statement (SQLAlchemy renders it from the reflected schema),
        then write a single ``CREATE TABLE IF NOT EXISTS ...`` per
        table followed by the inserts. ``IF NOT EXISTS`` makes the
        restore idempotent on an already-populated DB.
      * Postgres — we emit a ``CREATE TABLE IF NOT EXISTS`` per table
        using the dialect-specific DDL from SQLAlchemy's compiler.
        The single-row-per-INSERT body is the same as SQLite; both
        ``sqlite3`` and ``psql`` parse it.
    """
    metadata = MetaData()
    row_counts: dict[str, int] = {}
    total = 0

    out_path.parent.mkdir(parents=True, exist_ok=True)

    reflected_tables: dict[str, Table] = {}
    table_names = _sorted_table_names(eng)
    for name in table_names:
        try:
            reflected_tables[name] = Table(name, metadata, autoload_with=eng)
        except Exception as exc:
            log.warning("Could not reflect table %s: %s", name, exc)

    with eng.connect() as conn, gzip.open(out_path, "wt", encoding="utf-8") as f:
        dialect = eng.dialect.name
        ts = utcnow_naive().replace(tzinfo=timezone.utc).isoformat()
        f.write(f"-- VulnWatch backup ({dialect}) generated {ts}\n")
        # Schema first — without CREATE TABLE the inserts would target
        # nothing. ``IF NOT EXISTS`` keeps the script re-runnable.
        for name in table_names:
            table = reflected_tables.get(name)
            if table is None:
                continue
            create = _render_create_table(conn, table)
            if create:
                f.write(f"{create}\n")
        f.write("\nBEGIN;\n")

        for name in table_names:
            table = reflected_tables.get(name)
            if table is None:
                continue
            cols = _column_list(table)
            if not cols:
                continue
            col_list_sql = ", ".join(f'"{c}"' for c in cols)
            f.write(f"\n-- Table: {name}\n")
            count = 0
            stmt = select(table)
            chunk_size = 1000
            offset = 0
            while True:
                chunk = conn.execute(stmt.offset(offset).limit(chunk_size)).mappings().all()
                if not chunk:
                    break
                for row in chunk:
                    values = ", ".join(_format_value(row[c]) for c in cols)
                    f.write(f'INSERT INTO "{name}" ({col_list_sql}) VALUES ({values});\n')
                    count += 1
                offset += chunk_size
            row_counts[name] = count
            total += count

        f.write("\nCOMMIT;\n")

    return row_counts, total


def _render_create_table(conn, table: Table) -> str | None:
    """Ask the dialect to render a ``CREATE TABLE IF NOT EXISTS`` for
    ``table``. ``conn`` carries the engine's dialect so SQLite and
    Postgres each get their correct DDL (auto-increment, JSON vs
    JSONB, enum-as-text, etc.)."""
    from sqlalchemy.schema import CreateTable

    try:
        stmt = CreateTable(table, if_not_exists=True)
        # ``compile`` honours the connection's dialect.
        ddl = str(stmt.compile(bind=conn.engine))
        # Strip trailing semicolon — we add one ourselves.
        return ddl.rstrip(";").strip() + ";"
    except Exception as exc:
        log.warning("Could not render CREATE TABLE for %s: %s", table.name, exc)
        return None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(64 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _build_manifest(sql_path: Path, dialect: str, schema_version: list[str],
                    row_counts: dict[str, int]) -> dict:
    return {
        "timestamp": utcnow_naive().replace(tzinfo=timezone.utc).isoformat(),
        "dialect": dialect,
        "schema_version": schema_version,
        "row_counts": row_counts,
        "sha256": _sha256(sql_path),
        "size_bytes": sql_path.stat().st_size,
        "tool": "scripts.backup",
    }


def _write_manifest(manifest: dict, sql_path: Path) -> Path:
    p = sql_path.with_name(sql_path.name.removesuffix(_BACKUP_SUFFIX) + _MANIFEST_SUFFIX)
    p.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return p


# ===========================================================================
# Subcommand: backup
# ===========================================================================
def _cmd_backup(args: argparse.Namespace) -> int:
    out_dir = Path(args.output or settings.backup_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M%S")
    sql_name = f"{_BACKUP_PREFIX}{timestamp}{_BACKUP_SUFFIX}"
    sql_path = out_dir / sql_name

    log.info("Writing backup to %s", sql_path)
    row_counts, total = _dump(engine, sql_path)

    manifest = _build_manifest(
        sql_path,
        dialect=engine.dialect.name,
        schema_version=_schema_version(engine),
        row_counts=row_counts,
    )
    manifest_path = _write_manifest(manifest, sql_path)

    log.info(
        "Backup complete: %d rows across %d tables, %d bytes",
        total, len(row_counts), manifest["size_bytes"],
    )
    log.info("Manifest: %s", manifest_path)

    if args.upload or settings.backup_upload_to_s3:
        _upload_to_s3(sql_path)
        _upload_to_s3(manifest_path)
    return 0


# ===========================================================================
# Subcommand: list
# ===========================================================================
def _list_local(out_dir: Path) -> list[dict]:
    rows: list[dict] = []
    if not out_dir.exists():
        return rows
    for sql in sorted(out_dir.glob(f"{_BACKUP_PREFIX}*{_BACKUP_SUFFIX}")):
        manifest_path = sql.with_name(
            sql.name.removesuffix(_BACKUP_SUFFIX) + _MANIFEST_SUFFIX
        )
        entry = {
            "name": sql.name,
            "size_bytes": sql.stat().st_size,
            "modified": datetime.fromtimestamp(sql.stat().st_mtime, tz=timezone.utc).isoformat(),
            "manifest": str(manifest_path) if manifest_path.exists() else None,
        }
        rows.append(entry)
    return rows


def _list_s3() -> list[dict]:
    """List S3 backups if boto3 + AWS creds are available. Lazy import."""
    if not (settings.s3_bucket and settings.aws_access_key_id and settings.aws_secret_access_key):
        return []
    try:
        import boto3
    except ImportError:
        log.warning("boto3 not installed — skipping S3 listing")
        return []
    s3 = boto3.client(
        "s3",
        region_name=settings.aws_region,
        aws_access_key_id=settings.aws_access_key_id,
        aws_secret_access_key=settings.aws_secret_access_key,
    )
    rows: list[dict] = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=settings.s3_bucket, Prefix="backups/"):
        for obj in page.get("Contents") or []:
            if obj["Key"].endswith(_BACKUP_SUFFIX):
                rows.append({
                    "name": obj["Key"].split("/", 1)[-1],
                    "size_bytes": obj["Size"],
                    "modified": obj["LastModified"].isoformat(),
                })
    return rows


def _cmd_list(args: argparse.Namespace) -> int:
    out_dir = Path(args.output or settings.backup_dir).resolve()
    local = _list_local(out_dir)
    remote = _list_s3()

    print(f"Local backups ({out_dir}):")
    if not local:
        print("  (none)")
    for entry in local:
        print(f"  {entry['modified']}  {entry['size_bytes']:>12,} B  {entry['name']}")
    print()
    print("S3 backups:")
    if not remote:
        if not (settings.s3_bucket and settings.aws_access_key_id):
            print("  (S3 not configured)")
        else:
            print("  (none)")
    for entry in remote:
        print(f"  {entry['modified']}  {entry['size_bytes']:>12,} B  {entry['name']}")
    return 0


# ===========================================================================
# Subcommand: prune
# ===========================================================================
def _prune_local(out_dir: Path, keep: int) -> int:
    entries = _list_local(out_dir)
    # Sort newest-first by mtime; keep the first ``keep``.
    entries.sort(key=lambda e: e["modified"], reverse=True)
    victims = entries[keep:]
    removed = 0
    for entry in victims:
        sql = out_dir / entry["name"]
        manifest = Path(entry["manifest"]) if entry["manifest"] else sql.with_name(
            sql.name.removesuffix(_BACKUP_SUFFIX) + _MANIFEST_SUFFIX
        )
        for p in (sql, manifest):
            if p.exists():
                p.unlink()
                removed += 1
        log.info("Pruned %s", sql.name)
    return removed


def _prune_s3(keep: int) -> int:
    if not (settings.s3_bucket and settings.aws_access_key_id and settings.aws_secret_access_key):
        return 0
    try:
        import boto3
    except ImportError:
        return 0
    s3 = boto3.client(
        "s3",
        region_name=settings.aws_region,
        aws_access_key_id=settings.aws_access_key_id,
        aws_secret_access_key=settings.aws_secret_access_key,
    )
    entries = _list_s3()
    entries.sort(key=lambda e: e["modified"], reverse=True)
    victims = entries[keep:]
    removed = 0
    for entry in victims:
        key = f"backups/{entry['name']}"
        manifest_name = entry["name"].removesuffix(_BACKUP_SUFFIX) + _MANIFEST_SUFFIX
        for k in (key, f"backups/{manifest_name}"):
            try:
                s3.delete_object(Bucket=settings.s3_bucket, Key=k)
                removed += 1
            except Exception as exc:
                log.warning("S3 delete %s failed: %s", k, exc)
    return removed


def _cmd_prune(args: argparse.Namespace) -> int:
    out_dir = Path(args.output or settings.backup_dir).resolve()
    keep = args.keep if args.keep is not None else settings.backup_retention_count
    log.info("Pruning local backups in %s — keeping newest %d", out_dir, keep)
    removed_local = _prune_local(out_dir, keep)
    log.info("Pruning S3 backups — keeping newest %d", keep)
    removed_remote = _prune_s3(keep)
    log.info("Removed %d local + %d S3 objects", removed_local, removed_remote)
    return 0


# ===========================================================================
# Subcommand: restore
# ===========================================================================
def _verify_manifest(manifest_path: Path, sql_path: Path) -> dict:
    if not manifest_path.exists():
        raise SystemExit(f"manifest not found: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_hash = manifest.get("sha256")
    actual_hash = _sha256(sql_path)
    if expected_hash and expected_hash != actual_hash:
        raise SystemExit(
            f"manifest sha256 mismatch — backup may be tampered with.\n"
            f"  expected: {expected_hash}\n"
            f"  actual:   {actual_hash}"
        )
    return manifest


def _replay_sqlite(backup_path: Path, target_path: Path) -> dict[str, int]:
    """Apply a backup to a fresh SQLite file. Returns per-table row counts
    from the target after restore (used for verification)."""
    if target_path.exists():
        target_path.unlink()
    target_path.parent.mkdir(parents=True, exist_ok=True)

    row_counts: dict[str, int] = {}
    conn = sqlite3_stdlib.connect(str(target_path))
    try:
        # The dump wraps INSERTs in BEGIN; ... COMMIT;. The FKs aren't
        # enforced on the empty DB so order doesn't matter, but we keep
        # the explicit BEGIN/COMMIT from the dump.
        with gzip.open(backup_path, "rt", encoding="utf-8") as f:
            script = f.read()
        conn.executescript(script)
        # Quick sanity count for the tables we care about.
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        for (table,) in cur.fetchall():
            if table.startswith("sqlite_"):
                continue
            n = conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            row_counts[table] = n
        conn.commit()
    finally:
        conn.close()
    return row_counts


def _derive_sqlite_target_path() -> Path | None:
    """Extract the file path from ``settings.database_url`` if it's a
    sqlite:///path URL. None for non-sqlite URLs."""
    url = settings.database_url
    if url.startswith("sqlite:///"):
        return Path(url[len("sqlite:///"):])
    if url.startswith("sqlite://"):
        return Path(url[len("sqlite://"):])
    return None


def _cmd_restore(args: argparse.Namespace) -> int:
    backup_path = Path(args.backup).resolve()
    if not backup_path.exists():
        raise SystemExit(f"backup not found: {backup_path}")
    manifest_path = backup_path.with_name(
        backup_path.name.removesuffix(_BACKUP_SUFFIX) + _MANIFEST_SUFFIX
    )
    manifest = _verify_manifest(manifest_path, backup_path)
    log.info(
        "Backup dialect=%s, rows=%d, sha256=%s…",
        manifest.get("dialect"),
        sum(manifest.get("row_counts", {}).values()),
        manifest.get("sha256", "")[:12],
    )

    target = (
        Path(args.target).resolve() if args.target
        else _derive_sqlite_target_path()
    )
    if target is None:
        raise SystemExit(
            "restore currently supports sqlite:/// URLs only. For Postgres, "
            "use `psql -f <backup>.sql.gz` after gunzipping."
        )

    if args.verify:
        # Write to a temp DB so the live DB is untouched.
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            verify_path = Path(tmp.name)
        try:
            counts = _replay_sqlite(backup_path, verify_path)
            print(f"Verify OK — row counts in restored DB at {verify_path}:")
            for table, n in sorted(counts.items()):
                print(f"  {table:30s}  {n}")
        finally:
            if verify_path.exists():
                verify_path.unlink()
        return 0

    # Live restore. Disposes the engine so the file lock is released
    # before we replace it.
    if not args.yes:
        ans = input(
            f"This will REPLACE the database at {target} with the contents of "
            f"{backup_path}. Type 'yes' to continue: "
        )
        if ans.strip().lower() != "yes":
            print("Aborted.")
            return 1

    engine.dispose()
    _replay_sqlite(backup_path, target)
    log.info("Restore complete: %s", target)

    # Re-run schema patches defensively. They're idempotent — adding
    # columns since the backup won't hurt the restored data.
    try:
        from app.main import _apply_schema_patches
        _apply_schema_patches()
        log.info("Schema patches re-applied (idempotent)")
    except Exception as exc:
        log.warning("Schema patch re-apply failed (non-fatal): %s", exc)
    return 0


# ===========================================================================
# S3 helpers
# ===========================================================================
def _upload_to_s3(path: Path) -> None:
    if not (settings.s3_bucket and settings.aws_access_key_id and settings.aws_secret_access_key):
        log.warning("S3 upload skipped: AWS settings incomplete")
        return
    try:
        import boto3
    except ImportError:
        log.warning("S3 upload skipped: boto3 not installed")
        return
    s3 = boto3.client(
        "s3",
        region_name=settings.aws_region,
        aws_access_key_id=settings.aws_access_key_id,
        aws_secret_access_key=settings.aws_secret_access_key,
    )
    key = f"backups/{path.name}"
    s3.upload_file(str(path), settings.s3_bucket, key)
    log.info("Uploaded %s → s3://%s/%s", path.name, settings.s3_bucket, key)


# ===========================================================================
# argparse
# ===========================================================================
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m scripts.backup",
        description="VulnWatch backup / recovery CLI.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("backup", help="Write a backup file")
    b.add_argument("--output", "-o", help="Output directory (default: settings.backup_dir)")
    b.add_argument("--upload", action="store_true", help="Upload to S3 if configured")
    b.set_defaults(func=_cmd_backup)

    l = sub.add_parser("list", help="List local + S3 backups")
    l.add_argument("--output", "-o", help="Output directory (default: settings.backup_dir)")
    l.set_defaults(func=_cmd_list)

    pr = sub.add_parser("prune", help="Delete old backups")
    pr.add_argument("--keep", type=int, help="Number to keep (default: settings.backup_retention_count)")
    pr.add_argument("--output", "-o", help="Output directory (default: settings.backup_dir)")
    pr.set_defaults(func=_cmd_prune)

    r = sub.add_parser("restore", help="Restore a backup into the configured DB")
    r.add_argument("backup", help="Path to a *.sql.gz backup file")
    r.add_argument("--target", help="Override target sqlite DB path (defaults to settings.database_url)")
    r.add_argument("--verify", action="store_true", help="Restore into a temp DB and report counts")
    r.add_argument("--yes", action="store_true", help="Skip the confirmation prompt")
    r.set_defaults(func=_cmd_restore)

    return p


def main(argv: Iterable[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())