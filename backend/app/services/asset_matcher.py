"""CVE matcher — bridges detected technologies to stored CVEs.

Strategy:
  1. For each (vendor, product) tuple, query ``vulnerabilities`` for rows
     whose JSON ``affected_products`` array contains an entry with matching
     vendor and product (case-insensitive substring on lowercased JSON).
  2. Optionally filter by version range when the CVE JSON includes a
     versionEndExcluding / versionStartIncluding that we can parse.
  3. Sort matches by CVSS desc; insert ``AssetCveMatch`` rows so future
     scans are idempotent.
"""

from __future__ import annotations

from typing import Any, Iterable

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.time import utcnow_naive
from app.models import AssetCveMatch, Vulnerability
from app.services.vendor_filter import is_cve_excluded, is_vendor_excluded


def _version_tuple(s: str | None) -> tuple[int, ...]:
    if not s:
        return ()
    parts: list[int] = []
    for p in s.replace("*", "0").split("."):
        try:
            parts.append(int("".join(ch for ch in p if ch.isdigit()) or 0))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def _cve_version_matches(detected_version: str | None, ap: dict[str, Any]) -> bool:
    """Best-effort version check. Returns True when the CVE's recorded
    version range matches the detected version, or when we can't tell."""
    if not detected_version or not ap:
        return True
    v = _version_tuple(detected_version)
    start = _version_tuple(ap.get("versionStartIncluding"))
    end_excl = _version_tuple(ap.get("versionEndExcluding"))
    end_incl = _version_tuple(ap.get("versionEndIncluding"))
    if start and v < start:
        return False
    if end_excl and v >= end_excl:
        return False
    if end_incl and v > end_incl:
        return False
    return True


def match_cves(
    db: Session,
    asset_id: int,
    tech_pairs: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Look up CVEs for each (vendor, product) pair and persist matches.

    ``tech_pairs`` is a list of dicts with at least ``vendor`` and ``product``
    (and optionally ``version``, ``id``). Returns the list of CVEs that
    matched, sorted by CVSS desc.
    """
    pairs = [
        {"vendor": (t["vendor"] or "").lower(), "product": (t["product"] or "").lower(),
         "version": t.get("version"), "id": t.get("id")}
        for t in tech_pairs if t.get("vendor") and t.get("product")
        and not is_vendor_excluded(t.get("vendor"))
    ]
    if not pairs:
        return []

    # Pull candidate CVEs. Two strategies per (vendor, product):
    #   1. Strict: match (vendor, product) against affected_products JSON
    #   2. Loose: title/description contains the product token — catches
    #      CVEs whose CPE column is sparse but whose prose names the
    #      technology (common for Vercel, Next.js, Cloudflare).
    # Results are union'd and dedup'd on CVE id.
    matched: dict[str, dict[str, Any]] = {}

    for tp in pairs:
        vendor, product = tp["vendor"], tp["product"]

        def _record(c: Vulnerability, bridging_ap: dict[str, Any] | None) -> None:
            matched.setdefault(
                c.cve_id,
                {"cve": c, "bridging": tp, "bridging_ap": bridging_ap},
            )

        # ---- 1. Strict (CPE match) — cap at 2000 most-recent rows ----
        # Filter the JSON ``affected_products`` at the SQL level via LIKE
        # on the lowercased JSON text. SQLite/Postgres both support this;
        # it lets the DB use the cvss index and drops irrelevant rows
        # before the Python loop runs (the original code fetched the top
        # 2000 globally regardless of vendor).
        # Escape LIKE wildcards in user-derived vendor/product so a
        # product named ``node_js`` doesn't accidentally match ``nodeXjs``.
        like_vendor = (
            vendor.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        )
        like_product = (
            product.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        )
        # We substring-match on the *lowercased* JSON. NVD's vendor
        # strings vary in case ("Apache" vs "apache") so case-insensitive
        # matching is required.
        strict_stmt = (
            select(Vulnerability)
            .where(
                or_(
                    # vendor appears anywhere in the JSON
                    func.lower(func.coalesce(Vulnerability.affected_products, "")).like(
                        f"%{like_vendor}%", escape="\\"
                    ),
                    # Some CVEs don't list a vendor in CPE but the title
                    # or description mentions the product by name.
                    func.lower(func.coalesce(Vulnerability.title, "")).like(
                        f"%{like_product}%", escape="\\"
                    ),
                )
            )
            .order_by(Vulnerability.cvss_v3_score.desc().nullslast())
            .limit(2000)
        )
        for c in db.execute(strict_stmt).scalars().all():
            products = c.affected_products or []
            if not isinstance(products, list):
                continue
            if is_cve_excluded(products):
                continue
            for ap in products:
                if not isinstance(ap, dict):
                    continue
                ap_vendor = (ap.get("vendor") or "").lower()
                ap_product = (ap.get("product") or "").lower()
                if is_vendor_excluded(ap_vendor):
                    continue
                if (
                    ap_vendor == vendor
                    and ap_product == product
                    and _cve_version_matches(tp.get("version"), ap)
                ):
                    _record(c, ap)
                    break

        # ---- 2. Loose (prose match) — limited LIKE scan ----
        aliases = {product}
        if product in ("next.js", "nextjs"):
            aliases |= {"next.js", "nextjs"}
        # Escape each alias so an asset registered with vendor/product
        # containing LIKE wildcards can't trigger an unbounded scan.
        escaped_aliases = [
            a.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            for a in aliases
        ]
        like_pattern = "%" + "%".join(escaped_aliases) + "%"
        loose_stmt = (
            select(Vulnerability)
            .where(
                or_(
                    func.lower(func.coalesce(Vulnerability.title, "")).like(like_pattern, escape="\\"),
                    func.lower(func.coalesce(Vulnerability.description, "")).like(like_pattern, escape="\\"),
                )
            )
            .order_by(Vulnerability.cvss_v3_score.desc().nullslast())
            .limit(200)
        )
        for c in db.execute(loose_stmt).scalars().all():
            if c.cve_id in matched:
                continue
            products = c.affected_products or []
            if is_cve_excluded(products):
                continue
            _record(c, None)

    # Persist AssetCveMatch rows (idempotent on (asset_id, cve_id)).
    # Two safety nets:
    #   * If a match already exists but its ``technology_id`` is NULL or
    #     points at a deleted row, look up the current AssetTechnology
    #     row for the (vendor, product) tuple and re-link.
    #   * Otherwise just insert.
    if matched:
        existing_rows = {
            row.cve_id: row for row in db.query(AssetCveMatch)
            .filter(AssetCveMatch.asset_id == asset_id).all()
        }
        # Map (vendor, product) -> current tech row id so we can re-link
        # orphan matches in one query.
        tech_pairs = {(info["bridging"]["vendor"], info["bridging"]["product"])
                      for info in matched.values()}
        tech_id_by_pair: dict[tuple[str, str], int] = {}
        if tech_pairs:
            from app.models import AssetTechnology
            for t in db.query(AssetTechnology).filter(AssetTechnology.asset_id == asset_id).all():
                tech_id_by_pair[(t.vendor.lower(), t.product.lower())] = t.id

        new_rows = []
        for cve_id, info in matched.items():
            pair = (info["bridging"]["vendor"], info["bridging"]["product"])
            tech_id = info["bridging"].get("id") or tech_id_by_pair.get(pair)
            if cve_id in existing_rows:
                # Re-link orphans (null or deleted tech_id).
                row = existing_rows[cve_id]
                if tech_id and row.technology_id != tech_id:
                    row.technology_id = tech_id
                continue
            new_rows.append(AssetCveMatch(
                asset_id=asset_id,
                cve_id=cve_id,
                technology_id=tech_id,
            ))
        if new_rows:
            db.add_all(new_rows)
        db.commit()

    out = sorted(
        (
            {
                "cve_id": info["cve"].cve_id,
                "matched_at": utcnow_naive(),
                "technology_vendor": info["bridging"]["vendor"],
                "technology_product": info["bridging"]["product"],
                "cve_severity": info["cve"].severity.value if info["cve"].severity else None,
                "cve_cvss_v3_score": info["cve"].cvss_v3_score,
                "cve_title": info["cve"].title,
            }
            for info in matched.values()
        ),
        key=lambda r: (r.get("cve_cvss_v3_score") or 0),
        reverse=True,
    )
    return out