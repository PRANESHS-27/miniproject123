"""One-shot: prune vulnerabilities whose every affected_products vendor is
in the exclusion list (Apple / Google / etc.). CVEs that touch both an
excluded and a relevant vendor stay — only the excluded entries are stripped.

Safe to re-run. Run from backend/ so SQLAlchemy finds the .env / models::

    cd backend && python -m scripts.prune_excluded_vendors
"""

from __future__ import annotations

import sys

sys.path.insert(0, ".")

from app.db import SessionLocal
from app.models import Vulnerability
from app.services.vendor_filter import (
    excluded as excluded_set,
    filter_affected_products,
    is_cve_excluded,
)


def main() -> None:
    excl = excluded_set()
    if not excl:
        print("No excluded_vendors configured in .env — nothing to do.")
        return
    print(f"Excluded vendors: {sorted(excl)}")

    db = SessionLocal()
    try:
        rows = db.query(Vulnerability).all()
        dropped = 0
        cleaned = 0
        for v in rows:
            products = v.affected_products or []
            if not is_cve_excluded(products):
                continue  # at least one relevant vendor — keep as-is
            # Try to salvage: strip the excluded products.
            kept_products = filter_affected_products(products)
            if kept_products:
                v.affected_products = kept_products
                cleaned += 1
            else:
                db.delete(v)
                dropped += 1
        db.commit()
        print(f"Done. Dropped={dropped}, partially cleaned (kept entries)={cleaned}.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
