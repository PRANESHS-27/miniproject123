"""Stand-alone CLI to run a single NVD + CISA sync.

Usage:
    python -m scheduler.run_once            # full sync
    python -m scheduler.run_once --pages 2  # only 2 pages of NVD (testing)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Make the backend importable when running from project root
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app.core.logging_config import setup_logging  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.services.cve_fetcher import (  # noqa: E402
    fetch_all_cves,
    fetch_cisa_kev,
)

setup_logging()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a single CVE sync.")
    parser.add_argument("--pages", type=int, default=None, help="Limit NVD pages (testing)")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        print(">> Fetching NVD CVEs...")
        nvd = fetch_all_cves(db, max_pages=args.pages)
        print(f"   NVD: {nvd}")

        print(">> Fetching CISA KEV...")
        kev = fetch_cisa_kev(db)
        print(f"   KEV: {kev}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
