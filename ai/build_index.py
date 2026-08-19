"""CLI helper to build the vector index after a CVE sync."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app.ai.rag import build_index  # noqa: E402
from app.core.logging_config import setup_logging  # noqa: E402
from app.db import SessionLocal  # noqa: E402

setup_logging()


def main() -> None:
    db = SessionLocal()
    try:
        count = build_index(db)
        print(f"Indexed {count} vulnerability documents into ChromaDB.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
