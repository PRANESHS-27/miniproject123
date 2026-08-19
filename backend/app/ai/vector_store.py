"""ChromaDB-backed vector store wrapper (optional)."""

from __future__ import annotations

from functools import lru_cache
from typing import Any


@lru_cache(maxsize=1)
def get_vector_store() -> Any | None:
    """Return a Chroma collection, or None if Chroma isn't installed."""
    try:
        from langchain_community.vectorstores import Chroma  # noqa: F401
    except Exception:
        return None
    try:
        from app.ai.embeddings import get_embeddings
    except Exception:
        return None

    from langchain_community.vectorstores import Chroma
    from app.core.config import settings

    return Chroma(
        collection_name="vulnerabilities",
        embedding_function=get_embeddings(),
        persist_directory=settings.chroma_persist_dir,
    )