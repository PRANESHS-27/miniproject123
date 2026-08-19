"""Embedding model factory — OpenAI or local Sentence-Transformers (optional)."""

from functools import lru_cache
from typing import Any


@lru_cache(maxsize=1)
def get_embeddings() -> Any:
    raise RuntimeError(
        "Embeddings not available. Install langchain + sentence-transformers or "
        "langchain-openai to enable the AI / RAG features."
    )


@lru_cache(maxsize=1)
def get_llm() -> Any:
    raise RuntimeError(
        "LLM not configured. Set OPENAI_API_KEY or OLLAMA_HOST and install the "
        "langchain integrations to enable AI features."
    )
