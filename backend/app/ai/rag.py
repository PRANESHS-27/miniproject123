"""Retrieval-Augmented Generation over the vulnerability store.

Retrieval strategy
------------------
We classify each incoming question before doing retrieval:

* **Exact CVE ID** (``CVE-YYYY-NNNN+``) → precise SQL lookup by primary key.
  This is the fastest, most reliable path; no LLM hallucination possible.
* **Vendor / natural-language query** → ChromaDB vector search when
  available, otherwise SQL keyword search. Either path returns a list of
  CVE-shaped rows; the rest of this module is identical.

Anti-hallucination
------------------
When retrieval returns **zero** rows, the LLM path is skipped entirely.
We never ask the model to "answer based on no context" — that is exactly
where LLMs start inventing. Instead the user sees an explicit
"I couldn't find verified information" refusal with a structured hint
about what we searched for.

Structured response
-------------------
Every answer carries a ``structured`` block describing what was retrieved
and a ``summary`` field derived purely from the CVE metadata (CVSS, KEV,
severity). The summary is **descriptive**, not institutional risk — the
authoritative institutional risk lives in the Risk Engine and is surfaced
separately via the Findings API. The LLM is forbidden from inventing risk
numbers; it only explains the retrieved evidence.

  {
    "answer": "<natural-language explanation of retrieved evidence>",
    "sources": [{ "cve_id", "severity", "cvss_v3_score", "title",
                  "snippet", "in_kev" }],
    "retrieval": "vector" | "sql" | "exact",
    "query_type": "exact_cve" | "natural_language" | "empty",
    "structured": {
      "summary": {
        "cvss": float | None,
        "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN" | None,
        "in_kev": bool,
        "cve_ids": [...],
      },
      "evidence_count": int,
      "primary_cve_id": str | None,
    },
    "provider": str,
  }
"""

from __future__ import annotations

import logging
import re
from typing import Any

from sqlalchemy.orm import Session

from app.ai import llm
from app.models import Vulnerability
from app.services.search_service import search_vulnerabilities

log = logging.getLogger("rag")

_CONTEXT_LIMIT = 8  # CVEs per answer (natural-language path)
_SNIPPET_LEN = 600  # used both for context and source snippet
_MAX_QUESTION_LEN = 4096  # bound to prevent DoS via huge prompts

# Matches one or more CVE IDs in any input. Word boundaries on both sides
# so we don't pick up things like "bcecve-1234". Allows a handful of
# digits per CVE (some test fixtures use shorter ids).
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{2,7}\b", re.IGNORECASE)

# Cached on first call so we don't pay the import cost on every /ask.
_VECTOR_AVAILABLE: bool | None = None

REFUSAL_EMPTY = (
    "I couldn't find verified information about that in the institutional "
    "vulnerability registry. Try searching for a specific CVE ID "
    "(e.g. CVE-2024-12345) or a vendor/product name."
)
REFUSAL_UNCONFIGURED = (
    "AI assistant is not configured. Set GROQ_API_KEY (or OPENAI_API_KEY / "
    "GEMINI_API_KEY / OLLAMA_HOST) in the backend .env to enable "
    "natural-language answers."
)


# ---------------------------------------------------------------------------
# Query classifier
# ---------------------------------------------------------------------------
def extract_cve_ids(question: str) -> list[str]:
    """Return every CVE ID found in the question, uppercased + deduped."""
    if not question:
        return []
    return sorted({m.group(0).upper() for m in _CVE_RE.finditer(question)})


def classify_query(question: str) -> dict[str, Any]:
    """Classify the question into one of three buckets.

    Returns ``{"type": ..., "cve_ids": [...]}`` where ``type`` is one of:
      * ``"exact_cve"`` — question contains only CVE IDs and connector words.
      * ``"natural_language"`` — anything else.
      * ``"empty"`` — empty / whitespace.
    """
    if not question or not question.strip():
        return {"type": "empty", "cve_ids": []}
    cves = extract_cve_ids(question)
    if cves:
        # Strip the CVE IDs and connector words; if nothing meaningful is
        # left, treat as an exact-Cve query. Otherwise it's natural-language
        # that happens to mention CVE IDs.
        leftover = _CVE_RE.sub(" ", question)
        leftover = re.sub(
            r"\b(?:show|details|info|about|for|on|please|give|me|tell)\b",
            " ",
            leftover,
            flags=re.IGNORECASE,
        )
        if not leftover.strip():
            return {"type": "exact_cve", "cve_ids": cves}
    return {"type": "natural_language", "cve_ids": cves}


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------
def _chroma_available() -> bool:
    """Probe the optional ML stack and cache the result."""
    global _VECTOR_AVAILABLE
    if _VECTOR_AVAILABLE is not None:
        return _VECTOR_AVAILABLE
    try:
        from app.ai.vector_store import get_vector_store  # type: ignore
        store = get_vector_store()
        _VECTOR_AVAILABLE = store is not None
    except Exception as exc:
        log.info("ChromaDB unavailable, using SQL fallback: %s", exc)
        _VECTOR_AVAILABLE = False
    return _VECTOR_AVAILABLE


def _vector_search(question: str, k: int) -> list[Any]:
    """Try semantic retrieval. Returns a list of objects with the same shape
    as the SQL path (``cve_id``, ``severity``, ``cvss_v3_score``, ``title``,
    ``description``) or an empty list on any failure."""
    try:
        from app.ai.vector_store import get_vector_store  # type: ignore
        store = get_vector_store()
        if store is None:
            return []
        docs = store.similarity_search(question, k=k)
        out: list[Any] = []
        for d in docs:
            md = getattr(d, "metadata", {}) or {}
            out.append(type("Row", (), {
                "cve_id": md.get("cve_id") or "",
                "severity": md.get("severity"),
                "cvss_v3_score": md.get("cvss_v3_score"),
                "title": md.get("title"),
                "description": md.get("description") or d.page_content,
            })())
        return out
    except Exception as exc:
        log.warning("Vector search failed, falling back to SQL: %s", exc)
        return []


def _exact_cve_lookup(db: Session, cve_ids: list[str]) -> list[Vulnerability]:
    """Precise lookup by primary key. Order matches the input order."""
    if not cve_ids:
        return []
    rows = db.query(Vulnerability).filter(Vulnerability.cve_id.in_(cve_ids)).all()
    by_id = {r.cve_id: r for r in rows}
    return [by_id[c] for c in cve_ids if c in by_id]


def _retrieve(db: Session, question: str, query_type: str, cve_ids: list[str]) -> tuple[list[Any], str]:
    """Return (rows, source). ``source`` is ``"exact" | "vector" | "sql"``."""
    if query_type == "exact_cve":
        return _exact_cve_lookup(db, cve_ids), "exact"

    # If explicit CVE IDs are mentioned in natural language, exact lookup is authoritative if found.
    if cve_ids:
        rows = _exact_cve_lookup(db, cve_ids)
        if rows:
            return rows, "exact"

    # 2. Vector search via ChromaDB if available.
    if _chroma_available():
        rows = _vector_search(question, _CONTEXT_LIMIT)
        if rows:
            return rows, "vector"
        log.info("Vector search returned no rows; falling back to SQL")

    # 3. SQL keyword search with stop-word and KEV filtering.
    stop_words = {
        "what", "is", "are", "which", "show", "tell", "about", "me", "how", "do",
        "does", "i", "we", "can", "fix", "mitigate", "the", "a", "an", "in", "from",
        "for", "with", "and", "or", "to", "of", "recent", "vulnerabilities",
        "vulnerability", "details", "cve", "cves", "please", "give", "summarize",
        "find", "list", "lookup", "any", "all",
    }
    raw_words = [w.strip("?,.!:;\"'()[]{}") for w in question.lower().split()]
    in_kev = True if any(w in ("kev", "cisa") for w in raw_words) else None
    terms = [w for w in raw_words if w and w not in stop_words and w not in ("cisa", "kev")]

    if terms:
        clean_query = " ".join(terms)
        rows, total = search_vulnerabilities(db, query=clean_query, in_kev=in_kev, limit=_CONTEXT_LIMIT)
        if rows:
            return rows, "sql"
        # If combined terms return 0 results and there are multiple terms, try individual terms
        if len(terms) > 1:
            for term in terms:
                rows, total = search_vulnerabilities(db, query=term, in_kev=in_kev, limit=_CONTEXT_LIMIT)
                if rows:
                    return rows, "sql"

    # Fallback to literal query string
    rows, _total = search_vulnerabilities(db, query=question, in_kev=in_kev, limit=_CONTEXT_LIMIT)
    return rows, "sql"


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------
def _scrub_for_prompt(text: str | None) -> str:
    """Strip characters that an LLM might interpret as instruction delimiters."""
    if not text:
        return ""
    cleaned = re.sub(r"[`#]+", " ", text)
    return cleaned.strip()


def _format_context(rows) -> str:
    """Render the matched CVEs as plain text for the LLM prompt."""
    chunks: list[str] = []
    for r in rows:
        sev = r.severity.value if r.severity else "UNKNOWN"
        cvss = f"CVSS {r.cvss_v3_score}" if r.cvss_v3_score is not None else "no CVSS"
        kev = " [CISA KEV — actively exploited]" if getattr(r, "in_kev", False) else ""
        desc = _scrub_for_prompt(r.description)
        chunks.append(f"[{r.cve_id} | {sev} | {cvss}]{kev}\n{desc[:_SNIPPET_LEN]}")
    return "<<<CONTEXT_START>>>\n" + "\n\n".join(chunks) + "\n<<<CONTEXT_END>>>"


def _format_sources(rows) -> list[dict[str, Any]]:
    """Structured source rows."""
    out: list[dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "cve_id": r.cve_id,
                "severity": r.severity.value if r.severity else "",
                "cvss_v3_score": r.cvss_v3_score,
                "title": r.title,
                "snippet": _scrub_for_prompt(r.description)[:_SNIPPET_LEN // 2],
                "in_kev": bool(getattr(r, "in_kev", False)),
            }
        )
    return out


# ---------------------------------------------------------------------------
# Structured response builder
# ---------------------------------------------------------------------------
def _structured_for_rows(rows) -> dict[str, Any]:
    """Build the structured block from retrieved rows.

    This is a **descriptive** summary of what was retrieved — it surfaces
    CVSS, severity and KEV from the CVE metadata but does **not** perform
    institutional risk calculation. The Risk Engine (``app.services.risk``)
    is the single source of truth for institutional risk, and consumers
    query the Findings API for that.
    """
    if not rows:
        return {
            "summary": {
                "cvss": None,
                "severity": None,
                "in_kev": False,
                "cve_ids": [],
            },
            "evidence_count": 0,
            "primary_cve_id": None,
        }
    # Sort by retrieved priority: KEV-listed rows first, then highest CVSS.
    rows_sorted = sorted(
        rows,
        key=lambda r: (
            bool(getattr(r, "in_kev", False)),
            r.cvss_v3_score or 0.0,
        ),
        reverse=True,
    )
    top = rows_sorted[0]
    return {
        "summary": {
            "cvss": top.cvss_v3_score,
            "severity": top.severity.value if top.severity else None,
            "in_kev": bool(getattr(top, "in_kev", False)),
            "cve_ids": [r.cve_id for r in rows],
        },
        "evidence_count": len(rows),
        "primary_cve_id": top.cve_id,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def answer_question(question: str, db: Session | None = None) -> dict[str, Any]:
    """Answer a question with structured fields, retrieval tracing, and a
    refusal guard."""
    base_provider = llm.provider_name()

    # 1. Empty input --------------------------------------------------------
    if not question or not question.strip():
        return {
            "answer": "Please ask a question about vulnerabilities in your stack.",
            "sources": [],
            "retrieval": None,
            "query_type": "empty",
            "structured": _structured_for_rows([]),
            "provider": base_provider,
        }

    question = question.strip()[:_MAX_QUESTION_LEN]

    # 2. Classify -----------------------------------------------------------
    cls = classify_query(question)
    query_type: str = cls["type"]
    cve_ids: list[str] = cls["cve_ids"]

    # 3. Retrieve -----------------------------------------------------------
    if db is None:
        return {
            "answer": REFUSAL_UNCONFIGURED,
            "sources": [],
            "retrieval": None,
            "query_type": query_type,
            "structured": _structured_for_rows([]),
            "provider": base_provider,
        }

    rows, retrieval_source = _retrieve(db, question, query_type, cve_ids)
    sources = _format_sources(rows)
    structured = _structured_for_rows(rows)

    # 4. Refusal guard ------------------------------------------------------
    if not rows:
        return {
            "answer": REFUSAL_EMPTY,
            "sources": [],
            "retrieval": retrieval_source,
            "query_type": query_type,
            "structured": structured,
            "provider": base_provider,
        }

    # 5. SQL-only summary ---------------------------------------------------
    summary_lines = [
        f"- {r.cve_id} [{r.severity.value if r.severity else 'UNKNOWN'}, "
        f"CVSS {r.cvss_v3_score or 'n/a'}] {r.title or ''}"
        for r in rows
    ]
    sql_summary = "\n".join(summary_lines)

    # 6. No LLM configured --------------------------------------------------
    if not llm.is_configured():
        return {
            "answer": (
                "Found these matching CVEs (no LLM configured — set "
                "GROQ_API_KEY or OPENAI_API_KEY for a natural-language answer):\n\n"
                + sql_summary
            ),
            "sources": sources,
            "retrieval": retrieval_source,
            "query_type": query_type,
            "structured": structured,
            "provider": base_provider,
        }

    # 7. LLM answer ---------------------------------------------------------
    context = _format_context(rows)
    try:
        text = llm.chat_structured(question, context, structured)
        answer = f"{text}\n\nSources:\n{sql_summary}"
    except (RuntimeError, ConnectionError, TimeoutError, OSError) as exc:
        # Don't echo the raw provider error back to the user.
        log.warning("LLM chat failed: %s", exc)
        answer = (
            "LLM call failed; falling back to SQL results:\n\n" + sql_summary
        )

    return {
        "answer": answer,
        "sources": sources,
        "retrieval": retrieval_source,
        "query_type": query_type,
        "structured": structured,
        "provider": base_provider,
    }


def build_index(db: Session | None = None) -> int:
    """Return -1 when no embedding backend is configured."""
    from app.ai.embeddings import get_embeddings
    try:
        get_embeddings()
    except RuntimeError:
        return -1
    return 0


def retrieval_mode() -> str:
    """Return "vector" or "sql" so the UI can badge the active path."""
    return "vector" if _chroma_available() else "sql"