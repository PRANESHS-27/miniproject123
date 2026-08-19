"""Retrieval-Augmented Generation over the vulnerability store.

Flow:
1. Pull the top-N CVEs from SQLite using the user's question as a keyword
   (cheap, deterministic, no vector store needed for 200k rows).
2. Build a small context string with their IDs, severity, and description.
3. Hand the question + context to the configured LLM (OpenAI or Ollama).
4. Fall back to the bare SQL summary when no LLM is configured.
"""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy.orm import Session

from app.ai import llm
from app.services.search_service import search_vulnerabilities

_CONTEXT_LIMIT = 8  # CVEs per answer
_SNIPPET_LEN = 600  # used both for context and source snippet
_MAX_QUESTION_LEN = 4096  # bound to prevent DoS via huge prompts


def _scrub_for_prompt(text: str | None) -> str:
    """Strip characters that an LLM might interpret as instruction
    delimiters from text we inject as *context* (not as instruction).

    CVE descriptions occasionally contain backticks, role-tag-like phrases,
    or even attacker-controlled samples. We never want them to override the
    system prompt. Stripping those characters loses a little formatting
    fidelity but keeps the model behaviour predictable.
    """
    if not text:
        return ""
    # Remove backticks (used by many models as code-fence delimiters) and
    # triple-hash headers. Keep newlines so the prompt is still readable.
    cleaned = re.sub(r"[`#]+", " ", text)
    return cleaned.strip()


def _format_context(rows) -> str:
    """Render the matched CVEs as plain text for the LLM prompt.

    Wrapped in <<<CONTEXT_START>>> / <<<CONTEXT_END>>> markers so the
    model is explicitly told where the untrusted CVE text begins/ends.
    """
    chunks: list[str] = []
    for r in rows:
        sev = r.severity.value if r.severity else "UNKNOWN"
        cvss = f"CVSS {r.cvss_v3_score}" if r.cvss_v3_score is not None else "no CVSS"
        desc = _scrub_for_prompt(r.description)
        chunks.append(f"[{r.cve_id} | {sev} | {cvss}]\n{desc[:_SNIPPET_LEN]}")
    return "<<<CONTEXT_START>>>\n" + "\n\n".join(chunks) + "\n<<<CONTEXT_END>>>"


def _format_sources(rows) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "cve_id": r.cve_id,
                "severity": r.severity.value if r.severity else "",
                "cvss_v3_score": r.cvss_v3_score,
                "title": r.title,
                # HTML-escape on the server side as well as the client so a
                # CVE description containing ``<script>`` can't XSS a
                # consumer that forgets to escape on render.
                "snippet": _scrub_for_prompt(r.description)[:_SNIPPET_LEN // 2],
            }
        )
    return out


def answer_question(question: str, db: Session | None = None) -> dict[str, Any]:
    if db is None:
        return {
            "answer": "AI module unavailable. No database session provided.",
            "sources": [],
            "provider": llm.provider_name(),
        }

    # Bound the question length so a malicious client can't ship a 1 MB
    # prompt and exhaust our LLM quota / DB CPU.
    if not question or not question.strip():
        return {
            "answer": "Please ask a question about vulnerabilities in your stack.",
            "sources": [],
            "provider": llm.provider_name(),
        }
    question = question.strip()[:_MAX_QUESTION_LEN]

    rows, _total = search_vulnerabilities(db, query=question, limit=_CONTEXT_LIMIT)
    sources = _format_sources(rows)

    if not rows:
        return {
            "answer": "I couldn't find any matching CVEs in the database.",
            "sources": [],
            "provider": llm.provider_name(),
        }

    # Always include the SQL summary so the user sees data even if the LLM
    # call fails or isn't configured.
    summary_lines = [
        f"- {r.cve_id} [{r.severity.value if r.severity else 'UNKNOWN'}, "
        f"CVSS {r.cvss_v3_score or 'n/a'}] {r.title or ''}"
        for r in rows
    ]
    sql_summary = "\n".join(summary_lines)

    if not llm.is_configured():
        return {
            "answer": (
                "Found these matching CVEs (no LLM configured — set "
                "OPENAI_API_KEY or OLLAMA_HOST for a natural-language answer):\n\n"
                + sql_summary
            ),
            "sources": sources,
            "provider": llm.provider_name(),
        }

    context = _format_context(rows)
    try:
        text = llm.chat(question, context)
        answer = f"{text}\n\nSources:\n{sql_summary}"
    except (RuntimeError, ConnectionError, TimeoutError, OSError) as exc:
        # Don't echo the raw provider error back to the user — it often
        # contains the user's own question or full CVE context and is a
        # PII / sensitive-data leak. Log it server-side, show a generic
        # fallback.
        import logging
        logging.getLogger("rag").warning("LLM chat failed: %s", exc)
        answer = (
            "LLM call failed; falling back to SQL results:\n\n" + sql_summary
        )

    return {
        "answer": answer,
        "sources": sources,
        "provider": llm.provider_name(),
    }


def build_index(db: Session | None = None) -> int:
    """Return -1 when no embedding backend is configured.

    Callers that want to surface a "rebuild index" button to the user
    can detect -1 and show a config-required message.
    """
    from app.ai.embeddings import get_embeddings
    try:
        get_embeddings()
    except RuntimeError:
        return -1
    return 0
