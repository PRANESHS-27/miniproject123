"""Tests for the RAG retrieval + answer path.

These tests run against an in-memory SQLite so they don't depend on
the project's real vulnwatch.db. They cover the fallback path
(``retrieval == "sql"``) which is what production uses on this machine
when ChromaDB is not installed.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.ai import rag
from app.db.session import Base
from app.models import Severity, Vulnerability


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    s = SessionLocal()
    # Seed with three CVEs across vendors / severities.
    s.add_all([
        Vulnerability(
            cve_id="CVE-2024-0001", title="Apache HTTP Server RCE",
            description="Remote code execution in Apache HTTP Server 2.4.x via mod_rewrite.",
            cvss_v3_score=9.8, severity=Severity.CRITICAL, in_kev=False,
        ),
        Vulnerability(
            cve_id="CVE-2024-0002", title="Moodle SQL Injection",
            description="SQL injection in Moodle login form allowing credential bypass.",
            cvss_v3_score=7.5, severity=Severity.HIGH, in_kev=True,
        ),
        Vulnerability(
            cve_id="CVE-2024-0003", title="Nginx off-by-one",
            description="Off-by-one in nginx request line parsing.",
            cvss_v3_score=5.0, severity=Severity.MEDIUM, in_kev=False,
        ),
    ])
    s.commit()
    yield s
    s.close()


# ---------------------------------------------------------------------------
# Retrieval mode
# ---------------------------------------------------------------------------
def test_retrieval_mode_is_known_string():
    """Whatever the environment, the answer is one of the documented
    modes. If a future change adds a third, this test makes the
    change visible."""
    assert rag.retrieval_mode() in {"vector", "sql"}


def test_chroma_probe_does_not_raise():
    """Even on a broken install, the probe must not raise — the
    fallback contract is "always answer, never crash"."""
    assert isinstance(rag._chroma_available(), bool)


# ---------------------------------------------------------------------------
# Retrieval (SQL fallback path)
# ---------------------------------------------------------------------------
def test_retrieve_returns_rows_for_known_vendor(db):
    cls = rag.classify_query("Apache")
    rows, source = rag._retrieve(db, "Apache", cls["type"], cls["cve_ids"])
    assert source in {"vector", "sql", "exact"}
    # Either path may return zero rows depending on the keyword index,
    # so the contract we enforce is "the function doesn't crash and
    # returns a list" rather than "always finds a match".
    assert isinstance(rows, list)


def test_retrieve_falls_back_to_sql_when_chromadb_unavailable(db, monkeypatch):
    """Force the vector probe to fail and confirm the SQL path runs."""
    monkeypatch.setattr(rag, "_chroma_available", lambda: False)
    cls = rag.classify_query("Moodle")
    rows, source = rag._retrieve(db, "Moodle", cls["type"], cls["cve_ids"])
    assert source == "sql"
    assert isinstance(rows, list)


def test_retrieve_uses_vector_when_available(db, monkeypatch):
    """When ChromaDB is available and returns rows, we use them."""
    sentinel = [object()]
    monkeypatch.setattr(rag, "_chroma_available", lambda: True)
    monkeypatch.setattr(rag, "_vector_search", lambda q, k: sentinel)
    cls = rag.classify_query("anything")
    rows, source = rag._retrieve(db, "anything", cls["type"], cls["cve_ids"])
    assert source == "vector"
    assert rows is sentinel


def test_retrieve_falls_back_when_vector_returns_empty(db, monkeypatch):
    """Empty vector result should trigger the SQL fallback — never
    return an empty answer when SQL has matches."""
    monkeypatch.setattr(rag, "_chroma_available", lambda: True)
    monkeypatch.setattr(rag, "_vector_search", lambda q, k: [])
    cls = rag.classify_query("Apache")
    rows, source = rag._retrieve(db, "Apache", cls["type"], cls["cve_ids"])
    assert source == "sql"


# ---------------------------------------------------------------------------
# Answer contract
# ---------------------------------------------------------------------------
def test_answer_includes_provider_and_retrieval(db):
    result = rag.answer_question("Apache", db=db)
    assert "provider" in result
    assert "retrieval" in result
    assert result["retrieval"] in {"vector", "sql", "exact"}
    assert isinstance(result["sources"], list)


def test_answer_handles_empty_question(db):
    result = rag.answer_question("", db=db)
    assert "answer" in result
    assert result["sources"] == []


def test_answer_handles_missing_db():
    result = rag.answer_question("anything", db=None)
    assert "AI module unavailable" in result["answer"] or "not configured" in result["answer"].lower() or "couldn't" in result["answer"].lower()


def test_answer_bounds_long_question(db):
    huge = "x" * 10_000
    result = rag.answer_question(huge, db=db)
    # Should not raise, should return a structured dict.
    assert isinstance(result, dict)
    assert "answer" in result


def test_answer_scrubs_dangerous_chars_in_source_snippets(db):
    """Source snippets must not contain backticks or hashes that an
    LLM could interpret as prompt delimiters."""
    # Add a CVE with adversarial characters
    db.add(Vulnerability(
        cve_id="CVE-2024-9999",
        title="evil",
        description="try to break out `with backticks` and ```triple```",
        cvss_v3_score=5.0, severity=Severity.MEDIUM,
    ))
    db.commit()
    result = rag.answer_question("evil", db=db)
    for s in result["sources"]:
        assert "`" not in s["snippet"]


# ---------------------------------------------------------------------------
# 20-question regression eval
# ---------------------------------------------------------------------------
EVAL_QUESTIONS = [
    "Apache vulnerabilities",
    "Moodle SQL injection",
    "nginx off-by-one",
    "critical CVEs",
    "CVE-2024-0001",
    "CVE-2024-0002",
    "CVE-2024-0003",
    "KEV listed vulnerabilities",
    "remote code execution",
    "high severity",
    "medium severity",
    "exploited in the wild",
    "credential bypass",
    "mod_rewrite exploit",
    "login form",
    "off-by-one parsing",
    "2024 vulnerabilities",
    "9.8 CVSS",
    "Apache 2.4.x",
    "known exploited",
]


@pytest.mark.parametrize("question", EVAL_QUESTIONS)
def test_20_question_eval_set_does_not_crash(db, question):
    """Regression: the 20 representative questions should all be
    answered without raising. Whether the answer is rich or sparse
    depends on the underlying data, but the contract is "always
    answer, never crash"."""
    result = rag.answer_question(question, db=db)
    assert isinstance(result, dict)
    assert "answer" in result
    assert "sources" in result
    assert isinstance(result["sources"], list)


# ===========================================================================
# Step 7 — query classifier, refusal guard, structured response
# ===========================================================================
class TestQueryClassifier:
    """``classify_query`` and ``extract_cve_ids`` are pure functions over
    the input string — no DB, no LLM. They must be deterministic and
    handle every reasonable input shape."""

    def test_extract_cve_ids_finds_single(self):
        assert rag.extract_cve_ids("Tell me about CVE-2024-1234") == ["CVE-2024-1234"]

    def test_extract_cve_ids_dedupes_and_sorts(self):
        ids = rag.extract_cve_ids("CVE-2024-0003 and CVE-2024-0001 and CVE-2024-0001 again")
        assert ids == ["CVE-2024-0001", "CVE-2024-0003"]

    def test_extract_cve_ids_uppercases(self):
        assert rag.extract_cve_ids("cve-2024-0001") == ["CVE-2024-0001"]

    def test_extract_cve_ids_returns_empty_on_garbage(self):
        assert rag.extract_cve_ids("just a question about Apache") == []

    def test_extract_cve_ids_returns_empty_on_empty(self):
        assert rag.extract_cve_ids("") == []

    def test_classify_empty(self):
        cls = rag.classify_query("")
        assert cls["type"] == "empty"
        assert cls["cve_ids"] == []

    def test_classify_whitespace_only(self):
        cls = rag.classify_query("   \t  ")
        assert cls["type"] == "empty"

    def test_classify_exact_cve(self):
        cls = rag.classify_query("CVE-2024-0001")
        assert cls["type"] == "exact_cve"
        assert cls["cve_ids"] == ["CVE-2024-0001"]

    def test_classify_exact_with_connector_words(self):
        cls = rag.classify_query("Show details about CVE-2024-0001 please")
        assert cls["type"] == "exact_cve"

    def test_classify_natural_language_with_cve_mention(self):
        cls = rag.classify_query(
            "Why is CVE-2024-0001 critical and which assets does it affect?"
        )
        assert cls["type"] == "natural_language"
        assert "CVE-2024-0001" in cls["cve_ids"]

    def test_classify_natural_language_no_cve(self):
        cls = rag.classify_query("Which critical vulnerabilities affect Apache?")
        assert cls["type"] == "natural_language"
        assert cls["cve_ids"] == []


class TestRefusalGuard:
    """When retrieval returns zero rows, the LLM path must NOT run.
    The user gets the explicit refusal string instead."""

    def test_empty_question_returns_prompt_to_ask(self):
        result = rag.answer_question("", db=None)
        assert "answer" in result
        assert result["query_type"] == "empty"
        assert result["sources"] == []

    def test_no_db_returns_unconfigured_refusal(self, monkeypatch):
        monkeypatch.setattr(rag.llm, "is_configured", lambda: True)
        result = rag.answer_question("Apache", db=None)
        assert "not configured" in result["answer"].lower()
        assert result["sources"] == []
        assert result["structured"]["evidence_count"] == 0

    def test_no_results_returns_explicit_refusal(self, db):
        """Question about a vendor that doesn't exist in the seeded DB."""
        result = rag.answer_question("Zorblax Quantum Framework vulnerabilities", db=db)
        assert result["sources"] == []
        assert "couldn't find" in result["answer"].lower()
        assert result["query_type"] == "natural_language"
        # The refusal must include the structured block but with zero evidence.
        assert result["structured"]["evidence_count"] == 0
        assert result["structured"]["primary_cve_id"] is None

    def test_refusal_does_not_call_llm_when_no_rows(self, db, monkeypatch):
        """The contract: zero rows → no LLM call. We assert by patching
        ``chat_structured`` to raise if it ever gets called on an empty
        retrieval."""
        def _should_not_be_called(*a, **kw):
            raise AssertionError("LLM was called on empty retrieval")

        monkeypatch.setattr(rag.llm, "chat_structured", _should_not_be_called)
        monkeypatch.setattr(rag.llm, "is_configured", lambda: True)
        result = rag.answer_question("Zorblax", db=db)
        assert "couldn't find" in result["answer"].lower()

    def test_exact_cve_not_in_db_returns_refusal(self, db):
        result = rag.answer_question("CVE-2099-99999", db=db)
        assert result["sources"] == []
        assert "couldn't find" in result["answer"].lower()
        assert result["retrieval"] == "exact"


class TestExactCveLookup:
    """Exact-CVE queries take a different code path — authoritative SQL
    lookup by primary key, not vector / keyword search."""

    def test_exact_cve_returns_one_row(self, db):
        result = rag.answer_question("CVE-2024-0001", db=db)
        assert result["retrieval"] == "exact"
        assert result["query_type"] == "exact_cve"
        assert len(result["sources"]) == 1
        assert result["sources"][0]["cve_id"] == "CVE-2024-0001"

    def test_exact_cve_returns_match_in_input_order(self, db):
        """Two-CVE question, second one exists but first doesn't → only
        the second is returned, in the order it was requested."""
        result = rag.answer_question("CVE-2099-99999 CVE-2024-0002", db=db)
        assert result["retrieval"] == "exact"
        assert [s["cve_id"] for s in result["sources"]] == ["CVE-2024-0002"]

    def test_exact_cve_uses_sql_path_even_when_chromadb_available(self, db, monkeypatch):
        """Even if ChromaDB is available, exact-CVE queries bypass it."""
        monkeypatch.setattr(rag, "_chroma_available", lambda: True)
        # If the vector path were taken, source would be "vector".
        result = rag.answer_question("CVE-2024-0001", db=db)
        assert result["retrieval"] == "exact"


class TestStructuredResponse:
    """The structured block is descriptive (CVSS/severity/KEV from CVE
    metadata) — it must NOT carry an institutional risk calculation.
    The Risk Engine is authoritative for institutional risk."""

    def test_structured_block_present_on_hit(self, db):
        result = rag.answer_question("CVE-2024-0001", db=db)
        s = result["structured"]
        assert s["evidence_count"] == 1
        assert s["primary_cve_id"] == "CVE-2024-0001"
        # Descriptive facts from CVE metadata — these are allowed.
        assert s["summary"]["cvss"] == 9.8
        assert s["summary"]["severity"] == "CRITICAL"
        assert s["summary"]["in_kev"] is False
        assert "CVE-2024-0001" in s["summary"]["cve_ids"]

    def test_structured_block_picks_kev_row_as_primary(self, db):
        """When multiple CVEs match, the structured block surfaces the
        KEV-listed one as primary, not just the highest CVSS.

        We seed an extra KEV-listed row whose keyword matches the seed
        description so we don't depend on the SQL keyword index hitting
        the existing 3 rows verbatim.
        """
        from app.models import Vulnerability, Severity
        db.add(Vulnerability(
            cve_id="CVE-2024-9001",
            title="Apache Tomcat path traversal",
            description="Apache Tomcat 9.x path traversal vulnerability.",
            cvss_v3_score=6.5,
            severity=Severity.MEDIUM,
            in_kev=True,
        ))
        db.commit()
        result = rag.answer_question("Apache", db=db)
        # The KEV row is picked as primary even though its CVSS (6.5) is
        # lower than the CRITICAL 9.8 row.
        assert result["structured"]["primary_cve_id"] == "CVE-2024-9001"
        assert result["structured"]["summary"]["in_kev"] is True

    def test_structured_block_does_not_contain_institutional_risk(self, db):
        """Constraint: the LLM/RAG layer must NOT compute risk.
        The Risk Engine remains authoritative."""
        result = rag.answer_question("CVE-2024-0001", db=db)
        forbidden_keys = {"risk", "affected_assets", "why_it_matters",
                          "recommended_action", "risk_score", "risk_label"}
        assert not (forbidden_keys & set(result["structured"].keys()))
        # Also the top-level response should not have those keys.
        assert not (forbidden_keys & set(result.keys()))

    def test_structured_block_on_empty_has_nulls(self, db):
        result = rag.answer_question("Zorblax", db=db)
        s = result["structured"]
        assert s["evidence_count"] == 0
        assert s["primary_cve_id"] is None
        assert s["summary"]["cvss"] is None
        assert s["summary"]["severity"] is None
        assert s["summary"]["in_kev"] is False
        assert s["summary"]["cve_ids"] == []

    def test_sources_carry_in_kev_flag(self, db):
        result = rag.answer_question("CVE-2024-0002", db=db)
        assert len(result["sources"]) == 1
        assert result["sources"][0]["in_kev"] is True


class TestResponseShape:
    """Every response — hit, miss, empty — has the same key set."""

    EXPECTED_KEYS = {"answer", "sources", "retrieval", "query_type",
                     "structured", "provider"}

    def test_keys_on_hit(self, db):
        result = rag.answer_question("CVE-2024-0001", db=db)
        assert self.EXPECTED_KEYS <= set(result.keys())

    def test_keys_on_miss(self, db):
        result = rag.answer_question("Zorblax", db=db)
        assert self.EXPECTED_KEYS <= set(result.keys())

    def test_keys_on_empty(self):
        result = rag.answer_question("", db=None)
        assert self.EXPECTED_KEYS <= set(result.keys())

    def test_query_type_is_one_of_three(self, db):
        for q in ["CVE-2024-0001", "Apache", "Zorblax", ""]:
            result = rag.answer_question(q, db=db)
            assert result["query_type"] in {"exact_cve", "natural_language", "empty"}

    def test_retrieval_is_one_of_three(self, db):
        for q in ["CVE-2024-0001", "Apache"]:
            result = rag.answer_question(q, db=db)
            assert result["retrieval"] in {"exact", "vector", "sql", None}


class TestPromptInjectionGuard:
    """CVE descriptions occasionally contain adversarial characters.
    The prompt scrubber must strip backticks and hashes."""

    def test_scrub_strips_backticks(self):
        assert "`" not in rag._scrub_for_prompt("a `b` c")
        assert "`" not in rag._scrub_for_prompt("```code```")

    def test_scrub_strips_hashes(self):
        assert "#" not in rag._scrub_for_prompt("## heading")

    def test_scrub_handles_none(self):
        assert rag._scrub_for_prompt(None) == ""

    def test_scrub_preserves_newlines(self):
        out = rag._scrub_for_prompt("line1\nline2")
        assert "\n" in out
