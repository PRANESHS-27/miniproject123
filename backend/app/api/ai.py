"""AI / RAG and Intelligent Security Assistant routes."""

from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.ai import llm, rag
from app.api.deps import get_current_user
from app.db import get_db
from app.models import SearchLog, User

router = APIRouter(prefix="/api/ai", tags=["ai"])
assistant_router = APIRouter(prefix="/api/assistant", tags=["assistant"])


class QuestionRequest(BaseModel):
    question: Optional[str] = None
    query: Optional[str] = None


def _handle_assistant_query(payload: QuestionRequest, db: Session, user: User) -> dict:
    prompt = (payload.question or payload.query or "").strip()
    result = rag.answer_question(prompt, db=db)
    try:
        db.add(
            SearchLog(
                user_id=user.id,
                query=prompt,
                result_count=len(result.get("sources", [])),
                source="rag",
            )
        )
        db.commit()
    except Exception:
        pass
    return result


@router.post("/ask")
def ask(
    payload: QuestionRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Answer a natural-language question using RAG over the CVE store."""
    return _handle_assistant_query(payload, db, user)


@assistant_router.post("/query")
def query_assistant(
    payload: QuestionRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Intelligent Security Query Interface — grounded in verified database records."""
    return _handle_assistant_query(payload, db, user)


@router.get("/status")
@assistant_router.get("/status")
def status(_: User = Depends(get_current_user)):
    """Report which LLM provider is wired up so the UI can badge it."""
    from app.ai import rag
    return {
        "provider": llm.provider_name(),
        "configured": llm.is_configured(),
        "retrieval": rag.retrieval_mode(),
    }