"""AI / RAG routes."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.ai import llm, rag
from app.api.deps import get_current_user
from app.db import get_db
from app.models import SearchLog, User

router = APIRouter(prefix="/api/ai", tags=["ai"])


class QuestionRequest(BaseModel):
    question: str


@router.post("/ask")
def ask(
    payload: QuestionRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Answer a natural-language question using RAG over the CVE store."""
    result = rag.answer_question(payload.question, db=db)
    db.add(
        SearchLog(
            user_id=user.id,
            query=payload.question,
            result_count=len(result.get("sources", [])),
            source="rag",
        )
    )
    db.commit()
    return result


@router.get("/status")
def status(_: User = Depends(get_current_user)):
    """Report which LLM provider is wired up so the UI can badge it."""
    return {
        "provider": llm.provider_name(),
        "configured": llm.is_configured(),
    }