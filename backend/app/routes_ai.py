"""AI-assist endpoints: plain-English search, analyst copilot and the analyst-feedback triage model."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from . import copilot, nlsearch, store, triage

router = APIRouter(prefix="/api")


class SearchIn(BaseModel):
    query: str = Field(..., min_length=1, max_length=300)


class AskIn(BaseModel):
    question: str = Field(..., min_length=1, max_length=500)
    use_llm: bool = True


class TrainIn(BaseModel):
    activate: bool = False


def _scan_or_404(scan_id: str) -> dict:
    scan = store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found.")
    return scan


@router.post("/scans/{scan_id}/nl-search")
def nl_search(scan_id: str, body: SearchIn):
    """Turn plain English into explicit, visible filters over flagged events."""
    return nlsearch.search(_scan_or_404(scan_id), body.query)


@router.post("/scans/{scan_id}/copilot")
def ask_copilot(scan_id: str, body: AskIn):
    """Grounded Q&A over one scan. Uses Gemini only if enabled; otherwise answers offline."""
    return copilot.answer(_scan_or_404(scan_id), body.question.strip(), body.use_llm)


@router.get("/feedback/summary")
def feedback_summary():
    return triage.summary()


@router.post("/feedback/train")
def feedback_train(body: TrainIn):
    """Preview (default) or activate a triage model learned from false-positive / escalated alerts."""
    return triage.train(body.activate)


@router.post("/feedback/rollback")
def feedback_rollback():
    return triage.rollback()
