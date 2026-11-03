"""Additive v2 endpoints: history, thresholds, alert investigation, user analytics, reports."""
from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, HTTPException, Query, Response

from . import llm, service, store
from .config import STATUSES, settings
from .investigation import BANDS_TEXT, SEVERITY_POLICY
from .reports import build_report, facts_for_llm
from .schemas import (AlertDetail, AlertPage, AppConfig, HistoryPage, NoteIn, Note, StatusIn,
                      ThresholdEvaluation, ThresholdIn, UserPage, UserProfile)

router = APIRouter(prefix="/api")


def _scan_or_404(scan_id: str) -> dict:
    scan = store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found.")
    return scan


@router.get("/config", response_model=AppConfig)
def config():
    return {"llm_available": llm.available(), "statuses": STATUSES, "severity_policy": SEVERITY_POLICY,
            "severity_bands": BANDS_TEXT,
            "limits": {"max_file_bytes": settings.max_file_bytes, "max_rows": settings.max_rows}}


# ---------------------------------------------------------------- history
@router.get("/history", response_model=HistoryPage)
def history(page: int = Query(1, ge=1), page_size: int = Query(10, ge=1, le=100),
            q: Optional[str] = Query(None, max_length=100)):
    items, total = store.list_scans(page_size, (page - 1) * page_size, q)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.delete("/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: str):
    if not store.delete_scan(scan_id):
        raise HTTPException(404, "Scan not found.")
    return Response(status_code=204)


# -------------------------------------------------------------- thresholds
@router.get("/scans/{scan_id}/evaluate", response_model=ThresholdEvaluation)
def evaluate(scan_id: str, threshold: Optional[float] = Query(None, gt=0, lt=1)):
    """Preview flags and metrics at a threshold without changing the stored scan."""
    scan = _scan_or_404(scan_id)
    return service.threshold_evaluation(scan, scan["threshold"] if threshold is None else threshold)


@router.put("/scans/{scan_id}/threshold", response_model=ThresholdEvaluation)
def set_threshold(scan_id: str, body: ThresholdIn):
    """Persist a new active threshold (re-derives flags, metrics and severities; no re-scoring)."""
    scan = _scan_or_404(scan_id)
    service.apply_threshold(scan, body.threshold)
    return service.threshold_evaluation(_scan_or_404(scan_id), body.threshold)


# ------------------------------------------------------------------ alerts
@router.get("/scans/{scan_id}/alerts", response_model=AlertPage)
def alerts(scan_id: str,
           detector: Literal["model", "rules", "either"] = "model",
           severity: Optional[Literal["low", "medium", "high", "critical", "none"]] = None,
           status: Optional[Literal["new", "in_review", "escalated", "false_positive", "resolved"]] = None,
           username: Optional[str] = Query(None, max_length=100),
           q: Optional[str] = Query(None, max_length=100),
           threshold: Optional[float] = Query(None, gt=0, lt=1),
           page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100)):
    scan = _scan_or_404(scan_id)
    return service.list_alerts(scan, detector, severity, status, username, q, page, page_size, threshold)


def _event_or_404(scan_id: str, row: int) -> dict:
    ev = store.get_event(scan_id, row)
    if ev is None:
        raise HTTPException(404, "Event not found.")
    return ev


@router.get("/scans/{scan_id}/alerts/{row}", response_model=AlertDetail)
def alert(scan_id: str, row: int):
    scan = _scan_or_404(scan_id)
    return service.alert_detail(scan, _event_or_404(scan_id, row))


@router.patch("/scans/{scan_id}/alerts/{row}", response_model=AlertDetail)
def update_status(scan_id: str, row: int, body: StatusIn):
    scan = _scan_or_404(scan_id)
    _event_or_404(scan_id, row)
    store.set_status(scan_id, row, body.status)
    return service.alert_detail(scan, _event_or_404(scan_id, row))


@router.post("/scans/{scan_id}/alerts/{row}/notes", response_model=Note, status_code=201)
def add_note(scan_id: str, row: int, body: NoteIn):
    _scan_or_404(scan_id)
    _event_or_404(scan_id, row)
    return store.add_note(scan_id, row, body.author.strip(), body.note.strip())


# ------------------------------------------------------------------- users
@router.get("/scans/{scan_id}/users", response_model=UserPage)
def users(scan_id: str, q: Optional[str] = Query(None, max_length=100),
          page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100)):
    return service.list_users(_scan_or_404(scan_id), q, page, page_size)


@router.get("/scans/{scan_id}/user-profile", response_model=UserProfile)
def user_profile(scan_id: str, username: str = Query(..., min_length=1, max_length=100)):
    prof = service.get_user_profile(_scan_or_404(scan_id), username)
    if prof is None:
        raise HTTPException(404, "User not found in this scan.")
    return prof


# ----------------------------------------------------------------- reports
@router.get("/scans/{scan_id}/report")
def report(scan_id: str, format: Literal["md", "txt"] = "md",
           top: int = Query(10, ge=1, le=100), include_notes: bool = True,
           row: Optional[int] = Query(None, ge=1), use_llm: bool = False,
           download: bool = False):
    scan = _scan_or_404(scan_id)
    if row is not None:
        _event_or_404(scan_id, row)
    ctx = service.report_context(scan, top, include_notes, row)
    narrative, llm_reason = None, "disabled"
    if use_llm:
        try:
            narrative, llm_reason = llm.complete_with_reason(facts_for_llm(ctx))
        except Exception:
            # Keep provider details, request data, and credentials out of logs and responses.
            llm_reason = "network"
        if narrative is None:
            ctx["uncertainty"].append(
                "LLM summary could not be generated; showing the offline template report."
            )
    text = build_report(ctx, format, narrative)
    headers = {"X-Content-Type-Options": "nosniff", "X-LLM-Used": str(narrative is not None).lower(),
               "X-LLM-Reason": llm_reason}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="incident_report_{scan["scan_id"]}.{format}"'
    media = "text/markdown" if format == "md" else "text/plain"
    return Response(text, media_type=f"{media}; charset=utf-8", headers=headers)
