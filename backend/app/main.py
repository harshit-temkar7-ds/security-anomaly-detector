"""FastAPI application: Security Log Anomaly Detector."""
from __future__ import annotations

from typing import Literal, Optional

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from . import service, store
from .config import DEFAULT_UBA_MIN_HISTORY, FEATURES, settings
from .routes_ai import router as ai_router
from .routes_v2 import router as v2_router
from .schemas import AnalyzeResponse, ScanListItem
from .validation import parse_csv

WARNING = service.WARNING  # kept for backwards compatibility

app = FastAPI(
    title="Security Log Anomaly Detector",
    version="3.0.0",
    description="API for investigating unusual login events. "
                "Flags are leads for a human analyst, not proof of an attack.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,  # explicit origins; never '*' with credentials
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["*"],
    expose_headers=["X-LLM-Used", "X-LLM-Reason"],
)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "security-log-anomaly-detector"}


@app.get("/api/sample")
def sample():
    """Download the bundled sample CSV (handy for demos)."""
    if not settings.sample_path.exists():
        raise HTTPException(404, "Sample file not generated. Run scripts/generate_data.py.")
    return FileResponse(settings.sample_path, media_type="text/csv", filename="sample_login_events.csv")


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze(
    file: UploadFile = File(...),
    mode: Literal["baseline", "batch"] = Query("baseline"),
    threshold: Optional[float] = Query(None, gt=0, lt=1, description="Optional score threshold (label-free)."),
    uba_min_history: int = Query(DEFAULT_UBA_MIN_HISTORY, ge=3, le=100),
):
    raw = await file.read(settings.max_file_bytes + 1)  # bounded read
    df = parse_csv(file.filename, raw)

    def run() -> dict:
        scan_id = service.analyze_dataframe(df, file.filename or "upload.csv", mode, threshold, uba_min_history)
        return service.scan_response(scan_id)  # type: ignore[return-value]

    return await run_in_threadpool(run)


@app.get("/api/scans", response_model=list[ScanListItem])
def list_scans(limit: int = Query(20, ge=1, le=200), offset: int = Query(0, ge=0)):
    items, _ = store.list_scans(limit, offset)
    return items


@app.get("/api/scans/{scan_id}", response_model=AnalyzeResponse)
def get_scan(scan_id: str):
    resp = service.scan_response(scan_id)
    if resp is None:
        raise HTTPException(404, "Scan not found.")
    return resp


app.include_router(v2_router)
app.include_router(ai_router)

__all__ = ["app", "FEATURES"]
