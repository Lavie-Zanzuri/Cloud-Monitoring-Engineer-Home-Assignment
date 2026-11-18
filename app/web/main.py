"""FastAPI app: the UI, the scan API, history, and health checks.

Run locally:   uvicorn web.main:app --reload
API docs:      http://localhost:8000/docs
"""
from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .config import HISTORY_PAGE_SIZE, INSTANCE_ID, MAX_EMAIL_BYTES
from .cache import cache_status
from .db import db_is_reachable, get_session, init_db
from .logging_config import setup_logging
from .service import recent_scans, scan_email

setup_logging()
log = logging.getLogger("phishing.web")
STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(_: FastAPI):
    try:
        init_db()
        log.info("database ready")
    except SQLAlchemyError:
        # Keep serving: /health stays up, /health/ready reports the DB problem.
        log.exception("database not reachable at startup")
    yield


app = FastAPI(title="Phishing Detector", version="1.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def log_requests(request: Request, call_next):
    request_id = request.headers.get("X-Request-Id") or uuid.uuid4().hex[:12]
    start = time.perf_counter()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
    finally:
        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        if request.url.path not in ("/health",):          # ALB health checks every few seconds = noise
            log.info("request", extra={"fields": {
                "request_id": request_id, "method": request.method, "path": request.url.path,
                "status": status, "latency_ms": latency_ms,
                "client_ip": request.headers.get("X-Forwarded-For", request.client.host if request.client else ""),
            }})
    response.headers["X-Served-By"] = INSTANCE_ID
    response.headers["X-Request-Id"] = request_id
    return response


# ---------- health ----------

@app.get("/health", tags=["health"])
def health():
    """Liveness for the load balancer: is this process up? Deliberately does NOT
    touch the database - if RDS has a problem, both instances would fail this
    check and the ALB would pull the whole site, turning a DB issue into a full outage."""
    return {"status": "ok", "instance": INSTANCE_ID}


@app.get("/health/ready", tags=["health"])
def ready():
    """Readiness for monitoring: can this instance do real work (DB included)?"""
    # The cache is reported but never makes the instance "not ready": without it
    # the app is slower on repeats, not broken.
    cache = cache_status()
    if db_is_reachable():
        return {"status": "ready", "database": "ok", "cache": cache, "instance": INSTANCE_ID}
    return JSONResponse(status_code=503,
                        content={"status": "degraded", "database": "unreachable", "cache": cache,
                                 "instance": INSTANCE_ID})


# ---------- API ----------

class ScanRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=MAX_EMAIL_BYTES,
                         description="Raw email (.eml text) or pasted email body")


def _run_scan(session: Session, raw: str) -> dict:
    try:
        result = scan_email(session, raw)
    except SQLAlchemyError:
        log.exception("scan could not be saved")
        raise HTTPException(503, "Scan history is temporarily unavailable, please retry.")
    log.info("scan", extra={"fields": {"verdict": result["verdict"], "score": result["score"],
                                       "indicators": len(result["findings"]),
                                       "cache": "hit" if result.get("cached") else "miss"}})
    return result


@app.post("/api/scan", tags=["scan"])
def scan_text(body: ScanRequest, session: Session = Depends(get_session)):
    return _run_scan(session, body.content)


@app.post("/api/scan/file", tags=["scan"])
async def scan_file(file: UploadFile = File(...), session: Session = Depends(get_session)):
    data = await file.read(MAX_EMAIL_BYTES + 1)
    if len(data) > MAX_EMAIL_BYTES:
        raise HTTPException(413, f"File too large (max {MAX_EMAIL_BYTES // 1000} KB).")
    if not data.strip():
        raise HTTPException(400, "File is empty.")
    return _run_scan(session, data.decode("utf-8", errors="replace"))


@app.get("/api/history", tags=["history"])
def history(limit: int = Query(HISTORY_PAGE_SIZE, ge=1, le=100), session: Session = Depends(get_session)):
    try:
        return {"scans": recent_scans(session, limit)}
    except SQLAlchemyError:
        log.exception("history query failed")
        raise HTTPException(503, "Scan history is temporarily unavailable.")


# ---------- UI ----------

@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")
