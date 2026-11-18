"""Glue between the detector and the database: run a scan, add what history
tells us about the sender, store the result."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from detector.analyzer import AnalysisResult, analyze
from detector.domains import domain_of, registered_domain
from detector.models import Finding
from detector.scorer import score_findings

from . import cache
from .config import INSTANCE_ID
from .db import Scan

POINTS_PREVIOUSLY_FLAGGED = 20


def _iso_utc(moment: datetime | None) -> str | None:
    """SQLite drops the timezone on read, PostgreSQL keeps it. Times are always
    stored in UTC, so a naive value is UTC - say so, or browsers show it as local time."""
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.isoformat()


def _history_findings(session: Session, sender_domain: str) -> list[Finding]:
    """A sender domain we already flagged as phishing is more likely to be phishing again."""
    if not sender_domain:
        return []
    flagged = session.scalar(
        select(func.count()).select_from(Scan)
        .where(Scan.sender_domain == sender_domain, Scan.verdict == "Phishing"))
    if not flagged:
        return []
    times = "once" if flagged == 1 else f"{flagged} times"
    return [Finding("history", "Sender previously flagged",
                    f"'{sender_domain}' was flagged as phishing {times} before",
                    POINTS_PREVIOUSLY_FLAGGED)]


def scan_email(session: Session, raw: str) -> dict:
    content_sha256 = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()

    # Same email scanned before (e.g. one campaign sent to many people)? Reuse the analysis.
    key = cache.analysis_key(content_sha256)
    cached = cache.get_json(key)
    if cached is not None:
        result = AnalysisResult.from_dict(cached)
    else:
        result = analyze(raw)
        cache.set_json(key, result.to_dict())

    # History is NOT cached: "sender previously flagged" must reflect the latest scans.
    sender_domain = registered_domain(domain_of(result.from_address))

    extra = _history_findings(session, sender_domain)
    if extra:                       # re-score with the history evidence included
        result.findings = sorted(result.findings + extra, key=lambda f: f.points, reverse=True)
        scored = score_findings(result.findings)
        result.score, result.verdict, result.category_scores = (
            scored.score, scored.verdict, scored.category_scores)

    row = Scan(
        sender_address=result.from_address[:320],
        sender_domain=sender_domain[:255],
        subject=result.subject[:500],
        verdict=result.verdict,
        score=result.score,
        findings=[f.__dict__ for f in result.findings],
        content_sha256=content_sha256,
        served_by=INSTANCE_ID,
    )
    session.add(row)
    session.commit()

    data = result.to_dict()
    data["scan_id"] = row.id
    data["created_at"] = _iso_utc(row.created_at)
    data["cached"] = cached is not None
    return data


def recent_scans(session: Session, limit: int) -> list[dict]:
    rows = session.scalars(select(Scan).order_by(Scan.id.desc()).limit(limit)).all()
    return [{
        "id": r.id,
        "created_at": _iso_utc(r.created_at),
        "sender": r.sender_address,
        "subject": r.subject,
        "verdict": r.verdict,
        "score": r.score,
        "indicators": len(r.findings or []),
        "served_by": r.served_by,
    } for r in rows]
