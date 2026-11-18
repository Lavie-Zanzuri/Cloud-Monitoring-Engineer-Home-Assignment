"""Optional cache in front of the detector (ElastiCache / Valkey on AWS).

Why: one phishing campaign sends the SAME email to thousands of people, so the
same content gets scanned again and again. We cache the analysis by the email's
sha256 and skip the work on repeats. Today the detector takes milliseconds; the
cache matters once analysis includes slow external lookups (URL reputation,
WHOIS), which is the natural next step.

Design rule: the cache is an optimisation, never a dependency. If it is down or
slow, every call here returns "no cache" quickly and the app keeps working.
"""
from __future__ import annotations

import json
import logging

from .config import CACHE_TTL_SECONDS, CACHE_URL

log = logging.getLogger("phishing.cache")

# Bump when detection rules change, so old cached verdicts are not reused.
KEY_VERSION = "v1"

_client = None


def _get_client():
    global _client
    if not CACHE_URL:
        return None
    if _client is None:
        import redis   # imported lazily: not needed when the cache is disabled
        _client = redis.Redis.from_url(
            CACHE_URL,
            socket_connect_timeout=0.3,   # a dead cache must not slow every request
            socket_timeout=0.3,
            decode_responses=True,
        )
    return _client


def analysis_key(content_sha256: str) -> str:
    return f"analysis:{KEY_VERSION}:{content_sha256}"


def get_json(key: str) -> dict | None:
    client = _get_client()
    if client is None:
        return None
    try:
        value = client.get(key)
        return json.loads(value) if value else None
    except Exception as exc:          # any cache problem = cache miss
        log.warning("cache read failed", extra={"fields": {"error": type(exc).__name__}})
        return None


def set_json(key: str, value: dict, ttl: int = CACHE_TTL_SECONDS) -> None:
    client = _get_client()
    if client is None:
        return
    try:
        client.set(key, json.dumps(value), ex=ttl)   # TTL: entries expire on their own
    except Exception as exc:
        log.warning("cache write failed", extra={"fields": {"error": type(exc).__name__}})


def cache_status() -> str:
    """For /health/ready: 'disabled', 'ok' or 'unreachable'."""
    client = _get_client()
    if client is None:
        return "disabled"
    try:
        client.ping()
        return "ok"
    except Exception:
        return "unreachable"
