"""One JSON object per log line. CloudWatch Logs Insights can then filter and
aggregate on fields (status, latency_ms, path) instead of grepping free text."""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

from .config import INSTANCE_ID


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "time": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "instance": INSTANCE_ID,
        }
        entry.update(getattr(record, "fields", {}))      # extra structured fields
        if record.exc_info:
            entry["error"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


def setup_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    # uvicorn's own access log would duplicate our request log
    logging.getLogger("uvicorn.access").disabled = True
