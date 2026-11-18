"""All settings come from environment variables (12-factor style), so the same
code runs locally (SQLite) and on AWS (PostgreSQL on RDS) without changes."""
from __future__ import annotations

import os
import socket

# Locally: a SQLite file next to the app. On AWS: postgresql+psycopg://user:pass@host:5432/db
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./phishing.db")

# Which machine served the request - shown in logs and the X-Served-By header,
# so the demo can show the load balancer spreading requests across instances.
INSTANCE_ID = os.getenv("INSTANCE_ID") or socket.gethostname()

MAX_EMAIL_BYTES = int(os.getenv("MAX_EMAIL_BYTES", str(1_000_000)))   # 1 MB
HISTORY_PAGE_SIZE = 20

# Optional cache (ElastiCache / Valkey). Empty = no cache; everything still works.
# On AWS: rediss://<primary-endpoint>:6379/0  (rediss = TLS)
CACHE_URL = os.getenv("CACHE_URL", "")
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "3600"))
