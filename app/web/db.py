"""Database model + session. SQLAlchemy hides the SQLite/PostgreSQL difference."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Integer, String, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from .config import DATABASE_URL

_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(
    DATABASE_URL,
    connect_args=_connect_args,
    pool_pre_ping=True,     # drop dead connections (e.g. after an RDS failover) instead of failing a request
)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class Scan(Base):
    """One row per scan = the 'history of actions'. The email itself is NOT stored
    (privacy): only who sent it, what we decided and why, and a hash to spot repeats."""
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    sender_address: Mapped[str] = mapped_column(String(320), default="")
    sender_domain: Mapped[str] = mapped_column(String(255), default="", index=True)
    subject: Mapped[str] = mapped_column(String(500), default="")
    verdict: Mapped[str] = mapped_column(String(20), index=True)
    score: Mapped[int] = mapped_column(Integer)
    findings: Mapped[list] = mapped_column(JSON, default=list)
    content_sha256: Mapped[str] = mapped_column(String(64), index=True)
    served_by: Mapped[str] = mapped_column(String(255), default="")


def init_db() -> None:
    """Create tables if missing. Fine for this project; Alembic migrations would be the next step."""
    Base.metadata.create_all(engine)


def db_is_reachable() -> bool:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def get_session():
    with SessionLocal() as session:
        yield session


__all__ = ["Scan", "Session", "SessionLocal", "engine", "get_session", "init_db", "db_is_reachable"]
