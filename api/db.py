# guardrail/api/db.py

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import Column, String, Float, DateTime, Integer, JSON
from datetime import datetime

DATABASE_URL = "postgresql+asyncpg://guardrail:guardrail@localhost/guardrail"

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    request_id = Column(String, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    layer = Column(String, index=True)
    label = Column(String, index=True)
    score = Column(Float)
    latency_ms = Column(Float)
    payload = Column(JSON)


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def log_event(row: dict):
    async with AsyncSessionLocal() as session:
        session.add(AuditLog(**row))
        await session.commit()