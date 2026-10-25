"""Read-only endpoints for the in-memory live monitoring buffer."""

from __future__ import annotations

import asyncio
import hmac
import json
import os
from typing import AsyncIterator, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from guardrail.api.monitoring import live_events

router = APIRouter(prefix="/v1/monitoring", tags=["monitoring"])


def _require_configured_token(request: Request) -> None:
    """Enforce bearer auth when a dashboard token has been configured."""
    expected = os.getenv("GUARDRAIL_MONITORING_TOKEN", "").strip()
    if not expected:
        # Local Phase-I development mode. Configure a token before exposing the
        # monitoring endpoints outside a trusted development environment.
        return
    supplied = request.headers.get("authorization", "")
    expected_header = f"Bearer {expected}"
    if not hmac.compare_digest(supplied.encode("utf-8"), expected_header.encode("utf-8")):
        raise HTTPException(
            status_code=401,
            detail="monitoring_auth_required",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.get("/events")
async def get_live_events(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
):
    """Return the latest bounded in-memory events (newest first)."""
    _require_configured_token(request)
    return {
        "storage_mode": "in_memory",
        "persistent": False,
        "capacity": live_events.capacity,
        "events": live_events.latest(limit),
    }


@router.get("/stream")
async def stream_live_events(
    request: Request,
    after: Optional[str] = Query(default=None, max_length=80),
):
    """Stream live events using Server-Sent Events (SSE)."""
    _require_configured_token(request)
    initial_cursor = after or request.headers.get("last-event-id")

    async def generate() -> AsyncIterator[str]:
        cursor = initial_cursor
        while not await request.is_disconnected():
            batch = live_events.after(cursor, limit=100)
            if batch:
                for event in batch:
                    cursor = event["event_id"]
                    payload = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
                    yield f"id: {cursor}\nevent: guardrail-monitor\ndata: {payload}\n\n"
            else:
                yield ": keep-alive\n\n"
            await asyncio.sleep(1)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
