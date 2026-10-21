from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from guardrail.api.monitoring import monitoring_store

router = APIRouter(tags=["monitoring"])


@router.get("/v1/audit/logs")
async def audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
):
    return monitoring_store.list_events(limit)


@router.get("/v1/audit/stats")
async def audit_stats(window: str = "24h"):
    # window is accepted for frontend compatibility.
    # The current implementation covers this server session.
    return monitoring_store.stats()


@router.get("/v1/alerts")
async def alerts(
    limit: int = Query(default=50, ge=1, le=200),
):
    return monitoring_store.alerts(limit)


@router.websocket("/ws/events")
async def event_websocket(websocket: WebSocket):
    await websocket.accept()
    queue = monitoring_store.subscribe()

    try:
        while True:
            event = await queue.get()
            await websocket.send_json(event)
    except WebSocketDisconnect:
        pass
    finally:
        monitoring_store.unsubscribe(queue)