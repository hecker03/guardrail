from collections import deque
from datetime import datetime, timezone
from threading import Lock
from typing import Any
import asyncio
import uuid


class MonitoringStore:
    def __init__(self, max_events: int = 2000):
        self._events = deque(maxlen=max_events)
        self._lock = Lock()
        self._subscribers: set[asyncio.Queue] = set()

    async def record(
        self,
        *,
        request_id: str,
        layer: str,
        label: str,
        score: float,
        latency_ms: float,
        action: str,
        payload: dict[str, Any] | None = None,
    ) -> dict:
        event = {
            "id": str(uuid.uuid4()),
            "request_id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": layer,
            "label": label,
            "score": round(float(score), 4),
            "latency_ms": round(float(latency_ms), 3),
            "action": action,
            "payload": payload or {},
        }

        with self._lock:
            self._events.appendleft(event)

        dead_queues = []

        for queue in list(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                dead_queues.append(queue)

        for queue in dead_queues:
            self._subscribers.discard(queue)

        return event

    def list_events(self, limit: int = 100) -> list[dict]:
        limit = max(1, min(limit, 500))

        with self._lock:
            return list(self._events)[:limit]

    def alerts(self, limit: int = 50) -> list[dict]:
        with self._lock:
            events = list(self._events)

        alerts = []

        for event in events:
            if (
                event["action"] in {"rejected", "blocked"}
                or event["score"] >= 0.85
            ):
                alerts.append({
                    "id": event["id"],
                    "severity": (
                        "critical"
                        if event["score"] >= 0.9
                        else "warning"
                    ),
                    "title": (
                        f'{event["layer"]} security event'
                    ),
                    "message": event["label"],
                    "timestamp": event["timestamp"],
                    "layer": event["layer"],
                })

        return alerts[:limit]

    def stats(self) -> dict:
        with self._lock:
            events = list(self._events)

        latencies = sorted(
            event["latency_ms"]
            for event in events
            if event["latency_ms"] is not None
        )

        if latencies:
            index = min(
                len(latencies) - 1,
                int(0.95 * len(latencies)),
            )
            p95 = latencies[index]
        else:
            p95 = 0.0

        blocked = sum(
            event["action"] in {"rejected", "blocked"}
            for event in events
        )

        pii_redacted = sum(
            event["layer"] == "L5"
            and event["payload"].get("pii_count", 0) > 0
            for event in events
        )

        layer_counts = {}

        for event in events:
            key = (
                event["layer"],
                event["label"],
            )
            layer_counts[key] = layer_counts.get(key, 0) + 1

        layer_breakdown = [
            {
                "layer": layer,
                "label": label,
                "count": count,
            }
            for (layer, label), count in layer_counts.items()
        ]

        return {
            "total_requests": len(events),
            "attacks_blocked": blocked,
            "pii_redacted": pii_redacted,
            "p95_latency_ms": round(p95, 3),
            "timeline": [],
            "layer_breakdown": layer_breakdown,
        }

    def subscribe(self) -> asyncio.Queue:
        queue = asyncio.Queue(maxsize=200)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)


monitoring_store = MonitoringStore()