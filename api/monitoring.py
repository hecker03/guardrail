"""Bounded, process-local monitoring events for Phase-I live dashboards.

This module intentionally stores only request metadata and layer outcome labels.
It does not retain request/response bodies, write to PostgreSQL, or provide a
persistent security-audit trail. Data is lost when the process restarts.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import os
import threading
import uuid
from typing import Any, Iterable, Optional


DEFAULT_EVENT_CAPACITY = 500
MAX_EVENT_CAPACITY = 10_000


def _configured_capacity() -> int:
    try:
        capacity = int(os.getenv("GUARDRAIL_LIVE_EVENT_CAPACITY", DEFAULT_EVENT_CAPACITY))
    except (TypeError, ValueError):
        return DEFAULT_EVENT_CAPACITY
    return max(10, min(MAX_EVENT_CAPACITY, capacity))


def _safe_labels(labels: Optional[Iterable[str]]) -> list[str]:
    if labels is None:
        return []
    if isinstance(labels, str):
        labels = (labels,)
    safe: list[str] = []
    for label in labels:
        value = str(label).strip()[:100]
        if value and value not in safe:
            safe.append(value)
        if len(safe) >= 25:
            break
    return safe


def record_layer_result(
    request: Any,
    *,
    layer: str,
    action: str,
    score: Optional[float] = None,
    labels: Optional[Iterable[str]] = None,
) -> None:
    """Attach non-content outcome metadata to the current FastAPI request."""
    results = getattr(request.state, "guardrail_layer_results", None)
    if results is None:
        results = []
        request.state.guardrail_layer_results = results

    item: dict[str, Any] = {
        "layer": str(layer)[:16],
        "action": str(action)[:40],
    }
    if score is not None:
        try:
            item["score"] = round(max(0.0, min(1.0, float(score))), 4)
        except (TypeError, ValueError):
            pass
    safe = _safe_labels(labels)
    if safe:
        item["labels"] = safe
    results.append(item)


class InMemoryEventStore:
    """Thread-safe, bounded ring buffer for live monitoring (not persistence)."""

    def __init__(self, capacity: int = DEFAULT_EVENT_CAPACITY) -> None:
        self.capacity = max(1, min(MAX_EVENT_CAPACITY, int(capacity)))
        self._events: deque[dict[str, Any]] = deque(maxlen=self.capacity)
        self._lock = threading.Lock()

    def record_request(
        self,
        *,
        request_id: str,
        method: str,
        path: str,
        status_code: int,
        latency_ms: float,
        layer_results: Optional[Iterable[dict[str, Any]]] = None,
    ) -> dict[str, Any]:
        status = int(status_code)
        if status in {400, 401, 403, 409}:
            outcome = "blocked"
        elif status >= 500:
            outcome = "error"
        elif status >= 400:
            outcome = "client_error"
        else:
            outcome = "success"

        # Copy a bounded metadata-only subset. Do not accept request/response
        # payloads or arbitrary dictionaries from a route.
        safe_layers = []
        for result in layer_results or ():
            if not isinstance(result, dict):
                continue
            item: dict[str, Any] = {
                "layer": str(result.get("layer", ""))[:16],
                "action": str(result.get("action", ""))[:40],
            }
            if result.get("score") is not None:
                try:
                    item["score"] = round(max(0.0, min(1.0, float(result["score"]))), 4)
                except (TypeError, ValueError):
                    pass
            labels = _safe_labels(result.get("labels"))
            if labels:
                item["labels"] = labels
            safe_layers.append(item)
            if len(safe_layers) >= 10:
                break

        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "request_id": str(request_id)[:80],
            "method": str(method).upper()[:12],
            "path": str(path)[:200],
            "status_code": status,
            "outcome": outcome,
            "latency_ms": round(max(0.0, float(latency_ms)), 3),
            "layer_results": safe_layers,
        }
        with self._lock:
            self._events.append(event)
        return dict(event)

    def latest(self, limit: int = 100) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(self.capacity, int(limit)))
        with self._lock:
            selected = list(self._events)[-bounded_limit:]
        return [dict(event) for event in reversed(selected)]

    def after(self, event_id: Optional[str], limit: int = 100) -> list[dict[str, Any]]:
        """Return events newer than a stream cursor, oldest first."""
        bounded_limit = max(1, min(self.capacity, int(limit)))
        with self._lock:
            events = list(self._events)
        if not events:
            return []
        if not event_id:
            return [dict(event) for event in events[-bounded_limit:]]
        cursor_index = next(
            (index for index, event in enumerate(events) if event["event_id"] == event_id),
            None,
        )
        if cursor_index is None:
            # A stale cursor may have fallen out of the bounded ring buffer.
            return [dict(event) for event in events[-bounded_limit:]]
        return [dict(event) for event in events[cursor_index + 1:cursor_index + 1 + bounded_limit]]

    def clear(self) -> None:
        """Clear process-local events; useful for tests and local development."""
        with self._lock:
            self._events.clear()


live_events = InMemoryEventStore(_configured_capacity())
