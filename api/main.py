# guardrail/api/main.py

import time
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from .monitoring import live_events
from .routes import sanitize, isolate, classify, filter, pipeline, monitoring

app = FastAPI(
    title="GuardRail",
    version="1.0.0",
    description="Adaptive 5-layer security middleware for LLM applications.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def capture_live_api_event(request: Request, call_next):
    """Capture metadata-only request events in the bounded local ring buffer."""
    request_id = str(uuid.uuid4())
    request.state.guardrail_request_id = request_id
    request.state.guardrail_layer_results = []
    started = time.perf_counter()

    try:
        response = await call_next(request)
    except Exception:
        elapsed_ms = (time.perf_counter() - started) * 1000
        path = getattr(request.scope.get("route"), "path", request.url.path)
        if request.url.path.startswith("/v1/") and not request.url.path.startswith("/v1/monitoring"):
            live_events.record_request(
                request_id=request_id,
                method=request.method,
                path=path,
                status_code=500,
                latency_ms=elapsed_ms,
                layer_results=getattr(request.state, "guardrail_layer_results", ()),
            )
        raise

    elapsed_ms = (time.perf_counter() - started) * 1000
    response.headers["X-Request-ID"] = request_id
    path = getattr(request.scope.get("route"), "path", request.url.path)
    # Monitoring endpoints are excluded to avoid self-generated event noise.
    if request.url.path.startswith("/v1/") and not request.url.path.startswith("/v1/monitoring"):
        live_events.record_request(
            request_id=request_id,
            method=request.method,
            path=path,
            status_code=response.status_code,
            latency_ms=elapsed_ms,
            layer_results=getattr(request.state, "guardrail_layer_results", ()),
        )
    return response


app.include_router(sanitize.router)
app.include_router(isolate.router)
app.include_router(classify.router)
app.include_router(filter.router)
app.include_router(pipeline.router)
app.include_router(monitoring.router)


@app.get("/health")
async def health():
    return {"status": "ok"}
