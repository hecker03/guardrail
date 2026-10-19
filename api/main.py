# guardrail/api/main.py

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routes import sanitize, isolate, classify, filter, pipeline, monitoring

app = FastAPI(
    title="GuardRail",
    version="1.0.0",
    description="Adaptive 5-layer security middleware for LLM applications.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://127.0.0.1:3000"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(sanitize.router)
app.include_router(isolate.router)
app.include_router(classify.router)
app.include_router(filter.router)
app.include_router(pipeline.router)
app.include_router(monitoring.router)

@app.get("/health")
async def health():
    return {"status": "ok"}