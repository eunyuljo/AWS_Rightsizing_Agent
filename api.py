"""FastAPI 진입점"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from store.memory import init_db, get_recent_alerts
from scheduler import start_scheduler
from chat.agent import chat

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    scheduler = start_scheduler()
    yield
    scheduler.shutdown()


app = FastAPI(title="InfraChat", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Chat ──────────────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    question: str
    history: list[dict] = []


@app.post("/chat")
async def chat_endpoint(req: ChatRequest):
    try:
        result = chat(req.question, req.history)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Alerts ────────────────────────────────────────────────────────────────────

@app.get("/alerts")
async def list_alerts(hours: int = 24, limit: int = 50):
    return get_recent_alerts(hours=hours, limit=limit)


# ── Manual trigger (개발/테스트용) ────────────────────────────────────────────

@app.post("/trigger/{job_id}")
async def trigger_job(job_id: str):
    from scheduler import run_cost_check, run_resource_check, run_security_check, run_daily_summary
    jobs = {
        "cost": run_cost_check,
        "resource": run_resource_check,
        "security": run_security_check,
        "summary": run_daily_summary,
    }
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail=f"Unknown job: {job_id}")
    jobs[job_id]()
    return {"status": "ok", "job": job_id}


@app.get("/health")
async def health():
    return {"status": "ok"}
