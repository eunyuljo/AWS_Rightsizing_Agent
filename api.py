"""FastAPI 진입점"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

from store.memory import init_db, get_recent_alerts
from scheduler import start_scheduler, run_full_scan
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


# ── Alerts (DB 저장된 알림) ───────────────────────────────────────────────────

@app.get("/alerts")
async def list_alerts(hours: int = 24, limit: int = 50):
    return get_recent_alerts(hours=hours, limit=limit)


# ── Scan (실시간 룰 실행) ─────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    categories: Optional[list[str]] = None   # None → 전체
    notify: bool = False                      # Slack 발송 여부


@app.post("/scan")
async def run_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """
    룰 엔진을 즉시 실행하고 결과 반환.
    notify=true 이면 백그라운드에서 Slack 전송.
    """
    from rules.engine import run_all
    try:
        result = run_all(categories=req.categories)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    if req.notify:
        from scheduler import _save_and_notify
        background_tasks.add_task(_save_and_notify, result["violations"])

    return result


@app.get("/scan/summary")
async def scan_summary():
    """카테고리별 위반 수만 빠르게 반환 (알림 없음)"""
    from rules.engine import run_all
    try:
        result = run_all()
        return result["summary"]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Manual trigger (개발/테스트용) ────────────────────────────────────────────

@app.post("/trigger/{job_id}")
async def trigger_job(job_id: str):
    from scheduler import (
        run_cost_check, run_reliability_check,
        run_security_check, run_daily_summary, run_full_scan,
    )
    jobs = {
        "cost": run_cost_check,
        "reliability": run_reliability_check,
        "security": run_security_check,
        "summary": run_daily_summary,
        "full": run_full_scan,
    }
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail=f"Unknown job: {job_id}")
    result = jobs[job_id]()
    return {"status": "ok", "job": job_id, "result": result}


@app.get("/health")
async def health():
    return {"status": "ok"}
