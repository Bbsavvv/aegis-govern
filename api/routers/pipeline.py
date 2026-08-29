from __future__ import annotations

from fastapi import APIRouter, Query

from aegis_core.models import TelemetryEvent
from aegis_core.pipeline import GovernancePipeline
from aegis_core.store import get_store

router = APIRouter(prefix="/pipeline", tags=["pipeline"])
_pipeline = GovernancePipeline()


@router.post("/tick")
def pipeline_tick(batch_size: int = Query(default=8, ge=1, le=50)) -> dict:
    return _pipeline.tick(batch_size=batch_size)


@router.post("/ingest")
def pipeline_ingest(events: list[TelemetryEvent]) -> dict:
    return _pipeline.ingest(events)


@router.get("/stats")
def pipeline_stats() -> dict:
    return {"store": get_store().stats(), "index": _pipeline.sentinel.snapshot()}
