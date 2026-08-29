from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from aegis_core.models import TelemetryEvent
from aegis_core.store import get_store
from telemetry_sentinel.worker import TelemetrySentinelWorker

router = APIRouter(prefix="/telemetry", tags=["telemetry"])
_sentinel = TelemetrySentinelWorker()


@router.post("/ingest")
def ingest_telemetry(event: TelemetryEvent) -> dict:
    stored = _sentinel.ingest(event)
    return {"event": stored.model_dump(mode="json"), "catalog": _sentinel.snapshot()}


@router.post("/ingest/batch")
def ingest_batch(events: list[TelemetryEvent]) -> dict:
    stored = _sentinel.ingest_many(events)
    return {
        "count": len(stored),
        "event_ids": [event.event_id for event in stored],
        "catalog": _sentinel.snapshot(),
    }


@router.post("/simulate")
def simulate_tick(batch_size: int = Query(default=8, ge=1, le=50)) -> dict:
    events = _sentinel.tick(batch_size=batch_size)
    return {
        "count": len(events),
        "events": [event.model_dump(mode="json") for event in events],
        "index": _sentinel.snapshot(),
    }


@router.get("/events")
def list_events(tenant_id: str | None = None, limit: int = Query(default=50, ge=1, le=500)) -> dict:
    events = get_store().list_events(tenant_id=tenant_id, limit=limit)
    return {"count": len(events), "events": [event.model_dump(mode="json") for event in events]}


@router.get("/events/{event_id}")
def get_event(event_id: str) -> dict:
    event = get_store().get_event(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="event not found")
    return event.model_dump(mode="json")
