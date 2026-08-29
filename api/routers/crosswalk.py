from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from aegis_core.store import get_store
from regulatory_crosswalker.worker import RegulatoryCrosswalkerWorker

router = APIRouter(prefix="/evaluations", tags=["crosswalk"])
_worker = RegulatoryCrosswalkerWorker()


@router.post("/crosswalk")
def run_crosswalk(event_id: str | None = None) -> dict:
    store = get_store()
    if event_id:
        event = store.get_event(event_id)
        if event is None:
            raise HTTPException(status_code=404, detail="event not found")
        findings = _worker.evaluate_event(event)
    else:
        findings = _worker.tick()
    return {
        "count": len(findings),
        "violations": [item.model_dump(mode="json") for item in findings],
    }


@router.get("/violations")
def list_violations(
    event_id: str | None = None,
    tenant_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict:
    items = get_store().list_violations(event_id=event_id, tenant_id=tenant_id, limit=limit)
    return {"count": len(items), "violations": [item.model_dump(mode="json") for item in items]}
