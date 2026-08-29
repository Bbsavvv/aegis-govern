from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from aegis_core.store import get_store
from remediator_engine.worker import RemediatorEngineWorker

router = APIRouter(prefix="/remediations", tags=["remediation"])
_worker = RemediatorEngineWorker()


@router.post("/generate")
def generate_pull_requests() -> dict:
    staged = _worker.tick()
    return {"count": len(staged), "pull_requests": [pr.model_dump(mode="json") for pr in staged]}


@router.get("/pull-requests")
def list_pull_requests(tenant_id: str | None = None, limit: int = Query(default=50, ge=1, le=200)) -> dict:
    items = get_store().list_pull_requests(tenant_id=tenant_id, limit=limit)
    return {"count": len(items), "pull_requests": [item.model_dump(mode="json") for item in items]}


@router.get("/pull-requests/{pr_id}")
def get_pull_request(pr_id: str) -> dict:
    item = get_store().get_pull_request(pr_id)
    if item is None:
        raise HTTPException(status_code=404, detail="pull request not found")
    return item.model_dump(mode="json")
