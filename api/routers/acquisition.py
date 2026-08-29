from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from aegis_core.models import SealedPatchBundle
from aegis_core.store import get_store
from acquisition_engine.license import LicenseEnvelope
from acquisition_engine.pr_generator_extension import AcquisitionRemediator
from acquisition_engine.target_auditor import TargetAuditor

router = APIRouter(prefix="/acquisition", tags=["acquisition"])
_auditor = TargetAuditor()
_remediator = AcquisitionRemediator()


class AuditRequest(BaseModel):
    target: str = Field(..., examples=["https://api.northstar.example/v1/chat"])
    annual_turnover_eur: float | None = Field(default=None, gt=0)
    sweep_size: int | None = Field(default=None, ge=2, le=40)


class UnlockRequest(BaseModel):
    license_key: str
    sealed_patch: SealedPatchBundle


class UnlockStoredRequest(BaseModel):
    license_key: str


@router.post("/audit")
def audit_target(body: AuditRequest) -> dict:
    try:
        report = _auditor.audit(
            body.target,
            annual_turnover_eur=body.annual_turnover_eur,
            sweep_size=body.sweep_size,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return report.model_dump(mode="json")


@router.post("/package/{report_id}")
def package_report(report_id: str) -> dict:
    report = get_store().get_proof_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="proof-report not found")
    try:
        package = _remediator.package_report(report)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return package.model_dump(mode="json")


@router.post("/unlock")
def unlock_patch(body: UnlockRequest) -> dict:
    try:
        payload = LicenseEnvelope().unlock(body.sealed_patch, body.license_key)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    data = json.loads(payload.decode("utf-8"))
    data["unlocked"] = True
    return data


@router.get("/reports")
def list_reports(limit: int = Query(default=20, ge=1, le=100)) -> dict:
    items = get_store().list_proof_reports(limit=limit)
    return {"count": len(items), "reports": [item.model_dump(mode="json") for item in items]}


@router.get("/reports/{report_id}")
def get_report(report_id: str) -> dict:
    report = get_store().get_proof_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="proof-report not found")
    return report.model_dump(mode="json")


@router.get("/reports/{report_id}/verify")
def verify_report(report_id: str) -> dict:
    from acquisition_engine.notary import ProofNotary

    report = get_store().get_proof_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="proof-report not found")
    return ProofNotary().inspect(report.report_id, report.findings, report.integrity)


@router.get("/packages")
def list_packages(tenant_id: str | None = None, limit: int = Query(default=20, ge=1, le=100)) -> dict:
    items = get_store().list_acquisition_packages(tenant_id=tenant_id, limit=limit)
    public = []
    for item in items:
        dumped = item.model_dump(mode="json")
        dumped["license_key"] = None
        public.append(dumped)
    return {"count": len(public), "packages": public}


@router.get("/packages/{package_id}")
def get_package(package_id: str) -> dict:
    item = get_store().get_acquisition_package(package_id)
    if item is None:
        raise HTTPException(status_code=404, detail="package not found")
    dumped = item.model_dump(mode="json")
    dumped["license_key"] = None
    return dumped


@router.post("/packages/{package_id}/unlock")
def unlock_stored_package(package_id: str, body: UnlockStoredRequest) -> dict:
    item = get_store().get_acquisition_package(package_id)
    if item is None:
        raise HTTPException(status_code=404, detail="package not found")
    try:
        payload = LicenseEnvelope().unlock(item.sealed_patch, body.license_key)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    data = json.loads(payload.decode("utf-8"))
    data["unlocked"] = True
    data["package_id"] = package_id
    return data
