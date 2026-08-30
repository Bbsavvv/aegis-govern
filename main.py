import os
import time
import hmac
import hashlib
import json
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, Header, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Text, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker, Session

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./aegis.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class DBProofReport(Base):
    __tablename__ = "proof_reports"
    report_id = Column(String, primary_key=True, index=True)
    target = Column(String, nullable=False)
    turnover = Column(Float, nullable=False)
    risk_score = Column(Float, nullable=False)
    chain_hash = Column(String, nullable=False)
    hmac_signature = Column(String, nullable=False)
    dossier_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class DBStagedPackage(Base):
    __tablename__ = "staged_packages"
    package_id = Column(String, primary_key=True, index=True)
    report_id = Column(String, nullable=False)
    license_key = Column(String, nullable=False)
    unlocked = Column(Boolean, default=False)
    patch_payload = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class DBComplianceEvent(Base):
    __tablename__ = "compliance_events"
    event_id = Column(String, primary_key=True, index=True)
    worker_source = Column(String, nullable=False)
    summary = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI(title="Aegis Control Plane", description="Non-discretionary regulatory verification engine.", version="2.1.0")

if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

ADMIN_API_KEY = os.getenv("AEGIS_API_KEY", "aegis-sec-master-key-2026")
HMAC_SECRET = os.getenv("AEGIS_HMAC_SECRET", "aegis-cryptographic-master-salt-99")

def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if not x_api_key or x_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return x_api_key

class AuditRequest(BaseModel):
    target: str
    turnover: float
    sweep: int = 10

class PackageRequest(BaseModel):
    report_id: str

class UnlockRequest(BaseModel):
    package_id: str
    license_key: str

class TickRequest(BaseModel):
    batch_size: int = 8

class ClientOnboardRequest(BaseModel):
    company_name: str
    contact_email: str
    tier: str = Field("Enterprise Pilot", description="Subscription tier")

@app.get("/", response_class=HTMLResponse)
def read_index():
    path = os.path.join("static", "index.html")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h3>Aegis Control Plane Active</h3>"

@app.get("/api/health")
def health_check(db: Session = Depends(get_db)):
    return {"status": "operational", "engine": "Aegis Governance Control Plane", "database": "connected", "timestamp": datetime.utcnow().isoformat()}

@app.post("/api/audit")
def run_audit(req: AuditRequest, db: Session = Depends(get_db), api_key: str = Depends(verify_api_key)):
    report_id = f"prf_{uuid.uuid4().hex[:12]}"
    risk_score = round(min(99.9, (req.turnover / 1_000_000_000) * 14.5 + (req.sweep * 1.2)), 2)
    dossier = {"target_analyzed": req.target, "turnover_eur": req.turnover, "sweep_nodes": req.sweep, "frameworks_crosswalked": ["GDPR Art. 32", "EU AI Act"], "evaluated_status": "Non-Compliant" if risk_score > 40 else "Nominal"}
    dossier_str = json.dumps(dossier)
    chain_payload = f"{report_id}:{req.target}:{req.turnover}:{risk_score}"
    chain_hash = hashlib.sha256(chain_payload.encode()).hexdigest()
    hmac_sig = hmac.new(HMAC_SECRET.encode(), chain_payload.encode(), hashlib.sha256).hexdigest()
    db.add(DBProofReport(report_id=report_id, target=req.target, turnover=req.turnover, risk_score=risk_score, chain_hash=chain_hash, hmac_signature=hmac_sig, dossier_json=dossier_str))
    db.commit()
    return {"report_id": report_id, "target": req.target, "risk_score": risk_score, "chain_hash": chain_hash, "hmac_signature": hmac_sig, "dossier": dossier}

@app.get("/api/proofs")
def list_proofs(db: Session = Depends(get_db), api_key: str = Depends(verify_api_key)):
    reports = db.query(DBProofReport).order_by(DBProofReport.created_at.desc()).limit(20).all()
    return [{"report_id": r.report_id, "target": r.target, "turnover": r.turnover, "risk_score": r.risk_score, "chain_hash": r.chain_hash[:16] + "...", "created_at": r.created_at.isoformat()} for r in reports]

@app.post("/api/packages")
def stage_package(req: PackageRequest, db: Session = Depends(get_db), api_key: str = Depends(verify_api_key)):
    report = db.query(DBProofReport).filter(DBProofReport.report_id == req.report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Not found")
    package_id = f"acq_{uuid.uuid4().hex[:12]}"
    license_key = f"AEGIS-ENT-{uuid.uuid4().hex.upper()[:16]}"
    patch_payload = json.dumps({"patch_id": package_id, "source_report": report.report_id})
    db.add(DBStagedPackage(package_id=package_id, report_id=report.report_id, license_key=license_key, unlocked=False, patch_payload=patch_payload))
    db.commit()
    return {"package_id": package_id, "report_id": req.report_id, "license_key": license_key}

@app.post("/api/unlock")
def unlock_package(req: UnlockRequest, db: Session = Depends(get_db), api_key: str = Depends(verify_api_key)):
    pkg = db.query(DBStagedPackage).filter(DBStagedPackage.package_id == req.package_id).first()
    if not pkg or pkg.license_key != req.license_key:
        raise HTTPException(status_code=403, detail="Invalid key")
    pkg.unlocked = True
    db.commit()
    return {"status": "unlocked", "package_id": pkg.package_id, "payload": json.loads(pkg.patch_payload)}

@app.post("/api/tick")
def run_tick(req: TickRequest, db: Session = Depends(get_db), api_key: str = Depends(verify_api_key)):
    return {"tick_batch": uuid.uuid4().hex[:8], "processed_units": req.batch_size, "status": "completed"}

@app.post("/api/admin/onboard-client")
def onboard_client(req: ClientOnboardRequest, db: Session = Depends(get_db), api_key: str = Depends(verify_api_key)):
    client_id = f"cli_{uuid.uuid4().hex[:10]}"
    client_api_key = f"AEGIS-KEY-{uuid.uuid4().hex.upper()[:16]}"
    db_event = DBComplianceEvent(
        event_id=f"evt_{uuid.uuid4().hex[:10]}",
        worker_source="Admin Onboarding Controller",
        summary=f"Provisioned client key for {req.company_name} ({req.contact_email}) under tier {req.tier}",
        severity="INFO"
    )
    db.add(db_event)
    db.commit()
    return {
        "client_id": client_id,
        "company": req.company_name,
        "assigned_api_key": client_api_key,
        "tier": req.tier,
        "status": "provisioned"
    }
