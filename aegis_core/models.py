from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, computed_field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:12]}"


class EventKind(str, Enum):
    MODEL_CALL = "model_call"
    CROSS_BORDER_PIPELINE = "cross_border_pipeline"
    AGENT_TRANSACTION = "agent_transaction"


class Framework(str, Enum):
    EU_AI_ACT = "eu_ai_act"
    GDPR = "gdpr"
    FINANCIAL_SECURITY = "financial_security"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def score(self) -> int:
        return {
            Severity.INFO: 10,
            Severity.LOW: 25,
            Severity.MEDIUM: 50,
            Severity.HIGH: 75,
            Severity.CRITICAL: 95,
        }[self]


class RiskMetadata(BaseModel):
    composite_score: float = Field(ge=0, le=100)
    pii_categories: list[str] = Field(default_factory=list)
    special_category_data: bool = False
    data_residency_source: str
    data_residency_destination: str
    adequacy_decision: bool = False
    standard_contractual_clauses: bool = False
    encryption_in_transit: bool = True
    encryption_at_rest: bool = True
    human_oversight: bool = True
    model_risk_class: Literal["minimal", "limited", "high", "unacceptable"] = "limited"
    annex_iii_use_case: str | None = None
    automated_decision: bool = False
    biometric_processing: bool = False
    financial_instrument: bool = False
    payment_card_data: bool = False
    audit_logging_enabled: bool = True
    mfa_enforced: bool = True
    involves_minors: bool = False
    social_scoring: bool = False
    real_time_remote_biometric_id: bool = False
    purpose: str = "operational"
    lawful_basis: str | None = "legitimate_interest"

    @computed_field
    @property
    def cross_border(self) -> bool:
        return self.data_residency_source != self.data_residency_destination


class ModelCallPayload(BaseModel):
    model_id: str
    provider: str
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    tools_enabled: list[str] = Field(default_factory=list)
    system_prompt_present: bool = True
    user_facing: bool = True
    output_logged: bool = False
    disclosed_as_ai: bool = True


class CrossBorderPipelinePayload(BaseModel):
    pipeline_id: str
    dataset_name: str
    record_count: int = Field(ge=0)
    processor: str
    controller: str
    transfer_mechanism: Literal["adequacy", "scc", "bcr", "derogation", "none"]
    fields: list[str] = Field(default_factory=list)
    masked_fields: list[str] = Field(default_factory=list)


class AgentTransactionPayload(BaseModel):
    agent_id: str
    action: str
    target_system: str
    amount_usd: float | None = None
    approval_required: bool = False
    approved_by: str | None = None
    writes_code: bool = False
    accesses_secrets: bool = False
    production_mutation: bool = False


class TelemetryEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: new_id("evt"))
    ingested_at: datetime = Field(default_factory=utcnow)
    source_system: str
    tenant_id: str
    environment: str = "production"
    kind: EventKind
    risk: RiskMetadata
    model_call: ModelCallPayload | None = None
    pipeline: CrossBorderPipelinePayload | None = None
    agent: AgentTransactionPayload | None = None
    tags: list[str] = Field(default_factory=list)
    raw_context: dict[str, Any] = Field(default_factory=dict)

    def catalog_key(self) -> str:
        return f"{self.tenant_id}:{self.kind.value}:{self.source_system}"


class PolicyViolation(BaseModel):
    violation_id: str = Field(default_factory=lambda: new_id("vio"))
    event_id: str
    tenant_id: str
    framework: Framework
    citation: str
    title: str
    description: str
    severity: Severity
    score: float = Field(ge=0, le=100)
    rule_id: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime = Field(default_factory=utcnow)
    remediable: bool = True


class FileChange(BaseModel):
    path: str
    action: Literal["create", "modify", "delete"]
    content: str
    patch: str
    language: str = "text"


class RemediationPullRequest(BaseModel):
    pr_id: str = Field(default_factory=lambda: new_id("pr"))
    created_at: datetime = Field(default_factory=utcnow)
    tenant_id: str
    title: str
    body: str
    base_branch: str = "main"
    head_branch: str
    commit_message: str
    files: list[FileChange]
    labels: list[str] = Field(default_factory=list)
    reviewers: list[str] = Field(default_factory=list)
    violation_ids: list[str]
    event_ids: list[str]
    merge_ready: bool = True
    checks: dict[str, str] = Field(
        default_factory=lambda: {
            "policy_lint": "pass",
            "secret_scan": "pass",
            "iac_drift": "pass",
        }
    )
    status: Literal["staged", "awaiting_review", "merged"] = "staged"


class FineLine(BaseModel):
    violation_id: str
    rule_id: str
    framework: Framework
    citation: str
    statutory_basis: str
    severity: Severity
    turnover_rate: float
    statutory_cap_eur: float
    statutory_maximum_eur: float
    expected_exposure_eur: float
    methodology: str


class HashLink(BaseModel):
    sequence: int
    record_id: str
    record_digest: str
    chain_digest: str


class IntegritySeal(BaseModel):
    algorithm: str = "HMAC-SHA256"
    hash_algorithm: str = "SHA-256"
    merkle_root: str
    chain: list[HashLink]
    signature: str
    key_id: str = "aegis-platform-v1"
    canonical_digest: str


class ComplianceProofReport(BaseModel):
    report_id: str = Field(default_factory=lambda: new_id("prf"))
    issued_at: datetime = Field(default_factory=utcnow)
    target_input: str
    target_host: str
    target_tenant_id: str
    collection_mode: Literal["simulated_posture_model"] = "simulated_posture_model"
    annual_turnover_eur: float
    event_ids: list[str]
    violation_ids: list[str]
    findings: list[PolicyViolation]
    fines: list[FineLine]
    expected_exposure_eur: float
    statutory_maximum_eur: float
    integrity: IntegritySeal
    disclaimer: str = (
        "Simulated conservative posture model for enterprise underwriting. "
        "Fine figures are statutory-cap and probability-weighted exposure estimates, "
        "not a determination of liability. Not legal advice."
    )


class SealedPatchBundle(BaseModel):
    bundle_id: str = Field(default_factory=lambda: new_id("seal"))
    report_id: str
    kdf: str = "PBKDF2-HMAC-SHA256"
    iterations: int = 200_000
    salt_b64: str
    nonce_b64: str
    ciphertext_b64: str
    mac_b64: str
    license_fingerprint: str
    locked: bool = True


class AcquisitionPackage(BaseModel):
    package_id: str = Field(default_factory=lambda: new_id("acq"))
    created_at: datetime = Field(default_factory=utcnow)
    report_id: str
    tenant_id: str
    executive_summary: str
    pull_request_ids: list[str]
    sealed_patch: SealedPatchBundle
    license_key: str
    unlock_instructions: str
