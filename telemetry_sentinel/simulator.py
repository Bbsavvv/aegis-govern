from __future__ import annotations

import random
from typing import Sequence

from aegis_core.models import (
    AgentTransactionPayload,
    CrossBorderPipelinePayload,
    EventKind,
    ModelCallPayload,
    RiskMetadata,
    TelemetryEvent,
)

TENANTS = ("northstar-capital", "helix-health", "aurora-retail")
EU_COUNTRIES = ("DE", "FR", "NL", "IE")
THIRD_COUNTRIES = ("US", "IN", "SG", "BR")
ADEQUATE = {"JP", "CA", "KR", "GB"}


class TelemetrySimulator:
    def __init__(self, seed: int | None = None) -> None:
        self.rng = random.Random(seed)

    def batch(self, size: int = 8) -> list[TelemetryEvent]:
        factories: Sequence = (
            self.model_call,
            self.cross_border_pipeline,
            self.agent_transaction,
        )
        return [self.rng.choice(factories)() for _ in range(size)]

    def model_call(self) -> TelemetryEvent:
        high_risk = self.rng.random() < 0.35
        disclosed = self.rng.random() > 0.2
        biometric = self.rng.random() < 0.12
        social = self.rng.random() < 0.05
        source = self.rng.choice(EU_COUNTRIES)
        dest = self.rng.choice(EU_COUNTRIES + THIRD_COUNTRIES)
        return TelemetryEvent(
            source_system="inference-gateway",
            tenant_id=self.rng.choice(TENANTS),
            kind=EventKind.MODEL_CALL,
            tags=["llm", "runtime"],
            risk=RiskMetadata(
                composite_score=0,
                pii_categories=["contact", "behavioral"] if high_risk else [],
                special_category_data=biometric,
                data_residency_source=source,
                data_residency_destination=dest,
                adequacy_decision=dest in ADEQUATE or dest in EU_COUNTRIES,
                standard_contractual_clauses=dest in THIRD_COUNTRIES and self.rng.random() < 0.4,
                human_oversight=not high_risk or self.rng.random() < 0.45,
                model_risk_class="high" if high_risk else self.rng.choice(["minimal", "limited"]),
                annex_iii_use_case="creditworthiness" if high_risk else None,
                automated_decision=high_risk,
                biometric_processing=biometric,
                real_time_remote_biometric_id=biometric and self.rng.random() < 0.4,
                social_scoring=social,
                purpose="customer_support" if not high_risk else "credit_scoring",
                lawful_basis="consent" if biometric else "legitimate_interest",
            ),
            model_call=ModelCallPayload(
                model_id=self.rng.choice(["gpt-govern-4", "aurora-risk-8b", "helix-clinical-70b"]),
                provider=self.rng.choice(["internal", "vendor-eu", "vendor-us"]),
                prompt_tokens=self.rng.randint(120, 4800),
                completion_tokens=self.rng.randint(40, 1600),
                tools_enabled=["retrieval", "code_exec"] if high_risk else ["retrieval"],
                user_facing=True,
                output_logged=self.rng.random() < 0.3,
                disclosed_as_ai=disclosed,
            ),
            raw_context={"channel": "api", "latency_ms": self.rng.randint(40, 2200)},
        )

    def cross_border_pipeline(self) -> TelemetryEvent:
        source = self.rng.choice(EU_COUNTRIES)
        dest = self.rng.choice(THIRD_COUNTRIES)
        mechanism = self.rng.choice(["adequacy", "scc", "none", "none", "derogation"])
        special = self.rng.random() < 0.3
        fields = ["email", "name", "country"]
        if special:
            fields += ["health_condition", "national_id"]
        masked = ["email"] if self.rng.random() < 0.5 else []
        return TelemetryEvent(
            source_system="data-mesh",
            tenant_id=self.rng.choice(TENANTS),
            kind=EventKind.CROSS_BORDER_PIPELINE,
            tags=["etl", "residency"],
            risk=RiskMetadata(
                composite_score=0,
                pii_categories=fields,
                special_category_data=special,
                data_residency_source=source,
                data_residency_destination=dest,
                adequacy_decision=mechanism == "adequacy",
                standard_contractual_clauses=mechanism == "scc",
                encryption_in_transit=self.rng.random() > 0.15,
                encryption_at_rest=self.rng.random() > 0.1,
                model_risk_class="limited",
                purpose="analytics",
                lawful_basis="contract" if not special else None,
            ),
            pipeline=CrossBorderPipelinePayload(
                pipeline_id=f"pipe-{self.rng.randint(100, 999)}",
                dataset_name=self.rng.choice(["crm_export", "claims_warehouse", "cardholder_mirror"]),
                record_count=self.rng.randint(250, 2_000_000),
                processor="snowflake-external",
                controller=source + "-legal-entity",
                transfer_mechanism=mechanism if mechanism != "none" else "none",
                fields=fields,
                masked_fields=masked,
            ),
        )

    def agent_transaction(self) -> TelemetryEvent:
        production = self.rng.random() < 0.4
        financial = self.rng.random() < 0.45
        approved = self.rng.random() < 0.35
        return TelemetryEvent(
            source_system="agent-orchestrator",
            tenant_id=self.rng.choice(TENANTS),
            kind=EventKind.AGENT_TRANSACTION,
            tags=["agent", "write"],
            risk=RiskMetadata(
                composite_score=0,
                pii_categories=["account"] if financial else [],
                data_residency_source=self.rng.choice(EU_COUNTRIES),
                data_residency_destination=self.rng.choice(EU_COUNTRIES + ("US",)),
                financial_instrument=financial,
                payment_card_data=financial and self.rng.random() < 0.25,
                audit_logging_enabled=self.rng.random() > 0.2,
                mfa_enforced=self.rng.random() > 0.25,
                automated_decision=True,
                human_oversight=approved,
                model_risk_class="high" if production else "limited",
                purpose="operations",
            ),
            agent=AgentTransactionPayload(
                agent_id=f"agent-{self.rng.choice(['remediator', 'trader', 'sre', 'kyc'])}",
                action=self.rng.choice(["mutate_production", "transfer_funds", "patch_repo", "export_dataset"]),
                target_system=self.rng.choice(["payments-core", "github", "core-banking", "iam"]),
                amount_usd=round(self.rng.uniform(50, 250000), 2) if financial else None,
                approval_required=production or financial,
                approved_by="compliance-officer" if approved else None,
                writes_code=self.rng.random() < 0.4,
                accesses_secrets=self.rng.random() < 0.2,
                production_mutation=production,
            ),
        )
