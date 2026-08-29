from __future__ import annotations

from aegis_core.models import (
    CrossBorderPipelinePayload,
    EventKind,
    ModelCallPayload,
    RiskMetadata,
    TelemetryEvent,
)


def make_event(**overrides) -> TelemetryEvent:
    risk_overrides = overrides.pop("risk", {})
    payload = dict(
        source_system="inference-gateway",
        tenant_id="northstar-capital",
        kind=EventKind.MODEL_CALL,
        risk=RiskMetadata(
            composite_score=0,
            data_residency_source="DE",
            data_residency_destination="DE",
            **risk_overrides,
        ),
        model_call=ModelCallPayload(
            model_id="aurora-risk-8b",
            provider="internal",
            prompt_tokens=120,
            completion_tokens=40,
            disclosed_as_ai=True,
        ),
    )
    payload.update(overrides)
    if "risk" in overrides:
        pass
    return TelemetryEvent(**payload)


def transfer_event() -> TelemetryEvent:
    return TelemetryEvent(
        source_system="data-mesh",
        tenant_id="helix-health",
        kind=EventKind.CROSS_BORDER_PIPELINE,
        risk=RiskMetadata(
            composite_score=0,
            pii_categories=["email", "national_id", "health_condition"],
            special_category_data=True,
            data_residency_source="DE",
            data_residency_destination="US",
            adequacy_decision=False,
            standard_contractual_clauses=False,
            encryption_in_transit=False,
            encryption_at_rest=True,
            lawful_basis=None,
        ),
        pipeline=CrossBorderPipelinePayload(
            pipeline_id="pipe-221",
            dataset_name="claims_warehouse",
            record_count=90000,
            processor="snowflake-external",
            controller="DE-legal-entity",
            transfer_mechanism="none",
            fields=["email", "national_id", "health_condition"],
            masked_fields=[],
        ),
    )
