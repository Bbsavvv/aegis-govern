from __future__ import annotations

from aegis_core.models import RiskMetadata, TelemetryEvent


def score_event(event: TelemetryEvent) -> TelemetryEvent:
    """Recompute composite risk from observable telemetry signals."""
    risk = event.risk
    score = 8.0

    if risk.cross_border:
        score += 18
        if not risk.adequacy_decision and not risk.standard_contractual_clauses:
            score += 22
    if risk.special_category_data:
        score += 16
    if risk.biometric_processing:
        score += 14
    if risk.real_time_remote_biometric_id:
        score += 28
    if risk.social_scoring:
        score += 40
    if risk.model_risk_class == "high":
        score += 18
    elif risk.model_risk_class == "unacceptable":
        score += 35
    if not risk.human_oversight and (risk.automated_decision or risk.model_risk_class == "high"):
        score += 16
    if risk.payment_card_data:
        score += 20
    if not risk.encryption_in_transit:
        score += 18
    if not risk.encryption_at_rest:
        score += 14
    if not risk.audit_logging_enabled:
        score += 12
    if not risk.mfa_enforced and (risk.financial_instrument or event.agent):
        score += 12
    if risk.involves_minors:
        score += 10
    if event.kind.value == "agent_transaction" and event.agent:
        if event.agent.production_mutation and not event.agent.approved_by:
            score += 15
        if event.agent.accesses_secrets:
            score += 10
    if event.pipeline and event.pipeline.transfer_mechanism == "none":
        score += 20
    if event.model_call and event.model_call.user_facing and not event.model_call.disclosed_as_ai:
        score += 8

    event.risk = risk.model_copy(update={"composite_score": min(100.0, round(score, 2))})
    return event
