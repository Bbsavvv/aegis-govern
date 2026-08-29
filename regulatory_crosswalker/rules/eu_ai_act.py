from __future__ import annotations

from aegis_core.models import (
    Framework,
    PolicyViolation,
    Severity,
    TelemetryEvent,
)


def _violation(
    event: TelemetryEvent,
    *,
    rule_id: str,
    citation: str,
    title: str,
    description: str,
    severity: Severity,
    evidence: dict,
) -> PolicyViolation:
    return PolicyViolation(
        event_id=event.event_id,
        tenant_id=event.tenant_id,
        framework=Framework.EU_AI_ACT,
        citation=citation,
        title=title,
        description=description,
        severity=severity,
        score=min(100.0, severity.score + event.risk.composite_score * 0.15),
        rule_id=rule_id,
        evidence=evidence,
    )


class ProhibitedSocialScoringRule:
    rule_id = "eu-ai-act-art-5-social-scoring"

    def evaluate(self, event: TelemetryEvent) -> PolicyViolation | None:
        if not event.risk.social_scoring:
            return None
        return _violation(
            event,
            rule_id=self.rule_id,
            citation="EU AI Act Art. 5(1)(c)",
            title="Prohibited social scoring practice detected",
            description=(
                "Telemetry indicates evaluation or classification of natural persons "
                "based on social behaviour or predicted personal characteristics, "
                "which is prohibited under Article 5."
            ),
            severity=Severity.CRITICAL,
            evidence={"social_scoring": True, "purpose": event.risk.purpose},
        )


class RealTimeRemoteBiometricRule:
    rule_id = "eu-ai-act-art-5-rbi"

    def evaluate(self, event: TelemetryEvent) -> PolicyViolation | None:
        if not event.risk.real_time_remote_biometric_id:
            return None
        return _violation(
            event,
            rule_id=self.rule_id,
            citation="EU AI Act Art. 5(1)(h)",
            title="Real-time remote biometric identification in use",
            description=(
                "Real-time remote biometric identification in publicly accessible "
                "spaces is prohibited except for narrowly defined law-enforcement "
                "authorizations. No such authorization is present in telemetry."
            ),
            severity=Severity.CRITICAL,
            evidence={"biometric_processing": True, "real_time": True},
        )


class HighRiskOversightRule:
    rule_id = "eu-ai-act-art-14-oversight"

    def evaluate(self, event: TelemetryEvent) -> PolicyViolation | None:
        high_risk = event.risk.model_risk_class == "high" or bool(event.risk.annex_iii_use_case)
        if not high_risk or event.risk.human_oversight:
            return None
        return _violation(
            event,
            rule_id=self.rule_id,
            citation="EU AI Act Art. 14",
            title="High-risk AI system lacks human oversight",
            description=(
                "Annex III / high-risk system is operating without demonstrated human "
                "oversight measures capable of intervening or interrupting the system."
            ),
            severity=Severity.HIGH,
            evidence={
                "model_risk_class": event.risk.model_risk_class,
                "annex_iii_use_case": event.risk.annex_iii_use_case,
                "automated_decision": event.risk.automated_decision,
            },
        )


class TransparencyDisclosureRule:
    rule_id = "eu-ai-act-art-50-transparency"

    def evaluate(self, event: TelemetryEvent) -> PolicyViolation | None:
        call = event.model_call
        if call is None or not call.user_facing or call.disclosed_as_ai:
            return None
        return _violation(
            event,
            rule_id=self.rule_id,
            citation="EU AI Act Art. 50",
            title="AI interaction not disclosed to the user",
            description=(
                "Natural persons interacting with an AI system are not informed that "
                "they are interacting with AI, contrary to Article 50 transparency duties."
            ),
            severity=Severity.MEDIUM,
            evidence={"model_id": call.model_id, "provider": call.provider},
        )


class HighRiskLoggingRule:
    rule_id = "eu-ai-act-art-12-logging"

    def evaluate(self, event: TelemetryEvent) -> PolicyViolation | None:
        high_risk = event.risk.model_risk_class == "high" or bool(event.risk.annex_iii_use_case)
        if not high_risk or event.risk.audit_logging_enabled:
            return None
        return _violation(
            event,
            rule_id=self.rule_id,
            citation="EU AI Act Art. 12",
            title="High-risk system missing automatic event logs",
            description=(
                "Automatically generated logs sufficient to trace operation of a "
                "high-risk AI system are not enabled."
            ),
            severity=Severity.HIGH,
            evidence={"audit_logging_enabled": False},
        )


EU_AI_ACT_RULES = [
    ProhibitedSocialScoringRule(),
    RealTimeRemoteBiometricRule(),
    HighRiskOversightRule(),
    TransparencyDisclosureRule(),
    HighRiskLoggingRule(),
]
