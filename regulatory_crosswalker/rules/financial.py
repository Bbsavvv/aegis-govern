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
        framework=Framework.FINANCIAL_SECURITY,
        citation=citation,
        title=title,
        description=description,
        severity=severity,
        score=min(100.0, severity.score + event.risk.composite_score * 0.1),
        rule_id=rule_id,
        evidence=evidence,
    )


class CardDataInCleartextRule:
    rule_id = "pci-dss-3-cardholder"

    def evaluate(self, event: TelemetryEvent) -> PolicyViolation | None:
        if not event.risk.payment_card_data:
            return None
        pan_exposed = bool(
            event.pipeline
            and "card_pan" in event.pipeline.fields
            and "card_pan" not in event.pipeline.masked_fields
        )
        unprotected = not event.risk.encryption_at_rest or not event.risk.encryption_in_transit
        if not unprotected and not pan_exposed:
            return None
        return _violation(
            event,
            rule_id=self.rule_id,
            citation="PCI DSS 3.4 / 4.2",
            title="Payment card data lacks required protection",
            description=(
                "Cardholder data is present in a telemetry path without encryption "
                "and/or PAN masking required by PCI DSS."
            ),
            severity=Severity.CRITICAL,
            evidence={"payment_card_data": True},
        )


class PrivilegedAgentWithoutMfaRule:
    rule_id = "dora-ict-access-mfa"

    def evaluate(self, event: TelemetryEvent) -> PolicyViolation | None:
        agent = event.agent
        if agent is None:
            return None
        privileged = agent.accesses_secrets or agent.production_mutation or event.risk.financial_instrument
        if not privileged or event.risk.mfa_enforced:
            return None
        return _violation(
            event,
            rule_id=self.rule_id,
            citation="DORA Art. 9; SOC 2 CC6.1",
            title="Privileged agent action without MFA enforcement",
            description=(
                f"Agent {agent.agent_id} is mutating {agent.target_system} without "
                "multi-factor authentication on the control plane."
            ),
            severity=Severity.HIGH,
            evidence={"agent_id": agent.agent_id, "action": agent.action},
        )


class UnapprovedProductionMutationRule:
    rule_id = "sox-change-control"

    def evaluate(self, event: TelemetryEvent) -> PolicyViolation | None:
        agent = event.agent
        if agent is None or not agent.production_mutation:
            return None
        if agent.approved_by:
            return None
        return _violation(
            event,
            rule_id=self.rule_id,
            citation="SOX §404; DORA Art. 16",
            title="Unaudited production mutation by autonomous agent",
            description=(
                "Production changes require documented change control and dual control. "
                f"{agent.agent_id} executed {agent.action} without an approver."
            ),
            severity=Severity.HIGH,
            evidence={
                "agent_id": agent.agent_id,
                "target_system": agent.target_system,
                "writes_code": agent.writes_code,
            },
        )


class MissingFinancialAuditTrailRule:
    rule_id = "glba-audit-trail"

    def evaluate(self, event: TelemetryEvent) -> PolicyViolation | None:
        if not event.risk.financial_instrument and not (event.agent and event.agent.amount_usd):
            return None
        if event.risk.audit_logging_enabled:
            return None
        return _violation(
            event,
            rule_id=self.rule_id,
            citation="GLBA Safeguards Rule; PCI DSS 10",
            title="Financial transaction path has no immutable audit log",
            description=(
                "Financial or payment activity is executing without an immutable "
                "audit trail covering who, what, when, and before/after state."
            ),
            severity=Severity.HIGH,
            evidence={"financial_instrument": event.risk.financial_instrument},
        )


FINANCIAL_RULES = [
    CardDataInCleartextRule(),
    PrivilegedAgentWithoutMfaRule(),
    UnapprovedProductionMutationRule(),
    MissingFinancialAuditTrailRule(),
]
