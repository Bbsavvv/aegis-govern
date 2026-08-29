from __future__ import annotations

from aegis_core.models import PolicyViolation, TelemetryEvent
from regulatory_crosswalker.rules import COMPLIANCE_RULES
from regulatory_crosswalker.rules.base import ComplianceRule


class RegulatoryRulesEngine:
    def __init__(self, rules: list[ComplianceRule] | None = None) -> None:
        self.rules = rules or list(COMPLIANCE_RULES)

    def evaluate(self, event: TelemetryEvent) -> list[PolicyViolation]:
        findings: list[PolicyViolation] = []
        for rule in self.rules:
            finding = rule.evaluate(event)
            if finding is not None:
                findings.append(finding)
        return findings

    def evaluate_many(self, events: list[TelemetryEvent]) -> list[PolicyViolation]:
        findings: list[PolicyViolation] = []
        for event in events:
            findings.extend(self.evaluate(event))
        return findings
