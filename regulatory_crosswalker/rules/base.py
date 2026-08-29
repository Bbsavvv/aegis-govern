from __future__ import annotations

from typing import Protocol

from aegis_core.models import PolicyViolation, TelemetryEvent


class ComplianceRule(Protocol):
    rule_id: str

    def evaluate(self, event: TelemetryEvent) -> PolicyViolation | None: ...
