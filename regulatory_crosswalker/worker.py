from __future__ import annotations

from aegis_core.models import PolicyViolation, TelemetryEvent
from aegis_core.store import GovernanceStore, get_store
from regulatory_crosswalker.engine import RegulatoryRulesEngine


class RegulatoryCrosswalkerWorker:
    """Worker 2: map telemetry onto EU AI Act, GDPR, and financial controls."""

    name = "regulatory_crosswalker"

    def __init__(self, store: GovernanceStore | None = None) -> None:
        self.store = store or get_store()
        self.engine = RegulatoryRulesEngine()

    def evaluate_event(self, event: TelemetryEvent) -> list[PolicyViolation]:
        findings = self.engine.evaluate(event)
        return self.store.add_violations(findings)

    def evaluate_events(self, events: list[TelemetryEvent]) -> list[PolicyViolation]:
        findings = self.engine.evaluate_many(events)
        return self.store.add_violations(findings)

    def tick(self, events: list[TelemetryEvent] | None = None) -> list[PolicyViolation]:
        batch = events if events is not None else self.store.list_events(limit=250)
        already = {v.event_id for v in self.store.list_violations(limit=10_000)}
        fresh = [event for event in batch if event.event_id not in already]
        return self.evaluate_events(fresh)
