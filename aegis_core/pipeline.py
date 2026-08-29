from __future__ import annotations

from aegis_core.config import Settings, get_settings
from aegis_core.models import RemediationPullRequest, TelemetryEvent
from aegis_core.store import GovernanceStore, get_store
from regulatory_crosswalker.worker import RegulatoryCrosswalkerWorker
from remediator_engine.worker import RemediatorEngineWorker
from telemetry_sentinel.worker import TelemetrySentinelWorker


class GovernancePipeline:
    """Runs Worker 1 → Worker 2 → Worker 3 as a single enforcement tick."""

    def __init__(self, store: GovernanceStore | None = None, settings: Settings | None = None, seed: int | None = None) -> None:
        self.store = store or get_store()
        self.settings = settings or get_settings()
        self.sentinel = TelemetrySentinelWorker(store=self.store, settings=self.settings, seed=seed)
        self.crosswalker = RegulatoryCrosswalkerWorker(store=self.store)
        self.remediator = RemediatorEngineWorker(store=self.store)

    def ingest(self, events: list[TelemetryEvent]) -> dict[str, object]:
        ingested = self.sentinel.ingest_many(events)
        violations = self.crosswalker.evaluate_events(ingested)
        pull_requests = self.remediator.remediate(violations)
        return self._summary(ingested, violations, pull_requests)

    def tick(self, batch_size: int | None = None) -> dict[str, object]:
        ingested = self.sentinel.tick(batch_size=batch_size)
        violations = self.crosswalker.evaluate_events(ingested)
        pull_requests = self.remediator.remediate(violations)
        return self._summary(ingested, violations, pull_requests)

    def _summary(self, events: list, violations: list, pull_requests: list[RemediationPullRequest]) -> dict[str, object]:
        return {
            "ingested_events": [event.event_id for event in events],
            "violations": [v.violation_id for v in violations],
            "pull_requests": [pr.pr_id for pr in pull_requests],
            "store": self.store.stats(),
            "index": self.sentinel.snapshot(),
        }
