from __future__ import annotations

from aegis_core.models import TelemetryEvent
from aegis_core.store import GovernanceStore
from telemetry_sentinel.risk import score_event


class TelemetryCatalog:
    def __init__(self, store: GovernanceStore) -> None:
        self.store = store

    def ingest(self, event: TelemetryEvent) -> TelemetryEvent:
        enriched = score_event(event)
        return self.store.upsert_event(enriched)

    def ingest_many(self, events: list[TelemetryEvent]) -> list[TelemetryEvent]:
        return [self.ingest(event) for event in events]
