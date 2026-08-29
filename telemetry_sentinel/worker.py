from __future__ import annotations

from aegis_core.config import Settings, get_settings
from aegis_core.models import TelemetryEvent
from aegis_core.store import GovernanceStore, get_store
from telemetry_sentinel.catalog import TelemetryCatalog
from telemetry_sentinel.indexer import TelemetryIndexer
from telemetry_sentinel.simulator import TelemetrySimulator


class TelemetrySentinelWorker:
    """Worker 1: ingest, catalog, and index model, pipeline, and agent telemetry."""

    name = "telemetry_sentinel"

    def __init__(
        self,
        store: GovernanceStore | None = None,
        settings: Settings | None = None,
        seed: int | None = None,
    ) -> None:
        self.store = store or get_store()
        self.settings = settings or get_settings()
        self.catalog = TelemetryCatalog(self.store)
        self.indexer = TelemetryIndexer(self.store)
        self.simulator = TelemetrySimulator(seed=seed)

    def ingest(self, event: TelemetryEvent) -> TelemetryEvent:
        return self.catalog.ingest(event)

    def ingest_many(self, events: list[TelemetryEvent]) -> list[TelemetryEvent]:
        return self.catalog.ingest_many(events)

    def tick(self, batch_size: int | None = None) -> list[TelemetryEvent]:
        size = batch_size or self.settings.ingest_batch_size
        simulated = self.simulator.batch(size)
        return self.ingest_many(simulated)

    def snapshot(self) -> dict[str, object]:
        return {"worker": self.name, **self.indexer.index_summary()}
