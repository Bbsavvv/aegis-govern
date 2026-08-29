from __future__ import annotations

from collections import Counter

from aegis_core.store import GovernanceStore


class TelemetryIndexer:
    """Maintains inverted indexes used by downstream compliance workers."""

    def __init__(self, store: GovernanceStore) -> None:
        self.store = store

    def index_summary(self) -> dict[str, object]:
        events = self.store.list_events(limit=10_000)
        kinds = Counter(event.kind.value for event in events)
        residencies = Counter(
            f"{event.risk.data_residency_source}->{event.risk.data_residency_destination}"
            for event in events
        )
        high_risk = sum(1 for event in events if event.risk.composite_score >= 70)
        return {
            "event_count": len(events),
            "by_kind": dict(kinds),
            "transfer_corridors": dict(residencies),
            "high_risk_events": high_risk,
            "catalog": self.store.catalog_snapshot(),
        }
