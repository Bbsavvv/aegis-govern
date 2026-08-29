from telemetry_sentinel.worker import TelemetrySentinelWorker
from tests.factories import transfer_event


def test_ingest_scores_and_catalogs_cross_border_event():
    worker = TelemetrySentinelWorker()
    event = worker.ingest(transfer_event())
    assert event.event_id in {item.event_id for item in worker.store.list_events()}
    assert event.risk.cross_border is True
    assert event.risk.composite_score >= 70
    snapshot = worker.snapshot()
    assert snapshot["event_count"] == 1
    assert snapshot["high_risk_events"] == 1


def test_simulator_tick_indexes_mixed_kinds():
    worker = TelemetrySentinelWorker(seed=42)
    events = worker.tick(batch_size=12)
    assert len(events) == 12
    kinds = {event.kind.value for event in events}
    assert kinds <= {"model_call", "cross_border_pipeline", "agent_transaction"}
    assert worker.store.stats()["events"] == 12
