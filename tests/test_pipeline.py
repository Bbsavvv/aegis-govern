from aegis_core.pipeline import GovernancePipeline
from tests.factories import transfer_event


def test_pipeline_ingest_runs_all_three_workers():
    pipeline = GovernancePipeline(seed=1)
    result = pipeline.ingest([transfer_event()])
    assert len(result["ingested_events"]) == 1
    assert len(result["violations"]) >= 1
    assert len(result["pull_requests"]) == 1
    assert result["store"]["events"] == 1
