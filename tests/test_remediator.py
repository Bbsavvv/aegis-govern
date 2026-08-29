from aegis_core.store import get_store
from remediator_engine.worker import RemediatorEngineWorker
from regulatory_crosswalker.worker import RegulatoryCrosswalkerWorker
from telemetry_sentinel.worker import TelemetrySentinelWorker
from tests.factories import transfer_event


def test_remediator_stages_scc_env_and_masking_pr():
    store = get_store()
    sentinel = TelemetrySentinelWorker(store=store)
    event = sentinel.ingest(transfer_event())
    violations = RegulatoryCrosswalkerWorker(store=store).evaluate_event(event)
    prs = RemediatorEngineWorker(store=store).remediate(violations)
    assert len(prs) == 1
    pr = prs[0]
    paths = {file.path for file in pr.files}
    assert ".env.compliance" in paths
    assert "config/data_masking.yaml" in paths
    env = next(file for file in pr.files if file.path == ".env.compliance")
    assert "GDPR_TRANSFER_MECHANISM=scc" in env.content
    assert env.patch.startswith("---")
    assert pr.violation_ids
    assert pr.status in {"staged", "awaiting_review"}
