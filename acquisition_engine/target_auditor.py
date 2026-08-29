from __future__ import annotations

from aegis_core.config import Settings, get_settings
from aegis_core.models import ComplianceProofReport, new_id
from aegis_core.store import GovernanceStore, get_store
from acquisition_engine.fines import FineProjector
from acquisition_engine.notary import ProofNotary
from acquisition_engine.sweep import TargetRef, TargetSweepSimulator
from regulatory_crosswalker.worker import RegulatoryCrosswalkerWorker
from telemetry_sentinel.worker import TelemetrySentinelWorker


class TargetAuditor:
    """Acquisition Worker: simulated domain sweep → crosswalker → sealed proof-report."""

    name = "target_auditor"

    def __init__(
        self,
        store: GovernanceStore | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.store = store or get_store()
        self.settings = settings or get_settings()
        self.sentinel = TelemetrySentinelWorker(store=self.store, settings=self.settings)
        self.crosswalker = RegulatoryCrosswalkerWorker(store=self.store)
        self.projector = FineProjector()
        self.notary = ProofNotary(settings=self.settings)

    def audit(
        self,
        target: str,
        annual_turnover_eur: float | None = None,
        sweep_size: int | None = None,
    ) -> ComplianceProofReport:
        ref = TargetRef(target)
        turnover = annual_turnover_eur if annual_turnover_eur is not None else self.settings.default_turnover_eur
        if turnover <= 0:
            raise ValueError("annual_turnover_eur must be positive")
        size = sweep_size if sweep_size is not None else self.settings.acquisition_sweep_size
        events = TargetSweepSimulator(ref).sweep(size=size)
        ingested = self.sentinel.ingest_many(events)
        violations = self.crosswalker.evaluate_events(ingested)
        fines = self.projector.project(violations, turnover)
        expected, statutory = self.projector.totals(fines)
        report_id = new_id("prf")
        integrity = self.notary.seal(
            report_id=report_id,
            target_host=ref.host,
            findings=violations,
            extra={
                "annual_turnover_eur": turnover,
                "expected_exposure_eur": expected,
                "statutory_maximum_eur": statutory,
            },
        )
        report = ComplianceProofReport(
            report_id=report_id,
            target_input=ref.raw,
            target_host=ref.host,
            target_tenant_id=ref.tenant_id,
            annual_turnover_eur=turnover,
            event_ids=[event.event_id for event in ingested],
            violation_ids=[item.violation_id for item in violations],
            findings=violations,
            fines=fines,
            expected_exposure_eur=expected,
            statutory_maximum_eur=statutory,
            integrity=integrity,
        )
        if not self.notary.verify(report.report_id, report.findings, report.integrity):
            raise RuntimeError("proof-report failed self-verification")
        return self.store.add_proof_report(report)
