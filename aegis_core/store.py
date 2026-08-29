from __future__ import annotations

from collections import defaultdict
from threading import RLock

from aegis_core.models import (
    AcquisitionPackage,
    ComplianceProofReport,
    PolicyViolation,
    RemediationPullRequest,
    TelemetryEvent,
)


class GovernanceStore:
    """Thread-safe in-memory catalog, violation index, and staged PR ledger."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._events: dict[str, TelemetryEvent] = {}
        self._by_catalog_key: dict[str, list[str]] = defaultdict(list)
        self._by_tenant: dict[str, list[str]] = defaultdict(list)
        self._violations: dict[str, PolicyViolation] = {}
        self._violations_by_event: dict[str, list[str]] = defaultdict(list)
        self._prs: dict[str, RemediationPullRequest] = {}
        self._prs_by_violation: dict[str, str] = {}
        self._reports: dict[str, ComplianceProofReport] = {}
        self._packages: dict[str, AcquisitionPackage] = {}

    def upsert_event(self, event: TelemetryEvent) -> TelemetryEvent:
        with self._lock:
            if event.event_id not in self._events:
                self._by_catalog_key[event.catalog_key()].append(event.event_id)
                self._by_tenant[event.tenant_id].append(event.event_id)
            self._events[event.event_id] = event
            return event

    def get_event(self, event_id: str) -> TelemetryEvent | None:
        with self._lock:
            return self._events.get(event_id)

    def list_events(self, tenant_id: str | None = None, limit: int = 100) -> list[TelemetryEvent]:
        with self._lock:
            ids = (
                list(self._by_tenant.get(tenant_id, []))
                if tenant_id
                else list(self._events.keys())
            )
            events = [self._events[i] for i in ids if i in self._events]
            events.sort(key=lambda e: e.ingested_at, reverse=True)
            return events[:limit]

    def catalog_snapshot(self) -> dict[str, int]:
        with self._lock:
            return {key: len(ids) for key, ids in self._by_catalog_key.items()}

    def add_violations(self, violations: list[PolicyViolation]) -> list[PolicyViolation]:
        stored: list[PolicyViolation] = []
        with self._lock:
            for violation in violations:
                self._violations[violation.violation_id] = violation
                self._violations_by_event[violation.event_id].append(violation.violation_id)
                stored.append(violation)
        return stored

    def list_violations(
        self,
        event_id: str | None = None,
        tenant_id: str | None = None,
        limit: int = 200,
    ) -> list[PolicyViolation]:
        with self._lock:
            if event_id:
                items = [
                    self._violations[vid]
                    for vid in self._violations_by_event.get(event_id, [])
                    if vid in self._violations
                ]
            else:
                items = list(self._violations.values())
            if tenant_id:
                items = [v for v in items if v.tenant_id == tenant_id]
            items.sort(key=lambda v: v.score, reverse=True)
            return items[:limit]

    def add_pull_request(self, pr: RemediationPullRequest) -> RemediationPullRequest:
        with self._lock:
            self._prs[pr.pr_id] = pr
            for violation_id in pr.violation_ids:
                self._prs_by_violation[violation_id] = pr.pr_id
            return pr

    def get_pull_request(self, pr_id: str) -> RemediationPullRequest | None:
        with self._lock:
            return self._prs.get(pr_id)

    def list_pull_requests(
        self, tenant_id: str | None = None, limit: int = 50
    ) -> list[RemediationPullRequest]:
        with self._lock:
            items = list(self._prs.values())
            if tenant_id:
                items = [pr for pr in items if pr.tenant_id == tenant_id]
            items.sort(key=lambda pr: pr.created_at, reverse=True)
            return items[:limit]

    def open_violations_without_pr(self) -> list[PolicyViolation]:
        with self._lock:
            return [
                v
                for v in self._violations.values()
                if v.remediable and v.violation_id not in self._prs_by_violation
            ]

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "events": len(self._events),
                "violations": len(self._violations),
                "pull_requests": len(self._prs),
                "catalog_keys": len(self._by_catalog_key),
                "proof_reports": len(self._reports),
                "acquisition_packages": len(self._packages),
            }

    def add_proof_report(self, report: ComplianceProofReport) -> ComplianceProofReport:
        with self._lock:
            self._reports[report.report_id] = report
            return report

    def get_proof_report(self, report_id: str) -> ComplianceProofReport | None:
        with self._lock:
            return self._reports.get(report_id)

    def list_proof_reports(self, limit: int = 50) -> list[ComplianceProofReport]:
        with self._lock:
            items = list(self._reports.values())
            items.sort(key=lambda r: r.issued_at, reverse=True)
            return items[:limit]

    def add_acquisition_package(self, package: AcquisitionPackage) -> AcquisitionPackage:
        with self._lock:
            self._packages[package.package_id] = package
            return package

    def get_acquisition_package(self, package_id: str) -> AcquisitionPackage | None:
        with self._lock:
            return self._packages.get(package_id)

    def list_acquisition_packages(self, tenant_id: str | None = None, limit: int = 50) -> list[AcquisitionPackage]:
        with self._lock:
            items = list(self._packages.values())
            if tenant_id:
                items = [p for p in items if p.tenant_id == tenant_id]
            items.sort(key=lambda p: p.created_at, reverse=True)
            return items[:limit]


_STORE = GovernanceStore()


def get_store() -> GovernanceStore:
    return _STORE


def reset_store() -> GovernanceStore:
    """Clear the singleton in place so API workers keep a valid reference."""
    store = get_store()
    store.__init__()
    return store
