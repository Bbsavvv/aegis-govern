from __future__ import annotations

import json
from collections import defaultdict

from aegis_core.config import Settings, get_settings
from aegis_core.models import (
    AcquisitionPackage,
    ComplianceProofReport,
    FileChange,
    PolicyViolation,
    RemediationPullRequest,
)
from aegis_core.store import GovernanceStore, get_store
from acquisition_engine.license import LicenseEnvelope
from remediator_engine.pr_builder import PullRequestBuilder, SEVERITY_RANK
from remediator_engine.worker import RemediatorEngineWorker


class AcquisitionRemediator(RemediatorEngineWorker):
    """Worker 3 extension: executive brief plus license-locked same-day patch bundle."""

    name = "acquisition_remediator"

    def __init__(self, store: GovernanceStore | None = None, settings: Settings | None = None) -> None:
        super().__init__(store=store)
        self.settings = settings or get_settings()
        self.builder = PullRequestBuilder(settings=self.settings)
        self.envelope = LicenseEnvelope()

    def package_report(self, report: ComplianceProofReport) -> AcquisitionPackage:
        stored = self.store.get_proof_report(report.report_id) or report
        violations = list(stored.findings)
        if not violations:
            raise ValueError("proof-report contains no violations to remediate")
        pull_requests = self._remediate_findings(violations)
        files = self._collect_files(pull_requests)
        license_key = self.envelope.issue_license(stored.report_id, stored.target_tenant_id)
        plaintext = json.dumps(
            {
                "report_id": stored.report_id,
                "target_host": stored.target_host,
                "files": [file.model_dump(mode="json") for file in files],
                "pull_requests": [pr.model_dump(mode="json") for pr in pull_requests],
            },
            indent=2,
            default=str,
        ).encode("utf-8")
        sealed = self.envelope.lock(plaintext, license_key, stored.report_id)
        summary = self._executive_summary(stored, pull_requests, files)
        package = AcquisitionPackage(
            report_id=stored.report_id,
            tenant_id=stored.target_tenant_id,
            executive_summary=summary,
            pull_request_ids=[pr.pr_id for pr in pull_requests],
            sealed_patch=sealed,
            license_key=license_key,
            unlock_instructions=(
                "Deliver the executive summary and sealed_patch JSON to the prospect. "
                "Retain license_key on the Aegis side until an enterprise license is activated. "
                "Call POST /acquisition/unlock with the sealed bundle and license_key to materialize patches."
            ),
        )
        return self.store.add_acquisition_package(package)

    def unlock_bundle(self, package: AcquisitionPackage, license_key: str) -> dict:
        raw = self.envelope.unlock(package.sealed_patch, license_key)
        payload = json.loads(raw.decode("utf-8"))
        payload["unlocked"] = True
        return payload

    def _remediate_findings(self, violations: list[PolicyViolation]) -> list[RemediationPullRequest]:
        grouped: dict[str, list[PolicyViolation]] = defaultdict(list)
        for violation in violations:
            grouped[violation.event_id].append(violation)
        staged: list[RemediationPullRequest] = []
        for event_id, event_violations in grouped.items():
            event = self.store.get_event(event_id)
            if event is None:
                continue
            pr = self.builder.build(event, event_violations)
            pr.labels = sorted(set(pr.labels + ["acquisition", "same-day-patch"]))
            staged.append(self.store.add_pull_request(pr))
        return staged

    def _collect_files(self, pull_requests: list[RemediationPullRequest]) -> list[FileChange]:
        unique: dict[str, FileChange] = {}
        for pr in pull_requests:
            for file in pr.files:
                unique[file.path] = file
        return list(unique.values())

    def _executive_summary(
        self,
        report: ComplianceProofReport,
        pull_requests: list[RemediationPullRequest],
        files: list[FileChange],
    ) -> str:
        lead = max(report.findings, key=lambda v: (SEVERITY_RANK[v.severity], v.score))
        fine_lines = []
        for line in sorted(report.fines, key=lambda item: item.expected_exposure_eur, reverse=True):
            fine_lines.append(
                f"- {line.citation} ({line.statutory_basis}): "
                f"expected €{line.expected_exposure_eur:,.0f} / statutory max €{line.statutory_maximum_eur:,.0f}"
            )
        article_list = ", ".join(sorted({item.citation for item in report.findings}))
        paths = "\n".join(f"- `{file.path}`" for file in files)
        pr_titles = "\n".join(f"- {pr.title} (`{pr.pr_id}`)" for pr in pull_requests)
        return "\n".join(
            [
                f"# Aegis Compliance Failure Proof-Report — {report.target_host}",
                "",
                f"**Report ID:** `{report.report_id}`  ",
                f"**Issued:** {report.issued_at.isoformat()}  ",
                f"**Merkle root:** `{report.integrity.merkle_root}`  ",
                f"**HMAC-SHA256:** `{report.integrity.signature}`  ",
                f"**Collection mode:** simulated conservative posture (no live intrusion of {report.target_host})",
                "",
                "## Executive snapshot",
                "",
                f"Aegis modeled {len(report.event_ids)} telemetry events for `{report.target_host}` and "
                f"crosswalked them through the EU AI Act, GDPR Chapter V, and financial-security rules. "
                f"**{len(report.findings)} article-level findings** were sealed into this immutable proof. "
                f"Lead finding: **{lead.title}** ({lead.citation}).",
                "",
                f"- Probability-weighted exposure: **€{report.expected_exposure_eur:,.0f}**",
                f"- Stacked statutory maximum (per framework): **€{report.statutory_maximum_eur:,.0f}**",
                f"- Assumed worldwide turnover: **€{report.annual_turnover_eur:,.0f}**",
                "",
                "## Article violations",
                "",
                f"{article_list}",
                "",
                *fine_lines,
                "",
                "## Same-day remediation (license-locked)",
                "",
                "Worker 3 staged the following pull requests. File contents are encrypted in the accompanying "
                "zero-day (same-day) patch bundle and unlock when the enterprise license is activated.",
                "",
                pr_titles,
                "",
                "### Locked artifacts",
                "",
                paths,
                "",
                "## Integrity",
                "",
                "Each finding is hashed; hashes are chained; the chain root is HMAC-signed with the Aegis "
                "platform key. Any alteration of findings breaks verification.",
                "",
                f"_{report.disclaimer}_",
            ]
        )
