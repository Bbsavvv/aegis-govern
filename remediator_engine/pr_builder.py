from __future__ import annotations

from aegis_core.config import Settings, get_settings
from aegis_core.models import FileChange, PolicyViolation, RemediationPullRequest, Severity, TelemetryEvent, new_id
from remediator_engine.patcher import PatchSynthesizer

SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class PullRequestBuilder:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.patcher = PatchSynthesizer()

    def build(self, event: TelemetryEvent, violations: list[PolicyViolation]) -> RemediationPullRequest:
        files_by_path: dict[str, FileChange] = {}
        for violation in violations:
            for file in self.patcher.synthesize(event, violation):
                files_by_path[file.path] = file
        files = list(files_by_path.values())
        lead = max(violations, key=lambda v: SEVERITY_RANK[v.severity])
        frameworks = sorted({v.framework.value for v in violations})
        citations = ", ".join(sorted({v.citation for v in violations}))
        slug = lead.rule_id.replace("_", "-")
        branch = f"aegis/remediate-{slug}-{new_id('br')[-8:]}"
        title = f"[Aegis] {lead.title}"
        body = self._body(event, violations, citations)
        return RemediationPullRequest(
            tenant_id=event.tenant_id,
            title=title,
            body=body,
            base_branch=self.settings.default_base_branch,
            head_branch=branch,
            commit_message=f"fix(compliance): remediate {lead.rule_id} for {event.event_id}",
            files=files,
            labels=["aegis", "auto-remediation", *frameworks, lead.severity.value],
            reviewers=list(self.settings.default_reviewers),
            violation_ids=[v.violation_id for v in violations],
            event_ids=[event.event_id],
            merge_ready=lead.severity != Severity.CRITICAL,
            status="awaiting_review" if lead.severity == Severity.CRITICAL else "staged",
        )

    def _body(self, event: TelemetryEvent, violations: list[PolicyViolation], citations: str) -> str:
        lines = [
            f"## Autonomous remediation for `{event.event_id}`",
            "",
            f"- Tenant: `{event.tenant_id}`",
            f"- Source: `{event.source_system}`",
            f"- Kind: `{event.kind.value}`",
            f"- Composite risk: `{event.risk.composite_score}`",
            f"- Corridor: `{event.risk.data_residency_source} → {event.risk.data_residency_destination}`",
            f"- Citations: {citations}",
            "",
            "### Violations",
        ]
        for violation in violations:
            lines.append(
                f"- **{violation.severity.value.upper()}** `{violation.rule_id}` "
                f"({violation.citation}): {violation.description}"
            )
        lines.extend(
            [
                "",
                "### Staged artifacts",
                "This pull request contains policy-as-code, masking configuration, and/or environment controls.",
                "Critical findings remain merge-blocked pending security-approvers review.",
            ]
        )
        return "\n".join(lines)
