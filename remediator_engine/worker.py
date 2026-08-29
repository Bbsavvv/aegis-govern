from __future__ import annotations

from collections import defaultdict

from aegis_core.models import PolicyViolation, RemediationPullRequest
from aegis_core.store import GovernanceStore, get_store
from remediator_engine.pr_builder import PullRequestBuilder


class RemediatorEngineWorker:
    """Worker 3: turn policy violations into staged, merge-ready PR payloads."""

    name = "remediator_engine"

    def __init__(self, store: GovernanceStore | None = None) -> None:
        self.store = store or get_store()
        self.builder = PullRequestBuilder()

    def remediate(self, violations: list[PolicyViolation] | None = None) -> list[RemediationPullRequest]:
        open_violations = violations if violations is not None else self.store.open_violations_without_pr()
        grouped: dict[str, list[PolicyViolation]] = defaultdict(list)
        for violation in open_violations:
            grouped[violation.event_id].append(violation)

        staged: list[RemediationPullRequest] = []
        for event_id, event_violations in grouped.items():
            event = self.store.get_event(event_id)
            if event is None:
                continue
            pr = self.builder.build(event, event_violations)
            staged.append(self.store.add_pull_request(pr))
        return staged

    def tick(self) -> list[RemediationPullRequest]:
        return self.remediate()
