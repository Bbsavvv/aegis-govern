from __future__ import annotations

from aegis_core.models import FileChange, PolicyViolation, TelemetryEvent
from remediator_engine.templates import RULE_FIXES, encryption_and_audit


class PatchSynthesizer:
    def synthesize(self, event: TelemetryEvent, violation: PolicyViolation) -> list[FileChange]:
        builders = RULE_FIXES.get(violation.rule_id, (encryption_and_audit,))
        files = [builder(event, violation) for builder in builders]
        unique: dict[str, FileChange] = {}
        for file in files:
            unique[file.path] = file
        return list(unique.values())
