from __future__ import annotations

from aegis_core.models import (
    Framework,
    PolicyViolation,
    Severity,
    TelemetryEvent,
)

EEA = {"AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "IS", "LI", "NO"}
ADEQUATE = {"AD", "AR", "CA", "FO", "GG", "IL", "IM", "JP", "JE", "NZ", "KR", "CH", "GB", "UY"}


def _violation(
    event: TelemetryEvent,
    *,
    rule_id: str,
    citation: str,
    title: str,
    description: str,
    severity: Severity,
    evidence: dict,
) -> PolicyViolation:
    return PolicyViolation(
        event_id=event.event_id,
        tenant_id=event.tenant_id,
        framework=Framework.GDPR,
        citation=citation,
        title=title,
        description=description,
        severity=severity,
        score=min(100.0, severity.score + event.risk.composite_score * 0.12),
        rule_id=rule_id,
        evidence=evidence,
    )


class UnlawfulThirdCountryTransferRule:
    rule_id = "gdpr-art-44-transfer"

    def evaluate(self, event: TelemetryEvent) -> PolicyViolation | None:
        dest = event.risk.data_residency_destination
        source = event.risk.data_residency_source
        if source not in EEA or dest in EEA or dest in ADEQUATE:
            return None
        if event.risk.standard_contractual_clauses or event.risk.adequacy_decision:
            return None
        mechanism = event.pipeline.transfer_mechanism if event.pipeline else "unknown"
        if mechanism in {"scc", "bcr", "adequacy"}:
            return None
        return _violation(
            event,
            rule_id=self.rule_id,
            citation="GDPR Art. 44–46",
            title="Cross-border transfer without a valid Chapter V mechanism",
            description=(
                f"Personal data is moving {source}→{dest} without an adequacy decision, "
                "standard contractual clauses, or binding corporate rules."
            ),
            severity=Severity.CRITICAL,
            evidence={
                "source": source,
                "destination": dest,
                "transfer_mechanism": mechanism,
                "record_count": event.pipeline.record_count if event.pipeline else None,
            },
        )


class SpecialCategoryWithoutBasisRule:
    rule_id = "gdpr-art-9-special-category"

    def evaluate(self, event: TelemetryEvent) -> PolicyViolation | None:
        if not event.risk.special_category_data:
            return None
        if event.risk.lawful_basis in {"explicit_consent", "consent", "vital_interests", "substantial_public_interest"}:
            return None
        return _violation(
            event,
            rule_id=self.rule_id,
            citation="GDPR Art. 9",
            title="Special-category data processed without an Article 9 condition",
            description=(
                "Health, biometric, or other special-category data is present without "
                "an explicit Article 9 processing condition."
            ),
            severity=Severity.HIGH,
            evidence={
                "pii_categories": event.risk.pii_categories,
                "lawful_basis": event.risk.lawful_basis,
            },
        )


class UnmaskedExportRule:
    rule_id = "gdpr-art-25-data-minimisation"

    def evaluate(self, event: TelemetryEvent) -> PolicyViolation | None:
        pipeline = event.pipeline
        if pipeline is None:
            return None
        sensitive = {"national_id", "health_condition", "card_pan", "biometric_template"}
        exposed = [field for field in pipeline.fields if field in sensitive and field not in pipeline.masked_fields]
        if not exposed:
            return None
        return _violation(
            event,
            rule_id=self.rule_id,
            citation="GDPR Art. 5(1)(c) and Art. 25",
            title="Sensitive fields exported without masking",
            description=(
                "Data-protection-by-design requires minimisation and masking of "
                f"sensitive identifiers before export. Exposed fields: {', '.join(exposed)}."
            ),
            severity=Severity.HIGH,
            evidence={"exposed_fields": exposed, "dataset": pipeline.dataset_name},
        )


class UnencryptedTransferRule:
    rule_id = "gdpr-art-32-security"

    def evaluate(self, event: TelemetryEvent) -> PolicyViolation | None:
        if event.risk.encryption_in_transit and event.risk.encryption_at_rest:
            return None
        if not event.risk.pii_categories and not event.pipeline:
            return None
        return _violation(
            event,
            rule_id=self.rule_id,
            citation="GDPR Art. 32",
            title="Personal data processed without appropriate encryption",
            description=(
                "Integrity and confidentiality controls are incomplete: encryption "
                f"in transit={event.risk.encryption_in_transit}, at rest={event.risk.encryption_at_rest}."
            ),
            severity=Severity.HIGH,
            evidence={
                "encryption_in_transit": event.risk.encryption_in_transit,
                "encryption_at_rest": event.risk.encryption_at_rest,
            },
        )


GDPR_RULES = [
    UnlawfulThirdCountryTransferRule(),
    SpecialCategoryWithoutBasisRule(),
    UnmaskedExportRule(),
    UnencryptedTransferRule(),
]
