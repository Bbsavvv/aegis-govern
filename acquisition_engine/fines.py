from __future__ import annotations

from dataclasses import dataclass

from aegis_core.models import FineLine, Framework, PolicyViolation, Severity


@dataclass(frozen=True)
class StatutorySchedule:
    statutory_basis: str
    turnover_rate: float
    cap_eur: float


SCHEDULE: dict[str, StatutorySchedule] = {
    "gdpr-art-44-transfer": StatutorySchedule("GDPR Art. 83(5)(c)", 0.04, 20_000_000),
    "gdpr-art-9-special-category": StatutorySchedule("GDPR Art. 83(5)(a)", 0.04, 20_000_000),
    "gdpr-art-25-data-minimisation": StatutorySchedule("GDPR Art. 83(5)(a)", 0.04, 20_000_000),
    "gdpr-art-32-security": StatutorySchedule("GDPR Art. 83(4)(a)", 0.02, 10_000_000),
    "eu-ai-act-art-5-social-scoring": StatutorySchedule("EU AI Act Art. 99(3)", 0.07, 35_000_000),
    "eu-ai-act-art-5-rbi": StatutorySchedule("EU AI Act Art. 99(3)", 0.07, 35_000_000),
    "eu-ai-act-art-14-oversight": StatutorySchedule("EU AI Act Art. 99(4)", 0.03, 15_000_000),
    "eu-ai-act-art-50-transparency": StatutorySchedule("EU AI Act Art. 99(4)", 0.03, 15_000_000),
    "eu-ai-act-art-12-logging": StatutorySchedule("EU AI Act Art. 99(4)", 0.03, 15_000_000),
    "pci-dss-3-cardholder": StatutorySchedule("PCI DSS contractual / scheme penalties", 0.0, 500_000),
    "dora-ict-access-mfa": StatutorySchedule("DORA Art. 64", 0.02, 10_000_000),
    "sox-change-control": StatutorySchedule("SOX §404 enforcement / restatement exposure", 0.0, 5_000_000),
    "glba-audit-trail": StatutorySchedule("GLBA / FTC civil penalty exposure", 0.0, 2_000_000),
}

SEVERITY_WEIGHT = {
    Severity.INFO: 0.01,
    Severity.LOW: 0.03,
    Severity.MEDIUM: 0.08,
    Severity.HIGH: 0.18,
    Severity.CRITICAL: 0.32,
}


class FineProjector:
    """Maps each finding to statutory maximum and probability-weighted exposure."""

    def project(self, violations: list[PolicyViolation], annual_turnover_eur: float) -> list[FineLine]:
        lines: list[FineLine] = []
        for violation in violations:
            schedule = SCHEDULE.get(
                violation.rule_id,
                StatutorySchedule("unscheduled administrative exposure", 0.01, 5_000_000),
            )
            if schedule.turnover_rate:
                statutory_maximum = max(schedule.cap_eur, annual_turnover_eur * schedule.turnover_rate)
            else:
                statutory_maximum = schedule.cap_eur
            weight = SEVERITY_WEIGHT[violation.severity]
            expected = round(statutory_maximum * weight, 2)
            lines.append(
                FineLine(
                    violation_id=violation.violation_id,
                    rule_id=violation.rule_id,
                    framework=violation.framework,
                    citation=violation.citation,
                    statutory_basis=schedule.statutory_basis,
                    severity=violation.severity,
                    turnover_rate=schedule.turnover_rate,
                    statutory_cap_eur=schedule.cap_eur,
                    statutory_maximum_eur=round(statutory_maximum, 2),
                    expected_exposure_eur=expected,
                    methodology=(
                        "statutory_maximum = max(article cap, turnover × rate); "
                        f"expected_exposure = statutory_maximum × {weight} severity weight"
                    ),
                )
            )
        return lines

    def totals(self, lines: list[FineLine]) -> tuple[float, float]:
        by_framework: dict[Framework, list[FineLine]] = {}
        for line in lines:
            by_framework.setdefault(line.framework, []).append(line)
        expected = 0.0
        statutory = 0.0
        for group in by_framework.values():
            expected += max((item.expected_exposure_eur for item in group), default=0.0)
            statutory += max((item.statutory_maximum_eur for item in group), default=0.0)
        return round(expected, 2), round(statutory, 2)
