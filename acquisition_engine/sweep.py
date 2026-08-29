from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse

from aegis_core.models import (
    CrossBorderPipelinePayload,
    EventKind,
    ModelCallPayload,
    RiskMetadata,
    TelemetryEvent,
)
from telemetry_sentinel.simulator import ADEQUATE, EU_COUNTRIES, TelemetrySimulator

TLD_REGION = {
    "de": "DE",
    "fr": "FR",
    "nl": "NL",
    "ie": "IE",
    "eu": "IE",
    "uk": "GB",
    "com": "US",
    "io": "US",
    "ai": "US",
    "us": "US",
    "in": "IN",
    "sg": "SG",
    "br": "BR",
}

BLOCKED_SCHEMES = {"file", "javascript", "data", "ftp", "ws", "wss"}


class TargetRef:
    def __init__(self, raw: str) -> None:
        self.raw = raw.strip()
        self.url = self._normalize(self.raw)
        parsed = urlparse(self.url)
        if parsed.scheme.lower() in BLOCKED_SCHEMES:
            raise ValueError(f"unsupported target scheme: {parsed.scheme}")
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("target must be a domain or http(s) URL")
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host or host in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
            raise ValueError("target host is not a public company domain")
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            raise ValueError("raw IP targets are not accepted; use a company domain")
        self.host = host
        self.path = parsed.path or "/"
        self.tenant_id = self._tenant(host)
        self.home_region = self._region(host)

    def seed(self) -> int:
        return int(hashlib.sha256(self.host.encode("utf-8")).hexdigest()[:12], 16)

    def _normalize(self, raw: str) -> str:
        if "://" in raw:
            return raw
        return f"https://{raw.lstrip('/')}"

    def _tenant(self, host: str) -> str:
        labels = [part for part in host.split(".") if part not in {"www", "api", "app"}]
        core = labels[0] if labels else "target"
        return re.sub(r"[^a-z0-9]+", "-", core)[:40] or "target"

    def _region(self, host: str) -> str:
        tld = host.rsplit(".", 1)[-1]
        return TLD_REGION.get(tld, "US")


class TargetSweepSimulator:
    """Builds a simulated estate for a named domain. Does not contact the target."""

    def __init__(self, target: TargetRef) -> None:
        self.target = target
        self.base = TelemetrySimulator(seed=target.seed())

    def sweep(self, size: int) -> list[TelemetryEvent]:
        events = [self._bind(event) for event in self.base.batch(max(0, size - 2))]
        events.append(self._public_inference_surface())
        events.append(self._eu_us_pipeline())
        return events

    def _bind(self, event: TelemetryEvent) -> TelemetryEvent:
        event.tenant_id = self.target.tenant_id
        event.source_system = f"{self.target.host}{self.target.path}"
        event.tags = sorted(set(event.tags + ["acquisition-sweep", "simulated"]))
        event.raw_context = {
            **event.raw_context,
            "collection_mode": "simulated_posture_model",
            "target_host": self.target.host,
        }
        return event

    def _public_inference_surface(self) -> TelemetryEvent:
        api_like = "api" in self.target.host or "v1" in self.target.path or "chat" in self.target.path
        dest = "US" if self.target.home_region in EU_COUNTRIES else self.target.home_region
        return TelemetryEvent(
            source_system=f"{self.target.host}:inference",
            tenant_id=self.target.tenant_id,
            kind=EventKind.MODEL_CALL,
            tags=["acquisition-sweep", "simulated", "public-api"],
            risk=RiskMetadata(
                composite_score=0,
                pii_categories=["contact"],
                data_residency_source=self.target.home_region if self.target.home_region in EU_COUNTRIES else "DE",
                data_residency_destination=dest,
                adequacy_decision=dest in ADEQUATE or dest in EU_COUNTRIES,
                standard_contractual_clauses=False,
                human_oversight=not api_like,
                model_risk_class="high" if api_like else "limited",
                annex_iii_use_case="creditworthiness" if api_like else None,
                automated_decision=api_like,
                audit_logging_enabled=False,
                purpose="customer_support",
            ),
            model_call=ModelCallPayload(
                model_id=f"{self.target.tenant_id}-prod-llm",
                provider="vendor-us",
                prompt_tokens=800,
                completion_tokens=220,
                tools_enabled=["retrieval"],
                user_facing=True,
                disclosed_as_ai=False,
            ),
            raw_context={
                "collection_mode": "simulated_posture_model",
                "target_host": self.target.host,
                "surface": "public_api_hypothesis",
            },
        )

    def _eu_us_pipeline(self) -> TelemetryEvent:
        source = self.target.home_region if self.target.home_region in EU_COUNTRIES else "DE"
        return TelemetryEvent(
            source_system=f"{self.target.host}:data-mesh",
            tenant_id=self.target.tenant_id,
            kind=EventKind.CROSS_BORDER_PIPELINE,
            tags=["acquisition-sweep", "simulated", "chapter-v"],
            risk=RiskMetadata(
                composite_score=0,
                pii_categories=["email", "national_id", "health_condition"],
                special_category_data=True,
                data_residency_source=source,
                data_residency_destination="US",
                adequacy_decision=False,
                standard_contractual_clauses=False,
                encryption_in_transit=False,
                encryption_at_rest=True,
                lawful_basis=None,
                purpose="analytics",
            ),
            pipeline=CrossBorderPipelinePayload(
                pipeline_id=f"acq-{self.target.tenant_id}",
                dataset_name="customer_export",
                record_count=125000,
                processor="external-us-region",
                controller=f"{source}-legal-entity",
                transfer_mechanism="none",
                fields=["email", "national_id", "health_condition"],
                masked_fields=[],
            ),
            agent=None,
            raw_context={
                "collection_mode": "simulated_posture_model",
                "target_host": self.target.host,
                "surface": "cross_border_hypothesis",
            },
        )
