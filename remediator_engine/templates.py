from __future__ import annotations

import difflib
from textwrap import dedent

from aegis_core.models import FileChange, PolicyViolation, TelemetryEvent


def unified_diff(path: str, before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )


def create_file(path: str, content: str, language: str) -> FileChange:
    normalized = content if content.endswith("\n") else content + "\n"
    return FileChange(
        path=path,
        action="create",
        content=normalized,
        patch=unified_diff(path, "", normalized),
        language=language,
    )


def scc_env_fix(event: TelemetryEvent, violation: PolicyViolation) -> FileChange:
    dest = event.risk.data_residency_destination
    content = dedent(
        f"""
        GDPR_TRANSFER_MECHANISM=scc
        GDPR_SCC_MODULE=eu_commission_2021_914
        DATA_RESIDENCY_SOURCE={event.risk.data_residency_source}
        DATA_RESIDENCY_ALLOWED_REGIONS={event.risk.data_residency_source},EU
        BLOCK_UNAPPROVED_TRANSFER_TO={dest}
        AEGIS_VIOLATION_ID={violation.violation_id}
        """
    ).strip()
    return create_file(".env.compliance", content, "dotenv")


def masking_config(event: TelemetryEvent, violation: PolicyViolation) -> FileChange:
    fields = event.pipeline.fields if event.pipeline else event.risk.pii_categories
    masked = event.pipeline.masked_fields if event.pipeline else []
    required = sorted(set(fields) | {"national_id", "health_condition", "card_pan", "email"})
    content = dedent(
        f"""
        version: 1
        tenant: {event.tenant_id}
        violation: {violation.violation_id}
        dataset: {event.pipeline.dataset_name if event.pipeline else "model_io"}
        masking:
          default_strategy: tokenize
          fields:
        """
    ).lstrip()
    for field in required:
        strategy = "hash" if field in {"national_id", "card_pan"} else "tokenize"
        content += f"            - name: {field}\n              strategy: {strategy}\n              already_masked: {field in masked}\n"
    return create_file("config/data_masking.yaml", content, "yaml")


def human_oversight_gate(event: TelemetryEvent, violation: PolicyViolation) -> FileChange:
    content = dedent(
        f'''
        from functools import wraps
        from typing import Callable

        HIGH_RISK_ACTIONS = {{"credit_scoring", "creditworthiness", "kyc", "mutate_production"}}


        def require_human_oversight(action: str) -> Callable:
            """Block high-risk AI or agent execution until a human approval token is present."""

            def decorator(fn: Callable) -> Callable:
                @wraps(fn)
                def wrapped(*args, **kwargs):
                    approval = kwargs.get("approval_token") or kwargs.get("approved_by")
                    if action in HIGH_RISK_ACTIONS and not approval:
                        raise PermissionError(
                            f"Aegis gate: {{action}} requires human oversight "
                            f"(violation {violation.violation_id}, tenant {event.tenant_id})."
                        )
                    return fn(*args, **kwargs)

                return wrapped

            return decorator
        '''
    ).strip()
    return create_file("aegis_runtime/human_oversight.py", content, "python")


def transparency_middleware(event: TelemetryEvent, violation: PolicyViolation) -> FileChange:
    model_id = event.model_call.model_id if event.model_call else "unknown-model"
    content = dedent(
        f'''
        from fastapi import Request
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.responses import Response

        DISCLOSURE = "You are interacting with an AI system ({model_id}). A human is available on request."


        class AiTransparencyMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request: Request, call_next) -> Response:
                response = await call_next(request)
                response.headers["X-AI-Disclosure"] = "true"
                response.headers["X-Aegis-Violation"] = "{violation.violation_id}"
                if request.url.path.startswith("/v1/chat"):
                    response.headers["X-AI-Notice"] = DISCLOSURE
                return response
        '''
    ).strip()
    return create_file("app/middleware/ai_transparency.py", content, "python")


def disable_prohibited_practice(event: TelemetryEvent, violation: PolicyViolation) -> FileChange:
    content = dedent(
        f"""
        {{
          "feature_flags": {{
            "social_scoring": false,
            "real_time_remote_biometric_id": false,
            "prohibited_by": "{violation.citation}",
            "violation_id": "{violation.violation_id}",
            "enforced": true
          }}
        }}
        """
    ).strip()
    return create_file("config/ai_act_prohibited_flags.json", content, "json")


def encryption_and_audit(event: TelemetryEvent, violation: PolicyViolation) -> FileChange:
    content = dedent(
        f"""
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: aegis-security-baseline
          labels:
            tenant: {event.tenant_id}
            violation: {violation.violation_id}
        data:
          ENCRYPT_IN_TRANSIT: "true"
          ENCRYPT_AT_REST: "true"
          TLS_MIN_VERSION: "1.3"
          KMS_KEY_ALIAS: "alias/aegis-{event.tenant_id}"
          AUDIT_LOG_DRAIN: "immutable-s3"
          AUDIT_HASH_CHAIN: "true"
          MFA_REQUIRED_FOR_AGENTS: "true"
          PCI_MASK_PAN: "true"
        """
    ).strip()
    return create_file("deploy/aegis-security-baseline.yaml", content, "yaml")


def change_control_policy(event: TelemetryEvent, violation: PolicyViolation) -> FileChange:
    agent_id = event.agent.agent_id if event.agent else "unknown-agent"
    content = dedent(
        f"""
        package aegis.change_control

        default allow := false

        dual_control_actions := {{"mutate_production", "transfer_funds", "patch_repo"}}

        allow if {{
          not dual_control_actions[input.action]
        }}

        allow if {{
          dual_control_actions[input.action]
          input.approved_by
          input.mfa == true
        }}

        # violation {violation.violation_id} agent {agent_id}
        """
    ).strip()
    return create_file("policy/change_control.rego", content, "rego")


RULE_FIXES = {
    "eu-ai-act-art-5-social-scoring": (disable_prohibited_practice,),
    "eu-ai-act-art-5-rbi": (disable_prohibited_practice,),
    "eu-ai-act-art-14-oversight": (human_oversight_gate, change_control_policy),
    "eu-ai-act-art-50-transparency": (transparency_middleware,),
    "eu-ai-act-art-12-logging": (encryption_and_audit,),
    "gdpr-art-44-transfer": (scc_env_fix, masking_config),
    "gdpr-art-9-special-category": (masking_config, scc_env_fix),
    "gdpr-art-25-data-minimisation": (masking_config,),
    "gdpr-art-32-security": (encryption_and_audit,),
    "pci-dss-3-cardholder": (masking_config, encryption_and_audit),
    "dora-ict-access-mfa": (encryption_and_audit, change_control_policy),
    "sox-change-control": (human_oversight_gate, change_control_policy),
    "glba-audit-trail": (encryption_and_audit,),
}
