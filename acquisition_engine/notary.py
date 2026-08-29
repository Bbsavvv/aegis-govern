from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from aegis_core.config import Settings, get_settings
from aegis_core.models import HashLink, IntegritySeal, PolicyViolation, utcnow


def canonical_dumps(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ProofNotary:
    """Builds an append-only SHA-256 hash chain and HMAC-SHA256 platform seal."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def seal(
        self,
        *,
        report_id: str,
        target_host: str,
        findings: list[PolicyViolation],
        extra: dict[str, Any],
    ) -> IntegritySeal:
        genesis = "0" * 64
        previous = genesis
        chain: list[HashLink] = []
        for index, finding in enumerate(findings):
            digest = sha256_hex(canonical_dumps(finding.model_dump(mode="json")))
            previous = sha256_hex(f"{previous}:{digest}".encode("utf-8"))
            chain.append(
                HashLink(
                    sequence=index,
                    record_id=finding.violation_id,
                    record_digest=digest,
                    chain_digest=previous,
                )
            )
        body = {
            "report_id": report_id,
            "issued_at": utcnow().isoformat(),
            "target_host": target_host,
            "finding_ids": [f.violation_id for f in findings],
            "merkle_root": previous,
            **extra,
        }
        canonical_digest = sha256_hex(canonical_dumps(body))
        signature = hmac.new(
            self.settings.signing_key.encode("utf-8"),
            f"{previous}:{canonical_digest}:{report_id}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return IntegritySeal(
            merkle_root=previous,
            chain=chain,
            signature=signature,
            canonical_digest=canonical_digest,
        )

    def verify(self, report_id: str, findings: list[PolicyViolation], seal: IntegritySeal) -> bool:
        previous = "0" * 64
        if len(findings) != len(seal.chain):
            return False
        for finding, link in zip(findings, seal.chain):
            digest = sha256_hex(canonical_dumps(finding.model_dump(mode="json")))
            if digest != link.record_digest or finding.violation_id != link.record_id:
                return False
            previous = sha256_hex(f"{previous}:{digest}".encode("utf-8"))
            if previous != link.chain_digest:
                return False
        if previous != seal.merkle_root:
            return False
        expected = hmac.new(
            self.settings.signing_key.encode("utf-8"),
            f"{seal.merkle_root}:{seal.canonical_digest}:{report_id}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, seal.signature)

    def inspect(self, report_id: str, findings: list[PolicyViolation], seal: IntegritySeal) -> dict:
        checks = {
            "finding_count_matches_chain": len(findings) == len(seal.chain),
            "record_digests": True,
            "chain_linkage": True,
            "merkle_root": True,
            "hmac_signature": True,
        }
        previous = "0" * 64
        if not checks["finding_count_matches_chain"]:
            checks["record_digests"] = False
            checks["chain_linkage"] = False
            checks["merkle_root"] = False
        else:
            for finding, link in zip(findings, seal.chain):
                digest = sha256_hex(canonical_dumps(finding.model_dump(mode="json")))
                if digest != link.record_digest or finding.violation_id != link.record_id:
                    checks["record_digests"] = False
                previous = sha256_hex(f"{previous}:{digest}".encode("utf-8"))
                if previous != link.chain_digest:
                    checks["chain_linkage"] = False
            if previous != seal.merkle_root:
                checks["merkle_root"] = False
        expected = hmac.new(
            self.settings.signing_key.encode("utf-8"),
            f"{seal.merkle_root}:{seal.canonical_digest}:{report_id}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        checks["hmac_signature"] = hmac.compare_digest(expected, seal.signature)
        return {
            "report_id": report_id,
            "valid": all(checks.values()),
            "algorithm": seal.algorithm,
            "hash_algorithm": seal.hash_algorithm,
            "key_id": seal.key_id,
            "merkle_root": seal.merkle_root,
            "signature": seal.signature,
            "canonical_digest": seal.canonical_digest,
            "chain_length": len(seal.chain),
            "finding_count": len(findings),
            "checks": checks,
        }
