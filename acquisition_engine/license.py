from __future__ import annotations

import hashlib
import hmac
import os
from base64 import b64decode, b64encode

from aegis_core.models import SealedPatchBundle


class LicenseEnvelope:
    """Authenticated license lock for same-day remediation artifacts.

    Uses PBKDF2-HMAC-SHA256 to derive an encryption key and MAC key, then a
    SHA-256 counter stream with HMAC-SHA256 over ciphertext. Wrong licenses
    fail closed on MAC verification.
    """

    iterations = 200_000

    def issue_license(self, report_id: str, tenant_id: str) -> str:
        material = os.urandom(18).hex()
        slug = tenant_id.replace("_", "-")[:24]
        return f"AEGIS-ENT-{slug}-{report_id[-8:]}-{material}"

    def fingerprint(self, license_key: str) -> str:
        return hashlib.sha256(license_key.encode("utf-8")).hexdigest()

    def lock(self, plaintext: bytes, license_key: str, report_id: str) -> SealedPatchBundle:
        salt = os.urandom(16)
        nonce = os.urandom(16)
        enc_key, mac_key = self._keys(license_key, salt)
        ciphertext = self._xor_stream(plaintext, enc_key, nonce)
        mac = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).digest()
        return SealedPatchBundle(
            report_id=report_id,
            iterations=self.iterations,
            salt_b64=b64encode(salt).decode("ascii"),
            nonce_b64=b64encode(nonce).decode("ascii"),
            ciphertext_b64=b64encode(ciphertext).decode("ascii"),
            mac_b64=b64encode(mac).decode("ascii"),
            license_fingerprint=self.fingerprint(license_key),
            locked=True,
        )

    def unlock(self, bundle: SealedPatchBundle, license_key: str) -> bytes:
        if self.fingerprint(license_key) != bundle.license_fingerprint:
            raise PermissionError("enterprise license does not match sealed bundle")
        salt = b64decode(bundle.salt_b64)
        nonce = b64decode(bundle.nonce_b64)
        ciphertext = b64decode(bundle.ciphertext_b64)
        mac = b64decode(bundle.mac_b64)
        enc_key, mac_key = self._keys(license_key, salt)
        expected = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, mac):
            raise PermissionError("sealed patch MAC check failed")
        return self._xor_stream(ciphertext, enc_key, nonce)

    def _keys(self, license_key: str, salt: bytes) -> tuple[bytes, bytes]:
        material = hashlib.pbkdf2_hmac(
            "sha256",
            license_key.encode("utf-8"),
            salt,
            self.iterations,
            dklen=64,
        )
        return material[:32], material[32:]

    def _xor_stream(self, data: bytes, key: bytes, nonce: bytes) -> bytes:
        out = bytearray(len(data))
        counter = 0
        offset = 0
        while offset < len(data):
            block = hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
            take = min(len(block), len(data) - offset)
            for i in range(take):
                out[offset + i] = data[offset + i] ^ block[i]
            offset += take
            counter += 1
        return bytes(out)
