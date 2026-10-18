# guardrail/layer2_isolation/hmac_verifier.py

import hmac
import hashlib
import os
import time
import secrets
from typing import Tuple, Optional
from .config import IsolationConfig, DEFAULT_CONFIG


class HMACVerifier:
    """
    Cryptographic integrity layer for system prompts and request payloads.

    Responsibilities:
      - Generate per-request nonce + timestamp
      - Compute HMAC-SHA256 over (system_prompt || nonce || timestamp)
      - Verify incoming signatures against expected values
      - Detect replay attacks via timestamp window
    """

    def __init__(
        self,
        secret_key: Optional[bytes] = None,
        config: IsolationConfig = DEFAULT_CONFIG,
    ):
        self.cfg = config
        self.secret_key = secret_key or self._generate_key()
        self._used_nonces: dict = {}   # nonce -> expiry (in-memory; use Redis in prod)

    # ------------------------------------------------------------------ #
    # Key management
    # ------------------------------------------------------------------ #
    def _generate_key(self) -> bytes:
        """Generate a cryptographically secure 256-bit key."""
        return secrets.token_bytes(self.cfg.HMAC_KEY_BYTES)

    def rotate_key(self) -> bytes:
        """Rotate the HMAC key (for key-compromise recovery)."""
        self.secret_key = self._generate_key()
        return self.secret_key

    # ------------------------------------------------------------------ #
    # Signing
    # ------------------------------------------------------------------ #
    def sign(self, system_prompt: str) -> Tuple[str, str, int, str]:
        """
        Sign a system prompt.

        Returns:
            (signature_hex, nonce_hex, timestamp, canonical_message)
        """
        nonce = secrets.token_hex(self.cfg.HMAC_NONCE_BYTES)
        timestamp = int(time.time())
        message = self._canonical_message(system_prompt, nonce, timestamp)
        signature = hmac.new(
            self.secret_key,
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return signature, nonce, timestamp, message

    # ------------------------------------------------------------------ #
    # Verification
    # ------------------------------------------------------------------ #
    def verify(
        self,
        system_prompt: str,
        signature: str,
        nonce: str,
        timestamp: int,
    ) -> Tuple[bool, str]:
        """
        Verify an HMAC signature.

        Returns:
            (is_valid, status_reason)
        """
        # ---- 1) Timestamp window ----
        now = int(time.time())
        if abs(now - timestamp) > self.cfg.HMAC_TIMESTAMP_TOLERANCE_SEC:
            return False, "expired"

        # ---- 2) Nonce replay check ----
        if nonce in self._used_nonces and self._used_nonces[nonce] > now:
            return False, "nonce_replay"

        # ---- 3) Format validation ----
        if not signature or len(signature) != self.cfg.HMAC_SIGNATURE_LENGTH:
            return False, "invalid_format"

        # ---- 4) Recompute + constant-time compare ----
        message = self._canonical_message(system_prompt, nonce, timestamp)
        expected = hmac.new(
            self.secret_key,
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(expected, signature):
            return False, "mismatch"

        # Mark nonce as used
        self._used_nonces[nonce] = timestamp + self.cfg.HMAC_TIMESTAMP_TOLERANCE_SEC
        return True, "verified"

    # ------------------------------------------------------------------ #
    # Prompt hashing (for audit logs)
    # ------------------------------------------------------------------ #
    def hash_prompt(self, prompt: str) -> str:
        """Deterministic prompt hash for audit logging."""
        return hashlib.sha256(prompt.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    @staticmethod
    def _canonical_message(prompt: str, nonce: str, timestamp: int) -> str:
        """Canonical string used for HMAC computation."""
        return f"{prompt}|{nonce}|{timestamp}"

    def _gc_nonces(self) -> None:
        """Garbage-collect expired nonces."""
        now = int(time.time())
        expired = [n for n, exp in self._used_nonces.items() if exp < now]
        for n in expired:
            del self._used_nonces[n]