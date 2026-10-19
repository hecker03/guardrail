from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from typing import Any, Dict, Optional, Tuple
from .config import IsolationConfig, DEFAULT_CONFIG


class HMACVerifier:
    """Canonical HMAC-SHA256 signing with bounded in-process replay detection.

    The in-memory nonce store is correct for a single process. A shared atomic
    store (for example Redis SET NX with TTL) is still required for multi-worker
    or multi-instance deployment.
    """

    def __init__(self, secret_key: Optional[bytes] = None, config: IsolationConfig = DEFAULT_CONFIG):
        self.cfg = config
        self.secret_key = secret_key or secrets.token_bytes(self.cfg.HMAC_KEY_BYTES)
        if len(self.secret_key) < self.cfg.HMAC_KEY_BYTES:
            raise ValueError(f"HMAC key must be at least {self.cfg.HMAC_KEY_BYTES} bytes")
        self._used_nonces: Dict[str, int] = {}
        self._lock = threading.Lock()

    def rotate_key(self) -> bytes:
        self.secret_key = secrets.token_bytes(self.cfg.HMAC_KEY_BYTES)
        with self._lock:
            self._used_nonces.clear()
        return self.secret_key

    def sign_payload(self, payload: Dict[str, Any]) -> Tuple[str, str, int, str]:
        nonce = secrets.token_hex(self.cfg.HMAC_NONCE_BYTES)
        timestamp = int(time.time())
        message = self._canonical_payload(payload, nonce, timestamp)
        return self._mac(message), nonce, timestamp, message

    def verify_payload(self, payload: Dict[str, Any], signature: str, nonce: str, timestamp: int) -> Tuple[bool, str]:
        now = int(time.time())
        if not isinstance(timestamp, int) or abs(now - timestamp) > self.cfg.HMAC_TIMESTAMP_TOLERANCE_SEC:
            return False, "expired"
        if not self._valid_hex(signature, self.cfg.HMAC_SIGNATURE_LENGTH):
            return False, "invalid_format"
        if not self._valid_hex(nonce, self.cfg.HMAC_NONCE_BYTES * 2):
            return False, "invalid_format"

        message = self._canonical_payload(payload, nonce, timestamp)
        if not hmac.compare_digest(self._mac(message), signature.lower()):
            return False, "mismatch"

        # Check and consume atomically only after cryptographic verification.
        with self._lock:
            self._gc_nonces(now)
            if self._used_nonces.get(nonce, 0) > now:
                return False, "nonce_replay"
            self._used_nonces[nonce] = now + self.cfg.HMAC_TIMESTAMP_TOLERANCE_SEC
        return True, "verified"

    # Backward-compatible prompt-only helpers. ContextIsolator uses payload APIs.
    def sign(self, system_prompt: str) -> Tuple[str, str, int, str]:
        return self.sign_payload({"system_prompt": system_prompt})

    def verify(self, system_prompt: str, signature: str, nonce: str, timestamp: int) -> Tuple[bool, str]:
        return self.verify_payload({"system_prompt": system_prompt}, signature, nonce, timestamp)

    @staticmethod
    def hash_prompt(prompt: str) -> str:
        return hashlib.sha256(prompt.encode("utf-8")).hexdigest()

    @staticmethod
    def hash_payload(payload: Dict[str, Any]) -> str:
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _canonical_payload(payload: Dict[str, Any], nonce: str, timestamp: int) -> str:
        envelope = {"nonce": nonce, "payload": payload, "timestamp": timestamp}
        return json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def _mac(self, message: str) -> str:
        return hmac.new(self.secret_key, message.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def _valid_hex(value: str, length: int) -> bool:
        if not isinstance(value, str) or len(value) != length:
            return False
        try:
            int(value, 16)
            return True
        except ValueError:
            return False

    def _gc_nonces(self, now: Optional[int] = None) -> None:
        now = int(time.time()) if now is None else now
        for nonce in [n for n, expiry in self._used_nonces.items() if expiry <= now]:
            del self._used_nonces[nonce]
