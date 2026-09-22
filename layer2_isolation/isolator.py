# guardrail/layer2_isolation/isolator.py

import time
from typing import List, Optional, Tuple
from .config import IsolationConfig, DEFAULT_CONFIG
from .models import (
    IsolationResult, IsolationAction, IntegrityStatus, RoleBlock,
)
from .hmac_verifier import HMACVerifier
from .delimiter import XMLDelimiter
from .role_manager import RoleManager


class ContextIsolator:
    """
    Layer 2 — GuardRail Context Isolation.

    Pipeline:
        1. Validate role blocks
        2. Sign the system prompt via HMAC-SHA256
        3. Wrap each block in XML role delimiters
        4. Verify inbound signature (if provided)
        5. Detect replay / tampering / privilege escalation
    """

    def __init__(
        self,
        config: IsolationConfig = DEFAULT_CONFIG,
        secret_key: Optional[bytes] = None,
    ):
        self.cfg = config
        self.hmac = HMACVerifier(secret_key=secret_key, config=config)
        self.delimiter = XMLDelimiter(config)
        self.roles = RoleManager(config)

    # ------------------------------------------------------------------ #
    # Primary API
    # ------------------------------------------------------------------ #
    def isolate(
        self,
        blocks: List[RoleBlock],
        inbound_signature: Optional[str] = None,
        inbound_nonce: Optional[str] = None,
        inbound_timestamp: Optional[int] = None,
    ) -> IsolationResult:
        """
        Isolate a set of role blocks into a signed, delimited prompt.

        Args:
            blocks: ordered list of RoleBlock (system first, then user, etc.)
            inbound_signature/nonce/timestamp: if verifying a pre-signed prompt
        """
        start = time.perf_counter()

        # ---- 1) Validate roles ----
        valid, warnings = self.roles.validate(blocks)
        if not valid:
            return self._reject(
                reason="; ".join(warnings),
                warnings=warnings,
                start=start,
            )

        # ---- 2) Locate system prompt ----
        system_prompt = next(
            (b.content for b in blocks if b.role == "system"), ""
        )
        if not system_prompt:
            return self._reject(
                reason="missing_system_prompt",
                warnings=warnings,
                start=start,
            )

        # ---- 3) Verify inbound signature (optional) ----
        integrity = IntegrityStatus.VERIFIED
        if inbound_signature is not None:
            ok, status = self.hmac.verify(
                system_prompt=system_prompt,
                signature=inbound_signature,
                nonce=inbound_nonce or "",
                timestamp=inbound_timestamp or 0,
            )
            if not ok:
                integrity = self._map_status(status)
                if self.cfg.REJECT_ON_HMAC_MISMATCH:
                    return self._reject(
                        reason=f"hmac_{status}",
                        warnings=warnings,
                        start=start,
                        integrity=integrity,
                    )

        # ---- 4) Sign system prompt ----
        signature, nonce, timestamp, _ = self.hmac.sign(system_prompt)
        prompt_hash = self.hmac.hash_prompt(system_prompt)

        # ---- 5) Build XML-delimited prompt ----
        boundaries = 0
        for b in blocks:
            if self.delimiter.contains_injection(b.content):
                warnings.append(f"delimiter_injection:{b.role}")
                boundaries += 1

        try:
            isolated_prompt = self.delimiter.build(blocks)
        except ValueError as e:
            return self._reject(
                reason=str(e),
                warnings=warnings,
                start=start,
            )

        # ---- 6) Token estimate ----
        total_tokens = sum(self._estimate_tokens(b.content) for b in blocks)
        for b in blocks:
            b.token_estimate = self._estimate_tokens(b.content)

        # ---- 7) Action decision ----
        action = (
            IsolationAction.ISOLATED
            if boundaries or warnings
            else IsolationAction.PASS
        )

        elapsed_ms = (time.perf_counter() - start) * 1000

        return IsolationResult(
            isolated_prompt=isolated_prompt,
            action=action,
            integrity_status=integrity,
            system_prompt_hash=prompt_hash,
            signature=signature,
            nonce=nonce,
            timestamp=timestamp,
            role_blocks=blocks,
            total_tokens_estimate=total_tokens,
            boundaries_enforced=boundaries,
            warnings=warnings,
            processing_time_ms=round(elapsed_ms, 3),
        )

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _estimate_tokens(text: str) -> int:
        """Rough token estimate (~4 chars/token)."""
        return max(1, len(text) // 4) if text else 0

    @staticmethod
    def _map_status(reason: str) -> IntegrityStatus:
        return {
            "mismatch": IntegrityStatus.MISMATCH,
            "expired": IntegrityStatus.EXPIRED,
            "invalid_format": IntegrityStatus.INVALID_FORMAT,
            "nonce_replay": IntegrityStatus.MISMATCH,
        }.get(reason, IntegrityStatus.INVALID_FORMAT)

    def _reject(
        self,
        reason: str,
        warnings: List[str],
        start: float,
        integrity: IntegrityStatus = IntegrityStatus.MISSING,
    ) -> IsolationResult:
        elapsed_ms = (time.perf_counter() - start) * 1000
        return IsolationResult(
            isolated_prompt="",
            action=IsolationAction.REJECTED,
            integrity_status=integrity,
            system_prompt_hash="",
            signature="",
            nonce="",
            timestamp=0,
            warnings=warnings,
            rejected_reason=reason,
            processing_time_ms=round(elapsed_ms, 3),
        )

    # ------------------------------------------------------------------ #
    # Convenience helpers
    # ------------------------------------------------------------------ #
    def quick_isolate(
        self,
        system_prompt: str,
        user_message: str,
        assistant_message: Optional[str] = None,
        retrieved_context: Optional[str] = None,
    ) -> IsolationResult:
        """Convenience wrapper for common 2–4 block prompts."""
        blocks: List[RoleBlock] = [
            RoleBlock(
                role="system",
                content=system_prompt,
                privilege=self.roles.privilege_of("system"),
            ),
        ]
        if retrieved_context:
            blocks.append(RoleBlock(
                role="retrieved_context",
                content=retrieved_context,
                privilege=self.roles.privilege_of("retrieved_context"),
            ))
        if assistant_message:
            blocks.append(RoleBlock(
                role="assistant",
                content=assistant_message,
                privilege=self.roles.privilege_of("assistant"),
            ))
        blocks.append(RoleBlock(
            role="user",
            content=user_message,
            privilege=self.roles.privilege_of("user"),
        ))
        return self.isolate(blocks)