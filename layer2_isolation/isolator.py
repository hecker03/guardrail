import time
import uuid
from typing import List, Optional
from .config import IsolationConfig, DEFAULT_CONFIG
from .models import IsolationResult, IsolationAction, IntegrityStatus, RoleBlock
from .hmac_verifier import HMACVerifier
from .delimiter import XMLDelimiter
from .role_manager import RoleManager


class ContextIsolator:
    """Layer 2: strict role boundaries plus canonical envelope integrity."""

    def __init__(self, config: IsolationConfig = DEFAULT_CONFIG, secret_key: Optional[bytes] = None):
        self.cfg = config
        self.hmac = HMACVerifier(secret_key=secret_key, config=config)
        self.delimiter = XMLDelimiter(config)
        self.roles = RoleManager(config)

    def isolate(
        self,
        blocks: List[RoleBlock],
        inbound_signature: Optional[str] = None,
        inbound_nonce: Optional[str] = None,
        inbound_timestamp: Optional[int] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        capability_scope: Optional[List[str]] = None,
        policy_version: str = "phase1-v1",
    ) -> IsolationResult:
        start = time.perf_counter()
        request_id = request_id or str(uuid.uuid4())
        session_id = session_id or request_id
        capability_scope = sorted(set(capability_scope or []))

        valid, warnings = self.roles.validate(blocks)
        if not valid:
            return self._reject("; ".join(warnings), warnings, start)

        system_prompt = blocks[0].content
        payload = self._envelope_payload(
            blocks, request_id, session_id, capability_scope, policy_version
        )

        integrity = IntegrityStatus.GENERATED
        inbound_fields = (inbound_signature, inbound_nonce, inbound_timestamp)
        if any(value is not None for value in inbound_fields):
            if not all(value is not None for value in inbound_fields):
                return self._reject(
                    "hmac_incomplete", warnings, start, IntegrityStatus.INVALID_FORMAT
                )
            ok, status = self.hmac.verify_payload(
                payload, inbound_signature or "", inbound_nonce or "", inbound_timestamp or 0
            )
            if not ok:
                mapped = self._map_status(status)
                if self.cfg.REJECT_ON_HMAC_MISMATCH:
                    return self._reject(f"hmac_{status}", warnings, start, mapped)
                integrity = mapped
            else:
                integrity = IntegrityStatus.VERIFIED

        signature, nonce, timestamp, _ = self.hmac.sign_payload(payload)
        prompt_hash = self.hmac.hash_prompt(system_prompt)
        envelope_hash = self.hmac.hash_payload(payload)

        boundaries = 0
        for block in blocks:
            if self.delimiter.contains_injection(block.content):
                warnings.append(f"delimiter_injection:{block.role}")
                boundaries += 1

        isolated_prompt = self.delimiter.build(blocks)
        total_tokens = 0
        for block in blocks:
            block.token_estimate = self._estimate_tokens(block.content)
            total_tokens += block.token_estimate

        action = IsolationAction.ISOLATED if boundaries or warnings else IsolationAction.PASS
        return IsolationResult(
            isolated_prompt=isolated_prompt,
            action=action,
            integrity_status=integrity,
            system_prompt_hash=prompt_hash,
            envelope_hash=envelope_hash,
            signature=signature,
            nonce=nonce,
            timestamp=timestamp,
            request_id=request_id,
            session_id=session_id,
            policy_version=policy_version,
            capability_scope=capability_scope,
            role_blocks=blocks,
            total_tokens_estimate=total_tokens,
            boundaries_enforced=boundaries,
            warnings=warnings,
            processing_time_ms=round((time.perf_counter() - start) * 1000, 3),
        )

    @staticmethod
    def _envelope_payload(blocks, request_id, session_id, capability_scope, policy_version):
        return {
            "envelope_version": "1.0",
            "request_id": request_id,
            "session_id": session_id,
            "policy_version": policy_version,
            "capability_scope": capability_scope,
            "blocks": [
                {
                    "role": block.role,
                    "content": block.content,
                    "privilege": block.privilege,
                    "source": block.source,
                    "trust_tier": block.trust_tier,
                }
                for block in blocks
            ],
        }

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        return max(1, len(text) // 4) if text else 0

    @staticmethod
    def _map_status(reason: str) -> IntegrityStatus:
        return {
            "mismatch": IntegrityStatus.MISMATCH,
            "expired": IntegrityStatus.EXPIRED,
            "invalid_format": IntegrityStatus.INVALID_FORMAT,
            "nonce_replay": IntegrityStatus.REPLAYED,
        }.get(reason, IntegrityStatus.INVALID_FORMAT)

    def _reject(self, reason, warnings, start, integrity=IntegrityStatus.MISSING):
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
            processing_time_ms=round((time.perf_counter() - start) * 1000, 3),
        )

    def quick_isolate(
        self,
        system_prompt: str,
        user_message: str,
        assistant_message: Optional[str] = None,
        retrieved_context: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        capability_scope: Optional[List[str]] = None,
    ) -> IsolationResult:
        blocks: List[RoleBlock] = [RoleBlock(
            role="system", content=system_prompt,
            privilege=self.roles.privilege_of("system"),
            source="application_config", trust_tier="trusted",
        )]
        if retrieved_context:
            blocks.append(RoleBlock(
                role="retrieved_context", content=retrieved_context,
                privilege=self.roles.privilege_of("retrieved_context"),
                source="retrieval", trust_tier="untrusted",
            ))
        if assistant_message:
            blocks.append(RoleBlock(
                role="assistant", content=assistant_message,
                privilege=self.roles.privilege_of("assistant"),
                source="model", trust_tier="untrusted",
            ))
        blocks.append(RoleBlock(
            role="user", content=user_message,
            privilege=self.roles.privilege_of("user"),
            source="user", trust_tier="untrusted",
        ))
        return self.isolate(
            blocks, request_id=request_id, session_id=session_id,
            capability_scope=capability_scope,
        )
