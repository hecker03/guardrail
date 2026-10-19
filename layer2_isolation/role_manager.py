from typing import List, Tuple
from .config import IsolationConfig, DEFAULT_CONFIG
from .models import RoleBlock


class RoleManager:
    """Validate role identity, ordering, count, and assigned privilege."""

    def __init__(self, config: IsolationConfig = DEFAULT_CONFIG):
        self.cfg = config

    def validate(self, blocks: List[RoleBlock]) -> Tuple[bool, List[str]]:
        warnings: List[str] = []
        if not blocks:
            return False, ["no_blocks"]
        if len(blocks) > self.cfg.MAX_ROLE_BLOCKS:
            return False, ["too_many_role_blocks"]

        for block in blocks:
            if block.role not in self.cfg.ALLOWED_ROLES:
                if self.cfg.REJECT_ON_UNKNOWN_ROLE:
                    return False, [f"unknown_role:{block.role}"]
                warnings.append(f"unknown_role:{block.role}")
                continue
            expected = self.privilege_of(block.role)
            if block.privilege != expected:
                return False, [f"invalid_privilege:{block.role}"]

        system_blocks = [b for b in blocks if b.role == "system"]
        if len(system_blocks) != 1:
            return False, ["missing_system_prompt" if not system_blocks else "multiple_system_prompts"]
        if blocks[0].role != "system":
            return False, ["system_must_be_first"]
        if not system_blocks[0].content:
            return False, ["missing_system_prompt"]
        if len(system_blocks[0].content) > self.cfg.MAX_SYSTEM_PROMPT_LENGTH:
            return False, ["system_prompt_too_long"]

        for block in blocks:
            if block.role in ("user", "tool", "retrieved_context") and self._claims_system_role(block.content):
                warnings.append(f"privilege_escalation:{block.role}")
        return True, warnings

    @staticmethod
    def _claims_system_role(content: str) -> bool:
        lowered = content.lower()
        markers = (
            "you are now", "new system prompt", "override instructions",
            "ignore previous", "system:", "### system",
        )
        return any(marker in lowered for marker in markers)

    def privilege_of(self, role: str) -> int:
        return self.cfg.ROLE_PRIVILEGE.get(role, 0)

    def is_higher_privilege(self, role_a: str, role_b: str) -> bool:
        return self.privilege_of(role_a) > self.privilege_of(role_b)
