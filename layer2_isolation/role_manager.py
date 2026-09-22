# guardrail/layer2_isolation/role_manager.py

from typing import List, Tuple
from .config import IsolationConfig, DEFAULT_CONFIG
from .models import RoleBlock


class RoleManager:
    """
    Enforces role-based access rules for the isolated prompt.

    - Validates role names against the allowlist
    - Enforces privilege ordering (system > assistant > tool > user)
    - Flags privilege-escalation attempts
    """

    def __init__(self, config: IsolationConfig = DEFAULT_CONFIG):
        self.cfg = config

    # ------------------------------------------------------------------ #
    # Validation
    # ------------------------------------------------------------------ #
    def validate(self, blocks: List[RoleBlock]) -> Tuple[bool, List[str]]:
        """
        Validate a list of role blocks.

        Returns:
            (is_valid, warnings)
        """
        warnings: List[str] = []

        if not blocks:
            return False, ["no_blocks"]

        # ---- 1) Role allowlist ----
        for b in blocks:
            if b.role not in self.cfg.ALLOWED_ROLES:
                if self.cfg.REJECT_ON_UNKNOWN_ROLE:
                    return False, [f"unknown_role:{b.role}"]
                warnings.append(f"unknown_role:{b.role}")

        # ---- 2) System prompt presence ----
        if not any(b.role == "system" for b in blocks):
            warnings.append("missing_system_prompt")

        # ---- 3) System prompt length ----
        for b in blocks:
            if (
                b.role == "system"
                and len(b.content) > self.cfg.MAX_SYSTEM_PROMPT_LENGTH
            ):
                return False, ["system_prompt_too_long"]

        # ---- 4) Privilege ordering ----
        # System must appear before user content
        roles_in_order = [b.role for b in blocks]
        if "system" in roles_in_order and "user" in roles_in_order:
            if roles_in_order.index("system") > roles_in_order.index("user"):
                warnings.append("system_after_user")

        # ---- 5) Privilege escalation ----
        # User/tool/retrieved content attempting to claim system privileges
        for b in blocks:
            if b.role in ("user", "tool", "retrieved_context"):
                if self._claims_system_role(b.content):
                    warnings.append(f"privilege_escalation:{b.role}")

        return True, warnings

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _claims_system_role(content: str) -> bool:
        """Detect attempts to impersonate system instructions."""
        lowered = content.lower()
        markers = (
            "you are now",
            "new system prompt",
            "override instructions",
            "ignore previous",
            "system:",
            "### system",
        )
        return any(m in lowered for m in markers)

    def privilege_of(self, role: str) -> int:
        return self.cfg.ROLE_PRIVILEGE.get(role, 0)

    def is_higher_privilege(self, role_a: str, role_b: str) -> bool:
        return self.privilege_of(role_a) > self.privilege_of(role_b)