# guardrail/layer2_isolation/delimiter.py

import html
import re
from typing import List
from .config import IsolationConfig, DEFAULT_CONFIG
from .models import RoleBlock


class XMLDelimiter:
    """
    Enforces role separation using structured XML-like tags.
    Strips delimiter injection attempts and escapes dangerous characters.
    """

    def __init__(self, config: IsolationConfig = DEFAULT_CONFIG):
        self.cfg = config
        prefix = re.escape(self.cfg.ROLE_TAG_PREFIX)
        self.injection_pattern = re.compile(
            rf"</?{prefix}:[a-zA-Z0-9_\-]+(\s+[^>]*)?>",
            re.IGNORECASE,
        )

    def contains_injection(self, text: str) -> bool:
        """Check whether the given text contains any role delimiter tags."""
        if not text:
            return False
        return bool(self.injection_pattern.search(text))

    def clean_content(self, text: str) -> str:
        """Sanitize content by stripping injected role tags and escaping XML."""
        if not text:
            return ""
        content = text
        if self.cfg.STRIP_NESTED_ROLE_TAGS:
            content = self.injection_pattern.sub("", content)
        if self.cfg.ESCAPE_XML_CONTENT:
            content = html.escape(content, quote=False)
        return content

    def build(self, blocks: List[RoleBlock]) -> str:
        """Wrap each role block in XML delimiters and combine them into a prompt."""
        if not blocks:
            return ""

        parts = []
        prefix = self.cfg.ROLE_TAG_PREFIX
        for b in blocks:
            clean = self.clean_content(b.content)
            tag_open = f"<{prefix}:{b.role}>"
            tag_close = f"</{prefix}:{b.role}>"
            parts.append(f"{tag_open}\n{clean}\n{tag_close}")

        return "\n\n".join(parts)
