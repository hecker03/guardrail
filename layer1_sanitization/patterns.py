# guardrail/layer1_sanitization/patterns.py

import re
from typing import List, Tuple


class PatternMatcher:
    """
    Regex-based detection of known prompt-injection signatures.
    Complements the ML classifier (Layer 4) with high-precision rules.
    """

    # (name, regex, threat_score)
    PATTERNS: List[Tuple[str, re.Pattern, float]] = [
        ("ignore_instructions",
        re.compile(
            r"(?:ignore|disregard|forget)\b\s+"
            r"(?:all\s+)?"
            r"(?:previous|prior|above)\s+"
            r"(?:instructions?|prompts?|rules?)\b",
            re.I,
        ),
        0.85),

        ("system_prompt_leak",
         re.compile(r"\b(reveal|show|print|output|repeat)\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?)", re.I),
         0.80),

        ("role_hijack",
         re.compile(r"\b(you\s+are\s+now|act\s+as|pretend\s+to\s+be|from\s+now\s+on)\b", re.I),
         0.70),

        ("dan_jailbreak",
         re.compile(r"\b(DAN|do\s+anything\s+now|jailbreak|developer\s+mode)\b", re.I),
         0.90),

        ("delimiter_injection",
         re.compile(r"(<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]|<\|system\|>)", re.I),
         0.85),

        ("xml_role_tag",
         re.compile(r"</?(system|assistant|user|tool)\s*>", re.I),
         0.75),

        ("base64_blob",
         re.compile(r"\b[A-Za-z0-9+/]{80,}={0,2}\b"),
         0.60),

        ("hex_escape",
         re.compile(r"(\\x[0-9a-fA-F]{2}){4,}"),
         0.55),

        ("override_safety",
         re.compile(r"\b(bypass|override|disable|turn\s+off)\s+(safety|security|filter|guardrail)", re.I),
         0.85),

        ("exfiltrate",
         re.compile(r"\b(send|email|post|upload|exfiltrate)\b.*\b(api[_ ]?key|token|password|secret|credential)", re.I | re.DOTALL),
         0.95),
    ]

    # Patterns evaluated against a lower-case ASCII-alphanumeric view.
# Gap limits are bounded to reduce accidental long-range matches.
    COMPACT_PATTERNS: List[Tuple[str, re.Pattern, float]] = [
        (
            "obfuscated_instruction_override",
            re.compile(
                r"(?:ignore|disregard|forget)"
                r"[a-z0-9]{0,40}"
                r"(?:previous|prior|above)"
                r"[a-z0-9]{0,16}"
                r"(?:instructions?|prompts?|rules?)",
                re.I,
            ),
            0.90,
        ),
        (
            "obfuscated_safety_override",
            re.compile(
                r"(?:bypass|override|disable|turnoff)"
                r"[a-z0-9]{0,32}"
                r"(?:safety|security|filter|guardrail)",
                re.I,
            ),
            0.88,
        ),
    ]

    def scan(self, text: str) -> Tuple[List[str], float]:
        if not text:
            return [], 0.0

        matched: List[str] = []
        max_score = 0.0

        # Normal visible-text patterns
        for name, regex, score in self.PATTERNS:
            if regex.search(text):
                matched.append(name)
                max_score = max(max_score, score)

        # Compact inspection-only view
        compact = re.sub(
            r"[^a-z0-9]+",
            "",
            text.casefold(),
        )

        for name, regex, score in self.COMPACT_PATTERNS:
            if regex.search(compact):
                if name not in matched:
                    matched.append(name)

                max_score = max(max_score, score)

        return matched, max_score