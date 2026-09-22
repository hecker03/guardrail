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
         re.compile(r"\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)", re.I),
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
         re.compile(r"\b(send|email|post|upload|exfiltrate)\b.*\b(api[_ ]?key|token|password|secret|credential)", re.I),
         0.95),
    ]

    def scan(self, text: str) -> Tuple[List[str], float]:
        """
        Returns (matched_pattern_names, max_threat_score)
        """
        if not text:
            return [], 0.0

        matched: List[str] = []
        max_score = 0.0

        for name, regex, score in self.PATTERNS:
            if regex.search(text):
                matched.append(name)
                max_score = max(max_score, score)

        return matched, max_score