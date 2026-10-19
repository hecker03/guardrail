import ipaddress
import re
from typing import List
from .config import PII_PATTERNS
from .models import PIIMatch


class PIIDetector:
    """Deterministic PII/secret detection with basic format validation."""

    def __init__(self, use_ner: bool = False):
        self.patterns = PII_PATTERNS
        self.use_ner = use_ner
        self._ner = None
        if use_ner:
            try:
                import spacy
                self._ner = spacy.load("en_core_web_trf")
            except Exception:
                self.use_ner = False

    def detect(self, text: str) -> List[PIIMatch]:
        if not text:
            return []
        matches: List[PIIMatch] = []
        for pii_type, pattern in self.patterns.items():
            for found in pattern.finditer(text):
                value = found.group(0)
                if not self._valid(pii_type, value):
                    continue
                matches.append(PIIMatch(
                    pii_type=pii_type, start=found.start(), end=found.end(),
                    snippet=value, masked="",
                ))

        if self.use_ner and self._ner:
            for entity in self._ner(text).ents:
                if entity.label_ in ("PERSON", "GPE", "ORG", "LOC"):
                    matches.append(PIIMatch(
                        pii_type=f"NER_{entity.label_}", start=entity.start_char,
                        end=entity.end_char, snippet=entity.text, masked="",
                    ))
        return sorted(self._dedupe(matches), key=lambda item: item.start)

    @staticmethod
    def _valid(pii_type: str, value: str) -> bool:
        if pii_type == "IPV4":
            try:
                ipaddress.IPv4Address(value)
                return True
            except ipaddress.AddressValueError:
                return False
        if pii_type == "CREDIT_CARD":
            # Output filtering favours redaction over a false negative. Luhn is
            # deliberately not mandatory because test/synthetic card values and
            # some account identifiers do not pass it.
            digits = re.sub(r"\D", "", value)
            return len(digits) in range(13, 17) and len(set(digits)) > 1
        return True

    @staticmethod
    def _dedupe(matches: List[PIIMatch]) -> List[PIIMatch]:
        if not matches:
            return []
        ordered = sorted(matches, key=lambda item: (item.start, -(item.end - item.start)))
        output: List[PIIMatch] = []
        for match in ordered:
            if not output or match.start >= output[-1].end:
                output.append(match)
            elif (match.end - match.start) > (output[-1].end - output[-1].start):
                output[-1] = match
        return output
