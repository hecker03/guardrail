# guardrail/layer5_output_filter/pii_detector.py

from typing import List, Tuple
from .config import PII_PATTERNS
from .models import PIIMatch


class PIIDetector:
    """
    Detects PII / secrets in LLM output.

    Regex-first (fast, deterministic). Optional transformer NER
    (spaCy en_core_web_trf) can be layered on top for names/addresses.
    """

    def __init__(self, use_ner: bool = False):
        self.patterns = PII_PATTERNS
        self.use_ner = use_ner
        self._ner = None

        if use_ner:
            try:
                import spacy
                self._ner = spacy.load("en_core_web_trf")
            except Exception:
                self.use_ner = False   # graceful fallback

    # ------------------------------------------------------------------ #
    # Public
    # ------------------------------------------------------------------ #
    def detect(self, text: str) -> List[PIIMatch]:
        if not text:
            return []

        matches: List[PIIMatch] = []

        # ---- Regex pass ----
        for pii_type, pattern in self.patterns.items():
            for m in pattern.finditer(text):
                matches.append(PIIMatch(
                    pii_type=pii_type,
                    start=m.start(),
                    end=m.end(),
                    snippet=m.group(0),
                    masked="",     # filled by masker
                ))

        # ---- NER pass (optional) ----
        if self.use_ner and self._ner:
            doc = self._ner(text)
            for ent in doc.ents:
                if ent.label_ in ("PERSON", "GPE", "ORG", "LOC"):
                    matches.append(PIIMatch(
                        pii_type=f"NER_{ent.label_}",
                        start=ent.start_char,
                        end=ent.end_char,
                        snippet=ent.text,
                        masked="",
                    ))

        # Deduplicate & sort
        matches = self._dedupe(matches)
        return sorted(matches, key=lambda m: m.start)

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _dedupe(matches: List[PIIMatch]) -> List[PIIMatch]:
        """Remove overlapping matches — keep widest."""
        if not matches:
            return []
        matches = sorted(matches, key=lambda m: (m.start, -m.end))
        out = [matches[0]]
        for m in matches[1:]:
            if m.start >= out[-1].end:
                out.append(m)
            elif m.end > out[-1].end:
                out[-1] = m
        return out