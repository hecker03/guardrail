"""Data-driven Layer-1 pattern matching using compiled Aho-Corasick automata.

Natural-language word and phrase indicators live in ``data/suspicious_tokens.csv``.
The dictionary is compiled once when the matcher is constructed. Each text view is
then walked once while token and compact-view automaton states are advanced; there
is no regex-per-entry matching loop.
"""

from __future__ import annotations

import os
from pathlib import Path
import unicodedata
from typing import Iterable, List, Optional, Set, Tuple

from .lexical_analyzer import LexicalAnalyzer, LexicalToken
from .token_matcher import (
    AhoCorasick,
    AhoHit,
    DictionaryEntry,
    lexical_token_key,
    lexical_token_stream,
    load_dictionary,
)


class PatternMatcher:
    """Compile an editable token dictionary and scan text views in O(N + Z)."""

    MAX_EXFILTRATION_TOKEN_GAP = 64
    MAX_COMPACT_OVERRIDE_GAP = 64
    MAX_COMPACT_PRIOR_TARGET_GAP = 32
    MAX_COMPACT_SIMPLE_GAP = 16
    MAX_COMPACT_SAFETY_GAP = 32

    def __init__(
        self,
        dictionary_path: Optional[str | Path] = None,
        lexical_analyzer: Optional[LexicalAnalyzer] = None,
    ) -> None:
        env_path = os.getenv("GUARDRAIL_SUSPICIOUS_TOKEN_DICTIONARY", "").strip()
        selected_path = dictionary_path or env_path or (
            Path(__file__).parent / "data" / "suspicious_tokens.csv"
        )
        self.dictionary_path = Path(selected_path)
        self.lexical_analyzer = lexical_analyzer or LexicalAnalyzer()
        self.entries = load_dictionary(self.dictionary_path)

        # The primary automaton accepts both lexical tokens and visible
        # punctuation/symbol tokens, so phrases and structural markers share a
        # single scan. Compact-signal entries use a second bounded character view.
        self._token_automaton = AhoCorasick()
        self._compact_automaton = AhoCorasick()
        contextual: Set[str] = set()

        for entry in self.entries:
            if entry.requires_context:
                contextual.add(entry.classification)

            if entry.match_mode in {"tokens", "literal", "signal"}:
                term_view = self.lexical_analyzer.tokenize(entry.word)
                sequence = lexical_token_stream(term_view)
                if sequence:
                    self._token_automaton.add(sequence, entry)
            elif entry.match_mode == "compact_signal":
                compact_term = self._compact_ascii(entry.word)
                if compact_term:
                    self._compact_automaton.add(tuple(compact_term), entry)

        # A compact simple override inherits the context policy of its verb
        # signals; strong three-part compact matches are still rejected by score.
        if any(
            entry.match_mode == "compact_signal"
            and entry.classification == "compact_override_verb"
            and entry.requires_context
            for entry in self.entries
        ):
            contextual.add("obfuscated_simple_instruction_override")
        self.CONTEXTUAL_CANDIDATE_PATTERNS = frozenset(contextual)

        self._token_automaton.build()
        self._compact_automaton.build()

    def scan(
        self,
        text: str,
        tokens: Optional[Iterable[LexicalToken]] = None,
    ) -> Tuple[List[str], float]:
        """Return matched classifications and the highest configured threat score."""
        if not text:
            return [], 0.0

        # In the Layer-1 path callers pass tokens from the same already-normalized
        # view. Direct users of PatternMatcher get a canonicalized local tokenization.
        scan_text = text if tokens is not None else unicodedata.normalize("NFKC", text)
        lexical_tokens = tuple(tokens) if tokens is not None else tuple(
            self.lexical_analyzer.tokenize(scan_text)
        )
        token_cursor = self._token_automaton.cursor()
        compact_cursor = self._compact_automaton.cursor()
        compact_hits: List[AhoHit] = []

        matched: List[str] = []
        matched_set: Set[str] = set()
        max_score = 0.0
        latest_exfiltration_action = None

        def record(classification: str, score: float) -> None:
            nonlocal max_score
            if classification not in matched_set:
                matched_set.add(classification)
                matched.append(classification)
            max_score = max(max_score, score)

        def consume_token_hit(hit: AhoHit) -> None:
            nonlocal latest_exfiltration_action
            entry = hit.value
            if entry.match_mode == "signal":
                if entry.classification == "exfiltration_action":
                    latest_exfiltration_action = hit
                elif entry.classification == "sensitive_data" and latest_exfiltration_action:
                    token_gap = hit.start - latest_exfiltration_action.end
                    if 0 <= token_gap <= self.MAX_EXFILTRATION_TOKEN_GAP:
                        record(
                            "exfiltrate",
                            max(entry.threat_score, latest_exfiltration_action.value.threat_score),
                        )
                return
            record(entry.classification, entry.threat_score)

        # Character loop advances both Aho states and the bounded format checks.
        # Token hits are fed at their original source boundaries in this same loop.
        token_index = 0
        b64_run = 0
        b64_padding = 0
        base64_blob_found = False
        hex_state = 0
        hex_run = 0
        hex_escape_found = False
        hex_digits = "0123456789abcdefABCDEF"

        for char_index, char in enumerate(scan_text):
            for folded in char.casefold():
                if folded.isascii() and ("a" <= folded <= "z" or "0" <= folded <= "9"):
                    compact_hits.extend(compact_cursor.feed(folded))

            if char.isascii() and (char.isalnum() or char in "+/"):
                b64_run += 1
                b64_padding = 0
            elif char == "=" and b64_run >= 80 and b64_padding < 2:
                b64_padding += 1
            else:
                if b64_run >= 80:
                    base64_blob_found = True
                b64_run = 0
                b64_padding = 0

            # Streaming recognition of four or more adjacent \\xNN escapes.
            if hex_state == 0:
                if char == "\\":
                    hex_state = 1
            elif hex_state == 1:
                if char in {"x", "X"}:
                    hex_state = 2
                elif char != "\\":
                    hex_state = 0
                    hex_run = 0
            elif hex_state == 2:
                if char in hex_digits:
                    hex_state = 3
                else:
                    hex_state = 1 if char == "\\" else 0
                    hex_run = 0
            elif hex_state == 3:
                if char in hex_digits:
                    hex_run += 1
                    if hex_run >= 4:
                        hex_escape_found = True
                    hex_state = 4
                else:
                    hex_state = 1 if char == "\\" else 0
                    hex_run = 0
            else:  # completed \\xNN; another backslash continues the run
                if char == "\\":
                    hex_state = 1
                else:
                    hex_state = 0
                    hex_run = 0

            source_end = char_index + 1
            while token_index < len(lexical_tokens) and lexical_tokens[token_index].end <= source_end:
                token = lexical_tokens[token_index]
                for hit in token_cursor.feed(lexical_token_key(token)):
                    consume_token_hit(hit)
                token_index += 1

        # Defensive tail handling for externally supplied token streams.
        while token_index < len(lexical_tokens):
            for hit in token_cursor.feed(lexical_token_key(lexical_tokens[token_index])):
                consume_token_hit(hit)
            token_index += 1

        if b64_run >= 80:
            base64_blob_found = True
        if base64_blob_found:
            record("base64_blob", 0.60)
        if hex_escape_found:
            record("hex_escape", 0.55)

        for classification, score in self._compose_compact_hits(compact_hits):
            record(classification, score)

        return matched, max_score

    def requires_context(self, pattern_names: Iterable[str]) -> bool:
        """Check direct or view-prefixed matches against dictionary policy."""
        return any(
            name.rsplit(":", 1)[-1] in self.CONTEXTUAL_CANDIDATE_PATTERNS
            for name in pattern_names
        )

    def _compose_compact_hits(self, hits: Iterable[AhoHit]) -> List[Tuple[str, float]]:
        """Combine Aho token signals with bounded gaps; no regex engine required."""
        results: List[Tuple[str, float]] = []
        latest_override = None
        latest_prior = None
        latest_safety_verb = None

        for hit in hits:
            entry = hit.value
            category = entry.classification

            if category == "compact_override_verb":
                latest_override = hit
                latest_prior = None
            elif category == "compact_prior_reference":
                if latest_override is not None:
                    gap = hit.start - latest_override.end
                    if 0 <= gap <= self.MAX_COMPACT_OVERRIDE_GAP:
                        latest_prior = (latest_override, hit)
            elif category == "compact_instruction_target":
                if latest_override is not None:
                    gap = hit.start - latest_override.end
                    if 0 <= gap <= self.MAX_COMPACT_SIMPLE_GAP:
                        results.append((
                            "obfuscated_simple_instruction_override",
                            max(latest_override.value.threat_score, entry.threat_score),
                        ))
                if latest_prior is not None:
                    verb_hit, prior_hit = latest_prior
                    gap = hit.start - prior_hit.end
                    if 0 <= gap <= self.MAX_COMPACT_PRIOR_TARGET_GAP:
                        score = max(
                            verb_hit.value.threat_score,
                            prior_hit.value.threat_score,
                            entry.threat_score,
                        )
                        results.append(("obfuscated_instruction_override", score))
                        # Retain the historic signature label for compatibility.
                        results.append(("ignore_instructions", score))
            elif category == "compact_safety_verb":
                latest_safety_verb = hit
            elif category == "compact_safety_target" and latest_safety_verb is not None:
                gap = hit.start - latest_safety_verb.end
                if 0 <= gap <= self.MAX_COMPACT_SAFETY_GAP:
                    results.append((
                        "obfuscated_safety_override",
                        max(latest_safety_verb.value.threat_score, entry.threat_score),
                    ))

        return results

    @staticmethod
    def _compact_ascii(text: str) -> str:
        normalized = unicodedata.normalize("NFKC", text).casefold()
        return "".join(
            char for char in normalized
            if char.isascii() and ("a" <= char <= "z" or "0" <= char <= "9")
        )
