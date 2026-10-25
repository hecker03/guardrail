"""Unicode-aware, inspection-only lexical front end for Layer 1.

This module borrows compiler front-end ideas without treating natural-language
prompts as source code. It tokenizes text, creates a bounded security-only
normalization view, and runs small deterministic token DFAs for instruction
override, prompt-leak, and explicit role-tag *candidates*. It never rewrites
the input and never makes an allow/block decision; ambiguous findings require
conversation context.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import unicodedata
from typing import FrozenSet, Iterable, List, Optional, Tuple


class TokenKind(str, Enum):
    WORD = "word"
    NUMBER = "number"
    PUNCTUATION = "punctuation"
    SYMBOL = "symbol"
    OTHER = "other"


@dataclass(frozen=True)
class LexicalToken:
    """A token with original source offsets and a security-only scan form."""

    surface: str
    normalized: str
    scan_form: str
    kind: TokenKind
    start: int
    end: int
    normalization_basis: Optional[str] = None


@dataclass(frozen=True)
class LexicalFinding:
    """A syntactic candidate, not a verdict that the user is malicious."""

    rule_id: str
    start: int
    end: int
    token_start: int
    token_end: int
    match_basis: Tuple[str, ...]
    requires_context: bool = True


@dataclass(frozen=True)
class LexicalAnalysis:
    tokens: Tuple[LexicalToken, ...]
    findings: Tuple[LexicalFinding, ...]


class LexicalAnalyzer:
    """Tokenize Unicode text and identify bounded prompt-security candidates.

    The inspection view recognizes the explicit abbreviation ``prev`` and a
    one-edit/adjacent-transposition tolerance for selected security terms. The
    original ``surface`` values and source offsets are preserved. This is
    deliberately only candidate generation: quotations, negation, and benign
    changes to a user's own earlier request need contextual analysis.
    """

    ABBREVIATIONS = {
        "prev": "previous",
    }

    OVERRIDE_VERBS: FrozenSet[str] = frozenset({"ignore", "disregard", "forget", "override"})
    PRIOR_REFERENCES: FrozenSet[str] = frozenset({"previous", "prior", "above", "earlier", "last"})
    INSTRUCTION_TARGETS: FrozenSet[str] = frozenset({
        "instruction", "instructions", "prompt", "prompts", "rule", "rules",
    })
    TRUSTED_ROLES: FrozenSet[str] = frozenset({"system", "developer"})
    ROLE_TAG_NAMES: FrozenSet[str] = frozenset({
        "system", "developer", "assistant", "user", "tool",
    })
    LEAK_VERBS: FrozenSet[str] = frozenset({
        "reveal", "show", "print", "output", "repeat", "disclose", "expose", "dump", "provide",
    })

    # Fuzzy matching is limited to these comparatively distinctive terms.
    # Short words such as "all", "my", and "prior" are not typo-corrected.
    FUZZY_TERMS: FrozenSet[str] = frozenset({
        "ignore", "disregard", "forget", "override", "previous", "instruction",
        "instructions", "prompt", "prompts", "earlier",
    })

    MAX_FILLER_WORDS = 2

    def analyze(self, text: str) -> LexicalAnalysis:
        tokens = tuple(self.tokenize(text))
        findings = self._scan_override_dfa(tokens)
        findings.extend(self._scan_two_part_dfa(
            tokens,
            start_terms=self.OVERRIDE_VERBS,
            end_terms=self.INSTRUCTION_TARGETS,
            rule_id="instruction_override_simple_candidate",
            max_gap=1,
        ))
        findings.extend(self._scan_role_tag_spans(tokens))
        findings.extend(self._scan_three_part_dfa(
            tokens,
            start_terms=self.OVERRIDE_VERBS,
            middle_terms=self.TRUSTED_ROLES,
            end_terms=self.INSTRUCTION_TARGETS,
            rule_id="trusted_instruction_override_candidate",
            max_gap=2,
        ))
        findings.extend(self._scan_two_part_dfa(
            tokens,
            start_terms=self.LEAK_VERBS,
            end_terms=self.INSTRUCTION_TARGETS,
            rule_id="system_prompt_leak_candidate",
            max_gap=4,
        ))
        findings.sort(key=lambda finding: (finding.start, finding.end, finding.rule_id))
        return LexicalAnalysis(tokens=tokens, findings=tuple(findings))

    def tokenize(self, text: str) -> List[LexicalToken]:
        """Return Unicode-aware lexemes; whitespace is skipped, spans are retained."""
        if not text:
            return []

        tokens: List[LexicalToken] = []
        start = 0
        current_kind = self._kind(text[0])

        def emit(left: int, right: int, kind: TokenKind) -> None:
            surface = text[left:right]
            normalized = unicodedata.normalize("NFKC", surface).casefold()
            scan_form, basis = self._security_form(normalized)
            tokens.append(LexicalToken(
                surface=surface,
                normalized=normalized,
                scan_form=scan_form,
                kind=kind,
                start=left,
                end=right,
                normalization_basis=basis,
            ))

        for index in range(1, len(text)):
            kind = self._kind(text[index])
            if kind != current_kind:
                if current_kind != TokenKind.OTHER or not text[start:index].isspace():
                    emit(start, index, current_kind)
                start = index
                current_kind = kind

        if current_kind != TokenKind.OTHER or not text[start:].isspace():
            emit(start, len(text), current_kind)

        return tokens

    @staticmethod
    def _kind(ch: str) -> TokenKind:
        category = unicodedata.category(ch)
        if category.startswith(("L", "M")):
            return TokenKind.WORD
        if category.startswith("N"):
            return TokenKind.NUMBER
        if category.startswith("P"):
            return TokenKind.PUNCTUATION
        if category.startswith("S"):
            return TokenKind.SYMBOL
        return TokenKind.OTHER

    @classmethod
    def _security_form(cls, normalized: str) -> Tuple[str, Optional[str]]:
        if normalized in cls.ABBREVIATIONS:
            return cls.ABBREVIATIONS[normalized], "abbreviation_expansion"

        if normalized in cls.OVERRIDE_VERBS | cls.PRIOR_REFERENCES | cls.INSTRUCTION_TARGETS:
            return normalized, None

        # Keep the fuzzy comparison ASCII-only for this English rule set. The
        # lexer itself remains Unicode-aware and preserves all scripts as tokens.
        if not normalized.isascii() or not normalized.isalpha():
            return normalized, None

        candidates = {
            term for term in cls.FUZZY_TERMS
            if len(term) >= 6 and cls._distance_at_most_one(normalized, term)
        }
        if len(candidates) == 1:
            return next(iter(candidates)), "bounded_typo_match"
        return normalized, None

    @staticmethod
    def _distance_at_most_one(left: str, right: str) -> bool:
        """Return whether strings differ by at most one edit or adjacent swap."""
        if left == right:
            return True
        if abs(len(left) - len(right)) > 1:
            return False

        if len(left) == len(right):
            mismatches = [i for i, (a, b) in enumerate(zip(left, right)) if a != b]
            if len(mismatches) == 1:
                return True
            if len(mismatches) == 2:
                first, second = mismatches
                return (
                    second == first + 1
                    and left[first] == right[second]
                    and left[second] == right[first]
                )
            return False

        # One insertion/deletion: scan with one skipped character in the longer word.
        shorter, longer = (left, right) if len(left) < len(right) else (right, left)
        i = j = edits = 0
        while i < len(shorter) and j < len(longer):
            if shorter[i] == longer[j]:
                i += 1
                j += 1
            else:
                edits += 1
                j += 1
                if edits > 1:
                    return False
        return True

    @classmethod
    def _scan_override_dfa(cls, tokens: Iterable[LexicalToken]) -> List[LexicalFinding]:
        """Recognize verb → prior-reference → instruction-target token paths.

        Punctuation is ignored for the phrase path (so ``prev. instruction``
        can be recognized); no finding is itself a blocking decision. Token
        indexes in findings refer to the complete ``LexicalAnalysis.tokens`` list.
        """
        words = [
            (source_index, token)
            for source_index, token in enumerate(tokens)
            if token.kind == TokenKind.WORD
        ]
        findings: List[LexicalFinding] = []

        SEEK_VERB = 0
        SEEK_PRIOR = 1
        SEEK_TARGET = 2
        state = SEEK_VERB
        filler_count = 0
        start_index = -1

        for index, (_, token) in enumerate(words):
            form = token.scan_form

            if state == SEEK_VERB:
                if form in cls.OVERRIDE_VERBS:
                    state = SEEK_PRIOR
                    start_index = index
                    filler_count = 0
                continue

            if state == SEEK_PRIOR:
                if form in cls.PRIOR_REFERENCES:
                    state = SEEK_TARGET
                    filler_count = 0
                elif form in cls.OVERRIDE_VERBS:
                    # A new verb is a deterministic restart point.
                    start_index = index
                    filler_count = 0
                elif filler_count < cls.MAX_FILLER_WORDS:
                    filler_count += 1
                else:
                    state = SEEK_VERB
                    start_index = -1
                    filler_count = 0
                continue

            # SEEK_TARGET
            if form in cls.INSTRUCTION_TARGETS:
                phrase_tokens = [item for _, item in words[start_index:index + 1]]
                bases = {
                    item.normalization_basis
                    for item in phrase_tokens
                    if item.normalization_basis is not None
                }
                if not bases:
                    bases.add("exact_token_sequence")
                findings.append(LexicalFinding(
                    rule_id="instruction_override_candidate",
                    start=words[start_index][1].start,
                    end=token.end,
                    token_start=words[start_index][0],
                    token_end=words[index][0],
                    match_basis=tuple(sorted(bases)),
                    requires_context=True,
                ))
                state = SEEK_VERB
                start_index = -1
                filler_count = 0
            elif form in cls.OVERRIDE_VERBS:
                start_index = index
                state = SEEK_PRIOR
                filler_count = 0
            elif filler_count < cls.MAX_FILLER_WORDS:
                filler_count += 1
            else:
                state = SEEK_VERB
                start_index = -1
                filler_count = 0

        return findings

    @classmethod
    def _scan_role_tag_spans(cls, tokens: Iterable[LexicalToken]) -> List[LexicalFinding]:
        """Record explicit XML-style and pipe-delimited role-tag token spans."""
        tokens = tuple(tokens)
        findings: List[LexicalFinding] = []

        for start_index, token in enumerate(tokens):
            if token.surface not in {"<", "<|"}:
                continue

            role_index = start_index + 1
            # Support both <system> and the visible spelling <|system|>.
            if (
                token.surface == "<"
                and role_index < len(tokens)
                and tokens[role_index].surface == "|"
            ):
                role_index += 1
            if role_index < len(tokens) and tokens[role_index].surface == "/":
                role_index += 1
            if role_index >= len(tokens):
                continue

            role = tokens[role_index].scan_form
            if tokens[role_index].kind != TokenKind.WORD or role not in cls.ROLE_TAG_NAMES:
                continue

            end_index = role_index + 1
            if end_index < len(tokens) and tokens[end_index].surface == "|":
                end_index += 1
            if end_index >= len(tokens) or tokens[end_index].surface not in {">", "|>"}:
                continue

            if role == "system":
                rule_id = "system_tag_span_candidate"
            elif role == "developer":
                rule_id = "developer_tag_span_candidate"
            else:
                rule_id = "role_tag_span_candidate"

            tag_tokens = tokens[start_index:end_index + 1]
            bases = {
                item.normalization_basis
                for item in tag_tokens
                if item.normalization_basis is not None
            }
            if not bases:
                bases.add("exact_token_sequence")
            findings.append(LexicalFinding(
                rule_id=rule_id,
                start=token.start,
                end=tokens[end_index].end,
                token_start=start_index,
                token_end=end_index,
                match_basis=tuple(sorted(bases)),
                requires_context=True,
            ))

        return findings

    @classmethod
    def _scan_three_part_dfa(
        cls,
        tokens: Iterable[LexicalToken],
        *,
        start_terms: FrozenSet[str],
        middle_terms: FrozenSet[str],
        end_terms: FrozenSet[str],
        rule_id: str,
        max_gap: int,
    ) -> List[LexicalFinding]:
        """Scan a bounded start → middle → end lexical path."""
        words = [
            (source_index, token)
            for source_index, token in enumerate(tokens)
            if token.kind == TokenKind.WORD
        ]
        findings: List[LexicalFinding] = []
        SEEK_START, SEEK_MIDDLE, SEEK_END = 0, 1, 2
        state = SEEK_START
        start_position = -1
        gap = 0

        for position, (_, token) in enumerate(words):
            form = token.scan_form
            if state == SEEK_START:
                if form in start_terms:
                    state = SEEK_MIDDLE
                    start_position = position
                    gap = 0
                continue

            if state == SEEK_MIDDLE:
                if form in middle_terms:
                    state = SEEK_END
                    gap = 0
                elif form in start_terms:
                    start_position = position
                    gap = 0
                elif gap < max_gap:
                    gap += 1
                else:
                    state = SEEK_START
                    start_position = -1
                    gap = 0
                continue

            if form in end_terms:
                phrase_tokens = [item for _, item in words[start_position:position + 1]]
                bases = {
                    item.normalization_basis
                    for item in phrase_tokens
                    if item.normalization_basis is not None
                }
                if not bases:
                    bases.add("exact_token_sequence")
                findings.append(LexicalFinding(
                    rule_id=rule_id,
                    start=words[start_position][1].start,
                    end=token.end,
                    token_start=words[start_position][0],
                    token_end=words[position][0],
                    match_basis=tuple(sorted(bases)),
                    requires_context=True,
                ))
                state = SEEK_START
                start_position = -1
                gap = 0
            elif form in start_terms:
                state = SEEK_MIDDLE
                start_position = position
                gap = 0
            elif gap < max_gap:
                gap += 1
            else:
                state = SEEK_START
                start_position = -1
                gap = 0

        return findings

    @classmethod
    def _scan_two_part_dfa(
        cls,
        tokens: Iterable[LexicalToken],
        *,
        start_terms: FrozenSet[str],
        end_terms: FrozenSet[str],
        rule_id: str,
        max_gap: int,
    ) -> List[LexicalFinding]:
        """Scan a bounded start → end lexical path."""
        words = [
            (source_index, token)
            for source_index, token in enumerate(tokens)
            if token.kind == TokenKind.WORD
        ]
        findings: List[LexicalFinding] = []
        SEEK_START, SEEK_END = 0, 1
        state = SEEK_START
        start_position = -1
        gap = 0

        for position, (_, token) in enumerate(words):
            form = token.scan_form
            if state == SEEK_START:
                if form in start_terms:
                    state = SEEK_END
                    start_position = position
                    gap = 0
                continue

            if form in end_terms:
                phrase_tokens = [item for _, item in words[start_position:position + 1]]
                bases = {
                    item.normalization_basis
                    for item in phrase_tokens
                    if item.normalization_basis is not None
                }
                if not bases:
                    bases.add("exact_token_sequence")
                findings.append(LexicalFinding(
                    rule_id=rule_id,
                    start=words[start_position][1].start,
                    end=token.end,
                    token_start=words[start_position][0],
                    token_end=words[position][0],
                    match_basis=tuple(sorted(bases)),
                    requires_context=True,
                ))
                state = SEEK_START
                start_position = -1
                gap = 0
            elif form in start_terms:
                start_position = position
                gap = 0
            elif gap < max_gap:
                gap += 1
            else:
                state = SEEK_START
                start_position = -1
                gap = 0

        return findings
