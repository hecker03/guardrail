"""Unicode-aware, inspection-only lexical front end for Layer 1.

This module borrows compiler front-end ideas without treating natural-language
prompts as source code. It tokenizes text, creates a bounded security-only
normalization view, and runs a small deterministic token DFA for an
instruction-override *candidate*. It never rewrites the input and never makes
an allow/block decision; ambiguous findings require conversation context.
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
    """Tokenize Unicode text and identify bounded override-shaped sequences.

    The inspection view recognizes the explicit abbreviation ``prev`` and a
    one-edit/adjacent-transposition tolerance for selected security terms. The
    original ``surface`` values and source offsets are preserved. This is
    deliberately only candidate generation: quotations, negation, and benign
    changes to a user's own earlier request need contextual analysis.
    """

    ABBREVIATIONS = {
        "prev": "previous",
    }

    OVERRIDE_VERBS: FrozenSet[str] = frozenset({"ignore", "disregard", "forget"})
    PRIOR_REFERENCES: FrozenSet[str] = frozenset({"previous", "prior", "above", "earlier", "last"})
    INSTRUCTION_TARGETS: FrozenSet[str] = frozenset({
        "instruction", "instructions", "prompt", "prompts", "rule", "rules",
    })

    # Fuzzy matching is limited to these comparatively distinctive terms.
    # Short words such as "all", "my", and "prior" are not typo-corrected.
    FUZZY_TERMS: FrozenSet[str] = frozenset({
        "ignore", "disregard", "forget", "previous", "instruction",
        "instructions", "prompt", "prompts", "earlier",
    })

    MAX_FILLER_WORDS = 2

    def analyze(self, text: str) -> LexicalAnalysis:
        tokens = tuple(self.tokenize(text))
        findings = tuple(self._scan_override_dfa(tokens))
        return LexicalAnalysis(tokens=tokens, findings=findings)

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
