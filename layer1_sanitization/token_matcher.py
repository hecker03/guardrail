"""Small dependency-free Aho-Corasick automata for Layer-1 dictionaries.

The automaton accepts either lexical tokens or characters. After compilation,
all registered patterns are matched in O(N + Z), where N is input length and Z
is the number of emitted matches.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import Path
import csv
import unicodedata
from typing import Dict, Hashable, Iterable, Iterator, List, Sequence, Tuple

from .lexical_analyzer import LexicalToken, TokenKind


@dataclass(frozen=True)
class DictionaryEntry:
    word: str
    classification: str
    threat_score: float
    requires_context: bool
    match_mode: str = "tokens"


@dataclass(frozen=True)
class AhoHit:
    start: int
    end: int  # exclusive
    value: DictionaryEntry


class AhoCorasick:
    """A trie with failure links; reusable for character and token alphabets."""

    def __init__(self) -> None:
        self._goto: List[Dict[Hashable, int]] = [{}]
        self._fail: List[int] = [0]
        self._output: List[List[Tuple[DictionaryEntry, int]]] = [[]]
        self._built = False

    def add(self, pattern: Sequence[Hashable], value: DictionaryEntry) -> None:
        if self._built:
            raise RuntimeError("Cannot add patterns after the automaton is built")
        if not pattern:
            raise ValueError(f"Empty pattern for classification {value.classification!r}")

        state = 0
        for symbol in pattern:
            next_state = self._goto[state].get(symbol)
            if next_state is None:
                next_state = len(self._goto)
                self._goto[state][symbol] = next_state
                self._goto.append({})
                self._fail.append(0)
                self._output.append([])
            state = next_state
        self._output[state].append((value, len(pattern)))

    def build(self) -> None:
        if self._built:
            return
        queue = deque()
        for child in self._goto[0].values():
            self._fail[child] = 0
            queue.append(child)

        while queue:
            state = queue.popleft()
            for symbol, child in self._goto[state].items():
                queue.append(child)
                fallback = self._fail[state]
                while fallback and symbol not in self._goto[fallback]:
                    fallback = self._fail[fallback]
                self._fail[child] = self._goto[fallback].get(symbol, 0)
                self._output[child].extend(self._output[self._fail[child]])

        self._built = True

    def cursor(self) -> "AhoCursor":
        if not self._built:
            self.build()
        return AhoCursor(self)

    def iter_matches(self, sequence: Iterable[Hashable]) -> Iterator[AhoHit]:
        cursor = self.cursor()
        for symbol in sequence:
            yield from cursor.feed(symbol)


class AhoCursor:
    """Incremental automaton state for interleaving several linear scans."""

    def __init__(self, automaton: AhoCorasick) -> None:
        self.automaton = automaton
        self.state = 0
        self.index = 0

    def feed(self, symbol: Hashable) -> List[AhoHit]:
        automaton = self.automaton
        while self.state and symbol not in automaton._goto[self.state]:
            self.state = automaton._fail[self.state]
        self.state = automaton._goto[self.state].get(symbol, 0)
        position = self.index
        self.index += 1
        return [
            AhoHit(start=position - length + 1, end=position + 1, value=entry)
            for entry, length in automaton._output[self.state]
        ]


def load_dictionary(path: str | Path) -> List[DictionaryEntry]:
    """Read and validate the editable CSV word/token dictionary."""
    dictionary_path = Path(path)
    entries: List[DictionaryEntry] = []
    required_columns = {"word", "classification", "threat_score"}

    with dictionary_path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        headers = set(reader.fieldnames or ())
        missing = required_columns - headers
        if missing:
            raise ValueError(
                f"Suspicious-token dictionary {dictionary_path} is missing columns: "
                f"{', '.join(sorted(missing))}"
            )

        for row_number, row in enumerate(reader, start=2):
            word = (row.get("word") or "").strip()
            classification = (row.get("classification") or "").strip()
            if not word or not classification:
                raise ValueError(
                    f"Dictionary row {row_number} must contain word and classification"
                )
            if len(word) > 200:
                raise ValueError(f"Dictionary term at row {row_number} exceeds 200 characters")

            try:
                score = float(row.get("threat_score", ""))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Invalid threat_score at dictionary row {row_number}") from exc
            if not 0.0 <= score <= 1.0:
                raise ValueError(f"threat_score at dictionary row {row_number} must be 0..1")

            context_value = (row.get("requires_context") or "false").strip().casefold()
            if context_value not in {"true", "false", "1", "0", "yes", "no"}:
                raise ValueError(f"Invalid requires_context at dictionary row {row_number}")
            requires_context = context_value in {"true", "1", "yes"}

            match_mode = (row.get("match_mode") or "tokens").strip().casefold()
            if match_mode not in {"tokens", "literal", "signal", "compact_signal"}:
                raise ValueError(f"Unsupported match_mode at dictionary row {row_number}: {match_mode}")

            entries.append(DictionaryEntry(
                word=word,
                classification=classification,
                threat_score=score,
                requires_context=requires_context,
                match_mode=match_mode,
            ))

    if not entries:
        raise ValueError(f"Suspicious-token dictionary {dictionary_path} is empty")
    return entries


def lexical_token_key(token: LexicalToken) -> Tuple[str, str]:
    """Canonical key for a complete lexical token, including visible delimiters."""
    if token.kind in (TokenKind.WORD, TokenKind.NUMBER):
        value = token.scan_form
    else:
        value = unicodedata.normalize("NFKC", token.surface).casefold()
    return token.kind.value, value


def lexical_token_stream(tokens: Iterable[LexicalToken]) -> List[Tuple[str, str]]:
    """Return one normalized stream for phrases and structural markers."""
    return [lexical_token_key(token) for token in tokens]
