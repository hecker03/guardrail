"""Bounded, single-pass inspection of common textual encodings.

Decoded views are inspected for indicators only. They are never executed, recursively
decoded, or substituted into the user-visible input.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
from dataclasses import dataclass
from typing import List
from urllib.parse import unquote


@dataclass(frozen=True)
class DecodedView:
    encoding: str
    text: str


class BoundedDecoderInspector:
    """Create small, one-level decoded views without decoder-bomb behaviour."""

    _B64_RE = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/])")
    _HEX_ESCAPE_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
    _PERCENT_RE = re.compile(r"%[0-9a-fA-F]{2}")
    _HTML_ENTITY_RE = re.compile(r"&(?:#\d+|#x[0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]+);")

    def __init__(self, max_source_chars: int = 32_000, max_candidates: int = 8, max_decoded_chars: int = 4_096):
        self.max_source_chars = max_source_chars
        self.max_candidates = max_candidates
        self.max_decoded_chars = max_decoded_chars

    def inspect(self, text: str) -> List[DecodedView]:
        if not text:
            return []
        source = text[: self.max_source_chars]
        views: List[DecodedView] = []

        if self._PERCENT_RE.search(source):
            self._append(views, "url", unquote(source))
        if self._HTML_ENTITY_RE.search(source):
            self._append(views, "html_entity", html.unescape(source))

        for match in self._HEX_ESCAPE_RE.finditer(source):
            if len(views) >= self.max_candidates:
                break
            try:
                raw = bytes.fromhex(match.group(0).replace("\\x", ""))
                self._append(views, "hex_escape", raw.decode("utf-8", errors="strict"))
            except (ValueError, UnicodeDecodeError):
                continue

        for match in self._B64_RE.finditer(source):
            if len(views) >= self.max_candidates:
                break
            token = match.group(1)
            try:
                padded = token + "=" * (-len(token) % 4)
                raw = base64.b64decode(padded, validate=True)
                decoded = raw.decode("utf-8", errors="strict")
            except (ValueError, UnicodeDecodeError, binascii.Error):
                continue
            if self._mostly_printable(decoded):
                self._append(views, "base64", decoded)

        return views[: self.max_candidates]

    def _append(self, views: List[DecodedView], encoding: str, decoded: str) -> None:
        decoded = decoded[: self.max_decoded_chars]
        if decoded and all(not (v.encoding == encoding and v.text == decoded) for v in views):
            views.append(DecodedView(encoding=encoding, text=decoded))

    @staticmethod
    def _mostly_printable(text: str) -> bool:
        if not text:
            return False
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
        return printable / len(text) >= 0.85
