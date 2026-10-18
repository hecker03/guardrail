# guardrail/layer5_output_filter/echo_detector.py

import re
from typing import Set, Tuple
from difflib import SequenceMatcher
from .config import OutputFilterConfig, DEFAULT_CONFIG


class PromptEchoDetector:
    """
    Detects when the model echoes back parts of the system prompt
    (a common jailbreak success indicator).
    """

    def __init__(self, config: OutputFilterConfig = DEFAULT_CONFIG):
        self.cfg = config

    def detect(
        self,
        output: str,
        system_prompt: str,
    ) -> Tuple[bool, float]:
        """
        Returns (echo_detected, similarity_score).
        """
        if not output or not system_prompt:
            return False, 0.0
        if len(output) < self.cfg.ECHO_MIN_LENGTH:
            return False, 0.0

        # ---- 1) Exact n-gram overlap ----
        out_grams = self._ngrams(output, self.cfg.ECHO_NGRAM_SIZE)
        sys_grams = self._ngrams(system_prompt, self.cfg.ECHO_NGRAM_SIZE)

        if out_grams and sys_grams:
            overlap = len(out_grams & sys_grams) / len(out_grams)
            if overlap >= self.cfg.ECHO_SIMILARITY_THRESHOLD:
                return True, overlap

        # ---- 2) SequenceMatcher on first 500 chars ----
        a = output[:500].lower()
        b = system_prompt[:500].lower()
        ratio = SequenceMatcher(None, a, b).ratio()

        return ratio >= self.cfg.ECHO_SIMILARITY_THRESHOLD, ratio

    # ------------------------------------------------------------------ #
    @staticmethod
    def _ngrams(text: str, n: int) -> Set[str]:
        tokens = re.findall(r"\w+", text.lower())
        if len(tokens) < n:
            return set()
        return {" ".join(tokens[i:i+n]) for i in range(len(tokens) - n + 1)}