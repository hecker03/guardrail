import re
from typing import Set, Tuple
from difflib import SequenceMatcher
from .config import OutputFilterConfig, DEFAULT_CONFIG


class PromptEchoDetector:
    """Detect substantial system-prompt reuse without returning prompt text."""

    def __init__(self, config: OutputFilterConfig = DEFAULT_CONFIG):
        self.cfg = config

    def detect(self, output: str, system_prompt: str) -> Tuple[bool, float]:
        if not output or not system_prompt or len(output) < self.cfg.ECHO_MIN_LENGTH:
            return False, 0.0

        out_grams = self._ngrams(output, self.cfg.ECHO_NGRAM_SIZE)
        sys_grams = self._ngrams(system_prompt, self.cfg.ECHO_NGRAM_SIZE)
        overlap = 0.0
        if out_grams and sys_grams:
            common = len(out_grams & sys_grams)
            # Use the smaller side so a leaked prompt embedded in a longer answer
            # is still detected.
            overlap = common / min(len(out_grams), len(sys_grams))
            if overlap >= self.cfg.ECHO_SIMILARITY_THRESHOLD:
                return True, overlap

        output_norm = self._normalise(output)[:1000]
        prompt_norm = self._normalise(system_prompt)[:1000]
        ratio = SequenceMatcher(None, output_norm, prompt_norm).ratio()
        score = max(overlap, ratio)
        return score >= self.cfg.ECHO_SIMILARITY_THRESHOLD, score

    @staticmethod
    def _normalise(text: str) -> str:
        return " ".join(re.findall(r"\w+", text.casefold()))

    @staticmethod
    def _ngrams(text: str, n: int) -> Set[str]:
        tokens = re.findall(r"\w+", text.casefold())
        if len(tokens) < n:
            return set()
        return {" ".join(tokens[index:index+n]) for index in range(len(tokens) - n + 1)}
