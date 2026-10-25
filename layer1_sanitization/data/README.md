# Layer-1 suspicious-token dictionary

`suspicious_tokens.csv` is the default, editable Layer-1 pattern dictionary. It is loaded and compiled into Aho-Corasick automata when `PatternMatcher` is created; editing the file does not require changing matcher code. Restart the application after changing it. During inspection, incremental automaton cursors advance with the text-view traversal so token, compact-signal, Base64-run, and hex-escape checks share a single character pass per view (plus output work proportional to emitted matches).

Columns:

- `word`: single token or phrase. Token matching uses the Layer-1 Unicode lexer; punctuation in ordinary phrases acts as a separator.
- `classification`: stable result label returned in `patterns_matched`.
- `threat_score`: score in the inclusive range 0.0–1.0.
- `requires_context`: whether this classification needs a contextual Layer-3 decision.
- `match_mode`: `tokens` (default phrase matching), `literal` (visible delimiter/tag string), `signal` (paired exfiltration indicators), or `compact_signal` (bounded obfuscation sequence input).

`signal` and `compact_signal` rows are internal components combined by the matcher; they are not returned as standalone findings. The compact-view gap limits and the exfiltration action-to-sensitive-data window are policy mechanics in the matcher, not word entries.

To use another CSV, set `GUARDRAIL_SUSPICIOUS_TOKEN_DICTIONARY` or pass `SUSPICIOUS_TOKEN_DICTIONARY_PATH` in `SanitizationConfig`. Invalid columns, terms, modes, or scores fail during matcher construction rather than silently disabling detection.
