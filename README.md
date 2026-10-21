# GUARDRAIL — Phase-I prototype

GUARDRAIL is a modular FastAPI security prototype for inspecting text entering and leaving an LLM application. This repository currently provides hardened implementations of **Layer 1**, **Layer 2**, and **Layer 5**, a Layer-4 research implementation, and a partial integrated route.

## Evidence-based status

| Area | Current status |
|---|---|
| Layer 1 input sanitisation | Implemented and unit tested |
| Layer 2 context isolation/integrity | Implemented and unit tested for one process |
| Layer 3 behavioural analysis | Under development; not in this snapshot |
| Layer 4 classifier | Source present; trained model quality is not established here |
| Layer 5 output filtering | Implemented and unit tested |
| L1 → L2 → L4 → optional L5 route | Source integrated; requires a valid Layer-4 environment/checkpoint |
| Database and Telegram helpers | Source present but not integrated end to end |
| Authentication, downstream LLM adapter, WebSocket, deployment | Not implemented in this snapshot |

## Security properties implemented in this hardening pass

### Layer 1

- Hard input-length limit before expensive work.
- Null/surrogate cleanup and NFKC canonicalisation.
- Unicode tag, supplementary variation selector, bidi-control, and unsafe invisible-character handling.
- Context-sensitive preservation of ZWJ/ZWNJ for non-ASCII language text; joiners used inside ASCII tokens are removed.
- Curated confusable mapping and deterministic injection indicators.
- Single-pass, bounded URL, HTML-entity, hex-escape, and Base64 **inspection views**. Decoded text is not executed, recursively decoded, or silently substituted.
- SHA-256 correlation hashes and explicit transformation metadata.

### Layer 2

- Strict allowlisted roles, exactly one first-position system block, server-assigned privilege values, block-count and prompt-length limits.
- Escaped XML-like role boundaries and injected-boundary removal.
- Canonical JSON HMAC-SHA-256 binding role content, source, trust tier, privileges, request/session identifiers, policy version, and capability scope.
- Correct distinction between locally `generated` integrity and verified inbound integrity.
- Timestamp, format, tamper, and atomic in-process nonce-replay checks.
- The integrated pipeline uses a server-owned system prompt unless the unsafe development override is explicitly enabled.

The replay cache is deliberately described as **single-process**. Multi-worker deployment still requires an atomic shared replay store such as Redis.

### Layer 5

- Regex-first PII/secret detection and deterministic masking.
- Returned PII metadata contains redacted labels and keyed fingerprints, not raw values.
- Prompt-echo comparison and redaction.
- Textual indicators for Markdown beacons, data URIs, suspicious URLs, and large encoded blobs.
- Domain-boundary-safe URL allowlisting.
- Query values are removed from blocked-URL forensic metadata.
- Truncation is reported as `redacted`, never silently as `pass`.

Layer 5 performs **textual exfiltration-indicator detection**. It is not network-level egress enforcement.

## Local setup

The repository directory itself is the Python package named `guardrail`. Run commands from its parent directory, or install/package it before running elsewhere.

```bash
cd /path/to/parent-of-guardrail
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r guardrail/requirements.txt
cp guardrail/.env.example guardrail/.env
# Replace every placeholder secret; export/load the variables using your preferred tool.
uvicorn guardrail.api.main:app --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000/docs` for Swagger UI.

## Tests

Layer 1, 2, and 5 tests do not require a trained Layer-4 checkpoint:

```bash
cd /path/to/parent-of-guardrail
PYTHONPATH=. python -m pytest -q \
  guardrail/tests/test_sanitizer.py \
  guardrail/tests/test_isolator.py \
  guardrail/tests/test_output_filter.py \
  guardrail/tests/test_hardening.py
```

Do not describe source presence as end-to-end validation. Keep separate evidence for source implementation, integration, unit tests, API tests, trained-model evaluation, and deployed execution.
