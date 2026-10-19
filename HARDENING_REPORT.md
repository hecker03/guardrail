# GUARDRAIL Layer 1, Layer 2, and Layer 5 Hardening Report

**Repository reviewed:** `https://github.com/hecker03/guardrail`

**Local hardened copy:** `/home/user/guardrail`

**Scope:** Layers 1, 2, and 5; direct FastAPI integration and reproducibility. Layer 3 and Layer 4 internals were excluded.

## Outcome

The repository now contains stronger, test-backed Layer-1, Layer-2, and Layer-5 implementations. The work closes concrete gaps identified in the original source instead of merely renaming existing functions.

This supports describing the project as an **approximately 30–40% Phase-I implementation**, provided this is explicitly presented as a planning/progress estimate. It is not a security-effectiveness percentage and does not mean that 30–40% of attacks are prevented.

## Executed evidence

The following focused suite was executed:

```text
53 passed, 1 deprecation warning in 0.46 seconds
```

Coverage in that executed suite includes:

- original Layer-1, Layer-2, and Layer-5 tests;
- new adversarial hardening tests;
- FastAPI health, Layer-1, Layer-2, Layer-5, and trusted-system-prompt boundary tests.

A Uvicorn server was also started successfully on port 8000. Runtime smoke checks confirmed:

- `GET /health` returned HTTP 200 and `{"status":"ok"}`;
- `/openapi.json` returned HTTP 200;
- clean Layer-1 input returned `pass`;
- injected Layer-2 delimiters were removed and reported;
- Layer-5 email PII was redacted without returning the raw email in metadata.

The complete repository test suite was not claimed as passing. Collection of `test_classifier.py` requires PyTorch, which was not installed in the execution sandbox. Layer 4 was outside this hardening scope.

## Layer 1 improvements

1. Retained length limiting, null/surrogate cleanup, NFKC normalization, Unicode-tag inspection, bidi-control handling, curated confusable mapping, deterministic patterns, and threat scoring.
2. Added bounded, one-level inspection views for URL encoding, HTML entities, hex escapes, and Base64.
3. Decoded content is never executed, recursively decoded, or silently substituted into the original input.
4. Added source and sanitized SHA-256 hashes for correlation.
5. Added explicit transformation metadata.
6. Changed ZWJ/ZWNJ handling so legitimate non-ASCII language shaping can be preserved, while joiners used to split ASCII keywords are removed.
7. Added tests for encoded injection, multilingual joiner handling, hashes, and transformations.

### Differentiation/gap addressed

The implementation avoids two common extremes: inspecting only visibly rendered text, and recursively decoding arbitrary input. It uses bounded inspection-only views and records transformations, reducing decoder-bomb risk and preserving evidence about what was changed.

## Layer 2 improvements

1. Added strict block-count, exactly-one-system-block, system-first, allowlisted-role, maximum-length, and server-assigned privilege checks.
2. Added canonical JSON envelope signing.
3. The HMAC now binds all role contents plus role, source, trust tier, privilege, request ID, session ID, policy version, and capability scope.
4. Added `generated`, `verified`, and `replayed` integrity states. Locally generated signatures are no longer misreported as verified provenance.
5. Added timestamp, signature/nonce format, constant-time comparison, tamper, and atomic in-process replay checks.
6. Added nonce garbage collection.
7. The integrated pipeline now uses a server-owned system prompt by default and rejects client attempts to assign the system prompt.
8. Added a process-wide API runtime so Layer-2 key state is shared across routes in one process.
9. Added tests showing that changing user content invalidates the signature, a verified nonce cannot be replayed, spoofed privilege values are rejected, and duplicate system blocks are rejected.

### Differentiation/gap addressed

The original implementation signed only the system-prompt string and labelled unsigned locally created contexts as verified. The hardened design binds cross-role context and provenance metadata while separating signature generation from inbound authenticity verification.

### Remaining limit

The replay cache is valid only within one running process. Multi-worker or multi-instance deployment requires an atomic shared store such as Redis `SET NX` with TTL. No distributed replay-protection claim should be made yet.

## Layer 5 improvements

1. Raw PII is removed from returned match metadata.
2. A keyed HMAC fingerprint supports correlation without storing the detected value.
3. IPv4 values receive format validation; broad credit-card detection remains conservative to favour redaction over false negatives.
4. URL allowlisting now uses DNS-label boundaries, preventing `evilapi.openai.com` from matching `api.openai.com`.
5. Non-allowlisted URLs now receive an explicit textual indicator.
6. Markdown beacons and data URIs receive blocking-level scores.
7. URL query values and fragments are removed from returned forensic metadata.
8. Output truncation returns `redacted`, not `pass`.
9. Prompt-echo comparison can detect a leaked prompt embedded in a longer answer.
10. Added tests for PII metadata leakage, URL-boundary confusion, URL-query leakage, truncation, and data URIs.

### Remaining limit

Layer 5 analyses output text. It does not intercept sockets, HTTP requests, DNS, tools, or other side effects. The supported claim is **textual exfiltration-indicator detection**, not network-egress enforcement.

## Supporting changes

- Added missing API, database, Celery, Redis, and HTTP dependencies to `requirements.txt`.
- Added `.env.example` with no live credentials.
- Moved the database URL to environment-aware configuration.
- Added lazy Layer-4 loading so Layer-1, Layer-2, and Layer-5 APIs can start independently. Layer-4 internals were not changed.
- Disabled synchronous LIME on the normal integrated pipeline path; this is an integration correction, not a Layer-4 model change.
- Expanded `README.md` with accurate status, setup, test, and claim boundaries.

## Claims now supportable

- Layer 1 is source-implemented, API-integrated, unit tested, adversarially tested for selected cases, and runtime smoke tested.
- Layer 2 is source-implemented, API-integrated, unit tested, and runtime smoke tested for role isolation, canonical envelope integrity, tamper detection, and single-process replay detection.
- Layer 5 is source-implemented, API-integrated, unit tested, adversarially tested for selected PII/URL/data-URI cases, and runtime smoke tested.
- FastAPI and OpenAPI start successfully for the tested Layer-1/2/5 routes.

## Claims still not supportable

- complete five-layer implementation;
- implemented Layer 3;
- trained or validated Layer-4 effectiveness;
- distributed Redis replay protection;
- downstream-LLM proxying;
- network-level egress enforcement;
- authenticated API access;
- PostgreSQL audit integration;
- automatic alert integration;
- deployed production performance;
- broad multilingual validation;
- complete resistance to prompt injection.
