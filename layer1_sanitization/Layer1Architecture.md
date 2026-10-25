# Layer 1 Prompt Security Middleware Architecture

This document maps out the comprehensive, production-grade architecture of our **Layer 1 Guardrail Pipeline**. This layer serves as a high-speed, deterministic pre-filter designed to neutralize obfuscation tactics and flag suspicious prompt signatures before inputs are passed to downstream layers.

---

## 🏗️ System Architecture Overview

```mermaid
graph TD
    %% Define System Input
    RawPrompt[Raw User Prompt String] --> Stage1[STAGE 1: HARD VOLUMETRIC LIMITS]

    %% Stage 1 Elements
    subgraph S1 [Volumetric Checks]
        Stage1 --> |Fail Bounds| Reject1[REJECTED: Length Exceeded]
        Stage1 --> |Pass Bounds| Stage2[STAGE 2: TEXT CLEANING & ALIGNMENT]
    end

    %% Stage 2 Elements
    subgraph S2 [Sanitization & Normalization]
        Stage2 --> C1[1. Null Byte & Invalid Surrogate Stripping]
        C1 --> C2[2. Invisible, BiDi, & Control Character Drop]
        C2 --> C3[3. Curated Homoglyph Dictionary Translation]
        C3 --> C4[4. Structural NFKC Normalization]
    end

    %% Dual Path Routing
    C4 --> NormalizedPrompt[Fully Normalized Text String]
    
    %% Direct Path
    NormalizedPrompt --> |Direct Path| Stage3A[STAGE 3A: REGULATORY SCHEDULER]
    Stage3A --> EngineA[Trie / Aho-Corasick Single-Pass DFA Matcher]

    %% Encoded/Multi-View Path
    NormalizedPrompt --> |Multi-View Subtraction| Stage3B[STAGE 3B: DECODED MULTI-VIEW MATRIX]
    subgraph S3B [View Extraction Windows]
        Stage3B --> V1[Base64 Unbounded View]
        Stage3B --> V2[Hex Stream View]
        Stage3B --> V3[URL / Percent Percent View]
    end
    
    %% Multi-view Processing Loop
    V1 & V2 & V3 --> EngineB[Trie / Aho-Corasick Single-Pass DFA Matcher]

    %% Aggregation and Matrix Decision
    EngineA & EngineB --> Aggregator[Aggregated Risk Metrics & Class Metadata]
    Aggregator --> DecisionMatrix{Decision State Logic Matrix}

    %% Final Routing Tiers
    DecisionMatrix --> |Score >= Threat Threshold| Tier1[REJECTED: Hard Block]
    DecisionMatrix --> |Ambiguous Flags Tripped| Tier2[FLAGGED: Route to Layer 2 Turing Machine]
    DecisionMatrix --> |Modifications Made But Safe| Tier3[SANITIZED: Forward Directly to LLM]
    DecisionMatrix --> |Completely Clean Stream| Tier4[PASS: Forward Directly to LLM]

    %% Styling Elements
    style RawPrompt fill:#f9f,stroke:#333,stroke-width:2px
    style Reject1 fill:#ff9999,stroke:#333,stroke-width:1px
    style Tier1 fill:#ff4d4d,stroke:#333,stroke-width:2px,color:#fff
    style Tier2 fill:#ffb366,stroke:#333,stroke-width:2px
    style Tier3 fill:#99ff99,stroke:#333,stroke-width:2px
    style Tier4 fill:#66ccff,stroke:#333,stroke-width:2px
```

---

## ⚡ Step-by-Step Processing Pipeline

### STAGE 1: HARD VOLUMETRIC LIMITS
* **Length Check:** Inspects the raw stream length against a maximum character threshold (`max_length`). If boundaries are broken, the prompt drops immediately without executing resource-heavy text parsers.

### STAGE 2: TEXT CLEANING & ALIGNMENT
* **Null Byte Stripping:** Eliminates structural break attempts (`\x00`).
* **Control Filter:** Strips hidden tokens, format markers (`Cf`), bidirectional text overrides (`BiDi`), and basic control codes (`Cc`).
* **Homoglyph Flattening:** Evaluates a curated character-mapping index to translate visually look-alike script variants (such as Cyrillic/Greek replacements) back to native ASCII values.
* **NFKC Normalization:** Applies Unicode Compatibility Decomposition to crush stylistic formatting exploits (like mathematical bold strings `𝐦𝐚𝐬𝐭er`) into unified tokens.

### STAGE 3: RECOGNITION (THE TRIE DFA MATCHING ENGINE)
The normalized main prompt and extracted bounded window views (Base64, Hex, URL) run through a high-performance **Aho-Corasick / Trie Finite Automaton Engine**:
1. **Single-Pass Parsing ($O(N)$ Complexity):** Scans each string exactly once, independent of the underlying dataset dictionary scale.
2. **Database Separation:** Suspicious words live in clean external JSON/database definitions (`[Word, Classification, Threat Score]`), allowing hot updates to the filter library without modifying pipeline script infrastructure.

---

## 📋 Multi-State Output Tiers

| Classification State | System Security Routing Behavior |
| :--- | :--- |
| **`REJECTED`** | Volumetric limits violated or maximum aggregated threat score hits the fatal boundary block threshold. Input dropped. |
| **`FLAGGED`** | Ambiguous security rule signatures hit intermediate weights. Sent to **Layer 2 (Turing Machine/LLM Evaluator)** for semantic evaluation. |
| **`SANITIZED`** | Structural obfuscations or homoglyphs were cleaned, but no active injection signatures were flagged. Safely passed directly to core LLM. |
| **`PASS`** | Clean prompt validation stream. Sent straight to the core LLM execution engine. |
