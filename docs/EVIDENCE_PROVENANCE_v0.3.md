# Evidence Provenance v0.3

## Purpose

RISU Verify must not allow a convenient narrative about external code to become a substitute for the evidence bytes used by assurance. v0.3 therefore places a fail-closed provenance gate before predeclaration checking and before the frozen v0.7 producer.

The gate closes four distinct links while keeping their epistemic strength separate.

### 1. Upstream identity

For pinned public source, the case records repository, immutable commit, path, and Git blob SHA. These are external revision identifiers. RISU checks their shape and commits them into the local provenance manifest; it does not claim that an offline excerpt alone cryptographically reconstructs a full remote Git object.

### 2. Bundled evidence bytes

The exact local source block or excerpt used for deterministic extraction is SHA-256 pinned. Any byte mutation fails before core execution.

### 3. Deterministic extraction

`tools/provenance_verify.py` re-runs declared required/forbidden source assertions over those pinned bytes and requires `provenance/EXTRACTED_SOURCE_FACTS.json` to reproduce exactly.

For Case 002, source-byte assertions are additionally linked to named observation IDs in the separately pinned semantic interpretation snapshot. This proves the structural relationship without pretending the semantic interpretation itself is a byte-level fact.

### 4. Core-consumption identity

For Case 003, the deterministic extraction used on the provenance side must be byte-identical to `assurance/evidence/extracted_source_facts.json`, the evidence copy pinned by the v0.7 adapter. This closes a substitution gap in which correct provenance could otherwise coexist with a different derived evidence document consumed by the core.

## Fail-closed ordering

```text
core archive pin
  → case provenance manifest pin
  → evidence byte pins
  → deterministic extraction
  → semantic links / core-binding links
  → predeclaration pin
  → v0.7 producer
  → independent v0.7 consumer
```

No provenance failure is translated into `INCOMPLETE_ASSURANCE` or a semantic verdict. It is an integrity failure and exits 30 before a core result is accepted.

## What this does not claim

This layer does not establish live-service behavior, truth of a hand-authored semantic premise, completeness of a source model, or independent third-party reproduction. It establishes a reproducible chain over the exact local evidence surface used by the package and records the immutable upstream identities from which those evidence bytes were selected.

## rc2 audit-hardening: explicit binding modes and retrieval classes

The hostile rc1 audit found that wording such as “provenance closure” could be read more strongly than the executable gate. rc2 therefore makes the distinction machine-visible.

An upstream source artifact may declare one of two binding modes:

- `FULL_GIT_BLOB`: the package contains the complete blob bytes and the verifier recomputes the Git blob object ID from `blob <length>\0<bytes>`.
- `RECORDED_OBJECT_ID_ONLY`: the package pins selected local bytes and records the cited remote Git object identity, but does **not** claim cryptographic membership of those selected bytes in the full remote blob.

The current commissioning source excerpts use `RECORDED_OBJECT_ID_ONLY`. This is a deliberate claim reduction, not a weaker hidden implementation.

Case 003 also retains connector-normalized public issue/PR snapshots and selected official-documentation snapshots as separately typed artifacts. Deterministic assertions over those snapshots are linked to the semantic interpretation documents consumed by the case. A connector-normalized or selected-docs snapshot is **not** described as a raw HTTP archive.

This gives four explicit epistemic layers:

```text
recorded upstream identity / typed retrieval snapshot
                 ↓
           pinned local bytes
                 ↓
       deterministic extracted facts
                 ↓
       semantic interpretation / model
```

Only the relevant lower-layer facts are copied into the frozen core where the adapter pins them. The provenance gate is not itself a semantic oracle.
