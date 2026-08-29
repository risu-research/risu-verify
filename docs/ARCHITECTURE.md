# Architecture — RISU Verify v0.4.0-rc1

## Design objective

Turn the frozen Projection Assurance substrate into repeatable developer CI and reproducible external-software validation **without enlarging the v0.7 scientific trusted computing base**.

v0.3/rc2 added evidence-provenance replay, a natural historical before/after transition, and release-integrity hardening. v0.4 adds a development Version-Bound Effect authoring profile and a sealed prospective-corpus protocol. None of these additions changes the frozen scientific core.

## Layer 0 — frozen scientific substrate

`vendor/Consequence_Preserving_Projections_Software_v0.7.0_DOI_READY.zip`

The archive is byte-for-byte pinned in `CORE_PIN.json`. RISU Verify checks SHA-256 before extraction and executes the core from a fresh temporary directory. It never patches the core.

## Layer 1 — provenance and case integrity

A provenance-enabled case pins `PROVENANCE_MANIFEST.json` from `case.json`. Before any semantic verdict is accepted, RISU Verify checks:

- local evidence byte SHA-256;
- upstream repository/commit/path/Git-blob identity shape where declared;
- deterministic required/forbidden source assertions;
- exact reproduction of `EXTRACTED_SOURCE_FACTS.json`;
- optional structural links from source assertions to separately labeled semantic-observation IDs;
- optional byte identity between provenance extraction and the derived evidence copy consumed by the frozen core.

A provenance failure is exit 30, never a semantic result.

## Layer 2 — predeclaration and case model

A case supplies `case.json`, a source consequence contract, Projection Adapter, evidence bindings, and qualification artifacts. Commissioning cases may pin a predeclaration or predeclaration seal.

Case 003 uses an immutable base predeclaration plus a separately hashed pre-run evidence-role clarification. The base file is never rewritten after sealing.

Current controls:

- Case 001: GitHub MCP guarded merge — historical negative control.
- Case 002: Microsoft Azure DevOps MCP reviewed-ETag wiki edit slice — external positive control.
- Mutation 002: synthetic ignore-supplied-ETag semantic mutation.
- Case 003 BEFORE: GitHub MCP `create_or_update_file` at PR #2134 base revision.
- Case 003 AFTER: same operation at PR #2134 merge revision, same byte-identical source consequence contract.

## Layer 2.5 — development authoring profile

The Version-Bound Effect profile is a carrier-neutral **authoring convenience layer**, not a verdict engine. A VBE instance supplies reusable semantic commitments while carrier-specific evidence remains in a separate envelope. `tools/vbe_compile.py` may compile accepted authoring material into ordinary case artifacts, but the profile/compiler is outside the scientific trusted computing base and cannot issue an assurance status.

`risu init --profile version-bound-effect` emits `DRAFT_UNVERIFIED` material. Compilation is refused until the author explicitly changes the declaration to `AUTHOR_ACCEPTED`.

Differential calibration over retained Case 001, Case 002, Case 003 BEFORE, and Case 003 AFTER requires the compiled representation to reproduce the legacy source semantic digest, admitted worlds, C/D/O, Exact result, and product status. This is calibration, not prospective generalization.

The separately sealed `PROSPECTIVE_CORPUS_0.1_PROTOCOL.json` fixes the next empirical selection/reporting design before Case 004 screening. Its screening gate remains closed until the exact protocol bytes receive an external public timestamp.

## Layer 3 — frozen producer

The wrapper invokes v0.7 with source-contract, consequence-blind, evidence, signature-grounding, and Exact Realization requirements enabled and requests a proof-carrying certificate.

RISU Verify does not independently implement C, D, O, source compilation, Exact Realization, or proof commitments.

## Layer 4 — independent consumer

Every certificate is immediately checked by the compact v0.7 consumer against the case evidence root. A negative semantic certificate is valid only if this independent check also passes. Consumer failure is an integrity failure.

## Layer 5 — deterministic product derivation

Only after the consumer succeeds does RISU Verify derive product status, terminal/Markdown/JSON output, run manifest, and optional semantic lock. Narrative case metadata cannot vote on product status.

## Layer 6 — semantic locks and transition records

A `PRESERVATION_GATE` lock is allowed only for certificate-backed preserving results. `RESEARCH_REPRODUCTION` records a known non-preserving result only under explicit acceptance.

`tools/historical_transition.py` is a deterministic pair adjudicator over two independently certificate-backed results. It can label a pair repair-consistent only under the rule frozen in `TRANSITION_PROTOCOL.json`; it cannot manufacture a semantic upgrade.

## Why Case 003 matters architecturally

Case 002 proved that a synthetic semantic mutation can flip preservation while visible guard surface remains. Case 003 adds a different evidence class: a real independently developed historical transition.

```text
same source consequence contract
       │
       ├── before #2134 → C0 / Exact contradiction
       │
       └── after  #2134 → C1/D1/O1 / Exact established
```

This moves the product from authored mutation qualification toward validation of external software evolution.

## Deliberate omissions

v0.4 still omits universal source/model acquisition, live runtime replay, representative ecosystem claims, automatic repair application, hosted control planes, certificate registries, prospective VBE generalization, and v0.8 core work. Those remain downstream of the externally timestamped Prospective Corpus 0.1, acquisition-friction evidence, and independent use.

## rc2 release-assurance layer

The scientific trust boundary remains unchanged: only the frozen v0.7 producer/consumer path establishes certificate-backed assurance. rc2 adds a separate release-assurance layer around the convenience tooling:

```text
exact package manifest
      ↓
toolchain seal
      ↓
provenance replay + schemas
      ↓
stored qualification integrity
      ↓
full reproduction entrypoint
      ↓
frozen core evaluations / independent consumers
```

`release_verify.py` is intentionally not described as full scientific reproduction. See `RELEASE_REPRODUCTION_v0.3.md`.
