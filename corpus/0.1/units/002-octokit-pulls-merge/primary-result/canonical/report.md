# RISU Verify — Preserved In Declared Scope

**Case:** Prospective Corpus 0.1 - corpus01-unit-002 - corpus01-002-octokit-pulls-merge-current  
**Assurance integrity:** PASS  
**Frozen core:** v0.7.0 · pin verified  
**Certificate:** independently checked · `75cbdba31eb7717ea3b30f084b3b5f77a05cecbd3eeba26a20cb7f55bf38d418`

## Bounded consequence check

| Otherwise Mergeable | Request Head Sha | Required | Projected effect | Match |
| --- | --- | --- | --- | --- |
| true | H0 | MERGED_REVIEWED_HEAD | MERGED_REVIEWED_HEAD | yes |
| true | H1 | STALE_REQUEST_REJECTED | STALE_REQUEST_REJECTED | yes |

**Verified finding.** Every admitted realization in the declared profile maps to the required consequence, with `C1 / D1 / O1` and Exact Realization established.

## Technical proof surface

- Structural: `C1 / D1 / O1` — `STRUCTURAL_ASSURANCE_ESTABLISHED`
- Exact Realization: `REALIZATION_ESTABLISHED` — `NONE`
- Coverage complete in declared profile: `false`
- Core archive SHA-256: `bc3c0be440b1b729d3131a630491cce62f1f885fb305aa46a4483fee0adad72f`
- Source contract SHA-256: `1e330c9cae597798613538d16fada720fd7a607fc178dc7ffe906587e9e16c16`
- Adapter digest: `1f23e1d04fdff4f048e5045a8971b2b77cdd0f795c7fe0c7ce70a4ad6933b543`
- Proof digest: `2018bf3cc824800e73dccf7493306085411859e64883bd3d9d2dca8744db4c85`

## Claim boundary

The human report is a derived convenience artifact. The proof-carrying certificate and independent consumer check are authoritative for the model-relative v0.7 result. This run does not establish live-runtime conformance, real-system model completeness, or independent reproduction unless separately evidenced.
