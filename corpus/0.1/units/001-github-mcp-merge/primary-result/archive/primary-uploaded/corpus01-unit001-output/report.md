# RISU Verify — Preserved

**Case:** Prospective Corpus 0.1 - corpus01-unit-001 - corpus01-001-github-mcp-merge-current  
**Action:** GitHub MCP · merge_pull_request  
**Assurance integrity:** PASS  
**Frozen core:** v0.7.0 · pin verified  
**Certificate:** independently checked · `ac57a340d5300602bb7655a5bd16f559c35bd751011a09bb5e071d69cfeca138`

## Declared consequence

Merge the reviewed head; if the request-time head differs from the reviewed head, reject the stale request.

## Why this matters

A pull request can change after review but before the merge effect. Preserving the visible head is not enough if the effect path is not bound to the reviewed head.

## Bounded consequence check

| Otherwise mergeable | Request Head Sha | Required | Projected effect | Match |
| --- | --- | --- | --- | --- |
| true | H0 | MERGED_REVIEWED_HEAD | MERGED_REVIEWED_HEAD | yes |
| true | H1 | STALE_REQUEST_REJECTED | STALE_REQUEST_REJECTED | yes |

**Verified finding.** Every admitted realization in the declared profile maps to the required consequence, with `C1 / D1 / O1` and Exact Realization established.

## Technical proof surface

- Structural: `C1 / D1 / O1` — `STRUCTURAL_ASSURANCE_ESTABLISHED`
- Exact Realization: `REALIZATION_ESTABLISHED` — `NONE`
- Coverage complete in declared profile: `true`
- Core archive SHA-256: `bc3c0be440b1b729d3131a630491cce62f1f885fb305aa46a4483fee0adad72f`
- Source contract SHA-256: `4b80861fc7aa28891fc3d1590cc8ae7a6e95b249e5791ae61c654d398e524925`
- Adapter digest: `06479e052110de3d7d4f806827558b35d86e39346eb7a7d3bfbc1fb59da6d9cd`
- Proof digest: `23a6f2dc76c0bd7a99f76b973bf6cadacfa542852e18feac0e740798ab84ae8c`

## Repair

**Suggested implementation direction (not certified):** Bind the merge effect to the reviewed head SHA, or perform an equivalent effect-time revalidation that rejects a changed head.

## Claim boundary

The human report is a derived convenience artifact. The proof-carrying certificate and independent consumer check are authoritative for the model-relative v0.7 result. This run does not establish live-runtime conformance, real-system model completeness, or independent reproduction unless separately evidenced.
