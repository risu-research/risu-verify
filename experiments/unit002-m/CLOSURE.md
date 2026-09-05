# Unit 002-M — Closure Record

## Final status

**CLOSED when this record is present on `main` and the final main gates pass.**

Unit 002-M is the prospectively frozen paired mutation-control experiment used to qualify RISU Verify's detector before any Unit 002-R real-target hunt.

The canonical scientific result remains GitHub Actions Run `33943444386`. Later runs are deterministic replay/qualification witnesses and never replace that canonical result.

## What was prospectively fixed

The mutation-control PLAN was committed before detector output at commit `cecaf792cb131f022a1c7bcdd3ab12c0968a409f`, Git blob `958bf01dbf89d338aa0f59a5d892127d65704222`, SHA-256 `735e5ce1e4523f965798bcab94a29a834291254a3fbda8494ad40525a192e913`.

The frozen matrix used two already-qualified preserving seeds. Each seed received three semantic-loss positive mutations and three nonsemantic negative mutations, with two verifier repetitions per mutation and two baseline repetitions per seed.

## Canonical result

Canonical Run `33943444386` was the first valid execution eligible after the explicitly recorded locality-representation correction. It produced:

- baseline validity: **2/2**
- positive sensitivity: **6/6**
- negative specificity: **6/6**
- false semantic alarms: **0**
- regression witness localization: **4/4**
- discriminator-collapse detection: **2/2**
- deterministic repeatability: **12/12**
- source-contract invariance: **12/12**
- mutation locality: **12/12**

Canonical Actions artifact: `9962563353`  
Artifact ZIP SHA-256: `46d31d919db3bd3d3da163053f1853b81243f4a974495cad804a72ec5c8da064`

The durable `CANONICAL_RESULT.json` stores the per-cell certificate SHA-256, proof digest, outcome, discriminator state, exact-realization state, witness identity, and repeat identity.

## Audit trail

Two early post-freeze implementation attempts were retained as invalid diagnostics rather than silently discarded or reclassified. A later complete run exposed a locality-checker representation defect: replacing a declared JSON subtree generated multiple descendant leaf deltas, while the checker incorrectly required equality with the parent path. `IMPLEMENTATION_CORRECTION_001.json` records the diagnosis and limits the correction strictly to locality representation. The PLAN, mutation bytes, seeds, semantic predicates, repetition counts, and promotion thresholds were not changed.

## Archival replay before merge

At PR-head `aef262bf1fa62e0d9ed1aec9e11e8adbfb174c67`, Run `33943769432` independently re-executed the full matrix and required every canonical proof identity to match Run `33943444386`. The canonical static record, matrix replay, and proof-identity equality gates all passed.

Replay artifact: `9962660475`  
Replay ZIP SHA-256: `3d15cbeaaf69427cafac6f93bc25d2b26bcc7b4c7fa0ffc30e5f0cd4964751ff`

At the same PR head, public semantic smoke, Corpus infrastructure, and Corpus infrastructure v0.8 also passed.

## Merge and merged-main replay

PR #4 was merged with expected-head protection on `aef262bf1fa62e0d9ed1aec9e11e8adbfb174c67`.

Merge commit: `f3f1db0ad806e0abd051ecfe23ffbcbf039ad117`

On that exact `main` commit:

- Corpus infrastructure v0.8 Run `33944438918`: **SUCCESS**
- Unit 002-M replay Run `33944438933`: **SUCCESS**
- Corpus infrastructure Run `33944438952`: **SUCCESS**
- Public semantic smoke Run `33944438961`: **SUCCESS**

The Unit 002-M merged-main run again passed PLAN freeze identity, canonical-record integrity, full 28-run replay, and canonical proof-identity equality.

Merged-main replay artifact: `9962868402`  
Replay ZIP SHA-256: `cb33169ae614285dd2f4bfc12b95b944dfac4465966d7cdeddc081e73e5c9234`

## What this establishes

Within the exact frozen control boundary, RISU Verify detected all six predeclared semantic-loss mutants, ignored all six predeclared nonsemantic mutants, localized all four required regression witnesses, and reproduced the same semantic/proof identities across deterministic replays.

It does **not** establish universal detector accuracy, real-world prevalence, arbitrary live-runtime conformance, safety of an external system, carrier neutrality beyond separately tested carriers, or independent replication.

## Next scientific gate

The next gate is **Unit 002-R — real prospective falsification**. Target selection must be frozen independently of Unit 002-M outcomes. `PRESERVED`, `CONSEQUENCE_REGRESSION`, and `INCOMPLETE_ASSURANCE` are all admissible scientific outcomes; target selection may not be optimized for any one of them.
