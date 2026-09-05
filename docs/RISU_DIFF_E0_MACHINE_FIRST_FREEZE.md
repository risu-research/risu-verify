# RISU Diff E0 — Machine-First Freeze Layer

Status: **prospective E0 freeze candidate; Unit003 target-specific semantics remain unconsumed**.

This layer freezes the execution contract between target-specific machine acquisition and the held-out E0 evaluation. It does not add canonical scientific authority to E0.

## Core boundary

The sealed core is target-agnostic and network-free. It consumes one local immutable machine-evidence packet and emits a deterministic semantic artifact set. Target acquisition happens outside this core and must later be provenance-bound before a held-out run is accepted.

`MACHINE_INPUT.json` cannot inject human gold, canonical verdicts, established consequence semantics, authoritative predictions, or an E0 prediction. Every evidence byte must be listed exactly once by safe relative path and SHA-256. Path traversal, duplicate entries, hash mismatch, hidden/unlisted files, and unknown input fields fail with infrastructure exit 20.

## Required semantic outputs

Every valid run emits all eight artifacts, including assurance-incomplete runs:

1. `CIR_CANDIDATE.json`
2. `REFINEMENT_MAP_CANDIDATE.json`
3. `VBE_OBLIGATIONS.json`
4. `E0_PREDICTION.json`
5. `PROBE_PLAN.json`
6. `REFINEMENT_REQUESTS.json`
7. `BASELINE_RESULTS.json`
8. `E0_RUN_MANIFEST.json`

`E0_OUTPUT_SEAL.json` closes SHA-256 over those eight artifacts plus the exact input-packet digest and frozen engine identity.

The optional `E0_EXECUTION_OBSERVATION.json` contains run-specific timing/host data and is deliberately excluded from the semantic seal. This preserves byte-for-byte semantic replay while retaining later burden/runtime measurement.

## E0 behavior frozen here

E0 is deliberately asymmetric and fail-closed.

- Static/name/flow extraction produces candidates only; it cannot self-establish consequence semantics.
- B0/B1/B2 remain non-authoritative.
- Unresolved material roles remain `UNRESOLVED`.
- Missing material semantics produce `E0_PREDICTED_ASSURANCE_INCOMPLETE`.
- Regression requires an independently recheckable concrete witness under the already-qualified foundation.
- Stability requires every frozen material obligation, complete refinement, and nonempty interpretation.
- CEGAR may request minimum target-only evidence; it may not rewrite source science, evaluation metrics, or verdict semantics.
- E0 never emits a canonical Corpus verdict.

At E0, the generic machine-first discovery core does **not** promote static evidence into established consequence semantics. Therefore an unseen target can legitimately produce assurance-incomplete. That is a measured outcome, not a runner failure and not evidence of compatibility.

## Determinism

Semantic JSON uses UTF-8 canonical serialization with sorted keys, compact separators, no wall-clock fields, no randomness, and a terminal newline. Same frozen engine bytes plus same exact packet bytes must reproduce byte-identical semantic artifacts and the same output seal.

## Qualification

The freeze is not effective merely because these files exist. It becomes the Unit003 engine only after:

1. prospective protocol commit remains unchanged;
2. repository Git-object and checkout byte identity pass;
3. the prior E0 foundation remains exact-byte qualified;
4. held-out Unit003–008 remain pristine;
5. all machine-input adversarial gates pass;
6. deterministic replay and tamper/seal gates pass;
7. full E0 regression qualification passes;
8. Corpus enrollment validation remains green;
9. exact tested PR head is guarded-merged;
10. the same qualification passes again on authoritative `main`.

After that main-qualified point, any scoring-affecting change is a new Ei and requires a timed numbered amendment.
