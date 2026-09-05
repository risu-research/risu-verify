# Corpus 0.1 protocol-preserving infrastructure

## Purpose

Unit 001 showed that the dominant avoidable friction was not the scientific question itself. It was the mechanical layer around a frozen scientific record: hand-entered hashes, cross-file consistency, provenance reachability, Unit-specific workflow wiring, diagnostic exposure, inherited scaffold metadata, and incomplete artifact packaging.

This infrastructure therefore automates **mechanics, not judgment**.

The scientific boundary remains human/researcher controlled:

- SOURCE consequence semantics;
- TARGET facts and mechanism interpretation;
- bounded worlds and admissibility;
- effect cut;
- evidence-strength labels;
- target pattern selection;
- AUTHOR_ACCEPTED.

The harness may validate those declarations. It may not invent, strengthen, or repair them after freeze.

## Architecture

`tools/corpus01_unit_harness.py` has three deliberately separated surfaces.

### `audit`

A read-only preflight. It checks:

- unit/candidate identity consistency;
- SOURCE ↔ BOUNDARY world equivalence;
- coordinate consistency;
- TARGET carrier consistency;
- pinned TARGET revision consistency;
- evidence file SHA-256 integrity;
- empirical-evidence ↔ envelope binding coverage;
- empirical vs methodological-qualification separation;
- provenance reachability of every `ESTABLISHED` derivation fact to the EXACT claim;
- a compile probe using the existing VBE compiler.

It never executes a primary verifier.

### `build-manifest`

This removes the Unit 001 checksum-entry failure mode. After AUTHOR_ACCEPTED has been committed, it reads the frozen bytes directly from Git, verifies the current bytes equal the chosen freeze commit, and computes the primary-run manifest hashes mechanically.

It refuses to run if `audit` has semantic/provenance blockers. It does not repair them.

### `run`

A manifest-driven generic primary harness. No Unit-specific workflow code is needed.

Order:

1. read-only unit audit;
2. Corpus procedural validator;
3. AUTHOR_ACCEPTED freeze gate;
4. retained-case materialization;
5. prospective compilation;
6. report-only scaffold metadata sanitation from frozen TARGET identity;
7. exact-SHA empirical evidence placement;
8. compiled provenance preflight;
9. frozen RISU verifier;
10. primary observation sealing;
11. full-tree artifact manifest;
12. deterministic self-contained archive.

Semantic verifier exits `0`, `10`, and `20` are all valid scientific outcomes and therefore return harness success. Other exits are infrastructure failures; console output and `failure.log`, when present, are surfaced and retained by the workflow's `always()` upload.

## Why metadata sanitation is allowed

The retained VBE scaffold can contain historical `display` / `external_system` fields. Unit 001 demonstrated that allowing those fields to survive silently can produce stale human-report metadata.

The harness removes inherited `display` data and binds `external_system` identity only from the frozen TARGET lane. Before and after sanitation it hashes `assurance/adapter.json` and `assurance/source-contract.json` and refuses to proceed if either changes. This makes the operation explicitly report-only.

## Archival rule

The generic runner creates a deterministic ZIP whose payload contains:

- the **complete compiled case tree**;
- the complete verifier output tree;
- console output;
- semantic exit code;
- primary observation;
- `BUNDLE.json`;
- `MANIFEST.sha256`.

ZIP entry order, timestamps, and file modes are normalized. The bundle is therefore content-addressable and reproducible from identical payload bytes.

## Unit 001 as calibration, not a template verdict

Unit 001 is CLOSED and remains immutable. The infrastructure does not fix it.

Instead, CI recompiles its already-accepted inputs in a temporary directory and requires the new preflight to rediscover exactly the two provenance gaps that caused the historical invalid execution:

- `GH_U001_EXPECTED_HEAD_INPUT`;
- `GH_U001_LIBRARY_PIN`.

That is a falsification test for the infrastructure itself: if the harness can no longer see the known historical defect, it must not be promoted for later units.

The stale scaffold projection ref is also observed, but it is nonblocking because the generic harness deterministically sanitizes report-only metadata before a future primary verifier is invoked.

## Explicit non-goals

This first infrastructure tranche intentionally does **not** automate source-contract extraction, target semantic interpretation, evidence acquisition from arbitrary upstream repositories, world selection, or target-pattern choice. Unit 001 alone is insufficient evidence that those authoring structures are stable enough to automate safely.

Those surfaces may be promoted only after repeated friction across later units establishes a stable mechanical pattern.
