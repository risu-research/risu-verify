# Corpus 0.1 infrastructure v0.8

Infrastructure v0.8 is a **protocol-preserving execution layer**, not a new scientific protocol. `PROSPECTIVE_CORPUS_0.1` remains unchanged.

Its purpose is to remove the mechanical failure modes exposed by Unit 001 while refusing to automate scientific judgment.

## What changed

### 1. Explicit-bound-evidence compilation

`tools/corpus01_bound_evidence.py` turns the compiled evidence surface into an allowlist rather than an inheritance surface.

For every carrier-envelope binding:

- `EVIDENCE` must map one-to-one by SHA-256 to bytes already frozen in `PRIMARY_RUN_MANIFEST.json`;
- `QUALIFICATION` must use an explicit `SEALED_*` role and already exist with the exact declared digest;
- any inherited file under `assurance/evidence/` or `assurance/qualification/` that is not explicitly bound is removed before the primary verifier;
- `adapter.json` and `source-contract.json` are hashed before and after, and any mutation is fatal.

This addresses the general class of scaffold-contamination risk without modifying source semantics, target semantics, worlds, or verdict logic.

### 2. Complete report-metadata sanitation

The v0.8 primary runner no longer allows retained scaffolds to supply current human-report identity or scope.

- inherited `display` is removed;
- `external_system` comes only from the frozen `TARGET_LANE.json`;
- `claim_boundary` comes only from the frozen `BOUNDARY_MODEL.json`;
- semantic adapter and source-contract bytes must remain identical.

The report remains a convenience layer. The certificate remains authoritative.

### 3. One-command mechanical seal

After the scientific records are `AUTHOR_ACCEPTED`, committed, and the working tree is clean:

```bash
python tools/corpus01_seal.py corpus/0.1/units/<unit>
```

The command:

1. requires the freeze commit to equal the clean current `HEAD`;
2. runs the read-only unit audit;
3. generates `PRIMARY_RUN_MANIFEST.json` hashes from frozen Git bytes;
4. runs the existing freeze gate;
5. performs a temporary prospective compile;
6. applies current TARGET/BOUNDARY report sanitation;
7. applies explicit-bound-evidence compilation;
8. runs provenance reachability preflight;
9. writes `UNIT_SEAL.json` pinning the generated manifest.

It **does not execute `risu-verify`**, does not observe a semantic outcome, and does not change scientific input bytes.

The generated manifest and seal are then committed. No hash in the primary sealing/execution path should be hand-edited.

### 4. Sealed generic primary

`.github/workflows/corpus-0.1-generic-primary.yml` remains manual-dispatch only but now invokes `tools/corpus01_primary_v08.py`.

A primary is refused unless the committed seal exactly pins the committed manifest.

Execution order is:

1. verify seal;
2. read-only audit;
3. Corpus procedural validator;
4. AUTHOR_ACCEPTED freeze gate;
5. retained-case materialization;
6. prospective compilation;
7. TARGET/BOUNDARY report sanitation;
8. explicit-bound-evidence compilation;
9. provenance preflight;
10. frozen RISU verifier;
11. observation sealing;
12. complete compiled-case + verifier-output deterministic archive.

Semantic exits `0`, `10`, and `20` remain equally valid scientific outcomes. Infrastructure does not prefer `PRESERVED`.

## Why this is stronger than auto-repair

A tempting design would add missing provenance edges, infer evidence bindings, or repair target semantics automatically. v0.8 deliberately does not do that.

If a declared scientific record is incomplete or inconsistent, the machinery stops before the primary. The infrastructure can say **where** the record is mechanically incomplete; it cannot decide **what the scientific answer ought to be**.

That preserves the main asset created in Unit 001: prospective integrity.

## Qualification strategy

Unit 001 remains permanently CLOSED and is never rerun as a new scientific primary.

Instead, v0.8 uses it in two read-only ways:

- the original pre-overlay envelope must still reproduce exactly the two historical provenance blockers, proving the detector has not forgotten a real failure mode;
- the already-recorded pre-verdict provenance overlay may be used only in a temporary compile probe to test the new explicit-bound-evidence sandbox and provenance preflight without observing a new semantic verdict.

Unit tests separately attack duplicate-SHA ambiguity, inherited unbound evidence, report-metadata contamination, semantic-file mutation, and seal/manifest drift.

## Versioning rule

Scientific protocol version and infrastructure version are independent.

A future infrastructure v0.9 may improve hashing, packaging, ergonomics, or deterministic execution without changing the Corpus scientific rules. Any change that alters source semantics, target interpretation, admissible worlds, effect cut, evidence-strength rules, or verdict semantics requires a scientific-protocol change instead.

## Next gate

After v0.8 qualifies on PR head and again on `main`, the next experiment is **Unit 002-M paired mutation control**:

- positive controls: deliberately remove consequential distinctions that RISU should detect;
- negative controls: change schema-compatible but consequence-irrelevant presentation/refactor details that RISU should ignore.

The promotion criterion is therefore not merely sensitivity. It is **sensitivity with specificity** before any new real prospective target is hunted in Unit 002-R.
