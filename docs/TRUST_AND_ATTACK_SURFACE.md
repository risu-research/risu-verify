# Trust and Attack Surface — v0.4.0-rc1

## Scientific TCB

The scientific trusted computing base remains the frozen **Consequence-Preserving Projections v0.7.0** archive pinned by SHA-256 in `CORE_PIN.json`, together with the case artifacts and evidence that the frozen producer/consumer require under the declared model.

RISU Verify itself is a convenience and orchestration layer. It may refuse to run, render results, compare locks, or validate provenance, but it cannot author a substitute certificate or upgrade a v0.7 result.

## Fail-closed product integrity gates

Before a semantic result is accepted, the product requires:

1. frozen-core archive pin;
2. case provenance-manifest pin when declared;
3. evidence-byte pins and deterministic extraction;
4. structural semantic/core-binding provenance links when declared;
5. predeclaration or predeclaration-seal pin when declared;
6. v0.7 producer completion;
7. independent v0.7 consumer acceptance.

Failure in any integrity gate exits 30 rather than becoming a semantic status.

## Authority separation

- `case.json` display/narrative fields cannot vote on `PRESERVED` or `CONSEQUENCE_REGRESSION`.
- Human reports are derived convenience artifacts, not certificates.
- Semantic locks commit previously certificate-backed results; they cannot raise assurance.
- Public issue/PR text can be evidence only under its predeclared epistemic role; it cannot directly set C/D/O/Exact.
- Suggested implementation directions remain non-certified unless the frozen core explicitly certifies an obligation.

## Development authoring layer

The Version-Bound Effect profile, `risu init`, and `tools/vbe_compile.py` are outside the scientific TCB. They may reduce authoring friction but may not vote on C/D/O/Exact or manufacture a preserving result. Draft profile instances are not verdict-eligible; explicit human acceptance is required before compilation.

The VBE differential calibration is intentionally retrospective over the retained cases and therefore does **not** establish prospective generalization. The next empirical transfer test is governed by the separately sealed Prospective Corpus 0.1 protocol. Candidate screening remains closed until the protocol receives an external public timestamp.

## Provenance attack surface

v0.3 explicitly tests:

- bundled source-byte mutation;
- provenance manifest mismatch;
- deterministic-extraction mutation;
- semantic-observation substitution even after recomputing the manifest pin;
- mismatch between provenance extraction and the evidence copy consumed by the core;
- predeclaration and amendment mutation;
- before/after assurance revision swap.

The provenance layer does not prove live remote-service behavior or semantic-model truth. Its job is narrower: make the local evidence chain used by assurance reproducible and substitution-resistant.

## Historical-transition attack surface

Case 003 is not outcome-blinded because the public issue/PR identify the transition. The protection is fixed pre-run scope, worlds, source consequence, revisions, evidence roles, and adjudication. Before and after use a byte-identical source contract and are independently certificate checked.

The pair label is deterministic and directional only after both runs. It does not assert that the upstream PR fixed every reported issue.

## Residual risks / nonclaims

- author-declared bounded-model adequacy;
- accuracy/completeness of semantic interpretation beyond pinned evidence premises;
- live runtime conformance;
- representative ecosystem prevalence;
- independent third-party reproduction;
- universal source acquisition;
- general security or safety certification.

## rc2 audit findings now enforced

rc2 explicitly rejects unmanifested package files, pins the test/reproduction executables in `TOOLCHAIN_SEAL.json`, and actually replays provenance inside the fast release verifier. Stored qualification summaries are integrity records, not replay claims.

Upstream Git provenance also carries an explicit binding mode. The current selected source excerpts use `RECORDED_OBJECT_ID_ONLY`; the package records the cited remote Git object identity but does not claim that an excerpt alone cryptographically proves membership in the full remote blob. `tools/provenance_verify.py` additionally supports `FULL_GIT_BLOB`, which recomputes the Git blob ID if a future case bundles the complete blob bytes.

Case 003's original pre-run amendment remains sealed unchanged. `POST_RUN_AUDIT_001.json` records the stricter later assessment that the amendment substantively expanded the admissible empirical-evidence role for Exact. It also records that the original predeclaration lacked an independent external timestamp.
