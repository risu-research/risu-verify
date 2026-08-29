# RISU Verify

**v0.4.0-rc1 · consequence assurance for agent-facing projections**

> An agent-facing tool can keep the same name and schema while losing a distinction that changes what the action can actually do. RISU Verify checks whether a **declared consequence-relevant distinction** survives that projection.

RISU Verify is a developer-facing assurance layer over the frozen **Consequence-Preserving Projections v0.7.0** core. The current release includes external preservation/regression controls, one real GitHub historical bug-to-repair transition, audit-hardened provenance, and the development **Version-Bound Effect (VBE)** profile.

## Public chronology

The exact `PROSPECTIVE_CORPUS_0.1_PROTOCOL.json` was the repository's first commit, before Corpus 0.1 candidate screening. The public root commit is:

```text
3316528f22599c808262d10c2c451df672b1cba0
Seal Prospective Corpus 0.1 protocol before screening
2026-08-29T01:51:24Z
GitHub signature: verified
```

The sealed protocol itself is not edited after publication. The later publication event is recorded separately in [`protocols/EXTERNAL_TIMESTAMP_RECORD_001.json`](protocols/EXTERNAL_TIMESTAMP_RECORD_001.json).

## Canonical audited release vs. this GitHub tree

This repository uses a **compact browser edition** so the source can be uploaded and reviewed without GitHub's 100-file web-upload limit or hidden-file handling. It keeps the source, profile compiler, schemas, documentation, tests, and three content-addressed exact case bundles visible.

The authoritative audited release is the immutable archive:

```text
RISU_Verify_v0.4.0-rc1_Profile_Driven_Evidence_Indexed_Final.zip
SHA-256: df06e8d6a8b072333355e1ef91b80c30e43fa68d6fc4666dd920a3fc0e46fc6f
Manifested files: 183
```

That full archive is the object to attach to the GitHub Release and archive on Zenodo. It contains the exact release manifest, release verifier, active CI configuration, qualification bundles, full evidence snapshots, and machine-verifiable evidence index. See [`CANONICAL_RELEASE.json`](CANONICAL_RELEASE.json).

## Restore the exact case trees

The canonical case directories are stored as three content-addressed bundles under `case-bundles/`. To materialize them locally:

```bash
python tools/materialize_case_bundles.py
```

The materializer verifies each bundle SHA-256, performs safe extraction, and checks the expected file count. It recreates:

```text
cases/github-guarded-merge
cases/azure-devops-wiki-etag
cases/github-create-update-sha-transition
```

Then the semantic paths can be exercised directly:

```bash
python src/risu_verify.py verify cases/github-create-update-sha-transition/before
python src/risu_verify.py verify cases/github-create-update-sha-transition/after
python tools/vbe_differential.py
bash tests/semantic_ci_demo.sh
bash tests/historical_transition_demo.sh
```

## Commissioning record

| Case | Role | Result |
| --- | --- | --- |
| GitHub guarded merge | historical negative control | `CONSEQUENCE_REGRESSION` · C1/D1/O0 |
| Azure DevOps wiki edit | external positive control | `PRESERVED` · C1/D1/O1 |
| GitHub file update BEFORE | natural historical revision | `CONSEQUENCE_REGRESSION` · C0/D-NA/O-NA |
| GitHub file update AFTER | same transition after merged repair | `PRESERVED` · C1/D1/O1 |

The historical transition is not presented as independent bug discovery. It is a retrospective validation against independently developed software and public historical evidence. The exact claim boundaries are documented in [`docs/PUBLIC_EVIDENCE_OVERVIEW.md`](docs/PUBLIC_EVIDENCE_OVERVIEW.md).

## Version-Bound Effect profile — development

The VBE profile asks one narrow carrier-neutral question:

> **Does the consequential effect remain bound to the version that was reviewed or otherwise declared authoritative for that effect?**

Its semantic tuple is:

```text
(reviewed_version, current_version_at_effect, effect, mismatch_consequence, binding_mechanism)
```

The profile compiler is an untrusted authoring convenience layer. It does **not** decide C/D/O, Exact Realization, or the product verdict. Those remain functions of the frozen v0.7 assurance path. Four retained calibration cells are differentially replayed in [`results/VBE_CALIBRATION_DIFFERENTIAL.json`](results/VBE_CALIBRATION_DIFFERENTIAL.json).

## Repository workflow

`GITHUB_ACTION_WORKFLOW_TEMPLATE.yml` is intentionally visible rather than stored under a hidden `.github/` path in this browser-upload edition. It first materializes the content-addressed case bundles, then runs provenance replay, VBE differential calibration, the semantic-CI demonstration, and the historical-transition demonstration.

For the exact 180-check release qualification and exact-file-set verification, use the **canonical release archive**, not this compact GitHub layout.

## Boundaries

RISU Verify provides bounded, model-relative consequence assurance. It does not establish general agent safety, whole-operation correctness, live-runtime conformance, representative ecosystem prevalence, or completeness of a declared consequence model. The development VBE profile has been calibrated on retained cases; prospective generalization is intentionally reserved for Corpus 0.1.

## License and citation

Apache-2.0. See [`LICENSE`](LICENSE), [`NOTICE`](NOTICE), [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md), and [`CITATION.cff`](CITATION.cff).
