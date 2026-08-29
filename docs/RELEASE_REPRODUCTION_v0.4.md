# Release Integrity and Scientific Reproduction — v0.4.0-rc1

v0.4 preserves the rc2 distinction between **fast release integrity** and **full scientific reproduction**, then adds profile/prospective and public-evidence coherence checks without moving verdict authority outside the frozen v0.7 producer/consumer path.

## Fast release integrity

```sh
python tools/release_verify.py
```

This command verifies:

- the **exact** package file set against `FULL_PACKAGE_MANIFEST.sha256`;
- every manifested file digest;
- the frozen v0.7.0 core archive pin;
- `TOOLCHAIN_SEAL.json` for the convenience/reproduction executables and schemas;
- actual replay of all four provenance gates;
- development artifact-schema checks;
- sealed commissioning predeclarations and the byte-identical Case 003 source contract;
- semantic-lock internal consistency and policy;
- the versioned historical-transition record;
- the evidence-strength ablation record;
- the Version-Bound Effect profile and 4-cell differential-calibration record;
- the Prospective Corpus 0.1 local seal and closed pre-screening gate;
- the machine-verifiable public `EVIDENCE_INDEX.json`; and
- integrity of stored qualification summaries.

It does **not** silently relabel stored test summaries as freshly replayed tests. Its output therefore says `Recorded qualification artifact` for those records.

## Full scientific reproduction

```sh
./reproduce-release.sh
```

The release-level entrypoint runs the fast integrity verifier and then independently executes:

1. inherited commissioning qualification — 39 checks;
2. provenance/history qualification — 44 checks;
3. release-audit hardening qualification — 27 checks;
4. VBE/profile/prospective qualification — 57 checks;
5. public claim-to-evidence qualification — 13 checks;
6. semantic-CI mutation demonstration;
7. natural historical-transition demonstration; and
8. evidence-strength ablation replay.

The resulting **180 qualification checks** span commissioning, provenance, replay, mutation, release integrity, profile calibration, prospective-protocol controls, evidence indexing, and tamper resistance. They are **not** described as 180 independent semantic experiments.

## Public claim-to-evidence verification

`EVIDENCE_INDEX.json` is intentionally descriptive rather than authoritative. It maps six concise release claims to exact supporting artifacts, SHA-256 values, semantic assertions, and explicit nonclaims.

```sh
python tools/evidence_index_verify.py
```

The verifier checks both artifact identity and selected semantic fields. Rehashing a semantically altered artifact in the index is insufficient if the machine-checked assertion no longer matches.

## CI hierarchy

Pull requests keep the faster semantic-CI path. Pushes to `main`, version tags, and manual dispatch run full release reproduction. This preserves fast developer feedback while keeping the release path stricter than the ordinary PR path.
