# RISU Verify → Browser Workbench handoff

RISU Verify produces proof-carrying run artifacts on disk. The Browser Workbench is an independent, browser-local consumer of those already-produced artifacts. This handoff layer removes the manual step of selecting several files without changing the assurance boundary.

## One run, one file

After a RISU Verify run, package its output directory:

```bash
./risu-workbench run \
  .risu/out/<case-id> \
  --output <case-id>.risu.json
```

The resulting `.risu.json` file embeds the exact bytes of:

- `report.json`
- `certificate.json`
- `run-manifest.json`
- `report.md`, `producer.log`, and `consumer.log` when present

Each embedded artifact is content-addressed by SHA-256. The bundle also commits to the ordered artifact descriptors with `artifact_manifest_sha256`.

The exporter refuses to package a run if the report, certificate, and run manifest disagree on their recorded hashes, case identity, or frozen-core identity. This is packaging validation only. It does **not** rerun the frozen scientific producer or independent certificate checker and does not issue a new verdict.

Open the public Workbench and drop the single bundle:

```text
https://risuinstitute.org/tools/#workbench
```

The Workbench verifies the bundle manifest, rehashes every embedded artifact, reconstructs the existing report/certificate/run-manifest cross-checks, and then renders the result.

## Compare two runs

For baseline/current or before/after analysis:

```bash
./risu-workbench compare \
  .risu/out/<baseline-case> \
  .risu/out/<current-case> \
  --output transition.risu-compare.json
```

The comparison bundle embeds two independently checkable run bundles. The Workbench reports whether both runs carry the same `source_semantic_digest`.

- `SAME_DECLARED_SOURCE_SEMANTICS` permits a focused before/after reading of the projection result.
- `SOURCE_SEMANTIC_COMMITMENT_CHANGED` is surfaced as a warning. The runs can still be inspected, but the interface does not present the change as a pure projection repair under an unchanged source consequence.

## CI handoff

A CI job can preserve the same `.risu.json` object as a downloadable build artifact. The visible `GITHUB_ACTION_WORKFLOW_TEMPLATE.yml` includes an example using `actions/upload-artifact`.

This creates one continuous path:

```text
RISU Verify producer/checker
        ↓
proof-carrying run artifacts
        ↓
content-addressed .risu.json handoff
        ↓
CI artifact or local file
        ↓
Browser Workbench independent consumer
```

## Boundary

The handoff bundle is a transport object, not a RISU assurance certificate. The authoritative scientific verdict remains the result produced by the frozen core and independently checked certificate. The browser consumer performs local consistency, digest, and result-surface checks over those artifacts.
