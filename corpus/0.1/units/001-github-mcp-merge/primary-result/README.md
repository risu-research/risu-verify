# Corpus 0.1 — Unit 001 primary result

## Scientific status

The canonical first primary result is **PRESERVED**, bounded to `github/github-mcp-server` `merge_pull_request` at the pinned target revision and only to the guarded invocation in which `expectedHeadSha` is explicitly supplied as reviewed head `H0`.

This does **not** claim safety of unguarded merge calls, all GitHub MCP merge behavior, live deployment conformance, or ecosystem-wide prevalence.

The scientific inputs were frozen before the first valid primary result at commit `355a4b77187d5b2118ac71eae9dec1cadc036847`. The canonical first primary remains GitHub Actions run `33939000332`; it is never replaced by a later run.

## Exact-byte primary archive

The original first-primary Actions artifact is now preserved byte-for-byte in this repository:

- artifact ID: `9961142844`
- raw ZIP SHA-256: `b4bce32ad794e0e356a4bd886084021e49a245c9696c8eca42c32b45dcebe27e`
- certificate SHA-256: `ac57a340d5300602bb7655a5bd16f559c35bd751011a09bb5e071d69cfeca138`
- raw ZIP: `archive/raw/corpus01-unit001-primary.zip`
- every file actually uploaded by that artifact: `archive/primary-uploaded/`

The capture was performed by GitHub Actions run `33941343083`, which downloaded the artifact by immutable artifact ID, verified the raw ZIP SHA-256, verified all **12/12** uploaded entries against their canonical SHA-256 values, and only then committed the bytes. The resulting archival commit is `3fdec7e33d56f43aced09917af6af4299da9a560`.

`ARCHIVE_MANIFEST.json` is the machine-readable archive index.

### Important archival boundary

The first Actions artifact did **not** contain the full compiled-case runtime tree, even though that tree existed during the original verifier execution. This repository therefore preserves all bytes that were actually uploaded but does not invent or regenerate the omitted runtime tree. The limitation remains recorded as `U001-AUDIT-002` in `POST_RESULT_AUDIT.json`.

## Deterministic replay witness

Run `33939366714` remains a **post-result deterministic replay witness**, never a replacement primary and not an independent replication.

Its raw artifact is preserved at `archive/raw/corpus01-unit001-replay.zip`. Across the 12 uploaded entries, 10 are byte-identical to the first primary. The two differing entries are the run-specific observation wrapper and its checksum manifest. `DETERMINISTIC_REPLAY.json` records the exact comparison.

## Closure state

`CLOSURE.json` is the authoritative closure ledger. It may become `CLOSED` only after:

1. the exact final PR head passes the Corpus 0.1 procedural validator;
2. the Unit 001 archive verifier passes;
3. the public semantic smoke passes without invoking a new Unit 001 primary;
4. PR #1 is merged without head drift; and
5. the merge SHA and final CI run identity are recorded on `main`.

The auto-triggering Unit 001 primary workflow remains retired. Archival and CI work do not alter the frozen scientific result.
