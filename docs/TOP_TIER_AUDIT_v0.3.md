# Top-Tier Audit Hardening — v0.3.0-rc2

This release preserves the v0.3.0-rc1 scientific results and the frozen v0.7.0 core. It hardens how those results are packaged, reproduced, and described.

## What the audit changed

The audit found no reason to alter the Case 003 source consequence contract, bounded worlds, revision pins, or before/after core results. It did find three important presentation and release-integrity issues.

First, the rc1 release verifier could report stored provenance and qualification state with wording that sounded like replay. rc2 separates **integrity verification**, **provenance replay**, **recorded qualification artifacts**, and **full reproduction**. Only `./reproduce-release.sh` may claim a full reproduction.

Second, provenance strength is now explicit. Selected upstream source blocks remain locally content-pinned and carry immutable remote Git object identifiers, but unless a full Git blob is bundled and its Git object ID is recomputed, the package does **not** claim cryptographic membership of the selected bytes in that remote blob. Connector-normalized issue/PR snapshots and selected documentation snapshots are also labeled by retrieval class rather than presented as raw HTTP archives.

Third, the original sealed `PREDECLARATION_AMENDMENT_001.json` is preserved byte-for-byte. The later hostile audit concluded that its self-label `EVIDENCE_ROLE_CLARIFICATION_ONLY` understates the practical change: it expanded the admissible empirical-evidence role for the Exact layer. Because the amendment preceded every Case 003 core run and did not modify scope, consequence, worlds, revisions, or adjudication, the historical result remains valid as a **pre-run amended retrospective validation**, not an outcome-blind discovery.

## Evidence-strength split for Case 003

**Structural layer.** The pre-fix source exposes a caller blob-SHA concept but routes validation through HTTP ETag semantics. The post-fix source compares the caller SHA with the current Contents API blob SHA. These source/contract facts support the structural transition from correspondence not established to C1/D1/O1 under the declared bounded model.

**Exact layer.** The pre-fix `REALIZATION_CONTRADICTED` result additionally uses the public historical observation in issue #2133 that legitimate current-SHA updates could be rejected by the ETag-vs-blob-SHA path. rc2 therefore describes this Exact result as **historically corroborated**, not independently discovered.

## Temporal boundary

Case 003's predeclaration and amendment were internally sealed before any frozen-core execution. They were not independently timestamped. rc2 does not retroactively claim otherwise. Future empirical cases should commit the predeclaration to a public immutable revision before evaluation.
