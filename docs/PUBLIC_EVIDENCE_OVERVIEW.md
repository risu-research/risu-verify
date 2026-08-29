# RISU Verify — Public Evidence Overview

## In 30 seconds

An agent-facing tool can look unchanged while losing a distinction that matters to what the action actually does. RISU Verify checks a narrower question than general security or API compatibility: **does the declared consequence-relevant distinction survive the projection into the action the agent can use?**

The current release is built around a frozen scientific core and a fail-closed evidence path. It retains external positive and negative controls, reproduces one real GitHub MCP bug-to-repair transition under the same bounded consequence contract, and extracts a development **Version-Bound Effect** profile that differentially reproduces the retained cases without gaining verdict authority.

The strongest current evidence is not one headline number. It is the combination of **formal separation of C/D/O, proof-carrying certificates checked by an independent consumer, external software cases, provenance replay, hostile release-audit tests, a natural historical transition, and a reusable profile whose outputs are checked against the legacy cases**.

## What the release establishes

| Evidence | What it supports | Important boundary |
| --- | --- | --- |
| Frozen v0.7 core | The product uses a byte-pinned scientific substrate rather than reimplementing the formal verdict logic | Model-relative assurance only |
| GitHub guarded merge | Certificate-backed consequence regression with C1/D1/O0 | Historical commissioning control, not live deployment certification |
| Azure DevOps Wiki ETag | Certificate-backed preservation with C1/D1/O1 in a declared existing-page edit slice | Narrow scope; wider tool behavior is not claimed |
| GitHub `create_or_update_file` before/after #2134 | Real historical transition from non-preservation to preservation under a byte-identical source consequence contract | Known historical case; not independent bug discovery |
| Evidence-strength ablation | Structural C0 before #2134 does not directly depend on the public issue report, while the stronger Exact contradiction does | Makes the evidence dependency explicit rather than hiding it |
| Version-Bound Effect profile | One carrier-neutral development profile differentially reproduces 4 retained calibration cells | Calibration, not prospective generalization |
| Prospective Corpus 0.1 protocol | The next empirical round has fixed selection/reporting rules before Case 004 screening | Public timestamp still required before screening opens |

## The historical transition in one picture

```text
GitHub MCP · create_or_update_file

BEFORE PR #2134
caller-reviewed value: blob SHA
operative validator: HTTP ETag

CONSEQUENCE_REGRESSION
C0 / D NA / O NA
Exact: REALIZATION_CONTRADICTED

                 ↓ same source consequence contract

AFTER PR #2134
current blob SHA obtained from Contents API
caller-reviewed blob SHA compared to current blob SHA

PRESERVED
C1 / D1 / O1
Exact: REALIZATION_ESTABLISHED
```

The pair is classified `REPAIR_CONSISTENT_HISTORICAL_TRANSITION`. That label is intentionally narrower than “the PR fixed the whole issue” or “RISU reproduced GitHub's live service.”

## Why the Version-Bound Effect profile matters

The first three external examples use different carriers — reviewed Git head SHA, Azure Wiki ETag, and Git blob SHA — but share a recurring semantic question:

```text
reviewed_version
       ↓
current_version_at_effect
       ↓
consequential effect

same version      → declared effect may proceed
changed version   → declared stale consequence must occur
```

RISU now represents that pattern as a **development-only** authoring profile. The profile/compiler is outside the scientific trusted computing base: it can prepare artifacts, but it cannot issue `PRESERVED` or `CONSEQUENCE_REGRESSION`. Those statuses still come only from the frozen producer and independent certificate consumer.

## What RISU Verify does not claim

This release does not claim general AI-agent safety, universal MCP correctness, representative ecosystem prevalence, live-runtime certification, complete source-model adequacy, independent third-party reproduction, or prospective generalization of the VBE profile. The next prospective corpus is designed specifically to test transfer beyond the retained calibration cases.

## Verify the evidence map

The concise claims above are mirrored in `EVIDENCE_INDEX.json`. Each claim points to exact local artifacts and their SHA-256 values and includes machine-checked semantic assertions.

```sh
python tools/evidence_index_verify.py
```

For package integrity and provenance replay:

```sh
python tools/release_verify.py
```

For full scientific reproduction:

```sh
./reproduce-release.sh
```
