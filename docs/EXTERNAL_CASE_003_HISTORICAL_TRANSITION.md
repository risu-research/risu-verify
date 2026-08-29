# External Case 003 — GitHub `create_or_update_file` natural historical transition

## Question

For an existing regular-file update where the caller supplies the blob SHA of the version it reviewed, does the agent-facing projection preserve this consequence?

> Commit the update only if the current file is still that reviewed blob version; otherwise reject the stale update.

## Why this case is different

Cases 001 and 002 are commissioning controls. Case 003 evaluates a **real upstream before/after transition** identified independently of RISU: GitHub issue #2133 reported SHA validation that mixed blob-SHA input with HTTP ETag semantics, and merged PR #2134 changed the implementation to read the current blob SHA from Contents API metadata and compare like with like.

The public issue and PR motivate revision selection. They do not vote on the RISU result.

## Frozen revisions

Before:

- repository: `github/github-mcp-server`
- PR base revision: `b50a343da5d03fb9454062377792a6b54631a84d`
- file: `pkg/github/repositories.go`
- Git blob: `a236609bc6699069e6f9bcd704ea6b2bedfdab46`

After:

- merge commit: `ccb9b5308d705465d4619164083667b720df7279`
- same file
- Git blob: `6eab707f958534228baca5ce3fde770f548b0ee8`

## Predeclared scope

Included:

- existing regular file;
- caller supplies reviewed blob SHA `S0`;
- effect-time current blob SHA is bounded to `S0` or `S1`;
- single-segment path;
- other authentication, permission, encoding, branch, and transport failures held non-material.

Excluded:

- new-file creation;
- omitted-SHA behavior;
- the separate multi-segment `PathEscape` problem;
- the separate blind-update ETag-as-SHA path;
- connection/body-close issues;
- the later optional-SHA schema/acquisition issue;
- live GitHub deployment conformance.

Base predeclaration SHA-256:

`d52e0760d02bd3b80e998436a022d42d55a1c41f374de1df7babc952418fd668`

A separately sealed pre-run amendment only clarifies that issue #2133 may be used as a historical empirical observation about the reported ETag/blob-SHA mismatch and spurious rejection. It cannot define the consequence contract, worlds, or verdict.

## Shared source consequence contract

Before and after use byte-identical `source-contract.json`:

`09825b375d92e17faa3146eddeb403a65d8cba9f75cffc02b326fef764508437`

Worlds:

| Current blob | Required consequence |
| --- | --- |
| `S0` | `UPDATE_COMMITTED` |
| `S1` | `STALE_UPDATE_REJECTED` |

## Observed BEFORE result

```text
CONSEQUENCE REGRESSION
C0 / D NA / O NA
CORRESPONDENCE_NOT_ESTABLISHED
REALIZATION_CONTRADICTED
OPERATIVE_INSUFFICIENCY
```

The before model does not pretend an HTTP ETag is a valid corresponding carrier for a declared blob-SHA version fact. Exact realization additionally produces a collapsed-signature witness:

```text
{ validator_kind: HTTP_ETAG, supplied_value: S0 }
```

for both the `S0` and `S1` current-blob worlds. In the reported pre-fix behavior this makes the valid-current-blob world reject instead of commit.

## Observed AFTER result

```text
PRESERVED
C1 / D1 / O1
STRUCTURAL_ASSURANCE_ESTABLISHED
REALIZATION_ESTABLISHED
```

The after implementation obtains the current blob SHA from Contents API metadata and compares it against the caller-supplied reviewed blob SHA. The bounded `S0` and `S1` worlds therefore remain distinguishable at the consequential cut.

## Pair result

`tools/historical_transition.py` derives:

```text
REPAIR_CONSISTENT_HISTORICAL_TRANSITION
CONSEQUENCE_REGRESSION → PRESERVED
C0 → C1
D NA → D1
O NA → O1
REALIZATION_CONTRADICTED → REALIZATION_ESTABLISHED
```

This label means only that the pinned after revision is preserving where the pinned before revision is non-preserving under the same declared bounded consequence contract. It is not a claim that PR #2134 fixed every bug in issue #2133.
