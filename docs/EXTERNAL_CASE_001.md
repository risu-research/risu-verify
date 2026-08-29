# External Case 001 — GitHub MCP guarded merge

## Why this is the commissioning case

The case is based on independently developed public software rather than a RISU-authored toy interface:

- target projection: `github/github-mcp-server`, MCP tool `merge_pull_request`;
- source operation library: `google/go-github`, `PullRequests.Merge` / `PullRequestOptions`;
- retained projection evidence ref: `822c87761f8587395b3e1a04b5386b2611252cd1`;
- retained source-library ref: `34349a88bac3`.

The scientific meaning is inherited unchanged from the frozen v0.7.0 release. RISU Verify tests whether that qualified result can survive a product surface without being weakened or overstated.

## Declared consequence

On the bounded guarded-merge profile, the reviewed head is H0. A request made while the head remains H0 may merge the reviewed head. If the request-time head has changed to H1, the declared consequence is stale-request rejection.

## Qualified result

The projection exposes enough information to discriminate H0 and H1 (`D1`), but the operative merge path does not bind the effect to the reviewed head (`O0`). Exact Realization is contradicted by mechanism misalignment.

The minimal product witness is therefore:

| Reviewed | Request-time | Required | Grounded projected effect |
| --- | --- | --- | --- |
| H0 | H0 | merge reviewed head | merge H0 |
| H0 | H1 | reject stale request | merge H1 |

## Current-upstream relevance observation — 2026-08-28

This is deliberately **not** part of the certificate. As a separate freshness check, the official GitHub MCP server main branch observed on 2026-08-28 still exposes `merge_pull_request` without an expected-head/SHA input and constructs the underlying merge options without assigning the source library's SHA guard. The same current `go.mod` pins `github.com/google/go-github/v89` to pseudo-version commit `34349a88bac3`, whose `PullRequestOptions` supports the SHA match guard.

That observation supports continued relevance of the case, but RISU Verify v0.1.0-rc1 does **not** relabel the frozen certificate as a live-current-runtime certification.

Public references:

- https://github.com/github/github-mcp-server
- https://github.com/github/github-mcp-server/blob/febc3293a4feb70e62399f39a26b082f78b9b176/pkg/github/pullrequests.go
- https://github.com/github/github-mcp-server/blob/febc3293a4feb70e62399f39a26b082f78b9b176/go.mod
- https://github.com/google/go-github/blob/master/github/pulls.go
