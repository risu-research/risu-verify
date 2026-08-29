# External Case 002 — Microsoft Azure DevOps MCP Wiki Edit

## Why this case

Case 002 is a fresh external positive control selected from the independently developed official `microsoft/azure-devops-mcp` repository. The target operation is `wiki_upsert_page` at pinned commit:

`7675bb70e3ab2cd84e2991f453a8fdc9d0c8ce89`

Pinned file:

`src/tools/wiki.ts`

Git blob SHA-1 returned by GitHub for that file:

`36932f79ab5acee34f72bb8bf6740329601e31bc`

Repository: https://github.com/microsoft/azure-devops-mcp

## Predeclared scope

The claim is deliberately narrower than the whole upsert tool.

Included profile:

- the page already exists;
- the implementation has entered its existing-page fallback arm after the initial create attempt returns 409 or 500;
- the caller supplies the reviewed page ETag, modeled as `E0`;
- the effect-time current ETag is either `E0` or `E1`;
- the edit consequence is governed by the official Azure DevOps `If-Match` version precondition.

Excluded from the claim are new-page creation, caller-omitted ETag behavior, other status paths, authentication behavior, other wiki operations, and live-service conformance.

The immutable predeclaration is `PREDECLARATION.json`, SHA-256:

`42bac8308b45bee1d628f9492fd2f8212aee4c243f9b1d83e8ac5585a4881565`

## External grounding

The pinned MCP implementation exposes an optional `etag`, initializes the edit ETag from the caller value on the declared arm, and forwards that value in `If-Match` on the update PUT.

The source consequence is grounded in Microsoft's Azure DevOps Wiki Pages REST API 7.1 documentation, which specifies the page version in `If-Match` as mandatory for edit:

- https://learn.microsoft.com/en-us/rest/api/azure/devops/wiki/pages/create-or-update?view=azure-devops-rest-7.1
- https://learn.microsoft.com/en-us/rest/api/azure/devops/wiki/pages/update?view=azure-devops-rest-7.1

No live tenant execution is claimed.

## Bounded consequence

```text
reviewed ETag = E0

current = E0  -> UPDATE_COMMITTED
current = E1  -> STALE_EDIT_REJECTED
```

## Frozen-core result

The first v0.7 core evaluation was run only after the predeclaration was sealed.

```text
PRESERVED
Structural: C1 / D1 / O1
Exact: REALIZATION_ESTABLISHED
Coverage complete: true
Independent consumer: PASS (21/21 checks)
```

This establishes preservation only for the declared slice.

## Semantic mutation

Mutation `M-IGNORE-SUPPLIED-ETAG` is RISU-authored and is **not** attributed to Microsoft.

It keeps:

- the same agent-facing operation;
- the same `etag` input surface;
- the same `If-Match` header surface;
- the same source consequence contract.

It changes only the operative binding: the caller-reviewed ETag is ignored, causing the fallback to bind `If-Match` to the latest fetched ETag.

The mutation result is:

```text
CONSEQUENCE REGRESSION
Structural: C1 / D1 / O0
Exact: REALIZATION_CONTRADICTED
Failure: MECHANISM_MISALIGNMENT
```

Minimal stale-world witness:

```text
Page ETag at edit cut: E1
Reviewed ETag:          E0
Required:               STALE_EDIT_REJECTED
Projected effect:       UPDATE_COMMITTED
```

This is the intended semantic-CI demonstration: **the visible guard survives while the consequential binding does not**.
