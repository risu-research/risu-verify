# Semantic CI Demonstration

The Case 002 baseline and mutation are designed as a single CI experiment.

## Baseline

```sh
./risu-verify check cases/azure-devops-wiki-etag
```

Expected result:

```text
PRESERVED
SEMANTIC LOCK: MATCH
exit 0
```

## Mutation verdict

```sh
./risu-verify verify cases/azure-devops-wiki-etag/mutations/ignore-supplied-etag
```

Expected result:

```text
CONSEQUENCE REGRESSION
C1 / D1 / O0
REALIZATION_CONTRADICTED
MECHANISM_MISALIGNMENT
exit 10
```

## Baseline-lock rejection

```sh
./risu-verify check \
  cases/azure-devops-wiki-etag/mutations/ignore-supplied-etag \
  --lock cases/azure-devops-wiki-etag/risu.lock.json
```

Expected result: `SEMANTIC LOCK MISMATCH`, exit 40.

The mutation intentionally preserves the visible ETag/If-Match surface. It therefore tests consequence binding rather than simple schema or guard presence.

`tests/semantic_ci_demo.sh` runs the three checks with the expected exit-code assertions. The pull-request workflow repeats the same gates.
