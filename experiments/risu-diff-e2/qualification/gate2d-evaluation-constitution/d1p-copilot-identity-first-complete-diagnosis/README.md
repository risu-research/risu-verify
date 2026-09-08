# Gate2D D1′ first-complete pre-provider diagnosis

The first hosted D1′ failure was not caused by a Copilot model, credential, semantic baseline, evaluator, checker, registry, or production-semantic defect.

A diagnosis-only workflow recomputed the exact static predicates against the frozen implementation bytes and found exactly two failures:

- `D1P_SEMANTIC_CREDENTIAL_SURFACE`
- `D1P_SEMANTIC_REQUEST_SURFACE`

Both are false positives from one self-referential checker design: the identity workflow searches its entire own source for forbidden substrings, while those same substrings appear literally inside the embedded detection code. The checker therefore detects itself.

All other static predicates passed. Copilot CLI installation was never reached in the first qualification; Copilot semantic request count remains zero, and no provider semantic output has been observed.

The only authorized repair is a prospective, non-self-matching structural/whitelist replacement for these two workflow-surface checks plus identity metadata transitively changed by that workflow byte change. Baseline/model/prompt/schema/metrics/evaluator semantics/checker semantics/production semantics/C1 and heldout state remain frozen.

Diagnosis run: `34255462285`; job: `102160013963`; artifact: `10067659925`; artifact ZIP SHA-256: `8fc4b27de935cadc993130d0dc0b86957f822a925fdde7df4e024fa93d7cbc92`.
