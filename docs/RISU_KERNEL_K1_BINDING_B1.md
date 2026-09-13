# RISU Kernel K1 — Binding B1

**Status:** CANDIDATE QUALIFICATION — controlled local multi-world regression binding  
**Frozen base:** `k1-observed-pair-p1-qualified@7dc6e4a34f9bbee025894474df430fd202028244`  
**Evidence lane:** `k1.observed-pair/v1`

## Purpose

B1 closes the next gap after P1. P1 can independently verify that exact observation bytes ground one forbidden `(world, consequence)` pair in a multi-world K1 claim, but P1 deliberately does not claim that those bytes were actually produced by the executable. B1 supplies a controlled local execution path that creates those bytes and mints P1 evidence only from the fresh effect sink of that run.

The semantic kernel is unchanged. B1 realizes the existing K1 asymmetry in the implementation-binding layer:

```text
one admitted world
+ one actual controlled execution
+ one durable observed consequence outside ALLOW
+ independently accepted P1 witness
------------------------------------------------
BOUND_REGRESSION
```

No claim is made about unrelated worlds. A clean run has no preservation authority.

## Controlled-run trust boundary

For every invocation B1:

1. validates the exact W0 claim and selected-world membership;
2. hashes the exact executable bytes before launch;
3. creates a new private temporary execution directory;
4. writes the exact selected world bytes into that directory;
5. creates a fresh empty private sink;
6. launches the executable with only the world path and sink path;
7. after exit or timeout termination, reads only `sink/effects.log` as consequence authority;
8. treats stdout/stderr as content-bound metadata, never as consequences;
9. strictly parses E1 effect records in order;
10. selects the first observed consequence outside `ALLOW` for the selected world;
11. mints a `k1.observed-pair/v1` artifact and W0 regression witness for that exact record;
12. returns `BOUND_REGRESSION` only if frozen W3 and W4 both independently return `ACCEPTED/REGRESSION`.

A nonzero process exit or timeout after a durable forbidden sink record does not erase the side effect. A timeout before any effect gives no authority. A malformed sink gives no authority.

## Multi-world locality

B1 does not fabricate a finite target model to satisfy unrelated worlds. The B1 gate explicitly expands the claim from three worlds to ten while observing only the selected world. The same real forbidden pair remains sufficient for regression.

This is not a relaxation of positive assurance. It is the negative-witness rule K1 already had: a grounded counterexample is local, while preservation remains global over its declared scope.

## P1 evidence object

When B1 sees a forbidden record, it creates the exact P1 artifact that binds:

- the claim ID;
- the selected world/consequence pair;
- exact executable digest;
- exact world-input bytes;
- exact complete effect-log bytes;
- selected record index;
- timeout and exit metadata;
- stdout/stderr digests;
- the local-observation target commitment.

The artifact is content-addressed and referenced by a standard W0 regression witness. W3 and W4 independently recompute the relevant commitments; the B1 runner does not import their implementation code.

## Saved-run envelope and post-hoc verification

B1 also creates a content-bound local run envelope over the claim, world, executable, effect log, process metadata, P1 artifact/witness IDs, and authority result.

`tools/risu_kernel_k1_binding_b1_report_verify.py` independently rechecks a saved `BOUND_REGRESSION` report against externally supplied exact claim, world, and executable bytes. It then extracts the embedded P1 artifact and witness and re-runs W3 and W4.

This catches post-run substitution of the executable, selected world, effect evidence, P1 artifact, witness, or recorded checker outcome.

The envelope is **not** a signature, remote attestation, or transferable proof of execution. Its causal meaning is intentionally scoped to the controlled local runner.

## B1 authority gate

The prospectively fixed B1 gate contains 16 authority-changing vectors. The final hosted run passed **16/16**.

It verifies, among other cases:

- allowed effect → `NO_AUTHORITY`;
- forbidden effect → `BOUND_REGRESSION`;
- forbidden-looking stdout with allowed sink → `NO_AUTHORITY`;
- nonzero exit after forbidden durable effect → `BOUND_REGRESSION`;
- timeout after forbidden durable effect → `BOUND_REGRESSION`;
- timeout before any effect → `NO_AUTHORITY`;
- malformed sink → `NO_AUTHORITY`;
- allowed record followed by forbidden record → `BOUND_REGRESSION`;
- ten-world claim with nine unrelated unobserved worlds → `BOUND_REGRESSION`;
- claim world/ALLOW reordering invariance;
- unadmitted selected-world rejection;
- executable/world/effect evidence substitution rejection;
- clean-run preservation laundering impossible by interface;
- W3/W4 disagreement or checker failure → fail closed.

For accepted bound-regression cases the independent saved-report verifier also returns `VERIFIED_BOUND_REGRESSION`.

## D2 independent execution observer

A second implementation in Go re-executes the same eight runtime variants using a separate temporary directory and sink. It invokes no P1 checker and executes no Python.

D2 independently derives:

- selected world commitment;
- executable commitment;
- exact effect-log digest;
- ordered consequence commitments;
- first forbidden pair;
- timeout state;
- stdout/stderr digests;
- coarse observation class and authority candidate.

The final D2 run passed **8/8**.

The differential intentionally normalizes only presentation vocabulary: the Python runner distinguishes `OBSERVED_NO_FORBIDDEN_CONSEQUENCE` from `OBSERVED_FORBIDDEN_CONSEQUENCE`, while the Go observer uses `OBSERVED`. Both are compared as the coarse parse class `OBSERVED`; the authority-changing fields `authority_candidate`, `first_forbidden_pair`, ordered consequences, hashes, world, executable, and timeout remain exact comparisons. This avoids coupling independent implementations merely through UI/status wording.

## Fail-then-fix history

Two failures were retained rather than waived:

1. The first B1 hosted attempt stopped at source hygiene because the new Go observer was not `gofmt`-canonical. The observer alone was canonicalized, the one-shot helper was removed, and the complete gate was restarted.
2. The first D2 semantic attempt produced B1 **16/16 PASS** but D2 **1/8** because the observer used `OBSERVED` while the runner used two more specific observed-status labels. Inspection showed all authority-relevant values matched. The differential was corrected to normalize only this presentation vocabulary while keeping forbidden selection and every authority-relevant commitment exact. The entire B1 16-vector gate and D2 8-vector differential were then rerun from scratch and both passed.

The second failure is useful evidence: the differential gate rejected unnecessary representation coupling instead of silently calling two semantically identical observations different.

## Strongest justified claim

Under the qualified B1 controlled-local-run contract, exact executable bytes can be run against one admitted world of a multi-world K1 claim, and a durable forbidden effect from that execution can be transformed into a content-bound P1 regression witness that two independent checkers accept. Unrelated claim worlds need not be modeled or closed for that negative result. A separately implemented observer reproduces the authority-relevant execution observation over the qualified runtime variants.

## Explicit non-claims

B1 does not establish:

- preservation from clean or finite executions;
- closure or exhaustiveness over implementation behavior;
- anything about unobserved claim worlds beyond the frozen claim commitments;
- authenticated remote execution or hardware-backed attestation;
- that a saved run envelope, detached from the controlled runner, proves historical causality by itself;
- deterministic behavior across arbitrary replays;
- unbounded liveness or deadline properties;
- sandbox safety for hostile arbitrary programs;
- a change to the K1 `ALLOW/REALIZE` semantic kernel.

## Structural implication

After B1, the main unresolved problem is no longer whether K1 can connect a real negative observation to a multi-world semantic claim. It can, within the qualified controlled-local boundary.

The hard remaining positive side is implementation adequacy and closure: what evidence producer can justifiably establish enough of an implementation's consequence space to support preservation? More black-box clean runs cannot solve that problem. It requires a stronger closure-producing frontend, formal execution model, exhaustive finite boundary, or another independently checkable adequacy argument.
