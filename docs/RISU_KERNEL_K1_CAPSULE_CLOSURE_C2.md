# RISU Kernel K1 — Capsule Closure C2

**Status:** prospective positive preservation lane under adversarial qualification  
**Frozen base:** `k1-closure-c1-capsule-falsification-qualified@168512cd0e4e260a84788c2c10f140fa39dc6aef`  
**Proof kind:** `k1.capsule-closure/v1`  
**Capsule semantics:** `risu.k1.capsule/v1`

## Why C2 exists

K1 already has a strong one-sided implementation-bound regression lane: one actually observed forbidden consequence is enough to establish regression. Preservation is harder. A finite set of clean executions, high coverage, or a producer assertion that a model is complete cannot justify that no omitted consequential behavior exists.

C0 therefore attacked unsound closure producers first, and C1 narrowed the positive problem to a tiny deterministic capability-free capsule. C2 is the first attempt to turn that narrowed architecture into independently checkable positive authority.

## Narrow-waist rule

C2 does **not** change the K1 semantic kernel. The semantic claim remains the W0 safety-subset relation:

`PRESERVATION iff derived REALIZE is exhaustively established and REALIZE ⊆ ALLOW.`

The new work is entirely in the evidence layer: how `REALIZE` is established for one exact implementation class.

## No producer-supplied closure relation

The `k1.capsule-closure/v1` artifact contains only:

- proof-format/version,
- W0 claim binding,
- capsule-semantics version,
- SHA-256 of exact program bytes,
- exact finite boundary: W0 worlds, finite string-valued slot domains, and gas limit.

The artifact contains **no** `REALIZE`, `possible`, `closed`, `complete`, `target_id`, or verdict field. Extra fields are rejected.

Both checkers receive the exact program bytes separately, verify their digest, strictly parse them, enumerate every admitted world × finite slot valuation, execute every operational point, collect every emitted consequence, and derive the relation themselves.

## Independent checker pair

- **W5** — Python implementation.
- **W6** — Go standard-library-only implementation.

W6 imports no RISU checker code and executes no Python. W5 imports no C1 implementation and executes no subprocesses. Both are implemented against the precommitted C2 protocol and wire transcript.

The checker pair must independently derive the same:

- complete relation,
- semantic target commitment,
- preservation verdict.

Agreement is corroboration, not a universal correctness theorem.

## Capsule closure conditions

Closure authority exists only if all of the following hold:

1. Exact W0 claim is structurally and cryptographically valid.
2. Artifact digest matches its exact bytes.
3. Exact program SHA-256 matches the artifact.
4. Boundary world set equals the W0 claim world set exactly.
5. Every slot domain is explicit, finite, nonempty, duplicate-free, and canonical at the value level.
6. Program uses only the C1/C2 capability-free instruction surface.
7. Every world × slot valuation executes to `HALT` within identity-bound gas.
8. Every execution emits at least one consequence.
9. Every emitted effect is retained at the consequential cut.
10. The certificate's submitted `REALIZE` equals the independently derived relation exactly.
11. Grounding entries are exactly one per derived pair, with no omissions or surplus, and all bind the same exact capsule proof artifact.
12. Certificate target commitment equals the independently derived target commitment.
13. Derived `REALIZE` is a subset of W0 `ALLOW`.

Any parse uncertainty, missing input, fallthrough, gas exhaustion, zero-effect halt, artifact/program mismatch, or closure mismatch fails closed.

## Identity separation

Artifact identity is byte-level:

`p:sha256 = SHA-256(exact artifact bytes)`.

Semantic target identity is representation-invariant and binds:

- capsule semantics version,
- exact program digest,
- sorted W0 world set,
- sorted finite slot names and domains,
- gas limit,
- sorted independently derived `REALIZE`.

Therefore harmless JSON/world/domain ordering changes may change `p:` while preserving `t:`. Program, boundary, gas, semantics, or derived behavior changes must change `t:`.

## Authority claim if qualified

The strongest permitted claim is:

> For the exact `risu.k1.capsule/v1` program bytes and exact finite boundary accepted by the C2 checkers, W5 and W6 independently exhaust the declared operational space, derive the same complete consequential relation and target commitment, and accept W0 preservation only when that derived relation is a subset of `ALLOW`.

This is an **implementation-bound preservation result for the bounded capsule**, because the exact capsule program bytes are the implementation under analysis.

## Nonclaims

C2 does not establish:

- preservation of arbitrary native binaries, containers, operating systems, cloud services, or agent stacks;
- remote or hardware-backed execution attestation;
- absence of compiler/runtime bugs outside the defined capsule semantics;
- unbounded liveness or arbitrary temporal properties;
- correctness of a future translator from native software into the capsule;
- universal completeness of K1;
- equivalence to or superiority over Lean as a general theorem prover.

The intended comparison to proof-assistant architecture is narrower: a small evidence language plus independently checkable derivation should carry authority, not producer trust.

## Qualification gates

C2 is not qualified unless hosted CI passes both:

- **28/28 static adversarial vectors**, covering relation omission/surplus, forbidden consequence, artifact/program/claim/boundary tamper, ambient capability attempts, parser ambiguity, gas/zero-effect incompleteness, grounding attacks, target/certificate mutation, self-certification-field injection, and representation invariance.
- **768/768 seeded generative comparisons** (`seed=1123581321`, 96 trials × 8 properties), covering independently derived relation, target and verdict equality plus semantic permutation and tamper properties.

The C1-qualified base must remain add-only untouched throughout qualification.
