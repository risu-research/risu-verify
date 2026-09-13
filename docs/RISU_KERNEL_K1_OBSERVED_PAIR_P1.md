# RISU Kernel K1 — Observed-Pair Proof Kind P1

**Status:** CANDIDATE QUALIFICATION — regression-only local grounding  
**Frozen base:** `k1-binding-b0-qualified@305bbc50fe5db94a73f33aca6fbfb1590fb99509`  
**Proof kind:** `k1.observed-pair/v1`

## Why P1 exists

The qualified B0 runner proved that an actual forbidden effect can be connected to a normal K1 regression witness, but B0 intentionally supported only a single-world claim because `k1.finite-model/v1` requires the proof artifact's world domain to equal the claim's whole world domain.

That requirement is correct for preservation: a positive claim needs closure over its declared scope. It is unnecessarily strong for a negative witness. K1's semantic rule is asymmetric: one grounded forbidden realized pair is already sufficient for regression. Unrelated worlds do not need to be closed to validate that counterexample.

P1 makes that asymmetry executable without changing K1 semantics.

## Constitutional rule

For a W0 claim with admitted worlds `W` and relation `ALLOW`, a P1 witness may establish only:

```text
(w, u) is grounded by one recognized local observation artifact
(w, u) not in ALLOW
----------------------------------------------
REGRESSION
```

It does **not** establish `REALIZE` for any other pair or world. It cannot be used as a closure proof or preservation certificate.

## Artifact boundary

A `k1.observed-pair/v1` artifact is content-addressed by `p:sha256` over its exact bytes. It binds:

- `claim_id`;
- exactly one `(world, consequence)` pair;
- a recognized observation profile;
- the digest of the exact executable independently supplied to the checker;
- exact world-input bytes;
- exact effect-log bytes;
- selected effect-record index;
- timeout/exit metadata;
- stdout/stderr digests;
- a distinct local-observation `target_id`.

The checker recomputes the world commitment from the exact world bytes and the consequence commitment from the selected exact effect record. Producer-supplied world or consequence IDs are therefore not authoritative merely because they appear in JSON.

## Target identity is intentionally not a finite-model identity

P1 uses the separate domain:

```text
RISU-K1-TARGET-OBSERVED-PAIR-V1\0
```

A P1 `target_id` commits to one local observed-run transcript. It does not claim to enumerate a target's behavior or model its other worlds. This prevents a local witness from being mistaken for an exhaustive finite model.

## Two independent checkers

- `kernel/k1_checker_w3.py` — Python standard library only.
- `kernel/k1_checker_w4.go` — Go standard library only; no Python execution or RISU checker imports.

Both independently recompute:

1. W0 claim identity and well-formedness;
2. W0 witness identity;
3. proof-artifact byte digest;
4. exact executable digest;
5. world commitment from embedded world bytes;
6. selected consequence commitment from the strict E1 effect record;
7. local observed-pair target commitment;
8. whether the grounded pair is outside `ALLOW`.

## Adversarial qualification

The prospectively fixed P1 gate contains 18 authority-changing vectors. It includes:

- accepted forbidden pair in a three-world claim;
- rejection when that same pair is allowed;
- undeclared-world rejection;
- claim/world/effect/executable/target/artifact/witness substitution attacks;
- malformed or out-of-range observation evidence;
- preservation laundering attempt;
- ten-world claim with only one locally observed world;
- representation reordering invariance;
- multiple effects with a selected forbidden record;
- timeout/nonzero metadata after a durable forbidden record;
- unknown observation profile.

Hosted qualification passed **18/18** with exact W3/W4 agreement and zero preservation authority.

## What P1 establishes

P1 establishes that, relative to a valid W0 claim and recognized observation profile, the exact submitted local observation bytes ground the submitted forbidden pair; and that the artifact is content-bound to the exact executable bytes supplied independently to the checker.

This is enough for the K1 regression rule. No global target closure is needed.

## What P1 deliberately does not establish

P1 does not establish:

- preservation from clean runs;
- exhaustive implementation behavior;
- closure over unobserved worlds;
- deterministic replay behavior;
- liveness/deadline properties;
- authenticated remote attestation;
- a signature or transferable trust token;
- causal provenance of embedded observation bytes outside a controlled binding runner.

The last boundary matters. P1 verifies the evidence object. The follow-on B1 runner is responsible for minting such an object only from an effect sink it actually observed while executing exact implementation bytes.

## Next gate

The next structural step is **B1 multi-world local implementation binding**. B1 must execute a real specimen, observe its external effect sink, mint a P1 artifact only for a forbidden record, and have both W3 and W4 accept the resulting witness while an independently implemented observer re-executes the same variants.

A clean run must still produce **NO AUTHORITY**, never preservation.
