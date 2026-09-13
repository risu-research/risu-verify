# RISU Kernel K1 — Implementation Binding B0

**Status:** CANDIDATE QUALIFICATION — one-sided observed-execution regression binding only  
**Frozen base:** `k1-w2-qualified@3f3e6b9071d7fe1cd447f2bbbba9addbbe509533`  
**Kernel semantics changed:** **no**

## Why B0 is the right next gate

K1 RC1 already survived mutation testing, cross-domain constitutional falsification, strict wire/identity checks, legacy-equivalence checks, and a second independently implemented checker. The strongest remaining epistemic break was therefore no longer “does the calculus survive another synthetic example?” or “does one checker have a bug?” It was the gap between a declared finite target model and an actual executable implementation.

B0 attacks that gap narrowly rather than pretending to solve more than the evidence permits.

A finite black-box run can directly establish that a particular forbidden consequence actually occurred at a declared consequential cut. It cannot establish that all possible implementation behavior has been exhausted. Therefore B0 is deliberately asymmetric:

- an independently observed forbidden effect can ground a K1 **REGRESSION** witness;
- an allowed or clean finite run yields **NO_AUTHORITY**;
- B0 has no interface that can mint preservation authority from black-box testing.

This preserves K1's existing asymmetric epistemology instead of weakening it.

## Architecture

The qualified path is:

```text
frozen single-world K1 claim + exact world-input bytes
                    |
                    v
             exact executable bytes
                    |
                    v
       strict append/result sink at effect cut
                    |
           +--------+--------+
           |                 |
           v                 v
   Python B0 binder    independent Go observer D1
           |                 |
           |          independently recomputes
           |          world/effect/forbidden set
           |
           v
   observed forbidden pair
           |
           v
   W0 finite-model artifact + regression witness
           |
        +--+--+
        |     |
        v     v
       W1     W2
        |     |
        +--+--+
           |
           v
      BOUND_REGRESSION
```

The Python binder imports neither checker. W1 and W2 are invoked only as external consumers. The Go D1 observer creates no K1 proof object and invokes neither binder nor checker; it independently reimplements execution observation, strict sink parsing, world/consequence commitments, single-world ALLOW recovery, and forbidden-set derivation.

## Observation contract

B0 observes only `effects.log` in a dedicated sink directory. A record has the exact grammar:

```text
E1|kind=<token>|subject=<token>|value=<token>\n
```

with tokens restricted to `^[a-z0-9._:@/-]{1,128}$`.

The consequential cut is after the target exits or after the binder terminates it for timeout. The sink bytes are then read exactly once. `stdout`, `stderr`, and process exit status are diagnostic channels, not consequence sources.

That distinction is tested explicitly:

- printing a forbidden-looking record to stdout while writing an allowed sink produces no authority;
- a forbidden effect durably present before a nonzero exit remains a regression witness;
- a forbidden effect durably present before timeout remains a regression witness;
- timeout before any effect gives no authority;
- a malformed sink is rejected as a whole; a valid-looking prefix is not salvaged.

## Commitments and producer non-authority

The binder computes the world commitment from the exact world-input bytes under a B0-specific domain separator. It computes consequence commitments from strict parsed effect records under a separate domain separator. It commits the exact executable bytes as `impl:sha256:<SHA256>`.

The target process cannot supply a world id, consequence id, target id, finite-model proof bytes, witness id, or authority label. Its stdout/stderr cannot create semantic authority.

For the frozen qualification fixture:

- world: `w:sha256:13cc08218b3578873c7cb0438f32f4bc9ad8f732e4d810193bb15e89214ad314`
- allowed consequence `(transfer, alice, 100)`: `c:sha256:238c9f640b79314187064c6f722f726ec981c980229233cb5c1a5453b37f6ee0`
- forbidden consequence `(transfer, bob, 100)`: `c:sha256:e9d1d1a276a1c50b31187d32763d4584a6b9f5b92a7c4aa7e53d71adfed9455e`
- claim: `claim:sha256:d1f58f461082d72270105da7795f7c53d586f1b19b7d3ac18decb4d93cf60c73`

The independent Go observer reproduced these exact commitment constants.

## B0 adversarial qualification: 13/13

The precommitted B0 gate passed all thirteen authority cases:

1. allowed effect → `NO_AUTHORITY`
2. forbidden effect → `BOUND_REGRESSION`
3. forbidden stdout / allowed sink → `NO_AUTHORITY`
4. forbidden effect then nonzero exit → `BOUND_REGRESSION`
5. forbidden effect then timeout → `BOUND_REGRESSION`
6. timeout before effect → `NO_AUTHORITY`
7. malformed sink → `NO_AUTHORITY`
8. allowed + forbidden multi-event sink → `BOUND_REGRESSION`
9. executable substitution → binding evidence rejected
10. world-input substitution → binding evidence rejected
11. observation/report tamper → binding evidence rejected
12. attempted preservation from an allowed run → impossible by B0 interface
13. multi-world claim → unsupported / no authority

For the simple forbidden run, the binder generated:

- target id: `t:sha256:4e8c30e81aa526341eadde4e8082360427129bc7b8e0f4fd8a4a6a5c2b73543e`
- proof artifact id: `p:sha256:164a6ff83c8751569d364fc7faaf693d25518b51be74f31a2f1e63d2717c2f35`
- regression witness id: `wit:sha256:5607336d713bb30d863dd72ec335017515fe05fd62a10721fdba7dcdfaa939fb`
- W1: `ACCEPTED/REGRESSION`
- W2: `ACCEPTED/REGRESSION`

For the allowed+forbidden multi-event run, the observed target relation contained both consequence commitments and both frozen checkers still accepted the forbidden witness as regression.

## D1 independent observer differential: 8/8

After B0 first passed, the binder itself became the largest newly introduced common-mode risk. B0 was therefore strengthened with a prospectively declared D1 observer gate rather than immediately frozen.

A Go-standard-library-only observer independently executes the same target variants and recomputes authority-relevant observations without importing or executing the Python binder, W1, W2, or Python itself.

The eight precommitted runtime variants all passed exact differential comparison:

- `good`
- `bad`
- `stdout-lie`
- `nonzero-forbidden`
- `timeout-after-forbidden`
- `timeout-before-effect`
- `malformed`
- `multi`

For every non-malformed vector, Python and Go agreed exactly on world commitment, implementation commitment, effect-log digest, observed consequence set, and forbidden consequence set. For the malformed vector, both refused authority and neither salvaged a valid-looking prefix.

D1 result: **8/8 PASS, 0 differential failures, 0 independence violations.**

## Meaningful fail-then-fix

The first hosted D1 attempt was stopped before D1 execution because the new Go observer was not `gofmt`-canonical. The failure was formatting-only, not semantic or compile-time. The observer bytes were canonicalized, the one-shot formatter was removed, and the entire source-hygiene/build + B0 13-vector + D1 8-vector sequence was rerun from scratch. The canonicalized run passed.

This earlier green was not reused after the source bytes changed.

## What B0 establishes

Within its declared scope, a B0-bound regression has a stronger evidence chain than the previous model-only lane:

1. the exact executable bytes are committed;
2. the exact world-input bytes are committed;
3. a strict externalized sink contains an actually observed consequence at the cut;
4. two independently implemented observation paths agree on the authority-relevant observation;
5. the observed pair is outside the frozen K1 ALLOW relation;
6. frozen W1 and independently implemented W2 both accept the generated W0 regression witness.

The strongest justified claim is therefore:

> For the qualified single-world B0 observation contract, an actual forbidden effect produced by an exact executable can be bound to a normal K1 regression witness and independently corroborated by both W1 and W2, while finite clean observations cannot be promoted to preservation authority.

## What B0 explicitly does **not** establish

B0 does not claim:

- preservation from black-box testing;
- exhaustive implementation behavior;
- determinism across replays;
- arbitrary-program sandboxing or hostile-code containment;
- unbounded liveness or deadline proof;
- multi-world local-witness support;
- a universal implementation-binding theorem;
- that a `binding_id` is a signature, authenticated attestation, or transferable trust token.

`binding_id` is a content-integrity commitment for the report. Because it is unkeyed, a party able to fabricate a report can also recompute its hash. Qualification authority comes from the live qualified observation procedure and frozen evidence chain, not from possession of a report hash alone.

## Why single-world is deliberate

Frozen W1/W2 `k1.finite-model/v1` currently require the finite proof artifact world domain to equal the entire claim world domain. A local observed forbidden pair should not require inventing observations for unrelated worlds merely to satisfy that proof-format restriction.

B0 therefore fails closed on multi-world claims rather than manufacturing evidence. This exposes the next structural bottleneck cleanly: a future proof kind for a **locally grounded observed pair** should allow a regression witness to bind one admitted world without pretending to close the rest of the claim.

That is an evidence-format problem, not a reason to enlarge the K1 semantic kernel.
