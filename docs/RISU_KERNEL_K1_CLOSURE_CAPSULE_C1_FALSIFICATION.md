# RISU Kernel K1 — Closure Capsule C1 Falsification

**Status:** PROSPECTIVE ARCHITECTURE FALSIFICATION  
**Frozen base:** `k1-closure-falsification-c0-qualified@8dd0887bae68fbe7d2cd23ed28c0f979c9f922ce`

## Thesis under attack

C0 showed that replay count, branch coverage, producer self-assertion, fixed environment/state/time/schedule, first-effect projection, world shrinkage, source-label binding, and laundering malformed or timed-out observations cannot justify implementation closure.

C1 therefore attacks a narrower architecture: instead of proving arbitrary native software closed, execute a small consequence program inside a deterministic capability-free capsule. All consequence-relevant variation must be explicit finite input. Exact program bytes, exact W0 worlds, slot domains, and gas are identity-bound. Ambient clock, randomness, files, network, hostcalls, and scheduling primitives do not exist in the accepted instruction set.

## Capsule semantics

Accepted instructions are only `LABEL`, `IF_EQ`, `GOTO`, `EMIT_HEX`, and `HALT`. `@world` is the only reserved input; all other input slots must come from the finite boundary descriptor. Each operational point is one world crossed with one value from every declared slot domain.

`EMIT_HEX` accepts arbitrary bytes and commits them into the open K1 consequence universe. A run is complete only if it parses, has every referenced input, halts within the identity-bound gas budget, and emits at least one consequence. Any parser error, missing input, gas exhaustion, fall-through, or zero-effect halt destroys closure eligibility.

The target identity binds exact program bytes, exact world set, finite slot domains, and gas. Enumeration order is set-like and therefore representation-invariant; changing any semantic member changes target identity.

## Falsification vectors

The gate precommits eighteen attacks: six ambient capabilities, unknown opcode, parser ambiguity, duplicate labels, gas exhaustion, zero-effect vacuity, missing boundary input, empty slot domain, duplicate world domain, program-byte substitution, boundary shrinkage, gas mutation, and first-effect-only projection.

Three positive controls are permitted: an exactly enumerable finite capsule, representation-order invariance, and an arbitrary target-native consequence payload that survives without a closed consequence enum.

## What a PASS means

A PASS means only that this tiny capsule architecture survived these precommitted constitutional attacks. It does **not** mean arbitrary native code is closed, and it creates no production K1 proof kind or preservation authority.

If the gate passes, the next admissible step is a separately versioned bounded-capsule closure artifact plus two independent checkers. Those checkers must recompute target identity and the full realized relation from the exact capsule program and boundary rather than trusting producer-supplied `closed`, `complete`, or `realize` fields.

The K1 semantic kernel remains `W + open U + ALLOW/REALIZE`; the capsule is a producer/proof layer, not a new semantic primitive.
