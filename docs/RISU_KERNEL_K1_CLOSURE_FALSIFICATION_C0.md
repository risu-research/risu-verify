# RISU Kernel K1 — Closure Falsification C0

**Status:** PROSPECTIVE FALSIFICATION GATE  
**Frozen base:** `k1-binding-b1-qualified@581ab6c1596751242a312b72d743d7595a43b327`  
**Purpose:** attack positive implementation closure before creating any new preservation authority.

## Why C0 exists

W1 can certify preservation relative to an explicit finite target model, but it intentionally reports `implementation_binding=false`. B1 closes the opposite, easier direction: one actual forbidden effect can ground regression without closing unrelated behavior. The remaining structural gap is therefore not more regression testing. It is the positive adequacy question:

> What independently checkable evidence is sufficient to say that a finite REALIZE relation exhausts the consequential behavior of an exact implementation over the exact W0 world claim and a declared operational boundary?

C0 does not answer that question by decree. It first tries to destroy tempting answers.

## C0 is a falsification laboratory, not a proof lane

The harness contains a synthetic hidden oracle that knows the full bounded behavior of deliberately adversarial challenge machines. Candidate producers do not receive production authority from this oracle. The oracle exists only so the gate can say, with certainty inside the synthetic laboratory, that a producer claiming closure omitted real behavior or bound the wrong object.

Consequently:

- C0 creates **no K1 proof kind**;
- C0 creates **no PRESERVED result** for an external implementation;
- C0 does **not** change `W + open U + ALLOW/REALIZE`;
- the positive controls establish only that the gate can recognize an exactly enumerable, fully bounded synthetic machine.

## Fourteen producer mutants

C0 precommits fourteen nearby strategies that are attractive but unsound as closure authority:

1. trust a producer-supplied `closed=true` equivalent;
2. infer closure from 1,000 identical clean replays;
3. substitute 100% control-flow branch coverage for consequence-space closure;
4. enumerate worlds while fixing the external environment;
5. reset persistent state and ignore warm/history-dependent behavior;
6. assume determinism after one random/nondeterministic choice;
7. fix one time class;
8. fix one schedule/interleaving class;
9. record only the first consequential effect;
10. discard a target-native consequence that is absent from a source-known enum;
11. treat timeout as an empty safe execution;
12. bind a source label while exact executable bytes drift;
13. close only a producer-selected subset of W0 worlds;
14. drop malformed/unresolved observation and still assert completeness.

The attack cases are constructed so that some failures are obvious relation mismatches, while others are subtler. In particular, the self-declaration case has the **same observed relation by coincidence** even though an operational point was never justified. That prevents C0 from collapsing adequacy into “the set happened to match on this fixture.”

## Positive controls

`C0-P1` uses explicit Cartesian enumeration over a completely bounded synthetic machine, exact implementation identity, exact world-domain equality, complete effect sequences, and no unresolved observation. `C0-P2` reverses enumeration order. The resulting relation and eligibility must be invariant.

The string `explicit-cartesian-enumeration/v0` is deliberately **not** a universal K1 requirement. It is only the first positive control family. A future symbolic or deductive producer may establish the same obligations without enumeration, but it must be independently checkable and at least as strong on the relevant boundary.

## What a PASS may justify

If C0 kills 14/14 mutants and both positive controls survive, the justified conclusion is only that a future positive implementation-adequacy lane must, at minimum, solve the following obligations rather than hand-wave them away:

- exact implementation binding;
- exact W0 world-domain binding;
- independently justified completeness over every consequence-relevant operational dimension;
- explicit treatment of state/history, nondeterminism, time and scheduling when semantically relevant;
- sequence-complete consequential observation;
- an open consequence universe;
- fail-closed handling of timeout, unresolved execution and malformed observation;
- a distinction between diagnostic coverage/replay evidence and closure authority;
- independent verification of the closure argument.

These are **producer/proof obligations**, not new semantic kernel primitives.

## What C0 explicitly refuses to claim

A PASS does not show that arbitrary software can be exhaustively modeled, that source coverage implies semantic adequacy, that a finite number of black-box executions can prove preservation, or that a practical general-purpose closure producer already exists. It also does not add liveness/MUST semantics, remote attestation, hostile-code sandboxing, probabilistic guarantees, or unbounded temporal reasoning.

## Decision rule

If any unsound mutant survives, C1 is forbidden until the hole is repaired. If all fourteen are killed and both controls pass, C1 may attempt the narrowest independently checkable bounded implementation-adequacy proof lane consistent with the obligations above. The default remains fail closed: inability to prove closure is `UNKNOWN`, not `PRESERVED`.
