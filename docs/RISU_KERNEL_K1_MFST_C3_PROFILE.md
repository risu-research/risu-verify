# K1 C3 — Mediated Finite-State Transducer Profile

Status: **design-frozen, non-authoritative**.

Normative sources are:

- `protocols/RISU_KERNEL_K1_MEDIATION_REFINEMENT_C3_PROSPECTIVE.json`
- `protocols/RISU_KERNEL_K1_MFST_C3_PROFILE.json`
- `protocols/RISU_KERNEL_K1_MFST_C3_WIRE.json`

This document explains the design. It does not create a proof kind, preservation authority, implementation binding, or any change to K1 semantics.

## 1. Why C3 exists

C2 solved a deliberately narrow positive problem: exact bounded hermetic capsule bytes plus an explicit finite boundary can be exhaustively executed by two independent checkers, producing an implementation-bound K1 `REALIZE` relation. That is powerful precisely because the capsule has almost no hidden behavior.

The next problem is not “make C2 a bigger language.” A larger language can silently reintroduce the exact closure failures that C0 killed: ambient state, hidden exits, omitted effects, unbounded scheduling, or a producer asserting that its own abstraction is complete.

C3 therefore adds expressiveness only where the added behavior remains mechanically closed.

The admitted subject is a **Mediated Finite-State Transducer (MFST)**:

1. the external boundary is finite and explicit;
2. all mutable state is finite and explicit;
3. all pure transformations are finite and total;
4. control flow is deterministic;
5. `EMIT_HEX` is the only consequence-capable operation;
6. there are no ambient capabilities;
7. termination is decided structurally from the finite configuration space;
8. exact ordered effects are retained before projection to K1;
9. two independent implementations reconstruct both the direct semantics and the C2 refinement;
10. the already-qualified C2 W5/W6 lane independently re-derives the final K1 relation.

That is the C3 bargain: more stateful behavior, but no hidden consequential surface.

## 2. The central invariant: closed effect surface

The v1 operation ontology has one and only one effectful primitive:

`EMIT_HEX <exact bytes>`

Everything else is a deterministic transformation of explicit finite data. A valid profile has no semantic operation for files, network, clocks, RNG, environment, subprocesses, FFI, dynamic loading, reflection, threads, callbacks, signals, shared memory, or persistence.

This is stronger than asking a static analysis to *discover* all effects in a general language. In C3 v1, an unmediated effect is not merely discouraged; there is no admitted semantic construct that can express it.

An unknown opcode is not interpreted conservatively as a no-op. It invalidates the profile for positive authority.

## 3. Why finite state is the right first expansion

C2 can branch on finite inputs but has no mutable semantic state. Many useful policy/workflow behaviors are naturally stateful: phase transitions, revocation state, approval state, retries modeled as bounded states, lifecycle progression, or explicit prior-history categories.

C3 adds exactly that class without adding an unbounded heap or hidden persistence.

Each state cell declares:

- a finite domain;
- an explicit initial constant, or initialization from an explicit boundary slot;
- no value outside the declared domain.

The complete mutable state is the declared state vector. There is no second state channel.

This makes “history” honest. If prior history matters, it must enter as a finite boundary slot or be represented in the finite machine state. It cannot leak in from a filesystem, cache, clock, environment variable, or process-global singleton.

## 4. Total finite tables instead of host-language computation

A tempting C3 design would add arithmetic, strings, library functions, or embedded code. That would immediately expand the trusted semantic surface.

C3 instead uses **total finite tables** for nontrivial pure transforms.

A table explicitly declares its argument sources, result domain, and one row for every tuple in the finite Cartesian argument domain. Independent verifiers reject a missing row, duplicate row, surplus row, wrong-domain input, or wrong-domain result.

This is intentionally brute-force. It buys three properties:

- no host-language integer/string corner cases;
- no coercion or undefined behavior;
- no hidden failure or exception channel.

A producer can generate a table using any sophisticated tool it wants. The producer's generator is outside the authority boundary. The verifier only trusts the explicit total table after independently checking it.

## 5. Blocks, explicit branching, and no fallthrough

A block contains an ordered list of pure operations / `EMIT_HEX` operations followed by exactly one terminator.

The terminators are:

- `GOTO`
- `IF_EQ`
- `HALT`

`IF_EQ` names both the true and false successor. There is no implicit fallthrough. Every target must exist.

This removes a class of parser/control-flow ambiguity and gives the reachability graph a small exact semantics.

## 6. Structural termination instead of producer gas

C2 needs a gas value because its tiny instruction language can loop and has no state-space theorem. C3 can do better.

For a fixed boundary point, external inputs never change. A C3 block-entry configuration is:

`(block label, complete finite state vector)`

Execution is deterministic. Therefore, if the same configuration occurs twice before `HALT`, the entire future behavior repeats. The run is nonterminating.

So a C3 verifier does not ask the producer for a timeout or gas budget. It records visited configurations.

- `HALT` before repetition: finite run.
- repeated configuration: deterministic nontermination; no positive closure authority.

For one boundary point there are at most:

`|blocks| × product(state-domain cardinalities)`

possible block-entry configurations.

This converts termination from a heuristic timeout into a finite-state property. Emitting effects before entering a cycle does not help: a finite observed prefix never becomes a complete execution.

## 7. Non-vacuity

C2 rejects a zero-effect halt for positive preservation authority. C3 preserves that discipline.

Every declared boundary point must:

1. terminate; and
2. have a nonempty complete effect trace.

This prevents “nothing was observed, therefore safe” from becoming a preservation proof.

## 8. Ordered trace evidence without changing K1

K1 remains exactly what it was: worlds, an open consequence universe, `ALLOW`, and `REALIZE` as relations.

C3 does **not** change K1 into a trace logic.

However, refinement can lose information before K1 if effects are deleted, duplicated, or reordered. Therefore C3 internally retains a stronger witness:

`boundary point -> ordered sequence of exact raw effect payloads`

The C3 trace map preserves:

- effect presence;
- multiplicity;
- order;
- boundary-point attribution.

Only after the complete trace map is accepted are raw payloads converted using the existing C2 consequence commitment and projected into the K1 set relation.

Thus trace evidence protects the refinement boundary while K1 semantics remain untouched.

## 9. Reachable state-lift graph

The trace alone is extensional. C3 also reconstructs an intensional finite witness: the reachable state-lift graph.

For each boundary point, a graph node binds:

- boundary point;
- block label;
- complete pre-block state vector.

The edge binds:

- the exact ordered effects emitted in that block;
- either `HALT` or the exact successor block/state configuration.

Two independent C3 verifiers must reconstruct the same canonical graph. A producer does not supply the authoritative reachability set.

This is designed to expose attacks that can otherwise look extensionally innocent in a small fixture: omitted states, forged reachability, state-update laundering, hidden branches, or selective effect deletion.

## 10. The C3 → C2 bridge is a normal form, not a trusted compiler

A general source-to-source compiler would create a new trusted component. C3 avoids that.

Each independent C3 verifier first computes the complete direct trace map. It then independently constructs a **Canonical Boundary-Trace Normal Form (CBTNF-v1)** using only the already-qualified C2 instruction set.

The normal form is a canonical decision tree over:

1. `@world`;
2. boundary slots in lexicographic name order;
3. values in lexicographic order.

Every leaf contains the exact direct C3 raw payload trace followed by `HALT`.

An unreachable canonical trap closes the false path after the complete value chain. It must be unreachable for every declared boundary point.

The C2 gas value is not supplied by the producer. W7 and W8 independently execute the exact normal-form bytes under C2 semantics and derive the maximum exact instruction count over the declared boundary.

If the resulting program or gas exceeds the existing qualified C2 limits, the v1 result is **unsupported**, not “probably safe.”

## 11. Why the bridge is extensional

It would be possible to compile every C3 state transition into C2 control locations. That is attractive aesthetically, but it creates a much larger compiler-correctness surface.

CBTNF deliberately chooses the smaller theorem:

> the exact complete behavior of this finite C3 subject, over this exact finite boundary, is extensionally equal to this exact C2 capsule behavior at the consequential cut.

The reachable state-lift graph separately preserves the C3 internal reachability witness. The C2 normal form is only the authority bridge for complete behavior.

This separation is intentional:

- state-lift graph: audit the richer C3 machine;
- ordered trace map: bind exact consequential behavior;
- C2 normal form: reuse qualified closure machinery;
- W0/K1: decide preservation from the exact derived relation.

## 12. The crossed refinement square

The main common-mode risk is a compiler checking its own output using the same mistaken assumptions.

C3 therefore requires two independent implementations, provisionally W7 (Python) and W8 (Go standard library only).

Each independently implements:

- strict C3 parsing;
- validation;
- direct execution;
- state-lift graph reconstruction;
- trace-map reconstruction;
- semantic identity;
- C2 normal-form generation;
- parsing and trace execution of the final exact C2 normal-form byte vector.

The authority gate requires, among other equalities:

- W7 direct C3 trace = W8 direct C3 trace;
- W7 graph id = W8 graph id;
- W7 C2 bytes = W8 C2 bytes;
- W7's independent replay of those C2 bytes = W8 direct C3 trace;
- W8's independent replay of those C2 bytes = W7 direct C3 trace;
- both replay traces = both direct traces, including order and duplicates;
- W5 and W6 independently derive the same final C2 `REALIZE` relation and target.

This forms a crossed refinement square rather than a single compiler pipeline.

## 13. Exact-source identity and semantic identity are different on purpose

C3 binds two identities.

### Exact source identity

`c3src:sha256:` commits the exact submitted profile bytes under a C3-specific domain separator.

Changing whitespace, key order, or declaration order changes this identity when the bytes change. Therefore evidence for one exact source representation cannot be replayed against another.

### Semantic profile identity

`c3sem:sha256:` is independently reconstructed from the parsed semantic object under the exact transcript in the wire protocol.

Only explicitly nonsemantic ordering is normalized: world order, slot-domain order, state/table/block declaration order, and total-table row order. Operation order, table-argument order, and effect order are never normalized away.

Thus representation invariance and exact-byte binding coexist rather than being conflated.

## 14. Why producer metadata is outside authority

The authority profile has an exact-key schema and contains no free-form metadata field.

A surrounding producer envelope may contain names, comments, UI labels, provenance notes, or cached derived values, but those are not authority inputs. A verifier must obtain the exact MFST authority bytes separately and recompute every semantic/derived fact.

This makes the prospective “metadata tamper” positive control precise: metadata can change presentation, but cannot change the independently reconstructed authority result. If exact authority profile bytes change, exact-source identity changes and old evidence cannot be reused.

## 15. Forbidden effects must propagate, not disappear

A verifier that rejects every interesting program is safe but useless. It can also hide semantic bugs.

Therefore a crucial positive/falsification control is:

- if a profile is structurally valid;
- if an effect is fully mediated through `EMIT_HEX`;
- and that payload maps to a consequence outside `ALLOW`;

then C3 must preserve that payload through direct trace reconstruction and C2 normalization. Downstream K1 preservation must fail because the derived `REALIZE` is not a subset of `ALLOW`.

The effect must not disappear merely because it is inconvenient or unknown.

## 16. Relationship to the prospective 32-vector attack gate

The profile was chosen specifically so the frozen C3 attacks have structural answers rather than ad hoc patches.

Examples:

- **direct effect bypass:** no admitted effect primitive other than `EMIT_HEX`;
- **relabeling / laundering:** exact raw payload is retained through ordered trace evidence;
- **first-effect-only projection:** full trace including duplicates is reconstructed;
- **unknown target-native effect:** all raw payloads receive the open-universe C2 commitment;
- **time/RNG/environment/history:** no ambient read exists; variation must be explicit boundary input;
- **async / subprocess / FFI / reflection / dynamic load / thread / signal / shared memory:** absent from the semantic ontology;
- **world/domain shrink:** boundary is reconstructed and worlds must equal the W0 claim exactly;
- **fake `REALIZE`, `complete`, target, reachability:** none is trusted from a producer;
- **TOCTOU:** hash and parse the same byte vector, generate the bridge from that in-memory semantic object;
- **parser differential:** strict JSON subset plus independent implementations;
- **checker disagreement:** no positive authority;
- **reject-everything escape:** valid mediated forbidden effects must propagate to downstream failure rather than be silently suppressed.

Passing the attack gate will still require executable vectors. This design document is not evidence that they pass.

## 17. What C3 v1 intentionally does not solve

C3 v1 does **not** establish any of the following:

- preservation of arbitrary native programs;
- completeness of arbitrary operating-system effects;
- unbounded memory or data;
- recursion or Turing-complete source semantics;
- concurrency or scheduling closure;
- unbounded liveness or deadline properties;
- files, sockets, devices, clocks, RNG, or ambient environment semantics;
- callbacks or external effect responses;
- remote/hardware attestation;
- correctness of a native compiler that claims to implement an MFST profile.

Those are later bridges, not facts smuggled into C3.

## 18. Why this is not merely another toy DSL

The research contribution is not the syntax.

The important architecture is a **proof-carrying narrowing of the implementation boundary**:

1. make all consequence-capable behavior explicit by construction;
2. make all admitted state finite and inspectable;
3. make nontermination decidable for the admitted subject;
4. retain richer trace evidence across refinement without contaminating the kernel;
5. independently reconstruct both intensional reachability and extensional behavior;
6. normalize behavior into an already-qualified smaller authority language;
7. cross-check the refinement in two directions with independent implementations;
8. reuse the existing K1/C2 authority instead of continually enlarging the trusted kernel.

This follows the intended RISU Verify architecture: a small semantic kernel and small authority checkers, with expressiveness pushed outward into producers and profiles that must earn their way back into the trusted core.

## 19. Qualification sequence

The design does not become authority by documentation. The next qualification sequence is:

1. freeze concrete MFST fixtures for every applicable prospective C3 attack and positive control;
2. implement W7 from the normative profile/wire without changing the gate;
3. implement W8 independently from the normative profile/wire;
4. add exact graph/trace/identity known-answer tests;
5. add CBTNF byte-level known-answer tests;
6. cross-run the refinement square;
7. feed the independently reconstructed C2 bridge to W5 and W6;
8. run the frozen 32-vector adversarial gate;
9. add seeded generative/differential testing over valid finite machines and one-field mutations;
10. only then consider creating and qualifying a versioned C3 production proof kind.

A failing vector is evidence against the current C3 design or implementation. The frozen gate is not to be weakened to save the result.

## 20. Promotion boundary

Even after successful qualification, the strongest honest claim should remain narrow:

> For an exact valid C3 MFST profile over an exact finite boundary, two independent C3 verifiers can reconstruct the same complete finite-state behavior and exact ordered consequential traces, independently reduce that behavior to the same canonical C2 capsule, and the existing independent C2 checkers can re-derive the same K1 closure relation and preservation result.

That claim would be materially stronger than C2 in expressiveness while preserving the central K1 discipline: positive preservation comes from adequate closure, not from sampling, confidence, or a producer declaring itself complete.
