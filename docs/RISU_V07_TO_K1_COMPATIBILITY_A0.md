# RISU v0.7 → K1 Compatibility A0

**Status:** prospective architectural calibration; non-authoritative with respect to new source or target truth.  
**K1 branch:** `k1-adversarial-gate-a0`  
**Frozen calibration source:** `risu-research/risu-verify@a548a07152c068805a147e47aa18aa40a2ffa492`, `results/VBE_CALIBRATION_DIFFERENTIAL.json`, Git blob `434ef5f4601e8adb7eb33570676ab0f68fc09306`.

## Question

Can the proposed K1 narrow waist reproduce the four already-frozen v0.7 commissioning conclusions **without** C/D/O, Exact Realization, carrier coordinates, or profile-specific logic becoming kernel primitives?

This is not a new analysis of GitHub or Azure behavior. The adapter is forbidden to recover authority from current source, network state, repository paths, or retrospective interpretation. It consumes only the pinned four-row semantic differential already produced by v0.7.

## Translation

For each frozen row:

1. each legacy world becomes one committed K1 world, namespaced by the frozen `source_semantic_digest` for that declared source semantics;
2. `(world, required_consequence)` becomes `ALLOW`;
3. a projected effect in consequence space `C` becomes the correspondingly named realized consequence;
4. a projected effect in `OUTSIDE_C` becomes a distinct **target-native** open-universe consequence rather than being discarded or coerced into the source vocabulary;
5. the resulting complete finite relation is submitted to the independent W1 finite-model checker;
6. a forbidden realized pair is checked as a regression witness; otherwise the complete finite relation is checked as a preservation certificate.

The source semantic digest is a **migration identity namespace**, not a K1 kernel primitive. This matters for the historical repair pair: BEFORE and AFTER have the same frozen source semantics and world labels, so they must produce the same K1 claim identity. The target relation alone changes.

The adapter computes the K1 conclusion first. Only afterward is that conclusion compared with the frozen legacy product status.

## Anti-tautology controls

The compatibility verifier is designed to catch a fake adapter that merely copies the legacy result.

- Altering a frozen semantic projected effect while leaving the legacy status unchanged must make equivalence fail.
- Altering C/D/O, Exact fields, `matches`, or world coordinates must not change K1 claim identity, target identity, proof identity, or verdict.
- Tampering with the pinned source locator is rejected.
- `OUTSIDE_C` survives translation as a target-native consequence and therefore remains capable of producing a forbidden K1 witness.
- The GitHub blob-SHA BEFORE/AFTER pair must preserve both the same frozen source semantic digest **and the same K1 claim ID**, while changing the target ID and reproducing `CONSEQUENCE_REGRESSION → PRESERVED`.

The initial compatibility run intentionally failed this final repair invariant because the first adapter version incorrectly namespaced migrated worlds by case-instance ID. That defect was not waived. World identity was repaired to bind to the frozen source semantic identity instead, after which the compatibility test step passed. This failure is retained in workflow history as evidence that the gate can reject a structurally plausible but semantically wrong migration design.

## Interpretation rule

A PASS establishes only this:

> On the four frozen calibration rows, the K1 `ALLOW/REALIZE` safety relation plus independently checked finite-model proof objects is sufficient to reproduce the v0.7 product-level semantic conclusions without importing C/D/O or Exact as kernel primitives.

A PASS does **not** establish that W1 is bound to a real implementation. W1 explicitly reports `implementation_binding: false` and `assurance_scope: DECLARED_FINITE_TARGET_MODEL`. The old evidence/provenance machinery remains relevant to future proof kinds that establish such binding.

## Architectural consequence

If the gate passes, the migration experiment has done what it was meant to do: it has failed to find an irreducible semantic role for C/D/O/Exact inside the K1 kernel on the commissioning set. They remain valuable diagnostics and evidence decomposition, but the burden of proof shifts against enlarging the narrow waist.

That result is deliberately narrower than “K1 is complete.” New domains may still falsify the calculus. Future kernel growth is justified only by a counterexample that cannot be represented faithfully by the current consequence relation and proof obligations.
