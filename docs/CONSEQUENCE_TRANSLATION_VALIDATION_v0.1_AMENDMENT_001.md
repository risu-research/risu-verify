# Consequence Translation Validation — Amendment 001

**Status:** FROZEN PRE-UNIT003 / PRE-VERDICT  
**Parent:** `RISU_CTV_META_THEORY_001`  
**Effective:** Corpus 0.1 Unit 003 onward  
**Historical effect:** none. Units 001 and 002 remain exactly as canonically closed.

## Why this amendment exists

The first merged CTV v0.1 contract correctly made `S(w)` and `T(w)` nonempty, but it did not explicitly require the interpretation set `M(r)` to be nonempty when a target realization is used to establish consequence refinement. That leaves a classic vacuity hole: if `M(r)=∅`, then `union M(r) ⊆ S(w)` can hold even though the target realization has not been given any consequence meaning at all.

That is unacceptable for RISU. Missing interpretation is missing assurance, not preservation.

A second ambiguity came from rendering `L0` through `L5` as an ordered list while the prose also allowed levels to be reported independently. A future implementation could incorrectly infer `L4 => L3 => ...` from numeric labels alone. This amendment makes the intended structure machine-explicit: compatibility is a named obligation vector, not an implicit total order.

Both defects were identified after the v0.1 freeze merged but while Unit003 remained pristine: `authoring_started=false`, `authoring_frozen=false`, and no Unit003 verdict had been observed. The amendment therefore changes no observed scientific result.

## A001.1 Non-vacuous consequence interpretation

For every admitted world `w` and every target realization `r ∈ T(w)` that is material to an `L4_CONSEQUENCE_REFINEMENT` or `CONSEQUENCE_STABLE_IN_DECLARED_SCOPE` claim:

`M(r) != ∅`.

The effective relational obligation is therefore:

1. `T(w) != ∅`;
2. every material `r ∈ T(w)` has `M(r) != ∅`;
3. `union_{r in T(w)} M(r) ⊆ S(w)`.

If the evidence does not support any consequence interpretation for a material target realization, that realization is **unresolved**. The engine must either prospectively narrow the declared scope before primary execution or return `ASSURANCE_INCOMPLETE`. It may not encode missing knowledge as an empty set to manufacture refinement.

This also restores the expected bridge to the deterministic fragment. If source consequences are singletons and a deterministic target realization is shared by two worlds, a single nonempty `M(r)` cannot be a subset of two different singleton source consequences. Thus relational refinement cannot silently coexist with a deterministic collapse witness.

## A001.2 Compatibility is not an implicit chain

The names remain:

- `L0_SURFACE`
- `L1_REPRESENTATION`
- `L2_DISTINCTION`
- `L3_OPERATIVE`
- `L4_CONSEQUENCE_REFINEMENT`
- `L5_DECLARED_SCOPE_COVERAGE`

But their structure is normatively:

`NAMED_OBLIGATION_VECTOR_NOT_TOTAL_ORDER`.

There are **no implicit level implications**. A profile may declare an implication only when that implication is separately justified and machine-recorded. In particular:

- an `L4` result does not automatically establish `L3` effect placement;
- `L5` is coverage/completeness over the declared claim and does not silently upgrade semantic obligations `L0–L4`;
- UI may present the labels in numeric order for readability, but the verifier must reason over explicit obligations, not ordinal arithmetic.

## A001.3 Verdict hardening

`CONSEQUENCE_STABLE_IN_DECLARED_SCOPE` now additionally requires nonempty consequence interpretation for every target realization material to the declared stability obligation.

An uninterpreted material realization produces `ASSURANCE_INCOMPLETE` unless the scope was narrowed prospectively before the primary freeze.

A sound concrete `CONSEQUENCE_REGRESSION` witness still dominates unrelated incompleteness on its witnessed declared slice. The amendment does not make regression harder to report when the violating semantics are already established.

## A001.4 Non-retroactivity

This amendment does not rename, recalculate, strengthen, weaken, or reinterpret Unit001 or Unit002. Their canonical verdicts, C/D/O values, Exact Realization state, coverage fields, evidence, artifacts, and closure authority remain untouched.

The amendment may not be cited as though it had been precommitted before those historical primary results.

## A001.5 External-theory pressure test

The amendment is consistent with the external ideas already adopted by CTV:

- translation validation treats a concrete translation as a refinement question rather than trusting the transformer globally;
- strong preservation/partition refinement warns against collapsing semantically distinguishable states;
- CEGAR treats missing abstraction precision as a reason to refine or remain incomplete, not as evidence of correctness;
- certifying verification motivates a small checker whose accepted proof obligations are explicit and non-vacuous.

The key RISU rule is correspondingly strict: **absence of interpreted consequence is absence of assurance.**

## Freeze rule

A001 is frozen before Unit003 authoring and before any Unit003 verdict. Any later normative change requires Amendment 002 or a new version, with explicit timing and result-impact classification.
