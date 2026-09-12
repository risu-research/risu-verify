# RISU Kernel K1 — Adversarial Gate A0

**Status:** PROSPECTIVE / NON-NORMATIVE / PRE-WIRE-SCHEMA  
**Parent:** `e2-development@e5bb5285acbfce6c9b22fea94f8bb58c746aed0b`  
**Purpose:** attempt to falsify the proposed `ALLOW / REALIZE` narrow waist before freezing any K1 constitution, wire schema, or checker.

## 1. Why A0 exists

The v0.7-to-K1 equivalence audit reproduced the four canonical historical conclusions while exposing two design errors in the first K1 draft: factorization alone is not consequence correctness, and an empty interpretation can make subset refinement vacuously true. The surviving candidate center is the relation normal form

`ALLOW ⊆ W × U`

`REALIZE ⊆ W × U`

with a grounded forbidden realization as the primitive regression witness.

A0 is deliberately not another benchmark. It is a constitutional falsification gate. Its job is to make tempting incorrect kernels fail before any format becomes stable.

## 2. A0 method: mutation testing the kernel idea

A test suite that merely makes the intended implementation pass is weak. A0 therefore defines ten deliberately wrong kernels and asks whether the synthetic cases kill them.

The mutants encode mistakes that are plausible given the project's own history:

1. omit closure and treat subset inclusion as sufficient;
2. let one allowed nondeterministic branch mask a forbidden sibling;
3. count an ungrounded realization as a regression;
4. require equality instead of safety refinement by subset;
5. require global completeness before accepting a local grounded counterexample;
6. admit a world with no source-allowed consequence;
7. admit an empty world scope and accept vacuous preservation;
8. omit per-world consequence-cut totality;
9. close the consequence universe over source labels and silently discard target-native outcomes;
10. return to factorization/partition preservation as the fundamental verdict rule.

A0 contains one positive control and nine mutation-killer cases. Against the declared mutant class, the nine-case attack basis is **deletion-minimal**: removing any one mutation-killer leaves at least one declared mutant alive. This is a precise claim about the explicit A0 mutant class, not a claim of universal mathematical minimality.

## 3. Kernel attack basis

| Case | Expected | What it attacks |
|---|---|---|
| `K0_BASELINE` | `PRESERVED` | positive sanity control |
| `K1_WRONG_LABEL_DISTINGUISHABLE` | `BREAKING` | factorization-only and closed consequence vocabularies |
| `K2_PARTIAL_REALIZE` | `UNKNOWN` | incomplete realization presented as complete |
| `K3_NONDET_POISON` | `BREAKING` | allowed branch masking a forbidden branch |
| `K4_UNGROUNDED_FORBIDDEN` | `UNKNOWN` | semantic claims without grounding |
| `K5_STRICT_SAFE_SUBSET` | `PRESERVED` | accidental equality semantics instead of safety refinement |
| `K6_LOCAL_BREAK_GLOBAL_INCOMPLETE` | `BREAKING` | global incompleteness erasing a valid local regression witness |
| `K7_EMPTY_WORLD` | `MALFORMED` | vacuous empty-scope preservation |
| `K8_EMPTY_ALLOW` | `MALFORMED` | contradictory admitted source world |
| `K9_NO_OUTCOME_AT_CUT` | `UNKNOWN` | positive vacuity from an outcome-less consequential cut |

The synthetic field `actual_possible` is **A0 oracle data only**. It lets the gate know whether a submitted `REALIZE` relation is genuinely exhaustive. It must not become a future K1 wire field or a trusted `closed=true` assertion.

## 4. Boundary metamorphics

A0 also checks four properties that belong at the kernel boundary rather than in the fundamental relation calculus.

### B1 — representation invariance

Changing carrier/diagnostic metadata while `W`, `ALLOW`, `REALIZE`, grounding, and claim identity remain fixed must not alter the semantic verdict. HTTP headers, MCP fields, CIR nodes, guard names, and similar representation objects therefore stay outside the K1 judgment.

### B2 — evidence ablation

If the only grounding for a forbidden realized consequence is removed, `BREAKING` must downgrade to `UNKNOWN`, not to `PRESERVED`. Diagnostic evidence may survive independently, but it cannot impersonate a semantic witness.

### B3 — post-check material transition

K1 does not require a temporal logic primitive merely because a state may change between check and effect. A declared world may be a trajectory, and grounding is anchored at the declared consequential cut. A trajectory `reviewed=H0 | check=H0 | effect=H1` that realizes `COMMIT_H1` where the contract permits only `STALE_REJECT` is an ordinary forbidden realization.

### B4 — contract/scope binding

`W` and `ALLOW` are part of claim identity. Post-hoc widening of `ALLOW` or deletion of a violating world can trivially flip a result and therefore must create a different claim/certificate. The future wire format must cryptographically bind them before evidence/results can be used to support that claim.

## 5. A0 result

The executable gate passes all ten reference cases, kills all ten declared mutants, proves deletion-minimality of the nine mutation-killer cases against that mutant class, and passes all four boundary metamorphics.

The result is **support for**, not a freeze of, the `ALLOW / REALIZE` narrow waist.

## 6. Constitutional findings after A0

A0 strengthens the provisional K1 constitution in several precise ways without adding a new semantic relation.

### 6.1 Fundamental safety relation survives

For the tested safety/refinement fragment, the semantic center remains:

`Violation = Grounded(REALIZE) − ALLOW`

A single grounded element of that difference is enough for `BREAKING` in the witnessed declared slice.

### 6.2 Positive proof needs three independent obligations

`PRESERVED` cannot be derived from inclusion alone. It requires:

1. **checkable closure/exhaustiveness** of the submitted target consequence relation;
2. **grounding** of every submitted realized consequence;
3. **per-world consequence-cut totality**, so every admitted world has an explicit material outcome at the declared cut;
4. and only then `REALIZE ⊆ ALLOW`.

`Closed` must eventually be a proof/certificate property. A producer-supplied Boolean is not evidence.

### 6.3 Regression and preservation remain deliberately asymmetric

A valid local forbidden witness must not be erased by unrelated incompleteness elsewhere. Conversely, failure to find a counterexample never establishes preservation.

### 6.4 Open consequence universe is mandatory

Target-native outcomes not named by the source contract must remain representable. Otherwise precisely the outcomes RISU needs to reject can disappear before the subset test is evaluated.

### 6.5 Factorization stays derived, not fundamental

Partition/factorization remains useful for generating collapse witnesses. It is not sufficient for consequence correctness because a target can distinguish every world and still perform the wrong action.

### 6.6 Strict safe subset does not yet justify `MUST`

A target that realizes a strict subset of source-permitted outcomes passes the pure safety/refinement claim when the relation is closed, grounded, and total. If a profile requires availability, progress, or a success path, that obligation must be explicit. A0 does not add `MUST/REQUIRE` to K1 merely to encode an undeclared liveness intention.

## 7. What A0 does not prove

A0 does not prove model adequacy, source truth, target extraction correctness, or universal expressiveness. It does not define the final certificate calculus. It does not authorize retroactive reinterpretation of v0.7 results. It does not establish that the nine attack cases cover every possible incorrect K1 design.

Its narrower achievement is stronger: the current candidate relation survives a deliberately adversarial, mutation-tested pre-freeze gate, and the gate itself is strong enough to distinguish it from ten concrete nearby wrong designs.

## 8. Next gate

Only after A0 passes should K1 acquire a wire format.

The next step is therefore **K1 Wire W0**, with one hard rule inherited from A0:

> the wire schema may serialize claims and proof objects, but it may not turn untrusted assertions such as `closed=true`, `grounded=true`, or a producer-selected consequence vocabulary into semantic authority.

W0 should make `W + ALLOW` claim identity explicit, represent target-native canonical consequences in an open universe, and leave closure/grounding as independently checkable certificate obligations. Only after W0 survives its own malformed-input and canonicalization attacks should a tiny independent checker be implemented.
