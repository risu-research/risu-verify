# RISU Diff E0 — Development Firewall and Held-Out Evaluation Contract v0.1

**Status:** prospective freeze before Unit003 semantic inspection  
**Base main:** `bd9ed54e9c1703f505f1b08ff3cb4c8f22c48afc`  
**Applies to:** RISU Diff / CTV engine E0 and the prequential evaluation beginning with Corpus 0.1 Unit003.

## 1. Why this freeze exists

E0 is not allowed to become a system that looks good because its architecture, features, baselines, or metrics were tuned after inspecting the next Corpus target. The remaining verdict-blind Corpus sequence is too valuable to consume as ordinary development data.

The protocol therefore separates three things:

1. **development data** — Unit001, Unit002, historical/calibration cases, and Unit002-M mutation controls;
2. **held-out evaluation units** — Unit003 through Unit008, consumed sequentially by a test-then-learn protocol;
3. **canonical scientific authority** — the existing prospective Corpus authoring and frozen scientific producer/consumer, which E0 does not replace.

This is an evaluation firewall, not a claim that the author has never seen the enrollment table. Enrollment identity and ordering are already public. The protected information is **target-specific semantic evidence and implementation analysis beyond the guard-only enrollment metadata before the machine-first E0 output is sealed**.

## 2. Design lineage used by E0

E0 intentionally combines mature ideas rather than treating API-diff tooling as its only ancestor.

- **Alive2 / translation validation:** validate each concrete translation instance instead of proving an entire transformer. E0 is a candidate front-end for CTV, not a proof that every SDK/MCP/API generator is correct.
- **CodeQL path queries:** represent semantic flow as a graph and make source-to-sink/path explanations a first-class output.
- **cargo-semver-checks / Trustfall:** prefer checks-as-data over a growing collection of carrier-specific imperative checks. VBE obligations should be declarative over CIR.
- **RESTler:** infer resource/producer-consumer dependencies and use targeted execution feedback to resolve stateful uncertainty.
- **CEGAR:** begin with a conservative coarse model and acquire only evidence needed to eliminate a spurious witness or discharge a required obligation.
- **QuickCheck/Hypothesis + delta debugging:** minimize a valid failure after finding it; never shrink by weakening the failure predicate.
- **certifying verification:** treat extractors, probes, model builders, synthesizers, and search as untrusted. Long-term proof/witness checking should be independently replayable.

These ideas shape implementation, but the normative semantic meanings remain those frozen in CTV v0.1 plus Amendment 001.

## 3. Development-data firewall

E0 semantic development may use:

- closed Unit001 and Unit002 artifacts;
- VBE calibration cases;
- Unit002-M mutation-control data;
- historical cases and the existing VBE calibration differential.

The frozen CTV contracts, CIR/refinement-map schemas, VBE profile, Workbench transport layer, and frozen core may be consulted as methodology/implementation references.

`ENROLLMENT.json` and the prospective Corpus protocol are **guard-only**: E0 code/tests may inspect only enrollment identity, ordering, and pristine authoring/verdict flags. They may not mine later-unit target descriptions to create features, rules, probes, or test fixtures.

Before a held-out unit's machine-first output is sealed, E0 development must not inspect external source code, documentation, issues, tests, or discussions specific to that held-out target. Methodological research remains allowed.

## 4. E0 architecture boundary

E0 is an **untrusted model-acquisition and explanation layer**. Its planned stages are:

`evidence/source trees → conservative CIR → declarative VBE obligations → static coordinate-flow candidates → probe plan → CEGAR evidence refinement → CTV prediction → witness shrinking → baseline comparison`

E0 may emit predictions in the `E0_PREDICTED_*` namespace. It may not emit or masquerade as the canonical scientific Corpus verdict.

Unknowns remain explicit. A missing edge, mapping, consequence interpretation, unsupported carrier construct, or probe failure cannot be converted into stability.

## 5. Checks as data

The VBE engine must separate:

- **CIR extraction** — carrier-specific and untrusted;
- **profile obligations** — declarative and carrier-neutral;
- **query execution** — generic over CIR;
- **scientific authority** — external to E0.

The target architecture is therefore closer to a CodeQL/Trustfall-style semantic database plus declarative queries than to a pile of one-off scanners.

## 6. Machine-first artifact contract

Each held-out run must seal, before human gold authoring can inspect it:

- `CIR_CANDIDATE.json`
- `REFINEMENT_MAP_CANDIDATE.json`
- `VBE_OBLIGATIONS.json`
- `E0_PREDICTION.json`
- `PROBE_PLAN.json`
- `REFINEMENT_REQUESTS.json`
- `BASELINE_RESULTS.json`
- `E0_RUN_MANIFEST.json`

A regression candidate additionally should provide a replayable `WITNESS_CANDIDATE.json` and shrink trace when available.

Every `ESTABLISHED` semantic element must identify evidence. Evidence-free confidence is not an established fact.

## 7. Blind gold isolation

The strongest useful comparison requires two independent freezes:

1. E0 analyzes the held-out unit and its exact machine-first output is sealed.
2. Human scientific authoring proceeds under the prospective Corpus protocol **without access to E0 output**.
3. Human gold is frozen.
4. Only then are E0 and gold compared.

If E0 output leaks to the human-gold lane before freeze, the scientific unit may remain valid, but that unit loses its status as a clean held-out evaluation of machine semantic acquisition.

## 8. Prequential test-then-learn

The remaining Corpus is consumed sequentially:

`freeze E0 → test Unit003 → freeze gold → score E0 → learn from Unit003 → freeze E1 → test Unit004 → ...`

A unit becomes development data only after its engine prediction and independent human gold are both frozen and scored.

This produces a sequential generalization record rather than a retrospective benchmark optimized on all available cases.

## 9. What gets measured

For VBE, the material role set is frozen as:

1. authoritative version coordinate;
2. current version at effect;
3. binding/compare guard;
4. declared effect;
5. stale mismatch outcome/interpreter.

Evaluation reports role recall, material edge recall, precision of `ESTABLISHED` facts, explicit unresolved rate, refinement-map relation accuracy, prediction agreement, witness validity/minimality when relevant, generated-probe success, human correction count, active human authoring time, and machine runtime.

Unit003 is one held-out observation. It may establish a hard-stop violation or provide descriptive evidence, but it cannot justify population-level accuracy claims.

## 10. Hard stops

E0 fails its safety objective if any of these occur:

- **false stable** against a canonical consequence regression;
- an `ESTABLISHED` semantic fact or mapping has no evidence or is contradicted by frozen gold;
- unknown material semantics are silently converted into compatibility;
- held-out target-specific semantic inspection occurs before machine-first seal;
- machine output contaminates human gold before gold freeze;
- metrics/baseline meanings are rewritten after result observation without a timed amendment;
- an E0 prediction is represented as the canonical scientific verdict.

These are intentionally asymmetric. A conservative `ASSURANCE_INCOMPLETE` may hurt automation recall; a false stability claim attacks the core assurance property.

## 11. Baselines

E0 begins with carrier-neutral baselines that make progressively stronger non-CTV assumptions:

- **B0 Surface** — callable/schema/argument surface only;
- **B1 Name/shape** — candidate semantic-coordinate matching from lexical or structural similarity, without operative flow;
- **B2 Flow-only** — coordinate reaches an effect/request sink, but source consequence and failure interpretation are ignored;
- **Human gold oracle** — post-freeze reference only, never a machine-first input.

Carrier-specific external baselines may be added only by a pre-result amendment for the held-out unit where they will be scored. This prevents choosing a convenient baseline after seeing the outcome.

## 12. CEGAR policy

E0 begins with the smallest conservative CIR it can justify. When a required VBE obligation is unresolved or a candidate witness may be spurious, it records the exact uncertainty and asks for the minimum additional evidence or target-only probe needed to resolve that uncertainty.

A counterexample can be dismissed as spurious only because:

- new evidence establishes the missing relation; or
- a modeling/extraction defect is identified and recorded.

The system may not change the source consequence, metric, or verdict semantics merely to make a counterexample disappear.

## 13. Witness shrinking

After a valid failure predicate exists, shrinking optimizes lexicographically:

1. number of differing world coordinates;
2. action/realization trace length;
3. irrelevant context/evidence.

Validity is checked after every shrink. The end goal is a witness a maintainer can independently understand and replay, not merely the smallest JSON object.

## 14. Freeze rule

Any change to this evaluation contract after merge requires a numbered amendment stating:

- whether any held-out semantic target inspection had occurred;
- whether any E0 machine output had been observed;
- whether human gold had been frozen;
- whether a canonical scientific result had been observed;
- exact changed metric/baseline/firewall semantics;
- whether the change can affect scoring.

Unit003 authoring must remain pristine until the E0 engine intended for its machine-first evaluation is itself frozen.
