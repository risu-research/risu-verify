# Consequence Translation Validation — Meta-Theory v0.1

**Status:** NORMATIVE FUTURE-UNIT FREEZE  
**Effective scope:** future RISU engine/product work beginning before Corpus 0.1 Unit 003 authoring  
**Non-retroactivity:** Corpus 0.1 Units 001 and 002 retain their canonical scientific records exactly as closed. This document does not rename, strengthen, weaken, recompute, or reinterpret their C/D/O, Exact Realization, coverage, certificate, or product verdicts.

## 1. Objective

RISU treats an interface projection as a semantic translation boundary.

A source operation has consequence semantics over an admitted world space. A target carrier—SDK, API wrapper, MCP tool, generated binding, CLI, or another interface—realizes observations and behaviors from those worlds. **Consequence Translation Validation (CTV)** asks whether the target realization preserves the consequence distinctions declared by the source model.

CTV is deliberately per-instance and bounded. It follows the translation-validation strategy: the system does not need a proof that every transformation performed by a carrier generator is correct. It checks a concrete source-to-target projection under an explicit scope and evidence boundary.

This meta-theory is a contract for future RISU engines. It does not enlarge the trusted computing base of the frozen v0.7 scientific producer/consumer, and it is not itself a formal proof of that core.

## 2. Semantic objects

Let:

- `W` be the declared world space.
- `A ⊆ W` be the admitted worlds for the claim.
- `C` be a consequence domain.
- `R` be a target-realization domain.
- `S(w) ⊆ C` be the nonempty set of source-admissible consequences at world `w`.
- `T(w) ⊆ R` be the nonempty set of target realizations at world `w`.
- `M(r) ⊆ C` be an **explicit** interpretation/refinement mapping from target realization `r` to consequences.

No semantic equivalence between source and target identifiers is inferred from spelling, carrier convention, prior RISU verdict, or a desired result. Any cross-representation equivalence needed by a claim must appear in a frozen refinement mapping with evidence.

### 2.1 Relational consequence refinement

For admitted world `w ∈ A`, define the target-induced consequence set:

`T_hat(w) = union_{r in T(w)} M(r)`.

The target is **consequence-refining in declared scope** when:

`for all w in A: T_hat(w) ⊆ S(w)`.

This is a safety/refinement condition: the target may not realize a consequence excluded by the declared source semantics.

A future profile MAY require stronger obligations—availability of a success path, failure exactness, effect placement, evidence coverage, or exact realization. Those obligations must be recorded separately rather than smuggled into the subset relation. In particular, a target that rejects everything may satisfy a pure behavior-subset relation while failing an operative or realization obligation.

### 2.2 Deterministic factorization fragment

When both the declared source consequence and target realization are deterministic:

`kappa_S : A -> C`  
`rho_T   : A -> R`

CTV's distinction-preservation condition is:

`there exists g : R -> C such that kappa_S = g o rho_T`.

Equivalently:

`rho_T(w1) = rho_T(w2)  =>  kappa_S(w1) = kappa_S(w2)`.

Equivalently, using kernels/equivalence relations:

`ker(rho_T) ⊆ ker(kappa_S)`.

Thus the target-realization partition must be at least as fine as the declared source-consequence partition.

This deterministic fragment is the normative basis for RISU's minimal collapsed-world witness.

## 3. Regression witnesses

A **consequence-collapse witness** is an admitted pair `(w1, w2)` such that:

`rho_T(w1) = rho_T(w2)` and `kappa_S(w1) != kappa_S(w2)`.

Such a pair is a constructive refutation of deterministic distinction preservation.

For the general relational fragment, a regression witness is an admitted world `w`, a target realization `r ∈ T(w)`, and a consequence `c ∈ M(r)` with `c ∉ S(w)`. A product MAY additionally return a paired-world witness when one exists.

Witnesses must identify the declared world coordinates that differ, the source consequence that separates them, the target realization that collapses or violates them, and the evidence chain supporting each material fact.

## 4. Repair as refinement

For deterministic CTV, the target induces partition `P_T` on admitted worlds by equality of `rho_T`. The source consequence induces partition `P_S` by equality of `kappa_S`.

A repair is semantically sufficient only if the repaired realization partition `P_T'` no longer places any pair with different source consequences in the same block.

A **minimal repair obligation** is a minimal-cost refinement, under an explicitly declared cost/order relation, that separates every currently admitted violating pair. The meta-theory does not commit to one synthesis algorithm. Weighted hitting set, partition refinement, CEGIS, SyGuS, or another sound method may implement this obligation.

No repair suggestion becomes a preservation result until the repaired projection is reverified.

## 5. Consequence IR (CIR)

CIR is a carrier-neutral typed graph used by future untrusted extraction and product layers. CIR is not a verdict engine.

Normative node kinds in v0.1:

- `OPERATION`
- `RESOURCE`
- `INPUT`
- `SEMANTIC_COORDINATE`
- `GUARD`
- `EFFECT`
- `OUTCOME`
- `FAILURE`
- `INTERPRETER`
- `EVIDENCE`

Normative edge kinds in v0.1:

- `CARRIES`
- `DERIVES`
- `BINDS_TO`
- `COMPARES`
- `GUARDS`
- `PRECEDES`
- `MUTATES`
- `REJECTS_AS`
- `INTERPRETS_AS`
- `EVIDENCED_BY`

CIR may contain unknown or unresolved nodes/edges. Unknown information must remain explicit; extractors may not invent an edge to satisfy a profile.

A profile such as Version-Bound Effect is expressed as obligations over CIR plus source consequences, not as carrier-specific procedural truth.

## 6. Explicit refinement mapping

Any future CTV comparison between source semantic elements and target CIR elements must carry a frozen mapping entry whose relation is one of:

- `EXACT_IDENTITY`
- `ESTABLISHED_EQUIVALENT`
- `REPRESENTED_BY`
- `DISTINCT`
- `UNRESOLVED`

`ESTABLISHED_EQUIVALENT` and `REPRESENTED_BY` require evidence references and a declared direction. `UNRESOLVED` may narrow coverage or force `ASSURANCE_INCOMPLETE`; it may not be silently upgraded after seeing a primary result.

Mapping is explicit by design. Identifier equality is neither necessary nor sufficient for semantic equivalence.

## 7. Compatibility levels

CTV separates progressively stronger claims rather than compressing them into one `compatible` bit.

1. `L0_SURFACE` — callable/schema surface compatibility only.
2. `L1_REPRESENTATION` — a required source semantic coordinate has an explicit target representation mapping.
3. `L2_DISTINCTION` — target observations do not collapse declared consequence-separated worlds in the deterministic fragment, or the corresponding relational distinction obligation is established.
4. `L3_OPERATIVE` — the represented distinction is connected to the declared effect/failure cut by established guard/interpreter paths.
5. `L4_CONSEQUENCE_REFINEMENT` — relational consequence refinement is established on admitted worlds.
6. `L5_DECLARED_SCOPE_COVERAGE` — every material mapping/obligation required by the declared claim scope is resolved at its required evidence strength.

Levels are not inferred merely from a higher-looking schema feature. Each level requires its own evidence/derivation obligations. A future engine may report several levels independently when the relation is not a simple chain.

## 8. Future CTV verdict semantics

Future `risu diff`/CTV engines use a verdict namespace distinct from the closed v0.7 case vocabulary.

### `CONSEQUENCE_REGRESSION`

Allowed only when a valid consequence-refinement violation is established, with a concrete witness and evidence chain.

This verdict dominates unrelated incompleteness for the witnessed declared slice: once a sound violation exists, unresolved unrelated mappings do not erase the regression, though coverage limitations must remain visible.

### `CONSEQUENCE_STABLE_IN_DECLARED_SCOPE`

Allowed only when the required consequence-refinement obligations for the declared scope are established and no admitted counterexample exists under the accepted model/evidence boundary.

It must always expose a separate coverage field. The unqualified word `STABLE` must not be rendered as a substitute when coverage or model adequacy is narrower than a reader could reasonably infer.

### `ASSURANCE_INCOMPLETE`

Required when neither a valid regression witness nor the required preservation/refinement proof obligations can be established at the declared evidence strength.

Missing evidence, unresolved refinement mapping, unsupported carrier semantics, solver/resource exhaustion, or model-acquisition uncertainty are not semantic preservation.

### Infrastructure failure

Malformed inputs, broken provenance, seal failures, checker failures, or toolchain/infrastructure defects are not CTV verdicts. They remain fail-closed infrastructure outcomes.

## 9. Coverage and model adequacy are separate

CTV distinguishes:

- **declared-scope coverage:** whether all mappings and obligations required by the already-declared claim are resolved;
- **model adequacy:** whether the declared source consequence model omitted a material consequence distinction.

The first can be mechanically audited. The second generally cannot be proven by CTV itself.

Future units therefore may add target-blind source-model adequacy challenges, independent red-team authoring, or other model-elicitation procedures. Such procedures strengthen confidence but must not be described as universal completeness proofs.

## 10. Trust boundary

The long-term architecture SHOULD minimize the trusted base.

**Untrusted/disposable candidates:** LLM extraction, static analysis, dependency traversal, black-box learning, generated probes, repair synthesis, SMT search.

**Trusted/checkable boundary:** CIR/refinement-map validation, small consequence semantics, certificate/witness checker, immutable evidence identities.

Regression witnesses should become independently replayable. Preservation proofs may gain independent proof checking in supported fragments. A cvc5/Alethe/Carcara-style proof lane is a candidate future mechanism, not a normative dependency of v0.1.

## 11. Anti-retroactivity

This freeze is prospective.

It MUST NOT:

- rename Unit 001 or Unit 002 canonical verdicts;
- recalculate their C/D/O or Exact Realization under CTV;
- convert Unit 002's `coverage_complete=false` into a stronger result;
- backfill refinement mappings that retroactively strengthen closed primary claims;
- alter closed primary artifacts or closure records.

Historical units MAY later be translated into CIR solely as a separately labeled calibration/compatibility exercise. Such a translation must preserve the original canonical result as authoritative and may not be cited as if CTV had been precommitted before those results.

## 12. Intellectual lineage

CTV intentionally combines established ideas rather than claiming them as new in isolation:

- **Translation validation / Alive2:** concrete per-transformation refinement checking rather than proving an entire transformer correct. Alive2 is bounded, automatic, SMT-backed, and designed to avoid false alarms.
- **Strong preservation / abstract interpretation:** state abstraction as partitioning/indistinguishability, with refinement toward an abstraction that strongly preserves a specification language.
- **CEGAR:** refine a coarse model in response to spurious counterexamples rather than demanding a maximally rich model up front.
- **Delta debugging / shrinking:** minimize failure-inducing circumstances after a valid failure predicate exists.
- **Certifying verification:** independently check produced evidence/proofs where the fragment permits it.

The RISU-specific research question is the composition of these ideas at an interface projection boundary around **declared consequential machine action**, with prospective evidence and explicit claim limits.

### Primary references

1. N. P. Lopes, J. Lee, C.-K. Hur, Z. Liu, J. Regehr. *Alive2: Bounded Translation Validation for LLVM*. PLDI 2021. DOI: `10.1145/3453483.3454030`.
2. F. Ranzato, F. Tapparo. *Generalized Strong Preservation by Abstract Interpretation*. arXiv:`cs/0401016`.
3. E. Clarke, O. Grumberg, S. Jha, Y. Lu, H. Veith. *Counterexample-Guided Abstraction Refinement*. CAV 2000.
4. A. Zeller, R. Hildebrandt. *Simplifying and Isolating Failure-Inducing Input*. IEEE TSE 28(2), 2002.
5. cvc5 documentation: Alethe proof output and independent checking ecosystem.
6. Cedar documentation: formal Lean model plus differential testing of the production validator.

## 13. Freeze rule

This v0.1 meta-theory is frozen before Unit 003 authoring begins.

Future changes require a new version or numbered amendment. No future Unit003–008 result may silently change the definitions above. Any amendment must state:

- timing relative to observed unit verdicts;
- exact affected definitions;
- whether it changes a result-producing rule;
- whether historical outputs are affected;
- why the change could not be represented as a non-normative implementation improvement.

The machine-readable freeze and schemas are normative companions to this document.
