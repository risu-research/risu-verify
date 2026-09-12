# RISU Kernel K1 — Narrow-Waist Checkpoint A0

**Status:** CANDIDATE CHECKPOINT / NOT A K1 FREEZE  
**Branch:** `k1-adversarial-gate-a0`  
**Prospective base:** `e2-development@e5bb5285acbfce6c9b22fea94f8bb58c746aed0b`

This checkpoint records the smallest K1 design that survived the first prospective adversarial sequence. It does not reinterpret frozen v0.7 results and does not declare K1 complete.

## 1. Qualification chain

### A0 — adversarial semantic gate

The candidate `ALLOW / REALIZE` calculus was tested against one control, nine mutation-killer models, ten deliberately wrong nearby kernels, and four boundary metamorphics.

The declared mutant class was killed 10/10. The nine mutation-killer cases are deletion-minimal against that explicit mutant class: removing any one leaves at least one declared mutant alive.

A0 forced or confirmed the following constraints:

- factorization/partition preservation is derived, not fundamental;
- the consequence universe is open to target-native outcomes;
- `PRESERVED` needs checkable closure, grounding, per-world consequence-cut totality, and subset refinement;
- producer assertions such as `closed=true` or `grounded=true` are not authority;
- one grounded forbidden realization is sufficient for local regression even when unrelated scope is incomplete;
- an empty admitted world set or a world with no allowed source consequence is malformed;
- a strict safe subset is preserved under the pure safety profile unless a stronger progress/availability obligation is explicitly declared.

### W0 — wire gate

The wire prototype separates claim identity from proof authority.

- JSON is transport, not semantic canonicalization authority.
- Claim identity binds the exact semantics tag, admitted worlds, and `ALLOW` relation using typed digest tokens plus a domain-separated length-prefixed transcript.
- Ordering is normalized before hashing; duplicates are invalid rather than silently deduplicated.
- `REALIZE` may contain a target-native consequence not named in `ALLOW`.
- Closure and grounding are proof references, not Boolean claims.
- Unknown proof kinds remain structurally transportable but semantically unsupported.

### W1 — tiny independent checker

The first checker recognizes exactly one deliberately small proof fragment: `k1.finite-model/v1`.

For that fragment, it independently checks the finite target model, target commitment, closure of submitted `REALIZE`, grounding of every realized pair, per-world totality, and the `REALIZE ⊆ ALLOW` preservation condition. It accepts a grounded forbidden pair as a regression witness.

W1 has no network, source parser, MCP/OpenAPI parser, SMT solver, LLM, repository selection, repair synthesis, or producer dependency.

Its assurance claim is intentionally narrow:

- `assurance_scope = DECLARED_FINITE_TARGET_MODEL`
- `implementation_binding = false`

This is a feature, not an omission disguised as proof. Binding a proof model to real implementation behavior is a separate future proof kind/evidence problem.

### v0.7 compatibility A0

The migration adapter consumes only the pinned four-row VBE calibration differential and asks whether K1 reproduces the already-frozen product conclusions.

The adapter computes K1 first and compares with legacy status afterward. C/D/O, Exact, coordinates, and match annotations are not used by the K1 semantic judgment.

The four frozen conclusions are reproduced:

1. GitHub guarded merge → `CONSEQUENCE_REGRESSION`
2. Azure Wiki ETag → `PRESERVED`
3. GitHub blob-SHA BEFORE → `CONSEQUENCE_REGRESSION`
4. GitHub blob-SHA AFTER → `PRESERVED`

The historical BEFORE/AFTER pair has the same frozen source semantic identity and now compiles to the **same K1 claim ID**, while target identity changes and the result moves from regression to preservation.

The first compatibility CI attempt failed precisely because the initial adapter incorrectly namespaced world identity by case-instance ID, making BEFORE and AFTER different claims. The failure was not waived; migration identity was repaired to use the frozen source semantic namespace. The corrected compatibility test passes.

## 2. Candidate K1 semantic center

Let `W` be a nonempty admitted world set.

Let `U` be an open universe of canonical consequence commitments. K1 does not require a closed source consequence enum.

Let

`ALLOW ⊆ W × U`

be the declared source-admissible consequence relation, with at least one allowed consequence for every admitted world.

Let

`REALIZE ⊆ W × U`

be a target consequence relation established by an accepted proof object.

### Regression

A regression proof is locally sufficient when it establishes a grounded pair

`(w, u) ∈ REALIZE \ ALLOW`.

No global preservation proof is required to preserve an already valid forbidden witness.

### Preservation

A preservation proof over a declared scope must independently establish:

1. `REALIZE` is exhaustive/closed for the exact target claim represented by the proof;
2. every realized pair is grounded by an accepted proof/evidence rule;
3. the consequential cut is total for every admitted world;
4. `REALIZE ⊆ ALLOW`.

Failure to establish these obligations is not evidence of regression and is not preservation. The product layer may report `UNKNOWN` / `ASSURANCE_INCOMPLETE`.

## 3. What is deliberately not a K1 primitive

The following are valuable but currently remain outside the candidate semantic kernel:

- C / D / O;
- Exact Realization;
- factorization and kernel-inclusion tests;
- CIR nodes and edges;
- Version-Bound Effect profile logic;
- source-language ASTs;
- MCP / OpenAPI / SDK semantics;
- repository or network acquisition;
- source semantic digests as a universal K1 object;
- temporal logic as a built-in primitive;
- model-adequacy judgments;
- proof search;
- SMT solving;
- LLM reasoning;
- repair synthesis.

Some of these may establish, generate, explain, or bind K1 proof objects. None has yet shown that the fundamental consequence judgment itself cannot be expressed without becoming a kernel primitive.

## 4. Constitutional invariants surviving A0

1. **Open-universe invariant.** A target-native consequence may enter `REALIZE` even if the source contract never named it.
2. **No-vacuity invariant.** Empty worlds, empty per-world source permission, missing consequence-cut outcome, or incomplete target closure may not create preservation by set-theoretic vacuity.
3. **Grounding invariant.** A semantic claim cannot be promoted solely by an ungrounded producer statement.
4. **Asymmetry invariant.** One valid forbidden witness can prove regression; samples with no witness cannot prove preservation.
5. **Identity invariant.** Changing the declared world/allow relation changes the claim. Changing a target realization changes the target/proof identity, not the claim it is being compared against.
6. **Diagnostic non-authority invariant.** Adding or removing C/D/O/Exact diagnostics cannot strengthen the K1 semantic claim.
7. **Tiny-TCB invariant.** More sophisticated producers may find better evidence, but producer sophistication does not change the meaning of an accepted K1 proof.
8. **Model-boundary invariant.** Preservation in a declared model is not a claim that the model contains every real-world consequence that matters.

## 5. What this checkpoint means

The strongest conclusion justified now is not “K1 is finished.” It is:

> The `ALLOW / REALIZE` safety-refinement narrow waist has survived a mutation-tested semantic gate, a strict wire/identity gate, an independent finite-model checker gate, and a four-case legacy-equivalence gate without requiring C/D/O, Exact, factorization, or profile logic as semantic kernel primitives.

That is enough to justify **holding the kernel small** while moving the burden of proof onto any proposed new primitive.

## 6. Next falsification — A1, not another VBE rerun

The next high-leverage test must be semantically heterogeneous. Re-running more Version-Bound Effect variants would mostly retest an already represented structure.

A1 should ask whether the same K1 relation can faithfully encode consequence obligations from several families that are structurally different from the commissioning set, for example:

- authorization/revocation binding;
- recipient/amount binding for monetary movement;
- duplicate-effect/idempotence safety;
- external-communication recipient binding;
- a bounded progress/deadline consequence that directly attacks the current safety-only boundary.

A1 is not a benchmark race. Its acceptance question is constitutional:

> Does any carefully constructed non-VBE counterexample require a new kernel primitive, or can the obligation be compiled into admitted worlds, open consequence commitments, and accepted proof obligations without semantic loss?

A1 must be allowed to kill or enlarge K1. If no such counterexample survives, only then should a K1 release-candidate freeze and a second independent checker implementation be considered.
