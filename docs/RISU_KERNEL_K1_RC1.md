# RISU Kernel K1 RC1

**Status:** RELEASE CANDIDATE / SCOPED / NOT FINAL  
**Normative constitution:** `protocols/RISU_KERNEL_K1_RC1_CONSTITUTION.json`  
**Exact freeze manifest:** `protocols/RISU_KERNEL_K1_RC1_FREEZE.json`  
**Composite qualifier:** `tools/risu_kernel_k1_rc1_verify.py`

## 1. What RC1 freezes

K1 RC1 freezes the smallest semantic narrow waist that survived A0 and the strengthened cross-domain A1 falsification program:

- a nonempty admitted world set `W`;
- an open consequence universe `U`;
- a source-first, precommitted admissibility relation `ALLOW ⊆ W × U` with at least one allowed consequence per admitted world;
- a target-realizability relation `REALIZE ⊆ W × U` established by an accepted proof object.

The semantic rules are intentionally asymmetric.

**Regression** is established by one accepted, grounded pair in `REALIZE − ALLOW`.

**Preservation** requires accepted closure/exhaustiveness for the exact target scope, grounding of every realized pair, per-world consequential-cut totality, and `REALIZE ⊆ ALLOW`.

Anything short of those obligations is `UNKNOWN` / assurance incomplete. Failure to prove preservation is not regression; failure to find a regression is not preservation.

## 2. Why A1 justified an RC instead of another kernel expansion

A1 deliberately moved away from the original Version-Bound Effect commissioning family. It used five heterogeneous pressure classes:

1. authorization and revocation binding;
2. monetary recipient and amount binding;
3. history-sensitive idempotence and duplicate-effect safety;
4. external communication audience binding;
5. bounded progress/deadline behavior at an explicit consequential cut.

Every family used a prospective source lowering. GOOD and BAD targets were required to share the same source-lowering commitment and the same K1 claim. Target observations were forbidden from retrospectively changing worlds or enlarging `ALLOW`.

The strengthened A1 also used nonredundant counterexamples. In the authorization and idempotence cases, the BAD target was intentionally constructed so that a buggy lowerer that ignored the material world distinction could falsely preserve it. Recipient, amount, audience, history, revocation state, and bounded terminal status were each attacked with identity-blind mutants.

The strengthened gate result was:

- five of five GOOD/BAD families shared claim identity;
- five of five GOOD targets produced preservation;
- five of five primary BAD targets produced regression;
- all ten declared nearby/lossy mutations were killed;
- zero declared A1 semantic kernel counterexamples survived;
- no new semantic kernel primitive was justified.

This is evidence for a scoped RC, not evidence that K1 is universally complete.

## 3. The important negative result: A1 found proof gaps, not kernel gaps

A1 did not merely return green. It exposed two limitations in the proof ecosystem.

### Unbounded trace liveness

`k1.finite-model/v1` does not establish an unbounded eventuality claim. Replacing “eventually” with an arbitrary finite deadline would change the source obligation, so A1 refuses to launder that surrogate into preservation.

Current classification: **proof-kind gap**.

### Local regression witness over a partial model

The abstract K1 rule says one independently grounded forbidden realization is enough for regression. W1 currently grounds witnesses through `k1.finite-model/v1`, whose artifact checker requires per-world totality. Therefore an unrelated unproved world can prevent W1 from accepting an otherwise semantically sufficient local witness.

Current classification: **proof-kind overconstraint**, not a reason to enlarge the semantic kernel. A future local-witness proof kind is the natural repair.

A third known boundary remains from W1: `implementation_binding = false`. Binding a declared target model to real implementation behavior remains an evidence/proof-kind problem unless a future counterexample proves otherwise.

## 4. What is outside the RC1 semantic kernel

C/D/O, Exact Realization, factorization/kernel-inclusion tests, CIR, VBE profile logic, source-language ASTs, MCP/OpenAPI/SDK semantics, temporal logic, SMT, LLM reasoning, proof search, repository/network acquisition, and repair synthesis are not RC1 semantic primitives.

They may compile claims, generate or establish proof objects, explain failures, bind models to implementations, or synthesize repairs. Their usefulness does not make them part of the narrow waist.

## 5. Change-control rule

A future K1 primitive is not admitted because a domain looks different, a solver would be convenient, a proof kind is missing, or a frontend cannot yet lower a contract.

Kernel growth requires a minimal semantic counterexample showing that a material obligation still collapses under every admissible target-independent lowering into `W`, open consequence commitments, `ALLOW/REALIZE`, and accepted proof obligations.

Until such a counterexample exists, the burden of proof is against enlarging K1.

## 6. Qualification and freeze discipline

RC1 is not qualified by this prose document. The exact dependency set is pinned by Git blob identity in `RISU_KERNEL_K1_RC1_FREEZE.json`.

The composite qualifier first verifies those exact blobs and then reruns, in sequence:

`A0 → W0 → W1 → v0.7 compatibility → strengthened A1`.

The RC branch is to be created only from a commit for which the composite GitHub Actions qualification succeeds. The resulting branch therefore records a reproducible semantic checkpoint rather than a moving “latest” implementation.

## 7. RC1 claim, stated narrowly

> Within the declared consequence-cut safety scope tested by A0, legacy compatibility, and strengthened cross-domain A1—including bounded deadline violations—the `W + open consequence universe + ALLOW/REALIZE + accepted proof obligations` narrow waist survived the declared adversarial class without requiring an additional semantic kernel primitive.

That statement is the ceiling of RC1. Unbounded liveness, local-witness proof ergonomics, and implementation binding remain explicit open proof/evidence problems rather than hidden assumptions.
