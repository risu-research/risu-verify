# Mediated Refinement Research Checkpoint — October 2026

This document records post-release research performed after the archived **RISU Verify v0.4.0-rc1** software release.

The archived release and its DOI artifact remain unchanged. The work below is a separate research frontier that tests one narrow question:

> Can a richer but still finite source model be refined into RISU's already-qualified bounded execution model without silently dropping, duplicating, reordering, relabeling, or otherwise changing consequence-relevant behavior?

The current answer is limited but materially stronger than the September checkpoint: a bounded **mediated finite-state transducer (MFST) → qualified C2** refinement candidate has survived adversarial, generative, orthogonal-reference, certificate, and qualification gates.

**No production refinement authority has been created.**

## Evidence progression

| Layer | Purpose | Result | Public anchor |
| --- | --- | --- | --- |
| F0 | Pre-implementation adversarial semantics and crossed replay | 62/62 frozen oracles passed | c0ad24a9f8078078865c67bcb509c11901b8d0ab |
| G1 | Large-scale generated, metamorphic, differential, and fail-closed testing | 4,288 counted scenarios + 1,024 full-square controls passed | 22cc0df36661dbd7fac50d9b551d1e78505fc253 |
| R0 | Orthogonal bounded reference semantics | 18,432 descriptors × 4 boundary points = 73,728 executions; zero reference/cross/downstream disagreements; 4/4 common-mode compiler vetoes | c0894d0a31974b42fdeb85fcd935240731d18391 |
| C0 | Independently checked refinement-certificate object | 46/46 adversarial certificate vectors passed | d66cccb586893320235ba3bbb57429639debed0c |
| Q0 | Qualification of the independent certificate-checker pair | F0 62; G1 176 + 104 support; R0 48 + 4 vetoes; 1,024 negative + 256 positive certificate mutations | a857fe1f72b7341d549354e9ccc330dca22e9c0d |

## What the crossed path checks

The candidate does not rely on one producer declaring that refinement succeeded.

For closure-eligible positive cases:

1. W7 and W8 independently interpret the same MFST source.
2. Each reconstructs reachable state, ordered consequential effects, projected K1 realization, and the exact canonical C2 normal form.
3. W8 replays the C2 emitted by W7 and W7 replays the C2 emitted by W8.
4. Both producer paths are then checked again by the previously qualified W5 and W6 downstream checkers.
5. A positive case survives only when the direct semantics, crossed replay, exact canonical lowering, and downstream reconstruction converge on the same consequential behavior.

The path therefore tests more than final-set equality. Ordered effect deletion, duplication, and reordering can be rejected even when the final projected K1 set is unchanged.

## F0 — frozen adversarial gate

The F0 corpus was frozen before W7/W8 implementation.

It contains 62 oracles: 14 ACCEPT, 15 PARSE_REJECT, 12 SEMANTIC_REJECT, and 21 CROSSCHECK_REJECT.

The gate also enforces the intended failure plane. A semantic or crossed-refinement attack does not count as successfully detected merely because malformed input happened to fail earlier in parsing.

Hosted crossed run: https://github.com/risu-research/risu-verify/actions/runs/36823783571

## G1 — generated differential campaign

G1 froze its seeds, scenario counts, metamorphic relations, negative mutation families, and coverage floors before execution.

Results:

- 4,288 counted generated scenarios: 4,288/4,288 passed
- 1,536 structured valid profiles
- 2,048 metamorphic transformations
- 512 adversarial/fail-closed mutations
- 192 high-complexity stress profiles
- 1,024 additional full-square support controls
- 8/8 independent CI shards passed

Each closure-eligible profile had to satisfy the direct, crossed-replay, exact-normal-form, and W5/W6 downstream equalities.

Hosted run: https://github.com/risu-research/risu-verify/actions/runs/37105015579

## R0 — orthogonal bounded reference semantics

Differential agreement alone cannot exclude a shared semantic mistake. R0 therefore introduced a smaller source sublanguage with an independently specified reference semantics.

The frozen reference space contains 18,432 distinct source descriptors, four boundary points per descriptor, and 73,728 expected executions.

The reference lane computes each expected trace using two separate evaluators: a Boolean-equation evaluator and an explicit truth-table evaluator. These agreed on all 73,728 executions before the source-to-MFST cross lane was attached.

The later W9 → W7/W8 → crossed replay → W5/W6 campaign produced zero W9 mismatches, zero W7/W8 disagreements, zero crossed-replay disagreements, zero W5/W6 downstream disagreements, and vetoed 4/4 deliberately wrong common-mode compiler mutations.

Hosted run: https://github.com/risu-research/risu-verify/actions/runs/37162620992

## C0 — independently checked refinement certificates

C0 adds a transportable certificate object but does not treat the submitted certificate as authority.

Independent Python and Go checkers rerun the source semantics, reconstruct the exact C2 lowering, verify exact program and artifact identity, generate a fresh downstream C2 certificate, rerun qualified W5/W6 checks, and only then compare the submitted refinement certificate.

The C0 adversarial battery contained 38 negative and 8 positive vectors. All 46 produced the intended result.

Hosted adversarial run: https://github.com/risu-research/risu-verify/actions/runs/37164819695

## Q0 — qualification campaign

Q0 froze an exact W10/W11 candidate pair and replayed the earlier evidence through the certificate layer.

The first candidate did **not** qualify unchanged. A representation-preserving positive mutation exposed a W10 comparison defect: the checker compared a projected relation as a raw ordered list instead of the mathematical set required by the frozen transcript. The positive oracle was retained, W10 was minimally corrected, and the new implementation pair was frozen and fully requalified.

Final anchor-head qualification:

- F0: 62
- G1 selected scenarios: 176
- G1 support controls: 104
- R0 independent-reference descriptors: 48
- R0 common-mode vetoes: 4
- certificate negative mutations: 1,024
- representation-preserving positive mutations: 256
- final status: AUTHORITY_CREATED false

Final full qualification run: https://github.com/risu-research/risu-verify/actions/runs/37316423805

Qualification anchor: https://github.com/risu-research/risu-verify/commit/a857fe1f72b7341d549354e9ccc330dca22e9c0d

## Strongest supported claim

Within the frozen bounded MFST profile and the tested qualification boundary, the candidate refinement path has not produced a disagreement across independent source semantics, bidirectional crossed replay, exact canonical C2 lowering, qualified W5/W6 downstream reconstruction, the orthogonal W9 reference lane, independently checked refinement certificates, and the precommitted certificate mutation campaign.

This is executable evidence for a **narrow bounded refinement candidate**.

## Nonclaims

This checkpoint does **not** establish refinement correctness for arbitrary native programs, arbitrary containers or cloud systems, concurrency, threads, asynchronous effects, filesystem or network behavior, unrestricted liveness, arbitrary agent stacks, general agent safety, absence of all possible common-mode bugs, or a production k1.mediated-refinement/v1 proof kind.

The current qualification state intentionally remains **AUTHORITY_CREATED false**.

Production-authority composition, downgrade/versioning resistance, replay across claims, and related promotion concerns remain a separate research step.

## Relationship to v0.4.0-rc1

Nothing in this checkpoint rewrites the archived v0.4.0-rc1 release, the frozen Projection Assurance evaluation, or the previously qualified C2/K1 base.

The checkpoint records additive post-release research only.
