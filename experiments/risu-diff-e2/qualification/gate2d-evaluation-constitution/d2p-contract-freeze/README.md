# Gate2D D2′ — prospective exact-30 requalification freeze

D2′ is frozen before any D2′ case execution. It is not a new challenge and it is not permitted to tune the original matrix.

The exact historical D2 generator must first reproduce the original raw 30-case matrix whose manifest SHA-256 is `fe433e55b33da2ff84b74f4c9dd822403984184c3537b6d63a14073ca3154b28`. Only then may two top-level baseline dictionary keys be mechanically renamed:

- `B3A_GPT56_SOL_FRONTIER` → `B3A_GPT56_SOL_COPILOT`
- `B3B_CLAUDE_OPUS45_DATED` → `B3B_CLAUDE_OPUS5_COPILOT`

For every evaluation-input case, inverse renaming must recover the raw generated canonical bytes exactly. T23/T24/T25 policy inputs remain byte-identical. No unit, truth, support, system, integrity, ablation, baseline-output, claim, ordering, population, predicate, or expected-value mutation is authorized.

Execution uses the exact D1′ evaluator/checker wrappers, the already-qualified T22 ablation-driver repair, and the exact historical independent oracle. The new execution harness is permitted to differ from the historical harness by exactly three path substitutions: evaluator v2, checker v2, and T22 ablation shadow v2.

PASS requires all 30 preregistered predicates, all applicable evaluator/checker dual-replays, independent-checker PASS, T22 isolation, zero orchestration failures, exact raw-matrix identity, and exact mechanical-substitution proof.

No Copilot semantic command or provider request is authorized in D2′. Epistemic-10, truth, fresh-target bytes, Mutation Algebra, and Gate2E remain sealed.

Contract SHA-256: `25bd376b0ab6bc127c9e46cdd2b7bb9782e965e95772188118ebce712de279e6`
