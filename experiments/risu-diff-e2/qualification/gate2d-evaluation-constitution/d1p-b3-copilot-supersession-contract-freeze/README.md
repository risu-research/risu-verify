# Gate2D D1′ — prospective B3 Copilot supersession freeze

This freeze preserves the historical D1/D2/D3 lineage and prospectively replaces only the B3 frontier-LLM execution identities before any Epistemic-10, truth, fresh-target, Mutation Algebra, or B3 semantic output is observed.

## Why this is scientifically admissible

The prior D3 r2 stopped before provider emission because direct OpenAI/Anthropic credentials were unavailable. Provider semantic request count therefore remained zero. This supersession is not selected from heldout performance or any B3 answer.

The GPT lane retains GPT-5.6 Sol and changes only transport/authentication. The Anthropic lane moves from the now-retired Claude Opus 4.5 identity to Claude Opus 5, the current GitHub Copilot replacement, before heldout exposure.

## Frozen replacement

- B3A: `B3A_GPT56_SOL_COPILOT` → `gpt-5.6-sol` through GitHub Copilot CLI
- B3B: `B3B_CLAUDE_OPUS5_COPILOT` → `claude-opus-5` through GitHub Copilot CLI
- Copilot CLI package: `@github/copilot@1.0.83`
- authentication: `COPILOT_GITHUB_TOKEN` sourced only from repository secret `RISU_COPILOT_PERSONAL_TOKEN`
- credential class: fine-grained GitHub PAT with `Copilot Requests` permission
- billing authority: the PAT creator's active Copilot seat entitlements
- programmatic single-response execution; no self-consistency; no semantic retries
- per-response Copilot AI-credit soft cap: 30
- no repository/shell/web tool use by the classifier
- original B3 prompt, response schema, blinded-input boundary, normalization outcomes, and 1 MiB input cap remain unchanged

## Required requalification

This is not a silent edit to D1. A new D1′ identity must be frozen on an isolated branch. The only permitted evaluator/checker change is replacement of the two expected B3 IDs. B0/B1/B2/B4, all metrics, denominators, result-priority rules, ablations, production semantics, C1 semantics, and heldout selection remain unchanged.

After D1′ identity closure, the exact preregistered 30-case D2 evaluator challenge must be rerun with the new B3 IDs substituted mechanically. Only a 30/30 D2′ pass may proceed to a nonheldout D3′ Copilot dual-lane smoke. Only an immutable D3′ pass may authorize a separately frozen Gate2E execution protocol.

## Firewall at freeze

- `epistemic10_read = false`
- `truth_read = false`
- `fresh_target_read = false`
- `mutation_algebra_opened = false`
- `copilot_semantic_request_count = 0`
- `gate2e_authorized = false`

Contract SHA-256: `770743362c6453b38ad621d2b576e01919c7df3a9dc71bac6e1ce31fde322e42`
