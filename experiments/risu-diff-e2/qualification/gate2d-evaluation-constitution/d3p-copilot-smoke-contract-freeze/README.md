# Gate2D D3′ — prospective Copilot nonheldout smoke freeze

D3′ is an execution-identity/response-shape closure, not a performance experiment.

It reuses the exact D1′ Copilot configuration, prompt, response schema, blinded-input contract, runner, CLI package/version, and two prospectively frozen lane identities. The synthetic smoke text is exactly the nonheldout text already frozen in the historical D3 protocol; it has no gold label, truth bytes, fresh-target bytes, mutation identity, or expected P/R/I answer.

The smoke will invoke each lane exactly once:
- `B3A_GPT56_SOL_COPILOT` → `gpt-5.6-sol`
- `B3B_CLAUDE_OPUS5_COPILOT` → `claude-opus-5`

D3′ success depends only on execution identity and schema-valid normalization. The P/R/I semantic values are ignored for closure and are not compared or selected.

Authentication is restricted to the personal-seat path frozen in D1′: repository secret `RISU_COPILOT_PERSONAL_TOKEN` mapped to `COPILOT_GITHUB_TOKEN`. The organization repository's built-in `GITHUB_TOKEN` is forbidden for semantic requests so that this smoke uses the PAT creator's personal Copilot seat rather than organization metering.

Missing credentials must stop before semantic invocation with request count zero. After any semantic invocation, the first complete D3′ result must be frozen before diagnosis regardless of PASS or FAIL.

Contract SHA-256: `2320c9c9a52d3a46cf21661d581e756df0a9670a2af8b84dc85ed01d4662bdcf`
Contract Git blob: `f3073558dfb33eba46801cff34f4879e8a79054d`

At this freeze:
- Copilot semantic requests: **0**
- Epistemic-10: unopened
- truth: unopened
- fresh target: unopened
- Mutation Algebra: unopened
- Gate2E: unauthorized
