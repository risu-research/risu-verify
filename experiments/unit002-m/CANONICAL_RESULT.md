# Unit 002-M — canonical detector-control result

**Status:** `PROMOTED_CANONICAL_CONTROL_RESULT`

The canonical Unit 002-M execution is GitHub Actions Run `33943444386`, checked out at exact PR head `ba3613aef6531d07d559d20b79f16544a8db6871` after the frozen-plan-preserving `UNIT002_M_IMPLEMENTATION_CORRECTION_001`.

## Result

The full predeclared matrix passed:

- baseline validity: **2/2**;
- semantic-loss sensitivity: **6/6**;
- nonsemantic specificity: **6/6**;
- false semantic alarms: **0**;
- regression witness localization: **4/4**;
- discriminator-collapse detection: **2/2**;
- deterministic repeatability: **12/12** mutants;
- mutation locality: **12/12**;
- source-contract invariance: **12/12**.

Across both preserved seeds, `P_MECHANISM_ALWAYS_ACCEPTS` and `P_INTERPRETER_ALWAYS_SUCCESS` produced `CONSEQUENCE_REGRESSION` with `REALIZATION_CONTRADICTED` and the predeclared stale-world witness. `P_DISCRIMINATOR_COLLAPSE` produced `D0` / `INCOMPLETE_ASSURANCE`. All three nonsemantic controls per seed remained `PRESERVED`.

## Prospective integrity

The matrix and scoring rules were fixed in `PLAN.json` at commit `cecaf792cb131f022a1c7bcdd3ab12c0968a409f`, Git blob `958bf01dbf89d338aa0f59a5d892127d65704222`, before the executor existed or any Unit 002-M output was observed.

Two early runs were implementation-invalid before a complete eligible control result. A third complete run exposed a locality-checker representation bug. That run remains non-promoted. `IMPLEMENTATION_CORRECTION_001.json` records the diagnosis and narrowly permits only a change in how a predeclared parent JSON subtree is represented for mutation-locality checking. The PLAN, mutation bytes, semantic scoring rules, seeds, and promotion thresholds were unchanged.

## Canonical evidence identity

- Actions artifact ID: `9962563353`
- Actions artifact ZIP SHA-256: `46d31d919db3bd3d3da163053f1853b81243f4a974495cad804a72ec5c8da064`
- `MATRIX_RESULT.json`: `79918b47feac59bd440b7184b5cfb1c180b78966297fc44122a87aa6d553330e`
- `MATRIX_RESULT.md`: `1801b9cdfbbaca716a79c7dac2ed999f36858bce5218345b00bb4ca65ba9b618`
- `ARTIFACT_MANIFEST.json`: `d6203d1f6b86e6522885448a7d39db7a448bc5e97cc51a608ac7dff643e726ac`

`CANONICAL_RESULT.json` permanently retains the metrics plus one certificate SHA-256 and proof digest for every baseline and mutant cell. Later CI executions may verify deterministic replay but may not replace Run `33943444386` as canonical.

## Claim boundary

This is a **synthetic detector-control** result. It supports sensitivity/specificity claims only for these two frozen seeds and six predeclared mutation families. It is not a live-runtime result, a real-target safety result, an ecosystem prevalence estimate, or a universal detector-accuracy claim.

The next scientific gate is **Unit 002-R**, whose real target must be selected independently of Unit 002-M outcomes.
