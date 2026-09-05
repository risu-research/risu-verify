# RISU Diff Engine E0 — Foundation Qualification

Status: **development-only / untrusted machine-first front-end**.

This foundation is intentionally asymmetric: concrete, independently recheckable counterexamples may support an E0 regression prediction, while an E0 stability prediction requires every declared VBE material obligation, a complete refinement mapping, and a nonempty material interpretation. Any unresolved material fact yields `E0_PREDICTED_ASSURANCE_INCOMPLETE` rather than stability.

## Components

- deterministic Consequence Graph/CIR canonicalization and SHA-256 digest;
- fail-closed evidence discipline for `ESTABLISHED` material nodes and edges;
- declarative VBE obligation evaluator;
- deterministic-collapse and relational-extra-consequence witness search;
- validity-first witness shrinking;
- independent stdlib-only witness checker that imports no E0 producer code;
- conservative static coordinate-flow candidate extraction;
- target-only CEGAR refinement-request planning;
- non-authoritative B0/B1/B2 baseline harness;
- development-only calibration adapter for existing frozen/historical VBE data;
- persistent exact-byte/frozen-boundary verifier for post-firewall E0 development.

## Trust boundary

E0 is not the canonical RISU scientific producer and does not issue canonical Corpus verdicts. Its namespace is limited to `E0_PREDICTED_*` results. Static extraction, heuristics, baselines, and probe planning have no consequence authority. A baseline cannot emit an authoritative prediction.

## Qualification

`python tools/risu_e0_qualify.py`

The foundation qualification includes calibration/history checks plus adversarial gates for:

- omitted-guard regression and preserved-compare stability on development data;
- Unit002-M-style discriminator collapse and metadata-only negative control;
- empty-interpretation vacuity hard stop;
- unresolved-material-obligation fail closed;
- evidence-less `ESTABLISHED` material node/edge rejection;
- graph/evidence ordering digest invariance, including deterministic permutation fuzz;
- semantic-change digest sensitivity;
- relational extra-consequence hard-stop regression;
- independent acceptance of valid shrunken collapse and relational witnesses;
- tampered-witness rejection matrices;
- minimal-coordinate-difference witness selection;
- static extractor non-authority even for semantically suggestive identifiers;
- CEGAR prohibition on source-contract/metric rewriting or unsupported evidence upgrades;
- baseline non-authority and authority-escalation rejection.

Unit003 target-specific semantics are outside this foundation's development inputs under the already-merged E0 evaluation firewall.
