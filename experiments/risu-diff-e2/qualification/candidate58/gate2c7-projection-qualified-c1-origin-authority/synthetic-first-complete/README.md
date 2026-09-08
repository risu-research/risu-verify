# Gate2C7 frozen adversarial synthetic qualification

This directory is a result-only immutable freeze of the first complete successful Gate2C7 synthetic qualification.

- Protocol authority: `c9b0e1b805fa7193972894bd6a83f3390cb4be75`
- C1 implementation: `1dd07617de61b1bbd3e39f11a73594d0d98f4433`
- Orchestration-only correction: `a334a40b6c65508386ae6f89b3ab86bcd36e32b5`
- Hosted successful run: `34175363175`
- Artifact: `10037054384` (`sha256:5e8c6f59e12baa3503bd5172c8590633632acc37e51ce5efcb49983ba68210e5`)
- Frozen adversarial cases: 14/14 expected decisions exact.
- Independent checker agreement: PASS.
- Candidate58 C1 executions before this freeze: 0.
- Epistemic-10 read: false.

The earlier hosted run `34174765144` is retained as a non-scientific orchestration failure (`SYNTHETIC_RUNNER_PYTHON_IMPORT_PATH`); it executed zero candidate C1 cases and produced no scientific result.

This freeze authorizes only the preregistered seven Python C1 development cases. It does not authorize heldout evidence, Go/TypeScript support, Mutation Algebra, or any primary-adapter/semantic-kernel change.
