# Gate2D-D3 prospective credential provisioning gate

D3 r2 reached the exact frozen provider request boundary with every scientific and runtime preflight obligation passing. Both B3 request identities were built exactly, but neither provider request was emitted because the required GitHub Actions repository secrets were absent.

This freeze deliberately makes **no code or scientific repair**. It freezes only the credential handoff required to exercise the already-frozen providers:

- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`

The secret values may exist only as GitHub Actions repository secrets. They may not be committed, logged, stored in artifacts, pasted into workflow-dispatch inputs, or substituted with another authentication/provider path.

After both secrets are provisioned, the only allowed execution is a fresh isolated D3 r3 using the unchanged provider-smoke blob `b60ab434aeffd6a411039f7ff9e4d32e190ffd87`, unchanged D3 fixture/prompt/schema/models/endpoints, unchanged success rule, exact runtime, upload-before-assertion, and immutable first-complete freeze.

At this freeze there have still been **zero provider requests** across D3 attempts. Gate2E remains unauthorized and all heldout/truth firewalls remain closed.
