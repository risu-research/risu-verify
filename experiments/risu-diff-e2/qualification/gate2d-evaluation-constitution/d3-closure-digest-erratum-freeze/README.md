# Gate2D-D3 prospective metadata erratum freeze

The first D3 closure attempt failed before any provider request because the original prospective freeze receipt recorded the wrong raw-byte SHA-256 for the already-frozen D3 contract.

The original contract bytes and Git blob remain unchanged. The exact frozen blob is `e528f6022de092f492d01b1057db3b956398848d`; its independently reproduced raw-byte SHA-256 is `dd51563e3194241e3bbeb60948b4aed1dc26e969c46cbc437cd19a69320b6ae3` over 6,394 bytes.

This erratum changes **metadata only**. It does not change the D3 smoke fixture, provider/model identities, prompt, response schema, retry policy, success rule, D1 identities, D2 evidence, or semantic production code. The original incorrect receipt and the first-complete D3 failure remain immutable history.

Because the first failure emitted zero provider requests, a fresh isolated r2 qualification is authorized using the same D3 scientific procedure with only the preflight digest authority corrected and the workflow branch selector moved to the fresh r2 branch.

Gate2E remains unauthorized and all heldout/truth firewalls remain closed at this freeze.
