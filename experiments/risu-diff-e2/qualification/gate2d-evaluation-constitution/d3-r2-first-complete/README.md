# Gate2D-D3 r2 first-complete failure freeze

This directory freezes the first complete r2 D3 closure qualification before diagnosis.

- original prospective D3 contract: `4a06481243654da6237c23474a4fe0fc64b9e69b`
- prospective digest erratum: `7efa6e5dbb949312b66264fcf6ff60bbef5e42e9`
- isolated r2 execution commit: `67e4bd736ce6770546d6198fc5be8fb32c910a60`
- hosted run: `34249199435`
- job: `102138958371`
- artifact: `10065278255`
- artifact ZIP SHA-256: `c4d16f4663dd749e6e01c844ab46e129d28272564bbd3d368701cb6eafa73a60`
- workflow conclusion: **failure**
- final frozen D3 r2 assertion: **failure**

The r2 preflight and provider-smoke steps both completed, and the artifact was uploaded before the final assertion. Before this freeze, the freezer deliberately did not parse provider lane states or semantic provider responses. It only verified the artifact ZIP digest and content-addressed the seven artifact files.

The exact first-attempt provider-smoke runner blob `b60ab434aeffd6a411039f7ff9e4d32e190ffd87` was reused unchanged in r2. The original D3 first-complete failure, its diagnosis, and the digest erratum remain immutable history.

This r2 result is therefore an undiagnosed first-complete failure. Gate2E remains unauthorized. Epistemic-10, truth, fresh-target bytes, and Mutation Algebra remain unopened.

The only next authorized action is post-freeze diagnosis of the r2 D3 failure.
