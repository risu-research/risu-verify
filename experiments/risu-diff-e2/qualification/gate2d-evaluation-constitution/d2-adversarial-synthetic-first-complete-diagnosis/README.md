# Gate2D-D2 T22 post-hoc diagnosis

This directory records diagnosis only. It does not repair, reinterpret, rerun, or promote the frozen first-complete Gate2D-D2 result at commit `13a20a8c68c2eafadfc00d7a2e873543a6845ecb`.

## Diagnosis

The T22 failure is **not** a transient GitHub-hosted-runner anomaly, and there is no evidence here of a defect in the primary Gate2D evaluator or production C1 semantics.

The narrow root classification is:

**Frozen D1 ablation-driver executable/runtime-contract defect exposed by the D2 direct-script launch path.**

The causal chain is exact:

1. D1 froze `tools/e2_gate2d_ablation_shadow.py` as the common A1/A2/A3 shadow driver.
2. The A1 transformation is primary-only and does not semantically require C1 recomputation.
3. `EVALUATOR_RUNTIME_CONFIG_v0.1.json` correspondingly states that the frozen C1 snapshot is imported by the A2/A3 shadow driver path only.
4. The frozen driver nevertheless imports `risu_e2_c1.semantics._independent_semantic_eval` unconditionally at module load, before ablation dispatch.
5. D1 hosted identity qualification performed byte/identity checks and `py_compile`, but did not execute the ablation driver and did not audit the ablation driver's import/runtime contract. `py_compile` does not execute imports.
6. D2 T22 invokes the frozen driver as `python tools/e2_gate2d_ablation_shadow.py ...`. The D2 workflow neither installs the repository package nor adds the repository root to `PYTHONPATH`. Under direct script execution, the script directory is the import root, so the repository-root package `risu_e2_c1` is unavailable.
7. The hosted `ModuleNotFoundError` is therefore the deterministic manifestation of a latent frozen-driver/runtime mismatch, not random infrastructure noise.

A secondary runtime-conformance gap is also present: the frozen runtime config specifies `LC_ALL=C.UTF-8`, `PYTHONHASHSEED=0`, and `TZ=UTC`, while the D2 workflow's "Exact runtime" gate enforces CPython 3.13.5 but does not enforce those three variables.

## Scientific interpretation

- The D1 **identity freeze remains historically valid for the claim it actually made**: it fixed bytes/IDs before heldout exposure. D1 did not claim successful ablation execution.
- The frozen **A1 executable identity is defective as an executable/runtime contract**. This is narrower than saying the primary evaluator or C1 semantic machinery is defective.
- D2 behaved correctly by refusing promotion: T22 was specifically the isolation/execution challenge that exposed the latent defect.
- The first-complete D2 result remains **29/30 FAIL** and immutable.
- Gate2E remains unauthorized.
- D3 closure remains unauthorized.
- This diagnosis does not authorize a repaired rerun or any D1 identity change. Any repair must be separately prospective and must preserve the frozen first-complete failure unchanged.

## Frozen evidence anchors

- D2 first-complete run: `34242375490`
- D2 job: `102115547247`
- D2 source execution commit: `805643a0bb77a34d36e72e809f1675fa024bb0d7`
- D2 freeze commit: `13a20a8c68c2eafadfc00d7a2e873543a6845ecb`
- D1 execution commit: `d5268edf88f8a4f72a4bab5b1a28ed4aa3790a2a`
- D1 freeze commit: `63e9da4a846e48883935abf35abe60a11cb35610`
- Frozen ablation driver blob: `6dcfb202c1b1cdc8796266a7c8f51300504de745`
- Frozen runtime config blob: `db0ebde895a547ffd4ca069dcc3161fdcab3c3f4`
- Frozen D1 identity checker blob: `6f693fcfa50bfd548f838b47b2510004930677e4`
- D2 execution harness blob: `e9bc78b6c257eac7ff4269e492e0f32077d2d999`
- D2 workflow blob: `bb92571dac93daf0b5da7bf6824ca60b4bd9e9a6`
