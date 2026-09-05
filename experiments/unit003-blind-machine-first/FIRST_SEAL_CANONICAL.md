# Unit003 — Canonical First E0 Seal

**Status:** `CANONICAL_FIRST_SEAL_ARCHIVED`

Unit003 is the first held-out machine-first execution of the frozen E0 layer against the prospectively bound `kubernetes/kubectl` target revision `04f459470f58642063b0374361bee0011278f6d8`, screened at `kubectl annotate --resource-version`.

## First emission

The first valid E0 output seal was emitted in Actions Run `33979191679` at head `0b15aacd280fe5e669aa0de5bc9a7775b9e709ce`.

- semantic selection: `912bc1241519e95fe2e3a3aa02267c2bf4a5e2e3377dd31a963fc0757e40d74b`
- `MACHINE_INPUT.json`: `7e8a34a4cf384529b34826555a5dc9f4ec0d1e7913c00f8fb77f053829fe379c`
- input packet digest: `6b0d4280fe26dc61fd09663b3fcbb5ee6f5797c8bd0b6f72017faaebe306704c`
- first seal digest: `e9b14a6f948436b837a5abd6054d4468e93c84922d5bc35a3866673c234b2c36`

The frozen E0 execution itself passed. A separate post-seal record helper then failed because it was invoked from the wrong Python import context. The prediction value was not inspected before archival recovery.

## Exact archival replay

Run `33979316666` at head `9b3f65851536c0f1f1f2bf4e0b672f2ce5a09d66` reconstructed the exact first-seal packet and required all three identities before archival acceptance:

1. semantic selection `912bc124...`
2. exact `MACHINE_INPUT.json` `7e8a34a4...`
3. exact first seal `e9b14a6f...`

All three passed. The replay is an **exact deterministic archival replay, not an independent replication**.

The full 45-file archive is Actions artifact `9973268426`, with ZIP SHA-256:

`54408113ae05b88b4acf52f18f18f8e59b911aac84aadf0f895982e9d257f027`

The downloaded archive was independently hashed locally and matched GitHub's reported artifact digest exactly.

## Result

After archival completion, the sealed prediction was inspected:

`E0_PREDICTED_ASSURANCE_INCOMPLETE`

Hard stop:

`UNRESOLVED_MATERIAL_OBLIGATION`

All nine Version-Bound-Effect material obligations remained unresolved, so E0 generated nine target-only refinement probes. This matches the structural ceiling recorded before target semantic contents were consumed: the first E0 prediction was not target-discriminative and E0 had no machine semantic-upgrade ingestion path.

Therefore this result is **not** evidence that `kubectl annotate` is preserved, regressed, safe, or unsafe. It is evidence that the frozen E0 pipeline ran on the held-out packet and failed closed instead of inventing semantic authority.

## Machine-first learning signal

The frozen path-only selector deterministically chose `pkg/cmd/annotate/annotate.go` and `annotate_test.go` as ranks 1 and 2. Under the frozen no-threshold top-24 policy, the remaining 22 positions were lexical fallbacks. B1 name-shape analysis found version-like names including `ResourceVersion`, while B2 flow-only extraction found zero consequence-coordinate candidates and zero comparison candidates.

Without changing E0 retroactively, Unit003 therefore identifies three concrete E1 targets:

- improve evidence-acquisition precision after strong anchor hits;
- add carrier-aware Go consequence-coordinate/comparison extraction;
- make generated refinement probes machine-ingestible rather than requiring human semantic translation.

Any E1 learned from Unit003 must first be tested prospectively on **Unit004**, not scored back onto Unit003.

## Boundary

Strict zero-byte preseal blindness is **not claimed** because the earlier metadata endpoint over-return incident remains disclosed. No human gold or manual semantic inspection of the selected target files was used before the first seal. The result carries no canonical consequence authority and makes no population, prevalence, live-deployment, or universal-correctness claim.
