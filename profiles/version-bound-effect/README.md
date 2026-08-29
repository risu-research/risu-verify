# Version-Bound Effect Profile — development

The Version-Bound Effect (VBE) profile is an **untrusted authoring and compilation profile** over the frozen Consequence-Preserving Projections v0.7.0 assurance path.

Its narrow question is: **does the consequential effect remain bound to the version that was reviewed or otherwise declared authoritative for that effect?**

The profile does not add a new verdict system. It compiles an accepted VBE instance into a Source Consequence Contract and a consequence-blind target semantic program, then the existing frozen producer and independent consumer determine the result.

## Carrier-neutral semantic tuple

`(reviewed_version, current_version_at_effect, effect, mismatch_consequence, binding_mechanism)`

The initial development profile supports three projection forms because all three are already represented by independently developed external systems in the calibration set:

* `PRESERVED_COMPARE` — the reviewed version and effect-time current version are compared in the same semantic version space and the distinction gates the effect.
* `OMITTED_REVIEWED_GUARD` — current-version information may remain visible, but the reviewed version does not gate the effect.
* `WRONG_VALIDATOR_REJECT_PATH` — a supplied reviewed-version token is routed into a materially different validator/semantic space.

These are not verdicts. They are authoring patterns whose compiled artifacts must still be checked by the frozen assurance core.

## Evidence is deliberately outside the profile

Carrier-specific source bytes, API contracts, provenance graphs, qualification facts, and fact identifiers live in a separate **carrier evidence envelope**. This prevents the reusable semantic profile from becoming a vendor-specific evidence bundle.

## Calibration rule

A calibration instance passes only if the VBE-compiled artifact and the retained legacy artifact agree on:

* source semantic digest;
* admitted worlds and required/projected consequence rows;
* C/D/O;
* structural classification and coverage;
* Exact Realization status and failure mode;
* product status.

Adapter/proof digests are not required to match because compilation reserializes the Source Consequence Contract and therefore legitimately changes file-level identities while preserving semantic content.

## Nonclaims

This development profile is not a standard, not an ABI, not a generic semantic parser, and not an evidence oracle. It has not yet been prospectively validated on a preselected corpus or independently authored by an external user.
