# Gate2D D2′ first hosted attempt — post-freeze diagnosis

The immutable pre-science failure at run `34258109081` was diagnosed only after its failure freeze `db8fefb28a18373944683629a5719b6c054f5315`.

## Exact diagnosis

The D2′ v0.1 prospective freeze receipt and the preflight pinned an intended contract Git blob `a8023a97ed255864396723f31f77b7430e723447`, but the contract bytes actually committed at `5684cbdf163afbbf39922dccda32a3e0721bd8da` have Git blob `84b2e48877f652db22d5215aa7ebae42b6b13832`.

The drift is confined to a metadata/failure-policy JSON key introduced while manually serializing the already-designed contract into the Git tree. The committed v0.1 uses `any repair requires a new prospective erratum or remediation contract`; the intended canonical contract used `repair_requires_new_prospective_erratum_or_remediation_contract`. The scientific challenge, 30-case identity, B3 substitution mapping, evaluator/checker identities, T22 repair identity, pass criteria, runtime, and firewalls were not selected or changed based on scientific output.

The preflight therefore correctly failed closed on `CONTRACT_IDENTITY` before raw-matrix generation. Scientific case consumption remained zero and provider/Copilot semantic request count remained zero.

## Classification

`D2P_V01_CONTRACT_RECEIPT_CONTENT_ADDRESS_MISMATCH_FROM_MANUAL_METADATA_KEY_SERIALIZATION_DRIFT`

This diagnosis does not authorize editing or replacing v0.1 in place. The only admissible repair is a separately content-addressed prospective v0.2 erratum contract, followed by a fresh isolated r2 qualification that reuses all scientific implementation bytes unchanged and changes only contract anchoring/diagnostic plumbing required by the erratum.
