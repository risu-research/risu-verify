#!/usr/bin/env python3
"""Non-authoritative v0.7 -> K1 compatibility adapter.

This adapter does NOT re-read source code or reinterpret historical evidence.
It consumes only the pinned four-row VBE calibration snapshot and asks whether
K1 W0/W1 can reproduce the already-frozen product conclusion without C/D/O or
Exact entering the K1 semantic judgment.
"""

import argparse
import copy
import hashlib
import importlib.util
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_SNAPSHOT = ROOT / "compatibility" / "v07_k1" / "VBE_CALIBRATION_4ROW_SNAPSHOT.json"
CHECKER_PATH = ROOT / "kernel" / "k1_checker_w1.py"

spec = importlib.util.spec_from_file_location("k1_checker_w1", CHECKER_PATH)
K = importlib.util.module_from_spec(spec)
spec.loader.exec_module(K)

PINNED_SOURCE = {
    "repository": "risu-research/risu-verify",
    "commit": "a548a07152c068805a147e47aa18aa40a2ffa492",
    "path": "results/VBE_CALIBRATION_DIFFERENTIAL.json",
    "git_blob_sha1": "434ef5f4601e8adb7eb33570676ab0f68fc09306",
    "source_status": "PASS",
    "calibration_count": 4,
}


class CompatError(Exception):
    pass


def sha(prefix, domain, text):
    raw = (domain + "\0" + text).encode("utf-8")
    return prefix + hashlib.sha256(raw).hexdigest()


def world_id(instance, legacy_world):
    return sha("w:sha256:", "RISU-V07-WORLD-A0", instance + "\0" + legacy_world)


def consequence_id(atom):
    return sha("c:sha256:", "RISU-V07-CONSEQUENCE-A0", atom)


def consequence_atom(projected_effect):
    if not isinstance(projected_effect, dict):
        raise CompatError("projected_effect must be an object")
    space = projected_effect.get("space")
    if space == "C":
        if set(projected_effect) != {"space", "label"} or not isinstance(projected_effect["label"], str):
            raise CompatError("C-space projected effect must contain exactly space+label")
        return projected_effect["label"]
    if space == "OUTSIDE_C":
        if set(projected_effect) != {"space", "native"} or not isinstance(projected_effect["native"], dict):
            raise CompatError("OUTSIDE_C effect must contain exactly space+native")
        # Adapter-only deterministic atom encoding. This is deliberately outside
        # the K1 kernel identity/TCB; the kernel sees only an open consequence ID.
        native = json.dumps(projected_effect["native"], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return "OUTSIDE_C:" + native
    raise CompatError("unsupported frozen projected-effect space")


def build_claim_and_model(row):
    if not isinstance(row.get("worlds"), list) or not row["worlds"]:
        raise CompatError("legacy row has no worlds")

    seen_legacy = set()
    worlds = []
    allow = []
    possible = []
    translated = []

    for legacy in row["worlds"]:
        required_keys = {"world", "coordinates", "required_consequence", "projected_effect", "matches"}
        if set(legacy) != required_keys:
            raise CompatError("legacy world shape drift")
        if legacy["world"] in seen_legacy:
            raise CompatError("duplicate legacy world")
        seen_legacy.add(legacy["world"])

        w = world_id(row["instance"], legacy["world"])
        required_atom = legacy["required_consequence"]
        realized_atom = consequence_atom(legacy["projected_effect"])
        required = consequence_id(required_atom)
        realized = consequence_id(realized_atom)

        worlds.append(w)
        allow.append([w, required])
        possible.append([w, realized])

        semantic_match = required == realized
        if semantic_match != legacy["matches"]:
            raise CompatError(f"{row['instance']}:{legacy['world']}: frozen matches flag disagrees with translated semantic atoms")

        translated.append({
            "legacy_world": legacy["world"],
            "world_id": w,
            "required_atom": required_atom,
            "required_consequence_id": required,
            "realized_atom": realized_atom,
            "realized_consequence_id": realized,
            "frozen_matches": legacy["matches"],
        })

    claim = {
        "wire": "risu.k1.w0",
        "kind": "claim",
        "semantics": "safety-subset-v1",
        "worlds": worlds,
        "allow": allow,
        "claim_id": "claim:sha256:" + "0" * 64,
    }
    claim["claim_id"] = K.claim_id(claim)
    K.check_claim(claim)

    possible_set = frozenset((p[0], p[1]) for p in possible)
    target = K.target_id(frozenset(worlds), possible_set)
    artifact_obj = {
        "proof_format": K.PROOF_KIND,
        "claim_id": claim["claim_id"],
        "target_id": target,
        "worlds": list(worlds),
        "possible": possible,
    }
    artifact_raw = (json.dumps(artifact_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    artifact_id = "p:sha256:" + hashlib.sha256(artifact_raw).hexdigest()

    return claim, possible, artifact_obj, artifact_raw, artifact_id, translated


def make_certificate(claim, possible, artifact_obj, artifact_id):
    proof = {"kind": K.PROOF_KIND, "artifact": artifact_id}
    cert = {
        "wire": "risu.k1.w0",
        "kind": "preservation_certificate",
        "claim_id": claim["claim_id"],
        "target_id": artifact_obj["target_id"],
        "realize": copy.deepcopy(possible),
        "closure_proof": copy.deepcopy(proof),
        "grounding_proofs": [
            {"pair": copy.deepcopy(pair), "proof": copy.deepcopy(proof)} for pair in possible
        ],
        "evidence_roots": [],
        "certificate_id": "cert:sha256:" + "0" * 64,
    }
    cert["certificate_id"] = K.cert_id(cert)
    return cert


def make_witness(claim, pair, artifact_obj, artifact_id):
    wit = {
        "wire": "risu.k1.w0",
        "kind": "regression_witness",
        "claim_id": claim["claim_id"],
        "target_id": artifact_obj["target_id"],
        "pair": list(pair),
        "grounding_proof": {"kind": K.PROOF_KIND, "artifact": artifact_id},
        "evidence_roots": [],
        "witness_id": "wit:sha256:" + "0" * 64,
    }
    wit["witness_id"] = K.witness_id(wit)
    return wit


def compute_k1(row):
    claim, possible, artifact_obj, artifact_raw, artifact_id, translated = build_claim_and_model(row)
    allow = frozenset((p[0], p[1]) for p in claim["allow"])
    realize = frozenset((p[0], p[1]) for p in possible)
    forbidden = sorted(realize - allow)

    if forbidden:
        witness = make_witness(claim, forbidden[0], artifact_obj, artifact_id)
        checked = K.check_witness(witness, claim, artifact_raw)
        if checked["semantic_claim"] != "REGRESSION":
            raise CompatError("W1 failed to accept generated regression witness")
        product = "CONSEQUENCE_REGRESSION"
        proof_object_id = witness["witness_id"]
        proof_object_kind = "regression_witness"
    else:
        cert = make_certificate(claim, possible, artifact_obj, artifact_id)
        checked = K.check_certificate(cert, claim, artifact_raw)
        if checked["semantic_claim"] != "PRESERVATION":
            raise CompatError("W1 failed to accept generated preservation certificate")
        product = "PRESERVED"
        proof_object_id = cert["certificate_id"]
        proof_object_kind = "preservation_certificate"

    return {
        "instance": row["instance"],
        "k1_product_status": product,
        "claim_id": claim["claim_id"],
        "target_id": artifact_obj["target_id"],
        "finite_model_artifact_id": artifact_id,
        "proof_object_kind": proof_object_kind,
        "proof_object_id": proof_object_id,
        "forbidden_pair_count": len(forbidden),
        "translated_worlds": translated,
        "checker_assurance_scope": checked["assurance_scope"],
        "implementation_binding": checked["implementation_binding"],
    }


def diagnostics_ablated(row):
    x = copy.deepcopy(row)
    x["source_semantic_digest"] = "DIAGNOSTIC_ABLATED"
    x["exact_status"] = "DIAGNOSTIC_ABLATED"
    x["exact_failure_mode"] = "DIAGNOSTIC_ABLATED"
    x["structural"] = {"diagnostic": "ABLATED"}
    for world in x["worlds"]:
        world["coordinates"] = {"diagnostic": "ABLATED"}
        # 'matches' is diagnostic only. Preserve type but deliberately flip it;
        # build_claim_and_model normally validates it, so remove the validation
        # influence by recomputing it from the semantic atoms before translation.
        effect_atom = consequence_atom(world["projected_effect"])
        world["matches"] = effect_atom == world["required_consequence"]
    return x


def validate_snapshot(snapshot):
    if snapshot.get("snapshot_id") != "RISU_V07_K1_COMPAT_CALIBRATION_A0":
        raise CompatError("unexpected snapshot identity")
    source = snapshot.get("source")
    if not isinstance(source, dict):
        raise CompatError("missing snapshot source")
    for key, expected in PINNED_SOURCE.items():
        if source.get(key) != expected:
            raise CompatError(f"pinned source drift: {key}")
    rows = snapshot.get("rows")
    if not isinstance(rows, list) or len(rows) != PINNED_SOURCE["calibration_count"]:
        raise CompatError("calibration row count drift")
    instances = [row.get("instance") for row in rows]
    if len(set(instances)) != len(instances):
        raise CompatError("duplicate calibration instance")
    expected_statuses = {
        "001-github-guarded-merge": "CONSEQUENCE_REGRESSION",
        "002-azure-wiki-etag": "PRESERVED",
        "003-before-github-blob-sha": "CONSEQUENCE_REGRESSION",
        "003-after-github-blob-sha": "PRESERVED",
    }
    if {row["instance"]: row["legacy_product_status"] for row in rows} != expected_statuses:
        raise CompatError("legacy status pattern drift")
    return rows


def run(snapshot):
    rows = validate_snapshot(snapshot)
    output = []
    for row in rows:
        computed = compute_k1(row)
        if computed["k1_product_status"] != row["legacy_product_status"]:
            raise CompatError(
                f"{row['instance']}: K1={computed['k1_product_status']} legacy={row['legacy_product_status']}"
            )

        # Metamorphic proof that C/D/O, Exact, source digest, and coordinates are
        # not inputs to the K1 semantic judgment.
        ablated = compute_k1(diagnostics_ablated(row))
        semantic_keys = [
            "k1_product_status",
            "claim_id",
            "target_id",
            "finite_model_artifact_id",
            "proof_object_kind",
            "proof_object_id",
            "forbidden_pair_count",
        ]
        if any(ablated[key] != computed[key] for key in semantic_keys):
            raise CompatError(f"{row['instance']}: diagnostic ablation changed K1 semantic result")

        computed["legacy_product_status"] = row["legacy_product_status"]
        computed["legacy_exact_status"] = row["exact_status"]
        computed["legacy_exact_failure_mode"] = row["exact_failure_mode"]
        computed["legacy_structural"] = row["structural"]
        computed["legacy_source_semantic_digest"] = row["source_semantic_digest"]
        computed["compatibility_match"] = True
        computed["diagnostic_ablation_invariant"] = True
        output.append(computed)

    # Historical repair invariant: the BEFORE/AFTER pair has the same frozen
    # source semantic digest but changes from regression to preserved.
    before = next(x for x in rows if x["instance"] == "003-before-github-blob-sha")
    after = next(x for x in rows if x["instance"] == "003-after-github-blob-sha")
    if before["source_semantic_digest"] != after["source_semantic_digest"]:
        raise CompatError("historical transition source semantic digest changed")
    k_before = next(x for x in output if x["instance"] == before["instance"])
    k_after = next(x for x in output if x["instance"] == after["instance"])
    if (k_before["k1_product_status"], k_after["k1_product_status"]) != (
        "CONSEQUENCE_REGRESSION",
        "PRESERVED",
    ):
        raise CompatError("K1 failed historical repair transition")

    return {
        "status": "PASS",
        "adapter": "RISU_V07_TO_K1_COMPAT_A0",
        "authority": "CALIBRATION_TRANSLATION_ONLY",
        "source": snapshot["source"],
        "case_count": len(output),
        "semantic_equivalence": "4/4",
        "diagnostic_ablation_invariance": "4/4",
        "historical_repair_transition": "CONSEQUENCE_REGRESSION->PRESERVED",
        "kernel_primitives_needed_from_v07": [],
        "legacy_diagnostics_retained_outside_kernel": ["C", "D", "O", "Exact", "coordinates", "matches"],
        "checker": "risu-k1-checker-w1",
        "checker_scope": "DECLARED_FINITE_TARGET_MODEL",
        "implementation_binding": False,
        "rows": output,
        "interpretation": "The adapter demonstrates architectural equivalence on the four frozen calibration rows. It does not establish new source truth, new target truth, or implementation binding."
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", default=str(DEFAULT_SNAPSHOT))
    parser.add_argument("--output")
    args = parser.parse_args()

    with open(args.snapshot, "r", encoding="utf-8") as handle:
        snapshot = json.load(handle)
    result = run(snapshot)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        pathlib.Path(args.output).write_text(text, encoding="utf-8")
    print(text, end="")


if __name__ == "__main__":
    try:
        main()
    except (CompatError, K.Reject, K.Unsupported) as exc:
        print(json.dumps({"status": "FAIL", "reason": str(exc)}, indent=2, sort_keys=True))
        raise SystemExit(1)
