#!/usr/bin/env python3
"""Seeded generative differential gate for W1 and independent W2.

The generator imports only the neutral D0 fixture/transcript helper, never either
checker implementation. It invokes checker CLIs externally through D0's neutral
runner and compares both against six precommitted properties per trial.
"""

import argparse
import copy
import json
import pathlib
import random
import tempfile

import risu_kernel_k1_w1_w2_differential as D

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "protocols" / "RISU_KERNEL_K1_W1_W2_GENERATIVE_D1.json"


def run_one(root, idx, name, claim, proof, raw, expected, w2):
    v = D.vector(name, claim, proof, raw, expected)
    d = root / f"{idx:04d}-{name}"
    d.mkdir()
    c, p, a = D.write_case(d, v)
    w1 = D.run_checker([D.sys.executable, str(D.W1), "--claim", str(c), "--proof-object", str(p), "--artifact", str(a)])
    w2r = D.run_checker([w2, "--claim", str(c), "--proof-object", str(p), "--artifact", str(a)])
    return {
        "name": name,
        "expected": expected,
        "w1": w1["class"],
        "w1_rc": w1["rc"],
        "w2": w2r["class"],
        "w2_rc": w2r["rc"],
        "agree": w1["class"] == w2r["class"] and w1["rc"] == w2r["rc"],
        "oracle_ok": w1["class"] == expected and w2r["class"] == expected,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--w2", required=True)
    ap.add_argument("--output")
    args = ap.parse_args()

    protocol = json.loads(PROTOCOL.read_text(encoding="utf-8"))
    seed = protocol["generator"]["seed_decimal"]
    trials = protocol["generator"]["trial_count"]
    rng = random.Random(seed)

    rows = []
    disagreements = []
    oracle_failures = []
    identity_failures = []
    index = 0

    with tempfile.TemporaryDirectory(prefix="k1-d1-") as td:
        root = pathlib.Path(td)
        for t in range(trials):
            n_worlds = rng.randint(*protocol["generator"]["world_count_range"])
            world_names = [f"t{t:02d}-w{i}" for i in range(n_worlds)]
            allowed_spec = []
            allowed_labels = {}
            for i, w in enumerate(world_names):
                count = rng.randint(*protocol["generator"]["allowed_consequences_per_world_range"])
                labels = [f"t{t:02d}-w{i}-allow{j}" for j in range(count)]
                allowed_labels[w] = labels
                allowed_spec.extend((w, x) for x in labels)

            claim, W = D.make_claim(world_names, allowed_spec)
            safe = []
            for w in world_names:
                labels = allowed_labels[w]
                take = rng.randint(1, len(labels))
                chosen = rng.sample(labels, take)
                safe.extend((W[w], D.consequence(x)) for x in chosen)
            rng.shuffle(safe)

            root_count = rng.randint(*protocol["generator"]["evidence_root_count_range"])
            roots = [D.token("e:sha256:", f"t{t:02d}-root{i}") for i in range(root_count)]

            art, raw, aid = D.artifact_from(claim, safe)
            cert = D.certificate(claim, art, safe, aid, roots=roots)
            row = run_one(root, index, f"t{t:02d}-safe", claim, cert, raw, D.PRESERVE, args.w2); index += 1; rows.append(row)

            bad_world = rng.choice(world_names)
            bad_c = D.consequence(f"t{t:02d}-target-native-forbidden")
            bad_pair = (W[bad_world], bad_c)
            bad_possible = list(safe) + [bad_pair]
            rng.shuffle(bad_possible)
            bad_art, bad_raw, bad_aid = D.artifact_from(claim, bad_possible)
            bad_wit = D.witness(claim, bad_art, bad_pair, bad_aid, roots=roots)
            row = run_one(root, index, f"t{t:02d}-forbidden-witness", claim, bad_wit, bad_raw, D.REGRESS, args.w2); index += 1; rows.append(row)

            bad_cert = D.certificate(claim, bad_art, bad_possible, bad_aid, roots=roots)
            row = run_one(root, index, f"t{t:02d}-forbidden-cert", claim, bad_cert, bad_raw, D.REJECT, args.w2); index += 1; rows.append(row)

            # Semantic permutation: claim/target identities must be invariant,
            # while proof-artifact/certificate identities remain byte-bound.
            perm_claim = copy.deepcopy(claim)
            rng.shuffle(perm_claim["worlds"])
            rng.shuffle(perm_claim["allow"])
            perm_claim["claim_id"] = D.claim_id(perm_claim)
            if perm_claim["claim_id"] != claim["claim_id"]:
                identity_failures.append(f"t{t:02d}:claim-id-permutation")

            perm_safe = list(safe); rng.shuffle(perm_safe)
            artifact_worlds = list(perm_claim["worlds"]); rng.shuffle(artifact_worlds)
            perm_art, perm_raw, perm_aid = D.artifact_from(perm_claim, perm_safe, artifact_worlds=artifact_worlds)
            if perm_art["target_id"] != art["target_id"]:
                identity_failures.append(f"t{t:02d}:target-id-permutation")
            perm_roots = list(roots); rng.shuffle(perm_roots)
            perm_cert = D.certificate(perm_claim, perm_art, perm_safe, perm_aid, roots=perm_roots)
            rng.shuffle(perm_cert["grounding_proofs"])
            rng.shuffle(perm_cert["evidence_roots"])
            perm_cert["certificate_id"] = D.cert_id(perm_cert)
            row = run_one(root, index, f"t{t:02d}-permutation", perm_claim, perm_cert, perm_raw, D.PRESERVE, args.w2); index += 1; rows.append(row)

            row = run_one(root, index, f"t{t:02d}-artifact-tamper", claim, cert, raw + b"!", D.REJECT, args.w2); index += 1; rows.append(row)

            missing = copy.deepcopy(cert)
            del missing["grounding_proofs"][rng.randrange(len(missing["grounding_proofs"]))]
            missing["certificate_id"] = D.cert_id(missing)
            row = run_one(root, index, f"t{t:02d}-grounding-omission", claim, missing, raw, D.REJECT, args.w2); index += 1; rows.append(row)

    for row in rows:
        if not row["agree"]:
            disagreements.append(row["name"])
        if not row["oracle_ok"]:
            oracle_failures.append(row["name"])

    expected_count = protocol["required_comparisons"]
    status = "PASS" if len(rows) == expected_count and not disagreements and not oracle_failures and not identity_failures else "FAIL"
    result = {
        "gate": protocol["protocol_id"],
        "status": status,
        "seed_decimal": seed,
        "trial_count": trials,
        "comparison_count": len(rows),
        "required_comparisons": expected_count,
        "w1_w2_disagreements": disagreements,
        "oracle_failures": oracle_failures,
        "semantic_identity_failures": identity_failures,
        "all_comparisons_agree": not disagreements,
        "all_oracles_match": not oracle_failures,
        "claim_target_permutation_invariance": not identity_failures,
        "assurance_scope": "DECLARED_FINITE_TARGET_MODEL",
        "implementation_binding": False,
    }
    text = json.dumps(result, indent=2, sort_keys=True)
    print(text)
    if args.output:
        pathlib.Path(args.output).write_text(text + "\n", encoding="utf-8")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
