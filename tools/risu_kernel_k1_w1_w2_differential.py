#!/usr/bin/env python3
"""Neutral differential harness for frozen W1 and independent Go W2.

This file imports neither checker. It constructs W0 / finite-model-v1 fixtures
from the frozen wire transcript rules, invokes both CLIs as external processes,
and compares each checker with an independently declared expected semantic
class. Malformed boundary sentinels are reported separately from the W0-valid
qualification domain.
"""

import argparse
import copy
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
W1 = ROOT / "kernel" / "k1_checker_w1.py"
W2_SRC = ROOT / "kernel" / "k1_checker_w2.go"
PROTOCOL = ROOT / "protocols" / "RISU_KERNEL_K1_W1_W2_DIFFERENTIAL_D0.json"
PROOF_KIND = "k1.finite-model/v1"

PRESERVE = "ACCEPTED/PRESERVATION"
REGRESS = "ACCEPTED/REGRESSION"
REJECT = "REJECTED/NONE"
UNSUPPORTED = "UNSUPPORTED/UNKNOWN"


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def token(prefix, text):
    return prefix + hashlib.sha256(text.encode("utf-8")).hexdigest()


def net(s):
    b = s.encode("utf-8")
    return str(len(b)).encode("ascii") + b":" + b + b","


def vals(tag, xs):
    out = tag.encode("ascii") + net(str(len(xs)))
    for x in xs:
        out += b"V" + net(x)
    return out


def pairs_tx(tag, xs):
    out = tag.encode("ascii") + net(str(len(xs)))
    for a, b in xs:
        out += b"P" + net(a) + net(b)
    return out


def claim_id(doc):
    ws = sorted(doc["worlds"])
    allow = sorted((x[0], x[1]) for x in doc["allow"])
    pre = b"RISU-K1-CLAIM-W0\0" + b"S" + net(doc["semantics"]) + vals("W", ws) + pairs_tx("A", allow)
    return "claim:sha256:" + hashlib.sha256(pre).hexdigest()


def target_id(worlds, possible):
    pre = b"RISU-K1-TARGET-FINITE-V1\0" + vals("W", sorted(worlds)) + pairs_tx("R", sorted(possible))
    return "t:sha256:" + hashlib.sha256(pre).hexdigest()


def cert_id(doc):
    realize = sorted((x[0], x[1]) for x in doc["realize"])
    ground = sorted(
        (x["pair"][0], x["pair"][1], x["proof"]["kind"], x["proof"]["artifact"])
        for x in doc["grounding_proofs"]
    )
    roots = sorted(doc["evidence_roots"])
    q = doc["closure_proof"]
    pre = b"RISU-K1-CERT-W0\0" + b"C" + net(doc["claim_id"]) + b"T" + net(doc["target_id"])
    pre += pairs_tx("R", realize) + b"Q" + net(q["kind"]) + net(q["artifact"])
    pre += b"G" + net(str(len(ground)))
    for w, c, k, a in ground:
        pre += b"g" + net(w) + net(c) + net(k) + net(a)
    pre += vals("E", roots)
    return "cert:sha256:" + hashlib.sha256(pre).hexdigest()


def wit_id(doc):
    roots = sorted(doc["evidence_roots"])
    q = doc["grounding_proof"]
    pre = b"RISU-K1-WIT-W0\0" + b"C" + net(doc["claim_id"]) + b"T" + net(doc["target_id"])
    pre += b"P" + net(doc["pair"][0]) + net(doc["pair"][1])
    pre += b"G" + net(q["kind"]) + net(q["artifact"]) + vals("E", roots)
    return "wit:sha256:" + hashlib.sha256(pre).hexdigest()


def make_claim(world_names, allowed, world_order=None, allow_order=None):
    ids = {name: token("w:sha256:", "world:" + name) for name in world_names}
    order = world_order or list(world_names)
    allow_rows = [[ids[w], token("c:sha256:", "consequence:" + c)] for w, c in allowed]
    if allow_order is not None:
        allow_rows = [allow_rows[i] for i in allow_order]
    doc = {
        "wire": "risu.k1.w0",
        "kind": "claim",
        "semantics": "safety-subset-v1",
        "worlds": [ids[x] for x in order],
        "allow": allow_rows,
        "claim_id": "claim:sha256:" + "0" * 64,
    }
    doc["claim_id"] = claim_id(doc)
    return doc, ids


def consequence(name):
    return token("c:sha256:", "consequence:" + name)


def artifact_from(claim, possible, *, artifact_worlds=None, claim_override=None, target_override=None, extra=None):
    world_rows = list(artifact_worlds if artifact_worlds is not None else claim["worlds"])
    target = target_id(claim["worlds"], [(x[0], x[1]) for x in possible])
    obj = {
        "proof_format": PROOF_KIND,
        "claim_id": claim_override if claim_override is not None else claim["claim_id"],
        "target_id": target_override if target_override is not None else target,
        "worlds": world_rows,
        "possible": [list(x) for x in possible],
    }
    if extra:
        obj.update(extra)
    raw = (canon(obj) + "\n").encode("utf-8")
    aid = "p:sha256:" + hashlib.sha256(raw).hexdigest()
    return obj, raw, aid


def certificate(claim, artifact, possible, aid, *, proof_kind=PROOF_KIND, roots=None, grounding=None):
    proof = {"kind": proof_kind, "artifact": aid}
    doc = {
        "wire": "risu.k1.w0",
        "kind": "preservation_certificate",
        "claim_id": claim["claim_id"],
        "target_id": artifact["target_id"],
        "realize": [list(x) for x in possible],
        "closure_proof": copy.deepcopy(proof),
        "grounding_proofs": (
            copy.deepcopy(grounding)
            if grounding is not None
            else [{"pair": list(x), "proof": copy.deepcopy(proof)} for x in possible]
        ),
        "evidence_roots": list(roots or []),
        "certificate_id": "cert:sha256:" + "0" * 64,
    }
    doc["certificate_id"] = cert_id(doc)
    return doc


def witness(claim, artifact, pair, aid, *, proof_kind=PROOF_KIND, roots=None):
    doc = {
        "wire": "risu.k1.w0",
        "kind": "regression_witness",
        "claim_id": claim["claim_id"],
        "target_id": artifact["target_id"],
        "pair": list(pair),
        "grounding_proof": {"kind": proof_kind, "artifact": aid},
        "evidence_roots": list(roots or []),
        "witness_id": "wit:sha256:" + "0" * 64,
    }
    doc["witness_id"] = wit_id(doc)
    return doc


def clone(v):
    return copy.deepcopy(v)


def vector(name, claim, proof, raw, expected, *, domain="QUALIFICATION"):
    return {"name": name, "claim": claim, "proof": proof, "artifact": raw, "expected": expected, "domain": domain}


def build_vectors():
    V = []
    claim, W = make_claim(["fresh", "stale"], [("fresh", "commit"), ("stale", "reject")])
    ok = [(W["fresh"], consequence("commit")), (W["stale"], consequence("reject"))]
    art, raw, aid = artifact_from(claim, ok)
    cert = certificate(claim, art, ok, aid)
    V.append(vector("complete_preservation", claim, cert, raw, PRESERVE))

    native_bad = consequence("native-bad")
    bad_possible = [ok[0], (W["stale"], native_bad)]
    bad_art, bad_raw, bad_aid = artifact_from(claim, bad_possible)
    bad_wit = witness(claim, bad_art, bad_possible[1], bad_aid)
    V.append(vector("target_native_regression", claim, bad_wit, bad_raw, REGRESS))

    partial = certificate(claim, bad_art, [bad_possible[0]], bad_aid)
    V.append(vector("partial_closure_rejection", claim, partial, bad_raw, REJECT))

    miss = clone(cert); miss["grounding_proofs"] = miss["grounding_proofs"][:-1]; miss["certificate_id"] = cert_id(miss)
    V.append(vector("missing_grounding_rejection", claim, miss, raw, REJECT))

    unknown = certificate(claim, art, ok, aid, proof_kind="future.solver/v99")
    V.append(vector("unknown_proof_kind_unsupported", claim, unknown, raw, UNSUPPORTED))

    V.append(vector("artifact_byte_tamper_rejection", claim, cert, raw + b" ", REJECT))

    one, O = make_claim(["w"], [("w", "ok")])
    nondet = [(O["w"], consequence("ok")), (O["w"], consequence("poison"))]
    na, nr, nid = artifact_from(one, nondet)
    nc = certificate(one, na, nondet, nid)
    nw = witness(one, na, nondet[1], nid)
    V.append(vector("nondeterministic_poison_cert_rejection", one, nc, nr, REJECT))
    V.append(vector("nondeterministic_poison_witness_acceptance", one, nw, nr, REGRESS))

    subset_claim, S = make_claim(["w"], [("w", "commit"), ("w", "reject")])
    subset = [(S["w"], consequence("reject"))]
    sa, sr, sid = artifact_from(subset_claim, subset)
    sc = certificate(subset_claim, sa, subset, sid)
    V.append(vector("strict_safe_subset_preservation", subset_claim, sc, sr, PRESERVE))

    bad_claim_id = clone(claim); bad_claim_id["claim_id"] = "claim:sha256:" + "f" * 64
    V.append(vector("claim_identity_mismatch", bad_claim_id, cert, raw, REJECT))

    target_mismatch = clone(cert); target_mismatch["target_id"] = "t:sha256:" + "a" * 64; target_mismatch["certificate_id"] = cert_id(target_mismatch)
    V.append(vector("target_identity_mismatch", claim, target_mismatch, raw, REJECT))

    cert_mismatch = clone(cert); cert_mismatch["certificate_id"] = "cert:sha256:" + "b" * 64
    V.append(vector("certificate_identity_mismatch", claim, cert_mismatch, raw, REJECT))

    wit_mismatch = clone(bad_wit); wit_mismatch["witness_id"] = "wit:sha256:" + "c" * 64
    V.append(vector("witness_identity_mismatch", claim, wit_mismatch, bad_raw, REJECT))

    dup_world = clone(claim); dup_world["worlds"].append(dup_world["worlds"][0]); dup_world["claim_id"] = claim_id(dup_world)
    V.append(vector("duplicate_worlds_rejection", dup_world, cert, raw, REJECT))

    dup_allow = clone(claim); dup_allow["allow"].append(clone(dup_allow["allow"][0])); dup_allow["claim_id"] = claim_id(dup_allow)
    V.append(vector("duplicate_allow_rejection", dup_allow, cert, raw, REJECT))

    undeclared_allow = clone(claim); undeclared_allow["allow"].append([token("w:sha256:", "outside"), consequence("x")]); undeclared_allow["claim_id"] = claim_id(undeclared_allow)
    V.append(vector("undeclared_allow_world_rejection", undeclared_allow, cert, raw, REJECT))

    world_no_allow, _ = make_claim(["fresh", "stale", "orphan"], [("fresh", "commit"), ("stale", "reject")])
    V.append(vector("world_without_allow_rejection", world_no_allow, cert, raw, REJECT))

    dup_realize = clone(cert); dup_realize["realize"].append(clone(dup_realize["realize"][0])); dup_realize["certificate_id"] = cert_id(dup_realize)
    V.append(vector("duplicate_realize_rejection", claim, dup_realize, raw, REJECT))

    und_realize = clone(cert); outside_pair = [token("w:sha256:", "outside-r"), consequence("commit")]; und_realize["realize"].append(outside_pair); und_realize["grounding_proofs"].append({"pair": outside_pair, "proof": clone(und_realize["closure_proof"])}); und_realize["certificate_id"] = cert_id(und_realize)
    V.append(vector("undeclared_realize_world_rejection", claim, und_realize, raw, REJECT))

    omit = clone(cert); omit["grounding_proofs"] = omit["grounding_proofs"][1:]; omit["certificate_id"] = cert_id(omit)
    V.append(vector("grounding_set_omission_rejection", claim, omit, raw, REJECT))

    surplus = clone(cert); surplus["grounding_proofs"].append({"pair": [W["fresh"], consequence("surplus")], "proof": clone(surplus["closure_proof"])}); surplus["certificate_id"] = cert_id(surplus)
    V.append(vector("grounding_set_surplus_rejection", claim, surplus, raw, REJECT))

    dup_ground = clone(cert); dup_ground["grounding_proofs"].append(clone(dup_ground["grounding_proofs"][0])); dup_ground["certificate_id"] = cert_id(dup_ground)
    V.append(vector("duplicate_grounding_pair_rejection", claim, dup_ground, raw, REJECT))

    ground_other = clone(cert); ground_other["grounding_proofs"][0]["proof"]["artifact"] = "p:sha256:" + "d" * 64; ground_other["certificate_id"] = cert_id(ground_other)
    V.append(vector("grounding_artifact_mismatch_rejection", claim, ground_other, raw, REJECT))

    closure_bad = clone(cert); closure_bad["closure_proof"]["artifact"] = "p:sha256:" + "e" * 64
    for g in closure_bad["grounding_proofs"]: g["proof"]["artifact"] = closure_bad["closure_proof"]["artifact"]
    closure_bad["certificate_id"] = cert_id(closure_bad)
    V.append(vector("closure_artifact_digest_mismatch_rejection", claim, closure_bad, raw, REJECT))

    other_claim = "claim:sha256:" + "1" * 64
    ac_obj, ac_raw, ac_aid = artifact_from(claim, ok, claim_override=other_claim)
    ac_cert = certificate(claim, ac_obj, ok, ac_aid)
    V.append(vector("proof_artifact_claim_mismatch_rejection", claim, ac_cert, ac_raw, REJECT))

    wrong_target = "t:sha256:" + "2" * 64
    at_obj, at_raw, at_aid = artifact_from(claim, ok, target_override=wrong_target)
    at_cert = certificate(claim, at_obj, ok, at_aid)
    V.append(vector("proof_artifact_target_mismatch_rejection", claim, at_cert, at_raw, REJECT))

    aw_obj, aw_raw, aw_aid = artifact_from(claim, ok, artifact_worlds=[claim["worlds"][0]])
    aw_cert = certificate(claim, aw_obj, ok, aw_aid)
    V.append(vector("proof_artifact_world_domain_mismatch_rejection", claim, aw_cert, aw_raw, REJECT))

    only_fresh = [ok[0]]
    an_obj, an_raw, an_aid = artifact_from(claim, only_fresh)
    an_cert = certificate(claim, an_obj, only_fresh, an_aid)
    V.append(vector("proof_artifact_non_totality_rejection", claim, an_cert, an_raw, REJECT))

    root = token("e:sha256:", "root")
    dup_root = clone(cert); dup_root["evidence_roots"] = [root, root]; dup_root["certificate_id"] = cert_id(dup_root)
    V.append(vector("duplicate_evidence_root_rejection", claim, dup_root, raw, REJECT))

    native2 = consequence("another-native")
    native_possible = [ok[0], (W["stale"], native2)]
    n2a, n2r, n2id = artifact_from(claim, native_possible)
    n2w = witness(claim, n2a, native_possible[1], n2id)
    V.append(vector("open_universe_consequence_acceptance", claim, n2w, n2r, REGRESS))

    # Metamorphics: same relation/identity under semantically unordered permutations.
    rev_claim, _ = make_claim(["fresh", "stale"], [("fresh", "commit"), ("stale", "reject")], world_order=["stale", "fresh"])
    assert rev_claim["claim_id"] == claim["claim_id"]
    rev_art, rev_raw, rev_aid = artifact_from(rev_claim, list(reversed(ok)), artifact_worlds=list(reversed(rev_claim["worlds"])))
    rev_cert = certificate(rev_claim, rev_art, list(reversed(ok)), rev_aid)
    V.append(vector("world_order_metamorphic_preservation", rev_claim, rev_cert, rev_raw, PRESERVE))

    rel_claim, _ = make_claim(["fresh", "stale"], [("fresh", "commit"), ("stale", "reject")], allow_order=[1, 0])
    assert rel_claim["claim_id"] == claim["claim_id"]
    rel_art, rel_raw, rel_aid = artifact_from(rel_claim, list(reversed(ok)))
    rel_cert = certificate(rel_claim, rel_art, list(reversed(ok)), rel_aid)
    V.append(vector("relation_order_metamorphic_preservation", rel_claim, rel_cert, rel_raw, PRESERVE))

    gr_cert = clone(cert); gr_cert["grounding_proofs"] = list(reversed(gr_cert["grounding_proofs"])); gr_cert["certificate_id"] = cert_id(gr_cert)
    assert gr_cert["certificate_id"] == cert["certificate_id"]
    V.append(vector("grounding_order_metamorphic_preservation", claim, gr_cert, raw, PRESERVE))

    r1, r2 = token("e:sha256:", "r1"), token("e:sha256:", "r2")
    ev1 = certificate(claim, art, ok, aid, roots=[r1, r2]); ev2 = clone(ev1); ev2["evidence_roots"] = [r2, r1]; ev2["certificate_id"] = cert_id(ev2)
    assert ev1["certificate_id"] == ev2["certificate_id"]
    V.append(vector("evidence_order_metamorphic_preservation", claim, ev2, raw, PRESERVE))

    # Boundary sentinels outside the declared W0-valid qualification domain.
    bad_kind = certificate(claim, art, ok, aid, proof_kind="Future Solver")
    V.append(vector("sentinel_proof_kind_schema_pattern", claim, bad_kind, raw, None, domain="BOUNDARY"))

    extra_claim = clone(claim); extra_claim["unexpected"] = "x"
    V.append(vector("sentinel_json_unknown_field", extra_claim, cert, raw, REJECT, domain="BOUNDARY"))

    return V


def write_case(root, v):
    c = root / "claim.json"; p = root / "proof.json"; a = root / "artifact.json"
    c.write_text(json.dumps(v["claim"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    p.write_text(json.dumps(v["proof"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    a.write_bytes(v["artifact"])
    return c, p, a


def run_checker(cmd):
    cp = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
    try:
        obj = json.loads(cp.stdout)
    except Exception as exc:
        raise RuntimeError(f"checker did not emit JSON; rc={cp.returncode}; stdout={cp.stdout!r}; stderr={cp.stderr!r}") from exc
    cls = f"{obj.get('proof_status')}/{obj.get('semantic_claim')}"
    return {"rc": cp.returncode, "class": cls, "reason": obj.get("reason"), "raw": obj}


def independence_audit():
    src = W2_SRC.read_text(encoding="utf-8")
    forbidden = ["k1_checker_w1", "os/exec", "subprocess", "exec.Command("]
    hits = [x for x in forbidden if x in src]
    imports = re.search(r'import\s*\((.*?)\)', src, re.S)
    if not imports:
        raise AssertionError("W2 import block not found")
    libs = sorted(re.findall(r'"([^"]+)"', imports.group(1)))
    allowed = sorted(["bytes", "crypto/sha256", "encoding/hex", "encoding/json", "errors", "flag", "fmt", "os", "regexp", "sort", "strconv", "strings"])
    if libs != allowed:
        raise AssertionError(f"W2 imports drifted from standard-library allowlist: {libs}")
    return {"forbidden_reference_hits": hits, "imports": libs, "pass": not hits}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--w2", required=True, help="compiled W2 binary")
    ap.add_argument("--output")
    args = ap.parse_args()

    protocol = json.loads(PROTOCOL.read_text(encoding="utf-8"))
    assert protocol["base_release_candidate"]["commit"] == "9e85515d4974fe06c0b1db8e94e88935381fefe5"
    vectors = build_vectors()
    qualification = [x for x in vectors if x["domain"] == "QUALIFICATION"]
    boundary = [x for x in vectors if x["domain"] == "BOUNDARY"]
    if len(qualification) < protocol["minimum_qualification_vectors"]:
        raise AssertionError("insufficient qualification vectors")

    indep = independence_audit()
    if not indep["pass"]:
        raise AssertionError("W2 independence audit failed: " + repr(indep["forbidden_reference_hits"]))

    rows = []
    q_disagreements = []
    oracle_failures = []
    boundary_divergences = []
    with tempfile.TemporaryDirectory(prefix="k1-w1-w2-") as td:
        base = pathlib.Path(td)
        for i, v in enumerate(vectors):
            d = base / f"{i:03d}-{v['name']}"; d.mkdir()
            c, p, a = write_case(d, v)
            w1 = run_checker([sys.executable, str(W1), "--claim", str(c), "--proof-object", str(p), "--artifact", str(a)])
            w2 = run_checker([args.w2, "--claim", str(c), "--proof-object", str(p), "--artifact", str(a)])
            row = {
                "name": v["name"], "domain": v["domain"], "expected": v["expected"],
                "w1": w1["class"], "w1_rc": w1["rc"], "w1_reason": w1["reason"],
                "w2": w2["class"], "w2_rc": w2["rc"], "w2_reason": w2["reason"],
                "agree": w1["class"] == w2["class"] and w1["rc"] == w2["rc"],
            }
            rows.append(row)
            if v["domain"] == "QUALIFICATION":
                if not row["agree"]: q_disagreements.append(v["name"])
                if w1["class"] != v["expected"] or w2["class"] != v["expected"]:
                    oracle_failures.append(v["name"])
            else:
                if v["expected"] is not None and (w1["class"] != v["expected"] or w2["class"] != v["expected"]):
                    oracle_failures.append(v["name"])
                if not row["agree"]: boundary_divergences.append(v["name"])

    semantic_ok = not q_disagreements and not oracle_failures
    full_parser = semantic_ok and not boundary_divergences
    result = {
        "gate": protocol["protocol_id"],
        "status": "PASS" if semantic_ok else "FAIL",
        "semantic_differential_equivalence": "QUALIFIED" if semantic_ok else "NOT_QUALIFIED",
        "full_wire_parser_equivalence": "QUALIFIED" if full_parser else "NOT_QUALIFIED",
        "qualification_vector_count": len(qualification),
        "boundary_sentinel_count": len(boundary),
        "qualification_disagreements": q_disagreements,
        "oracle_failures": oracle_failures,
        "boundary_divergences": boundary_divergences,
        "independence_audit": indep,
        "w2_language": "Go",
        "w2_runtime_dependencies": "Go standard library only",
        "assurance_scope": "DECLARED_FINITE_TARGET_MODEL",
        "implementation_binding": False,
        "rows": rows,
    }
    text = json.dumps(result, indent=2, sort_keys=True)
    print(text)
    if args.output:
        pathlib.Path(args.output).write_text(text + "\n", encoding="utf-8")
    return 0 if semantic_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
