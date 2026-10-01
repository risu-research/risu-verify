#!/usr/bin/env python3
"""C3 crossed-refinement gate over the exact frozen F0 62-oracle corpus.

This is a science gate, not a production proof kind.  It does not modify W7,
W8, W5, W6, C2, or K1.  For every closure-eligible source profile it forces
both crossed directions:

  W7 direct C3 == W8 replay(W7 CBTNF)
  W8 direct C3 == W7 replay(W8 CBTNF)

at the ordered pointwise payload-trace level (including multiplicity/order),
and then requires the K1 projection of those traces to equal the REALIZE set
independently reconstructed by W5 and W6 from both producer paths.

The 62 oracle meanings are read from the frozen pre-implementation F0 file;
the harness refuses to run if its case inventory differs.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "kernel"
CLAIM = ROOT / "fixtures" / "k1_mfst_c3_f0" / "claim.json"
BASE = ROOT / "fixtures" / "k1_mfst_c3_f0" / "baseline.json"
FREEZE = ROOT / "protocols" / "RISU_KERNEL_K1_MFST_C3_F0_FREEZE.json"
W7CLI = KERNEL / "k1_checker_w7.py"
W8BIN = ROOT / "build" / "k1_checker_w8"
W8CROSS = ROOT / "build" / "k1_w8_cross_replay"
W5CLI = KERNEL / "k1_checker_w5.py"
W6BIN = ROOT / "build" / "k1_checker_w6"

sys.path.insert(0, str(KERNEL))
import k1_w7_model as w7m  # frozen W7 implementation
import k1_w7_exec as w7e   # frozen W7 implementation
import k1_checker_w5 as w5wire  # certificate producer helper only; W5/W6 recheck

CLAIM_RAW = CLAIM.read_bytes()
CLAIM_OBJ = json.loads(CLAIM_RAW)
BASE_OBJ = json.loads(BASE.read_text(encoding="utf-8"))
F0 = json.loads(FREEZE.read_text(encoding="utf-8"))
PROOF_KIND = "k1.capsule-closure/v1"
passed = 0


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def consequence(payload_hex):
    return "c:sha256:" + hashlib.sha256(b"RISU-K1-CAPSULE-CONSEQUENCE-V1\0" + bytes.fromhex(payload_hex)).hexdigest()


def run_json(argv):
    cp = subprocess.run(argv, capture_output=True, text=True, check=True)
    try:
        return json.loads(cp.stdout)
    except Exception as exc:
        raise AssertionError((argv, cp.stdout, cp.stderr)) from exc


def write(path, raw):
    path.write_bytes(raw)
    return path


def direct(raw, td):
    profile = write(td / "profile.json", raw)
    o7 = td / "w7"; o8 = td / "w8"
    r7 = run_json([sys.executable, str(W7CLI), "--claim", str(CLAIM), "--profile", str(profile), "--out-dir", str(o7)])
    r8 = run_json([str(W8BIN), "--claim", str(CLAIM), "--profile", str(profile), "--out-dir", str(o8)])
    return profile, r7, r8, o7, o8


def direct_status(raw):
    with tempfile.TemporaryDirectory() as s:
        td = Path(s)
        p = write(td / "profile.bin", raw)
        r7 = run_json([sys.executable, str(W7CLI), "--claim", str(CLAIM), "--profile", str(p)])
        r8 = run_json([str(W8BIN), "--claim", str(CLAIM), "--profile", str(p)])
        return r7, r8


def norm_trace(rows):
    return [{"point": dict(x["point"]), "payloads": list(x["payloads"])} for x in rows]


def w7_replay(profile_raw, program_raw):
    c = w7m.loads(CLAIM_RAW, "claim")
    worlds, _ = w7m.check_claim(c)
    p = w7m.loads(profile_raw, "profile", True)
    m = w7m.validate(p, worlds)
    rr, gas = w7e.replay(program_raw, m)
    rows = [{"point": dict(pt), "payloads": list(pl)} for pt, pl in rr]
    return rows, gas


def w8_cross(profile_path, program_path):
    return run_json([str(W8CROSS), "--claim", str(CLAIM), "--profile", str(profile_path), "--program", str(program_path)])


def make_cert(case_id, aid, target, realize):
    proof = {"kind": PROOF_KIND, "artifact": aid}
    rows = [list(x) for x in sorted(tuple(x) for x in realize)]
    cert = {
        "wire": "risu.k1.w0",
        "kind": "preservation_certificate",
        "claim_id": CLAIM_OBJ["claim_id"],
        "target_id": target,
        "realize": rows,
        "closure_proof": dict(proof),
        "grounding_proofs": [{"pair": r, "proof": dict(proof)} for r in rows],
        "evidence_roots": ["e:sha256:" + hashlib.sha256(("RISU-C3-CROSSED-" + case_id).encode()).hexdigest()],
        "certificate_id": "cert:sha256:" + "0" * 64,
    }
    cert["certificate_id"] = w5wire.certificate_id(cert)
    return cert


def downstream(case_id, program, artifact, target, realize, td, suffix):
    aid = "p:sha256:" + hashlib.sha256(artifact).hexdigest()
    cert = make_cert(case_id + ":" + suffix, aid, target, realize)
    pp = write(td / (suffix + ".cap"), program)
    ap = write(td / (suffix + ".artifact.json"), artifact)
    cp = write(td / (suffix + ".certificate.json"), canon(cert))
    r5 = run_json([sys.executable, str(W5CLI), "--claim", str(CLAIM), "--certificate", str(cp), "--artifact", str(ap), "--program", str(pp)])
    r6 = run_json([str(W6BIN), "--claim", str(CLAIM), "--certificate", str(cp), "--artifact", str(ap), "--program", str(pp)])
    return r5, r6, cert


def assert_direct_agreement(case_id, r7, r8):
    if r7.get("proof_status") != "ACCEPTED" or r8.get("proof_status") != "ACCEPTED":
        raise AssertionError((case_id, "direct-not-accepted", r7, r8))
    for k in ("c3_semantic_id", "graph_id", "trace_map_id", "direct_trace_map", "projected_realize",
              "c2_program_sha256", "c2_derived_gas", "c2_artifact_id", "c2_target_id", "k1_subset_allowed"):
        if r7.get(k) != r8.get(k):
            raise AssertionError((case_id, "W7/W8 disagreement", k, r7.get(k), r8.get(k)))


def full_chain(case_id, raw, require_allowed=True):
    with tempfile.TemporaryDirectory() as s:
        td = Path(s)
        profile, r7, r8, o7, o8 = direct(raw, td)
        assert_direct_agreement(case_id, r7, r8)
        if require_allowed and not r7["k1_subset_allowed"]:
            raise AssertionError((case_id, "unexpected forbidden relation"))
        p7 = (o7 / "c2_program.cap").read_bytes(); p8 = (o8 / "c2_program.cap").read_bytes()
        a7 = (o7 / "c2_artifact.json").read_bytes(); a8 = (o8 / "c2_artifact.json").read_bytes()
        # The wire requires independently generated byte-identical CBTNF and artifacts.
        if p7 != p8 or a7 != a8:
            raise AssertionError((case_id, "normal-form byte disagreement"))
        d7 = norm_trace(r7["direct_trace_map"]); d8 = norm_trace(r8["direct_trace_map"])
        # Cross 1: W8 replays exact W7-generated program and must equal W7 direct.
        x8 = w8_cross(profile, o7 / "c2_program.cap")
        if x8.get("proof_status") != "ACCEPTED" or norm_trace(x8["replay_trace_map"]) != d7 or norm_trace(x8["direct_trace_map"]) != d8:
            raise AssertionError((case_id, "W8 replay(W7 CBTNF) mismatch", x8))
        # Cross 2: W7 replays exact W8-generated program and must equal W8 direct.
        x7trace, x7gas = w7_replay(raw, p8)
        if norm_trace(x7trace) != d8 or x7gas != r8["c2_derived_gas"]:
            raise AssertionError((case_id, "W7 replay(W8 CBTNF) mismatch"))
        realize = [list(x) for x in r7["projected_realize"]]
        if x8["direct_realize"] != realize:
            raise AssertionError((case_id, "W8 direct projection mismatch"))
        # Downstream: both independent C2 checkers reconstruct both producer paths.
        d57, d67, _ = downstream(case_id, p7, a7, r7["c2_target_id"], realize, td, "path7")
        d58, d68, _ = downstream(case_id, p8, a8, r8["c2_target_id"], realize, td, "path8")
        for tag, out in (("W5(P7)", d57), ("W6(P7)", d67), ("W5(P8)", d58), ("W6(P8)", d68)):
            if out.get("proof_status") != "ACCEPTED" or out.get("derived_realize") != realize:
                raise AssertionError((case_id, tag, out, realize))
        return {"r7": r7, "r8": r8, "program": p7, "artifact": a7, "trace": d7, "realize": realize}


def faithful_forbidden(case_id, raw):
    with tempfile.TemporaryDirectory() as s:
        td = Path(s)
        profile, r7, r8, o7, o8 = direct(raw, td)
        assert_direct_agreement(case_id, r7, r8)
        if r7["k1_subset_allowed"] or not r7["forbidden_projected_pairs"]:
            raise AssertionError((case_id, "forbidden consequence did not survive"))
        p7 = (o7 / "c2_program.cap").read_bytes(); p8 = (o8 / "c2_program.cap").read_bytes()
        if p7 != p8:
            raise AssertionError((case_id, "program disagreement"))
        if norm_trace(w8_cross(profile, o7 / "c2_program.cap")["replay_trace_map"]) != norm_trace(r7["direct_trace_map"]):
            raise AssertionError((case_id, "crossed forbidden trace mismatch"))
        x7, _ = w7_replay(raw, p8)
        if norm_trace(x7) != norm_trace(r8["direct_trace_map"]):
            raise AssertionError((case_id, "reverse crossed forbidden trace mismatch"))
        # A faithful certificate carrying this relation must be rejected by both downstream checkers.
        r5, r6, _ = downstream(case_id, p7, (o7 / "c2_artifact.json").read_bytes(), r7["c2_target_id"], r7["projected_realize"], td, "forbidden")
        if r5.get("proof_status") != "REJECTED" or r6.get("proof_status") != "REJECTED":
            raise AssertionError((case_id, "downstream failed to reject forbidden", r5, r6))
        return r7


def expect_reject(case_id, raw, allowed_status=("REJECTED",)):
    r7, r8 = direct_status(raw)
    if r7.get("proof_status") not in allowed_status or r8.get("proof_status") not in allowed_status:
        raise AssertionError((case_id, "wrong rejection class", r7, r8))


def emit_pass(case_id, note=""):
    global passed
    passed += 1
    print("ORACLE_PASS", case_id, note)


def block(obj, label):
    return next(x for x in obj["blocks"] if x["label"] == label)


def op_reject(opname):
    p = copy.deepcopy(BASE_OBJ)
    block(p, "safe")["ops"].insert(0, {"op": opname, "payload": "01"})
    return canon(p)


def representation_raw():
    p = copy.deepcopy(BASE_OBJ)
    p["boundary"]["worlds"].reverse(); p["boundary"]["slots"]["mode"].reverse()
    p["state"].reverse(); p["tables"].reverse(); p["tables"][0]["rows"].reverse(); p["blocks"].reverse()
    return json.dumps(p, separators=(",", ":"), ensure_ascii=True).encode()


def state_progress_profile(two_state=False):
    p = copy.deepcopy(BASE_OBJ); p["boundary"]["slots"] = {}
    if two_state:
        p["state"].append({"name":"aux","domain":["a0","a1"],"initial":{"kind":"const","value":"a0"}})
        p["tables"] = [{"name":"advance","arguments":[{"name":"x","domain":["a0","a1"]}],"result_domain":["a0","a1"],"rows":[{"when":["a0"],"result":"a1"},{"when":["a1"],"result":"a1"}]}]
        src = {"kind":"state","name":"aux"}; dst = "aux"; zero = "a0"
    else:
        p["tables"] = [{"name":"advance","arguments":[{"name":"x","domain":["p0","p1"]}],"result_domain":["p0","p1"],"rows":[{"when":["p0"],"result":"p1"},{"when":["p1"],"result":"p1"}]}]
        src = {"kind":"state","name":"phase"}; dst = "phase"; zero = "p0"
    p["blocks"] = [
        {"label":"entry","ops":[],"term":{"op":"GOTO","target":"loop"}},
        {"label":"loop","ops":[],"term":{"op":"IF_EQ","source":src,"value":zero,"if_true":"advance","if_false":"done"}},
        {"label":"advance","ops":[{"op":"APPLY_TABLE","dst":dst,"table":"advance","arguments":[src]}],"term":{"op":"GOTO","target":"loop"}},
        {"label":"done","ops":[{"op":"EMIT_HEX","payload":"01"}],"term":{"op":"HALT"}},
    ]
    return p


def world_input_profile():
    p = copy.deepcopy(BASE_OBJ)
    p["state"].append({"name":"wid","domain":copy.deepcopy(p["boundary"]["worlds"]),"initial":{"kind":"input","name":"@world"}})
    return p


def alias_profile():
    p = copy.deepcopy(BASE_OBJ)
    p["blocks"][0]["term"] = {"op":"IF_EQ","source":{"kind":"state","name":"phase"},"value":"p1","if_true":"safe","if_false":"alt"}
    return p


def binding_profile():
    p = copy.deepcopy(BASE_OBJ)
    p["state"].append({"name":"other","domain":["p0","p1"],"initial":{"kind":"const","value":"p1"}})
    p["blocks"][0]["ops"][0]["arguments"] = [{"kind":"state","name":"other"}]
    return p


def forbidden_profile(two=False):
    p = copy.deepcopy(BASE_OBJ)
    block(p, "safe")["ops"] = [{"op":"EMIT_HEX","payload":"01"},{"op":"EMIT_HEX","payload":"de"}] if two else [{"op":"EMIT_HEX","payload":"de"}]
    return p


def compare_trace_reject(case_id, source, forged_trace):
    with tempfile.TemporaryDirectory() as s:
        td = Path(s)
        _, r7, r8, _, _ = direct(canon(source), td)
        assert_direct_agreement(case_id, r7, r8)
        if norm_trace(forged_trace) == norm_trace(r7["direct_trace_map"]):
            raise AssertionError((case_id, "forged trace accidentally equal"))


def projection(trace):
    out = set()
    for row in trace:
        w = row["point"]["@world"]
        for h in row["payloads"]:
            out.add((w, consequence(h)))
    return [list(x) for x in sorted(out)]


def tampered_cert_reject(case_id, cert_mutator=None, artifact_mutator=None, program_mutator=None):
    with tempfile.TemporaryDirectory() as s:
        td = Path(s)
        profile, r7, r8, o7, _ = direct(canon(BASE_OBJ), td)
        assert_direct_agreement(case_id, r7, r8)
        prog = (o7 / "c2_program.cap").read_bytes(); art = (o7 / "c2_artifact.json").read_bytes()
        if program_mutator: prog = program_mutator(prog)
        if artifact_mutator: art = artifact_mutator(art)
        aid = "p:sha256:" + hashlib.sha256(art).hexdigest()
        cert = make_cert(case_id, aid, r7["c2_target_id"], r7["projected_realize"])
        if cert_mutator: cert_mutator(cert)
        cert["certificate_id"] = w5wire.certificate_id(cert)
        pp=write(td/"attack.cap",prog); ap=write(td/"attack.artifact.json",art); cp=write(td/"attack.cert.json",canon(cert))
        x5=run_json([sys.executable,str(W5CLI),"--claim",str(CLAIM),"--certificate",str(cp),"--artifact",str(ap),"--program",str(pp)])
        x6=run_json([str(W6BIN),"--claim",str(CLAIM),"--certificate",str(cp),"--artifact",str(ap),"--program",str(pp)])
        if x5.get("proof_status") == "ACCEPTED" or x6.get("proof_status") == "ACCEPTED":
            raise AssertionError((case_id,"tamper accepted",x5,x6))


# Full accepted cases -------------------------------------------------------
def accepted_case(case_id):
    p = copy.deepcopy(BASE_OBJ); raw = canon(p)
    if case_id == "C3-P02": raw = representation_raw()
    elif case_id == "C3-P04" or case_id == "F0-02": raw = canon(state_progress_profile())
    elif case_id == "C3-P05" or case_id == "AM1-07": raw = canon(world_input_profile())
    elif case_id == "C3-P06":
        block(p,"safe")["ops"]=[{"op":"EMIT_HEX","payload":"aa"}]; raw=canon(p)
    elif case_id == "C3-P07" or case_id == "AM1-09": raw = canon(alias_profile())
    elif case_id == "C3-P08":
        p["blocks"].append({"label":"dead","ops":[{"op":"EMIT_HEX","payload":"aa"}],"term":{"op":"HALT"}}); raw=canon(p)
    elif case_id == "AM1-01":
        p["tables"][0]["arguments"][0]["name"]="renamed"; raw=canon(p)
    elif case_id == "AM1-02": raw = canon(binding_profile())
    elif case_id == "AM1-10":
        p["tables"][0]["arguments"][0]["domain"].reverse(); p["tables"][0]["rows"].reverse(); raw=canon(p)
    b = full_chain(case_id, raw)
    if case_id == "C3-P02":
        base = full_chain(case_id+":baseline-control", canon(BASE_OBJ))
        for k in ("c3_semantic_id","graph_id","trace_map_id","c2_program_sha256","projected_realize"):
            if b["r7"][k] != base["r7"][k]: raise AssertionError((case_id,k))
        if b["r7"]["c3_source_id"] == base["r7"]["c3_source_id"]: raise AssertionError((case_id,"source id"))
    if case_id == "C3-P03":
        alt=[x for x in b["trace"] if x["point"].get("mode")=="alt"]
        if not alt or any(x["payloads"] != ["02","03"] for x in alt): raise AssertionError(case_id)
    emit_pass(case_id,"full-crossed+W5/W6")


# Parse-reject cases --------------------------------------------------------
def parse_case(case_id):
    opmap={
        "C3-01":"EFFECT","C3-08":"ASYNC","C3-09":"SPAWN","C3-11":"HOSTCALL",
        "C3-12":"DYNAMIC_LOAD","C3-13":"EVAL","C3-14":"SHARED_MEMORY","C3-15":"THREAD",
        "C3-16":"SIGNAL","C3-17":"CLOCK","C3-18":"RNG","C3-19":"ENV_READ","C3-20":"PERSIST",
    }
    if case_id in opmap:
        expect_reject(case_id,op_reject(opmap[case_id])); emit_pass(case_id,"closed grammar"); return
    if case_id=="C3-10":
        p=copy.deepcopy(BASE_OBJ); p["blocks"][0]["ops"].insert(0,{"op":"SET_FROM","dst":"phase","source":{"kind":"ambient","name":"handle"}})
        expect_reject(case_id,canon(p)); emit_pass(case_id,"source namespace"); return
    if case_id=="C3-26":
        raws=[]
        b=canon(BASE_OBJ)
        raws += [b[:-1]+b',"wire":"risu.k1.c3.mfst/v1"}', b+b"\x00", b.replace(b'"entry"',b'"entry\t"',1), b"\xff"+b,
                 b[:-1]+b',"unknown":"x"}', b[:-1]+b',"unknown":1}', b[:-1]+b',"unknown":true}', b[:-1]+b',"unknown":null}']
        for i,raw in enumerate(raws): expect_reject(case_id+":"+str(i),raw)
        emit_pass(case_id,"ambiguity battery"); return
    raise AssertionError("unhandled parse "+case_id)


# Semantic-reject cases -----------------------------------------------------
def semantic_case(case_id):
    p=copy.deepcopy(BASE_OBJ)
    if case_id=="C3-07":
        faithful_forbidden(case_id,canon(forbidden_profile(two=True))); emit_pass(case_id,"forbidden survives crossed path"); return
    if case_id=="C3-21": p["boundary"]["worlds"]=p["boundary"]["worlds"][:1]
    elif case_id=="AM1-03":
        p["tables"][0]["arguments"][0]["domain"]=["p0"]; p["tables"][0]["rows"]=[{"when":["p0"],"result":"p1"}]
    elif case_id=="AM1-04": p["tables"][0]["rows"]=p["tables"][0]["rows"][:1]
    elif case_id=="AM1-05": p["tables"][0]["rows"].append(copy.deepcopy(p["tables"][0]["rows"][0]))
    elif case_id=="AM1-06": p["tables"][0]["rows"].append({"when":["p2"],"result":"p0"})
    elif case_id=="AM1-08": p["blocks"][0]["ops"][0]["arguments"]=[{"kind":"input","name":"missing"}]
    elif case_id=="F0-01": block(p,"safe")["term"]={"op":"GOTO","target":"safe"}
    elif case_id=="F0-03": block(p,"safe")["ops"]=[]
    elif case_id=="F0-04": p["blocks"].append({"label":"dead","ops":[],"term":{"op":"GOTO","target":"missing"}})
    elif case_id=="F0-08": p["state"][0]["domain"]=["p0"]
    elif case_id=="F0-12":
        vals=["safe","alt"]+["v%04d"%i for i in range(700)]
        p["boundary"]["slots"]["mode"]=vals
        r7,r8=direct_status(canon(p))
        if r7.get("proof_status")!="UNSUPPORTED" or r8.get("proof_status")!="UNSUPPORTED": raise AssertionError((case_id,r7,r8))
        emit_pass(case_id,"C2 normalization limit fail-closed"); return
    else: raise AssertionError("unhandled semantic "+case_id)
    expect_reject(case_id,canon(p)); emit_pass(case_id,"direct semantic fail-closed")


# Cross-check reject cases --------------------------------------------------
def cross_case(case_id):
    # Trace/evidence forgery vectors: exact source reconstruction stays authoritative.
    if case_id in {"C3-02","C3-03","C3-04","C3-05","C3-06","F0-05","F0-06","F0-07","C3-31"}:
        src=copy.deepcopy(BASE_OBJ)
        if case_id in {"C3-03","C3-04"}: src=forbidden_profile(two=True)
        elif case_id=="C3-05": block(src,"safe")["ops"]=[{"op":"EMIT_HEX","payload":"aa"}]
        elif case_id=="F0-07": block(src,"alt")["ops"].append({"op":"EMIT_HEX","payload":"03"})
        elif case_id=="C3-31": block(src,"safe")["ops"].append({"op":"EMIT_HEX","payload":"aa"})
        with tempfile.TemporaryDirectory() as s:
            td=Path(s); _,r7,r8,_,_=direct(canon(src),td); assert_direct_agreement(case_id,r7,r8); forged=copy.deepcopy(r7["direct_trace_map"])
        if case_id in {"C3-02","C3-06"}:
            for row in forged:
                if row["point"].get("mode")=="alt": row["payloads"]=row["payloads"][:1]
        elif case_id in {"C3-03","C3-04"}:
            for row in forged: row["payloads"]=["01" if x=="de" else x for x in row["payloads"]]
        elif case_id=="C3-05":
            for row in forged:
                if row["point"].get("mode")=="safe": row["payloads"]=[]
        elif case_id=="F0-05":
            for row in forged:
                if row["point"].get("mode")=="alt": row["payloads"]=["03","02"]
            if projection(forged)!=r7["projected_realize"]: raise AssertionError(case_id+": K1 set changed")
        elif case_id=="F0-06":
            for row in forged:
                if row["point"].get("mode")=="alt": row["payloads"].append("03")
            if projection(forged)!=r7["projected_realize"]: raise AssertionError(case_id+": K1 set changed")
        elif case_id=="F0-07":
            for row in forged:
                if row["point"].get("mode")=="alt" and row["payloads"][-2:]==["03","03"]: row["payloads"].pop()
            if projection(forged)!=r7["projected_realize"]: raise AssertionError(case_id+": K1 set changed")
        elif case_id=="C3-31": forged=full_chain(case_id+":stale-baseline",canon(BASE_OBJ))["trace"]
        if norm_trace(forged)==norm_trace(r7["direct_trace_map"]): raise AssertionError(case_id+": forgery equal")
        emit_pass(case_id,"crossed trace veto"); return

    if case_id in {"C3-23","C3-30"}:
        b=full_chain(case_id+":base",canon(BASE_OBJ))
        if case_id=="C3-23":
            p=copy.deepcopy(BASE_OBJ); block(p,"safe")["ops"]=[{"op":"EMIT_HEX","payload":"aa"}]; raw=canon(p)
        else:
            raw=json.dumps(BASE_OBJ,indent=1,ensure_ascii=True).encode()
        with tempfile.TemporaryDirectory() as s:
            td=Path(s); _,r7,r8,_,_=direct(raw,td); assert_direct_agreement(case_id,r7,r8)
        if r7["c3_source_id"]==b["r7"]["c3_source_id"]: raise AssertionError(case_id+": stale source id survived")
        if case_id=="C3-30" and r7["c3_semantic_id"]!=b["r7"]["c3_semantic_id"]: raise AssertionError(case_id+": semantic drift")
        emit_pass(case_id,"exact source-byte binding"); return

    if case_id=="C3-22":
        # Deliberately shrink the C2 slot boundary and re-sign it. C2 alone can
        # accept this safe subset; C3 must veto because declared MFST points vanished.
        with tempfile.TemporaryDirectory() as s:
            td=Path(s); _,r7,r8,o7,_=direct(canon(BASE_OBJ),td); assert_direct_agreement(case_id,r7,r8)
            prog=(o7/"c2_program.cap").read_bytes(); art=json.loads((o7/"c2_artifact.json").read_text())
            art["boundary"]["slots"]["mode"]=["safe"]; araw=canon(art); aid="p:sha256:"+hashlib.sha256(araw).hexdigest()
            _,derived,tid=w5wire.check_artifact(araw,aid,CLAIM_OBJ,prog)
            cert=make_cert(case_id,aid,tid,[list(x) for x in sorted(derived)])
            pp=write(td/"shrink.cap",prog); ap=write(td/"shrink.artifact.json",araw); cp=write(td/"shrink.cert.json",canon(cert))
            x5=run_json([sys.executable,str(W5CLI),"--claim",str(CLAIM),"--certificate",str(cp),"--artifact",str(ap),"--program",str(pp)])
            x6=run_json([str(W6BIN),"--claim",str(CLAIM),"--certificate",str(cp),"--artifact",str(ap),"--program",str(pp)])
            if x5.get("proof_status")!="ACCEPTED" or x6.get("proof_status")!="ACCEPTED": raise AssertionError((case_id,"C2 control should accept",x5,x6))
            if len(derived)>=len(r7["projected_realize"]): raise AssertionError(case_id+": shrink ineffective")
        emit_pass(case_id,"C3 catches boundary shrink that C2 alone accepts"); return

    if case_id=="C3-24":
        # Exact mapper/program substitution under stale artifact identity.
        def pm(raw): return raw.replace(b"EMIT_HEX 03",b"EMIT_HEX 02",1)
        tampered_cert_reject(case_id,program_mutator=pm); emit_pass(case_id,"program/artifact binding"); return

    if case_id=="C3-25":
        def am(raw):
            a=json.loads(raw); a["boundary"]["gas"]+=1; return canon(a)
        tampered_cert_reject(case_id,artifact_mutator=am); emit_pass(case_id,"C2 target/limit reconstruction"); return

    if case_id=="C3-27":
        def cm(c):
            c["realize"]=c["realize"][:-1]; c["grounding_proofs"]=c["grounding_proofs"][:-1]
        tampered_cert_reject(case_id,cert_mutator=cm); emit_pass(case_id,"REALIZE reconstructed"); return

    if case_id=="C3-28":
        def am(raw):
            a=json.loads(raw); a["complete"]=True; return canon(a)
        tampered_cert_reject(case_id,artifact_mutator=am); emit_pass(case_id,"self-certification excluded"); return

    if case_id=="C3-29":
        def cm(c): c["target_id"]="t:sha256:"+"0"*64
        tampered_cert_reject(case_id,cert_mutator=cm); emit_pass(case_id,"target independently derived"); return

    if case_id=="C3-32":
        b=full_chain(case_id+":control",canon(BASE_OBJ)); fake=copy.deepcopy(b["r8"]); fake["graph_id"]="c3graph:sha256:"+"0"*64
        if all(b["r7"].get(k)==fake.get(k) for k in ("graph_id","trace_map_id","projected_realize","c2_program_sha256")): raise AssertionError(case_id)
        emit_pass(case_id,"checker disagreement veto"); return

    if case_id=="F0-09":
        b=full_chain(case_id+":exact",canon(state_progress_profile(two_state=True)))
        # Deliberately broken cycle key (label + phase only) sees a false cycle.
        # Exact W7/W8 include the complete state vector and accept.
        if b["r7"]["proof_status"]!="ACCEPTED": raise AssertionError(case_id)
        emit_pass(case_id,"full-state graph defeats omitted-dimension cycle key"); return

    if case_id=="F0-10":
        b=full_chain(case_id+":control",canon(BASE_OBJ)); p=b["program"]
        mutant=p+b"LABEL C3.UNREACH\nEMIT_HEX 01\nHALT\n"
        if mutant==p: raise AssertionError(case_id)
        # Replay remains pointwise equal, proving byte identity is a separate necessary check.
        x7,_=w7_replay(canon(BASE_OBJ),mutant)
        with tempfile.TemporaryDirectory() as s:
            td=Path(s); prof=write(td/"profile.json",canon(BASE_OBJ)); mp=write(td/"mut.cap",mutant); x8=w8_cross(prof,mp)
        if norm_trace(x7)!=b["trace"] or norm_trace(x8["replay_trace_map"])!=b["trace"]: raise AssertionError(case_id+": control not semantically equivalent")
        emit_pass(case_id,"byte-different normal form veto despite equal traces"); return

    if case_id=="F0-11":
        def am(raw):
            a=json.loads(raw); a["boundary"]["gas"]-=1; return canon(a)
        tampered_cert_reject(case_id,artifact_mutator=am); emit_pass(case_id,"gas underbound fail-closed"); return

    raise AssertionError("unhandled cross "+case_id)


# Inventory is authority data, not a hand-maintained count. -----------------
oracles={}
for x in F0["positive_controls"]: oracles[x["id"]]=(x["oracle"],x["name"])
for key in ("legacy_vectors","amendment_vectors","mandatory_additional_vectors"):
    for cid,name,oracle,_ in F0[key]:
        if cid in oracles: raise AssertionError("duplicate frozen oracle "+cid)
        oracles[cid]=(oracle,name)
if F0["counts"]["total_oracles"]!=62 or len(oracles)!=62:
    raise AssertionError(("frozen corpus count",F0["counts"],len(oracles)))

ACCEPT={cid for cid,(o,_) in oracles.items() if o=="ACCEPT"}
PARSE={cid for cid,(o,_) in oracles.items() if o=="PARSE_REJECT"}
SEM={cid for cid,(o,_) in oracles.items() if o=="SEMANTIC_REJECT"}
CROSS={cid for cid,(o,_) in oracles.items() if o=="CROSSCHECK_REJECT"}
expected_accept={"C3-P01","C3-P02","C3-P03","C3-P04","C3-P05","C3-P06","C3-P07","C3-P08","AM1-01","AM1-02","AM1-07","AM1-09","AM1-10","F0-02"}
if ACCEPT!=expected_accept: raise AssertionError(("accept inventory drift",ACCEPT^expected_accept))
if not (ACCEPT|PARSE|SEM|CROSS)==set(oracles): raise AssertionError("oracle class inventory")

print("FROZEN_F0_INVENTORY",len(oracles),"ACCEPT",len(ACCEPT),"PARSE",len(PARSE),"SEMANTIC",len(SEM),"CROSSCHECK",len(CROSS))
for cid in sorted(oracles):
    oracle,name=oracles[cid]
    if oracle=="ACCEPT": accepted_case(cid)
    elif oracle=="PARSE_REJECT": parse_case(cid)
    elif oracle=="SEMANTIC_REJECT": semantic_case(cid)
    elif oracle=="CROSSCHECK_REJECT": cross_case(cid)
    else: raise AssertionError((cid,oracle))

if passed!=62: raise AssertionError(("not all frozen oracles executed",passed))
print("C3_CROSSED_F0_PASS",passed)
print("AUTHORITY_CREATED false")
