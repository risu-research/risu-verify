#!/usr/bin/env python3
from __future__ import annotations

"""Gate2B4 counterfactual obligation sufficiency decomposition (stdlib only)."""
import argparse, hashlib, json, re
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

PROTOCOL_SCHEMA = "risu.e2-candidate58-gate2b4-counterfactual-obligation-sufficiency-protocol/v0.1"
G2B2_SCHEMA = "risu.e2-candidate58-gate2b2-closure-provenance-ledger/v0.1"
G2B3_SCHEMA = "risu.e2-candidate58-gate2b3-guard-scope-attribution-ledger/v0.1"
EXPECTED_G2B2_SHA256 = "da53c72af39adba927b56fbeaf52922245bb503f8b6b5a14c45ce157fed5e2a2"
EXPECTED_G2B3_SHA256 = "d911b97fd6b2b466166e472cf2728bc3ebe0fd5b76fac05ce9d76660905799d9"
TARGET = "GUARD_SCOPE_UNRESOLVED"
WRAPPER = "FINITE_WORLD_TARGET_REALIZATION_INCOMPLETE"
PRIMARY_G2B3 = "GUARD_SCOPE_CARRIER_SURVIVAL_FAILURE"
SECONDARY = "OUTSIDE_SCOPE_OF_SCOPE_REPAIR_COUNTERFACTUAL"
TAXONOMY = (
    "SCOPE_ONLY_KNOWN_F_CLOSURE_SUFFICIENT",
    "SCOPE_ONLY_INSUFFICIENT_SINGLE_RESIDUAL_FAMILY",
    "SCOPE_ONLY_INSUFFICIENT_MULTI_RESIDUAL_FAMILY",
    SECONDARY,
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")

def cbytes(v: Any) -> bytes:
    return (json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()

def sha(raw: bytes) -> str: return hashlib.sha256(raw).hexdigest()
def shafile(p: Path) -> str: return sha(p.read_bytes())
def load(p: Path) -> Any: return json.loads(p.read_text(encoding="utf-8"))
def write(p: Path, v: Any) -> str:
    raw = cbytes(v); p.write_bytes(raw); return sha(raw)
def _rows(x: Any) -> list[Mapping[str, Any]]:
    return [r for r in x if isinstance(r, Mapping)] if isinstance(x, list) else []

def validate_protocol(p: Mapping[str, Any]) -> None:
    if p.get("schema") != PROTOCOL_SCHEMA: raise ValueError("Gate2B4 protocol schema mismatch")
    pop = p.get("population_lock", {})
    if not isinstance(pop, Mapping) or pop.get("expected_all_case_count") != 39 or pop.get("expected_primary_case_count") != 32 or pop.get("expected_secondary_case_count") != 7: raise ValueError("Gate2B4 population contract mismatch")
    tx = p.get("taxonomy", {}); order = tx.get("primary_first_match_order", []) if isinstance(tx, Mapping) else []
    ids = tuple(r.get("id") for r in order if isinstance(r, Mapping))
    if tx.get("mutually_exclusive") is not True or ids != TAXONOMY[:3] or tx.get("secondary_id") != SECONDARY: raise ValueError("Gate2B4 taxonomy contract mismatch")

def analyze_population(g2: Mapping[str, Any], g3: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if g2.get("schema") != G2B2_SCHEMA or g3.get("schema") != G2B3_SCHEMA: raise ValueError("Gate2B2/Gate2B3 ledger schema mismatch")
    r2 = _rows(g2.get("rows")); r3 = _rows(g3.get("rows"))
    if g2.get("case_count") != 39 or g3.get("case_count") != 39 or len(r2) != 39 or len(r3) != 39: raise ValueError("Gate2B4 requires exact 39+39 frozen rows")
    m2 = {str(r.get("case_id", "")): r for r in r2}; m3 = {str(r.get("case_id", "")): r for r in r3}
    if len(m2) != 39 or len(m3) != 39 or set(m2) != set(m3) or any(not HEX64.fullmatch(cid) for cid in m2): raise ValueError("Gate2B4 case-id bijection failure")
    out=[]; primary_count=0; secondary_count=0; family_freq=Counter(); sig_freq=Counter(); taxonomy_counts=Counter(); buckets={k:[] for k in TAXONOMY}; frontier_rows=[]
    for cid in sorted(m2):
        a,b=m2[cid],m3[cid]
        p2=sorted({str(x) for x in (a.get("primitive_atom_prefixes") or [])}); p3=sorted({str(x) for x in (b.get("gate2b2_primitive_atom_prefixes") or [])})
        f2=sorted(str(x) for x in (a.get("F_unresolved_atom_instances") or [])); f3=sorted(str(x) for x in (b.get("gate2b2_F_unresolved_atom_instances") or []))
        if p2 != p3 or f2 != f3: raise ValueError(f"Gate2B2/Gate2B3 copied-field mismatch:{cid}")
        if WRAPPER in p2: raise ValueError(f"wrapper illegally present in primitive set:{cid}")
        pred=b.get("predicates",{}); pred=pred if isinstance(pred,Mapping) else {}
        primary=b.get("causal_taxonomy_id")==PRIMARY_G2B3 and pred.get("P_GUARD_SCOPE_CARRIER_SURVIVAL_FAILURE") is True
        if primary:
            primary_count += 1
            if TARGET not in p2: raise ValueError(f"primary target family absent:{cid}")
            residual=sorted(set(p2)-{TARGET}); n=len(residual); sufficient=n==0
            tax=TAXONOMY[0] if n==0 else TAXONOMY[1] if n==1 else TAXONOMY[2]
            for fam in residual: family_freq[fam]+=1
            sig_freq["+".join(residual) if residual else "<EMPTY>"]+=1
            frontier_rows.append((cid,set(p2)))
        else:
            secondary_count += 1; residual=None; n=None; sufficient=None; tax=SECONDARY
        taxonomy_counts[tax]+=1; buckets[tax].append(cid)
        out.append({"case_id":cid,"gate2b3_causal_taxonomy_id":b.get("causal_taxonomy_id"),"original_primitive_atom_prefixes":p2,"target_primitive_family":TARGET if primary else None,"residual_primitive_atom_prefixes":residual,"residual_distinct_family_count":n,"scope_only_known_primitive_F_closure_sufficient":sufficient,"gate2b4_taxonomy_id":tax})
    if primary_count != 32 or secondary_count != 7: raise ValueError(f"Gate2B4 frozen population mismatch:{primary_count}:{secondary_count}")
    universe=sorted(family_freq); frontier={}
    for fam in universe:
        ids=sorted(cid for cid,orig in frontier_rows if orig <= {TARGET,fam}); frontier[fam]={"count":len(ids),"denominator":32,"case_ids":ids}
    sufficient_count=taxonomy_counts[TAXONOMY[0]]
    summary={"schema":"risu.e2-candidate58-gate2b4-counterfactual-obligation-sufficiency-summary/v0.1","status":"GATE2B4_KNOWN_PRIMITIVE_F_CLOSURE_COUNTERFACTUAL_NOT_VERDICT_GAIN","all_case_count":39,"primary_scope_carrier_failure_case_count":32,"secondary_outside_scope_case_count":7,"taxonomy_counts":{k:taxonomy_counts.get(k,0) for k in TAXONOMY},"scope_only_known_primitive_F_closure_sufficient_count":sufficient_count,"scope_only_known_primitive_F_closure_sufficient_fraction":{"numerator":sufficient_count,"denominator":32},"scope_only_known_primitive_F_closure_insufficient_count":32-sufficient_count,"scope_only_known_primitive_F_closure_insufficient_fraction":{"numerator":32-sufficient_count,"denominator":32},"residual_primitive_family_frequency":{k:family_freq[k] for k in sorted(family_freq)},"residual_primitive_signature_counts":{k:sig_freq[k] for k in sorted(sig_freq)},"residual_primitive_family_universe":universe,"two_family_closure_frontier":frontier,"taxonomy_case_ids":{k:sorted(buckets[k]) for k in TAXONOMY},"interpretation_boundary":{"known_primitive_F_closure_only":True,"actual_definitive_verdict_gain_inferred":False,"semantic_counterfactual_execution_performed":False,"remediation_priority_inferred":False,"truth_accuracy_or_population_generalization_inferred":False}}
    ledger={"schema":"risu.e2-candidate58-gate2b4-counterfactual-obligation-sufficiency-ledger/v0.1","status":"GATE2B4_FROZEN_SET_ALGEBRA_COUNTERFACTUAL_NOT_REMEDIATION","case_count":39,"primary_case_count":32,"secondary_case_count":7,"rows":out}
    return ledger,summary

def main() -> int:
    ap=argparse.ArgumentParser(); ap.add_argument("--protocol",type=Path,required=True); ap.add_argument("--gate2b2-ledger",type=Path,required=True); ap.add_argument("--gate2b3-ledger",type=Path,required=True); ap.add_argument("--output-dir",type=Path,required=True); a=ap.parse_args()
    p=load(a.protocol); validate_protocol(p)
    if shafile(a.gate2b2_ledger)!=EXPECTED_G2B2_SHA256: raise ValueError("Gate2B2 ledger SHA256 mismatch")
    if shafile(a.gate2b3_ledger)!=EXPECTED_G2B3_SHA256: raise ValueError("Gate2B3 ledger SHA256 mismatch")
    ledger,summary=analyze_population(load(a.gate2b2_ledger),load(a.gate2b3_ledger)); a.output_dir.mkdir(parents=True,exist_ok=False)
    ls=write(a.output_dir/"E2_CANDIDATE58_GATE2B4_COUNTERFACTUAL_SUFFICIENCY_LEDGER.json",ledger); ss=write(a.output_dir/"E2_CANDIDATE58_GATE2B4_COUNTERFACTUAL_SUFFICIENCY_SUMMARY.json",summary)
    rec={"schema":"risu.e2-candidate58-gate2b4-diagnostic-receipt/v0.1","status":"FIRST_COMPLETE_GATE2B4_LOGICAL_OUTPUT","inputs":{"protocol_sha256":shafile(a.protocol),"gate2b2_ledger_sha256":shafile(a.gate2b2_ledger),"gate2b3_ledger_sha256":shafile(a.gate2b3_ledger)},"outputs":{"counterfactual_sufficiency_ledger_sha256":ls,"counterfactual_sufficiency_summary_sha256":ss},"scientific_firewall":{"candidate_source_read":False,"overlay_or_path_evidence_read":False,"semantic_slice_read":False,"adapter_receipt_read":False,"kernel_result_read":False,"certificate_or_c1_read":False,"truth_or_operator_read":False,"epistemic10_read":False,"fresh_heldout_read":False,"semantic_engine_kernel_adapter_or_c1_rerun":False,"semantic_rule_change":False,"remediation":False}}
    write(a.output_dir/"E2_CANDIDATE58_GATE2B4_DIAGNOSTIC_RECEIPT.json",rec); return 0

if __name__=="__main__": raise SystemExit(main())
