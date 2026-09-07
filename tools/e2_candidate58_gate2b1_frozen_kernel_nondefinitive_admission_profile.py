#!/usr/bin/env python3
from __future__ import annotations

"""Gate 2B.1: profile frozen kernel-nondefinitive outputs without rerunning semantics.

Scientific inputs are deliberately narrow: the immutable Gate2B0 frontier
ledger, the immutable first-complete machine matrix, and only the replay1/2
kernel_result.json members for the 39 Gate2B0 KERNEL_NONDEFINITIVE cases in
the exact immutable first-machine bundle ZIP.  This module imports no RISU
semantic or C1 code and never reads source, semantic-slice, certificate, or
truth/operator content.
"""

import argparse
import hashlib
import json
import stat
import zipfile
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

PROTOCOL_SCHEMA = "risu.e2-candidate58-gate2b1-frozen-kernel-nondefinitive-admission-profile-protocol/v0.1"
PROTOCOL_STATUS = "POST_GATE2B0_DIAGNOSTIC_TAXONOMY_FROZEN_BEFORE_GATE2B1_KERNEL_RESULT_EXECUTION"
MATRIX_SCHEMA = "risu.e2-candidate58-machine-prediction-matrix/v0.1"
GATE2B0_LEDGER_SCHEMA = "risu.e2-candidate58-gate2b0-frontier-ledger/v0.1"
KERNEL_RESULT_SCHEMA = "risu.e2-semantic-kernel-result/v0.1"
INCOMPLETE = "E2_PREDICTED_ASSURANCE_INCOMPLETE"
EXPECTED_MATRIX_SHA256 = "7273ce4034d06e67989a33540f5b22fef3190cf311a8981474413b538e43472d"
EXPECTED_GATE2B0_LEDGER_SHA256 = "522a2e73f55fb79513a04c4edfafb96f6753431bb5cc036700b404398a0a92cc"
EXPECTED_BUNDLE_SHA256 = "d77caaf74bf4dc8e94cf769d10092f8413595ac93422042e8a374f76c343f42d"
EXPECTED_BUNDLE_MEMBERS = 946
EXPECTED_SELECTED = 39

ADMISSION_IDS = {
    "A": "A_COORDINATE_RESOURCE_IDENTITY",
    "B": "B_CARRIER_SURVIVAL",
    "C": "C_GUARD_SEMANTICS",
    "D": "D_GUARD_EFFECT_CONTROL",
    "E": "E_EFFECT_AND_OUTCOME",
    "F": "F_CLOSED_SCOPE",
}
ADMISSION_ORDER = tuple(ADMISSION_IDS)
OBLIGATIONS = (
    "A3_P1_REQUIRED_ROLE_REACHABILITY",
    "A3_P2_BINDING_IDENTITY",
    "A3_P3_DEFINITION_SENSITIVITY",
    "A3_P4_REPRESENTATION_SURVIVAL",
    "A3_P5_PATH_REALIZABILITY",
    "A4_P1_EFFECT_BOUNDARY",
    "A4_P2_EFFECTIVE_GUARD",
    "A4_P3_GUARD_DOMINATES_EFFECT",
    "A4_P4_CANONICAL_POLARITY",
    "A4_P5_NO_BYPASS_OR_FALLBACK",
    "A4_P6_ORDERING",
    "A4_P7_OUTCOME_DISTINCTION",
)
SHADOW_MAP = {
    "A3_P2_BINDING_IDENTITY": "A",
    "A3_P5_PATH_REALIZABILITY": "B",
    "A4_P1_EFFECT_BOUNDARY": "E",
    "A4_P2_EFFECTIVE_GUARD": "C",
    "A4_P5_NO_BYPASS_OR_FALLBACK": "D",
}
BRANCHES = (
    "WORLD_INTERPRETATION_INCOMPLETE",
    "COMPLETE_COLLAPSE_WITHOUT_ADMITTED_WITNESS",
    "COMPLETE_NO_COLLAPSE_PRESERVATION_DEFICIT",
)

LEDGER_SCHEMA = "risu.e2-candidate58-gate2b1-admission-profile-ledger/v0.1"
SUMMARY_SCHEMA = "risu.e2-candidate58-gate2b1-admission-profile-summary/v0.1"
READ_MANIFEST_SCHEMA = "risu.e2-candidate58-gate2b1-kernel-result-read-manifest/v0.1"
RECEIPT_SCHEMA = "risu.e2-candidate58-gate2b1-diagnostic-receipt/v0.1"


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_json(path: Path) -> tuple[Mapping[str, Any], bytes]:
    raw = path.read_bytes()
    obj = json.loads(raw.decode("utf-8"))
    if not isinstance(obj, Mapping):
        raise ValueError(f"top-level JSON object required:{path}")
    return obj, raw


def write_json(path: Path, value: Any) -> str:
    raw = canonical_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return sha256_bytes(raw)


def _string_list(value: Any, *, name: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
        raise ValueError(f"{name} must be a string list")
    return list(value)


def validate_protocol(protocol: Mapping[str, Any]) -> None:
    if protocol.get("schema") != PROTOCOL_SCHEMA or protocol.get("status") != PROTOCOL_STATUS:
        raise ValueError("Gate2B1 protocol identity mismatch")
    authority = protocol.get("authority") or {}
    if authority.get("gate2b0_first_complete_freeze_commit") != "2c36c0d0eae46844bc077fc548594ac84b376381":
        raise ValueError("Gate2B1 Gate2B0 authority mismatch")
    if (authority.get("gate2b0_frontier_ledger") or {}).get("sha256") != EXPECTED_GATE2B0_LEDGER_SHA256:
        raise ValueError("Gate2B1 frontier-ledger authority mismatch")
    if (authority.get("first_complete_machine_matrix") or {}).get("sha256") != EXPECTED_MATRIX_SHA256:
        raise ValueError("Gate2B1 machine-matrix authority mismatch")
    bundle = authority.get("first_complete_machine_bundle") or {}
    if bundle.get("sha256") != EXPECTED_BUNDLE_SHA256 or bundle.get("member_count") != EXPECTED_BUNDLE_MEMBERS:
        raise ValueError("Gate2B1 bundle authority mismatch")
    if (authority.get("frozen_kernel") or {}).get("git_blob") != "e91e51397f4cc201452b1a0f80d130265dca2ea0":
        raise ValueError("Gate2B1 frozen-kernel authority mismatch")
    pop = protocol.get("population_lock") or {}
    if pop.get("expected_selected_count") != EXPECTED_SELECTED:
        raise ValueError("Gate2B1 population lock mismatch")
    integrity = protocol.get("kernel_result_integrity_contract") or {}
    if integrity.get("admission_ids") != ADMISSION_IDS:
        raise ValueError("Gate2B1 admission-id lock mismatch")
    if tuple(integrity.get("obligation_keys") or ()) != OBLIGATIONS:
        raise ValueError("Gate2B1 obligation lock mismatch")
    if (protocol.get("direct_obligation_shadow_map") or {}).get("map") != SHADOW_MAP:
        raise ValueError("Gate2B1 direct-shadow lock mismatch")
    det = protocol.get("determinism_and_freeze") or {}
    if det.get("stdlib_only_analyzer") is not True or det.get("analyzer_must_not_import_risu_semantic_or_c1_packages") is not True:
        raise ValueError("Gate2B1 stdlib-only lock missing")


def validate_population(ledger: Mapping[str, Any], ledger_raw: bytes, matrix: Mapping[str, Any], matrix_raw: bytes) -> tuple[list[str], dict[str, Mapping[str, Any]]]:
    if sha256_bytes(ledger_raw) != EXPECTED_GATE2B0_LEDGER_SHA256:
        raise ValueError("Gate2B0 frontier ledger SHA-256 mismatch")
    if ledger.get("schema") != GATE2B0_LEDGER_SCHEMA or ledger.get("case_count") != 58:
        raise ValueError("Gate2B0 frontier ledger schema/count mismatch")
    lrows = ledger.get("rows")
    if not isinstance(lrows, list) or len(lrows) != 58:
        raise ValueError("Gate2B0 frontier ledger rows mismatch")
    ledger_ids = [str(r.get("case_id", "")) for r in lrows if isinstance(r, Mapping)]
    if len(ledger_ids) != 58 or len(set(ledger_ids)) != 58:
        raise ValueError("Gate2B0 frontier ledger case identities not bijective")

    selected: list[str] = []
    for row in lrows:
        if not isinstance(row, Mapping):
            raise ValueError("Gate2B0 frontier row not object")
        if row.get("frontier") == "KERNEL_NONDEFINITIVE":
            if row.get("tentative_kernel_prediction") != INCOMPLETE or row.get("machine_prediction") != INCOMPLETE or row.get("promotion_reasons") != []:
                raise ValueError("Gate2B0 selected frontier row contradicts population lock")
            selected.append(str(row["case_id"]))
    selected = sorted(selected)
    if len(selected) != EXPECTED_SELECTED or len(set(selected)) != EXPECTED_SELECTED:
        raise ValueError(f"Gate2B1 selected population must be exactly {EXPECTED_SELECTED}")

    if sha256_bytes(matrix_raw) != EXPECTED_MATRIX_SHA256:
        raise ValueError("first-complete machine matrix SHA-256 mismatch")
    if matrix.get("schema") != MATRIX_SCHEMA or matrix.get("case_count") != 58:
        raise ValueError("machine matrix schema/count mismatch")
    mrows = matrix.get("cases")
    if not isinstance(mrows, list) or len(mrows) != 58:
        raise ValueError("machine matrix rows mismatch")
    matrix_by_id: dict[str, Mapping[str, Any]] = {}
    for row in mrows:
        if not isinstance(row, Mapping):
            raise ValueError("machine matrix row not object")
        cid = str(row.get("case_id", ""))
        if not cid or cid in matrix_by_id:
            raise ValueError("machine matrix case identities not bijective")
        matrix_by_id[cid] = row
    if set(matrix_by_id) != set(ledger_ids):
        raise ValueError("Gate2B0 ledger and machine matrix populations differ")
    for cid in selected:
        row = matrix_by_id[cid]
        if row.get("tentative_kernel_prediction") != INCOMPLETE or row.get("machine_prediction") != INCOMPLETE or row.get("promotion_reasons") != []:
            raise ValueError(f"selected machine row contradicts Gate2B1 population:{cid}")
        digest = row.get("kernel_result_sha256")
        if not isinstance(digest, str) or len(digest) != 64:
            raise ValueError(f"selected machine row lacks kernel-result digest:{cid}")
    return selected, matrix_by_id


def validate_zip_metadata(z: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    infos = z.infolist()
    if len(infos) != EXPECTED_BUNDLE_MEMBERS:
        raise ValueError(f"bundle member count mismatch:{len(infos)}")
    by_name: dict[str, zipfile.ZipInfo] = {}
    for info in infos:
        name = info.filename
        if not name or name in by_name:
            raise ValueError("bundle contains empty or duplicate member name")
        p = PurePosixPath(name)
        if p.is_absolute() or ".." in p.parts:
            raise ValueError(f"unsafe bundle member path:{name}")
        mode = (info.external_attr >> 16) & 0o170000
        if mode == stat.S_IFLNK:
            raise ValueError(f"symlink bundle member forbidden:{name}")
        by_name[name] = info
    return by_name


def recompute_result_digest(doc: Mapping[str, Any]) -> str:
    copy = dict(doc)
    supplied = copy.pop("result_digest_sha256", None)
    if not isinstance(supplied, str) or len(supplied) != 64:
        raise ValueError("kernel result digest field malformed")
    actual = sha256_bytes(canonical_bytes(copy))
    if actual != supplied:
        raise ValueError("kernel result internal digest mismatch")
    return actual


def validate_kernel_result(doc: Mapping[str, Any]) -> dict[str, Any]:
    if doc.get("schema") != KERNEL_RESULT_SCHEMA or doc.get("prediction") != INCOMPLETE:
        raise ValueError("selected frozen kernel result schema/prediction mismatch")
    if doc.get("infrastructure_reasons") != []:
        raise ValueError("selected kernel-nondefinitive result has infrastructure reasons")
    recompute_result_digest(doc)

    admissions = doc.get("admissions")
    if not isinstance(admissions, Mapping) or set(admissions) != set(ADMISSION_ORDER):
        raise ValueError("kernel result admissions must be exactly A..F")
    normalized_admissions: dict[str, dict[str, Any]] = {}
    for aid in ADMISSION_ORDER:
        row = admissions[aid]
        if not isinstance(row, Mapping) or row.get("id") != ADMISSION_IDS[aid] or not isinstance(row.get("satisfied"), bool):
            raise ValueError(f"kernel admission malformed:{aid}")
        reasons = _string_list(row.get("reasons"), name=f"admission {aid} reasons")
        if reasons != sorted(set(reasons)):
            raise ValueError(f"kernel admission reasons not canonical:{aid}")
        if bool(row["satisfied"]) != (len(reasons) == 0):
            raise ValueError(f"kernel admission satisfied/reasons contradiction:{aid}")
        normalized_admissions[aid] = {"satisfied": bool(row["satisfied"]), "reasons": reasons}

    obligations = doc.get("obligations")
    if not isinstance(obligations, Mapping) or set(obligations) != set(OBLIGATIONS):
        raise ValueError("kernel result obligations must be exact frozen set")
    normalized_obligations: dict[str, bool] = {}
    for key in OBLIGATIONS:
        value = obligations[key]
        if not isinstance(value, bool):
            raise ValueError(f"kernel obligation nonboolean:{key}")
        normalized_obligations[key] = value

    world = doc.get("world_relation")
    if not isinstance(world, Mapping) or not isinstance(world.get("complete"), bool) or not isinstance(world.get("violating_pairs"), list):
        raise ValueError("kernel world_relation malformed")
    violating_pairs = world["violating_pairs"]
    for pair in violating_pairs:
        if not isinstance(pair, list) or len(pair) != 2 or any(not isinstance(x, str) for x in pair):
            raise ValueError("kernel violating pair malformed")
    witnesses = doc.get("witnesses")
    if not isinstance(witnesses, list) or any(not isinstance(x, Mapping) for x in witnesses):
        raise ValueError("kernel witnesses malformed")
    unresolved = _string_list(doc.get("unresolved"), name="kernel unresolved")
    if unresolved != sorted(set(unresolved)):
        raise ValueError("kernel unresolved list not canonical")

    expected_unresolved: set[str] = set()
    for aid in ADMISSION_ORDER:
        expected_unresolved.update(normalized_admissions[aid]["reasons"])
    if world["complete"] is False:
        expected_unresolved.add("WORLD_INTERPRETATION_INCOMPLETE")
    if violating_pairs and not witnesses:
        expected_unresolved.add("CTV_COLLAPSE_WITHOUT_ADMITTED_CONSTRUCTIVE_WITNESS")
    for key in OBLIGATIONS:
        if normalized_obligations[key] is False:
            expected_unresolved.add(f"OBLIGATION_UNPROVEN:{key}")
    if unresolved != sorted(expected_unresolved):
        raise ValueError("kernel unresolved bookkeeping does not reconstruct exactly")

    failed = [aid for aid in ADMISSION_ORDER if not normalized_admissions[aid]["satisfied"]]
    false_obligations = [key for key in OBLIGATIONS if not normalized_obligations[key]]
    shadowed = [key for key in false_obligations if key in SHADOW_MAP and SHADOW_MAP[key] in failed]
    residual = [key for key in false_obligations if key not in set(shadowed)]

    branch_matches: list[str] = []
    if world["complete"] is False and not violating_pairs:
        branch_matches.append("WORLD_INTERPRETATION_INCOMPLETE")
    if world["complete"] is True and violating_pairs and not witnesses:
        branch_matches.append("COMPLETE_COLLAPSE_WITHOUT_ADMITTED_WITNESS")
    if world["complete"] is True and not violating_pairs and (failed or false_obligations):
        branch_matches.append("COMPLETE_NO_COLLAPSE_PRESERVATION_DEFICIT")
    if len(branch_matches) != 1:
        raise ValueError(f"selected incomplete result matches {len(branch_matches)} top-level branches")
    branch = branch_matches[0]
    if branch == "WORLD_INTERPRETATION_INCOMPLETE" and "WORLD_INTERPRETATION_INCOMPLETE" not in unresolved:
        raise ValueError("world-incomplete branch missing required unresolved atom")
    if branch == "COMPLETE_COLLAPSE_WITHOUT_ADMITTED_WITNESS" and "CTV_COLLAPSE_WITHOUT_ADMITTED_CONSTRUCTIVE_WITNESS" not in unresolved:
        raise ValueError("collapse-without-witness branch missing required unresolved atom")

    reasons_by_admission = {aid: normalized_admissions[aid]["reasons"] for aid in ADMISSION_ORDER}
    families_by_admission = {
        aid: sorted({reason.split(":", 1)[0] for reason in normalized_admissions[aid]["reasons"]})
        for aid in ADMISSION_ORDER
    }
    return {
        "top_level_incomplete_branch": branch,
        "failed_admission_ids": failed,
        "failed_admission_signature": "+".join(failed) if failed else "NONE",
        "failed_admission_count": len(failed),
        "admission_reasons": reasons_by_admission,
        "admission_reason_families": families_by_admission,
        "false_preservation_obligations": false_obligations,
        "directly_shadowed_false_obligations": shadowed,
        "residual_false_obligations": residual,
        "world_complete": bool(world["complete"]),
        "violating_pair_count": len(violating_pairs),
        "witness_count": len(witnesses),
    }


def synthetic_kernel_result(*, world_complete: bool, violating_pairs: Sequence[Sequence[str]], witnesses: Sequence[Mapping[str, Any]], failed_admissions: Sequence[str], false_obligations: Sequence[str]) -> dict[str, Any]:
    failed = set(failed_admissions)
    false = set(false_obligations)
    admissions = {
        aid: {"id": ADMISSION_IDS[aid], "satisfied": aid not in failed, "reasons": ([] if aid not in failed else [f"{aid}_SYNTHETIC_REASON:item"])}
        for aid in ADMISSION_ORDER
    }
    obligations = {key: key not in false for key in OBLIGATIONS}
    unresolved: set[str] = {r for row in admissions.values() for r in row["reasons"]}
    if not world_complete:
        unresolved.add("WORLD_INTERPRETATION_INCOMPLETE")
    if violating_pairs and not witnesses:
        unresolved.add("CTV_COLLAPSE_WITHOUT_ADMITTED_CONSTRUCTIVE_WITNESS")
    for key in false:
        unresolved.add(f"OBLIGATION_UNPROVEN:{key}")
    doc: dict[str, Any] = {
        "schema": KERNEL_RESULT_SCHEMA,
        "prediction": INCOMPLETE,
        "infrastructure_reasons": [],
        "admissions": admissions,
        "obligations": obligations,
        "witnesses": list(witnesses),
        "world_relation": {"complete": world_complete, "violating_pairs": [list(x) for x in violating_pairs]},
        "unresolved": sorted(unresolved),
        "declared_scope_id": "synthetic",
    }
    doc["result_digest_sha256"] = sha256_bytes(canonical_bytes(doc))
    return doc


def self_test() -> None:
    a = synthetic_kernel_result(
        world_complete=False, violating_pairs=[], witnesses=[], failed_admissions=["F"],
        false_obligations=["A4_P4_CANONICAL_POLARITY"],
    )
    pa = validate_kernel_result(a)
    assert pa["top_level_incomplete_branch"] == "WORLD_INTERPRETATION_INCOMPLETE"
    assert pa["failed_admission_signature"] == "F"
    assert pa["residual_false_obligations"] == ["A4_P4_CANONICAL_POLARITY"]

    b = synthetic_kernel_result(
        world_complete=True, violating_pairs=[["w1", "w2"]], witnesses=[], failed_admissions=[], false_obligations=[],
    )
    pb = validate_kernel_result(b)
    assert pb["top_level_incomplete_branch"] == "COMPLETE_COLLAPSE_WITHOUT_ADMITTED_WITNESS"
    assert pb["failed_admission_signature"] == "NONE"

    c = synthetic_kernel_result(
        world_complete=True, violating_pairs=[], witnesses=[], failed_admissions=["A", "D"],
        false_obligations=["A3_P2_BINDING_IDENTITY", "A4_P5_NO_BYPASS_OR_FALLBACK", "A4_P6_ORDERING"],
    )
    pc = validate_kernel_result(c)
    assert pc["top_level_incomplete_branch"] == "COMPLETE_NO_COLLAPSE_PRESERVATION_DEFICIT"
    assert pc["failed_admission_signature"] == "A+D"
    assert pc["directly_shadowed_false_obligations"] == ["A3_P2_BINDING_IDENTITY", "A4_P5_NO_BYPASS_OR_FALLBACK"]
    assert pc["residual_false_obligations"] == ["A4_P6_ORDERING"]

    broken = dict(c)
    broken["unresolved"] = []
    broken["result_digest_sha256"] = sha256_bytes(canonical_bytes({k: v for k, v in broken.items() if k != "result_digest_sha256"}))
    try:
        validate_kernel_result(broken)
    except ValueError:
        pass
    else:
        raise AssertionError("broken unresolved bookkeeping did not fail closed")


def _counter_dict(counter: Counter[str], ordered: Sequence[str] | None = None) -> dict[str, int]:
    if ordered is not None:
        return {key: counter.get(key, 0) for key in ordered}
    return {key: counter[key] for key in sorted(counter)}


def execute(protocol_path: Path, ledger_path: Path, matrix_path: Path, bundle_path: Path, output_dir: Path) -> dict[str, Any]:
    protocol, protocol_raw = read_json(protocol_path)
    ledger, ledger_raw = read_json(ledger_path)
    matrix, matrix_raw = read_json(matrix_path)
    validate_protocol(protocol)
    selected, matrix_by_id = validate_population(ledger, ledger_raw, matrix, matrix_raw)
    bundle_raw_sha = sha256_bytes(bundle_path.read_bytes())
    if bundle_raw_sha != EXPECTED_BUNDLE_SHA256:
        raise ValueError("first-machine bundle ZIP SHA-256 mismatch")

    rows: list[dict[str, Any]] = []
    read_rows: list[dict[str, Any]] = []
    admission_counts: Counter[str] = Counter()
    signature_counts: Counter[str] = Counter()
    cardinality_counts: Counter[str] = Counter()
    branch_counts: Counter[str] = Counter()
    raw_obligation_counts: Counter[str] = Counter()
    shadowed_obligation_counts: Counter[str] = Counter()
    residual_obligation_counts: Counter[str] = Counter()
    family_counts: dict[str, Counter[str]] = {aid: Counter() for aid in ADMISSION_ORDER}
    pairwise = {a: {b: 0 for b in ADMISSION_ORDER} for a in ADMISSION_ORDER}
    branch_signature: dict[str, Counter[str]] = {branch: Counter() for branch in BRANCHES}
    world_presence = Counter()
    violating_presence = Counter()
    witness_presence = Counter()
    violating_count_distribution = Counter()
    witness_count_distribution = Counter()

    with zipfile.ZipFile(bundle_path) as z:
        members = validate_zip_metadata(z)
        permitted_names: set[str] = set()
        for cid in selected:
            n1 = f"replay1/cases/{cid}/kernel_result.json"
            n2 = f"replay2/cases/{cid}/kernel_result.json"
            permitted_names.update((n1, n2))
            if n1 not in members or n2 not in members:
                raise ValueError(f"selected case missing exact kernel-result members:{cid}")
            raw1 = z.read(n1)
            raw2 = z.read(n2)
            if raw1 != raw2:
                raise ValueError(f"replay kernel-result byte identity failed:{cid}")
            digest = sha256_bytes(raw1)
            if digest != matrix_by_id[cid]["kernel_result_sha256"]:
                raise ValueError(f"kernel-result digest does not match machine matrix:{cid}")
            try:
                doc = json.loads(raw1.decode("utf-8"))
            except Exception as exc:
                raise ValueError(f"kernel-result JSON decode failed:{cid}") from exc
            if not isinstance(doc, Mapping):
                raise ValueError(f"kernel-result top-level object required:{cid}")
            profile = validate_kernel_result(doc)
            row = {"case_id": cid, **profile}
            rows.append(row)
            read_rows.append({
                "case_id": cid,
                "replay1_member": n1,
                "replay2_member": n2,
                "kernel_result_sha256": digest,
                "replay_bytes_identical": True,
                "matches_machine_matrix_kernel_result_sha256": True,
            })

            failed = profile["failed_admission_ids"]
            for aid in failed:
                admission_counts[aid] += 1
            signature = profile["failed_admission_signature"]
            signature_counts[signature] += 1
            cardinality_counts[str(profile["failed_admission_count"])] += 1
            branch = profile["top_level_incomplete_branch"]
            branch_counts[branch] += 1
            branch_signature[branch][signature] += 1
            for a in ADMISSION_ORDER:
                if a in failed:
                    for b in ADMISSION_ORDER:
                        if b in failed:
                            pairwise[a][b] += 1
            for aid in ADMISSION_ORDER:
                for fam in profile["admission_reason_families"][aid]:
                    family_counts[aid][fam] += 1
            for key in profile["false_preservation_obligations"]:
                raw_obligation_counts[key] += 1
            for key in profile["directly_shadowed_false_obligations"]:
                shadowed_obligation_counts[key] += 1
            for key in profile["residual_false_obligations"]:
                residual_obligation_counts[key] += 1
            world_presence["complete" if profile["world_complete"] else "incomplete"] += 1
            violating_presence["present" if profile["violating_pair_count"] else "absent"] += 1
            witness_presence["present" if profile["witness_count"] else "absent"] += 1
            violating_count_distribution[str(profile["violating_pair_count"])] += 1
            witness_count_distribution[str(profile["witness_count"])] += 1

        if len(permitted_names) != EXPECTED_SELECTED * 2:
            raise ValueError("allowed kernel-result read surface is not exactly 78 members")

    if len(rows) != EXPECTED_SELECTED or len({r["case_id"] for r in rows}) != EXPECTED_SELECTED:
        raise ValueError("Gate2B1 output population is not exact 39")
    if sum(branch_counts.values()) != EXPECTED_SELECTED or sum(signature_counts.values()) != EXPECTED_SELECTED:
        raise ValueError("Gate2B1 aggregate partition mismatch")

    read_manifest = {
        "schema": READ_MANIFEST_SCHEMA,
        "status": "EXACT_FROZEN_KERNEL_RESULT_READ_SURFACE_VERIFIED",
        "selected_case_count": EXPECTED_SELECTED,
        "kernel_result_member_reads": EXPECTED_SELECTED * 2,
        "zip_member_metadata_count": EXPECTED_BUNDLE_MEMBERS,
        "forbidden_member_content_reads": 0,
        "rows": read_rows,
    }
    ledger_out = {
        "schema": LEDGER_SCHEMA,
        "status": "GATE2B1_FROZEN_KERNEL_NONDEFINITIVE_PROFILE_COMPLETE",
        "selected_case_count": EXPECTED_SELECTED,
        "rows": rows,
    }
    summary = {
        "schema": SUMMARY_SCHEMA,
        "status": "GATE2B1_DESCRIPTIVE_FROZEN_KERNEL_PROFILE_NOT_ROOT_CAUSE",
        "selected_case_count": EXPECTED_SELECTED,
        "top_level_incomplete_branch_counts": _counter_dict(branch_counts, BRANCHES),
        "admission_failure_counts": _counter_dict(admission_counts, ADMISSION_ORDER),
        "admission_signature_counts": _counter_dict(signature_counts),
        "failed_admission_cardinality_counts": {str(i): cardinality_counts.get(str(i), 0) for i in range(7)},
        "pairwise_admission_cofailure_matrix": pairwise,
        "admission_reason_family_counts": {aid: _counter_dict(family_counts[aid]) for aid in ADMISSION_ORDER},
        "raw_false_obligation_counts": _counter_dict(raw_obligation_counts, OBLIGATIONS),
        "directly_shadowed_false_obligation_counts": _counter_dict(shadowed_obligation_counts, OBLIGATIONS),
        "residual_false_obligation_counts": _counter_dict(residual_obligation_counts, OBLIGATIONS),
        "branch_by_admission_signature_counts": {branch: _counter_dict(branch_signature[branch]) for branch in BRANCHES},
        "world_completeness_counts": {"complete": world_presence.get("complete", 0), "incomplete": world_presence.get("incomplete", 0)},
        "violating_pair_presence_counts": {"present": violating_presence.get("present", 0), "absent": violating_presence.get("absent", 0)},
        "witness_presence_counts": {"present": witness_presence.get("present", 0), "absent": witness_presence.get("absent", 0)},
        "violating_pair_count_distribution": _counter_dict(violating_count_distribution),
        "witness_count_distribution": _counter_dict(witness_count_distribution),
        "interpretation_boundary": {
            "profile_is_not_semantic_root_cause": True,
            "admissions_are_parallel_not_ordered": True,
            "cofailure_is_not_causality": True,
            "direct_shadow_is_not_causal_dominance": True,
            "counterfactual_fix_or_coverage_gain_inferred": False,
            "remediation_priority_authorized": False,
            "truth_operator_language_seed_strata_used": False,
        },
    }

    output_dir.mkdir(parents=True, exist_ok=False)
    read_sha = write_json(output_dir / "E2_CANDIDATE58_GATE2B1_KERNEL_RESULT_READ_MANIFEST.json", read_manifest)
    ledger_sha = write_json(output_dir / "E2_CANDIDATE58_GATE2B1_ADMISSION_PROFILE_LEDGER.json", ledger_out)
    summary_sha = write_json(output_dir / "E2_CANDIDATE58_GATE2B1_ADMISSION_PROFILE_SUMMARY.json", summary)
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "status": "FIRST_COMPLETE_GATE2B1_LOGICAL_OUTPUT",
        "inputs": {
            "protocol_sha256": sha256_bytes(protocol_raw),
            "gate2b0_frontier_ledger_sha256": sha256_bytes(ledger_raw),
            "machine_matrix_sha256": sha256_bytes(matrix_raw),
            "machine_bundle_zip_sha256": bundle_raw_sha,
            "frozen_kernel_git_blob": "e91e51397f4cc201452b1a0f80d130265dca2ea0",
        },
        "integrity": {
            "selected_case_count": EXPECTED_SELECTED,
            "kernel_result_member_reads": EXPECTED_SELECTED * 2,
            "zip_member_metadata_count": EXPECTED_BUNDLE_MEMBERS,
            "replay_kernel_result_byte_identity_all_selected": True,
            "machine_matrix_kernel_result_digest_match_all_selected": True,
            "kernel_internal_digest_and_unresolved_bookkeeping_reconstructed_all_selected": True,
            "top_level_branch_partition_total": sum(branch_counts.values()),
        },
        "outputs": {
            "read_manifest_sha256": read_sha,
            "admission_profile_ledger_sha256": ledger_sha,
            "admission_profile_summary_sha256": summary_sha,
        },
        "scientific_firewall": {
            "semantic_engine_rerun": False,
            "kernel_rerun": False,
            "c1_checker_rerun": False,
            "candidate_source_read": False,
            "semantic_slice_content_read": False,
            "adapter_receipt_content_read": False,
            "certificate_content_read": False,
            "c1_report_content_read": False,
            "truth_or_operator_read": False,
            "gate2a_truth_join_input": False,
            "fresh_heldout_read": False,
            "remediation": False,
            "semantic_rule_change": False,
        },
    }
    receipt_sha = write_json(output_dir / "E2_CANDIDATE58_GATE2B1_DIAGNOSTIC_RECEIPT.json", receipt)
    return {
        "status": receipt["status"],
        "selected_case_count": EXPECTED_SELECTED,
        "top_level_incomplete_branch_counts": summary["top_level_incomplete_branch_counts"],
        "admission_failure_counts": summary["admission_failure_counts"],
        "read_manifest_sha256": read_sha,
        "ledger_sha256": ledger_sha,
        "summary_sha256": summary_sha,
        "receipt_sha256": receipt_sha,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--protocol")
    ap.add_argument("--gate2b0-ledger")
    ap.add_argument("--matrix")
    ap.add_argument("--bundle-zip")
    ap.add_argument("--output-dir")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        self_test()
        print(json.dumps({"status": "PASS", "test": "GATE2B1_FROZEN_KERNEL_PROFILE_SELF_TEST"}, sort_keys=True, separators=(",", ":")))
        return 0
    required = [args.protocol, args.gate2b0_ledger, args.matrix, args.bundle_zip, args.output_dir]
    if any(x is None for x in required):
        raise SystemExit("--protocol, --gate2b0-ledger, --matrix, --bundle-zip, and --output-dir are required")
    result = execute(
        Path(args.protocol), Path(args.gate2b0_ledger), Path(args.matrix), Path(args.bundle_zip), Path(args.output_dir)
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
