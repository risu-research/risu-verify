#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import risu_verify as rv
from vbe_compile import compile_instance

PLAN_PATH = ROOT / "experiments" / "unit002-m" / "PLAN.json"
FREEZE_PATH = ROOT / "experiments" / "unit002-m" / "FREEZE.json"
RESULT_SCHEMA = "risu.unit002-m-mutation-control-result/v0.1alpha1"
EXPECTED_POSITIVE = {
    "P_MECHANISM_ALWAYS_ACCEPTS",
    "P_DISCRIMINATOR_COLLAPSE",
    "P_INTERPRETER_ALWAYS_SUCCESS",
}
EXPECTED_NEGATIVE = {
    "N_CASE_METADATA_ONLY",
    "N_PROVENANCE_EDGE_ORDER_ONLY",
    "N_DERIVATION_FACT_ORDER_ONLY",
}


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git_bytes(ref: str, path: str) -> bytes:
    p = subprocess.run(
        ["git", "show", f"{ref}:{path}"],
        cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if p.returncode != 0:
        raise RuntimeError(
            f"cannot read frozen plan at {ref}:{path}: "
            + p.stderr.decode("utf-8", errors="replace")
        )
    return p.stdout


def verify_freeze() -> tuple[dict, dict, dict]:
    plan = read_json(PLAN_PATH)
    freeze = read_json(FREEZE_PATH)
    if plan.get("schema") != "risu.unit002-m-mutation-control-plan/v0.1alpha1":
        raise RuntimeError("unsupported Unit 002-M PLAN schema")
    if freeze.get("schema") != "risu.unit002-m-freeze/v0.1alpha1":
        raise RuntimeError("unsupported Unit 002-M FREEZE schema")
    if plan.get("status") != "PREDECLARED_BEFORE_MUTATION_EXECUTION":
        raise RuntimeError("PLAN is not predeclared")
    if freeze.get("status") != "FROZEN_BEFORE_MUTATION_EXECUTION":
        raise RuntimeError("FREEZE is not pre-execution")
    pmeta = freeze.get("plan") or {}
    if pmeta.get("path") != "experiments/unit002-m/PLAN.json":
        raise RuntimeError("freeze plan path mismatch")
    freeze_commit = str(pmeta.get("freeze_commit") or "")
    if not freeze_commit:
        raise RuntimeError("freeze commit missing")
    frozen = git_bytes(freeze_commit, str(pmeta["path"]))
    current = PLAN_PATH.read_bytes()
    if frozen != current:
        raise RuntimeError("PLAN bytes changed after freeze")
    hash_proc = subprocess.run(
        ["git", "hash-object", str(PLAN_PATH)], cwd=str(ROOT),
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if hash_proc.returncode != 0:
        raise RuntimeError("cannot compute PLAN git object identity")
    current_blob = hash_proc.stdout.strip()
    if current_blob != pmeta.get("git_blob_sha1"):
        raise RuntimeError("PLAN git blob identity differs from frozen identity")
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", freeze_commit, "HEAD"], cwd=str(ROOT)
    if ancestor.returncode != 0:
        raise RuntimeError("PLAN freeze commit is not an ancestor of current execution")

    pos = {x.get("operator_id") for x in plan.get("positive_semantic_loss_operators") or []}
    neg = {x.get("operator_id") for x in plan.get("negative_nonsemantic_operators") or []}
    if pos != EXPECTED_POSITIVE or neg != EXPECTED_NEGATIVE:
        raise RuntimeError(f"frozen operator set mismatch: positive={sorted(pos)} negative={sorted(neg)}")
    if len(plan.get("seeds") or []) != 2:
        raise RuntimeError("frozen plan must contain exactly two seeds")
    matrix = plan.get("matrix") or {}
    expected_matrix = {
        "seed_count": 2,
        "positive_operator_count": 3,
        "negative_operator_count": 3,
        "mutants_per_class": 6,
        "mutants_total": 12,
        "repetitions_per_mutant": 2,
        "mutant_verifications_total": 24,
        "baseline_verifications_per_seed": 2,
        "baseline_verifications_total": 4,
    }
    if any(matrix.get(k) != v for k, v in expected_matrix.items()):
        raise RuntimeError("frozen matrix cardinalities differ from executor contract")
    attest = freeze.get("preexecution_attestations") or {}
    if any(attest.get(k) is not False for k in (
        "unit002_m_mutation_runner_executed_before_freeze",
        "unit002_m_detector_outputs_observed_before_freeze",
        "mutation_matrix_selected_from_unit002_m_outputs",
        "unit002_r_target_selected_from_unit002_m_outputs",
    )):
        raise RuntimeError("freeze pre-execution attestations are not all false")
    return plan, freeze, {
        "status": "PASS",
        "plan_freeze_commit": freeze_commit,
        "plan_git_blob_sha1": current_blob,
        "plan_sha256": hashlib.sha256(current).hexdigest(),
    }


def semantic_view(summary: dict) -> dict:
    s = summary["structural"]
    e = summary["exact_realization"]
    worlds = []
    for row in summary.get("worlds") or []:
        worlds.append({
            "world": row.get("world"),
            "coordinates": row.get("coordinates"),
            "required_consequence": row.get("required_consequence"),
            "projected_effect": row.get("projected_effect"),
            "matches": row.get("matches"),
        })
    return {
        "product_status": summary.get("product_status"),
        "structural": {
            "C": s.get("C"),
            "D": s.get("D"),
            "O": s.get("O"),
            "coverage_complete": s.get("coverage_complete"),
        },
        "exact_realization": {
            "status": e.get("status"),
            "failure_mode": e.get("failure_mode"),
        },
        "worlds": worlds,
    }


def proof_view(summary: dict) -> dict:
    return {
        "certificate_sha256": (summary.get("certificate") or {}).get("sha256"),
        "proof_digest": (summary.get("commitments") or {}).get("proof_digest"),
        "adapter_digest": (summary.get("commitments") or {}).get("adapter_digest"),
        "normalized_bundle_digest": (summary.get("commitments") or {}).get("normalized_bundle_digest"),
    }


def diff_paths(before: Any, after: Any, prefix: str = "") -> set[str]:
    if type(before) is not type(after):
        return {prefix or "$"}
    if isinstance(before, dict):
        out: set[str] = set()
        for key in sorted(set(before) | set(after)):
            p = f"{prefix}.{key}" if prefix else str(key)
            if key not in before or key not in after:
                out.add(p)
            else:
                out |= diff_paths(before[key], after[key], p)
        return out
    if isinstance(before, list):
        return set() if before == after else {prefix or "$"}
    return set() if before == after else {prefix or "$"}


def subset_dict(actual: dict, expected: dict) -> bool:
    return all(actual.get(k) == v for k, v in expected.items())


def mismatch_at_coordinate(summary: dict, expected_coordinate: dict) -> bool:
    witness_id = summary.get("minimal_witness_world")
    for row in summary.get("worlds") or []:
        if row.get("world") == witness_id and row.get("matches") is False:
            return subset_dict(row.get("coordinates") or {}, expected_coordinate)
    return False


def stale_mismatch(summary: dict, expected_coordinate: dict) -> bool:
    for row in summary.get("worlds") or []:
        if subset_dict(row.get("coordinates") or {}, expected_coordinate):
            return row.get("matches") is False and row.get("projected_effect") != row.get("required_consequence")
    return False


def apply_operator(case_dir: Path, seed_instance: dict, operator_id: str) -> dict:
    adapter_path = case_dir / "assurance" / "adapter.json"
    case_path = case_dir / "case.json"
    source_path = case_dir / "assurance" / "source-contract.json"
    adapter_before = read_json(adapter_path)
    case_before = read_json(case_path)
    source_sha_before = sha256_file(source_path)
    adapter = copy.deepcopy(adapter_before)
    case = copy.deepcopy(case_before)

    expected_adapter_diffs: set[str] = set()
    expected_case_diffs: set[str] = set()
    t = seed_instance["target"]
    success = seed_instance["source"]["success_consequence"]

    if operator_id == "P_MECHANISM_ALWAYS_ACCEPTS":
        adapter["target"]["derivation"]["program"]["mechanism"]["expr"] = {
            "op": "literal", "value": {"kind": t["native_accept_kind"]}
        }
        expected_adapter_diffs = {"target.derivation.program.mechanism.expr"}
    elif operator_id == "P_DISCRIMINATOR_COLLAPSE":
        adapter["target"]["derivation"]["program"]["discriminator"]["expr"] = {
            "op": "literal", "value": "COLLAPSED"
        }
        expected_adapter_diffs = {"target.derivation.program.discriminator.expr"}
    elif operator_id == "P_INTERPRETER_ALWAYS_SUCCESS":
        adapter["target"]["derivation"]["program"]["interpreter"]["expr"] = {
            "op": "literal", "value": {"label": success, "space": "C"}
        }
        expected_adapter_diffs = {"target.derivation.program.interpreter.expr"}
    elif operator_id == "N_CASE_METADATA_ONLY":
        case["title"] = str(case.get("title") or "") + " — Unit 002-M metadata-only control"
        display = case.setdefault("display", {})
        display["unit002_m_control"] = "NON_SEMANTIC_METADATA_ONLY"
        expected_case_diffs = {"title", "display.unit002_m_control"}
    elif operator_id == "N_PROVENANCE_EDGE_ORDER_ONLY":
        edges = adapter["provenance"]["edges"]
        adapter["provenance"]["edges"] = list(reversed(edges))
        expected_adapter_diffs = {"provenance.edges"}
    elif operator_id == "N_DERIVATION_FACT_ORDER_ONLY":
        facts = adapter["target"]["derivation"]["facts"]
        adapter["target"]["derivation"]["facts"] = list(reversed(facts))
        expected_adapter_diffs = {"target.derivation.facts"}
    else:
        raise RuntimeError(f"unknown frozen operator: {operator_id}")

    write_json(adapter_path, adapter)
    write_json(case_path, case)
    adapter_after = read_json(adapter_path)
    case_after = read_json(case_path)
    actual_adapter_diffs = diff_paths(adapter_before, adapter_after)
    actual_case_diffs = diff_paths(case_before, case_after)
    source_sha_after = sha256_file(source_path)
    locality_pass = (
        actual_adapter_diffs == expected_adapter_diffs
        and actual_case_diffs == expected_case_diffs
        and source_sha_after == source_sha_before
    )
    return {
        "operator_id": operator_id,
        "adapter_diff_paths": sorted(actual_adapter_diffs),
        "case_diff_paths": sorted(actual_case_diffs),
        "expected_adapter_diff_paths": sorted(expected_adapter_diffs),
        "expected_case_diff_paths": sorted(expected_case_diffs),
        "source_contract_sha256_before": source_sha_before,
        "source_contract_sha256_after": source_sha_after,
        "source_contract_invariant": source_sha_before == source_sha_after,
        "mutation_locality_pass": locality_pass,
    }


def verify_case(case_dir: Path, output_dir: Path) -> tuple[dict, dict, float]:
    if output_dir.exists():
        shutil.rmtree(output_dir)
    started = time.perf_counter()
    summary, out = rv.perform_verify(str(case_dir), str(output_dir))
    elapsed = time.perf_counter() - started
    return summary, {
        "report_json_sha256": sha256_file(out / "report.json"),
        "certificate_sha256": (summary.get("certificate") or {}).get("sha256"),
        "proof_view": proof_view(summary),
    }, elapsed


def check_baseline(summary: dict, expected: dict) -> list[str]:
    errors = []
    if summary.get("product_status") != expected["product_status"]:
        errors.append(f"product_status={summary.get('product_status')}")
    s = summary.get("structural") or {}
    for key, val in expected["structural"].items():
        if s.get(key) != val:
            errors.append(f"structural.{key}={s.get(key)}")
    if (summary.get("exact_realization") or {}).get("status") != expected["exact_status"]:
        errors.append(f"exact_status={(summary.get('exact_realization') or {}).get('status')}")
    return errors


def check_positive(operator_id: str, summary: dict, seed_expected: dict) -> list[str]:
    errors = []
    if operator_id in {"P_MECHANISM_ALWAYS_ACCEPTS", "P_INTERPRETER_ALWAYS_SUCCESS"}:
        if summary.get("product_status") != "CONSEQUENCE_REGRESSION":
            errors.append(f"expected CONSEQUENCE_REGRESSION got {summary.get('product_status')}")
        if (summary.get("exact_realization") or {}).get("status") != "REALIZATION_CONTRADICTED":
            errors.append("expected REALIZATION_CONTRADICTED")
        coord = seed_expected["stale_witness_coordinate"]
        if not mismatch_at_coordinate(summary, coord):
            errors.append(f"minimal witness not localized at stale coordinate {coord}")
        if not stale_mismatch(summary, coord):
            errors.append(f"stale coordinate {coord} did not expose required/projected mismatch")
    elif operator_id == "P_DISCRIMINATOR_COLLAPSE":
        d = (summary.get("structural") or {}).get("D")
        if d == "D1":
            errors.append("discriminator collapse incorrectly retained D1")
        if summary.get("product_status") not in {"INCOMPLETE_ASSURANCE", "CONSEQUENCE_REGRESSION"}:
            errors.append(f"unexpected product_status={summary.get('product_status')}")
    else:
        errors.append("unknown positive operator")
    return errors


def check_negative(summary: dict, baseline_view: dict) -> list[str]:
    current = semantic_view(summary)
    if current != baseline_view:
        return ["semantic view differs from baseline"]
    return []


def render_markdown(result: dict) -> str:
    lines = [
        "# Unit 002-M — Paired Mutation Control",
        "",
        f"**Status:** `{result['status']}`  ",
        f"**Sensitivity:** `{result['metrics']['positive_sensitivity']['passed']}/{result['metrics']['positive_sensitivity']['total']}`  ",
        f"**Specificity:** `{result['metrics']['negative_specificity']['passed']}/{result['metrics']['negative_specificity']['total']}`  ",
        f"**Witness localization:** `{result['metrics']['regression_witness_localization']['passed']}/{result['metrics']['regression_witness_localization']['total']}`  ",
        f"**Repeatability:** `{result['metrics']['deterministic_repeatability']['passed']}/{result['metrics']['deterministic_repeatability']['total']}`",
        "",
        "This is a synthetic detector-control result, not a real-target safety or prevalence claim.",
        "",
        "| Seed | Operator | Class | Result | Repeatable | Locality |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for cell in result["cells"]:
        lines.append(
            f"| {cell['seed_id']} | {cell['operator_id']} | {cell['class']} | "
            f"{'PASS' if cell['pass'] else 'FAIL'} | {'yes' if cell['repeatable'] else 'no'} | "
            f"{'yes' if cell['mutation_locality_pass'] else 'no'} |"
        )
    lines += [
        "",
        "## Boundary",
        "",
        "The mutation matrix and scoring predicates were frozen before this executor existed or any Unit 002-M detector output was observed. A failure is retained as a falsification of this control version; failed cells are not deleted or redefined after observation.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Execute the frozen Unit 002-M paired mutation control")
    ap.add_argument("--output", default=".risu/unit002-m")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    try:
        plan, freeze, freeze_check = verify_freeze()
        materialize = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "materialize_case_bundles.py")],
            cwd=str(ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        if materialize.returncode != 0:
            raise RuntimeError("case-bundle materialization failed:\n" + (materialize.stdout or ""))

        work = Path(args.output)
        if not work.is_absolute():
            work = (ROOT / work).resolve()
        if work.exists():
            shutil.rmtree(work)
        work.mkdir(parents=True)

        cells = []
        baselines = []
        baseline_by_seed: dict[str, dict] = {}
        baseline_pass_count = 0
        runtime_seconds = 0.0

        for seed in plan["seeds"]:
            seed_id = seed["seed_id"]
            instance_path = ROOT / seed["instance_path"]
            instance = read_json(instance_path)
            if instance.get("status") != "CALIBRATION_ONLY":
                raise RuntimeError(f"Unit002-M seed must remain CALIBRATION_ONLY: {seed_id}")
            seed_root = work / "seeds" / seed_id
            baseline_case = seed_root / "baseline-case"
            compile_instance(instance_path, baseline_case)
            source_sha = sha256_file(baseline_case / "assurance" / "source-contract.json")
            baseline_runs = []
            for rep in (1, 2):
                summary, artifacts, elapsed = verify_case(
                    baseline_case, seed_root / "baseline-runs" / f"repeat-{rep}"
                )
                runtime_seconds += elapsed
                errors = check_baseline(summary, seed["expected_baseline"])
                baseline_runs.append({
                    "repeat": rep,
                    "pass": not errors,
                    "errors": errors,
                    "semantic_view": semantic_view(summary),
                    "artifacts": artifacts,
                    "elapsed_seconds": round(elapsed, 6),
                })
            repeat_equal = baseline_runs[0]["semantic_view"] == baseline_runs[1]["semantic_view"]
            baseline_pass = all(x["pass"] for x in baseline_runs) and repeat_equal
            baseline_pass_count += int(baseline_pass)
            baseline_view = baseline_runs[0]["semantic_view"]
            baseline_by_seed[seed_id] = baseline_view
            baselines.append({
                "seed_id": seed_id,
                "pass": baseline_pass,
                "repeatable": repeat_equal,
                "source_contract_sha256": source_sha,
                "runs": baseline_runs,
            })

            operators = [
                *(x["operator_id"] for x in plan["positive_semantic_loss_operators"]),
                *(x["operator_id"] for x in plan["negative_nonsemantic_operators"]),
            ]
            for operator_id in operators:
                klass = "POSITIVE_SEMANTIC_LOSS" if operator_id in EXPECTED_POSITIVE else "NEGATIVE_NONSEMANTIC"
                mutant_case = seed_root / "mutants" / operator_id / "case"
                shutil.copytree(baseline_case, mutant_case)
                mutation = apply_operator(mutant_case, instance, operator_id)
                mutant_runs = []
                for rep in (1, 2):
                    summary, artifacts, elapsed = verify_case(
                        mutant_case,
                        seed_root / "mutants" / operator_id / "runs" / f"repeat-{rep}",
                    )
                    runtime_seconds += elapsed
                    if klass == "POSITIVE_SEMANTIC_LOSS":
                        errors = check_positive(operator_id, summary, seed["expected_baseline"])
                    else:
                        errors = check_negative(summary, baseline_view)
                    mutant_runs.append({
                        "repeat": rep,
                        "pass": not errors,
                        "errors": errors,
                        "semantic_view": semantic_view(summary),
                        "artifacts": artifacts,
                        "minimal_witness_world": summary.get("minimal_witness_world"),
                        "elapsed_seconds": round(elapsed, 6),
                    })
                repeatable = mutant_runs[0]["semantic_view"] == mutant_runs[1]["semantic_view"]
                cell_pass = (
                    baseline_pass
                    and mutation["mutation_locality_pass"]
                    and mutation["source_contract_invariant"]
                    and all(x["pass"] for x in mutant_runs)
                    and repeatable
                )
                cells.append({
                    "seed_id": seed_id,
                    "operator_id": operator_id,
                    "class": klass,
                    "pass": cell_pass,
                    "repeatable": repeatable,
                    "mutation_locality_pass": mutation["mutation_locality_pass"],
                    "source_contract_invariant": mutation["source_contract_invariant"],
                    "mutation": mutation,
                    "runs": mutant_runs,
                })

        positive_cells = [x for x in cells if x["class"] == "POSITIVE_SEMANTIC_LOSS"]
        negative_cells = [x for x in cells if x["class"] == "NEGATIVE_NONSEMANTIC"]
        localization_cells = [
            x for x in positive_cells
            if x["operator_id"] in {"P_MECHANISM_ALWAYS_ACCEPTS", "P_INTERPRETER_ALWAYS_SUCCESS"}
        ]
        discrim_cells = [x for x in positive_cells if x["operator_id"] == "P_DISCRIMINATOR_COLLAPSE"]
        repeat_cells = list(cells)
        locality_cells = list(cells)
        source_cells = list(cells)

        metrics = {
            "baseline_validity": {"passed": baseline_pass_count, "total": 2},
            "positive_sensitivity": {"passed": sum(x["pass"] for x in positive_cells), "total": 6},
            "negative_specificity": {"passed": sum(x["pass"] for x in negative_cells), "total": 6},
            "false_semantic_alarm_count": {"value": sum(not x["pass"] for x in negative_cells), "required": 0},
            "regression_witness_localization": {"passed": sum(x["pass"] for x in localization_cells), "total": 4},
            "discriminator_detection": {"passed": sum(x["pass"] for x in discrim_cells), "total": 2},
            "deterministic_repeatability": {"passed": sum(x["repeatable"] for x in repeat_cells), "total": 12},
            "mutation_locality": {"passed": sum(x["mutation_locality_pass"] for x in locality_cells), "total": 12},
            "source_contract_invariance": {"passed": sum(x["source_contract_invariant"] for x in source_cells), "total": 12},
        }
        promoted = (
            metrics["baseline_validity"]["passed"] == 2
            and metrics["positive_sensitivity"]["passed"] == 6
            and metrics["negative_specificity"]["passed"] == 6
            and metrics["false_semantic_alarm_count"]["value"] == 0
            and metrics["regression_witness_localization"]["passed"] == 4
            and metrics["discriminator_detection"]["passed"] == 2
            and metrics["deterministic_repeatability"]["passed"] == 12
            and metrics["mutation_locality"]["passed"] == 12
            and metrics["source_contract_invariance"]["passed"] == 12
        )
        result = {
            "schema": RESULT_SCHEMA,
            "experiment_id": plan["experiment_id"],
            "status": "PROMOTED" if promoted else "FALSIFIED_OR_NOT_PROMOTED",
            "scientific_role": plan["scientific_role"],
            "freeze_check": freeze_check,
            "infrastructure_baseline": freeze["infrastructure_baseline"],
            "execution": {
                "github_run_id": os.environ.get("GITHUB_RUN_ID"),
                "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
                "github_sha": os.environ.get("GITHUB_SHA"),
                "github_ref": os.environ.get("GITHUB_REF"),
                "runner_file_sha256": sha256_file(Path(__file__)),
                "total_verifier_seconds": round(runtime_seconds, 6),
                "verifier_runs": 28,
            },
            "metrics": metrics,
            "baselines": baselines,
            "cells": cells,
            "promotion_rule_satisfied": promoted,
            "boundary": {
                "real_target_result": false,
                "live_runtime_claim": false,
                "prevalence_claim": false,
                "unit002_r_target_selection_from_result": "PROHIBITED",
            },
        }
        write_json(work / "MATRIX_RESULT.json", result)
        (work / "MATRIX_RESULT.md").write_text(render_markdown(result), encoding="utf-8")
        manifest = {
            "schema": "risu.unit002-m-artifact-manifest/v0.1alpha1",
            "plan_sha256": freeze_check["plan_sha256"],
            "freeze_sha256": sha256_file(FREEZE_PATH),
            "result_sha256": sha256_file(work / "MATRIX_RESULT.json"),
            "result_md_sha256": sha256_file(work / "MATRIX_RESULT.md"),
            "runner_sha256": sha256_file(Path(__file__)),
            "file_count": sum(1 for p in work.rglob("*") if p.is_file()),
        }
        write_json(work / "ARTIFACT_MANIFEST.json", manifest)

        if args.json:
            print(json.dumps({
                "status": result["status"],
                "metrics": metrics,
                "result": str(work / "MATRIX_RESULT.json"),
                "artifact_manifest": str(work / "ARTIFACT_MANIFEST.json"),
            }, indent=2, sort_keys=True))
        else:
            print(f"UNIT 002-M: {result['status']}")
            print(json.dumps(metrics, indent=2, sort_keys=True))
        return 0 if promoted else 1
    except Exception as exc:
        print(f"UNIT 002-M: INVALID EXECUTION: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
