from __future__ import annotations

from argparse import Namespace
from typing import Any

from e2_mutation_verifier_common import *


def verify(args: Namespace) -> int:

    root = args.repo_root.resolve()
    corpus_path = (args.corpus or (root / CORPUS_REL)).resolve()
    if not corpus_path.exists():
        materializer = root / MATERIALIZER_REL
        corpus_path.parent.mkdir(parents=True, exist_ok=True)
        cp = subprocess.run([sys.executable, "-I", "-S", str(materializer), "--repo-root", str(root), "--output-corpus", str(corpus_path)], capture_output=True, text=True, timeout=60)
        if cp.returncode != 0:
            raise SystemExit("unable to regenerate canonical corpus before verification: " + cp.stderr[-2000:])
    catalog = load_json(root / CATALOG_REL)
    contract = load_json(root / CONTRACT_REL)
    matrix, matrix_raw = load_jsonl(root / MATRIX_REL)
    corpus, corpus_raw = load_jsonl(corpus_path)
    seeds = {s["seed_id"]: s for s in catalog["seeds"]}

    errors: list[str] = []
    runtime_records: list[dict[str, Any]] = []
    locality_records: list[dict[str, Any]] = []

    def require(cond: bool, msg: str) -> None:
        if not cond:
            errors.append(msg)

    require(sha256(matrix_raw) == EXPECTED_MATRIX_SHA256, "expanded matrix digest mismatch")
    require(len(matrix) == 58, "matrix row count != 58")
    require(len(corpus) == 58, "corpus row count != 58")
    require(len({x["cell_id"] for x in corpus}) == 58, "duplicate corpus cell ids")
    require([x["cell_id"] for x in corpus] == [f"Q{i:03d}" for i in range(1, 59)], "corpus cell order mismatch")

    for m, c in zip(matrix, corpus):
        try:
            compare_matrix_row(m, c)
        except AssertionError as exc:
            errors.append(str(exc))
            continue
        cell = c["cell_id"]
        seed = seeds[c["seed_id"]]
        seed_bytes = (root / seed["program_path"]).read_bytes()
        require(sha256(seed_bytes) == seed["program_sha256"], f"{cell}: seed catalog digest mismatch")
        require(c["seed_sha256"] == seed["program_sha256"], f"{cell}: corpus seed digest mismatch")
        require(c.get("truth_source") == "FROZEN_MUTATION_MATRIX_NOT_E2_OUTPUT", f"{cell}: invalid truth source")

        files: list[tuple[str, bytes]] = []
        for f in c["files"]:
            data = base64.b64decode(f["content_b64"])
            require(len(data) == f["bytes"], f"{cell}:{f['path']}: byte count mismatch")
            require(sha256(data) == f["sha256"], f"{cell}:{f['path']}: file digest mismatch")
            files.append((f["path"], data))
        require(bundle_hash(files) == c["bundle_sha256"], f"{cell}: bundle digest mismatch")

        primary_name = Path(seed["program_path"]).name
        primary = dict(files).get(primary_name)
        require(primary is not None, f"{cell}: primary source missing")
        if primary is None:
            continue
        mutant_text = primary.decode("utf-8")
        seed_text = seed_bytes.decode("utf-8")
        require(world_lines(mutant_text) == world_lines(seed_text), f"{cell}: W_MATCH/W_STALE invocation changed")

        limits = contract["locality_policy"]["limits"][c["operator_id"]]
        d = c["primary_diff"]
        loc_ok = (
            d["seed_changed_line_count"] <= limits["max_seed_changed_lines"]
            and d["mutant_changed_line_count"] <= limits["max_mutant_changed_lines"]
            and len(files) - 1 <= limits["max_extra_files"]
        )
        require(loc_ok, f"{cell}: locality ceiling exceeded")
        locality_records.append({
            "cell_id": cell,
            "operator_id": c["operator_id"],
            "seed_changed_lines": d["seed_changed_line_count"],
            "mutant_changed_lines": d["mutant_changed_line_count"],
            "extra_files": len(files) - 1,
            "pass": loc_ok,
        })

        op = c["operator_id"]
        cls = c["operator_class"]
        expected_fault = contract["epistemic_fault_contract"]["expected_fault_by_operator"].get(op)
        if cls == "M_QUESTION_EPISTEMIC_ADVERSARIAL":
            require(c.get("evidence_fault") == expected_fault, f"{cell}: epistemic fault mismatch")
        else:
            require(c.get("evidence_fault") is None, f"{cell}: unexpected evidence fault")

        if op == "A04_ACQUISITION_BUDGET_CEILING":
            require(c.get("evidence_contract", {}).get("acquisition_budget_files") == 1, f"{cell}: A04 budget mismatch")
            require(any(name == "material_edge.go" for name, _ in files), f"{cell}: A04 auxiliary edge missing")
        if op == "A07_INDEPENDENT_CHECKER_DISAGREEMENT_INJECTION":
            require(c.get("evidence_contract", {}).get("checker_disagreement_injected") is True, f"{cell}: A07 injection flag missing")

        try:
            rc, obs, stderr = run_program(seed["language"], files, args.runtime_timeout)
        except (subprocess.TimeoutExpired, Exception) as exc:
            errors.append(f"{cell}: runtime verifier exception {type(exc).__name__}:{exc}")
            runtime_records.append({"cell_id": cell, "pass": False, "error": repr(exc)})
            continue

        if op == "A01_MATERIAL_PARSE_FAILURE":
            ok = rc != 0 and obs is None
            require(ok, f"{cell}: A01 did not fail before semantic execution")
            runtime_records.append({"cell_id": cell, "returncode": rc, "observation": obs, "expected_relation": "PARSE_OR_COMPILE_FAIL", "pass": ok})
            continue

        ok = rc == 0 and isinstance(obs, dict)
        if ok:
            baseline = seed["baseline_expected_observation"]
            if cls == "M_PLUS_SEMANTIC_LOSS":
                applied = {"outcome": "WRITE_APPLIED", "effect": True}
                ok = obs.get("W_MATCH") == applied and obs.get("W_STALE") == applied
                relation = "EXPLICIT_TARGET_COLLAPSE_TO_APPLIED"
            else:
                ok = obs == baseline
                relation = "EXACT_BASELINE_INVARIANCE"
        else:
            relation = "RUNTIME_FAILURE"
        require(ok, f"{cell}: runtime relation failed ({relation}); rc={rc}; obs={obs}; stderr={stderr}")
        runtime_records.append({"cell_id": cell, "returncode": rc, "observation": obs, "expected_relation": relation, "pass": ok})

    replay = {
        "requested": args.replay_materializer,
        "corpus_bytes_identical": None,
        "emitted_tree_digest_identical": None,
        "replay_corpus_sha256": None,
        "emitted_tree_sha256": None,
    }
    if args.replay_materializer:
        materializer = root / MATERIALIZER_REL
        with tempfile.TemporaryDirectory(prefix="risu-e2-replay-a-") as a_s, tempfile.TemporaryDirectory(prefix="risu-e2-replay-b-") as b_s:
            a = Path(a_s); b = Path(b_s)
            a_c = a / "corpus.jsonl"; b_c = b / "corpus.jsonl"
            a_e = a / "emit"; b_e = b / "emit"
            commands = [
                [sys.executable, "-I", "-S", str(materializer), "--repo-root", str(root), "--output-corpus", str(a_c), "--emit-dir", str(a_e)],
                [sys.executable, "-I", "-S", str(materializer), "--repo-root", str(root), "--output-corpus", str(b_c), "--emit-dir", str(b_e)],
            ]
            cps = [subprocess.run(cmd, capture_output=True, text=True, timeout=60) for cmd in commands]
            require(all(cp.returncode == 0 for cp in cps), "materializer deterministic replay invocation failed")
            if all(cp.returncode == 0 for cp in cps):
                a_raw, b_raw = a_c.read_bytes(), b_c.read_bytes()
                replay["corpus_bytes_identical"] = a_raw == b_raw == corpus_raw
                replay["replay_corpus_sha256"] = sha256(a_raw)
                ta, tb = tree_digest(a_e), tree_digest(b_e)
                replay["emitted_tree_digest_identical"] = ta == tb
                replay["emitted_tree_sha256"] = ta
                require(replay["corpus_bytes_identical"], "materializer corpus replay differs from canonical corpus")
                require(replay["emitted_tree_digest_identical"], "materializer emitted tree replay is nondeterministic")

    class_counts: dict[str, int] = {}
    for row in corpus:
        class_counts[row["operator_class"]] = class_counts.get(row["operator_class"], 0) + 1

    receipt = {
        "schema": "risu.diff-e2-mutation-materialization-verification-receipt/v0.1",
        "status": "PASS" if not errors else "FAIL",
        "corpus_sha256": sha256(corpus_raw),
        "matrix_sha256": sha256(matrix_raw),
        "cell_count": len(corpus),
        "class_counts": class_counts,
        "bundle_hashes_verified": len(corpus) if not any("bundle digest" in e for e in errors) else None,
        "world_input_invariance_checked_cells": len(locality_records),
        "locality_pass_cells": sum(1 for x in locality_records if x["pass"]),
        "runtime_pass_cells": sum(1 for x in runtime_records if x.get("pass")),
        "runtime_records": runtime_records,
        "locality_records": locality_records,
        "deterministic_replay": replay,
        "anti_contamination": {
            "e2_prediction_consumed": False,
            "fresh_target_bytes_consumed": False,
            "real_target_gold_consumed": False,
        },
        "errors": errors,
        "claim_boundary": contract["claim_boundary"],
    }
    receipt_path = args.receipt
    if receipt_path:
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": receipt["status"],
        "cells": receipt["cell_count"],
        "runtime_pass_cells": receipt["runtime_pass_cells"],
        "locality_pass_cells": receipt["locality_pass_cells"],
        "corpus_sha256": receipt["corpus_sha256"],
        "errors": errors,
        "deterministic_replay": replay,
    }, sort_keys=True, separators=(",", ":")))
    return 0 if not errors else 1


