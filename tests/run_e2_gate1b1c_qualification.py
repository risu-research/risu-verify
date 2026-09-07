from __future__ import annotations

import hashlib
import json
import platform
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))

from tests.test_e2_c1_rechecker import GOOD, WRONG, do_recheck, make_cert


def cb(x):
    return (json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()


def one(source):
    sig,protocols,ids,cert=make_cert(source)
    result=do_recheck(cert,source,sig,protocols,ids)
    return {"certificate":cert,"c1":result}


def main():
    stable_a=one(GOOD); stable_b=one(GOOD)
    wrong_a=one(WRONG); wrong_b=one(WRONG)
    assert cb(stable_a)==cb(stable_b), "stable replay not byte-identical"
    assert cb(wrong_a)==cb(wrong_b), "wrong-carrier replay not byte-identical"
    assert stable_a["c1"]["checker_output"]=="VALID_C1"
    assert stable_a["c1"]["machine_prediction"]=="E2_PREDICTED_PRESERVATION_EVIDENCE"
    assert wrong_a["c1"]["checker_output"]=="VALID_C1"
    assert wrong_a["c1"]["machine_prediction"]=="E2_PREDICTED_REGRESSION_WITNESS"
    receipt={
        "schema":"risu.e2-gate1b1c-synthetic-qualification/v0.1",
        "status":"PASS",
        "candidate_58_bytes_read":False,
        "truth_operator_expected_prediction_read":False,
        "synthetic_only":True,
        "runtime":{"implementation":platform.python_implementation(),"python":platform.python_version(),"parser":"python_stdlib_ast"},
        "stable_replay_sha256":hashlib.sha256(cb(stable_a)).hexdigest(),
        "wrong_carrier_replay_sha256":hashlib.sha256(cb(wrong_a)).hexdigest(),
        "stable_prediction":stable_a["c1"]["machine_prediction"],
        "wrong_carrier_prediction":wrong_a["c1"]["machine_prediction"],
        "two_replay_byte_identity":True,
    }
    raw=cb(receipt); Path("gate1b1c-qualification.json").write_bytes(raw)
    print(raw.decode(),end="")

if __name__=="__main__": main()
