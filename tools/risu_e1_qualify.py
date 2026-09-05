#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, tempfile
from pathlib import Path
from risu_e1.engine import build_outputs, canonical_bytes
from risu_e1.acquisition import round0_select, dependency_tokens_from_text, expansion_select

IDENTITY={"engine_identity_digest":"qualification-e1"}
def h(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def mkpacket(td:Path,lang:str,src:str,run_id:str)->Path:
    p=td/run_id
    ext="go" if lang=="go" else "py"
    f=p/"evidence"/f"case.{ext}"
    f.parent.mkdir(parents=True)
    raw=src.encode()
    f.write_bytes(raw)
    root={"schema":"risu.diff-e0-machine-input/v0.1","run_id":run_id,"unit_id":"synthetic-e1-qualification","target_revision":"synthetic",
          "screened_operation":"tool update --resource-version","surface":{"name":"tool update","arguments":["resource-version"]},
          "evidence_files":[{"path":f.relative_to(p).as_posix(),"sha256":h(raw),"kind":"TARGET_TEXT","language":lang}]}
    (p/"MACHINE_INPUT.json").write_bytes(canonical_bytes(root))
    return p

CASES=[
("py-preserved","python","def update(resource_version,current_version,c):\n if resource_version == current_version:\n  c.update()\n  return None\n else:\n  raise RuntimeError('stale')\n","E1_PREDICTED_PRESERVATION_EVIDENCE"),
("go-preserved","go","package x\nimport \"errors\"\ntype C interface{Update()error}\nfunc update(resourceVersion,currentVersion string,c C)error{\n if resourceVersion==currentVersion { c.Update(); return nil } else { return errors.New(\"stale\") }\n}\n","E1_PREDICTED_PRESERVATION_EVIDENCE"),
("py-helper","python","def apply(expected_version,current_version,c):\n observed=expected_version\n if observed==current_version:\n  c.update();return None\n else: raise RuntimeError('stale')\ndef entry(resource_version,current_version,c):\n expected_version=resource_version\n return apply(expected_version,current_version,c)\n","E1_PREDICTED_PRESERVATION_EVIDENCE"),
("py-regression","python","def update(resource_version,c):\n resource_version=None\n c.update()\n","E1_PREDICTED_REGRESSION_WITNESS"),
("go-regression","go","package x\ntype C interface{Update()error}\nfunc update(resourceVersion string,c C)error{\n resourceVersion=\"\"\n return c.Update()\n}\n","E1_PREDICTED_REGRESSION_WITNESS"),
("py-absence","python","def update(resource_version,c):\n c.update()\n","E1_PREDICTED_ASSURANCE_INCOMPLETE"),
("py-name-only","python","def f():\n resource_version='v1';current_version='v1';return resource_version\n","E1_PREDICTED_ASSURANCE_INCOMPLETE"),
("go-name-only","go","package x\nfunc f()string{resourceVersion:=\"v1\";currentVersion:=\"v1\";_ = currentVersion;return resourceVersion}\n","E1_PREDICTED_ASSURANCE_INCOMPLETE"),
("py-unrelated-guard","python","def update(resource_version,current_version,c,x,y):\n if x==y:c.update()\n if resource_version==current_version:return True\n return False\n","E1_PREDICTED_ASSURANCE_INCOMPLETE"),
("py-cross-scope","python","def unrelated(resource_version,current_version):\n if resource_version==current_version:return True\n return False\ndef update(resource_version,c):\n c.update()\n","E1_PREDICTED_ASSURANCE_INCOMPLETE"),
("py-ambiguous","python","def update(resource_version,current_version,shadow_version,c):\n if resource_version==current_version:x=shadow_version\n c.update()\n","E1_PREDICTED_ASSURANCE_INCOMPLETE"),
]

def main()->int:
    rows=[]
    with tempfile.TemporaryDirectory() as d:
        td=Path(d)
        for cid,lang,src,expected in CASES:
            out=build_outputs(mkpacket(td,lang,src,cid),IDENTITY)
            pred=json.loads(out["E1_PREDICTION.json"])["prediction"]
            ok=pred==expected
            rows.append({"case":cid,"expected":expected,"actual":pred,"pass":ok})
            if not ok:
                raise SystemExit(f"{cid}: expected {expected}, got {pred}")
    tree=["pkg/cmd/update/update.go","pkg/random/a.go","docs/guide.md","pkg/version/resource_version.go"]
    a=round0_select(tree,"tool update --resource-version",["resource-version"])
    if "pkg/random/a.go" in [x["path"] for x in a]:
        raise SystemExit("round0 filler admitted")
    ar=round0_select(list(reversed(tree)),"tool update --resource-version",["resource-version"])
    if [x["path"] for x in a]!=[x["path"] for x in ar]:
        raise SystemExit("round0 order nondeterminism")
    deps=dependency_tokens_from_text('import "client/transport"\nfunc x(){transport.Update()}',"go")
    ex=expansion_select(["pkg/client/transport.go","pkg/random/other.go"],deps,[],1,8)
    if [x["path"] for x in ex]!=["pkg/client/transport.go"]:
        raise SystemExit("expansion precision failure")
    metrics={"cases":len(rows),"case_passes":sum(x["pass"] for x in rows),"false_regression_from_absence":0,
             "authority_upgrade_from_name_only":0,"cross_scope_false_support":0,"acquisition_filler_admitted":0,
             "round0_order_invariant":True,"status":"PASS"}
    print(json.dumps({"metrics":metrics,"rows":rows},sort_keys=True))
    return 0
if __name__=="__main__":
    raise SystemExit(main())
