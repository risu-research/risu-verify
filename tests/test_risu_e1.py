from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from risu_e1.acquisition import round0_select, dependency_tokens_from_text, expansion_select
from risu_e1.engine import build_outputs, canonical_bytes

def sha(b: bytes)->str: return hashlib.sha256(b).hexdigest()

def packet(td: Path, *, language: str, source: str, run_id: str="synthetic") -> Path:
    p=td/"packet"
    ev=p/"evidence"/f"case.{ 'go' if language=='go' else 'py'}"
    ev.parent.mkdir(parents=True)
    raw=source.encode()
    ev.write_bytes(raw)
    root={
        "schema":"risu.diff-e0-machine-input/v0.1",
        "run_id":run_id,
        "unit_id":"synthetic-e1",
        "target_revision":"synthetic-rev",
        "screened_operation":"tool update --resource-version",
        "surface":{"name":"tool update","arguments":["resource-version"]},
        "evidence_files":[{"path":ev.relative_to(p).as_posix(),"sha256":sha(raw),"kind":"TARGET_TEXT","language":language}],
    }
    (p/"MACHINE_INPUT.json").write_bytes(canonical_bytes(root))
    return p

IDENTITY={"engine_identity_digest":"synthetic-e1-identity"}

class E1Tests(unittest.TestCase):
    def _prediction(self, language: str, source: str):
        with tempfile.TemporaryDirectory() as d:
            outputs=build_outputs(packet(Path(d),language=language,source=source),IDENTITY)
            pred=json.loads(outputs["E1_PREDICTION.json"])
            roles=json.loads(outputs["MATERIAL_ROLE_PROOF.json"])
            return pred,roles,outputs

    def test_python_preservation_structural_support(self):
        src='''def update(resource_version, current_version, client):\n    if resource_version == current_version:\n        client.update()\n        return None\n    else:\n        raise RuntimeError("stale")\n'''
        pred,roles,_=self._prediction("python",src)
        self.assertEqual(pred["prediction"],"E1_PREDICTED_PRESERVATION_EVIDENCE")
        self.assertTrue(all(v["status"]=="STRUCTURALLY_SUPPORTED" for v in roles["roles"].values()))
        self.assertFalse(pred["canonical_scientific_authority"])

    def test_go_preservation_structural_support(self):
        src='''package x\nimport "errors"\ntype Client interface{ Update() error }\nfunc update(resourceVersion string, currentVersion string, client Client) error {\n if resourceVersion == currentVersion {\n  client.Update()\n  return nil\n } else {\n  return errors.New("stale")\n }\n}\n'''
        pred,roles,_=self._prediction("go",src)
        self.assertEqual(pred["prediction"],"E1_PREDICTED_PRESERVATION_EVIDENCE")
        self.assertTrue(all(v["status"]=="STRUCTURALLY_SUPPORTED" for v in roles["roles"].values()))

    def test_positive_regression_requires_overwrite_witness(self):
        src='''def update(resource_version, client):\n    resource_version = None\n    client.update()\n'''
        pred,roles,_=self._prediction("python",src)
        self.assertEqual(pred["prediction"],"E1_PREDICTED_REGRESSION_WITNESS")
        self.assertIsNotNone(roles["regression_witness"])

    def test_absence_never_becomes_regression(self):
        src='''def update(resource_version, client):\n    client.update()\n'''
        pred,_,_=self._prediction("python",src)
        self.assertEqual(pred["prediction"],"E1_PREDICTED_ASSURANCE_INCOMPLETE")

    def test_name_only_never_upgrades_authority(self):
        src='''def f():\n    resource_version = "v1"\n    current_version = "v1"\n    return resource_version\n'''
        pred,roles,_=self._prediction("python",src)
        self.assertEqual(pred["prediction"],"E1_PREDICTED_ASSURANCE_INCOMPLETE")
        self.assertFalse(roles["consequence_authority"])

    def test_ambiguous_dual_coordinates_abstain(self):
        src='''def update(resource_version, current_version, shadow_version, client):\n    if resource_version == current_version:\n        x = shadow_version\n    client.update()\n'''
        pred,_,_=self._prediction("python",src)
        self.assertEqual(pred["prediction"],"E1_PREDICTED_ASSURANCE_INCOMPLETE")

    def test_round0_has_no_filler(self):
        tree=["pkg/cmd/update/update.go","pkg/random/a.go","docs/guide.md","pkg/version/resource_version.go"]
        rows=round0_select(tree,"tool update --resource-version",["resource-version"])
        paths=[r["path"] for r in rows]
        self.assertIn("pkg/cmd/update/update.go",paths)
        self.assertIn("pkg/version/resource_version.go",paths)
        self.assertNotIn("pkg/random/a.go",paths)
        self.assertLessEqual(len(rows),4)

    def test_dependency_expansion_positive_only(self):
        deps=dependency_tokens_from_text('import "client/transport"\\nfunc x(){ transport.Update() }',"go")
        rows=expansion_select(["pkg/client/transport.go","pkg/random/other.go"],deps,[],1,8)
        self.assertEqual([r["path"] for r in rows],["pkg/client/transport.go"])

    def test_deterministic_outputs_same_packet(self):
        with tempfile.TemporaryDirectory() as d:
            p=packet(Path(d),language="python",source='''def update(resource_version,current_version,c):\n if resource_version == current_version:\n  c.update()\n else:\n  raise Exception("stale")\n''')
            a=build_outputs(p,IDENTITY)
            b=build_outputs(p,IDENTITY)
            self.assertEqual(a,b)

    def test_no_unit003_special_cases_in_e1_code(self):
        root=Path(__file__).resolve().parents[1]
        texts=[]
        for rel in ["risu_e1/acquisition.py","risu_e1/extractor.py","risu_e1/engine.py","tools/risu_e1_go_extract.go"]:
            texts.append((root/rel).read_text().lower())
        joined="\n".join(texts)
        self.assertNotIn("kubectl",joined)
        self.assertNotIn("annotate",joined)

    def test_cross_scope_same_name_does_not_create_false_support(self):
        src='''def unrelated(resource_version, current_version):
    if resource_version == current_version:
        return True
    return False

def update(resource_version, client):
    client.update()
'''
        pred,_,_=self._prediction("python",src)
        self.assertEqual(pred["prediction"],"E1_PREDICTED_ASSURANCE_INCOMPLETE")

    def test_explicit_helper_call_parameter_flow_is_supported(self):
        src='''def apply(expected_version, current_version, client):
    observed = expected_version
    if observed == current_version:
        client.update()
        return None
    else:
        raise RuntimeError("stale")

def entry(resource_version, current_version, client):
    expected_version = resource_version
    return apply(expected_version, current_version, client)
'''
        pred,roles,_=self._prediction("python",src)
        self.assertEqual(pred["prediction"],"E1_PREDICTED_PRESERVATION_EVIDENCE")
        self.assertTrue(all(v["status"]=="STRUCTURALLY_SUPPORTED" for v in roles["roles"].values()))

    def test_unrelated_comparison_does_not_guard_effect(self):
        src='''def update(resource_version, current_version, client, x, y):
    if x == y:
        client.update()
    if resource_version == current_version:
        return True
    return False
'''
        pred,_,_=self._prediction("python",src)
        self.assertEqual(pred["prediction"],"E1_PREDICTED_ASSURANCE_INCOMPLETE")


if __name__=="__main__":
    unittest.main()
