from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from risu_e2_semantic.adapter_support import (
    WORLDS_SCHEMA, _candidate_role_for_root, _derive_worlds, _execution_signature,
)
from risu_e2_semantic.closed_read_set import ClosedReadSet, sha256_bytes


class BridgeUnitTests(unittest.TestCase):
    def test_world_declaration_rejects_target_rho(self):
        canonical={"seed_id":"S","canonical_signature_digest_sha256":"d","required_binding_slot_roles":{},"effective_guard_form":"DIRECT_CONTROL","effect_polarity":False,"rejection_polarity":True}
        profile={"source_roles":{}}
        worlds={"schema":WORLDS_SCHEMA,"seed_id":"S","canonical_signature_digest_sha256":"d","worlds":[{"id":"w","role_values":{},"kappa":{"outcome":"x"},"rho":{"outcome":"forbidden"}}]}
        with self.assertRaisesRegex(ValueError,"may not supply target rho"):
            _execution_signature(canonical,profile,worlds)

    def test_role_binding_uses_parameter_index_not_spelling(self):
        nodes={"p":{"attrs":{"definition_role":"function_parameter","parameter_index":1,"scope":"renamed_scope"}}}
        roles={"BOUND_VALUE:expected_coordinate":{"status":"RESOLVED","scope_role":"GUARD_ANCHOR_SCOPE","parameter_index":1}}
        self.assertEqual(_candidate_role_for_root(nodes,"p",roles,"renamed_scope"),"BOUND_VALUE:expected_coordinate")
        self.assertIsNone(_candidate_role_for_root(nodes,"p",roles,"different_scope"))

    def test_world_rho_is_derived_from_primary_not_declared(self):
        execsig={"worlds":[
            {"id":"effect","role_values":{"BOUND_VALUE:current_coordinate":0,"BOUND_VALUE:expected_coordinate":0},"kappa":{"outcome":"SUCCESS_EFFECT"}},
            {"id":"reject","role_values":{"BOUND_VALUE:current_coordinate":0,"BOUND_VALUE:expected_coordinate":1},"kappa":{"outcome":"REJECTION_NO_EFFECT"}},
        ]}
        bindings=[
            {"slot_identity":{"operand_index":0},"observed_origins":["BOUND_VALUE:current_coordinate"]},
            {"slot_identity":{"operand_index":1},"observed_origins":["BOUND_VALUE:expected_coordinate"]},
        ]
        paths=[
            {"complete":True,"guard_polarity":"true","events":["ENTRY","GUARD:g","EFFECT:e","SUCCESS:s","EXIT"]},
            {"complete":True,"guard_polarity":"false","events":["ENTRY","GUARD:g","REJECTION:r","EXIT"]},
        ]
        worlds,bad=_derive_worlds(execution_signature=execsig,bindings=bindings,control_paths=paths,operator="EQ",guard_form="DIRECT_CONTROL",guardobs={})
        self.assertEqual(bad,[])
        self.assertEqual(worlds[0]["rho"]["outcome"],"SUCCESS_EFFECT")
        self.assertEqual(worlds[1]["rho"]["outcome"],"REJECTION_NO_EFFECT")

    def test_helper_inversion_changes_effective_branch(self):
        execsig={"worlds":[
            {"id":"w","role_values":{"BOUND_VALUE:current_coordinate":0,"BOUND_VALUE:expected_coordinate":0},"kappa":{"outcome":"REJECTION_NO_EFFECT"}}
        ]}
        bindings=[
            {"slot_identity":{"operand_index":0},"observed_origins":["BOUND_VALUE:current_coordinate"]},
            {"slot_identity":{"operand_index":1},"observed_origins":["BOUND_VALUE:expected_coordinate"]},
        ]
        paths=[
            {"complete":True,"guard_polarity":"false","events":["ENTRY","GUARD:g","REJECTION:r","EXIT"]},
            {"complete":True,"guard_polarity":"true","events":["ENTRY","GUARD:g","EFFECT:e","SUCCESS:s","EXIT"]},
        ]
        worlds,bad=_derive_worlds(execution_signature=execsig,bindings=bindings,control_paths=paths,operator="EQ",guard_form="HELPER_CONTROL",guardobs={"polarity_certificate_status":"PROVED","polarity_to_transported_guard":"INVERTED"})
        self.assertEqual(bad,[])
        self.assertEqual(worlds[0]["rho"]["outcome"],"REJECTION_NO_EFFECT")

    def test_closed_read_set_blocks_unlisted_and_forbidden_metadata(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/"allowed.json").write_text("{}\n"); (root/"other.json").write_text("{}\n")
            policy={"schema":"risu.e2-closed-runtime-read-policy/v0.1","closed":True,"entries":[{"path":"allowed.json","sha256":sha256_bytes((root/"allowed.json").read_bytes()),"purpose":"x","role":"x"}]}
            guard=ClosedReadSet(root,policy)
            self.assertEqual(guard.read_bytes("allowed.json",purpose="x"),b"{}\n")
            with self.assertRaises(PermissionError): guard.read_bytes("other.json")
            bad={"schema":"risu.e2-closed-runtime-read-policy/v0.1","closed":True,"entries":[{"path":"allowed.json","sha256":sha256_bytes((root/"allowed.json").read_bytes()),"purpose":"x","role":"x","expected_truth":"bad"}]}
            with self.assertRaisesRegex(ValueError,"forbidden semantic metadata"):
                ClosedReadSet(root,bad)

    def test_world_schema_minimal_has_no_rho(self):
        doc={"schema":WORLDS_SCHEMA,"seed_id":"S","canonical_signature_digest_sha256":"d","worlds":[{"id":"w","role_values":{"x":1},"kappa":{"outcome":"x"}}]}
        self.assertNotIn("rho",json.dumps(doc))


if __name__=="__main__": unittest.main()
