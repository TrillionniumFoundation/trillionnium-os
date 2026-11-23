"""Q4_0 provenance contracts; no device, download, or model execution."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from verify_ui_venus_runtime import load_pins,verify_q4_0_source_scope
NATIVE=ROOT/"provenance/ui-venus-app-r1/native-worker"

class Q40Scope(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pins=load_pins(ROOT)
        cls.receipt=json.loads((ROOT/"provenance/ui-venus-app-r1/NATIVE-BUILD-RECEIPT.json").read_text())
        cls.generation=json.loads((NATIVE/"SOURCE-GENERATION.json").read_text())
        cls.boundary=json.loads((NATIVE/"SOURCE-BOUNDARY.json").read_text())
        cls.baseline=json.loads((NATIVE/"provenance/ORIGINAL-APP-SOURCE-GENERATION.json").read_text())
        cls.original=(NATIVE/"provenance/ORIGINAL-APP-venus-runtime.inc").read_bytes()
        cls.actual=(NATIVE/"native/venus-runtime.inc").read_bytes()
    def scope(self, receipt=None,generation=None,boundary=None,actual=None):
        return verify_q4_0_source_scope(self.pins,
            self.receipt if receipt is None else receipt,
            self.generation if generation is None else generation,
            self.boundary if boundary is None else boundary,self.baseline,
            self.original,self.actual if actual is None else actual)
    def test_actual_new_build_source_scope(self):
        self.scope()
        self.assertEqual(self.pins["model"]["bytes"],5482832672)
    def test_previous_unchanged_core_claim_rejected(self):
        r=copy.deepcopy(self.receipt);r["original_core_byte_unchanged"]=True
        with self.assertRaises(RuntimeError):self.scope(receipt=r)
    def test_old_shell_17_count_boundary_rejected(self):
        b=copy.deepcopy(self.boundary);b["original_files"]=17;b["original_files_unchanged"]=17
        r=copy.deepcopy(self.receipt);r["source_boundary"]=b
        with self.assertRaises(RuntimeError):self.scope(receipt=r,boundary=b)
    def test_extra_runtime_source_change_rejected(self):
        with self.assertRaises(RuntimeError):self.scope(actual=self.actual+b"\n/* not a model identity */\n")
    def test_non_runtime_native_change_rejected(self):
        g=copy.deepcopy(self.generation);g["files"][0]["sha256"]="0"*64
        with self.assertRaises(RuntimeError):self.scope(generation=g)
    def test_context_budget_change_rejected(self):
        r=copy.deepcopy(self.receipt);g=copy.deepcopy(self.generation)
        r["context_tokens"]=g["context_tokens"]=4096
        with self.assertRaises(RuntimeError):self.scope(receipt=r,generation=g)
    def test_unknown_extra_multimodal_claim_rejected(self):
        r=copy.deepcopy(self.receipt);r["full_multimodal_token_admission_proven"]=True
        with self.assertRaises(RuntimeError):self.scope(receipt=r)
    def test_projector_mismatch_rejected(self):
        r=copy.deepcopy(self.receipt);r["mmproj"]["sha256"]="0"*64
        with self.assertRaises(RuntimeError):self.scope(receipt=r)
    def test_different_actual_builder_rejected(self):
        r=copy.deepcopy(self.receipt);r["build_helper_sha256"]="0"*64
        with self.assertRaises(RuntimeError):self.scope(receipt=r)
    def fixture(self,java=None,pins=None):
        td=tempfile.TemporaryDirectory()
        root=Path(td.name)
        for rel in ("native","src/org/trillionnium/hepta/local","provenance/ui-venus-app-r1"):
            (root/rel).mkdir(parents=True,exist_ok=True)
        (root/"native/ui-venus-runtime-pins.json").write_text(json.dumps(self.pins if pins is None else pins))
        (root/"src/org/trillionnium/hepta/local/UiVenusPins.java").write_text(
            (ROOT/"src/org/trillionnium/hepta/local/UiVenusPins.java").read_text() if java is None else java)
        (root/"provenance/ui-venus-app-r1/sdk-runtime-pins.json").write_bytes(
            (ROOT/"provenance/ui-venus-app-r1/sdk-runtime-pins.json").read_bytes())
        return td,root
    def test_old_java_model_name_rejected(self):
        java=(ROOT/"src/org/trillionnium/hepta/local/UiVenusPins.java").read_text().replace("UI-Venus-2-9B-Q4_0.gguf","UI-Venus-2-9B-Q4_K_M.gguf")
        td,root=self.fixture(java=java)
        with td,self.assertRaises(RuntimeError):load_pins(root)
    def test_old_java_profile_rejected(self):
        java=(ROOT/"src/org/trillionnium/hepta/local/UiVenusPins.java").read_text().replace("ui-venus2-9b-q4_0-f16-mmproj","ui-venus2-9b-q4_k_m-f16-mmproj")
        td,root=self.fixture(java=java)
        with td,self.assertRaises(RuntimeError):load_pins(root)
    def test_unknown_packaging_schema_rejected(self):
        pins=copy.deepcopy(self.pins);pins["schema"]="hepta.ui-venus.app-worker-packaging.unknown"
        td,root=self.fixture(pins=pins)
        with td,self.assertRaises(RuntimeError):load_pins(root)

if __name__=="__main__":unittest.main()
