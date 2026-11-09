import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("patch_runtime", ROOT / "patch_runtime.py")
patch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch)


class PatchContract(unittest.TestCase):
    def tree(self, root):
        for name in patch.FILES:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / "tests/upstream" / path.name).read_bytes())

    def test_exact_pinned_patch_and_idempotence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.tree(root)
            first = patch.apply(root)
            self.assertEqual(first, patch.apply(root))
            self.assertEqual((root / "source/core/Pipeline.cpp").read_text().count("if (hepta_mnn_observe)"), 3)
            self.assertEqual((root / "express/Executor.cpp").read_text().count("if (hepta_mnn_runtime)"), 1)
            self.assertEqual((root / "transformers/llm/engine/src/llm.cpp").read_text().count("if (hepta_mnn_input_ids)"), 1)

    def test_changed_source_rejected_before_any_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.tree(root)
            bad = root / "transformers/llm/engine/src/llm.cpp"
            bad.write_bytes(bad.read_bytes()+b"\nchanged\n")
            before = {n:(root/n).read_bytes() for n in patch.FILES}
            with self.assertRaisesRegex(ValueError,"pin mismatch"):
                patch.apply(root)
            self.assertEqual(before,{n:(root/n).read_bytes() for n in patch.FILES})

    def test_tampered_patched_source_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.tree(root)
            patch.apply(root)
            bad=root/"source/core/Pipeline.cpp"
            bad.write_bytes(bad.read_bytes()+b"\nchanged\n")
            with self.assertRaisesRegex(ValueError,"modified source"):
                patch.apply(root)


if __name__ == "__main__":
    unittest.main()
