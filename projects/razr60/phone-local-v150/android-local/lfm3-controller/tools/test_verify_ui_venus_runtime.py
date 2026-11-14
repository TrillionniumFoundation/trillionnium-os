"""Small host rejection tests; never substitutes synthetic bytes for the actual Android build."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import verify_ui_venus_runtime as runtime

ROOT = Path(__file__).resolve().parents[1]


class UiVenusPackagingTests(unittest.TestCase):
    def test_pending_app_worker_cannot_package_shell_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            source=ROOT/"native/ui-venus-runtime-pins.json"
            pin=json.loads(source.read_text());pin["worker_build_qualified"]=False
            (root/"native").mkdir();(root/"native/ui-venus-runtime-pins.json").write_text(json.dumps(pin))
            with self.assertRaisesRegex(RuntimeError,"no qualified independent Android build"):
                runtime.load_pins(root)

    def test_strict_nontransitive_dynamic_dependency_gate(self):
        text="(RUNPATH) [$ORIGIN]\n(NEEDED) [libgeniex.so]\n(NEEDED) [libc.so]\n"
        pin={"needed":["libgeniex.so","libc.so"]}
        self.assertFalse(runtime.verify_worker_dynamic(text,pin)["runtime_maps_proven"])
        for bad in (text.replace("RUNPATH","RPATH"),text.replace("$ORIGIN","$ORIGIN:/vendor/lib64"),
                    text+"(RUNPATH) [$ORIGIN]\n",text+"(RPATH) [$ORIGIN]\n",text+"(NEEDED) [libMNN.so]\n",
                    text.replace("libgeniex.so","libc.so"),text+"(RUNPATH) malformed\n"):
            with self.subTest(value=bad),self.assertRaises(RuntimeError):runtime.verify_worker_dynamic(bad,pin)


if __name__=="__main__":unittest.main()
