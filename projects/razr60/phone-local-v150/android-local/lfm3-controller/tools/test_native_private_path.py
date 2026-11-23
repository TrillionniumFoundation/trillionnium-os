"""Real Linux filesystem regression for both generated text and VLM IO."""
from pathlib import Path
import importlib.util,json,os,shutil,sys,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1]

@unittest.skipUnless(sys.platform.startswith("linux"),"Linux O_PATH/renameat2 filesystem boundary")
class NativePrivatePath(unittest.TestCase):
    def test_actual_ancestor_replacement_and_canonical_paths(self):
        self.assertNotEqual(os.getuid(),0,"run the real filesystem guard as an ordinary account")
        compiler=shutil.which("cc")
        self.assertIsNotNone(compiler,"native guard compiler required")
        path=ROOT/"tests/native-private-path/run_host.py"
        spec=importlib.util.spec_from_file_location("native_private_path_actual",path)
        runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
        with tempfile.TemporaryDirectory(prefix="hepta-native-private-path-suite-",dir="/tmp") as temporary:
            out=Path(temporary)/"actual"
            runner.run(ROOT,out,compiler,False)
            receipt=json.loads((out/"RESULT.json").read_text())
            self.assertIs(receipt["passed"],True)
            self.assertIs(receipt["sources_unchanged"],True)
            self.assertEqual(receipt["case_count"],68)
            self.assertEqual(receipt["failed_cases"],[])
            self.assertEqual({row["target"] for row in receipt["cases"]},{"text","vlm"})
            self.assertTrue(all(not row["result"]["foreign_descriptor_opened"]
                                and not row["result"]["foreign_output_created"] for row in receipt["cases"]))
            self.assertTrue(all(row["result"]["actual_rename_count"]==1
                                for row in receipt["cases"] if row["name"].startswith("raced_")))
if __name__=="__main__":unittest.main()
