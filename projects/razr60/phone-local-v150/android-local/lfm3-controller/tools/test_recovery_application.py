import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

class RecoveryApplicationTest(unittest.TestCase):
    def test_actual_application_recovery_close_and_retry(self):
        source=Path(__file__).resolve().parents[1]
        helper=source/"tests/recovery-application/prepare_engine_fixture.py"
        spec=importlib.util.spec_from_file_location("hepta_recovery_application_fixture",helper)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        javac=os.environ.get("HEPTA_TEST_JAVAC","javac")
        java=os.environ.get("HEPTA_TEST_JAVA","java")
        with tempfile.TemporaryDirectory(prefix="hepta-recovery-application-") as temporary:
            output=Path(temporary);classes=output/"classes";classes.mkdir()
            sources=module.prepare(source,output/"fixture")
            compile_result=subprocess.run(
                [javac,"--release","8","-encoding","UTF-8","-Xlint:all","-Werror","-d",str(classes)]+[str(p) for p in sources],
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=90)
            self.assertEqual(compile_result.returncode,0,compile_result.stdout)
            result=subprocess.run([java,"-cp",str(classes),
                                   "org.trillionnium.hepta.local.RecoveryApplicationHostTest"],
                                  stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=45)
            self.assertEqual(result.returncode,0,result.stdout)
            self.assertIn("PASS cases=18 ",result.stdout)
            print(result.stdout,end="")

if __name__=="__main__":
    unittest.main()
