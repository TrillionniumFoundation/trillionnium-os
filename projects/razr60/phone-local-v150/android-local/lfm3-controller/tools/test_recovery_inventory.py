"""Host fault gate for the production recovery inventory; no device access.

Android API shims deliberately reject real OS reads. Tests invoke the production
Proc census seam with controlled observations. This is not an Android procfs or
phone lifecycle qualification. Compilation requires --release 8; no fallback.
"""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest


class RecoveryInventoryHostTests(unittest.TestCase):
    def test_production_inventory_fault_contract(self):
        root = Path(__file__).resolve().parents[1]
        fixtures = root / "tests/recovery-inventory"
        production = root / "src/org/trillionnium/hepta/local"
        javac = os.environ.get("HEPTA_TEST_JAVAC") or shutil.which("javac")
        java = os.environ.get("HEPTA_TEST_JAVA") or shutil.which("java")
        self.assertTrue(javac and java, "JDK javac and java are required; this gate does not skip")
        shim_names = (
            "content/Context.java", "content/pm/ApplicationInfo.java",
            "os/Looper.java", "os/SystemClock.java", "os/Process.java",
            "system/ErrnoException.java", "system/StructStat.java",
            "system/OsConstants.java", "system/Os.java",
        )
        shims = fixtures / "android"
        self.assertEqual(
            sorted(str(path.relative_to(shims)) for path in shims.rglob("*.java")),
            sorted(shim_names), "unexpected Android API shim source",
        )
        sources = [
            production / "RecoveryProcessInventory.java",
            production / "RecoveryQuiescence.java",
            fixtures / "RecoveryInventoryHostTest.java",
            *(shims / name for name in shim_names),
        ]
        for path in sources:
            self.assertTrue(path.is_file() and not path.is_symlink(), str(path))
        with tempfile.TemporaryDirectory(prefix="hepta-recovery-inventory-") as temporary:
            command = [
                str(javac), "--release", "8", "-Xlint:all", "-Werror",
                "-d", temporary, *(str(path) for path in sources),
            ]
            compiled = subprocess.run(command, cwd=root, capture_output=True, text=True,
                                      encoding="utf-8", errors="replace", timeout=90)
            self.assertEqual(compiled.returncode, 0,
                             "strict Java 8-target compilation failed:\n" + compiled.stdout + compiled.stderr)
            tested = subprocess.run(
                [str(java), "-cp", temporary, "org.trillionnium.hepta.local.RecoveryInventoryHostTest"],
                cwd=root, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=30,
            )
            self.assertEqual(tested.returncode, 0, tested.stdout + tested.stderr)
            passed = re.findall(r"^PASS (.+)$", tested.stdout, re.MULTILINE)
            self.assertEqual(len(passed), 20, tested.stdout)
            self.assertEqual(len(set(passed)), 20, tested.stdout)
            self.assertEqual(tested.stdout.strip().splitlines()[-1], "TOTAL 20", tested.stdout)
            self.assertEqual(tested.stderr, "", tested.stderr)


if __name__ == "__main__":
    unittest.main()
