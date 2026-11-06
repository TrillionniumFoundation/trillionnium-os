"""Keep epoch reservation data and original admission replay in the same schema."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = ROOT / "projects/razr60/phone-local-v150/operators/r10-epoch-reservation-v2-r1/candidate"
SEAL_SHA256 = "93f4ddc0e1d734bc775ad929924a99834b2df57a40d9f6539880cfd205a25abe"


class Razr60EpochReservationV2(unittest.TestCase):
    def test_actual_pure_validators_and_replay_interfaces(self):
        seal_raw = (CANDIDATE / "SOURCE-SEAL.json").read_bytes()
        self.assertEqual(hashlib.sha256(seal_raw).hexdigest(), SEAL_SHA256)
        seal = json.loads(seal_raw)
        self.assertEqual(seal["source_limit"], 131072)
        self.assertEqual(seal["source_bytes"], 130365)
        self.assertIs(seal["final_runtime_assembly"], False)
        self.assertEqual(seal["case_credit"], 0)
        before = {}
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        with tempfile.TemporaryDirectory(prefix="razr60-reservation-v2-") as temporary:
            work = Path(temporary)
            for row in seal["files"]:
                raw = (CANDIDATE / row["path"]).read_bytes()
                self.assertEqual(len(raw), row["bytes"], row["path"])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), row["sha256"], row["path"])
                before[row["path"]] = raw
                target = work / row["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            completed = subprocess.run(
                [sys.executable, "-I", "-B", str(work / "run_regressions.py")],
                cwd=temporary, env=environment, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, timeout=45, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout[-20000:])
            report = json.loads((work / "validation/LOCAL-REGRESSIONS.json").read_bytes())
        self.assertEqual(report["schema"], "hepta.prepare-epoch-v2.local-regressions.v1")
        self.assertEqual((report["state"], report["passed"], report["total"]), ("PASS", 35, 35))
        self.assertIs(report["current_authority_bound"], False)
        self.assertEqual(report["phone_calls"], 0)
        self.assertEqual(report["new_native_nonces"], 0)
        self.assertEqual(report["case_credit"], 0)
        self.assertTrue(all(row["passed"] for row in report["tests"]))
        for path, raw in before.items():
            self.assertEqual((CANDIDATE / path).read_bytes(), raw, path)
        self.assertEqual((CANDIDATE / "SOURCE-SEAL.json").read_bytes(), seal_raw)


if __name__ == "__main__":
    unittest.main()
