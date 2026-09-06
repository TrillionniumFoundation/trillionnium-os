from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BROKER = ROOT / "owner-open" / "owner_open_connection_broker.py"

UPSTREAM = r'''#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
Path(os.environ["UPSTREAM_PID"]).write_text(str(os.getpid()))
for line in sys.stdin:
    value=json.loads(line)
    if value.get("kind")=="hello":
        print(json.dumps({"kind":"hello.ack","seq":0,"payload":{}}),flush=True)
    else:
        time.sleep(30)
'''


class BrokerStartupCleanupTest(unittest.TestCase):
    def test_descriptor_publication_failure_reaps_started_upstream(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw)
            upstream=root/"upstream.py"
            upstream.write_text(UPSTREAM)
            upstream.chmod(0o700)
            pid_file=root/"upstream.pid"
            descriptor=root/"broker.json"
            target=root/"target"
            target.write_text("do not replace")
            descriptor.symlink_to(target)
            env=os.environ.copy()
            env["UPSTREAM_PID"]=str(pid_file)
            process=subprocess.run(
                [
                    sys.executable,
                    str(BROKER),
                    "--socket",
                    str(root/"broker.sock"),
                    "--descriptor",
                    str(descriptor),
                    "--token-file",
                    str(root/"broker.token"),
                    "--broker-id",
                    "cleanup-test",
                    "--upstream",
                    str(upstream),
                ],
                capture_output=True,
                env=env,
                timeout=10,
            )
            self.assertEqual(process.returncode,2,process.stderr)
            self.assertTrue(pid_file.exists(),process.stderr)
            pid=int(pid_file.read_text())
            deadline=time.monotonic()+3
            while time.monotonic()<deadline:
                try:
                    os.kill(pid,0)
                except ProcessLookupError:
                    break
                time.sleep(0.02)
            else:
                self.fail(
                    f"upstream process {pid} survived broker initialization failure"
                )
            self.assertTrue(descriptor.is_symlink())
            self.assertEqual(target.read_text(),"do not replace")


if __name__ == "__main__":
    unittest.main()
