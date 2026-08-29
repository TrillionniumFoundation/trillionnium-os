from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import time
import unittest

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "owner-open"
    / "owner_open_rootlinux_supervisor.py"
)
spec = importlib.util.spec_from_file_location("owner_open_rootlinux_supervisor", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class OwnerOpenRootLinuxSupervisorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.child = self.root / "child.py"
        self.config_path = self.root / "supervisor.json"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_child(self, source: str) -> None:
        self.child.write_text("#!/usr/bin/env python3\n" + source, encoding="utf-8")
        self.child.chmod(0o500)

    def config(self, *, restart_limit: int = 0) -> dict:
        return {
            "schema": module.SCHEMA,
            "state_root": str(self.state),
            "emergency_stop": str(self.state / "emergency-stop"),
            "status_path": str(self.state / "status" / "supervisor.json"),
            "event_log_path": str(self.state / "events" / "supervisor.jsonl"),
            "poll_seconds": 0.01,
            "shutdown_grace_seconds": 0.1,
            "kill_grace_seconds": 1.0,
            "environment": {"ADB_SERVER_SOCKET": "tcp:127.0.0.1:15038"},
            "children": [
                {
                    "name": "host",
                    "argv": [str(self.child)],
                    "environment": {},
                    "critical": True,
                    "restart_limit": restart_limit,
                    "restart_window_seconds": 5.0,
                    "restart_backoff_seconds": 0.01,
                }
            ],
            "automatic_effect_redispatch": False,
        }

    def write_config(self, value: dict) -> module.Config:
        self.config_path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        self.config_path.chmod(0o400)
        return module.load_config(self.config_path)

    def test_emergency_stop_inhibits_spawn(self) -> None:
        marker = self.root / "spawned"
        self.write_child(f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n")
        (self.state / "emergency-stop").write_text("owner stop\n", encoding="utf-8")
        config = self.write_config(self.config())
        result = module.Supervisor(config).run()
        self.assertEqual(result, 75)
        self.assertFalse(marker.exists())
        status = json.loads(config.status_path.read_text(encoding="utf-8"))
        self.assertEqual(status["state"], "inhibited")
        self.assertFalse(status["automatic_effect_redispatch"])

    def test_critical_restart_budget_is_finite(self) -> None:
        counter = self.state / "counter"
        self.write_child(
            "from pathlib import Path\n"
            f"p=Path({str(counter)!r})\n"
            "n=int(p.read_text()) if p.exists() else 0\n"
            "p.write_text(str(n+1))\n"
            "raise SystemExit(3)\n"
        )
        config = self.write_config(self.config(restart_limit=1))
        result = module.Supervisor(config).run()
        self.assertEqual(result, 70)
        self.assertEqual(counter.read_text(encoding="utf-8"), "2")
        status = json.loads(config.status_path.read_text(encoding="utf-8"))
        self.assertIn("restart_budget_exhausted", status["reason"])
        events = config.event_log_path.read_text(encoding="utf-8")
        self.assertEqual(events.count('"kind":"child_started"'), 2)
        self.assertIn('"automatic_effect_redispatch":false', events)

    def test_requested_stop_reaps_child_process_group(self) -> None:
        pid_path = self.state / "child.pid"
        self.write_child(
            "import os,time\n"
            f"open({str(pid_path)!r},'w',encoding='utf-8').write(str(os.getpid()))\n"
            "while True: time.sleep(1)\n"
        )
        config = self.write_config(self.config(restart_limit=0))
        supervisor = module.Supervisor(config)

        def stop_when_started() -> None:
            deadline = time.monotonic() + 5
            while not pid_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            supervisor.request_stop("test_stop")

        stopper = threading.Thread(target=stop_when_started)
        stopper.start()
        result = supervisor.run()
        stopper.join(timeout=1)
        self.assertEqual(result, 0)
        pid = int(pid_path.read_text(encoding="utf-8"))
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        status = json.loads(config.status_path.read_text(encoding="utf-8"))
        self.assertEqual(status["state"], "terminal")
        self.assertEqual(status["reason"], "test_stop")

    def test_android_serial_and_semantic_redispatch_are_rejected(self) -> None:
        self.write_child("raise SystemExit(0)\n")
        value = self.config()
        value["environment"]["ANDROID_SERIAL"] = "implicit"
        with self.assertRaisesRegex(module.SupervisorError, "ANDROID_SERIAL"):
            self.write_config(value)
        self.config_path.chmod(0o600)
        value = self.config()
        value["automatic_effect_redispatch"] = True
        with self.assertRaisesRegex(module.SupervisorError, "must be false"):
            self.write_config(value)

    def test_config_and_executable_must_be_non_writable(self) -> None:
        self.write_child("raise SystemExit(0)\n")
        self.child.chmod(0o722)
        with self.assertRaisesRegex(module.SupervisorError, "non-writable executable"):
            self.write_config(self.config())


if __name__ == "__main__":
    unittest.main()
