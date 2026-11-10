"""Adversarial terminal-journal and pinned-import regressions; no phone input."""
import copy
import importlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

import test_warm_core_integration as integration
from test_warm_action_binding import reseal, write

acceptance, suite, core = integration.acceptance, integration.suite, integration.core


class WarmTerminalClosureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for target in ((acceptance, "Adb"), (socket, "create_connection"), (subprocess, "Popen"), (subprocess, "run")):
            guard = patch.object(*target, side_effect=AssertionError("phone/network/process access forbidden"))
            guard.start(); self.addCleanup(guard.stop)

    def case(self, name):
        builder = integration.WarmCoreIntegrationTests(); builder.root = self.root / name
        original = integration.synthetic_core.CoreChecks(); original.root = builder.root / "source"
        fixture = original.discovery()
        directory = builder.collect(fixture)
        return directory, fixture

    def reject_core(self, directory, fixture):
        result = core.evaluate_one(directory, fixture.case, suite, acceptance)
        self.assertEqual(result["verdict"], "unverified", result)
        self.assertFalse(result["action_sequence"]["evidence_complete"], result)
        self.assertEqual(result["launch_attempt_count"], 1)

    def omit(self, directory, paths):
        for relative in paths: (directory / relative).unlink()
        collection = json.loads((directory / "collection.json").read_bytes())
        collection["files"] = [item for item in collection["files"] if item["path"] not in paths]
        write(directory / "collection.json", collection); reseal(directory)

    def test_missing_terminal_action_or_after_cannot_pass_real_find_app_case(self):
        for suffixes in (("action",), ("after",), ("action", "after")):
            with self.subTest(missing=suffixes):
                directory, fixture = self.case("missing-" + "-".join(suffixes))
                self.omit(directory, ["task/step-03-" + suffix + ".json" for suffix in suffixes])
                self.reject_core(directory, fixture)

    def test_unselected_terminal_action_must_equal_its_native_raw_decision(self):
        for field, value in (("status", "blocked"), ("summary", "different summary"),
                             ("observation_id", "f" * 32), ("package", "another.application")):
            with self.subTest(field=field):
                directory, fixture = self.case(field)
                path = directory / "task/step-03-action.json"
                receipt = json.loads(path.read_bytes()); receipt["action"][field] = value; write(path, receipt)
                reseal(directory); self.reject_core(directory, fixture)

    def test_terminal_step_and_final_observation_must_name_last_complete_step(self):
        changes = (("steps", 1), ("steps", True), ("steps", 99), ("steps", None),
                   ("final_observation_id", "f" * 32), ("final_observation_id", None))
        for index, (field, value) in enumerate(changes):
            with self.subTest(field=field, value=value):
                directory, fixture = self.case("terminal%d" % index)
                path = directory / "task/result.json"
                terminal = json.loads(path.read_bytes())
                if value is None: terminal.pop(field)
                else: terminal[field] = value
                write(path, terminal); reseal(directory, synchronize_terminal=True)
                self.reject_core(directory, fixture)

    def test_success_terminal_requires_last_native_done_success(self):
        for mode in ("non-done", "unsuccessful-done"):
            with self.subTest(mode=mode):
                directory, fixture = self.case(mode)
                action_path = directory / "task/step-03-action.json"
                receipt = json.loads(action_path.read_bytes())
                if mode == "non-done":
                    receipt["action"]["action"] = "back"; receipt["action"].pop("status")
                    receipt["dispatched"] = True
                else:
                    receipt["action"]["status"] = "blocked"
                raw = (json.dumps(receipt["action"]) + "\n").encode()
                write(action_path, receipt)
                model_path = directory / "task/step-03-model-0.json"
                model = json.loads(model_path.read_bytes()); model["raw_text"] = raw.decode(); write(model_path, model)
                run = directory / "runs" / model["run_id"]
                (run / "raw-text.txt").write_bytes(raw)
                native = json.loads((run / "native-result.json").read_bytes())
                native.update(raw_text_sha256=acceptance.digest(raw), raw_text_bytes=len(raw))
                write(run / "native-result.json", native)
                app = json.loads((run / "app-receipt.json").read_bytes())
                app.update(native_receipt=copy.deepcopy(native), raw_text_sha256_read=acceptance.digest(raw))
                write(run / "app-receipt.json", app)
                reseal(directory); self.reject_core(directory, fixture)

    def test_missing_other_step_action_or_after_cannot_qualify_selected_open(self):
        for suffix in ("action", "after"):
            with self.subTest(missing=suffix):
                directory, fixture = self.case("earlier-" + suffix)
                self.omit(directory, ["task/step-01-" + suffix + ".json"])
                result = suite.action_sequence(directory, fixture.case["required_actions"], fixture.owner_sha)
                self.assertFalse(result["evidence_complete"], result)

    def foreign(self, name):
        module = types.ModuleType(name)
        module.__dict__.update(importlib.import_module(name).__dict__)
        module.__file__ = str(self.root / "unreviewed" / (name + ".py"))
        if name == "warm_action_evidence":
            module.verify_warm_action = lambda *args, **kwargs: {"foreign_helper_executed": True}
        return module

    def test_frozen_core_rejects_preloaded_foreign_warm_helpers(self):
        directory = Path(suite.__file__).parent
        pin, _ = core.driver_files(directory)
        for name in ("warm_action_evidence", "warm_receipts"):
            with self.subTest(module=name):
                foreign = self.foreign(name)
                with patch.dict(sys.modules, {name: foreign}), patch.object(sys, "path", list(sys.path)):
                    sys.modules.pop("phone_suite", None)
                    if name == "warm_receipts": sys.modules.pop("warm_action_evidence", None)
                    with self.assertRaisesRegex(ValueError, "another version|unexpected directory"):
                        loaded_suite, _ = core.load_drivers(pin, directory)
                        if name == "warm_action_evidence":
                            self.assertTrue(loaded_suite.verify_warm_action()["foreign_helper_executed"])

    def test_frozen_core_rechecks_helper_origins_after_import(self):
        directory = Path(suite.__file__).parent
        pin, _ = core.driver_files(directory)
        for name in ("warm_action_evidence", "warm_receipts"):
            with self.subTest(module=name):
                foreign = self.foreign(name)
                original = importlib.import_module
                def import_then_change(module, *args, **kwargs):
                    result = original(module, *args, **kwargs)
                    if module == "phone_suite": sys.modules[name] = foreign
                    return result
                with patch.dict(sys.modules), patch.object(sys, "path", list(sys.path)), patch.object(
                        core.importlib, "import_module", side_effect=import_then_change):
                    with self.assertRaisesRegex(ValueError, "another version|unexpected directory"):
                        core.load_drivers(pin, directory)


if __name__ == "__main__":
    unittest.main()
