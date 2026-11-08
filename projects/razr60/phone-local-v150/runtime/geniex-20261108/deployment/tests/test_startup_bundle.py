#!/usr/bin/env python3
"""Host-only startup materialization guards; no mount/init/policy execution."""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import staging
import build_startup_bundle as bundle


def observation():
    # Deliberate host metadata fixture, never an Android staging observation.
    return {"schema": "hepta.geniex-inverse-stage-provision.v1", "instance": "a" * 32,
            "candidate": {"st_dev": 10, "st_ino": 100, "uid": 0, "gid": 0, "mode": 0o700},
            "source": {"st_dev": 10, "st_ino": 101, "uid": 2000, "gid": 2000, "mode": 0o700},
            "alias": {"st_dev": 10, "st_ino": 102, "uid": 2000, "gid": 2000, "mode": 0o700},
            "mount_namespace": "mnt:[1234]", "stage_mounted": False, "old_state_permissions_changed": False,
            "stop_sha256": staging.STOP_SHA, "retained_claims_sha256": staging.CLAIMS_SHA}


def artifacts():
    root = "/data/local/tmp/hepta-geniex-artifacts-" + "b" * 32
    return {"schema": "hepta.geniex-isolated-artifacts.v1", "artifact_owner_uid": 0,
            "artifact_owner_gid": 0, "directory_mode": "0755", "context_tokens": 4096,
            "files": [{"target_android": root + "/model/part%02d.bin" % i,
                       "bytes": 100, "sha256": "1" * 64, "mode": "0644"} for i in range(20)]}


class StagingContract(unittest.TestCase):
    def test_parses_exact_stats_and_rejects_missing_or_duplicate_observations(self):
        raw = b"CANDIDATE 10:100:0:0:700\nSOURCE 10:101:2000:2000:700\nALIAS 10:102:2000:2000:700\nMOUNT_NAMESPACE mnt:[1234]\n"
        self.assertEqual(staging.parse_provision_output("a" * 32, raw), observation())
        for invalid in (raw.replace(b"SOURCE", b"MISSING"), raw + b"SOURCE 10:101:2000:2000:700\n"):
            with self.assertRaises(ValueError):
                staging.parse_provision_output("a" * 32, invalid)

    def test_stage_metadata_is_exact_and_cannot_be_already_bound(self):
        for key, value in (("st_ino", True), ("uid", 0), ("gid", 0), ("mode", 0o777)):
            candidate = observation(); candidate["source"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                staging.observation_contract(candidate)
        candidate = observation(); candidate["alias"] = dict(candidate["source"])
        with self.assertRaises(ValueError):
            staging.observation_contract(candidate)

    def test_claims_stop_and_original_state_preservation_are_required(self):
        for key, value in (("stop_sha256", "0" * 64), ("retained_claims_sha256", "0" * 64),
                           ("stage_mounted", True), ("old_state_permissions_changed", True)):
            candidate = observation(); candidate[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                staging.observation_contract(candidate)

    def test_instance_and_rc_digest_cannot_inject_commands(self):
        for instance in ("A" * 32, "../x", "a" * 32 + "\n", "a" * 16 + ";true"):
            with self.assertRaises(ValueError):
                staging.paths(instance)
        for digest in ("", "0" * 63, "0" * 64 + "\n"):
            with self.assertRaises(ValueError):
                staging.service_rc("a" * 32, digest)

    def test_rendered_scripts_pass_shell_parser_without_execution(self):
        scripts = [staging.provision_script("a" * 32), staging.bind_script(observation()),
                   staging.unbind_script(observation()), bundle.label_artifacts_script(bundle.artifact_contract(artifacts()))]
        for script in scripts:
            result = subprocess.run(["/bin/sh", "-n"], input=script.encode(), capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_bind_refuses_before_bootstrap_readiness_without_reaching_mutations(self):
        with tempfile.TemporaryDirectory(prefix="hepta-stage-host-") as tmp:
            root = Path(tmp)
            shim = root / "shim"
            shim.write_text("#!/bin/sh\ncase ${0##*/} in\nid) printf '0\\n';;\ngetenforce) printf 'Enforcing\\n';;\n"
                            "getprop) case $1 in init.svc.trillionnium_owner_open_bootstrap) printf 'stopped\\n';; *) exit 97;; esac;;\n"
                            "*) printf 'UNEXPECTED\\n' >&2; exit 98;;\nesac\n")
            shim.chmod(0o755)
            for name in ("id", "getenforce", "getprop"):
                (root / name).symlink_to(shim)
            # Explicit host-only replacement is applied to the rendered copy.
            # It cannot run mount or chcon, and no Android receipt is produced.
            script = staging.bind_script(observation()).replace("/system/bin/", str(root) + "/")
            result = subprocess.run(["/bin/sh"], input=script.encode(), capture_output=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stderr, b"")
            self.assertEqual(len(list(root.iterdir())), 4)

    def test_service_is_disabled_same_domain_and_no_automatic_replay(self):
        text = staging.service_rc("a" * 32, "1" * 64)
        self.assertIn("    disabled\n    oneshot\n", text)
        self.assertIn("seclabel u:r:trillionnium_owner_open_bootstrap:s0", text)
        self.assertIn("capabilities CHOWN DAC_OVERRIDE KILL SYS_CHROOT", text)
        self.assertNotIn("    start ", text)
        self.assertNotIn("restart", text)
        self.assertNotIn("magisk:s0", text)

    def test_new_policy_preserves_non_executable_stage_and_no_device_grants(self):
        stage = staging.policy_fragment()
        self.assertIn("setattr link unlink", stage)
        self.assertNotIn("execute", stage)
        self.assertNotIn("permissive", stage)
        artifact = staging.artifact_policy_fragment()
        self.assertIn("runtime_exec file { getattr open read map execute execute_no_trans }", artifact)
        for forbidden in ("vendor_qdsp_device", "vendor_xdsp_device", "shell_data_file file", "sys_admin", "setuid", "setgid"):
            self.assertNotIn(forbidden, stage + artifact)


class BundleContract(unittest.TestCase):
    def test_written_modes_are_exact_under_restrictive_umask_and_never_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = os.umask(0o077)
            try:
                for mode in (0o600, 0o644, 0o755):
                    path = root / str(mode)
                    bundle.write_new(path, b"original", mode)
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
                    with self.assertRaises(FileExistsError):
                        bundle.write_new(path, b"replacement", mode)
                    self.assertEqual(path.read_bytes(), b"original")
            finally:
                os.umask(old)

    def test_regular_input_reader_refuses_links_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "file"; target.write_bytes(b"original")
            self.assertEqual(bundle.raw_file(target, 8), b"original")
            with self.assertRaises(ValueError):
                bundle.raw_file(target, 7)
            link = root / "link"; link.symlink_to(target)
            with self.assertRaises(OSError):
                bundle.raw_file(link)
            link.unlink(); os.link(target, link)
            with self.assertRaises(ValueError):
                bundle.raw_file(target)

    def test_artifacts_refuse_shared_paths_duplicates_writes_and_fake_integers(self):
        value = artifacts(); self.assertEqual(len(bundle.artifact_contract(value)), 20)
        for path in ("/system/lib64/libc.so", "/data/local/tmp/original/model.bin",
                     "/data/local/tmp/hepta-geniex-artifacts-" + "b" * 32 + "/../old/model.bin"):
            candidate = copy.deepcopy(value); candidate["files"][0]["target_android"] = path
            with self.subTest(path=path), self.assertRaises(ValueError):
                bundle.artifact_contract(candidate)
        for key, changed in (("mode", "0666"), ("mode", "0755"), ("bytes", True)):
            candidate = copy.deepcopy(value); candidate["files"][0][key] = changed
            with self.subTest(key=key, changed=changed), self.assertRaises(ValueError):
                bundle.artifact_contract(candidate)
        candidate = copy.deepcopy(value); candidate["files"][1] = candidate["files"][0]
        with self.assertRaises(ValueError):
            bundle.artifact_contract(candidate)
        candidate = copy.deepcopy(value); candidate["artifact_owner_uid"] = False
        with self.assertRaises(ValueError):
            bundle.artifact_contract(candidate)

    def test_json_and_immutable_build_inputs_cannot_silently_drift(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            with self.assertRaises(ValueError):
                bundle.strict(raw)
        with self.assertRaises(ValueError):
            bundle.python_pin(b'{"entries":[]}')
        build = (HERE / "build-r3/BUILD-MANIFEST.json").read_bytes()
        self.assertEqual(hashlib.sha256(build).hexdigest(), bundle.ENTRY_BUILD_MANIFEST_SHA)
        value = json.loads(build)
        self.assertFalse(value["host_fixture_defined"])
        self.assertEqual(value["binary"]["sha256"], bundle.ENTRY_BINARY_SHA)


if __name__ == "__main__":
    unittest.main(verbosity=2)
