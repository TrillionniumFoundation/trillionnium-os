"""Real cache and input-mutation controls for the Android source admission."""
import hashlib
import importlib.util
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ("verify-owner-open-android-source-closure.py",
           "verify-owner-open-android-source-closure-v2.py")


def raw_module(name, path):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


MODULES = [raw_module("android_binding_test_" + str(i), ROOT / "tools" / name)
           for i, name in enumerate(SCRIPTS)]


def plant_timestamp_cache(path, old, current):
    if len(old) > len(current):
        raise AssertionError("fixture cache source must fit the current file length")
    old = old + b"\n#" + b" " * (len(current) - len(old) - 3) + b"\n"
    if len(old) != len(current):
        raise AssertionError("real timestamp cache requires equal source lengths")
    path.write_bytes(current)
    stamp = path.stat()
    path.write_bytes(old)
    os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    py_compile.compile(str(path), doraise=True)
    path.write_bytes(current)
    os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))


class AndroidSourceBindingTest(unittest.TestCase):
    def test_real_cache_runs_old_through_standard_loader_but_raw_bind_runs_current(self):
        for module in MODULES:
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "probe.py"
                current = b"VALUE='CURRENT'\n# retained measured source padding\n"
                plant_timestamp_cache(path, b"VALUE='CACHED'\n", current)
                spec = importlib.util.spec_from_file_location("standard_cache_control", path)
                cached = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(cached)
                self.assertEqual(cached.VALUE, "CACHED")
                actual = module.bind_helper("measured_control", path, hashlib.sha256(current).hexdigest())
                self.assertEqual(actual.VALUE, "CURRENT")
                self.assertEqual(path.read_bytes(), current)

    def test_wrong_source_parent_alias_and_multiple_links_are_rejected(self):
        for module in MODULES:
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                path = root / "probe.py"
                body = b"VALUE=42\n"
                path.write_bytes(body)
                sha = hashlib.sha256(body).hexdigest()
                with self.assertRaises(RuntimeError):
                    module.bind_helper("wrong_source", path, "0" * 64)
                (root / "alias").symlink_to(root, target_is_directory=True)
                with self.assertRaises(OSError):
                    module.bind_helper("alias_source", root / "alias/probe.py", sha)
                os.link(path, root / "second-link")
                with self.assertRaises(RuntimeError):
                    module.bind_helper("linked_source", path, sha)

    def test_fifo_and_postexecution_mutation_are_rejected(self):
        for module in MODULES:
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                fifo = root / "fifo.py"
                os.mkfifo(fifo)
                with self.assertRaises(RuntimeError):
                    module.bind_helper("fifo_source", fifo, "0" * 64)
                path = root / "mutating.py"
                body = b"from pathlib import Path\nPath(__file__).write_bytes(b'changed')\n"
                path.write_bytes(body)
                sentinel = types.ModuleType("prior_namespace")
                name = "registered_mutation_control"
                sys.modules[name] = sentinel
                try:
                    with self.assertRaises(RuntimeError):
                        module.bind_helper(name, path, hashlib.sha256(body).hexdigest(), register=True)
                    self.assertIs(sys.modules[name], sentinel)
                finally:
                    sys.modules.pop(name, None)

    def test_cached_generator_cannot_accept_retired_init_in_the_complete_closure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"
            shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns(".git", "__pycache__", "target"))
            base = root / "android-integration/working-tree/vendor/trillionnium/config/common_owner_open_base.mk"
            base.write_bytes(base.read_bytes() + b"\nPRODUCT_PACKAGES += init.trillionnium-system_ext.rc\n")
            helper = root / "tools/generate-owner-open-common-base.py"
            current = helper.read_bytes()
            old = (b"from pathlib import Path\nclass GenerationError(ValueError): pass\n"
                   b"def render(source):\n return (Path(__file__).resolve().parents[1]/"
                   b"'android-integration/working-tree/vendor/trillionnium/config/common_owner_open_base.mk').read_text()\n")
            plant_timestamp_cache(helper, old, current)
            spec = importlib.util.spec_from_file_location("old_generator_control", helper)
            cached = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cached)
            self.assertEqual(cached.render("ignored"), base.read_text())
            for name in SCRIPTS:
                result = subprocess.run([sys.executable, "-B", str(root / "tools" / name),
                                         "--root", str(root), "--json"], capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(b"owner-open shared common base differs from generated source", result.stdout)
            self.assertEqual(helper.read_bytes(), current)

    def test_interrupted_descriptor_close_retracts_registered_namespace(self):
        for module in MODULES:
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "probe.py"
                body = b"VALUE='ADMITTED'\n"
                path.write_bytes(body)
                name = "interrupted_close_namespace"
                prior = types.ModuleType(name)
                prior.VALUE = "PRIOR"
                sys.modules[name] = prior
                original_close = os.close
                interrupted = []

                def close_after_release(fd):
                    original_close(fd)
                    if not interrupted and getattr(sys.modules.get(name), "VALUE", None) == "ADMITTED":
                        interrupted.append(fd)
                        raise InterruptedError("actual released descriptor must not be retried")

                try:
                    with patch.object(module.os, "close", close_after_release):
                        with self.assertRaises(InterruptedError):
                            module.bind_helper(name, path, hashlib.sha256(body).hexdigest(), register=True)
                    self.assertEqual(len(interrupted), 1)
                    self.assertIs(sys.modules[name], prior)
                finally:
                    sys.modules.pop(name, None)


if __name__ == "__main__":
    unittest.main()
