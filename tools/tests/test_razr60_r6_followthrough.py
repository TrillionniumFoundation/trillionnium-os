"""Run exact R6 source admission and observation controls in existing G1 CI."""
import importlib.util
from pathlib import Path
import unittest


def load_tests(loader, tests, pattern):
    repository = Path(__file__).resolve().parents[2]
    package = repository / "projects/razr60/phone-local-v150/operators/r6-followthrough-20261107"
    suite = unittest.TestSuite()
    for name, relative, with_root in (
        ("razr60_original_attempt_admission_tests", "admission/tests/test_original_attempt_admission.py", False),
        ("razr60_deadline_followthrough_tests", "deadline/check_deadline_candidate.py", True),
    ):
        spec = importlib.util.spec_from_file_location(name, package / relative)
        if spec is None or spec.loader is None:
            raise RuntimeError("R6 followthrough source controls unavailable: " + relative)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        suite.addTests(module.load_suite(repository) if with_root else module.load_suite())
    return suite
