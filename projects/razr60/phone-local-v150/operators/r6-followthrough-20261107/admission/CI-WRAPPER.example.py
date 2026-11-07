"""Install as tools/tests/test_razr60_r6_followthrough.py in the existing repo."""
import importlib.util
from pathlib import Path


def load_tests(loader, tests, pattern):
    repository = Path(__file__).resolve().parents[2]
    path = repository / "projects/razr60/phone-local-v150/operators/r6-followthrough-20261107/admission/tests/test_original_attempt_admission.py"
    spec = importlib.util.spec_from_file_location("razr60_original_attempt_admission_tests", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("original-attempt admission tests unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_suite()
