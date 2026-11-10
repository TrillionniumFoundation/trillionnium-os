"""Reproduce R1's actual cached-code gap; prove R2 executes verified source.

The injected cache only raises a local sentinel exception or sets a string.
Original source bytes are never changed and no phone/network command is used.
"""
from helpers import *
import py_compile
import types

COUNTEREXAMPLES = []
NAMES = ('model_profiles', 'warm_receipts', 'qualification_scope', 'phone_acceptance', 'phone_inventory', 'phone_suite')


def cached_code(real_source, code):
    real_source = Path(real_source); before = real_source.read_bytes()
    fake = real_source.parent.parent / ('cache-input-' + real_source.stem + '.py')
    fake.write_text(code)
    cache = Path(importlib.util.cache_from_source(str(real_source))); cache.parent.mkdir(exist_ok=True)
    py_compile.compile(str(fake), cfile=str(cache), dfile=str(real_source), doraise=True,
                       invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
    fake.unlink(); assert real_source.read_bytes() == before
    return dict(source_sha256=qs.sha(before), pyc_sha256=qs.sha(cache.read_bytes()), source_unchanged=True)


def raw_module(path, name):
    value = types.ModuleType(name); value.__file__ = str(path)
    sys.modules[name] = value; exec(compile(Path(path).read_bytes(), str(path), 'exec'), value.__dict__)
    return value


@contextlib.contextmanager
def fresh_cohort():
    saved = {name: sys.modules.pop(name, None) for name in NAMES}; previous_path = sys.path[:]
    try: yield
    finally:
        for name in NAMES:
            sys.modules.pop(name, None)
            if saved[name] is not None: sys.modules[name] = saved[name]
        sys.path[:] = previous_path


class SourceCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)
        self.base = ROOT / 'tests/fixtures/legacy-loader-package'

    def test_actual_stage_loader_and_scope_loader_ignore_valid_poisoned_pyc(self):
        source = self.root / 'qualification_scope.py'; source.write_text("VALUE = 'VERIFIED_SOURCE'\n")
        evidence = cached_code(source, "VALUE = 'UNREVIEWED_CACHE'\n")
        old = raw_module(self.base / 'orvena_qualification.py', 'r1_actual_stage_loader')
        self.assertEqual(old.module(source, 'r1_cached_target').VALUE, 'UNREVIEWED_CACHE')
        self.assertEqual(m.module(source, 'r2_source_target').VALUE, 'VERIFIED_SOURCE')
        old_observer = raw_module(self.base / 'ordinary/ordinary_start_observer.py', 'r1_actual_scope_loader')
        self.assertEqual(old_observer.scope_module(self.root).VALUE, 'UNREVIEWED_CACHE')
        self.assertEqual(observer.scope_module(self.root).VALUE, 'VERIFIED_SOURCE')
        COUNTEREXAMPLES.append(dict(case='actual_stage_and_scope_loaders', **evidence,
            r1_executed_cache=True, r2_executed_original_source=True))

    def test_actual_cli_bootstrap_bypasses_pyc_even_with_B_flag(self):
        for revision, source in (('r1', self.base), ('r2', CANDIDATE)):
            target = self.root / revision; shutil.copytree(source, target, ignore=shutil.ignore_patterns('__pycache__'))
            evidence = cached_code(target / 'drivers/qualification_scope.py', "raise RuntimeError('UNREVIEWED_CACHE_EXECUTED')\n")
            # Existing source pins remain valid. -B itself is insufficient in R1.
            if revision == 'r1':
                qs.verify_package(target, qs.sha((target / 'PACKAGE-MANIFEST.json').read_bytes()))
            result = subprocess.run([sys.executable, '-B', str(target / 'orvena_qualification.py'), '--help'], capture_output=True, timeout=15)
            if revision == 'r1':
                self.assertNotEqual(result.returncode, 0); self.assertIn(b'UNREVIEWED_CACHE_EXECUTED', result.stderr)
            else:
                self.assertEqual(result.returncode, 0, result.stderr.decode()); self.assertNotIn(b'UNREVIEWED_CACHE_EXECUTED', result.stderr)
            COUNTEREXAMPLES.append(dict(case='actual_cli_bootstrap_' + revision, **evidence,
                exit_code=result.returncode, cached_sentinel_executed=b'UNREVIEWED_CACHE_EXECUTED' in result.stderr,
                stdout_sha256=qs.sha(result.stdout), stderr_sha256=qs.sha(result.stderr)))

    def test_actual_issuer_executes_the_same_hash_checked_build_helper_bytes(self):
        source = self.root / 'source'; (source / 'tools').mkdir(parents=True)
        helper = source / 'tools/build_identity.py'; shutil.copyfile(TEST_SOURCE / 'tools/build_identity.py', helper)
        self.assertEqual(qs.sha(helper.read_bytes()), issuer.BUILD_HELPER_SHA)
        evidence = cached_code(helper, "raise RuntimeError('UNREVIEWED_BUILD_CACHE_EXECUTED')\n")
        old = raw_module(self.base / 'prepare_binding.py', 'r1_actual_binding_issuer')
        with self.assertRaisesRegex(RuntimeError, 'UNREVIEWED_BUILD_CACHE_EXECUTED'):
            old.actual_build(source, self.root / 'absent.apk', b'{}', b'{}')
        with self.assertRaises((ValueError, OSError, KeyError, RuntimeError)) as rejected:
            issuer.actual_build(source, self.root / 'absent.apk', b'{}', b'{}')
        self.assertNotIn('UNREVIEWED_BUILD_CACHE_EXECUTED', str(rejected.exception))
        COUNTEREXAMPLES.append(dict(case='actual_pinned_build_helper', **evidence,
            r1_executed_cache_after_source_hash=True, r2_reached_original_missing_source_guard=True))

    def test_actual_core_loads_all_six_dependencies_from_frozen_source_not_cache(self):
        sys.path.insert(0, str(CANDIDATE / 'core'))
        tested_core = raw_module(CANDIDATE / 'core/core_phone_suite.py', 'r2_source_core')
        target = self.root / 'drivers'; shutil.copytree(CANDIDATE / 'drivers', target, ignore=shutil.ignore_patterns('__pycache__'))
        pins, _ = tested_core.driver_files(target)
        for name in NAMES: cached_code(target / (name + '.py'), "raise RuntimeError('UNREVIEWED_DEPENDENCY_CACHE_EXECUTED')\n")
        with fresh_cohort():
            suite, acceptance = tested_core.load_drivers(pins)
            self.assertEqual(Path(acceptance.__file__).parent, target)
            self.assertEqual(suite.acceptance, acceptance)
            self.assertEqual(Path(sys.modules['qualification_scope'].__file__).parent, target)
            self.assertEqual(sys.modules['qualification_scope'].PROFILE, qs.PROFILE)
        COUNTEREXAMPLES.append(dict(case='actual_core_six_source_dependencies', frozen_source_pin_verified=True,
            poisoned_valid_pyc_count=6, r2_cache_executions=0, scope_source_parent_bound=True))

    def test_actual_core_rejects_preloaded_scope_from_another_source(self):
        sys.path.insert(0, str(CANDIDATE / 'core'))
        old = raw_module(self.base / 'core/core_phone_suite.py', 'r1_unbound_scope_core')
        current = raw_module(CANDIDATE / 'core/core_phone_suite.py', 'r2_bound_scope_core')
        for revision, tested, driver_source in (('r1', old, self.base / 'drivers'), ('r2', current, CANDIDATE / 'drivers')):
            target = self.root / revision; shutil.copytree(driver_source, target, ignore=shutil.ignore_patterns('__pycache__'))
            pins, _ = tested.driver_files(target)
            foreign = types.ModuleType('qualification_scope'); foreign.__file__ = str(self.root / 'foreign/qualification_scope.py')
            with fresh_cohort():
                sys.modules['qualification_scope'] = foreign
                if revision == 'r1':
                    tested.load_drivers(pins); self.assertIs(sys.modules['qualification_scope'], foreign)
                else:
                    with self.assertRaisesRegex(ValueError, 'qualification_scope'): tested.load_drivers(pins)
        COUNTEREXAMPLES.append(dict(case='preloaded_scope_origin', r1_foreign_scope_not_rejected=True,
            r2_rejected_before_driver_execution=True))


if __name__ == '__main__': unittest.main()
