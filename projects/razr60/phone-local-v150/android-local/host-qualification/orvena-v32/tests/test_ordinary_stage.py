"""Real ordinary prefill/Start functions with all device/process writes trapped."""
from helpers import *
from PIL import Image


class OrdinaryStageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)
        self.q = binding_fixture(self.root / 'binding'); o.configure(self.q, package_manifest())
        self.parent = dict(pid=12345, uid=self.q['app_uid'])
        self.idle = dict(hashes={'runtime-config.json': self.q['runtime_config_sha256'],
                               'qualification-scope.json': self.q['scope_sha256']}, control=dict(cleanup_known=True))
        self.calls = []
        self.plan = dict(_scope_module=qs, _qualification=self.q)

    def test_real_prefill_emits_expected_scope_without_auto_or_start_tap(self):
        def command(words, label=None, **kw):
            self.calls.append((label, words))
            if label == 'resolve-home': return 0, (self.q['scope']['launcher_component'] + '\n').encode()
            if label == 'ordinary-main-prefill': return 0, b'Status: ok\n'
            if label == 'setup-home-once': return 0, b''
            raise AssertionError(label)
        ro = SimpleNamespace(focus=lambda: dict(package=qs.ROLES['launcher']),
            png=lambda label: dict(focus=dict(package=qs.ROLES['launcher']), sha256='a' * 64))
        native = SimpleNamespace(idle_snapshot=lambda *a: copy.deepcopy(self.idle), parent_identity=lambda *a: self.parent)
        p = self.root / 'prepared'; p.mkdir()
        args = SimpleNamespace(output=self.root / 'prefill', run_output=self.root / 'run', prepared_sha256='1' * 64)
        fake_process = SimpleNamespace(pid=os.getpid(), wait=lambda: 0)
        with patch.object(o, 'live', return_value=(ro, SimpleNamespace(command=command), self.parent, self.idle)), \
             patch.object(o, 'service_check'), patch.object(o, 'observer_argv', return_value=['SYNTHETIC_OBSERVER_NOT_STARTED']), \
             patch.object(o.subprocess, 'Popen', return_value=fake_process), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(o.prefill(args, p, {}, native, self.plan, None, None, None), 0)
        intents = [words for label, words in self.calls if label == 'ordinary-main-prefill']
        self.assertEqual(intents, [qs.ordinary_intent(qs.ORDINARY_INSTRUCTION, self.q)])
        self.assertFalse(any('tap' in words or 'auto_task' in words or 'auto_run' in words for _, words in self.calls))
        pf = qs.strict((args.output / 'PREFILL.json').read_bytes())
        self.assertFalse(pf['task_started']); self.assertEqual(pf['tap_attempts'], 0)
        self.assertEqual(pf['expected_scope_sha256'], self.q['scope_sha256'])

    def start_fixture(self, altered_ready=False):
        pre = self.root / 'prefill'; pre.mkdir(); run = self.root / 'run'; run.mkdir(); p = self.root / 'prepared'; p.mkdir()
        png = io.BytesIO(); Image.new('RGB', (1224, 2992), (25, 35, 45)).save(png, format='PNG'); raw = png.getvalue()
        (run / 'ready.png').write_bytes(raw)
        process_argv = Path('/proc/self/cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
        stat = Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()
        process = dict(pid=os.getpid(), start_ticks=int(stat[19]), argv=process_argv, launch_monotonic=time.monotonic())
        (pre / 'OBSERVER-PROCESS.json').write_bytes(qs.encoded(process))
        pf = dict(prepared_sha256='1' * 64, instruction_sha256=qs.ORDINARY_SHA, expected_scope_sha256=self.q['scope_sha256'],
                  qualification_binding_sha256=self.q['binding_sha256'], run_output=str(run), parent=self.parent, initial_idle=self.idle)
        (pre / 'PREFILL.json').write_bytes(qs.encoded(pf))
        ready = dict(event='ARMED_AWAITING_ROOT_START', instruction=qs.ORDINARY_INSTRUCTION, phone_actions_sent=0,
            expected_scope_sha256=('0' * 64 if altered_ready else self.q['scope_sha256']),
            qualification_binding_sha256=self.q['binding_sha256'], ready_ui=dict(sha256=qs.sha(raw)), parent=self.parent,
            baseline_tasks=[], wall_ms=int(time.time() * 1000))
        ready_raw = qs.encoded(ready); (run / 'READY.json').write_bytes(ready_raw)
        args = SimpleNamespace(prefill=pre, prepared_sha256='1' * 64, ready_sha256=qs.sha(ready_raw), reviewed_image_sha256=qs.sha(raw),
            output=self.root / 'start', review_rectangle=[100, 100, 800, 500], start_point=[400, 300])
        return args, p, process_argv, raw

    def run_start(self, changed_idle=False, altered_ready=False):
        args, p, argv, raw = self.start_fixture(altered_ready)
        focus = dict(package=qs.PACKAGE, component=qs.PACKAGE + '.MainActivity')
        def png(label):
            folder = args.output / 'readonly'; folder.mkdir(exist_ok=True)
            (folder / (label + '.png')).write_bytes(raw)
            return dict(focus=focus, sha256=qs.sha(raw))
        ro = SimpleNamespace(list_children=lambda *a, **k: [], focus=lambda: focus, png=png)
        cli = SimpleNamespace(command=lambda words, **kw: self.calls.append((kw.get('label'), words)))
        fresh = copy.deepcopy(self.idle)
        if changed_idle: fresh['hashes']['qualification-scope.json'] = '0' * 64
        native = SimpleNamespace(idle_snapshot=lambda *a: fresh, parent_identity=lambda *a: self.parent)
        with patch.object(o, 'observer_argv', return_value=argv), \
             patch.object(o, 'live', return_value=(ro, cli, self.parent, self.idle)), \
             patch.object(socket, 'create_connection', side_effect=AssertionError('no network')), contextlib.redirect_stdout(io.StringIO()):
            o.start(args, p, {}, native, self.plan, None, None, None)
        return args, p

    def test_real_start_keeps_actual_pid_argv_pixel_fences_and_one_tap(self):
        args, p = self.run_start()
        self.assertEqual(self.calls, [('ordinary-start-once', ['input', '-d', '0', 'tap', '400', '300'])])
        intent = qs.strict((p / 'start-reservation.json').read_bytes())
        self.assertEqual(intent['expected_scope_sha256'], self.q['scope_sha256']); self.assertEqual(intent['tap_attempts'], 1)
        self.assertTrue(qs.strict((args.output / 'RESULT.json').read_bytes())['task_start_not_inferred_from_exit'])

    def test_real_start_refuses_scope_change_before_tap(self):
        with self.assertRaisesRegex(RuntimeError, 'session/config changed before tap'): self.run_start(changed_idle=True)
        self.assertEqual(self.calls, []); self.assertFalse((self.root / 'prepared/start-reservation.json').exists())

    def test_real_start_refuses_ready_from_other_scope_before_live_io(self):
        args, p, argv, raw = self.start_fixture(True)
        with patch.object(o, 'observer_argv', return_value=argv), patch.object(o, 'live', side_effect=AssertionError('READY must reject before live I/O')):
            with self.assertRaisesRegex(RuntimeError, 'READY differs'): o.start(args, p, {}, None, self.plan, None, None, None)


if __name__ == '__main__': unittest.main()
