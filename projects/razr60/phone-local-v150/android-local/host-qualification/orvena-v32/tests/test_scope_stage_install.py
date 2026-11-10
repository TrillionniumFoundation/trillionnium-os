"""Exercise production scope_stage -> live -> idle_snapshot with fake phone I/O.

The prepared binding is the existing synthetic host fixture. Only the completed
prepare boundary, ADB transport factories and host server preflight are replaced;
the actual APK/UID/parser, parent, service, journal, config, worker, raw scope and
before/after comparisons execute. No real socket or process launch is allowed.
"""
from helpers import *
import phone_inventory as inventory


class ScopePhoneIo:
    def __init__(self, binding, scope=None):
        self.q = binding
        self.files = {"files/model/runtime-config.json": binding["raw_files"]["runtime-config.json"]}
        if scope is not None:
            self.files["files/qualification-scope.json"] = scope
        self.user = 0
        self.uid = binding["app_uid"]
        self.version = 32
        self.apk = binding["candidate"]["apk_sha256"]
        self.parent_ticks = 100
        self.worker = False
        self.drop_scope_write = False
        self.after_create = None
        self.scope_writes = []
        self.commands = []

    def _read(self, words, label, limit, **kwargs):
        words = tuple(words)
        if words == ("am", "get-current-user"):
            raw = (str(self.user) + "\n").encode()
        elif words == ("pm", "path", qs.PACKAGE):
            raw = b"package:/data/app/synthetic/base.apk\n"
        elif words == ("sha256sum", "/data/app/synthetic/base.apk"):
            raw = (self.apk + "  /data/app/synthetic/base.apk\n").encode()
        elif words == ("dumpsys", "package", qs.PACKAGE):
            raw = ("Package [" + qs.PACKAGE + "] (synthetic):\n"
                   "  userId=" + str(self.uid) + "\n"
                   "  versionCode=" + str(self.version) + " minSdk=30 targetSdk=35\n"
                   "  versionName=0.32.0-local-scoped-tools\n"
                   "  requested permissions:\n"
                   "  User 0: installed=true hidden=false\n").encode()
        elif words == ("pidof", qs.PACKAGE):
            raw = b"12345\n"
        else:
            raise AssertionError("unregistered fake read: " + repr(words))
        return 0, raw

    def app_read(self, words, label, limit, **kwargs):
        if words == ["id", "-u"]:
            return 0, (str(self.uid) + "\n").encode()
        if words == ["sh", "-c", observer.BARRIER_SCRIPT]:
            return 0, b""
        raise AssertionError("unregistered fake private read: " + repr(words))

    def app_bytes(self, name, optional=False):
        if name in self.files:
            return self.files[name]
        if optional:
            return None
        raise FileNotFoundError(name)

    def ps(self):
        return "PID PPID UID NAME ARGS\n" + (
            "12346 12345 10481 libhepta_local_runner.so libhepta_local_runner.so\n" if self.worker else "")

    def proc(self, pid):
        return dict(pid=pid, ppid=123, uid=self.uid, start_ticks=self.parent_ticks,
                    cmdline_sha256="1" * 64, argv=[qs.PACKAGE])

    def command(self, words, label=None, input_data=None, **kwargs):
        self.commands.append(label)
        if label == "main-accessibility-service":
            return 0, ("  * ServiceRecord{abc u0 " + qs.PACKAGE + "/.HeptaAccessibilityService}\n"
                       "    app=ProcessRecord{def 12345:" + qs.PACKAGE + "/u0a481}\n"
                       "    received=true hasBound=true\n").encode()
        if label == "accessibility-crash-check":
            return 0, b"Crashed services: {}\n"
        if label == "create-scope-once":
            assert words[:6] == ["run-as", qs.PACKAGE, "--user", "0", "sh", "-c"]
            assert "set -C" in words[6] and "if [ -e files/qualification-scope.json ]" in words[6]
            if "files/qualification-scope.json" in self.files:
                raise AssertionError("scope must never be overwritten")
            self.scope_writes.append(input_data)
            if not self.drop_scope_write:
                self.files["files/qualification-scope.json"] = input_data
            if self.after_create is not None:
                self.after_create(self)
            return 0, b""
        raise AssertionError("unregistered fake command: " + repr((label, words)))


class ScopeInstallStageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.q = binding_fixture(self.root / "binding")
        o.configure(self.q, package_manifest())
        self.plan = dict(runtime_config=self.q["runtime_config"],
                         runtime_config_sha256=self.q["runtime_config_sha256"],
                         _qualification=self.q, _scope_module=qs)
        self.prepared = self.root / "prepared"
        self.prepared.mkdir()

    def run_stage(self, phone, label="trial", mode="scope-install"):
        args = SimpleNamespace(mode=mode, axis="npu", output=self.root / label,
                               **self.q["device_target"],
                               prepared_result=self.prepared / "RESULT.json",
                               prepared_result_sha256="2" * 64, package_sha256="3" * 64)
        data = (self.prepared, {}, observer, self.plan,
                SimpleNamespace(Adb=lambda *a, **k: phone), inventory, ps)
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(m, "prepared", return_value=({}, o, data)))
            stack.enter_context(patch.object(m, "phone_args", return_value=args))
            stack.enter_context(patch.object(m, "scope_activation", return_value={}))
            stack.enter_context(patch.object(m, "Q", self.q))
            stack.enter_context(patch.object(m, "UID", self.q["app_uid"]))
            stack.enter_context(patch.object(observer, "ObserverAdb", return_value=phone))
            stack.enter_context(patch.object(inventory, "require_existing_adb_server", return_value={}))
            stack.enter_context(patch.object(socket, "create_connection", side_effect=AssertionError("real socket forbidden")))
            stack.enter_context(patch.object(subprocess, "Popen", side_effect=AssertionError("real process forbidden")))
            result = m.scope_stage(args)
        return result, qs.strict((args.output / "RESULT.json").read_bytes())

    def test_absent_scope_is_created_once_then_required(self):
        phone = ScopePhoneIo(self.q)
        result, receipt = self.run_stage(phone)
        self.assertEqual(result, 0, receipt)
        self.assertTrue(receipt["scope_present_verified"])
        self.assertFalse(receipt["scope_preexisted_identically"])
        self.assertEqual(phone.scope_writes, [self.q["raw_files"]["qualification-scope.json"]])
        self.assertEqual(receipt["phone_write_count"], 1)
        self.assertEqual(receipt["after"]["hashes"]["qualification-scope.json"], self.q["scope_sha256"])
        self.assertIs(self.plan["_qualification"], self.q)
        self.assertIs(self.plan["_scope_module"], qs)

    def test_identical_existing_scope_is_verified_without_write(self):
        phone = ScopePhoneIo(self.q, self.q["raw_files"]["qualification-scope.json"])
        result, receipt = self.run_stage(phone)
        self.assertEqual(result, 0, receipt)
        self.assertTrue(receipt["scope_preexisted_identically"])
        self.assertEqual(receipt["phone_write_count"], 0)
        self.assertEqual(phone.scope_writes, [])

    def test_foreign_scope_is_rejected_without_reservation_or_overwrite(self):
        foreign = b'{"foreign":true}\n'
        phone = ScopePhoneIo(self.q, foreign)
        result, receipt = self.run_stage(phone)
        self.assertEqual(result, 3)
        self.assertIn("another scope already present", receipt["error"])
        self.assertEqual(phone.files["files/qualification-scope.json"], foreign)
        self.assertEqual(phone.scope_writes, [])
        self.assertFalse((self.prepared / "scope-install-reservation.json").exists())

    def test_postinstall_missing_or_wrong_scope_remains_failure(self):
        for state in ("missing", "wrong"):
            with self.subTest(state=state):
                phone = ScopePhoneIo(self.q)
                if state == "missing":
                    phone.drop_scope_write = True
                else:
                    phone.after_create = lambda p: p.files.__setitem__("files/qualification-scope.json", b"wrong")
                result, receipt = self.run_stage(phone, state)
                self.assertEqual(result, 3)
                self.assertFalse(receipt["scope_present_verified"])
                self.assertEqual(len(phone.scope_writes), 1)
                (self.prepared / "scope-install-reservation.json").unlink()

    def test_journal_change_after_creation_is_rejected(self):
        journal = dict(schema="hepta.local-session.v1", app_uid=self.q["app_uid"], updated_wall_ms=1,
                       state="idle", pending=False, running=False, blocked=False, external_model=False,
                       automatic_resume=False, cleanup_known=True, status="not_started", instruction_sha256="4" * 64,
                       origin="user_button", debug_nonce_sha256=None, task_id=None)
        phone = ScopePhoneIo(self.q)
        phone.after_create = lambda p: p.files.__setitem__("files/control-session.json", qs.encoded(journal))
        result, receipt = self.run_stage(phone)
        self.assertEqual(result, 3)
        self.assertIn("scope installation changed journals/runtime", receipt["error"])
        self.assertFalse(receipt["scope_present_verified"])

    def test_config_parent_or_worker_change_after_creation_is_rejected(self):
        changes = {
            "config": lambda p: p.files.__setitem__("files/model/runtime-config.json", b"{}\n"),
            "parent": lambda p: setattr(p, "parent_ticks", p.parent_ticks + 1),
            "worker": lambda p: setattr(p, "worker", True),
        }
        for name, change in changes.items():
            with self.subTest(change=name):
                phone = ScopePhoneIo(self.q)
                phone.after_create = change
                result, receipt = self.run_stage(phone, name)
                self.assertEqual(result, 3)
                self.assertFalse(receipt["scope_present_verified"])
                self.assertEqual(len(phone.scope_writes), 1)
                (self.prepared / "scope-install-reservation.json").unlink()

    def test_existing_identity_and_clean_idle_guards_still_reject_before_write(self):
        changes = {"apk": lambda p: setattr(p, "apk", "0" * 64),
                   "uid": lambda p: setattr(p, "uid", 10000),
                   "version": lambda p: setattr(p, "version", 30),
                   "user": lambda p: setattr(p, "user", 10),
                   "worker": lambda p: setattr(p, "worker", True),
                   "journal": lambda p: p.files.__setitem__("files/control-session.json", b'{"running":true}\n')}
        for name, change in changes.items():
            with self.subTest(change=name):
                phone = ScopePhoneIo(self.q)
                change(phone)
                result, receipt = self.run_stage(phone, name)
                self.assertEqual(result, 3)
                self.assertEqual(phone.scope_writes, [])
                self.assertFalse((self.prepared / "scope-install-reservation.json").exists())

    def test_scope_removal_still_requires_scope_in_initial_live_snapshot(self):
        phone = ScopePhoneIo(self.q)
        result, receipt = self.run_stage(phone, mode="scope-remove")
        self.assertEqual(result, 3)
        self.assertIn("qualification-scope.json", receipt["error"])
        self.assertEqual(receipt["phone_write_count"], 0)
        self.assertEqual(phone.scope_writes, [])


if __name__ == "__main__":
    unittest.main()
