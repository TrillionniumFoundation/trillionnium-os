"""Host-only radio transaction qualification; never connects to ADB or a phone.

The real signal/child tests use a harmless Python process and an in-memory phone
state provider. They establish cleanup control flow, not Android radio behavior.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import offline_guards as g
import phone_offline_suite as w


def same_proc_namespace():
    try:return g.process_identity(Path("/proc/self/stat").read_text())["pid"]==os.getpid()
    except (OSError,ValueError):return False


class Clock:
    def __init__(self):self.now=100.0
    def monotonic(self):return self.now
    def sleep(self,value):self.now+=value


def arguments(root):
    return argparse.Namespace(adb_host="127.0.0.1",adb_port=5061,serial="HOST_ONLY_FIXTURE",
        data_setting_key="mobile_data1",expected_default_subscription=1,expected_multisim_config="dsds",
        command_timeout=10,stable_seconds=0.02,restore_seconds=0.3,preparation_seconds=0.3,
        suite_deadline_seconds=10,network_poll_seconds=1,child_exit_grace_seconds=1,
        expected_plan_sha256="a"*64,adb=str(root/"adb-version-stub"))


class FakePhone:
    def __init__(self,args,out,expected=None,allow_reconnected=False):
        self.args=args;self.out=out;self.expected=expected or {"serial":args.serial,"usb":"host-fixture","transport_id":"1"}
        self.wifi=1;self.global_data=1;self.selected=1;self.sub=1;self.mode="dsds";self.calls=[]
        self.fail_after_data_disable=False;self.invalid_offline_network=False;self.ignore_data_disable=False
        self.slow_restore=False;self.ever_disabled=False

    def smart(self,name,phase_deadline=None):
        if name!="host:version":raise AssertionError("unexpected host read")
        return b"0029"

    def identity(self,deadline=None):return self.expected

    def command(self,command,label,deadline=None):
        command=tuple(command);self.calls.append(command)
        if command[:1]==("svc",):
            _,radio,change=command;value=int(change=="enable")
            if radio=="wifi":
                if value and self.slow_restore and self.ever_disabled:time.sleep(0.4)
                self.wifi=value
            elif radio=="data":
                if not (self.ignore_data_disable and not value):self.selected=value
                if not value:self.ever_disabled=True
                if not value and self.fail_after_data_disable:
                    self.fail_after_data_disable=False;raise TimeoutError("remote effect occurred before reply timed out")
            else:raise AssertionError(command)
            return b""
        if command[:3]==("settings","get","global"):
            values={"wifi_on":self.wifi,"mobile_data":self.global_data,"mobile_data1":self.selected,"multi_sim_data_call":self.sub}
            return (str(values[command[3]])+"\n").encode()
        if command==("getprop","persist.radio.multisim.config"):return (self.mode+"\n").encode()
        if command==("cmd","wifi","status"):return b"Wifi is enabled\n" if self.wifi else b"Wifi is disabled\n"
        if command==("dumpsys","connectivity"):
            if not self.wifi and not self.selected and self.invalid_offline_network:return b"Active default network: none\nActive default network: unknown\n"
            return b"Active default network: 105\n" if self.wifi or self.selected else b"Active default network: none\n"
        raise AssertionError("unlisted fake command: "+str(command))


class ParserTests(unittest.TestCase):
    def test_default_network_requires_one_complete_header(self):
        self.assertIsNone(g.default_network(b"\tActive default network: none\r\n"))
        self.assertEqual(g.default_network(b"Active default network: 105\n"),105)
        for raw in (b"",b"default none",b"Active default network: none\nActive default network: 8\n",
                    b"Active default network: none\nActive default network: unknown\n",b"Active default network: none extra\n"):
            with self.subTest(raw=raw),self.assertRaises(g.UnknownState):g.default_network(raw)

    def test_wifi_rejects_duplicate_or_malformed_status(self):
        self.assertFalse(g.wifi_status(b"Wifi is disabled\r\n"))
        self.assertTrue(g.wifi_status(b"Wifi is enabled\n"))
        for raw in (b"Wifi is disabled\nWifi is unknown\n",b"Wifi is enabled\nWifi is disabled\n",b"Wifi is disabling\n"):
            with self.subTest(raw=raw),self.assertRaises(g.UnknownState):g.wifi_status(raw)

    def test_no_missing_key_fallback_or_inferred_subscription(self):
        self.assertEqual(g.selected_data_key("mobile_data1",1),"mobile_data1")
        with self.assertRaises(g.UnknownState):g.selected_data_key("mobile_data2",1)
        for raw in (b"null\n",b"2\n",b"true\n",b"0\n1\n"):
            with self.subTest(raw=raw),self.assertRaises(g.UnknownState):g.switch_value(raw)
        for raw in (b"-1\n",b"null\n",b"01\n"):
            with self.subTest(raw=raw),self.assertRaises(g.UnknownState):g.subscription_id(raw)

    def test_explicit_usb_identity_required(self):
        self.assertEqual(g.usb_device(b"HOST_ONLY_FIXTURE device usb:1-3 transport_id:8\n","HOST_ONLY_FIXTURE")["transport_id"],"8")
        for raw in (b"HOST_ONLY_FIXTURE device transport_id:8\n",b"HOST_ONLY_FIXTURE offline usb:1-3 transport_id:8\n",
                    b"HOST_ONLY_FIXTURE device usb:1-3 transport_id:8 transport_id:9\n",
                    b"HOST_ONLY_FIXTURE device usb:1-3 transport_id:8\nHOST_ONLY_FIXTURE device usb:1-4 transport_id:9\n"):
            with self.subTest(raw=raw),self.assertRaises(g.UnknownState):g.usb_device(raw,"HOST_ONLY_FIXTURE")

    def test_duplicate_json_and_nonfinite_values_rejected(self):
        for raw in ('{"a":1,"a":2}','{"a":NaN}'):
            with self.assertRaises((ValueError,g.UnknownState)):g.strict_json(raw)

    def test_expired_send_never_writes(self):
        class Channel:
            def settimeout(self,value):raise AssertionError("deadline already expired")
            def sendall(self,value):raise AssertionError("must not send")
        with self.assertRaises(TimeoutError):w.send_all(Channel(),b"test",time.monotonic()-1)

    def test_core_v2_revision_is_exact(self):
        parent=Path(__file__).resolve().parent.parent
        source=next(p for p in (parent/"razr-core-suite-r2",parent/"core-suite-r2",parent/"core-phone-suite-v2") if p.is_dir())
        self.assertEqual(g.sha((source/"core_phone_suite.py").read_bytes()),w.CORE_SHA)
        self.assertEqual(g.sha((source/"core_assertions.py").read_bytes()),w.ASSERTIONS_SHA)

    def test_mismatched_host_pid_namespace_rejected_before_phone_access(self):
        if same_proc_namespace():self.assertEqual(w.require_host_proc_namespace()["pid"],os.getpid())
        else:
            with self.assertRaises((g.UnknownState,OSError)):w.require_host_proc_namespace()


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.root=Path(self.directory.name)
        self.args=arguments(self.root);self.phone=FakePhone(self.args,self.root)
        self.tx=w.Transaction(self.args,self.root,self.phone);self.clock=Clock()
        self.patches=[patch.object(w.time,"monotonic",self.clock.monotonic),patch.object(w.time,"sleep",self.clock.sleep)]
        for p in self.patches:p.start()

    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.directory.cleanup()

    def baseline(self):return self.tx.baseline(self.clock.now+1)

    def test_actual_readback_twice_and_original_global_preserved(self):
        self.baseline();self.tx.disable(self.clock.now+1)
        self.assertTrue(self.tx.state["offline_precondition_verified_twice"])
        self.assertEqual(self.phone.global_data,1)
        self.assertTrue(self.tx.restore())
        self.assertEqual((self.phone.wifi,self.phone.global_data,self.phone.selected),(1,1,1))
        self.assertTrue(self.tx.state["restoration"]["verified_twice"])
        self.assertFalse(self.tx.state["data_key_qualification"]["android16_helper_storage_chain_claimed"])

    def test_command_timeout_after_effect_still_restores_both(self):
        self.baseline();self.phone.fail_after_data_disable=True
        with self.assertRaises(TimeoutError):self.tx.disable(self.clock.now+1)
        saved=g.strict_json((self.root/"network-journal.json").read_bytes())
        self.assertEqual(saved["mutation_intents"],{"wifi":True,"data":True})
        self.assertEqual((self.phone.wifi,self.phone.selected),(0,0))
        self.assertTrue(self.tx.restore());self.assertEqual((self.phone.wifi,self.phone.selected),(1,1))

    def test_unchanged_selected_candidate_is_not_offline(self):
        self.baseline();self.phone.ignore_data_disable=True
        with self.assertRaises(TimeoutError):self.tx.disable(self.clock.now+0.1)
        self.assertNotIn("offline_precondition_verified_twice",self.tx.state)
        self.assertTrue(self.tx.restore())

    def test_sim_drift_prevents_observed_new_target_but_restores_wifi(self):
        self.baseline();self.tx.disable(self.clock.now+1);self.phone.sub=2
        self.assertFalse(self.tx.restore())
        self.assertEqual(self.phone.wifi,1)
        self.assertNotIn(("svc","data","enable"),self.phone.calls)
        self.assertTrue(self.tx.state["restoration"]["manual_restoration_required"])

    def test_prior_verified_result_cannot_survive_failed_retry(self):
        self.baseline();self.tx.disable(self.clock.now+1);self.assertTrue(self.tx.restore())
        self.phone.sub=2
        self.assertFalse(self.tx.restore())
        self.assertFalse(self.tx.state["restoration"]["verified"])
        self.assertTrue(self.tx.state["previous_restoration_attempts"][0]["verified"])


class FullFlowTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.root=Path(self.directory.name)
        self.args=arguments(self.root)
        adb=self.root/"adb-version-stub";adb.write_text("#!/bin/sh\nprintf 'Android Debug Bridge version 1.0.41\\n'\n");adb.chmod(0o700)
        self.core=self.root/"host_core_stub.py"
        self.core.write_text("import json,sys,time\nfrom pathlib import Path\np=Path(sys.argv[sys.argv.index('--output')+1]);p.mkdir()\n(p/'suite-result.json').write_text(json.dumps({'suite_verdict':'fail','core_functional_acceptance':'fail'}))\nsys.exit(2)\n")
        self.out=self.root/"output";self.out.mkdir(mode=0o700)

    def tearDown(self):self.directory.cleanup()

    def run_fake(self,phone):
        # The transaction tests isolate radio behavior from this executor's
        # nonstandard /proc mount. The real signal test below requires a matched
        # namespace and performs actual Linux child supervision.
        with patch.object(w,"frozen_suite",return_value=(self.core,{"cases":[]})),patch.object(w,"Phone",return_value=phone),\
             patch.object(w,"require_host_proc_namespace",return_value={"host_only_test":True}):
            return w.run(self.args,self.out)

    def test_functional_failure_and_radio_restoration_are_separate(self):
        phone=FakePhone(self.args,self.out)
        self.assertEqual(self.run_fake(phone),3)
        report=g.strict_json((self.out/"offline-result.json").read_bytes())
        self.assertEqual(report["verdict"],"completed_and_restored")
        self.assertEqual(report["core_functional_acceptance"],"fail")
        self.assertTrue(report["restoration"]["verified"])
        self.assertFalse(report["whole_device_continuous_network_absence_claimed"])

    def test_unknown_offline_network_never_starts_suite(self):
        phone=FakePhone(self.args,self.out);phone.invalid_offline_network=True
        self.assertEqual(self.run_fake(phone),3)
        report=g.strict_json((self.out/"offline-result.json").read_bytes())
        self.assertNotIn("suite",report);self.assertFalse((self.out/"suite").exists())
        self.assertTrue(report["restoration"]["verified"])

    @unittest.skipUnless(hasattr(os,"fork") and same_proc_namespace(),"requires matching Linux /proc PID namespace")
    def test_two_real_sigterms_do_not_interrupt_restore(self):
        self.core.write_text("import time\ntime.sleep(20)\n")
        self.args.restore_seconds=2
        child=os.fork()
        if child==0:
            try:
                phone=FakePhone(self.args,self.out);phone.slow_restore=True
                code=self.run_fake(phone)
                os._exit(0 if code==3 else 1)
            except BaseException:os._exit(2)
        reaped=False
        try:
            deadline=time.monotonic()+8
            while time.monotonic()<deadline:
                path=self.out/"network-journal.json"
                if path.exists() and g.strict_json(path.read_bytes()).get("suite"):break
                time.sleep(0.02)
            else:self.fail("benign host child did not start")
            os.kill(child,signal.SIGTERM);time.sleep(0.1);os.kill(child,signal.SIGTERM)
            while time.monotonic()<deadline:
                result,status=os.waitpid(child,os.WNOHANG)
                if result:
                    reaped=True;break
                time.sleep(0.02)
            else:self.fail("finally did not finish within host bound")
            self.assertEqual(os.waitstatus_to_exitcode(status),0)
            report=g.strict_json((self.out/"offline-result.json").read_bytes())
            self.assertTrue(report["restoration"]["verified"])
            self.assertFalse(report["offline_conditions_observed_through_normal_suite"])
            self.assertFalse(report["phone_cleanup_known"])
            self.assertTrue(report["manual_phone_task_review_required"])
            self.assertIsNotNone(report["suite"]["exit_code"])
        finally:
            if not reaped:
                try:os.kill(child,signal.SIGKILL)
                except ProcessLookupError:pass
                try:os.waitpid(child,0)
                except ChildProcessError:pass


if __name__=="__main__":unittest.main()
