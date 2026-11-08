#!/usr/bin/env python3
"""Offline tests: this module never invokes ADB or connects to a phone."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

SOURCE = Path(__file__).with_name('phone_acceptance.py')
spec = importlib.util.spec_from_file_location('hepta_acceptance', SOURCE)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
TASK, RUN, OBS = 'b'*32, 'a'*32, 'c'*32


def xml_view(value='95', package='com.example.calculator'):
    return {'xml': ET.fromstring('<hierarchy><node package="%s" text="%s" bounds="[0,0][100,100]"/></hierarchy>' % (package, value)),
            'focus_line': 'mCurrentFocus=Window{a u0 '+package+'/.Main}', 'focus_package': package}


class FakeAdb:
    instances = []
    missing_native = False
    reject = False
    corrupt_raw = False
    native_overrides = {}
    app_overrides = {}
    def __init__(self, args, evidence=None):
        self.launched = False; self.calls = []; self.request = None; self.instruction = args.instruction
        self.files = {}; self.instances.append(self)
    def command(self, command, **kwargs):
        label = kwargs.get('label'); self.calls.append((label, command, kwargs.get('input_data')))
        if label == 'app-uid': return 0, b'10042\n'
        if label == 'phone-clock': return 0, b'1800000000\n'
        if label == 'write-one-private-request':
            self.request = kwargs['input_data']; self.files['files/debug-task.json'] = self.request; return 0,b''
        if label == 'launch-once':
            if self.launched: raise AssertionError('task replayed')
            self.launched = True; request = json.loads(self.request)
            nonce_sha = m.digest(request['nonce'].encode())
            trigger = {'nonce_sha256':nonce_sha,'accepted':not self.reject,'private_request_consumed':not self.reject}
            session = {'debug_nonce_sha256':nonce_sha,'task_id':TASK,'status':'model_reported_done','running':False,'pending':False,'cleanup_known':True}
            result = {'task_id':TASK,'status':'model_reported_done','cleanup_known':True,'external_model':False}
            owner = {'task_id':TASK,'instruction':self.instruction,'instruction_utf8_sha256':m.digest(self.instruction.encode())}
            raw = b'{"action":"done"}'
            records = {'files/debug-trigger-result.json':trigger,'files/control-session.json':session,
                'files/control-tasks/'+TASK+'/owner.json':owner,'files/control-tasks/'+TASK+'/result.json':result,
                'files/control-tasks/'+TASK+'/step-01-before.json':{'observation_id':OBS},
                'files/control-tasks/'+TASK+'/step-01-model-0.json':{'run_id':RUN},
                'files/runs/'+RUN+'/app-receipt.json':{'schema':'hepta.appuid-probe.receipt.v1','package_name':m.PACKAGE,'app_uid':10042,'runtime':'qairt','compute_requested':'npu','native_result_binding_valid':True,'run_id':RUN,'process_exit_observed':True,'exit_code':0,'inference_completed':True},
                'files/runs/'+RUN+'/native-result.json':{'schema':'hepta.geniex-once.result.v1','request_id':RUN,
                    'runtime':'qairt','compute_requested':'npu','device_resolved':'NPU','device_warning':None,
                    'raw_text_utf8':True,'raw_text_sha256':m.digest(raw),'raw_text_bytes':len(raw),'generation_complete':True,'raw_text_truncated':False,'error':None}}
            records['files/runs/'+RUN+'/native-result.json'].update(self.native_overrides)
            records['files/runs/'+RUN+'/app-receipt.json'].update(self.app_overrides)
            self.files.update({k:json.dumps(v).encode() for k,v in records.items()})
            self.files['files/runs/'+RUN+'/raw-text.txt'] = b'corrupted' if self.corrupt_raw else raw
            self.files['files/runs/'+RUN+'/stderr.log'] = b'native diagnostic\n'
            if self.missing_native: del self.files['files/runs/'+RUN+'/native-result.json']
            return 0,b'Status: ok\n'
        return 0,b''
    def app_bytes(self, path, optional=False):
        if path in self.files: return self.files[path]
        if optional: return None
        raise m.DriverError('missing fixture '+path)
    def app_json(self, path, optional=True):
        data = self.app_bytes(path, optional); return None if data is None else m.strict_json(data)
    def list_children(self, path, directories=False):
        if directories: return [RUN] if self.launched and path=='files/runs' else []
        return sorted(p[len(path)+1:] for p in self.files if p.startswith(path+'/') and '/' not in p[len(path)+1:])


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        FakeAdb.instances=[]; FakeAdb.missing_native=False; FakeAdb.reject=False; FakeAdb.corrupt_raw=False
        FakeAdb.native_overrides={}; FakeAdb.app_overrides={}
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
    def args(self, **changes):
        a=dict(case_id='new-case',instruction='计算 37 加 58。',evidence_root=Path(self.temp.name),adb='/not/executed',
            adb_host='127.0.0.1',adb_port=12345,serial='FAKE',command_timeout=1,timeout=1,poll=.01,stop_grace=0,
            setup_home=False,include_screenshots=False,expected_package='com.example.calculator',expected_visible_text=['95'],text_match='exact')
        a.update(changes); return types.SimpleNamespace(**a)
    def run_fake(self, **changes):
        args=self.args(**changes)
        with patch.object(m,'Adb',FakeAdb), patch.object(m,'capture_ui',return_value=xml_view()), contextlib.redirect_stdout(io.StringIO()):
            code=m.run_task(args)
        return code,json.loads((args.evidence_root/args.case_id/'acceptance.json').read_text())
    def test_pass_requires_ui_and_native_receipts(self):
        code, report=self.run_fake(); self.assertEqual(code,0); self.assertTrue(report['native_receipts_verified'])
        self.assertEqual(sum(label=='launch-once' for label,_,_ in FakeAdb.instances[-1].calls),1)
    def test_model_done_wrong_visible_result_fails(self):
        code, report=self.run_fake(expected_visible_text=['96']); self.assertEqual(code,2); self.assertEqual(report['verdict'],'fail')
    def test_no_predicates_never_passes(self):
        code, report=self.run_fake(expected_package=None,expected_visible_text=[]); self.assertEqual(code,3); self.assertEqual(report['verdict'],'unverified')
    def test_missing_native_is_unverified(self):
        FakeAdb.missing_native=True; code,report=self.run_fake(); self.assertEqual(code,3); self.assertFalse(report['native_receipts_verified'])
    def test_corrupt_raw_is_unverified(self):
        FakeAdb.corrupt_raw=True; code,report=self.run_fake(); self.assertEqual(code,3); self.assertFalse(report['native_receipts_verified'])
    def test_native_backend_must_be_explicit_npu_without_warning(self):
        for i, changed in enumerate(({'runtime':'llama_cpp'}, {'compute_requested':'cpu'}, {'device_resolved':'CPU'}, {'device_warning':'fallback'})):
            FakeAdb.native_overrides=changed
            code,report=self.run_fake(case_id='backend-'+str(i))
            self.assertEqual(code,3); self.assertFalse(report['native_receipts_verified'])
    def test_native_utf8_claim_must_be_explicit(self):
        FakeAdb.native_overrides={'raw_text_utf8':False}
        code,report=self.run_fake(); self.assertEqual(code,3)
    def test_app_receipt_identity_and_binding_required(self):
        for i,changed in enumerate(({'package_name':'other.app'}, {'app_uid':10043}, {'native_result_binding_valid':False}, {'runtime':'llama_cpp'}, {'schema':'wrong'})):
            FakeAdb.app_overrides=changed
            code,report=self.run_fake(case_id='app-'+str(i)); self.assertEqual(code,3)
    def test_timeout_observer_never_suppresses_service_or_guesses_stop(self):
        fake=FakeAdb(self.args()); request={'nonce':'1'*64}; fake.request=json.dumps(request).encode()
        fake.command(['unused'],label='launch-once')
        fake.calls.clear()
        result=m.request_visible_stop(fake,Path(self.temp.name),m.digest(request['nonce'].encode()),TASK)
        self.assertFalse(result['clicked']); self.assertFalse(fake.calls)
    def test_shell_v2_binary_read_preserves_exit_contract(self):
        adb=m.Adb.__new__(m.Adb);adb.base=['/fake/adb','-H','127.0.0.1','-P','12345','-s','FAKE'];adb.timeout=1;adb.evidence=None;adb.sequence=0
        with patch.object(m.subprocess,'run',return_value=types.SimpleNamespace(returncode=40,stdout=b'',stderr=b'')) as run:
            self.assertIsNone(adb.app_bytes('files/missing.json',optional=True))
            self.assertEqual(run.call_args.args[0][7:9],['shell','-T']);self.assertNotIn('exec-out',run.call_args.args[0])
        with patch.object(m.subprocess,'run',return_value=types.SimpleNamespace(returncode=0,stdout=b'',stderr=b'')):
            with self.assertRaises(ValueError):adb.app_json('files/empty.json')
        with patch.object(m.subprocess,'run',return_value=types.SimpleNamespace(returncode=41,stdout=b'',stderr=b'')):
            with self.assertRaises(m.DriverError):adb.app_bytes('files/notregular.json',optional=True)
    def test_rejected_nonce_is_not_replayed(self):
        FakeAdb.reject=True; code,report=self.run_fake(); self.assertEqual(code,2); self.assertFalse(report['cleanup_unknown'])
        self.assertEqual(sum(label=='launch-once' for label,_,_ in FakeAdb.instances[-1].calls),1)
    def test_existing_case_refuses_before_adb(self):
        self.run_fake(); count=len(FakeAdb.instances)
        with patch.object(m,'Adb',FakeAdb),self.assertRaises(FileExistsError):m.run_task(self.args())
        self.assertEqual(len(FakeAdb.instances),count)
    def test_owner_is_stdin_data_not_shell(self):
        owner='原文 $(id) `test` "; echo unexpected; #'
        self.run_fake(instruction=owner)
        for label,cmd,stdin in FakeAdb.instances[-1].calls:
            self.assertNotIn(owner,' '.join(cmd))
            if label=='write-one-private-request':self.assertEqual(json.loads(stdin)['instruction'],owner)
    def test_exact_visible_text_and_focused_package(self):
        self.assertFalse(m.ui_predicates(xml_view('195'),'com.example.calculator',['95'])['all_passed'])
        altered=xml_view();altered['focus_package']='com.android.systemui'
        self.assertFalse(m.ui_predicates(altered,'com.example.calculator',['95'])['all_passed'])
    def test_failure_run_association_uses_owner_and_observation(self):
        owner='原文\nOWNER\n仍是原文'
        prompt='UNTRUSTED_DATA\n'+json.dumps({'screen':{'observation_id':OBS}})+'\nOWNER\n'+owner
        self.assertTrue(m.prompt_binding(prompt,owner,{OBS}))
        self.assertFalse(m.prompt_binding(prompt,owner,{'d'*32}))
        self.assertFalse(m.prompt_binding(prompt,owner+'修改',{OBS}))
    def test_stop_button_must_be_unique_enabled_focused(self):
        node='<node package="%s" text="停止" enabled="true" clickable="true" bounds="[10,20][90,60]"/>'%m.PACKAGE
        ui={'xml':ET.fromstring('<hierarchy>'+node+'</hierarchy>'),'focus_package':m.PACKAGE,'focus_line':'x'}
        self.assertEqual(m.stop_button(ui),(10,20,90,60))
        ui['xml']=ET.fromstring('<hierarchy>'+node+node+'</hierarchy>')
        with self.assertRaises(m.DriverError):m.stop_button(ui)
        ui['focus_package']='another.package'
        with self.assertRaises(m.DriverError):m.stop_button(ui)
    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(m.DriverError):m.strict_json(b'{"accepted":false,"accepted":true}')
    def test_collect_status_has_no_action(self):
        fake=FakeAdb(self.args()); m.current_status(fake)
        self.assertFalse(fake.launched); self.assertEqual(fake.calls,[])


if __name__=='__main__':unittest.main(verbosity=2)
