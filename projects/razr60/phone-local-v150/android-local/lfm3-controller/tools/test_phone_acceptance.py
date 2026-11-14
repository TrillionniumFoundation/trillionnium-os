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
    missing_offload_log = False
    native_overrides = {}
    app_overrides = {}
    def __init__(self, args, evidence=None):
        self.launched = False; self.calls = []; self.request = None; self.instruction = args.instruction
        self.files = {}; self.instances.append(self); self.compute=args.expected_compute; self.context=args.expected_context
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
            grammar=b'root ::= "fixture-only"\n'
            records = {'files/debug-trigger-result.json':trigger,'files/control-session.json':session,
                'files/control-tasks/'+TASK+'/owner.json':owner,'files/control-tasks/'+TASK+'/result.json':result,
                'files/control-tasks/'+TASK+'/step-01-before.json':{'observation_id':OBS,'package':'com.example.calculator'},
                'files/control-tasks/'+TASK+'/step-01-model-0.json':{'run_id':RUN},
                'files/runs/'+RUN+'/app-receipt.json':{'schema':'hepta.local-model.receipt.v2','package_name':m.PACKAGE,'app_uid':10042,'runtime':'llama_cpp','compute_requested':'npu','native_result_binding_valid':True,'run_id':RUN,'process_exit_observed':True,'exit_code':0,'inference_completed':True},
                'files/runs/'+RUN+'/native-result.json':{'schema':'hepta.geniex-once.result.v1','request_id':RUN,
                    'runtime':'llama_cpp','compute_requested':'npu','device_resolved':'HTP0','device_warning':None,
                    'raw_text_utf8':True,'raw_text_sha256':m.digest(raw),'raw_text_bytes':len(raw),'generation_complete':True,'raw_text_truncated':False,'error':None}}
            model_path='/data/user/0/'+m.PACKAGE+'/files/model/'+m.MODEL_FILE
            records['files/runs/'+RUN+'/app-receipt.json'].update({'mode':'llm','compute_requested':self.compute,
                'context_tokens':self.context,'model_profile':'lfm3-1.7b-qad-q4_0','model_sha256_verified':m.MODEL_SHA256,'model_path':model_path,
                'image_sent_to_model':False,'fallback_allowed':False,'native_context_budget_valid':True,
                'grammar_constraint_enabled':True,'grammar_binding_valid':True,'grammar_schema':'hepta.observed-action-gbnf.v1',
                'grammar_sha256':m.digest(grammar),'grammar_observation_id':OBS,'grammar_current_package':'com.example.calculator'})
            records['files/runs/'+RUN+'/native-result.json'].update({'mode':'llm','compute_requested':self.compute,
                'device_resolved':'HTP0' if self.compute=='npu' else 'GPUOpenCL', 'model_path':model_path,
                'n_ctx_create':self.context,'n_gpu_layers_create':-1,'max_tokens':256,
                'input_sha256':{'grammar':m.digest(grammar)},
                'model_profile':'lfm3-1.7b-qad-q4_0','model_sha256_verified':m.MODEL_SHA256,
                'model_architecture':'lfm3','model_bytes_verified':1049615680,'model_metadata_unchanged':True,
                'chat_template_enable_thinking':False,'automatic_cpu_fallback':False,'profile':{'prompt_tokens':200},
                'prompt_budget':{'method':'llama_tokenize_exact_same_input_ids','model_contract_sha256':m.MODEL_SHA256,
                    'tokenizer_source_commit':'19cce6919992fdffd92e0ac152caaf1e2b8f254e',
                    'checked':True,'admitted':True,'is_exact_token_count':True,'formatted_utf8_bytes':500,
                    'add_special':True,'parse_special':True,'input_ids_passed_directly':True,
                    'prompt_tokens_exact':200,'input_ids_count':200,'input_ids_sha256':'a'*64,
                    'generation_tokens':256,'reserved_tokens':256,'total_context_tokens':712,'context_tokens':self.context}})
            records['files/runs/'+RUN+'/native-result.json'].update(self.native_overrides)
            records['files/runs/'+RUN+'/app-receipt.json'].update(self.app_overrides)
            self.files.update({k:json.dumps(v).encode() for k,v in records.items()})
            self.files['files/runs/'+RUN+'/raw-text.txt'] = b'corrupted' if self.corrupt_raw else raw
            self.files['files/runs/'+RUN+'/grammar.gbnf']=grammar
            self.files['files/runs/'+RUN+'/stderr.log'] = ('llama_model_load: offloaded 25/25 layers to GPU\nllama_model_load: '+('HTP0' if self.compute=='npu' else 'OpenCL')+' model buffer size = 1000.00 MiB\n').encode()
            if self.missing_offload_log: self.files['files/runs/'+RUN+'/stderr.log']=b'CPU model buffer size = 1000.00 MiB\n'
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
        FakeAdb.missing_offload_log=False
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
    def args(self, **changes):
        a=dict(case_id='new-case',instruction='计算 37 加 58。',evidence_root=Path(self.temp.name),adb='/not/executed',
            adb_host='127.0.0.1',adb_port=12345,serial='FAKE',command_timeout=1,timeout=1,poll=.01,stop_grace=0,
            setup_home=False,include_screenshots=False,expected_package='com.example.calculator',expected_visible_text=['95'],text_match='exact',expected_compute='npu',expected_context=4096)
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
        for i, changed in enumerate(({'runtime':'qairt'}, {'compute_requested':'cpu'}, {'device_resolved':'CPU'}, {'device_warning':'fallback'})):
            FakeAdb.native_overrides=changed
            code,report=self.run_fake(case_id='backend-'+str(i))
            self.assertEqual(code,3); self.assertFalse(report['native_receipts_verified'])
    def test_native_utf8_claim_must_be_explicit(self):
        FakeAdb.native_overrides={'raw_text_utf8':False}
        code,report=self.run_fake(); self.assertEqual(code,3)
    def test_explicit_gpu_8k_can_qualify_without_fallback(self):
        code,report=self.run_fake(expected_compute='gpu',expected_context=8192)
        self.assertEqual(code,0);self.assertTrue(report['native_receipts_verified'])
    def test_gpu_log_label_does_not_relax_native_device_identity(self):
        for i,device in enumerate(('OpenCL','CPU','HTP0','GPUOpenCL_other')):
            FakeAdb.native_overrides={'device_resolved':device}
            code,report=self.run_fake(case_id='gpu-device-'+str(i),expected_compute='gpu')
            self.assertEqual(code,3);self.assertFalse(report['native_receipts_verified'])
    def test_resolved_device_without_actual_offload_never_qualifies(self):
        FakeAdb.missing_offload_log=True
        code,report=self.run_fake();self.assertEqual(code,3);self.assertFalse(report['native_receipts_verified'])
    def test_missing_or_wrong_native_context_contract_never_qualifies(self):
        for i,override in enumerate(({'prompt_budget':None},{'n_ctx_create':8192},{'n_gpu_layers_create':0})):
            FakeAdb.native_overrides=override
            code,report=self.run_fake(case_id='context-'+str(i));self.assertEqual(code,3)
    def test_wrong_model_pin_or_image_request_never_qualifies(self):
        for i,override in enumerate(({'model_sha256_verified':'0'*64},{'image_sent_to_model':True},{'fallback_allowed':True})):
            FakeAdb.app_overrides=override
            code,report=self.run_fake(case_id='model-'+str(i));self.assertEqual(code,3)
    def test_control_grammar_requires_actual_native_input_binding(self):
        for i,override in enumerate(({'input_sha256':None},{'input_sha256':{'grammar':'0'*64}})):
            FakeAdb.native_overrides=override
            code,report=self.run_fake(case_id='grammar-native-'+str(i));self.assertEqual(code,3)
        FakeAdb.native_overrides={}
        for i,override in enumerate(({'grammar_constraint_enabled':False},{'grammar_binding_valid':False},{'grammar_observation_id':'d'*32})):
            FakeAdb.app_overrides=override
            code,report=self.run_fake(case_id='grammar-app-'+str(i));self.assertEqual(code,3)
    def test_known_reason_first_schema_qualifies_without_changing_other_gates(self):
        FakeAdb.app_overrides={'grammar_schema':'hepta.observed-action-gbnf.v2-reason-first'}
        code,report=self.run_fake()
        self.assertEqual(code,0);self.assertTrue(report['native_receipts_verified'])
        self.assertTrue(report['collection']['associated_runs'][0]['controller_grammar_binding_valid'])
    def test_unknown_or_missing_grammar_schema_cannot_qualify(self):
        for i,schema in enumerate((None,'hepta.observed-action-gbnf.v2','hepta.observed-action-gbnf.v3',{})):
            FakeAdb.app_overrides={'grammar_schema':schema}
            code,report=self.run_fake(case_id='schema-'+str(i))
            self.assertEqual(code,3)
            self.assertFalse(report['collection']['associated_runs'][0]['controller_grammar_binding_valid'])
    def test_grammar_observed_package_must_match_real_before_observation(self):
        for i,package in enumerate((None,'com.android.settings','')):
            FakeAdb.app_overrides={'grammar_current_package':package}
            code,report=self.run_fake(case_id='package-'+str(i))
            self.assertEqual(code,3)
            self.assertFalse(report['collection']['associated_runs'][0]['controller_grammar_binding_valid'])
    def test_grammar_helper_rejects_hash_identity_and_conflicting_packages(self):
        grammar=b'root ::= "test"\n'; package='com.example.calculator'
        receipt={'grammar_schema':'hepta.observed-action-gbnf.v2-reason-first',
            'grammar_sha256':m.digest(grammar),'grammar_observation_id':OBS,'grammar_current_package':package}
        native={'input_sha256':{'grammar':m.digest(grammar)}}
        self.assertTrue(m.controller_grammar_binding_valid(receipt,native,grammar,{OBS:{package}}))
        for bindings in ({},{'d'*32:{package}},{OBS:{package,'com.android.settings'}},{OBS:{package,None}}):
            self.assertFalse(m.controller_grammar_binding_valid(receipt,native,grammar,bindings))
        self.assertFalse(m.controller_grammar_binding_valid({**receipt,'grammar_sha256':'0'*64},native,grammar,{OBS:{package}}))
        self.assertFalse(m.controller_grammar_binding_valid(receipt,{'input_sha256':{'grammar':'0'*64}},grammar,{OBS:{package}}))
        self.assertFalse(m.controller_grammar_binding_valid(receipt,native,grammar+b' ',{OBS:{package}}))
    def test_app_receipt_identity_and_binding_required(self):
        for i,changed in enumerate(({'package_name':'other.app'}, {'app_uid':10043}, {'native_result_binding_valid':False}, {'runtime':'qairt'}, {'schema':'wrong'})):
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


class AcceleratorLogEvidenceTests(unittest.TestCase):
    layers = 'load_tensors: offloaded 43/43 layers to GPU'
    gpu_buffer = 'load_tensors:       OpenCL model buffer size = 3023.23 MiB'
    npu_buffer = 'load_tensors:         HTP0 model buffer size = 3257.16 MiB'

    def evidence(self, *lines, compute='gpu'):
        return m.accelerator_log_evidence('\n'.join(lines), compute)

    def test_real_historical_gpu_and_npu_excerpts(self):
        for compute,device,buffer_name in (('gpu','GPUOpenCL','OpenCL'),('npu','HTP0','HTP0')):
            path=Path(__file__).parent/'fixtures'/'accelerator-logs'/('bolt-'+compute+'-historical.json')
            fixture=json.loads(path.read_text())
            self.assertRegex(fixture['source_log_sha256'], r'^[0-9a-f]{64}$')
            self.assertTrue(fixture['historical_fixture_only'])
            self.assertEqual(fixture['native_expected_fields']['device_resolved'],device)
            result=self.evidence(*(line['text'] for line in fixture['selected_lines']),compute=compute)
            self.assertTrue(result['accelerator_offload_observed'])
            self.assertEqual(result['device'],device)
            self.assertEqual(result['model_buffer_device'],buffer_name)
            self.assertEqual(result['offloaded_layers_observed'],43)
            self.assertEqual(len(result['model_buffer_lines']),1)
            self.assertFalse(result['full_operator_coverage_proven'])

    def test_completed_v25_gpu_fixtures_match_the_pinned_log_format(self):
        for case in ('bolt-apps','bolt-calculator'):
            path=Path(__file__).parent/'fixtures'/'accelerator-logs'/(case+'-v25.json')
            fixture=json.loads(path.read_text())
            self.assertRegex(fixture['source_log_sha256'], r'^[0-9a-f]{64}$')
            self.assertRegex(fixture['native_result_sha256'], r'^[0-9a-f]{64}$')
            self.assertEqual(fixture['native_expected_fields']['compute_requested'],'gpu')
            self.assertEqual(fixture['native_expected_fields']['device_resolved'],'GPUOpenCL')
            result=self.evidence(*(line['text'] for line in fixture['selected_lines']))
            self.assertTrue(result['accelerator_offload_observed'])
            self.assertEqual(result['offloaded_layers_observed'],43)
            self.assertEqual(result['model_buffer_device'],'OpenCL')
            self.assertEqual(len(result['model_buffer_lines']),1)
            self.assertFalse(fixture['phone_task_qualified_by_fixture'])

    def test_positive_buffer_and_positive_offload_are_both_required(self):
        for lines in ((),(self.layers,),(self.gpu_buffer,),
                ('load_tensors: offloaded 0/43 layers to GPU',self.gpu_buffer),
                (self.layers,'load_tensors: OpenCL model buffer size = 0.00 MiB')):
            with self.subTest(lines=lines):
                self.assertFalse(self.evidence(*lines)['accelerator_offload_observed'])

    def test_cpu_other_backend_and_device_mentions_cannot_supply_gpu_buffer(self):
        for line in (
                'load_tensors: CPU model buffer size = 4000.00 MiB',
                'load_tensors: CPU_Mapped model buffer size = 4000.00 MiB',
                'load_tensors: GPUOpenCL model buffer size = 4000.00 MiB',
                'load_tensors: OpenCL_Host model buffer size = 4000.00 MiB',
                'load_tensors: OtherOpenCL model buffer size = 4000.00 MiB',
                'load_tensors: OpenCL0 model buffer size = 4000.00 MiB',
                'load_tensors: CPU model buffer size = 4000.00 MiB (GPUOpenCL requested)',
                self.npu_buffer):
            with self.subTest(line=line):
                self.assertFalse(self.evidence(self.layers,line)['accelerator_offload_observed'])
        self.assertFalse(self.evidence(self.layers,self.gpu_buffer,compute='npu')['accelerator_offload_observed'])

    def test_zero_gpu_size_cannot_borrow_positive_cpu_or_another_number(self):
        zero='load_tensors: OpenCL model buffer size = 0.00 MiB'
        cpu='load_tensors: CPU model buffer size = 4000.00 MiB'
        for lines in ((self.layers,zero,cpu),
                (self.layers,zero+'; total size = 4000.00 MiB'),
                (self.layers,'load_tensors: OpenCL model buffer 4000.00 MiB size = 0.00 MiB')):
            with self.subTest(lines=lines):
                self.assertFalse(self.evidence(*lines)['accelerator_offload_observed'])

    def test_only_the_complete_native_record_is_positive_evidence(self):
        for changed in ('warning: '+self.gpu_buffer,'"'+self.gpu_buffer+'"',
                '{"message":"'+self.gpu_buffer+'"}',self.gpu_buffer+' was not allocated',
                '[DEBUG] [other.cpp:52:message] '+self.gpu_buffer,
                'owner text\u2028'+self.gpu_buffer):
            with self.subTest(changed=changed):
                self.assertFalse(self.evidence(self.layers,changed)['accelerator_offload_observed'])
        for changed in ('expected '+self.layers,'"'+self.layers+'"',
                'load_tensors: notoffloaded 43/43 layers to GPU',
                'load_tensors: offloaded 43/43 layers to CPU',self.layers+' was not completed'):
            with self.subTest(changed=changed):
                self.assertFalse(self.evidence(changed,self.gpu_buffer)['accelerator_offload_observed'])

    def test_malformed_sizes_and_layer_counts_cannot_qualify(self):
        for size in ('-1.0','+1.0','nan','inf','1e9','1.2.3','1,000','\uff11.0'):
            with self.subTest(size=size):
                self.assertFalse(self.evidence(self.layers,
                    'load_tensors: OpenCL model buffer size = '+size+' MiB')['accelerator_offload_observed'])
        for counts in ('0/43','43/0','44/43','-1/43','+1/43','1.0/43','\uff11/43'):
            with self.subTest(counts=counts):
                self.assertFalse(self.evidence('load_tensors: offloaded '+counts+' layers to GPU',
                    self.gpu_buffer)['accelerator_offload_observed'])

    def test_native_color_wrapping_and_crlf_do_not_hide_valid_records(self):
        prefix='[DEBUG] [plugins/llama_cpp/src/plugin.cpp:52:ggml_to_geniex_log] '
        log='\r\n'.join('\x1b[34m'+prefix+line+'\x1b[0m' for line in (self.layers,self.gpu_buffer))+'\r\n'
        self.assertTrue(m.accelerator_log_evidence(log,'gpu')['accelerator_offload_observed'])

    def test_positive_partial_offload_retains_fallback_and_coverage_limit(self):
        warning='backend: unsupported operator; CPU fallback remains'
        result=self.evidence('load_tensors: offloaded 1/43 layers to GPU',self.gpu_buffer,warning)
        self.assertTrue(result['accelerator_offload_observed'])
        self.assertEqual(result['offloaded_layers_observed'],1)
        self.assertEqual(result['fallback_lines'],[warning])
        self.assertFalse(result['full_operator_coverage_proven'])


if __name__=='__main__':unittest.main(verbosity=2)
