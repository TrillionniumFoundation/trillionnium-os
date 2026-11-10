#!/usr/bin/env python3
"""One reviewed scoped Orvena/v32 qualification stage; never an automatic phone sequence.

Default/plan, prepare, probe-review and ordinary-review are host-only. Every
phone stage needs --execute --exclusive-idle-window, the exact package SHA and
the prior receipt SHA. NPU and GPU are separate fixed axes, never a fallback.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'drivers'))
from types import ModuleType
_scope_path = Path(__file__).resolve().parent / "drivers/qualification_scope.py"
_scope_raw = _scope_path.read_bytes()
qs = ModuleType("qualification_scope"); qs.__file__ = str(_scope_path)
sys.modules["qualification_scope"] = qs
exec(compile(_scope_raw, str(_scope_path), "exec", dont_inherit=True), qs.__dict__)
Q=None;PACKAGE_MANIFEST=None;SOURCE=None;APK_SHA=None;BUILD_ASSET_SHA=None;UID=None;CONFIG_SHAS={}
PACKAGE='org.trillionnium.hepta.local'
MODEL_SHA=qs.MODEL_SHA;MODEL_BYTES=qs.MODEL_BYTES;MODEL_FILE='Orvena-4B.Q4_K_M.gguf';PROFILE=qs.PROFILE
PROMPT = '手机上的计算器通常用来做什么？用一句简短中文回答。'
SYSTEM = '你是在手机本地运行的助手。直接用简体中文回答，不调用工具。'
MAX_TOKENS = 64
TIMEOUT_MS = 120000
SAMPLER=qs.expected_sampler()
LLAMA = '19cce6919992fdffd92e0ac152caaf1e2b8f254e'
SDK = '071f609995470bdb0e0769ab964754adfaab7e47'
HEX = re.compile(r'[a-f0-9]{64}\Z')
RUN = re.compile(r'[a-f0-9]{32}\Z')
CASE_IDS = ('core-settings-home-01', 'core-settings-apps-01', 'core-calculator-keypad-01',
            'core-settings-chinese-search-01', 'core-search-return-home-01', 'core-settings-home-settings-01',
            'core-cross-app-01', 'core-settings-scroll-01', 'core-find-calculator-01')
RUN_ARTIFACTS = ('app-receipt.json', 'native-result.json', 'prompt.txt', 'system.txt',
                 'formatted-prompt.txt', 'formatted-input-ids.le32', 'prompt-evidence.json',
                 'raw-text.txt', 'stdout.log', 'stderr.log')


def need(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode()


def read(path, limit=16 << 20):
    path = Path(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit,
         'nonregular/linked/oversized file: ' + str(path))
    raw = path.read_bytes()
    after = path.stat()
    need(len(raw) == before.st_size and
         all(getattr(before, field) == getattr(after, field) for field in
             ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')), 'file changed while read')
    return raw


def put(path, raw):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def save(path, value):
    put(path, encoded(value))


def bound(path, expected):
    need(isinstance(expected, str) and HEX.fullmatch(expected), 'explicit SHA256 required')
    raw = read(path)
    need(sha(raw) == expected, 'receipt/file SHA differs: ' + str(path))
    return strict(raw)


def module(path, name):
    path = Path(path).resolve(strict=True); raw = read(path)
    result = ModuleType(name); result.__file__ = str(path)
    sys.modules[name] = result
    exec(compile(raw, str(path), "exec", dont_inherit=True), result.__dict__)
    return result


def configure(args):
    global Q,PACKAGE_MANIFEST,SOURCE,APK_SHA,BUILD_ASSET_SHA,UID,CONFIG_SHAS,SAMPLER
    PACKAGE_MANIFEST=qs.verify_package(HERE,args.package_sha256)
    Q=qs.load_binding(args.qualification_binding,args.qualification_binding_sha256)
    need(Q['candidate']['compute']==args.axis,'another axis needs its own explicit config/scope binding')
    SOURCE=Path(Q['source_directory']);APK_SHA=Q['candidate']['apk_sha256'];BUILD_ASSET_SHA=Q['build_identity_sha256'];UID=Q['app_uid']
    CONFIG_SHAS={args.axis:Q['runtime_config_sha256']};SAMPLER=qs.expected_sampler()

def config(axis):
    need(Q is not None and axis==Q['candidate']['compute'],'explicit bound axis required')
    return Q['runtime_config']


def candidate(axis):
    config(axis);return Q['candidate']


def verify_package(expected):
    return qs.verify_package(HERE,expected)


def ordinary(axis):
    config(axis)
    value=module(HERE/'ordinary/ordinary_launcher.py','orvena_scoped_stage_'+axis)
    value.configure(Q,PACKAGE_MANIFEST)
    return value


def phone_args(args):
    need(args.execute and args.exclusive_idle_window,
         'phone stage requires --execute --exclusive-idle-window; host plan does not execute it')
    qs.require_device_target(args,Q)
    need(isinstance(args.adb,str) and Path(args.adb).is_absolute() and Path(args.adb).is_file()
         and os.access(args.adb, os.X_OK), 'explicit existing absolute adb executable required')
    need(args.adb_host in ('127.0.0.1','::1') and type(args.adb_port) is int and 1 <= args.adb_port <= 65535,
         'explicit existing loopback ADB endpoint required')
    return SimpleNamespace(adb=args.adb, adb_host=args.adb_host, adb_port=args.adb_port, **Q['device_target'],
                           qualification_binding=Path(Q['binding_path']), qualification_binding_sha256=Q['binding_sha256'],
                           command_timeout=15, arm_timeout=600,
                           poll_seconds=1, minimum_background_samples=3,
                           execute=True, exclusive_idle_window=True)


def stage_result(args,stage,**fields):
    return dict(schema='hepta.orvena-v32-scoped-stage-result.v1',stage=stage,axis=args.axis,
        package_sha256=args.package_sha256,candidate=candidate(args.axis),
        actual_build_identity_sha256=Q['build_identity_sha256'],complete_source_inventory_sha256=Q['complete_source_inventory_sha256'],
        source_commit=Q['source_commit'],runtime_config_sha256=Q['runtime_config_sha256'],
        qualification_binding_sha256=Q['binding_sha256'],expected_scope_sha256=Q['scope_sha256'],
        automatic_retry=False,automatic_fallback=False,**fields)


def prior(args,path,expected,stage,*,allow_other_axis=False):
    result=bound(path,expected)
    need(result.get('schema')=='hepta.orvena-v32-scoped-stage-result.v1' and result.get('stage')==stage
         and result.get('status')=='complete' and result.get('package_sha256')==args.package_sha256
         and result.get('actual_build_identity_sha256')==Q['build_identity_sha256']
         and result.get('qualification_binding_sha256')==Q['binding_sha256']
         and result.get('expected_scope_sha256')==Q['scope_sha256']
         and result.get('axis')==args.axis and result.get('candidate')==candidate(args.axis)
         and result.get('runtime_config_sha256')==Q['runtime_config_sha256'],'prior stage not complete/bound')
    return result


def new_output(path):
    path = Path(path).resolve()
    path.mkdir(parents=True, exist_ok=False, mode=0o700)
    return path


def reserve(directory, name, args, details=None):
    save(Path(directory) / (name + '-reservation.json'),
         stage_result(args, name, status='reserved_before_uncertain_action',
                      attempts=1, details=details or {}, wall_ms=int(time.time() * 1000)))


def call(argv, output, label, timeout=None):
    save(output / (label + '-COMMAND.json'), dict(argv=argv, timeout_seconds=timeout, automatic_retry=False))
    with (output / (label + '.stdout')).open('xb') as stdout, (output / (label + '.stderr')).open('xb') as stderr:
        result = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=timeout, check=False)
    save(output / (label + '-EXIT.json'), dict(exit_code=result.returncode, phone_success_inferred=False))
    return result.returncode


def current_source_contract():
    value=strict(Q['raw_files']['build-identity.json'])
    for row in value['source_inputs']:
        need(sha(read(SOURCE/row['path'],32<<20))==row['sha256'],'actual compiler input changed: '+row['path'])














def validate_core_plan(raw, axis):
    value = strict(raw)
    need(value.get('candidate') == candidate(axis), 'core candidate differs')
    cases = value.get('cases', [])
    need([case.get('case_id') for case in cases] == list(CASE_IDS)
         and all(case.get('timeout_seconds') == 540 for case in cases), 'full-nine case order/budget differs')
    need(cases == strict(read(HERE / 'reference/core-cases.json')), 'case contracts were changed')
    return value


def do_prepare(args):
    current_source_contract()
    selected=bound(args.selection_result,args.selection_result_sha256)
    selection=Path(args.selection_result).resolve().parent
    need(Path(args.selection_result).name=='RESULT.json','original selector result name required')
    o=ordinary(args.axis);o.host_contract()
    out=new_output(args.output);child=out/'ordinary'
    argv=[sys.executable,'-B',str(Path(o.__file__)),
        '--qualification-binding',Q['binding_path'],'--qualification-binding-sha256',Q['binding_sha256'],
        '--package-sha256',args.package_sha256,'prepare','--selection',str(selection),
        '--selection-result-sha256',args.selection_result_sha256,'--upgrade-proof',str(args.upgrade_proof),
        '--upgrade-proof-sha256',args.upgrade_proof_sha256,'--upgrade-helper',str(args.upgrade_helper),
        '--selector-helper',str(args.selector_helper),'--output',str(child)]
    need(call(argv,out,'ordinary-prepare',120)==0,'ordinary scoped host preparation failed')
    core_path=out/'core-plan.json'
    argv=[sys.executable,'-B',str(HERE/'core/core_phone_suite.py'),'freeze','--drivers',str(HERE/'drivers'),
        '--candidate',str(child/'candidate.json'),'--suite-id','orvena-v32-'+args.axis+'-8192-core9-r1','--output',str(core_path)]
    need(call(argv,out,'core-freeze',60)==0,'core freeze failed')
    argv=[sys.executable,'-B',str(HERE/'core/core_phone_suite.py'),'validate',str(core_path)]+qualification_arguments()
    need(call(argv,out,'core-validate',60)==0,'core plan validation failed')
    raw=read(core_path);validate_core_plan(raw,args.axis)
    save(out/'RESULT.json',stage_result(args,'prepare',status='complete',phone_contacted=False,
        selection_original=str(Path(args.selection_result).resolve()),selection_original_sha256=args.selection_result_sha256,
        ordinary_prepared=str(child),ordinary_prepared_sha256=sha(read(child/'PREPARED.json')),
        core_plan=str(core_path),core_plan_sha256=sha(raw),model_load_qualified=False,tool_accuracy_assessed=False))
    return 0


def prepared(args):
    value=prior(args,args.prepared_result,args.prepared_result_sha256,'prepare')
    bound(value['selection_original'],value['selection_original_sha256'])
    raw=read(value['core_plan']);need(sha(raw)==value['core_plan_sha256'],'core plan changed')
    validate_core_plan(raw,args.axis)
    o=ordinary(args.axis)
    a=SimpleNamespace(prepared=Path(value['ordinary_prepared']),prepared_sha256=value['ordinary_prepared_sha256'])
    return value,o,o.prepared(a)

def qualification_arguments():
    return ['--qualification-binding',Q['binding_path'],'--qualification-binding-sha256',Q['binding_sha256']]

def scope_activation(args):
    value=prior(args,args.scope_activation,args.scope_activation_sha256,'scope-install')
    need(value.get('prepared_result_sha256')==args.prepared_result_sha256
         and value.get('scope_present_verified') is True and value.get('cleanup_known') is True,'scope activation missing')
    return value

def scope_stage(args):
    value,o,data=prepared(args);a=phone_args(args);out=new_output(args.output)
    p,pv,m,plan,ac,iv,suite=data
    removing=args.mode=='scope-remove'
    if removing:scope_activation(args)
    result=stage_result(args,args.mode,status='blocked',phone_contacted=False,phone_write_count=0,cleanup_known=False,
        prepared_result_sha256=args.prepared_result_sha256,scope_present_verified=False)
    try:
        result['phone_contacted']=True
        ro,cli,parent,before=o.live(a,out,m,plan,ac,iv,require_scope=removing)
        current=ro.app_bytes('files/qualification-scope.json',optional=True)
        if removing:
            need(current==Q['raw_files']['qualification-scope.json'],'only exact owned scope may be removed')
            reserve(Path(args.prepared_result).parent,'scope-remove',args,{'output':str(out)})
            script='test -f files/qualification-scope.json && test ! -L files/qualification-scope.json && test "$(sha256sum files/qualification-scope.json | cut -d " " -f 1)" = '+Q['scope_sha256']+' && rm -- files/qualification-scope.json'
            result['phone_write_count']=1
            cli.command(['run-as',PACKAGE,'--user','0','sh','-c',script],label='remove-exact-owned-scope-once')
            need(ro.app_bytes('files/qualification-scope.json',optional=True) is None,'scope removal not observed')
            # A new ordinary launcher Intent clears the UI-only prefill claim;
            # it does not submit any task or change a running task's captured scope.
            launch=['am','start','-W','--user','0','-a','android.intent.action.MAIN','-c','android.intent.category.LAUNCHER','-n',PACKAGE+'/.MainActivity']
            save(out/'CLEAR-PREFILL-INTENT.json',dict(argv=launch,attempts=1,task_started=False))
            result['phone_write_count']=2
            _,ack=cli.command(launch,label='fresh-normal-main-after-scope-removal',timeout=30)
            need(re.search(rb'(?m)^Status: ok\s*$',ack),'fresh normal UI launch not acknowledged; no retry')
            plain={k:v for k,v in plan.items() if k not in ('_qualification','_scope_module')}
            after=m.idle_snapshot(ro,UID,plain);m.parent_identity(ro,parent)
            # before included the scope hash; all journals/config must still agree.
            expected=dict(before);expected['hashes']=dict(before['hashes']);expected['hashes'].pop('qualification-scope.json',None)
            need(after==expected and ro.app_bytes('files/qualification-scope.json',optional=True) is None,'removal changed task/config or scope reappeared')
            focus=ro.focus();need(focus['package']==PACKAGE and focus['component']==PACKAGE+'.MainActivity','fresh daily UI not observed')
            result.update(status='complete',cleanup_known=True,scope_absent_verified=True,daily_ui_prefill_cleared_by_normal_intent=True,after=after)
        else:
            need(current is None or current==Q['raw_files']['qualification-scope.json'],'another scope already present')
            reserve(Path(args.prepared_result).parent,'scope-install',args,{'output':str(out)})
            if current is None:
                script='umask 077; if [ -e files/qualification-scope.json ] || [ -L files/qualification-scope.json ]; then exit 42; fi; set -C; cat > files/qualification-scope.json'
                result['phone_write_count']=1
                cli.command(['run-as',PACKAGE,'--user','0','sh','-c',script],label='create-scope-once',input_data=Q['raw_files']['qualification-scope.json'])
            qs.fresh_files(ro,Q)
            after=m.idle_snapshot(ro,UID,plan);m.parent_identity(ro,parent)
            comparable=dict(after);comparable['hashes']=dict(after['hashes']);comparable['hashes'].pop('qualification-scope.json',None)
            need(comparable==before,'scope installation changed journals/runtime')
            result.update(status='complete',cleanup_known=True,scope_present_verified=True,scope_preexisted_identically=current is not None,after=after)
    except Exception as error:
        result['error']=type(error).__name__+': '+str(error)
    result['finished_wall_ms']=int(time.time()*1000);save(out/'RESULT.json',result)
    return 0 if result['status']=='complete' else 3


def same_json(left, right):
    """Compare Android-reencoded JSON; bool is not a number, 1 and 1.0 may agree."""
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is bool and type(right) is bool and left == right
    if left is None or right is None:
        return left is None and right is None
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(same_json(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(same_json(a, b) for a, b in zip(left, right))
    return left == right


def validate_probe_bytes(files, axis, run_id, parent, acceptance):
    """Recompute App/native/input-ID/output bindings; no cached PASS is sufficient."""
    need(set(files) == set(RUN_ARTIFACTS) and RUN.fullmatch(run_id), 'probe artifacts incomplete')
    app, native, evidence = (strict(files[name]) for name in ('app-receipt.json', 'native-result.json', 'prompt-evidence.json'))
    raw, formatted, ids = (files[name] for name in ('raw-text.txt', 'formatted-prompt.txt', 'formatted-input-ids.le32'))
    text = raw.decode('utf-8', 'strict')
    need(bool(text.strip()) and '\x00' not in text and '\ufffd' not in text, 'empty/invalid diagnostic output')
    need(app.get('status') == 'completed' and 'error' in app and app['error'] is None
         and app.get('cancel_requested') is False, 'App completion/cancellation/error differs')
    need(app.get('raw_text_sha256_read') == sha(raw) and app.get('raw_text_file') in
         ('/data/user/0/' + PACKAGE + '/files/runs/' + run_id + '/raw-text.txt',
          '/data/data/' + PACKAGE + '/files/runs/' + run_id + '/raw-text.txt'),
         'App raw text identity differs')
    need(files['prompt.txt'] == PROMPT.encode() and files['system.txt'] == SYSTEM.encode(), 'diagnostic input bytes differ')
    need(app.get('schema') == 'hepta.local-model.receipt.v2' and app.get('run_id') == run_id
         and app.get('package_name') == PACKAGE and app.get('app_uid') == UID and parent.get('uid') == UID
         and app.get('app_pid') == parent.get('pid') and app.get('expected_parent_pid') == parent.get('pid')
         and app.get('model_profile') == PROFILE and app.get('compute_requested') == axis
         and app.get('context_tokens') == 8192 and app.get('runtime') == 'llama_cpp' and app.get('mode') == 'llm'
         and app.get('model_sha256_verified') == MODEL_SHA, 'App probe identity differs')
    for key in ('parent_death_guard_requested', 'process_started', 'process_exit_observed', 'inference_completed',
                'native_result_binding_valid', 'runtime_device_selection_valid', 'native_context_budget_valid', 'grammar_binding_valid'):
        need(app.get(key) is True, 'App probe proof lacks ' + key)
    for key in ('timeout_observed', 'fallback_allowed', 'image_sent_to_model', 'grammar_constraint_enabled', 'automatic_retry'):
        need(app.get(key) is False, 'unexpected App probe mode: ' + key)
    need(type(app.get('exit_code')) is int and app['exit_code'] == 0, 'native exit not successful')
    need(native.get('schema') == 'hepta.geniex-once.result.v1' and native.get('request_id') == run_id
         and native.get('runtime') == 'llama_cpp' and native.get('mode') == 'llm'
         and native.get('compute_requested') == axis and native.get('device_resolved') == ('HTP0' if axis == 'npu' else 'GPUOpenCL')
         and 'device_warning' in native and native['device_warning'] is None
         and native.get('n_ctx_create') == 8192 and native.get('max_tokens') == MAX_TOKENS
         and type(native.get('n_gpu_layers_create')) is int and native['n_gpu_layers_create'] != 0
         and native.get('sdk_source_commit') == SDK and native.get('sdk_version') in ('0.10.0', 'v0.10.0')
         and native.get('automatic_retry') is False and native.get('generate_attempt_count') == 1,
         'native request/backend/config differs')
    need(qs.sampler_valid(native.get('sampler_requested')), 'actual v32 requested F32 sampler differs')
    # A successful one-shot producer attempts every lifecycle call.  Its
    # json_rc writer emits null when a call was not attempted; cached App
    # validity flags and generation_complete do not substitute for these
    # original native return codes.
    sdk_rc = native.get('sdk_rc')
    sdk_calls = {'resolve', 'set_log_level', 'init', 'create', 'template', 'generate', 'destroy', 'deinit'}
    need(isinstance(sdk_rc, dict) and set(sdk_rc) == sdk_calls
         and all(type(value) is int and value == 0 for value in sdk_rc.values()),
         'native SDK lifecycle incomplete or unsuccessful')
    need(acceptance.native_budget_valid(native, 8192, PROFILE), 'native exact admission invalid')
    model_path = native.get('model_path')
    need(model_path in ('/data/user/0/' + PACKAGE + '/files/model/' + MODEL_FILE,
                        '/data/data/' + PACKAGE + '/files/model/' + MODEL_FILE)
         and model_path == app.get('model_path'), 'native private model path differs')
    need(native.get('generation_complete') is True and native.get('raw_text_present') is True
         and native.get('raw_text_truncated') is False and native.get('raw_text_utf8') is True
         and native.get('raw_text_bytes') == len(raw) and native.get('raw_text_sha256') == sha(raw)
         and native.get('input_metadata_unchanged') is True and native.get('worker_exit_status_planned') == 0
         and native.get('error', 'missing') is None and native.get('stop_reason') in ('eos', 'stop_sequence'),
         'native output/completion invalid')
    source_inputs = dict(prompt=sha(PROMPT.encode()), system=sha(SYSTEM.encode()), grammar=None, image=None)
    need(native.get('input_sha256') == source_inputs and evidence.get('source_input_sha256') == source_inputs,
         'native prompt/system/grammar/image binding differs')
    budget = native['prompt_budget']
    need(0 < len(formatted) <= 262144 and native.get('formatted_prompt_sha256') == sha(formatted)
         and budget.get('formatted_utf8_bytes') == len(formatted) and len(ids) == 4 * budget['prompt_tokens_exact']
         and budget.get('input_ids_sha256') == sha(ids), 'actual formatted prompt/input IDs differ')
    need(evidence.get('schema') == 'hepta.private-prompt-evidence.v1' and evidence.get('request_id') == run_id
         and evidence.get('model_profile') == PROFILE and evidence.get('model_sha256') == MODEL_SHA
         and evidence.get('sdk_source_commit') == SDK and evidence.get('llama_source_commit') == LLAMA
         and evidence.get('formatted_prompt_sha256') == sha(formatted) and evidence.get('formatted_prompt_bytes') == len(formatted)
         and evidence.get('input_ids_count') == budget['prompt_tokens_exact'] and evidence.get('input_ids_bytes') == len(ids)
         and evidence.get('input_ids_encoding') == 'uint32-little-endian' and evidence.get('input_ids_sha256') == sha(ids),
         'private exact-input evidence differs')
    for key in ('input_ids_will_be_passed_directly', 'add_special', 'parse_special', 'use_jinja', 'add_generation_prompt'):
        need(evidence.get(key) is True, 'native evidence missing ' + key)
    for key in ('chat_template_override', 'enable_thinking', 'native_tools_argument', 'action_authorized'):
        need(evidence.get(key) is False, 'unexpected native evidence flag ' + key)
    pe = native.get('prompt_evidence', {})
    need(pe.get('schema') == 'hepta.private-prompt-evidence.v1' and pe.get('complete') is True, 'native prompt evidence incomplete')
    for key, filename in (('formatted_file', 'formatted-prompt.txt'), ('input_ids_file', 'formatted-input-ids.le32'), ('metadata_file', 'prompt-evidence.json')):
        need(pe.get(key) in ('/data/user/0/' + PACKAGE + '/files/runs/' + run_id + '/' + filename,
                            '/data/data/' + PACKAGE + '/files/runs/' + run_id + '/' + filename), 'private native evidence path differs')
    log = files['stderr.log'].decode('utf-8', 'replace')
    bootstrap = re.findall(r'(?m)^HEPTA_APPUID_BOOTSTRAP uid=(\d+) euid=(\d+) pid=(\d+) plugin=llama_cpp register_rc=0 runtime=([^\r\n]+)$', log)
    need(len(bootstrap) == 1 and tuple(map(int, bootstrap[0][:3])) == (UID, UID, native.get('pid')), 'native App UID/bootstrap PID differs')
    parents = re.findall(r'(?m)^HEPTA_PARENT_GUARD armed expected=(\d+) observed=(\d+) signal=SIGKILL$', log)
    need(len(parents) == 1 and tuple(map(int, parents[0])) == (parent['pid'], parent['pid']), 'native parent guard differs')
    offload = acceptance.accelerator_log_evidence(log, axis)
    need(offload['accelerator_offload_observed'] is True, 'positive selected-accelerator tensor evidence missing')
    need(isinstance(app.get('native_receipt'), dict) and same_json(app['native_receipt'], native),
         'App embedded native receipt differs from original')
    return dict(native_qualified=True, app_uid=UID, parent_pid=parent['pid'], worker_pid=native['pid'],
                run_id=run_id, resolved_device=native['device_resolved'], native_prompt_budget=native['prompt_budget'],
                runtime_profile=native.get('profile'), accelerator_evidence=offload,
                sampler_requested=native['sampler_requested'], sampler_scope='v32 requested F32 numeric policy; not a claim of optimal task sampling',
                raw_text_sha256=sha(raw), raw_text_bytes=len(raw), raw_text=text,
                text_integrity='requires_independent_review', ground_truth='not_assessed',
                controller_grammar_exercised=False, business_goal_assessed=False, full_operator_coverage_proven=False)


def do_probe(args):
    v, o, data = prepared(args)
    a = phone_args(args)
    a.prepared, a.prepared_sha256 = Path(v['ordinary_prepared']), v['ordinary_prepared_sha256']
    out = new_output(args.output)
    report = stage_result(args, 'probe', status='blocked', prepared_result_sha256=args.prepared_result_sha256,
                          phone_contacted=False, cleanup_known=False, native_qualified=False,
                          prompt_sha256=sha(PROMPT.encode()), system_sha256=sha(SYSTEM.encode()),
                          max_tokens=MAX_TOKENS, timeout_ms=TIMEOUT_MS, controller_grammar_exercised=False,
                          ground_truth='not_assessed', app_text_diagnostic_invocations=0,
                          memory_and_thermal_scope='Original identity /proc status reads retained; no whole-task/native/DSP peak or thermal measurement claimed.')
    p, value, m, plan, ac, iv, suite = data
    try:
        report.update(phone_contacted=None, phone_contact_attempted=True)
        ro, cli, parent, before = o.live(a, out, m, plan, ac, iv)
        report.update(phone_contacted=True, parent=parent, before=before)
        baseline_runs = set(ro.list_children('files/runs', directories=True))
        reserve(Path(args.prepared_result).parent, 'probe', args, {'output': str(out)})
        launch = ['am', 'start', '-W', '--user', '0', '-a', 'android.intent.action.MAIN', '-c', 'android.intent.category.LAUNCHER',
                  '-n', PACKAGE + '/.MainActivity', '--es', 'prompt', PROMPT, '--es', 'system_prompt', SYSTEM,
                  '--ez', 'auto_run', 'true', '--ei', 'max_tokens', str(MAX_TOKENS), '--el', 'timeout_ms', str(TIMEOUT_MS)]
        save(out / 'PROBE-INTENT.json', dict(argv=launch, attempts=1, grammar_argument_available=False, business_actions=0))
        report['app_text_diagnostic_invocations'] = 1
        _, launched = cli.command(launch, label='app-text-diagnostic-once', timeout=30)
        need(re.search(rb'(?m)^Status: ok\s*$', launched), 'diagnostic launch not acknowledged; no replay')
        deadline, run_id, receipt = time.monotonic() + 240, None, None
        while time.monotonic() < deadline:
            current = set(ro.list_children('files/runs', directories=True))
            added = current - baseline_runs
            need(baseline_runs <= current and len(added) <= 1, 'unexpected concurrent/replaced run directory')
            if added:
                found = next(iter(added))
                need(RUN.fullmatch(found) and run_id in (None, found), 'new run ID changed/invalid')
                run_id = found
                raw = ro.app_bytes('files/runs/' + run_id + '/app-receipt.json', optional=True)
                if raw is not None:
                    receipt = strict(raw)
                    break
            time.sleep(1)
        need(run_id is not None and receipt is not None, 'no terminal App receipt by observation deadline; cleanup UNKNOWN')
        report['run_id'] = run_id
        files = {}
        for name in RUN_ARTIFACTS:
            raw = ro.app_bytes('files/runs/' + run_id + '/' + name, optional=True)
            if raw is not None:
                put(out / 'run' / name, raw)
                files[name] = raw
        report['artifacts'] = {name: dict(bytes=len(raw), sha256=sha(raw)) for name, raw in files.items()}
        report['app_receipt'] = receipt
        report['app_recorded_memory_observations'] = {key: value for key, value in receipt.items()
            if any(part in key.lower() for part in ('memory', 'memavailable', 'memtotal', 'activity_manager'))}
        after = m.idle_snapshot(ro, UID, plan)
        m.parent_identity(ro, parent)
        o.service_check(cli, parent)
        report['after'] = after
        need(after == before, 'diagnostic changed journals/config; no further stage')
        report['cleanup_known'] = receipt.get('process_exit_observed') is True
        need(report['cleanup_known'], 'diagnostic process exit unknown')
        report.update(validate_probe_bytes(files, args.axis, run_id, parent, ac))
        report.update(status='complete', external_state_unchanged=True)
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    report['finished_wall_ms'] = int(time.time() * 1000)
    save(out / 'RESULT.json', report)
    return 0 if report['status'] == 'complete' else 3


def checked_probe(args, path, expected):
    value = prior(args, path, expected, 'probe')
    need(value.get('prepared_result_sha256') == args.prepared_result_sha256
         and value.get('cleanup_known') is True and value.get('external_state_unchanged') is True,
         'probe cleanup/preparation differs')
    _, _, (_, _, _, _, ac, _, _) = prepared(args)
    files = {name: read(Path(path).parent / 'run' / name, 4 << 20) for name in RUN_ARTIFACTS}
    for name, raw in files.items():
        need(value.get('artifacts', {}).get(name) == dict(bytes=len(raw), sha256=sha(raw)), 'probe artifact changed: ' + name)
    need(same_json(value.get('app_receipt'), strict(files['app-receipt.json'])),
         'probe cached App receipt differs from original')
    result = validate_probe_bytes(files, args.axis, value['run_id'], value['parent'], ac)
    need(value.get('native_qualified') is True and value.get('raw_text_sha256') == result['raw_text_sha256'], 'probe cached result differs')
    return value, result


def do_probe_review(args):
    value, recomputed = checked_probe(args, args.probe_result, args.probe_result_sha256)
    need(args.raw_text_sha256 == recomputed['raw_text_sha256'], 'reviewed text SHA differs')
    out = new_output(args.output)
    passed = args.text_integrity == 'readable'
    save(out / 'RESULT.json', stage_result(args, 'probe-review', status='complete' if passed else 'blocked', phone_contacted=False,
         probe_result=str(Path(args.probe_result).resolve()), probe_result_sha256=args.probe_result_sha256,
         prepared_result_sha256=args.prepared_result_sha256, raw_text_sha256=args.raw_text_sha256,
         text_integrity=args.text_integrity, ground_truth=args.ground_truth,
         reviewer='root_explicit_review_of_bound_original_text', native_qualified=True, cleanup_known=True,
         controller_grammar_exercised=False, semantic_correctness_inferred_from_native=False))
    return 0 if passed else 3


def probe_review(args):
    review = prior(args, args.probe_review, args.probe_review_sha256, 'probe-review')
    need(review.get('prepared_result_sha256') == args.prepared_result_sha256
         and review.get('text_integrity') == 'readable' and review.get('cleanup_known') is True,
         'probe is not independently readable/known-clean')
    _, recomputed = checked_probe(args, review['probe_result'], review['probe_result_sha256'])
    need(review['raw_text_sha256'] == recomputed['raw_text_sha256'], 'review no longer binds original text')
    return review


def ordinary_args(args, v):
    a = phone_args(args)
    a.prepared = Path(v['ordinary_prepared'])
    a.prepared_sha256 = v['ordinary_prepared_sha256']
    a.output = args.output
    for name in ('run_output', 'prefill', 'ready_sha256', 'reviewed_image_sha256',
                 'review_rectangle', 'start_point', 'observer_result_sha256'):
        if hasattr(args, name):
            setattr(a, name, getattr(args, name))
    return a


def do_ordinary(args):
    probe_review(args)
    v, o, data = prepared(args)
    a = ordinary_args(args, v)
    return {'ordinary-prefill': o.prefill, 'ordinary-start': o.start, 'ordinary-goal': o.collect_goal}[args.mode](a, *data) or 0


def do_ordinary_review(args):
    probe_review(args)
    v, o, data = prepared(args)
    raw = read(args.goal_review)
    need(sha(raw) == args.goal_review_sha256, 'goal review SHA differs')
    goal = strict(raw)
    need(goal.get('schema') == 'hepta.orvena-v32-ordinary-goal-review.v1'
         and goal.get('candidate') == candidate(args.axis) and goal.get('instruction_sha256') == o.INSTRUCTION_SHA,
         'ordinary goal identity differs')
    view = Path(args.goal_review).parent
    original = read(view / 'original-observer-RESULT.json')
    observer_result = strict(original)
    need(sha(original) == goal.get('observer_result_sha256') and observer_result.get('candidate') == candidate(args.axis)
         and observer_result.get('task_id') == goal.get('task_id') and observer_result.get('cleanup_known') is True,
         'ordinary observer/cleanup differs')
    p, pv, m, plan, ac, iv, suite = data
    collection = strict(read(view / 'collection.json'))
    # This calls the original observer's full native/request/owner/warm binding.
    m.native_collection_binding(view, collection, observer_result['parent'], goal['task_id'], o.INSTRUCTION, suite)
    terminal = strict(read(view / 'task/result.json'))
    need(terminal.get('task_id') == goal['task_id'] and terminal.get('external_model') is False
         and terminal.get('automatic_replay') is False, 'ordinary task terminal ownership differs')
    identities = strict(read(view / 'ORIGINAL-EVIDENCE.json'))['files']
    for relative, pin in identities.items():
        part = Path(relative)
        need(not part.is_absolute() and '..' not in part.parts, 'unsafe evidence member')
        b = read(view / part)
        need(pin == dict(bytes=len(b), sha256=sha(b)), 'ordinary evidence changed: ' + relative)
    scoped=qs.review(view,Q,goal['task_id'],o.INSTRUCTION,collection)
    need(scoped['verified'],'ordinary scope/native sampler evidence incomplete: '+str(scoped['errors']))
    output = new_output(args.output)
    native_ok = (observer_result.get('technical_evidence_complete') is True
                 and observer_result.get('all_native_bindings_verified') is True
                 and observer_result.get('errors') == [])
    allow_core = native_ok and args.text_integrity == 'readable'
    result = stage_result(args, 'ordinary-review', status='complete' if allow_core else 'blocked', phone_contacted=False,
                          prepared_result_sha256=args.prepared_result_sha256, probe_review_sha256=args.probe_review_sha256,
                          goal_review=str(Path(args.goal_review).resolve()), goal_review_sha256=args.goal_review_sha256,
                          ordinary_task_id=goal['task_id'], ordinary_goal_passed=goal.get('goal', {}).get('all_passed'),
                          task_status=goal.get('task_status'), text_integrity=args.text_integrity,
                          independent_visual=args.visual_goal, native_bindings_verified=native_ok, cleanup_known=True,
                          reviewer='root_explicit_review_of_collected_native_outputs_and_current_goal_screenshot',
                          semantic_failure_does_not_preclude_explicit_full_nine=True,
                          automatic_next_stage=False)
    save(output / 'RESULT.json', result)
    return 0 if allow_core else 3


def core_commands(plan, plan_sha, run_output, restore_output, connection):
    qs.require_device_target(connection,Q)
    wrapper = HERE / 'offline/phone_offline_suite.py'
    run = [sys.executable, '-B', str(wrapper), 'run', '--core', str(HERE / 'core/core_phone_suite.py'),
           '--plan', str(plan), '--expected-plan-sha256', plan_sha, '--adb', connection.adb, '--adb-host', connection.adb_host,
           '--adb-port', str(connection.adb_port), '--serial', connection.serial, '--data-setting-key', 'mobile_data1',
           '--expected-default-subscription', '1', '--expected-multisim-config', 'dsds',
           '--suite-deadline-seconds', '6000', '--supervisor-timeout-seconds', '7200',
           '--preparation-seconds', '120', '--network-poll-seconds', '15', '--child-exit-grace-seconds', '45',
           '--output', str(run_output), '--command-timeout', '10', '--stable-seconds', '1', '--restore-seconds', '120']
    run += qualification_arguments()
    restore = [sys.executable, '-B', str(wrapper), 'restore', '--journal', str(Path(run_output) / 'network-journal.json'),
               '--output', str(restore_output), '--command-timeout', '10', '--stable-seconds', '1', '--restore-seconds', '120']
    return dict(run_argv=run, restore_same_usb_argv=restore,
                restore_after_verified_reconnect_argv=restore + ['--allow-reconnected-usb'])


def do_core(args):
    probe_review(args)
    reviewed = prior(args, args.ordinary_review, args.ordinary_review_sha256, 'ordinary-review')
    need(reviewed.get('prepared_result_sha256') == args.prepared_result_sha256
         and reviewed.get('probe_review_sha256') == args.probe_review_sha256
         and reviewed.get('native_bindings_verified') is True and reviewed.get('cleanup_known') is True
         and reviewed.get('text_integrity') == 'readable', 'ordinary native/cleanup/text gate blocks further phone stages')
    bound(reviewed['goal_review'], reviewed['goal_review_sha256'])
    v, o, data = prepared(args)
    a = ordinary_args(args, v)
    out = new_output(args.output)
    run_output, restore_output = args.run_output.resolve(), args.restore_output.resolve()
    need(not run_output.exists() and not restore_output.exists(), 'new independent core/restore evidence directories required')
    argv = [sys.executable, '-B', str(HERE / 'core/core_phone_suite.py'), 'validate', v['core_plan']] + qualification_arguments()
    need(call(argv, out, 'core-validate-before-phone', 60) == 0, 'core plan/source changed')
    p, pv, m, plan, ac, iv, suite = data
    ro, cli, parent, idle = o.live(a, out, m, plan, ac, iv)
    need(idle['control'].get('task_id') == reviewed['ordinary_task_id'], 'current idle is not the reviewed ordinary terminal')
    commands = core_commands(v['core_plan'], v['core_plan_sha256'], run_output, restore_output,a)
    save(out / 'COMMANDS.json', commands)
    reserve(Path(args.prepared_result).parent, 'core9', args, {'output': str(out), 'run_output': str(run_output)})
    supervisor = module(HERE / 'offline_core9_supervisor.py', 'orvena_original_offline_supervisor')
    result = supervisor.supervise(commands['run_argv'], out)
    save(out / 'RESULT.json', stage_result(args, 'core9', status='returned_review_original_suite_and_network_journal',
         phone_contacted=True, ordinary_review_sha256=args.ordinary_review_sha256,
         core_plan_sha256=v['core_plan_sha256'], run_output=str(run_output),
         host_wrapper_exit_code=result.get('host_wrapper_exit_code'),
         phone_cleanup_known=None, radio_restoration_verified=None,
         success_not_inferred_from_supervisor_exit=True, automatic_restore_retry=False))
    return result.get('host_wrapper_exit_code') if type(result.get('host_wrapper_exit_code')) is int else 3


def parser():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--package-sha256',required=True)
    p.add_argument('--qualification-binding',type=Path,required=True)
    p.add_argument('--qualification-binding-sha256',required=True)
    p.add_argument('--axis',choices=('npu','gpu'),required=True)
    p.add_argument('--adb');p.add_argument('--adb-host',default='127.0.0.1');p.add_argument('--adb-port',type=int)
    p.add_argument('--serial',help='must equal the target in the private binding before any phone stage')
    p.add_argument('--execute',action='store_true');p.add_argument('--exclusive-idle-window',action='store_true')
    sub=p.add_subparsers(dest='mode');sub.add_parser('plan')
    q=sub.add_parser('prepare')
    for name in ('selection-result','upgrade-proof','upgrade-helper','selector-helper','output'):q.add_argument('--'+name,type=Path,required=True)
    q.add_argument('--selection-result-sha256',required=True);q.add_argument('--upgrade-proof-sha256',required=True)
    modes=('scope-install','scope-remove','probe','probe-review','ordinary-prefill','ordinary-start','ordinary-goal','ordinary-review','core9')
    for mode in modes:
        q=sub.add_parser(mode);q.add_argument('--prepared-result',type=Path,required=True)
        q.add_argument('--prepared-result-sha256',required=True);q.add_argument('--output',type=Path,required=True)
        if mode!='scope-install':
            q.add_argument('--scope-activation',type=Path,required=True);q.add_argument('--scope-activation-sha256',required=True)
        if mode.startswith('ordinary-') or mode=='core9':
            q.add_argument('--probe-review',type=Path,required=True);q.add_argument('--probe-review-sha256',required=True)
        if mode=='probe-review':
            q.add_argument('--probe-result',type=Path,required=True);q.add_argument('--probe-result-sha256',required=True)
            q.add_argument('--raw-text-sha256',required=True);q.add_argument('--text-integrity',choices=('readable','garbled','unverified'),required=True)
            q.add_argument('--ground-truth',choices=('pass','fail','unverified'),required=True)
        if mode in ('ordinary-prefill','ordinary-goal','core9'):q.add_argument('--run-output',type=Path,required=True)
        if mode=='ordinary-start':
            q.add_argument('--prefill',type=Path,required=True);q.add_argument('--ready-sha256',required=True)
            q.add_argument('--reviewed-image-sha256',required=True);q.add_argument('--review-rectangle',nargs=4,type=int,required=True)
            q.add_argument('--start-point',nargs=2,type=int,required=True)
        if mode=='ordinary-goal':q.add_argument('--observer-result-sha256',required=True)
        if mode=='ordinary-review':
            q.add_argument('--goal-review',type=Path,required=True);q.add_argument('--goal-review-sha256',required=True)
            q.add_argument('--text-integrity',choices=('readable','garbled','unverified'),required=True)
            q.add_argument('--visual-goal',choices=('pass','fail','unverified'),required=True)
        if mode=='core9':
            q.add_argument('--ordinary-review',type=Path,required=True);q.add_argument('--ordinary-review-sha256',required=True)
            q.add_argument('--restore-output',type=Path,required=True)
    return p


def main():
    need(__debug__,'optimized validation is forbidden');sys.dont_write_bytecode=True
    args=parser().parse_args();configure(args)
    phone_modes=('scope-install','scope-remove','probe','ordinary-prefill','ordinary-start','ordinary-goal','core9')
    if args.mode in (None,'plan') or args.mode in phone_modes and not args.execute:
        print(json.dumps(dict(status='host_plan_only',phone_contacted=False,candidate=candidate(args.axis),
            runtime_config_sha256=Q['runtime_config_sha256'],actual_build_identity_sha256=Q['build_identity_sha256'],
            qualification_binding_sha256=Q['binding_sha256'],expected_scope_sha256=Q['scope_sha256'],
            sampler_requested=SAMPLER,sampler_scope='v32 requested F32 numeric policy; SDK defaults explicitly retained; task quality unproven',
            requested_stage=args.mode,stages=['prepare','scope-install','probe','probe-review','ordinary-prefill','ordinary-start',
            'ordinary-goal','ordinary-review','core9','scope-remove'],automatic_sequence=False,automatic_fallback=False,
            same_instruction_gpu_rerun_is_not_same_prompt_numerical_equivalence=True),ensure_ascii=False,indent=2));return 0
    if args.mode in phone_modes:phone_args(args)
    if args.mode not in ('prepare','scope-install'):scope_activation(args)
    return {'prepare':do_prepare,'scope-install':scope_stage,'scope-remove':scope_stage,'probe':do_probe,
        'probe-review':do_probe_review,'ordinary-prefill':do_ordinary,'ordinary-start':do_ordinary,
        'ordinary-goal':do_ordinary,'ordinary-review':do_ordinary_review,'core9':do_core}[args.mode](args)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps(dict(status='blocked', error=type(error).__name__ + ': ' + str(error),
                              automatic_retry=False, phone_outcome_not_inferred=True), ensure_ascii=False), file=sys.stderr)
        raise SystemExit(3)
