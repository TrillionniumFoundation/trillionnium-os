#!/usr/bin/env python3
"""Local guard checks; none are a fixed19 case or a phone qualification."""
import ast
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
import types

BASE = Path('/workspace/scratch/1ad3d6f55439/epoch_consumer_candidate01/context-budget-preview02')
source = BASE / 'templates/release_boundaries.py'
raw = source.read_bytes()
assert len(raw) == 88368 and hashlib.sha256(raw).hexdigest() == '2ecf748b34b3e1806715a7c0b52672cf3936f850ae6dcf67a94c0daf9ae5946d'
names = {'need','sha','descriptor','meta','file_descriptor','read_pinned','checked_actual_context',
    'decoded_bundle_budget','component_modules','current_external_artifacts'}
tree = ast.parse(raw)
nodes = [n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
assert {n.name for n in nodes} == names
env = dict(__name__='local_consumer_guard_check',hashlib=hashlib,os=os,Path=Path,stat=stat,
    sys=sys,types=types,contextmanager=contextmanager,MAX_ORIGINAL=16*1024*1024,MAX_BUNDLE=32*1024*1024,
    HASH=re.compile(r'[0-9a-f]{64}\Z'))
exec(compile(ast.Module(body=nodes,type_ignores=[]),'<local-guard-functions>','exec'),env)
checks=[]
def accepted(name, action):
    action();checks.append({'name':name,'result':'passed'})
def rejected(name,action,kind=ValueError):
    try:action()
    except kind:checks.append({'name':name,'result':'rejected_as_required'})
    else:raise AssertionError('guard did not reject: '+name)

mock_sources={'source/component_common.py':b'observed_context = __actual_context__\n',
    'source/late_boundary.py':b'import component_common\nobserved_context = (__actual_context__, component_common.observed_context)\n'}
before={n:sys.modules.get(n) for n in ('component_common','late_boundary')}
def load_context(context):
    with env['component_modules']({'package_sources':mock_sources,'actual_context':context},actual_context=context,runtime=False) as modules:
        assert modules['late_boundary'].observed_context == (context,context)
    assert all(sys.modules.get(n) is v for n,v in before.items())
for context in ('phone','mac','p4'):
    accepted('explicit_'+context+'_propagates_before_exec_and_restores_import_state',lambda c=context:load_context(c))
rejected('missing_actual_context_has_no_default',lambda:env['component_modules']({'package_sources':mock_sources}),TypeError)
def enter(state,**kwargs):
    with env['component_modules'](state,**kwargs):pass
rejected('state_context_cannot_change',lambda:enter({'package_sources':mock_sources,'actual_context':'mac'},actual_context='phone'))
rejected('runtime_true_on_mac_is_rejected_before_module_loading',lambda:enter({'package_sources':{}},actual_context='mac',runtime=True))
rejected('boolean_context_is_rejected',lambda:enter({'package_sources':{}},actual_context=True))
rejected('current_artifact_read_on_host_is_rejected_before_module_loading',lambda:env['current_external_artifacts']({'actual_context':'mac','package_sources':{}}))

def item(path,size):return {'descriptor':{'path':path,'bytes':size,'sha256':'a'*64},'raw_b64':''}
def bundle(sizes):return {'inputs':{'component':item('/a',2),'policy':item('/b',2)},
    'originals':{format(i,'064x'):{'bytes':n,'zlib_b64':'eA=='} for i,n in enumerate(sizes)}}
def exact_limit():assert env['decoded_bundle_budget'](bundle([16*1024*1024,16*1024*1024-4]))==32*1024*1024
accepted('exact_combined_decoded_budget_includes_both_input_payloads',exact_limit)
rejected('compressed_headers_cannot_hide_decoded_pool_overflow',lambda:env['decoded_bundle_budget'](bundle([16*1024*1024,16*1024*1024])))
rejected('one_original_over16MiB_is_rejected',lambda:env['decoded_bundle_budget'](bundle([16*1024*1024+1])))
rejected('bool_is_not_an_original_byte_count',lambda:env['decoded_bundle_budget'](bundle([True])))

with tempfile.TemporaryDirectory(prefix='epoch-consumer-guard-') as td:
    p=Path(td)/'original';p.write_bytes(b'exact-original\n')
    row={'path':str(p),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
    def regular_read():
        body,identity=env['read_pinned'](row);assert body==b'exact-original\n' and identity==env['meta'](p.lstat())
    accepted('actual_regular_file_bytes_and_full9_bookends',regular_read)
    p.unlink();os.mkfifo(p,0o600)
    started=time.monotonic();rejected('actual_fifo_replacement_is_nonblocking_and_rejected',lambda:env['read_pinned'](row))
    assert time.monotonic()-started<1

# Confirm every new caller supplies context, including bracketed host helpers.
count=0
for p in BASE.rglob('*.py'):
    for n in ast.walk(ast.parse(p.read_bytes())):
        if not isinstance(n,ast.Call):continue
        f=n.func; name=f.id if isinstance(f,ast.Name) else f.attr if isinstance(f,ast.Attribute) else None
        if isinstance(f,ast.Subscript) and isinstance(f.slice,ast.Constant):name=f.slice.value
        if name in ('component_modules','validate_bundle','validate_component','prepare_bundle'):
            assert any(k.arg=='actual_context' for k in n.keywords),(p,n.lineno,name)
            count+=1
assert count==18
checks.append({'name':'all18_current_preview_call_sites_have_explicit_context','result':'passed'})
report={'schema':'hepta.epoch.consumer-local-guard-checks.v1','state':'LOCAL_SOURCE_GUARD_CHECKS_ONLY',
    'source':{'path':str(source),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()},
    'checks':checks,'check_count':len(checks),'runtime_sources_executed':False,
    'only_local_mock_module_sources_and_selected_consumer_functions_executed':True,
    'phone_calls':0,'fixed19_case_credit':False,'full_epoch_integration_verified':False}
with (BASE/'LOCAL-GUARD-CHECKS.json').open('x') as f:json.dump(report,f,sort_keys=True,indent=2);f.write('\n')
print(json.dumps({'state':report['state'],'checks':len(checks),'phone_calls':0,'fixed19_case_credit':False}))
