#!/usr/bin/env python3
"""Derive the live02 driver with reviewed bounded capture; never execute it."""
import ast
import difflib
import hashlib
import json
from pathlib import Path
import types

ROOT = Path('/workspace/scratch/1ad3d6f55439')
BASE = ROOT/'transport_fix/root-runtime-properties-transport-r6-20261105-1ad3'
PARENT = ROOT/'recovery_source_cache/r2-run_runtime_properties_policy_once.py'
NAME = 'root-runtime-properties-live02-capture-r6-1ad3-candidate02'
OUT = ROOT/'transport_fix'/NAME
MAC = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/'+NAME

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def enc(value):
    return (json.dumps(value, sort_keys=True, indent=2)+'\n').encode()

def checked(path, size, digest):
    raw=path.read_bytes()
    assert (len(raw),sha(raw))==(size,digest), str(path)
    return raw

def segment(raw, name):
    text=raw.decode()
    n=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name==name)
    return ''.join(text.splitlines(keepends=True)[n.lineno-1:n.end_lineno])

def main():
    parent=checked(PARENT,19616,'574e639f52a3b99dc2ea6d6f82a7455d445fdb4d758bc486cf877df316921ebb')
    donor=checked(BASE/'source/run_runtime_properties_policy_once.py',19879,'3d41a301f2944640b1721bade7bb72b2e493e92470c2c417f5223a015a195fd6')
    capture=checked(BASE/'source/run_component_root_once.py',68481,'0374a8858a26114a6184e2e40949e33dbb9b0014117ce4637b55b72e7629a5bd')
    original=checked(BASE/'reference/run_component_root_once.r4.original.py',43438,'860aaf747e89411efa993783b950f709b1d8ac5d7b606575065bdff74ef98e22')
    edits=[]
    text=parent.decode()
    def replace(before,after):
        nonlocal text
        assert text.count(before)==1, before
        text=text.replace(before,after,1)
        edits.append((before,after))
    replace("TRANSPORT_SOURCE=B/'native-guard-r10-r1-operator-r4/root-chain/source/run_component_root_once.py'\nTRANSPORT_SHA='860aaf747e89411efa993783b950f709b1d8ac5d7b606575065bdff74ef98e22'",
            "TRANSPORT_SOURCE=B/'"+NAME+"/source/run_component_root_once.py'\nTRANSPORT_SHA='0374a8858a26114a6184e2e40949e33dbb9b0014117ce4637b55b72e7629a5bd'\nTRANSPORT_BYTES=68481\nORIGINAL_VALIDATOR_SOURCE=B/'native-guard-r10-r1-operator-r4/root-chain/source/run_component_root_once.py'\nORIGINAL_VALIDATOR_SHA='860aaf747e89411efa993783b950f709b1d8ac5d7b606575065bdff74ef98e22'\nORIGINAL_VALIDATOR_BYTES=43438")
    replace(segment(parent,'load_transport'),segment(donor,'load_transport'))
    replace('def validate(m,raw):','def validate(m,original_validator,raw):')
    replace("'source/run_runtime_properties_policy_once.py','reference/run_component_root_once.r4.original.py'}\n         and len(sources['files'])==2",
            "'source/run_runtime_properties_policy_once.py','source/run_component_root_once.py',\n             'reference/run_component_root_once.r4.original.py'}\n         and len(sources['files'])==3")
    replace("    need(m.read(HERE.parent/'reference/run_component_root_once.r4.original.py')==m.read(TRANSPORT_SOURCE),\n         'reviewed original transport reference differs')",
            "    need(m.read(HERE/'run_component_root_once.py')==m.read(TRANSPORT_SOURCE),\n         'reviewed execution transport package member differs')\n    need(m.read(HERE.parent/'reference/run_component_root_once.r4.original.py')\n         ==original_validator.read(ORIGINAL_VALIDATOR_SOURCE),\n         'reviewed historical r4 validator reference differs')")
    replace("    original=m.pin(p['transport_root_plan']);transport_plan,_=m.validate_plan(original)",
            "    original=original_validator.pin(p['transport_root_plan'])\n    transport_plan,_=original_validator.validate_plan(original)")
    replace('    m,_source=load_transport();raw=m.read(a.plan)',
            '    m,_source,original_validator=load_transport();raw=m.read(a.plan)')
    replace('    p,transport_plan,requests,apply_pair,verifier=validate(m,raw)',
            '    p,transport_plan,requests,apply_pair,verifier=validate(m,original_validator,raw)')
    replace('    except BaseException as error:\n        m.put(OUT/',
            '    except BaseException as error:\n        host_cleanup=c.close_owned_host_outputs()\n        m.put(OUT/')
    replace("'state':'ORIGINAL_TRANSACTION_STOPPED_NO_REPLAY','error_type':type(error).__name__,",
            "'state':'ORIGINAL_TRANSACTION_STOPPED_NO_REPLAY','host_cleanup':host_cleanup,\n            'error_type':type(error).__name__,")
    reverse=text
    for before,after in reversed(edits):
        assert reverse.count(after)==1
        reverse=reverse.replace(after,before,1)
    assert reverse.encode()==parent
    raw=text.encode()
    compile(raw,str(OUT/'source/run_runtime_properties_policy_once.py'),'exec')
    prior_calls=lambda value:[ast.dump(n,include_attributes=False) for n in ast.walk(ast.parse(value))
        if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='verify_prior_failed_transaction']
    assert len(prior_calls(raw))==3 and prior_calls(raw)==prior_calls(parent)
    for name in ('need','sha','encode','strict','exact_phase_operation'):
        assert segment(raw,name)==segment(parent,name)
    OUT.mkdir(mode=0o700)
    for name in ('source','reference','validation'):(OUT/name).mkdir(mode=0o700)
    files={'source/run_runtime_properties_policy_once.py':raw,
           'source/run_component_root_once.py':capture,
           'reference/run_component_root_once.r4.original.py':original}
    rows=[]
    for name,value in files.items():
        with (OUT/name).open('xb') as f:f.write(value)
        rows.append({'path':name,'bytes':len(value),'sha256':sha(value)})
    manifest=enc({'schema':'hepta.root.runtime-properties-live-source-package.v1','files':rows})
    (OUT/'SOURCE-MANIFEST.json').write_bytes(manifest)
    (OUT/'reference/live02-driver.r2.original.py').write_bytes(parent)
    diff=''.join(difflib.unified_diff(parent.decode().splitlines(keepends=True),text.splitlines(keepends=True),fromfile='live02-r2-original.py',tofile='source/run_runtime_properties_policy_once.py'))
    (OUT/'validation/TRANSPORT-ONLY-INCREMENT.patch').write_text(diff)
    helper=ROOT/'transport_fix/test_port_and_driver.py'
    module=types.ModuleType('retained_driver_compatibility_checks')
    module.__file__=str(helper)
    exec(compile(helper.read_bytes(),str(helper),'exec'),module.__dict__)
    module.PACKAGE=OUT
    module.SOURCE=OUT/'source/run_component_root_once.py'
    module.DRIVER=OUT/'source/run_runtime_properties_policy_once.py'
    module.ORIGINAL=OUT/'reference/run_component_root_once.r4.original.py'
    module.EVIDENCE=OUT/'validation'
    checks=module.driver_loader_checks()
    handler=next(n for n in ast.walk(ast.parse(raw)) if isinstance(n,ast.ExceptHandler)
                 and isinstance(n.type,ast.Name) and n.type.id=='BaseException')
    assert ast.unparse(handler.body[0])=='host_cleanup = c.close_owned_host_outputs()'
    calls=[]
    cleanup={'state':'OWNED_HANDLES_RETAINED','signals_sent':0,'automatic_retry':False}
    def record(path,value):
        assert calls==['cleanup']
        payload=json.loads(value)
        assert payload['host_cleanup']==cleanup
        assert payload['prior_failed_transaction']=={'exact':'original'}
        assert payload['schema']=='hepta.root.runtime-properties-live-failure.v2'
        calls.append('failure')
    ns={'c':types.SimpleNamespace(close_owned_host_outputs=lambda:(calls.append('cleanup'),cleanup)[1],steps=[]),
        'm':types.SimpleNamespace(put=record),'OUT':OUT,'encode':enc,'error':RuntimeError('fixture-only'),
        'root_plan':{},'intent_row':{},'p':{'prior_failed_transaction':{'exact':'original'}},
        'apply_calls':0,'phases':[]}
    body=ast.fix_missing_locations(ast.Module(body=handler.body[:-1],type_ignores=[]))
    exec(compile(body,'original-final-failure-handler','exec'),ns)
    assert calls==['cleanup','failure']
    report={'schema':'hepta.root.live02-r2-capture-port.v1',
       'state':'HOST_SOURCE_CANDIDATE_NOT_EXECUTED_ON_PHONE',
       'parent':{'bytes':len(parent),'sha256':sha(parent)},
       'driver':{'path':MAC+'/source/run_runtime_properties_policy_once.py','bytes':len(raw),'sha256':sha(raw)},
       'manifest':{'path':MAC+'/SOURCE-MANIFEST.json','bytes':len(manifest),'sha256':sha(manifest)},
       'whole_inverse_equals_r2':True,'prior_failure_three_calls_AST_identical':True,
       'final_failure_cleanup_precedes_publication_and_preserves_prior':True,
       'old_transaction_and_new_live02_namespaces_unchanged':True,
       'unchanged_capture_source_existing_Linux_and_Mac_tests':[33,6,7],
       'driver_loader_checks':checks,'phone_calls':0,'policy_apply_calls':0,
       'fixed19_qualified':0,
       'required_integration':['Future actual verifier root-transaction check must bind these exact three manifest members.',
         'Regenerate host prepared binding, expectation and Root plan from final source bytes.',
         'Keep failed-live01 proof and live02 v2 schemas; never replay old427f.',
         'This source candidate is not an execution or replacement for actual adoption.']}
    (OUT/'validation/RESULT.json').write_bytes(enc(report))
    print(json.dumps(report,indent=2))

if __name__=='__main__':
    main()
