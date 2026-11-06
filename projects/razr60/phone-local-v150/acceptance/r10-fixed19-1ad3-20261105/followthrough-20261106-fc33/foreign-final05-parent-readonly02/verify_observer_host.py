#!/usr/bin/env python3
"""Pure host controls for the fixed observer; no real observation or dispatch."""
from pathlib import Path
import ast, base64, copy, hashlib, json, lzma, shlex, types

D = Path(__file__).resolve().parent
O = D / 'candidate02'
checks = []
def sha(raw): return hashlib.sha256(raw).hexdigest()
def check(name, value):
    if not value: raise AssertionError(name)
    checks.append(name)
def reject(name, fn, message):
    try: fn()
    except ValueError as exc: check(name, message in str(exc))
    else: raise AssertionError(name + ': accepted invalid fixture')
def enc(v): return (json.dumps(v, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)+'\n').encode()

raw = (O/'SOURCE.py').read_bytes()
ir = (O/'INPUTS.json').read_bytes()
rr = (O/'PHONE-REQUEST.json').read_bytes()
manifest = json.loads((O/'MANIFEST.json').read_bytes())
check('fixed_source_input_request_pins', all(
    len(b)==manifest[k]['bytes'] and sha(b)==manifest[k]['sha256']
    for k,b in [('source',raw),('inputs',ir),('request',rr)]))
ns = {'__name__':'pure_observer_host_control'}
exec(compile(raw, '<fixed-observer-definitions-only>', 'exec'), ns)
C = ns['C']; inp = ns['INPUTS']
check('unchanged_cap_definitions_only_no_state_created',
      C.STATE is None and ns['STATE'] is None and len(ns['CAP_SOURCE_RAW'])==63646 and
      sha(ns['CAP_SOURCE_RAW'])=='70c4dc710368da58f609208879f1fb83af5e0b428b712cfd31b8bced1907bc44')
request=json.loads(rr); argv=shlex.split(request['command']); loader=ast.parse(argv[-1])
assign={n.targets[0].id:n.value for n in loader.body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name)}
compressed=base64.b64decode(ast.literal_eval(assign['c'].args[0]), validate=True)
dec=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=32*1024*1024)
decoded=dec.decompress(compressed,max_length=len(raw)+1)
check('complete_bounded_xz_inverse_and_exact_root_route',
      decoded==raw and dec.eof and not dec.unused_data and len(compressed)==20288 and
      request['kind']=='shell' and request['root'] is True and request['timeout_seconds']==50 and
      argv[-5:-1]==['/usr/bin/python3','-I','-B','-c'] and 'su' not in argv and
      request['command']==(O/'PHONE-COMMAND.sh').read_text() and len(rr)<=65535)
ext=(D/'observer_extension.py').read_bytes()
check('whole_reviewed_extension_embedded_unchanged',
      sha(ext)=='cb9b0c9e89017eb88276bb6e552285c209cb2da48ab584b75a33ef415140bfe3' and
      raw.endswith(ext+b"\nif __name__=='__main__':raise SystemExit(observer_main())\n"))
ref_raw=(D/'FAILURE-PARENT-PROFILE-REFERENCE.original.json').read_bytes(); ref=json.loads(ref_raw)
t=json.loads((D.parent/'R5-final05-recovery01/TARGETS.original.json').read_bytes())
expected_ref=ref['complete_parent_profiles']+[{
    'path':'/proc/1/root/data/local/tmp','metadata':ref['fixture_absence']['parent_metadata'],
    'selinux_raw_b64':ref['fixture_absence']['parent_selinux_raw_b64'],'names_observed_in_reference':False}]
check('actual_failure_parent_reference_exact_no_invented_tmp_names',
      len(ref_raw)==12129 and sha(ref_raw)=='5dd20c0bb2fbc049dea1b168cb83a730a3abc9916677be5e47ac81bbd7518427' and
      inp['parent_identity_references']==expected_ref and len(expected_ref)==5 and
      inp['reference_failure_preflight']=={k:ref['source'][k] for k in ('path','bytes','sha256')})
prefix='/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg02-a1055-final05-v150-'
xml={r['path']:r for r in t['files'] if r['path'].startswith(prefix)}
stage='/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-staging-r10-r1/'
check('exact_11_xml_2_foreign_paths_and_one_fixture',
      {r['path']:r for r in inp['xml_files']}==xml and len(xml)==11 and
      [r['path'] for r in inp['xml_files']]==[prefix+str(i)+'.xml' for i in range(1,12)] and
      inp['foreign_audit_paths']==[stage+'root-r10-neg01-74ec-final05.SECONDARY4-CLEANUP-INTENT-74ec02.json',stage+'root-r10-neg01-74ec-final05.SECONDARY4-CLEANUP-RESULT-74ec02.json'] and
      inp['fixture_path']=='/proc/1/root/data/local/tmp/hepta-native-guard-9b37081161d7bcbc3adf76d2e6ec7841')
calls=[ast.unparse(n.func) for n in ast.walk(ast.parse(ext)) if isinstance(n,ast.Call)]
check('no_capture_main_mutation_model_ui_or_other_process_signal',
      not set(calls)&{'C.capture','C.main','os.unlink','os.remove','os.rmdir','os.rename','os.replace','os.kill','os.killpg','subprocess.run','subprocess.Popen'} and
      not any(x.startswith(('shutil.','subprocess.')) for x in calls))

# Window fixtures are explicitly synthetic. No real C reader, file, lock,
# process, signal, namespace, model, UI, or device operation is called below.
originals={k:getattr(C,k) for k in ('directory','project_directory','original','exact_absence')}
rows=copy.deepcopy(expected_ref)
rows[-1].pop('names_observed_in_reference'); rows[-1]['names']=['SYNTHETIC-WINDOW-NAME']
by_path={r['path']:r for r in rows}
foreign={p:{'path':p,'bytes':1,'sha256':sha(b'x'),'metadata':[1,900+i,33152,0,0,1,1,10,10],
            'selinux_raw_b64':'U1lOVEhFVElD'} for i,p in enumerate(inp['foreign_audit_paths'])}
mode={'parent_change':None,'original_change':None,'absence_change':False,'directory_calls':0}
def directory(path):
    mode['directory_calls']+=1
    row=copy.deepcopy(by_path[path])
    if mode['parent_change'] and mode['directory_calls']>=6 and path==rows[-1]['path']:
        if mode['parent_change']=='names': row['names'].append('SYNTHETIC-NEW-NAME')
        if mode['parent_change']=='time': row['metadata'][7]+=1
    return row
def original(path, limit, expected=None, owner=None, preserve=False):
    if path in xml:
        row=copy.deepcopy(xml[path]); assert owner==(2000,2000,(row['metadata'][2]&0o7777,)) and preserve
    else:
        row=copy.deepcopy(foreign[path]); assert owner is None and limit==4194304 and preserve
    if mode['original_change']==path: row['sha256']=sha(b'changed')
    if expected is not None and row!=expected: raise ValueError('mock exact original pin mismatch')
    return row, b'SYNTHETIC-NOT-AN-ORIGINAL'
def absence(path):
    assert path==inp['fixture_path']
    result={'path':path,'absent':True,'parent_metadata':copy.deepcopy(rows[-1]['metadata']),
            'parent_selinux_raw_b64':rows[-1]['selinux_raw_b64'],'observed_monotonic_ns':mode['directory_calls']}
    if mode['absence_change']: result['parent_metadata'][7]-=1
    return result
def reset():
    mode.update(parent_change=None,original_change=None,absence_change=False,directory_calls=0)
    ns['STATE']={'windows':[]}
C.directory=directory; C.project_directory=lambda v:v; C.original=original; C.exact_absence=absence
try:
    reset(); first=ns['window'](0); second=ns['window'](1,first)
    check('synthetic_coherent_two_windows_accept_with_all13_complete_reads_each',
          len(ns['STATE']['windows'])==2 and len(second['xml'])==11 and len(second['foreign_audit_originals'])==2)
    for field in ('names','time'):
        reset(); mode['parent_change']=field
        reject('synthetic_within_window_parent_'+field+'_change_rejected',lambda:ns['window'](0),'parent bookends changed')
    reset(); mode['absence_change']=True
    reject('synthetic_mixed_time_fixture_parent_rejected',lambda:ns['window'](0),'same complete XML parent profile')
    reset(); first=ns['window'](0); rows[-1]['names'].append('SYNTHETIC-SECOND-WINDOW-NEW')
    reject('synthetic_across_window_parent_membership_change_rejected',lambda:ns['window'](1,first),'two-window parent/XML/audit')
    rows[-1]['names'].pop()
    for kind,path in [('xml',inp['xml_files'][0]['path']),('foreign_audit',inp['foreign_audit_paths'][0])]:
        reset(); first=ns['window'](0); mode['original_change']=path
        reject('synthetic_second_window_'+kind+'_change_rejected',lambda:ns['window'](1,first),'exact original pin mismatch')
    reset(); rows[-1]['metadata'][4]+=1
    reject('synthetic_known_parent_owner_change_rejected',lambda:ns['window'](0),'identity/owner/mode/label')
    rows[-1]['metadata'][4]-=1
finally:
    for key,value in originals.items(): setattr(C,key,value)
check('original_cap_state_remains_unexecuted',C.STATE is None)
out={'schema':'hepta.fc33.final05.parent-observer-host-controls.v1','state':'PURE_HOST_CONTROLS_PASSED',
     'source':manifest['source'],'inputs':manifest['inputs'],'request':manifest['request'],
     'checks':checks,'check_count':len(checks),'synthetic_window_controls_not_device_evidence':True,
     'actual_phone_calls':0,'actual_role_liveness_refreshed':False,'actual97_targets_refreshed':False,
     'cleanup_authorized':False,'scope_closure':False,'business_qualified':False,'component_qualified':False}
b=enc(out); path=O/'HOST-CONTROLS.json'
if path.exists(): assert path.read_bytes()==b
else: path.write_bytes(b)
print(json.dumps({'path':str(path),'bytes':len(b),'sha256':sha(b),'check_count':len(checks)},sort_keys=True))
