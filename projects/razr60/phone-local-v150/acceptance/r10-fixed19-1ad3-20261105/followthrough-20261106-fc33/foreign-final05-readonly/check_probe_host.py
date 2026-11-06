#!/usr/bin/env python3
"""Pure host contract/failure controls. No actual proc/signal/phone capture."""
from pathlib import Path
import ast,base64,builtins,dis,errno,hashlib,json,shlex,time,types,zlib
D=Path(__file__).resolve().parent
raw=(D/'SOURCE.py').read_bytes()
g={'__name__':'host_only_probe_definition_check','__file__':'<no-phone-capture>'}
exec(compile(raw,g['__file__'],'exec'),g)
results=[]
def ok(name,value):
    assert value,name
    results.append({'name':name,'passed':True})
def rejected(name,call):
    try:call()
    except (ValueError,OSError,TimeoutError):ok(name,True)
    else:raise AssertionError(name+' unexpectedly accepted')
def state():
    g['STATE']={'deadline':time.monotonic()+60,'read_bytes':0,'complete_file_reads':0,'errors':[],
                'evidence':{},'blobs':{},'blob_bytes':0,'lock_fds':[],'last_complete_read':None}
def statraw(pid,pgid,sid,ticks):
    fields=['S','1',str(pgid),str(sid)]+['0']*15+[str(ticks)]
    return (str(pid)+' (synthetic control) '+' '.join(fields)+'\n').encode()

# No helper may fail later because a donor global was omitted by construction.
missing={}
def inspect(code):
    for instruction in dis.get_instructions(code):
        if instruction.opname in ('LOAD_GLOBAL','LOAD_NAME') and instruction.argval not in g and not hasattr(builtins,instruction.argval):
            missing.setdefault(code.co_name,[]).append(instruction.argval)
    for value in code.co_consts:
        if isinstance(value,types.CodeType):inspect(value)
for v in list(g.values()):
    if isinstance(v,types.FunctionType) and v.__globals__ is g:inspect(v.__code__)
ok('all_constructed_function_globals_resolve',not missing)
ok('actual_scope_and_counts',g['INPUTS']['lease']['nonce']=='9b37081161d7bcbc3adf76d2e6ec7841'
   and len(g['INPUTS']['runtime_files'])==37 and len(g['INPUTS']['baseline_roots'])==44
   and len(g['INPUTS']['known_originals'])==24)

request=json.loads((D/'PHONE-REQUEST.json').read_bytes())
outer=shlex.split(request['command']);inner=shlex.split(outer[2]);payload=ast.parse(inner[-1])
node=next(n for n in payload.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='data' for t in n.targets))
compressed=base64.b64decode(ast.literal_eval(node.value.args[0]),validate=True)
decoder=zlib.decompressobj();inverse=decoder.decompress(compressed)+decoder.flush()
ok('complete_phone_wire_reconstructs_exact_source',inverse==raw and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail)
ok('phone_wire_bounds',len(request['command'].encode())<=65535 and (D/'PHONE-REQUEST.json').stat().st_size<=65535
   and request['kind']=='shell' and request['root'] is True and request['timeout_seconds']==70)
source_ast=ast.parse(raw)
calls=[n for n in ast.walk(source_ast) if isinstance(n,ast.Call)]
kills=[n for n in calls if isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='os' and n.func.attr=='kill']
ok('only_signal_zero_query_expression',len(kills)==1 and len(kills[0].args)==2
   and isinstance(kills[0].args[1],ast.Constant) and kills[0].args[1].value==0)
forbidden={'unlink','remove','rename','replace','mkdir','makedirs','rmdir','chmod','chown','setxattr','fork','execve','execv','system','killpg'}
ok('no_filesystem_mutator_or_process_launcher',not [n for n in calls if isinstance(n.func,ast.Attribute) and n.func.attr in forbidden])
ok('no_dynamic_target_code_execution',not [n for n in calls if isinstance(n.func,ast.Name) and n.func.id in ('exec','eval','__import__')])

original_os,original_proc,original_inspect=g['os'],g['proc_bytes'],g['inspect_pid']
class FakeOS:
    def __init__(self,kill_errno=errno.ESRCH,member=False,read_error=None):
        self.kill_errno=kill_errno;self.member=member;self.read_error=read_error;self.queries=[]
    def listdir(self,path):
        assert path=='/proc';return ['123']
    def kill(self,pid,signal):
        assert pid in (-29207,-30384) and signal==0
        self.queries.append((pid,signal))
        if self.kill_errno is not None:raise OSError(self.kill_errno,'synthetic host-only query')
    def proc(self,path,maximum):
        assert path=='/proc/123/stat' and maximum==8192
        if self.read_error:raise OSError(self.read_error,'synthetic host-only proc read')
        return statraw(123,30384 if self.member else 123,30384 if self.member else 123,10)
def set_fake(fake):
    state();g['os']=fake;g['proc_bytes']=fake.proc
    g['inspect_pid']=lambda pid,ids:{'pid':pid,'original_identities':ids,'stat_before':{'state':'OBSERVED_ENOENT','errno':2},'synthetic_host_control':True}
try:
    fake=FakeOS();set_fake(fake);a=g['process_window'](0);b=g['process_window'](1)
    ok('two_windows_exact_four_signal_zero_queries',len(fake.queries)==4 and a['known_groups_absent_in_this_window'] and b['known_groups_absent_in_this_window'])
    fake=FakeOS(kill_errno=errno.EPERM);set_fake(fake);rejected('EPERM_remains_unknown',lambda:g['process_window'](0))
    fake=FakeOS(kill_errno=None);set_fake(fake);rejected('existing_kernel_group_refused',lambda:g['process_window'](0))
    fake=FakeOS(member=True);set_fake(fake);rejected('matching_session_member_refused_even_with_ESRCH',lambda:g['process_window'](0))
    fake=FakeOS(read_error=errno.EIO);set_fake(fake);rejected('unknown_proc_IO_refused',lambda:g['process_window'](0))
finally:
    g['os'],g['proc_bytes'],g['inspect_pid']=original_os,original_proc,original_inspect

base={'roots':['/synthetic'],'entries':{'/synthetic':{'kind':'directory','metadata':[1,2,16832,0,0,2,1,10,10],'names':[]}},'file_bytes_hashed':0}
observed={'roots':['/synthetic'],'entries':{'/synthetic':dict(base['entries']['/synthetic'],path='/synthetic',selinux_raw_b64='YQ==')},'file_bytes_hashed':0}
g['compare_baseline'](observed,base);ok('exact_inventory_projection_accepts_only_equal_fields',True)
bad=json.loads(json.dumps(observed));bad['entries']['/synthetic']['metadata'][8]+=1
rejected('baseline_full9_change_refused',lambda:g['compare_baseline'](bad,base))
bad=json.loads(json.dumps(observed));bad['entries']['/synthetic']['names']=['new']
rejected('baseline_new_child_refused',lambda:g['compare_baseline'](bad,base))
absence={'roots':['/fixture'],'entries':{'/fixture':{'kind':'absent','path':'/fixture','absence':'ENOENT','parent_metadata':[1,2,3,4,5,6,7,8,9],'parent_selinux_raw_b64':'YQ==','observed_monotonic_ns':1,'no_effect_inferred':False}},'file_bytes_hashed':0}
later=json.loads(json.dumps(absence));later['entries']['/fixture']['observed_monotonic_ns']=2
ok('absence_only_observation_time_is_not_a_content_change',g['stable_tree_projection'](absence)==g['stable_tree_projection'](later))
later['entries']['/fixture']['parent_metadata'][8]+=1
ok('absence_parent_full9_is_still_strict',g['stable_tree_projection'](absence)!=g['stable_tree_projection'](later))

state();wire=g['output_packet']({'schema':'host-control','qualification':False});envelope=json.loads(wire);packet=envelope['packet'];decoded=zlib.decompress(base64.b64decode(packet['base64'],validate=True))
ok('packet_descriptor_covers_complete_exact_bytes',len(decoded)==packet['bytes'] and hashlib.sha256(decoded).hexdigest()==packet['sha256'])
cap=g['MAX_OUTPUT'];g['MAX_OUTPUT']=1
try:rejected('output_cap_refuses_whole_packet',lambda:g['output_packet']({'x':1}))
finally:g['MAX_OUTPUT']=cap

report={'schema':'hepta.fc33.failed-final05-readonly.host-controls.v1','state':'HOST_ONLY_CONTROLS_PASSED_NO_PHONE_EXECUTION',
 'source':{'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()},'controls':results,'control_count':len(results),
 'actual_phone_calls':0,'actual_proc_reads':0,'actual_signal_queries':0,'native_or_model_requests':0,
 'synthetic_controls_do_not_grant_scope_closure':True,'actual_archive_host_check':None}
out=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode();p=D/'HOST-CONTROLS.json'
if p.exists():assert p.read_bytes()==out
else:p.write_bytes(out)
print(json.dumps({'controls':len(results),'bytes':len(out),'sha256':hashlib.sha256(out).hexdigest(),'phone_calls':0}))
