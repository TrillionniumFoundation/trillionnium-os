#!/usr/bin/env python3
"""Finite host-only controls, using only owned temporary files for mutation."""
from pathlib import Path
import ast,copy,errno,hashlib,json,os,shlex,stat,tempfile,time,types
D=Path(__file__).resolve().parent
source=(D/'SOURCE.py').read_bytes();g={'__name__':'host_controls_definitions_only'};exec(compile(source,'<recovery-definitions>','exec'),g)
C=g['C'];checks=[]
def need(v,s):
    if not v:raise AssertionError(s)
def ok(name,v=True):need(v,name);checks.append({'name':name,'passed':True})
def rejected(name,fn):
    try:fn()
    except (ValueError,OSError):ok(name)
    else:raise AssertionError('not rejected: '+name)
f,d,p=g['finite_plan']();ok('actual_finite_scope_97_files_10_dirs_5_parent_aliases',(len(f),len(d),len(p))==(97,10,5))
ok('all97_size_sha_pairs_in88_private_preserved_blobs',all((r['sha256'],r['bytes']) in {(b['sha256'],b['bytes']) for b in g['TARGETS']['preserved_blob_descriptors']} for r in f.values()))
original=g['TARGETS']
for name,change in [('missing_blob',lambda v:v['preserved_blob_descriptors'].pop()),('wrong_blob_size',lambda v:v['preserved_blob_descriptors'].__setitem__(0,{**v['preserved_blob_descriptors'][0],'bytes':v['preserved_blob_descriptors'][0]['bytes']+1})),('extra_target',lambda v:v['files'].append(copy.deepcopy(v['files'][0]))),('wrong_scope',lambda v:v.__setitem__('nonce','0'*32)),('private_member_drift',lambda v:v['directories'][0]['names'].append('foreign-entry'))]:
    g['TARGETS']=copy.deepcopy(original);change(g['TARGETS']);rejected('reject_'+name,g['finite_plan'])
g['TARGETS']=original
rejected('reject_boolean_metadata_integer',lambda:g['bounded_metadata']([True]+[1]*8))
rejected('reject_unbounded_metadata_integer',lambda:g['bounded_metadata']([1<<64]+[1]*8))
request=json.loads((D/'PHONE-REQUEST.json').read_bytes());loader=ast.parse(shlex.split(request['command'])[-1]);decoded={}
exec(compile(ast.Module(body=loader.body[:-1],type_ignores=[]),'<host-complete-wire-decode>','exec'),decoded)
ok('complete_actual_xz_command_inverse_byte_equal',decoded['r']==source)
ok('original_capture_module_globals_and_source_unchanged',len(g['CAP_SOURCE_RAW'])==63646 and hashlib.sha256(g['CAP_SOURCE_RAW']).hexdigest()=='70c4dc710368da58f609208879f1fb83af5e0b428b712cfd31b8bced1907bc44' and C.STATE is None)
rejected('oversize_output_reservation_before_effects',lambda:g['reserve_output']({'base64':'x'*(8*1024*1024)},f,d,p))

class OSProxy:
    def __getattr__(self,n):return getattr(os,n)
    def getxattr(self,p,n):need(n=='security.selinux','only synthetic label attr');return b'host-test-label\0'
proxy=OSProxy();C.os=proxy;g['os']=proxy
def init():
    C.STATE={'deadline':time.monotonic()+20,'read_bytes':0,'complete_file_reads':0,'blobs':{},'blob_bytes':0,'last_complete_read':None,'errors':[],'evidence':{},'lock_fds':[]}
    g['RECOVERY']={'operations':[],'phase':'control','file_fds':[],'directory_fds':[]}
def parent_handle(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY);m=C.metadata(os.fstat(fd))
    return {'fd':fd,'paths':[str(path)],'expected':{'metadata':m,'names':sorted(os.listdir(fd)),'selinux_raw_b64':C.base64.b64encode(b'host-test-label\0').decode()},'removed':False}
def file_handle(path,parent):
    fd=os.open(path,os.O_RDONLY);raw=path.read_bytes();r={'path':str(path),'metadata':C.metadata(os.fstat(fd)),'bytes':len(raw),'sha256':C.sha(raw),'selinux_raw_b64':parent['expected']['selinux_raw_b64']}
    return {'fd':fd,'parent':parent,'original':r,'removed':False}
def close_all(*handles):
    for h in handles:os.close(h['fd'])

with tempfile.TemporaryDirectory(prefix='fc33-recovery-controls-',dir=str(D)) as tmp:
    root=Path(tmp).resolve()
    # Real unlink of one entirely self-owned host fixture validates held FD,
    # canonical path, nlink0, exact parent delta and directory fsync behavior.
    for name,mode in [('exact','exact'),('changed_body','body'),('foreign_member','foreign'),('unknown_io','io'),('post_unlink_unknown','post')]:
        init();folder=root/name;folder.mkdir();path=folder/'owned';path.write_bytes(b'owned host control\n');ph=parent_handle(folder);fh=file_handle(path,ph)
        old_advance=g['advance_parent']
        try:
            if mode=='body':
                fh['original']['sha256']='0'*64
                rejected('wrong_target_bytes_rejected_before_unlink',lambda:g['remove_one_file'](fh));ok('wrong_bytes_zero_effect',path.exists() and not g['RECOVERY']['operations'])
            elif mode=='foreign':
                foreign=folder/'foreign';foreign.write_bytes(b'keep')
                rejected('unknown_parent_member_rejected_before_unlink',lambda:g['remove_one_file'](fh));ok('unknown_member_and_owned_preserved',foreign.read_bytes()==b'keep' and path.exists() and not g['RECOVERY']['operations'])
            elif mode=='io':
                def unknown(*a,**k):raise OSError(errno.EIO,'injected host-only unlink I/O')
                proxy.unlink=unknown
                rejected('unknown_unlink_io_refuses_success',lambda:g['remove_one_file'](fh));row=g['RECOVERY']['operations'][0]
                ok('unknown_attempt_is_explicit_not_zero_effect_inference',path.exists() and row['effect_attempted'] and not row['syscall_returned'] and not row['verified_absent'])
            elif mode=='post':
                def fail_after(*a,**k):raise OSError(errno.EIO,'injected host-only postcondition')
                g['advance_parent']=fail_after
                rejected('post_effect_error_never_becomes_success',lambda:g['remove_one_file'](fh));row=g['RECOVERY']['operations'][0]
                ok('actual_effect_retained_with_unknown_postcondition',not path.exists() and row['syscall_returned'] and not row['verified_absent'])
            else:
                g['remove_one_file'](fh);row=g['RECOVERY']['operations'][0]
                ok('actual_owned_host_unlink_exactly_once',not path.exists() and os.fstat(fh['fd']).st_nlink==0 and row['syscall_returned'] and row['verified_absent'] and row['parent_fsynced'])
                rejected('same_original_cannot_be_unlinked_again',lambda:g['remove_one_file'](fh));ok('no_second_attempt_record',len(g['RECOVERY']['operations'])==1)
        finally:
            g['advance_parent']=old_advance
            if 'unlink' in proxy.__dict__:del proxy.unlink
            close_all(fh,ph)
    init();folder=root/'directory-control';folder.mkdir();owned=folder/'owned-dir';owned.mkdir();ph=parent_handle(folder);dh=parent_handle(owned)
    try:
        g['remove_one_directory'](str(owned),dh,ph);row=g['RECOVERY']['operations'][0]
        ok('actual_owned_host_rmdir_exactly_once',not owned.exists() and os.fstat(dh['fd']).st_nlink==0 and row['verified_absent'] and row['parent_fsynced'])
    finally:close_all(dh,ph)
    init();folder=root/'nonempty-control';folder.mkdir();owned=folder/'owned-dir';owned.mkdir();foreign=owned/'foreign';foreign.write_bytes(b'keep');ph=parent_handle(folder);dh=parent_handle(owned)
    try:
        rejected('nonempty_owned_directory_not_removed',lambda:g['remove_one_directory'](str(owned),dh,ph));ok('foreign_file_retained_after_directory_refusal',foreign.read_bytes()==b'keep' and not g['RECOVERY']['operations'])
    finally:close_all(dh,ph)

report={'schema':'hepta.fc33.final05.recovery-host-controls.v1','state':'FINITE_HOST_CONTROLS_PASSED','source':{'bytes':len(source),'sha256':hashlib.sha256(source).hexdigest()},'count':len(checks),'controls':checks,'phone_calls':0,'real_scope_cleanup_executed':False,'all_effect_tests_only_in_owned_local_temporary_directory':True,'component_qualified':False,'business_qualified':False}
raw=(json.dumps(report,sort_keys=True,separators=(',',':'))+'\n').encode();out=D/'HOST-CONTROLS.json'
if out.exists():need(out.read_bytes()==raw,'create-only controls report')
else:out.write_bytes(raw)
print(json.dumps({'report':{'path':str(out),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()},'count':len(checks),'phone_calls':0},sort_keys=True))
