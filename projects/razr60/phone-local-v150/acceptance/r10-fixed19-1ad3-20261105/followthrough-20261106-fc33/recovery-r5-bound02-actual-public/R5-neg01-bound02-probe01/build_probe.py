from pathlib import Path
import ast,base64,hashlib,json,lzma,shlex,zlib
D=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
def need(v,s):
    if not v:raise ValueError(s)
inputs_raw=(D/'INPUTS.json').read_bytes();need(len(inputs_raw)==36390 and sha(inputs_raw)=='9f208e160b9f11de65e758b8f060991a2ea64427d50e851ea1a7b1522e13d11d','actual P4 input original')
q=json.loads(inputs_raw);donor=D.parent/'R5-final05-probe01/SOURCE.py';raw=donor.read_bytes();need(len(raw)==63646 and sha(raw)=='70c4dc710368da58f609208879f1fb83af5e0b428b712cfd31b8bced1907bc44','reviewed readonly helper source')
s=raw.decode();t=ast.parse(s);wanted=['need','sha','encoded','strict','metadata','parent_fd','stat_identity','check_time','read_fd','blob','absent_or_error','directory','proc_bytes','original','add_blob','project_directory','exact_absence','tree','legacy_projection','stable_tree_projection','compare_baseline']
defs={n.name:ast.get_source_segment(s,n) for n in t.body if isinstance(n,ast.FunctionDef)}
helpers='\n\n'.join(defs[n] for n in wanted)+'\n\n'
stage_raw=(D.parent/'R5-root/runtime/source/stage_component.py').read_bytes();need(len(stage_raw)==19085 and sha(stage_raw)=='e87dcf806f66a87ffbf4cbdfb00bac9280fb220268a9f3ee5e17f53ee35f07b9','actual reviewed stage source')
stage=stage_raw.decode();a=next(n for n in ast.parse(stage).body if isinstance(n,ast.FunctionDef) and n.name=='archive_members');archive_helper=ast.get_source_segment(stage,a)+'\n\n'
ext=(D/'probe_extension.py').read_bytes()
header='#!/usr/bin/env python3\n"""Actual bound02 unstarted scope: complete read-only preservation, no recovery."""\nimport base64,errno,fcntl,hashlib,io,json,os,signal,stat,sys,tarfile,time,zlib\nfrom pathlib import Path\n'
bindings={'INPUTS_RAW':inputs_raw,'INPUTS_SHA':sha(inputs_raw),'BOOT':q['lease']['boot_id'],'LABEL':q['label'],'NONCE':q['nonce'],'LEASE_SHA':q['lease_sha256'],'PACKAGE_SHA':q['package_sha256'],'BASELINE_FILE_BYTES':44353573,'MAX_FILE':16*1024*1024,'MAX_READ_BYTES':160*1024*1024,'MAX_BLOB_BYTES':16*1024*1024,'MAX_PRIVATE_TREE_BYTES':16*1024*1024,'MAX_PACKET':32*1024*1024,'MAX_OUTPUT':8*1024*1024,'MAX_SECONDS':45,'MAX_ENTRIES':30000,'STATE':None}
header+=''.join(k+' = '+repr(v)+'\n' for k,v in bindings.items())
header+='INPUTS = json.loads(INPUTS_RAW)\nassert hashlib.sha256(INPUTS_RAW).hexdigest() == INPUTS_SHA\nSCOPE_HOME=Path(INPUTS["phone_home"])\nANDROID_HOME=Path(INPUTS["android_home"])\nANDROID=Path("/proc/1/root")\nJOURNAL=ANDROID_HOME/"executor"\nFIXTURE=Path(INPUTS["fixture"])\n\n'
source=header.encode()+helpers.encode()+archive_helper.encode()+ext+b'\nif __name__=="__main__":raise SystemExit(probe_main())\n'
ast.parse(source);ns={'__name__':'bound02_readonly_source_review'};exec(compile(source,'<bound02-source-review>','exec'),ns)
need(ns['STATE'] is None and ns['PROBE_STATE'] is None and len(ns['INPUTS']['runtime_files'])==38,'source load is side-effect free')
compressed=zlib.compress(source,9)
loader=('import base64,hashlib,zlib\nc=base64.b64decode('+repr(base64.b64encode(compressed).decode())+',validate=True)\n'
 'assert len(c)=='+str(len(compressed))+' and hashlib.sha256(c).hexdigest()=='+repr(sha(compressed))+'\n'
 'd=zlib.decompressobj();r=d.decompress(c,'+str(len(source)+1)+')\n'
 'assert d.eof and not d.unconsumed_tail and not d.unused_data and len(r)=='+str(len(source))+' and hashlib.sha256(r).hexdigest()=='+repr(sha(source))+'\n'
 'exec(compile(r,"<fc33-bound02-unstarted-readonly01>","exec"),{"__name__":"__main__"})\n')
route='/data/adb/magisk/busybox env -i PATH=/usr/bin:/bin:/usr/libexec/trillionnium PYTHONHOME=/usr PYTHONDONTWRITEBYTECODE=1 LD_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu/android:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu LANG=C.UTF-8 LC_ALL=C.UTF-8 TMPDIR=/var/lib/trillionnium/owner-open/tmp NO_COLOR=1 TERM=dumb /data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -I -B -c '
command=route+shlex.quote(loader)+'\n';request=enc({'kind':'shell','root':True,'command':command,'timeout_seconds':70});need(len(command.encode())<65535 and len(request)<65535,'actual bounded wire')
label='ng-fc33-neg01-bound02-unstarted-readonly01';key='fc33-neg01-bound02-unstarted-readonly01';request_path='/home/alex/razr60-local-model-v150/requests/'+label+'.json'
runner='''from pathlib import Path
import hashlib,os,stat
actor=Path('/home/alex/razr60-local-model-v150/ops/phone_once.py')
request=Path(REQUEST_PATH)
fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
for p,size,digest in [(actor,5652,'179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'),(request,REQUEST_BYTES,REQUEST_SHA)]:
 assert p.resolve(strict=True)==p
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as stream:
  before=os.fstat(stream.fileno())
  assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==size
  body=stream.read(size+1);after=os.fstat(stream.fileno())
 assert len(body)==size and hashlib.sha256(body).hexdigest()==digest
 assert [getattr(before,k) for k in fields]==[getattr(after,k) for k in fields]==[getattr(p.lstat(),k) for k in fields]
 if p==request:assert stat.S_IMODE(before.st_mode)==0o600 and before.st_uid==before.st_gid==1000
os.execv('/usr/bin/python3',['/usr/bin/python3','-I','-B',str(actor),ACTOR_LABEL,str(request)])
'''.replace('REQUEST_PATH',repr(request_path)).replace('REQUEST_BYTES',str(len(request))).replace('REQUEST_SHA',repr(sha(request))).replace('ACTOR_LABEL',repr(label))
dispatch={'host':'pocket4','executable':'/usr/bin/python3','args':['-I','-B','-c',runner],'idempotency_key':key}
derivation={'schema':'hepta.fc33.bound02.readonly-source-derivation.v1','pure_helpers_parent':{'bytes':len(raw),'sha256':sha(raw)},'pure_helper_names':wanted,'all_helper_source_segments_identical':all(ast.get_source_segment(source.decode(),next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name==name))==defs[name] for name in wanted),'archive_helper_parent':{'bytes':len(stage_raw),'sha256':sha(stage_raw)},'archive_helper_source_identical':True,'extension':{'bytes':len(ext),'sha256':sha(ext)},'input_original':{'bytes':len(inputs_raw),'sha256':sha(inputs_raw)},'no_original_capture_or_process_functions_included':True,'host_source_load_STATE':None,'host_source_load_PROBE_STATE':None}
files={'SOURCE.py':source,'PHONE-COMMAND.sh':command.encode(),'PHONE-REQUEST.json':request,'ROOT-DISPATCH-RUNNER.py':runner.encode(),'DISPATCH.json':enc(dispatch),'SOURCE-DERIVATION.json':enc(derivation)}
for n,b in files.items():(D/n).write_bytes(b)
manifest={'schema':'hepta.fc33.bound02.unstarted-readonly-manifest.v1','state':'SOURCE_READY_AWAITING_ROOT_READONLY_DISPATCH','source':{'bytes':len(source),'sha256':sha(source)},'request':{'path':request_path,'bytes':len(request),'sha256':sha(request)},'dispatch':{'label':label,'key':key,'root_is_only_dispatcher':True},'files':{n:{'bytes':len(b),'sha256':sha(b)} for n,b in files.items()},'scope':{'label':q['label'],'nonce':q['nonce'],'package_sha256':q['package_sha256'],'lease_sha256':q['lease_sha256']},'actual_inputs':{'path':'/home/alex/razr60-local-model-v150/fc33-neg01-bound02-probe-inputs01/INPUTS.json','bytes':len(inputs_raw),'sha256':sha(inputs_raw)},'readset':{'original44_roots':44,'original_entries':3823,'old_file_bytes_per_window':44353573,'lock_aliases':26,'lock_inode_groups':14,'runtime_files':38,'archive_members':62,'home_files':63,'unique_private_directories':9,'transport_files':4,'sender_XML_paths':11,'owned_files_total':78,'complete_surviving_parent_aliases':5,'windows':2,'fixture_observed_ENOENT':q['fixture']},'bounds':{'body_seconds':45,'actor_seconds':70,'whole_read_bytes':160*1024*1024,'private_blob_bytes':16*1024*1024,'packet_bytes':32*1024*1024,'stdout_bytes':8*1024*1024,'zlib_bytes':len(compressed),'command_bytes':len(command.encode()),'request_bytes':len(request),'wire_headroom':65535-max(len(request),len(command.encode()))},'writes':0,'deletes':0,'external_process_signals':0,'ui_calls':0,'model_calls':0,'native_dispatches':0,'new_case_nonces':0,'current_role_liveness_tested':False,'cannot_prove':['fresh proc or kernel absence of an unknown role generation','historical native/effect success or whole failed case qualification','cleanup completion or permission to delete','L.verify_retired runtime or elapsed time'],'host_protocol_authority':'actual synchronous rc2, full wait/EOF, failed prepared phase before launch; not a fabricated remote PID or generic flag rewrite','original_lease_unchanged_and_expired_required':True,'scope_closure':False,'deletion_authorized':False,'component_qualified':False,'business_qualified':False}
(D/'MANIFEST.json').write_bytes(enc(manifest));print(json.dumps({'source':manifest['source'],'request':manifest['request'],'bounds':manifest['bounds'],'manifest_bytes':len(enc(manifest)),'manifest_sha256':sha(enc(manifest))},sort_keys=True))
