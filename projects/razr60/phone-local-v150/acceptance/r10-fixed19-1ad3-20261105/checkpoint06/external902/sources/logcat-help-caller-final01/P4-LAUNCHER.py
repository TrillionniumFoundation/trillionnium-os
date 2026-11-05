#!/usr/bin/env python3
"""One actual Android logcat --help request; no log buffer reads or clears."""
import pathlib,os,stat,json,hashlib,subprocess,time,shlex
BASE=pathlib.Path('/home/alex/razr60-local-model-v150')
LABEL='ng-902e851c3ca1f90deab3d880ab993774-logcat-help01'
COMMAND='/system/bin/logcat --help'
EXPECTED_BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
REQ={'kind': 'shell', 'command': '/system/bin/logcat --help', 'root': True, 'timeout_seconds': 30}
actor=BASE/'ops/phone_once.py'
assert hashlib.sha256(actor.read_bytes()).hexdigest()=='179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'
out=pathlib.Path('/home/alex/razr60-local-model-v150/fixed19-root-1ad3-logcat-help01')
assert out.parent.resolve(strict=True)==out.parent
os.mkdir(out,0o700)
def put(p,b):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 d=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)

def enc(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,indent=2)+'\n').encode()

command_raw=COMMAND.encode('utf-8')
assert COMMAND=='/system/bin/logcat --help' and REQ=={'kind':'shell','command':COMMAND,'root':True,'timeout_seconds':30}
put(out/'COMMAND.original.txt',command_raw)
request=BASE/'requests'/(LABEL+'.json')
request_raw=enc(REQ)
put(request,request_raw)
put(out/'REQUEST.original.json',request_raw)
argv=['/usr/bin/python3','-I','-B',str(actor),LABEL,str(request)]
put(out/'INTENT.json',enc({'argv':argv,'phone_calls_max':1,'command_sha256':hashlib.sha256(command_raw).hexdigest(),
    'request_sha256':hashlib.sha256(request_raw).hexdigest(),'expected_actor_baseline_boot':EXPECTED_BOOT,
    'requested_command_is_help_only':True,'reads_log_buffers':False,'clears_log_buffers':False,
    'starts_app_process':False,'phone_source_or_case_writes':0,'signals_sent':0,'automatic_retry':False,'case_pass':False}))
so=open(out/'actor.stdout.original','xb')
se=open(out/'actor.stderr.original','xb')
p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=so,stderr=se,start_new_session=True)
put(out/'CHILD.json',enc({'pid':p.pid,'maximum_starts':1,'automatic_retry':False}))
try:
 rc=p.wait(timeout=60)
except subprocess.TimeoutExpired:
 put(out/'UNKNOWN.json',enc({'pid':p.pid,'wait_returned':False,'signals_sent':0,'automatic_retry':False,
    'remote_phone_outcome_unknown':True}));raise
finally:
 so.flush();os.fsync(so.fileno());so.close();se.flush();os.fsync(se.fileno());se.close()
put(out/'JOINED.json',enc({'pid':p.pid,'returncode':rc,'wait_returned':True,'signals_sent':0}))
rows={};native={}
for name in ('intent.json','baseline.json','result.json'):
 f=BASE/'operations'/LABEL/name;fd=os.open(f,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as stream:
  a=os.fstat(stream.fileno());assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=8*1024*1024
  raw=stream.read(8*1024*1024+1);b=os.fstat(stream.fileno())
 assert len(raw)==a.st_size and (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns)
 put(out/('phone-'+name+'.original'),raw);rows[name]={'path':str(f),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
 native[name]=json.loads(raw)
operation=native['result.json'];baseline=native['baseline.json'];actual_intent=native['intent.json']
phone=operation.get('phone',{})
phone_stdout=phone.get('stdout','').encode('utf-8');phone_stderr=phone.get('stderr','').encode('utf-8')
put(out/'PHONE-STDOUT.original',phone_stdout);put(out/'PHONE-STDERR.original',phone_stderr)
baseline_lines=baseline.get('stdout','').splitlines()
observed_boot=baseline_lines[0] if baseline_lines else None
same_boot=baseline.get('rc')==0 and observed_boot==EXPECTED_BOOT
intent_bound=(actual_intent.get('label')==LABEL and actual_intent.get('request')==REQ
    and actual_intent.get('request_sha256')==hashlib.sha256(request_raw).hexdigest()
    and actual_intent.get('automatic_replay') is False)
command_bound=(operation.get('label')==LABEL and phone.get('command')=='/debug_ramdisk/su -c '+shlex.quote(COMMAND))
captured=(rc==0 and operation.get('status')=='command_exited' and type(phone.get('rc')) is int
    and intent_bound and command_bound and same_boot)
query_succeeded=captured and phone.get('rc')==0
result={'schema':'hepta.logcat.help-only-capability-observation.v1',
    'state':'HELP_QUERY_ORIGINALS_CAPTURED' if captured else 'HELP_QUERY_FAILED_OR_UNBOUND_ORIGINALS_RETAINED',
    'observation_complete':captured,'help_command_returned_zero':query_succeeded,
    'actor_returncode':rc,'phone_returncode':phone.get('rc'),'phone_status':operation.get('status'),
    'phone_stdout':{'path':str(out/'PHONE-STDOUT.original'),'bytes':len(phone_stdout),'sha256':hashlib.sha256(phone_stdout).hexdigest()},
    'phone_stderr':{'path':str(out/'PHONE-STDERR.original'),'bytes':len(phone_stderr),'sha256':hashlib.sha256(phone_stderr).hexdigest()},
    'phone_originals':rows,'requested_command':COMMAND,'command_sha256':hashlib.sha256(command_raw).hexdigest(),
    'expected_boot_id':EXPECTED_BOOT,'actor_baseline_boot_id':observed_boot,'actor_baseline_boot_matches':same_boot,
    'boot_rechecked_after_help':False,'actual_request_binding_matches':intent_bound,'actual_command_binding_matches':command_bound,
    'capability_options_parsed_or_inferred':False,'requested_log_buffer_reads':0,'requested_log_buffer_clears':0,
    'requested_app_process_starts':0,'phone_source_or_case_writes':0,'new_case_or_nonce':False,
    'native_boundary_created':False,'component_qualified':False,'case_pass':False,'signals_sent':0,'automatic_retry':False}
raw=enc(result);put(out/'RESULT.json',raw)
print(json.dumps({'result':{'path':str(out/'RESULT.json'),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()},
    'state':result['state'],'actor_returncode':rc,'phone_returncode':phone.get('rc'),'case_pass':False},sort_keys=True))
import tarfile,io,lzma
originals={q.name:q.read_bytes() for q in out.iterdir() if q.is_file()}
assert len(originals)==13 and sum(len(x) for x in originals.values())<=16*1024*1024
buf=io.BytesIO()
with tarfile.open(fileobj=buf,mode='w',format=tarfile.USTAR_FORMAT) as archive:
 for name,body in sorted(originals.items()):
  info=tarfile.TarInfo(name);info.size=len(body);info.mode=0o600;info.mtime=0;archive.addfile(info,io.BytesIO(body))
plain=buf.getvalue();compressed=lzma.compress(plain,preset=6)
assert lzma.decompress(compressed)==plain
put(out/'FULL-ORIGINALS.tar.xz',compressed)
manifest={'schema':'hepta.logcat.help-only-originals.v1','command_sha256':hashlib.sha256(command_raw).hexdigest(),
    'archive':{'path':str(out/'FULL-ORIGINALS.tar.xz'),'bytes':len(compressed),'sha256':hashlib.sha256(compressed).hexdigest()},
    'tar':{'bytes':len(plain),'sha256':hashlib.sha256(plain).hexdigest()},
    'files':[{'path':name,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()} for name,body in sorted(originals.items())],
    'originals_changed':False,'case_pass':False,'phone_request_count':1,'log_buffer_contents_requested':False}
raw=enc(manifest);put(out/'ARCHIVE-MANIFEST.json',raw)
print(json.dumps({'archive_manifest':{'path':str(out/'ARCHIVE-MANIFEST.json'),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()},
    'archive':manifest['archive'],'case_pass':False},sort_keys=True))
