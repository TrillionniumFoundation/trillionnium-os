#!/usr/bin/env python3
"""Root-only capture/export of ended attempt05. Never calls native Chain.run()."""
import argparse
import ast
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import sys
import tarfile
import time
import types
import zlib

sys.dont_write_bytecode=True
B=Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
F=B/'native-guard-root-chains-r10-r1/root-r10-neg01-20261105-05'
R=B/'native-guard-r10-r1-operator-r5'
CANDIDATE=B/'native-guard-attempt05-nonnative-capture-r1-candidate01'
DEST=B/'native-guard-attempt05-nonnative-capture-r1'
PREPARED=DEST/'prepared-01'
HOST_OUT=DEST/'capture-01'
NONCE='e4c3ccb0b2d706be3b7bf105ae772405'
LABEL='root-r10-neg01-20261105-05'
CAPTURE={'path':str(CANDIDATE/'source/capture_non_native_attempt05.py'),'bytes':22313,
 'sha256':'3e72353d8bd0dec122f10f5f3f5a6fe50e6dfb5251a41e51fc89974d4d4867bb'}
TRANSPORT={'path':str(R/'root-chain/source/run_component_root_once.py'),'bytes':45756,
 'sha256':'f2134edd87a21ae3cde5f461c6f9c8163cd9597c90c60a98b98bdbb0970ecc34'}
TRANSPORT_PACKAGE={'path':str(R/'root-chain/SOURCE-MANIFEST.json'),'bytes':2168,
 'sha256':'e45cfa522f75f2ad51973fafa302b784832217b6c609ed4427a82f068a9f2629'}
ROOT_PLAN={'path':str(F/'ROOT-PLAN.original.json'),'bytes':4737,
 'sha256':'30f50baff1418464d6abef24744f61ba88de927185208679a3a19cb3dbfa62f6'}
ROOT_FAILURE={'path':str(F/'ROOT-FAILURE.json'),'bytes':10082,
 'sha256':'ae8f5bc9d8897c561adcc901b93e1fd12e997afe655eeb0de44eb32a7263f857'}
MATERIAL={'path':str(F/'material/PREPARED.json'),'bytes':2873,
 'sha256':'054b08b4953dbf99c413b8879f5960eff05f127955db15ed5dba775c05e41045'}
LEASE={'path':str(F/'material/tree/LEASE.json'),'bytes':2496,
 'sha256':'4420765e2968387b861e938726349e17e18d798fd2e11c5deaa46ee57f2f0541'}
CHUNK=600000
MAX_ARCHIVE=64*1024*1024
MAX_PLAIN=72*1024*1024
MAX_CHUNKS=112
PHONE_OUT='/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-snapshots-r10-r1/'+LABEL+'-non-native-capture-01'
ENV='/data/adb/magisk/busybox env -i PATH=/usr/bin:/bin:/usr/libexec/trillionnium PYTHONHOME=/usr PYTHONDONTWRITEBYTECODE=1 LD_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu/android:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu LANG=C.UTF-8 LC_ALL=C.UTF-8 TMPDIR=/var/lib/trillionnium/owner-open/tmp NO_COLOR=1 TERM=dumb /data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root '


def need(ok,reason):
    if not ok:raise ValueError(reason)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(rows):
        out={}
        for key,value in rows:
            need(key not in out,'duplicate JSON key');out[key]=value
        return out
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))


def enc(v):
    return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()


def md(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


class Originals:
    def __init__(self):self.rows={}
    def read(self,path,maximum=MAX_ARCHIVE):
        p=Path(path)
        need(p.is_absolute() and p.resolve(strict=True)==p,'canonical host original required')
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            a=os.fstat(fd)
            need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=maximum,
                 'bounded single-link original required')
            with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(maximum+1)
            need(len(raw)==a.st_size and md(a)==md(os.fstat(fd))==md(p.lstat()),'host original changed')
        finally:os.close(fd)
        value={'path':str(p),'bytes':len(raw),'sha256':sha(raw),'metadata':md(a)}
        need(str(p) not in self.rows or self.rows[str(p)]==value,'original changed across host reads')
        self.rows[str(p)]=value
        return raw
    def pin(self,row,maximum=MAX_ARCHIVE):
        need(isinstance(row,dict) and set(row)=={'path','bytes','sha256'}
            and type(row['bytes']) is int and 0<=row['bytes']<=maximum
            and isinstance(row['sha256'],str) and re.fullmatch('[0-9a-f]{64}',row['sha256']),
            'exact bounded host descriptor required')
        raw=self.read(row['path'],maximum)
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'host original pin differs')
        return raw
    def recheck(self):
        for path,row in list(self.rows.items()):
            need(md(Path(path).lstat())==row['metadata'],'host original metadata changed')
            raw=self.read(path)
            need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'host original bytes changed')


def descriptor(path,raw):return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}


def syncdir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)


def newdir(path):
    path.mkdir(mode=0o700);syncdir(path);syncdir(path.parent)


def put(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    syncdir(path.parent)
    need(path.read_bytes()==raw,'new host original readback differs')


def module(originals,row,name):
    raw=originals.pin(row);m=types.ModuleType(name);m.__file__=row['path']
    exec(compile(raw,row['path'],'exec'),m.__dict__)
    return m


def captured_constants(raw):
    wanted={'LABEL','NONCE','BOOT','OWNER','PACKAGE','LEASE','COMBINATION',
        'PRIOR_BOUNDARY','ROOT_PLAN','ROOT_FAILURE','DEPENDENCIES'}
    values={}
    for node in ast.parse(raw).body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            name=node.targets[0].id
            if name in wanted:
                need(name not in values,'duplicate source constant')
                values[name]=ast.literal_eval(node.value)
    need(set(values)==wanted,'fixed capture constant set differs')
    return values


def source_and_inputs(o):
    raw=o.pin(CAPTURE);v=captured_constants(raw)
    root=strict(o.pin(ROOT_PLAN));failure=strict(o.pin(ROOT_FAILURE))
    prepared=strict(o.pin(MATERIAL));lease=strict(o.pin(LEASE))
    need(root['nonce']==NONCE and root['label']==LABEL and root['package']['sha256']==v['PACKAGE']['sha256']
        and root['source_package']==TRANSPORT_PACKAGE and root['request']['sha256']==v['OWNER'],
        'actual Root attempt05 source binding differs')
    need(failure['state']=='FAILED_OR_UNKNOWN_ORIGINALS_PRESERVED_NO_AUTOMATIC_CONTINUATION'
        and failure['detail']=='component ended before phase; preserve, no additional Root UI'
        and failure['root_fixture_attempts']==[] and len(failure['steps'])==11,
        'actual failed original Root phase differs')
    need(prepared['lease']==v['LEASE'] and lease['package_sha256']==v['PACKAGE']['sha256']
        and lease['nonce']==NONCE and lease['combination']==v['COMBINATION']
        and lease['prior_boundary']['sha256']==v['PRIOR_BOUNDARY'],'actual prepared lease differs')
    mf=strict(o.pin(TRANSPORT_PACKAGE))
    need(len(mf['files'])==3 and mf['frozen_component_package_sha256']==v['PACKAGE']['sha256'],
         'original current transport package differs')
    for row in mf['files']:
        name=PurePosixPath(row['path'])
        need(not name.is_absolute() and '..' not in name.parts,'transport source escaped')
        o.pin({'path':str(Path(TRANSPORT_PACKAGE['path']).parent/str(name)),
               'bytes':row['bytes'],'sha256':row['sha256']})
    o.pin(TRANSPORT)
    return raw,v,root,lease


def phone_request(source,plan_raw):
    payload=enc({'source_b64':base64.b64encode(source).decode(),
                 'plan_b64':base64.b64encode(plan_raw).decode()})
    need(len(payload)<=262144,'capture inline decompression bound')
    zipped=gzip.compress(payload,mtime=0)
    program="import base64,hashlib,json,sys,zlib\nsys.dont_write_bytecode=True\n"
    program+="z=base64.b64decode("+repr(base64.b64encode(zipped).decode())+",validate=True)\n"
    program+="d=zlib.decompressobj(16+zlib.MAX_WBITS);r=d.decompress(z,262145)\n"
    program+="assert len(r)<=262144 and d.eof and not d.unconsumed_tail and not d.unused_data\n"
    program+="p=json.loads(r);assert set(p)=={'source_b64','plan_b64'}\n"
    program+="s=base64.b64decode(p['source_b64'],validate=True);b=base64.b64decode(p['plan_b64'],validate=True)\n"
    program+="assert len(s)=="+str(len(source))+" and hashlib.sha256(s).hexdigest()=="+repr(sha(source))+"\n"
    program+="assert len(b)=="+str(len(plan_raw))+" and hashlib.sha256(b).hexdigest()=="+repr(sha(plan_raw))+"\n"
    program+="sys.argv=['capture_non_native_attempt05.py','--source-sha256',"+repr(sha(source))+",'--plan-sha256',"+repr(sha(plan_raw))+",'--execute-readonly-capture-once']\n"
    program+="exec(compile(s,'<reviewed-attempt05-non-native-capture>','exec'),{'__name__':'__main__','__file__':'<reviewed-attempt05-non-native-capture>','__capture_source_original__':s,'__capture_plan_original__':b})\n"
    compile(program,'fixed_capture_bootstrap','exec')
    request={'kind':'shell','root':True,'timeout_seconds':120,
        'command':ENV+'/usr/bin/python3 -I -B -c '+shlex.quote(program)}
    wire=('shell,v2,raw:/debug_ramdisk/su -c '+shlex.quote(request['command'])).encode()
    need(len(wire)<65536,'actual single-su ADB wire bound')
    return request,len(wire),program.encode()


def prepare():
    o=Originals();source,v,_root,lease=source_and_inputs(o)
    own=o.read(Path(__file__),1024*1024)
    plan={'schema':'hepta.native-guard.non-native-capture-plan.v1',
        'state':'ROOT_REVIEWABLE_READONLY_FAILED_ATTEMPT_CAPTURE','label':LABEL,'nonce':NONCE,
        'boot_id':v['BOOT'],'phone_home':'/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/'+LABEL,
        'phone_output':PHONE_OUT,'lease':v['LEASE'],'package':v['PACKAGE'],
        'combination':v['COMBINATION'],'owner_request_sha256':v['OWNER'],
        'native_prior_boundary_sha256':v['PRIOR_BOUNDARY'],'root_plan':ROOT_PLAN,
        'root_failure':ROOT_FAILURE,'source':{'bytes':len(source),'sha256':sha(source)},
        'dependencies':v['DEPENDENCIES'],'native_submissions':0,'ui_actions':0,'signals':0,
        'automatic_retry':False}
    plan_raw=enc(plan);request,wire,bootstrap=phone_request(source,plan_raw)
    driver={'schema':'hepta.root.non-native-capture-plan.v1','label':LABEL,'nonce':NONCE,
        'out':str(HOST_OUT),'driver_source':descriptor(Path(__file__),own),
        'transport_source':TRANSPORT,'transport_source_package':TRANSPORT_PACKAGE,
        'original_root_plan':ROOT_PLAN,'original_root_failure':ROOT_FAILURE,
        'prepared_material':MATERIAL,'actual_lease':LEASE,'capture_source':CAPTURE,
        'capture_plan':descriptor(PREPARED/'CAPTURE-PLAN.json',plan_raw),
        'capture_request':descriptor(PREPARED/'PHONE-CAPTURE-REQUEST.json',enc(request)),
        'capture_bootstrap':descriptor(PREPARED/'PHONE-CAPTURE-BOOTSTRAP.py',bootstrap),
        'maximum_capture_calls':1,'maximum_export_chunks':MAX_CHUNKS,
        'chunk_bytes':CHUNK,'actual_adb_wire_bytes':wire,
        'automatic_retry':False,'native_case_created':False,'phone_writes_limited_to_evidence_output':True}
    driver_raw=enc(driver);o.recheck()
    try:DEST.lstat()
    except FileNotFoundError:newdir(DEST)
    else:need(DEST.is_dir() and not DEST.is_symlink() and stat.S_IMODE(DEST.stat().st_mode)==0o700,
              'private evidence destination differs')
    newdir(PREPARED)
    for name,body in [('CAPTURE-PLAN.json',plan_raw),('PHONE-CAPTURE-REQUEST.json',enc(request)),
                      ('PHONE-CAPTURE-BOOTSTRAP.py',bootstrap),('ROOT-CAPTURE-PLAN.json',driver_raw)]:
        put(PREPARED/name,body)
    result={'state':'HOST_PREPARED_READONLY_CAPTURE_NOT_EXECUTED',
        'root_plan':descriptor(PREPARED/'ROOT-CAPTURE-PLAN.json',driver_raw),
        'capture_plan':driver['capture_plan'],'capture_request':driver['capture_request'],
        'actual_adb_wire_bytes':wire,'native_case_created':False,'phone_calls':0,'nonces_generated':0}
    put(PREPARED/'PREPARED.json',enc(result));print(json.dumps(result,sort_keys=True),flush=True)
    return 0


def chunk_request(result,index):
    archive=result['archive'];capture=result['capture']
    need(0<archive['bytes']<=MAX_ARCHIVE and 0<=index<MAX_CHUNKS,'chunk count or archive bound')
    prefix="from pathlib import Path\nimport base64,hashlib,json,os,stat\n"
    prefix+="D=Path("+repr(PHONE_OUT)+");A="+repr(archive)+";C="+repr(capture)+";I="+repr(index)+";S="+repr(CHUNK)+"\n"
    prefix+=r'''def md(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(name,pin,maximum):
 p=D/name;fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 try:
  for part in p.parts[1:-1]:
   n=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);os.close(fd);fd=n
  f=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
  try:
   a=os.fstat(f);assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_uid==a.st_gid==0 and stat.S_IMODE(a.st_mode)==0o600 and a.st_size==pin['bytes']<=maximum
   with os.fdopen(f,'rb',closefd=False) as z:b=z.read(maximum+1)
   assert md(a)==md(os.fstat(f))==md(os.stat(p.name,dir_fd=fd,follow_symlinks=False)) and len(b)==pin['bytes'] and hashlib.sha256(b).hexdigest()==pin['sha256']
   return b,md(a)
  finally:os.close(f)
 finally:os.close(fd)
a,am=read('ORIGINALS.tar.gz',A,67108864);c,cm=read('CAPTURE.json',C,16777216)
count=(len(a)+S-1)//S;assert 0<=I<count<=112
b=a[I*S:(I+1)*S]
print(json.dumps({'schema':'hepta.native-guard.non-native-export-chunk.v1','index':I,'count':count,
 'archive':A,'archive_metadata':am,'capture':C,'capture_metadata':cm,
 'offset':I*S,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'raw_b64':base64.b64encode(b).decode(),
 'phone_writes':0,'ui_actions':0,'native_submissions':0},sort_keys=True,separators=(',',':')))
'''
    compile(prefix,'readonly_original_capture_chunk','exec')
    return {'kind':'shell','root':True,'timeout_seconds':30,
        'command':ENV+'/usr/bin/python3 -I -B -c '+shlex.quote(prefix)}


def decode_archive(raw,result):
    need(len(raw)==result['archive']['bytes'] and sha(raw)==result['archive']['sha256'],'actual archive differs')
    d=zlib.decompressobj(16+zlib.MAX_WBITS);plain=d.decompress(raw,MAX_PLAIN+1)
    need(len(plain)<=MAX_PLAIN and d.eof and not d.unconsumed_tail and not d.unused_data,
         'complete bounded gzip archive required')
    with tarfile.open(fileobj=io.BytesIO(plain),mode='r:') as t:
        members=t.getmembers();need(0<len(members)<=8192,'archive member bound')
        files={}
        for row in members:
            name=PurePosixPath(row.name)
            need(row.isfile() and not row.issym() and not row.islnk()
                and not name.is_absolute() and '..' not in name.parts and str(name)==row.name
                and row.name not in files and 0<=row.size<=16*1024*1024,
                'archive type/name/count/size rejected before extraction')
            need(row.uid==row.gid==0 and row.mode==0o600,'capture archive member metadata differs')
            body=t.extractfile(row).read(row.size+1)
            need(len(body)==row.size,'incomplete archive member');files[row.name]=body
    cap_raw=files['CAPTURE.json'];need({'bytes':len(cap_raw),'sha256':sha(cap_raw)}==result['capture'],
         'original CAPTURE byte pin differs')
    cap=strict(cap_raw)
    need(cap['schema']=='hepta.native-guard.non-native-original-capture.v1'
        and cap['state']=='ORIGINAL_PRE_NATIVE_FAILURE_BYTES_CAPTURED_NOT_CLOSED'
        and cap['nonce']==NONCE and cap['label']==LABEL and cap['native_case_created'] is False
        and cap['native_scope_assigned'] is False and 'scope' not in cap,
        'non-native capture identity differs')
    need(set(files)==set(cap['files'])|{'CAPTURE.json'} and len(files)==result['archive_members'],
         'archive omitted or added a logical original')
    for name,row in cap['files'].items():
        body=files[name]
        need({'bytes':len(body),'sha256':sha(body)}=={k:row[k] for k in ('bytes','sha256')},
             'captured member raw pin differs')
    return cap_raw,len(files)


def independent_wrapper(chain,m,tag,out):
    label='ng-'+NONCE+'-'+tag
    path='/home/alex/razr60-local-model-v150/operations/'+label+'/result.json'
    code="from pathlib import Path\nimport base64,hashlib,json,os,stat\np=Path("+repr(path)+")\n"
    code+=r'''assert p.resolve(strict=True)==p
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
 a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<a.st_size<=16777216
 with os.fdopen(fd,'rb',closefd=False) as f:b=f.read(16777217)
 md=lambda s:[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
 assert md(a)==md(os.fstat(fd))==md(p.lstat()) and len(b)==a.st_size
 print(json.dumps({'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'metadata':md(a),'raw_b64':base64.b64encode(b).decode()},sort_keys=True))
finally:os.close(fd)
'''
    row=chain.remote('read-'+tag,code,40)
    raw=base64.b64decode(row['raw_b64'],validate=True)
    need(base64.b64encode(raw).decode()==row['raw_b64']
        and len(raw)==row['bytes'] and sha(raw)==row['sha256'],'independent wrapper bytes differ')
    env=strict(m.read(out/('phone-'+tag)/'stdout.original'))
    need(env['actor_rc']==0 and env['wrapper_sha256']==sha(raw) and env['wrapper']==strict(raw),
         'actual P4 wrapper differs from host phone envelope')
    put(out/(tag+'.WRAPPER.original.json'),raw)
    return env,{'original':{k:row[k] for k in ('path','bytes','sha256','metadata')},
                'copy':descriptor(out/(tag+'.WRAPPER.original.json'),raw)}


def execute(a):
    o=Originals();raw=o.read(Path(a.plan),262144)
    need(sha(raw)==a.plan_sha256,'explicit Root capture plan pin differs')
    p=strict(raw)
    fields={'schema','label','nonce','out','driver_source','transport_source','transport_source_package',
        'original_root_plan','original_root_failure','prepared_material','actual_lease','capture_source',
        'capture_plan','capture_request','capture_bootstrap','maximum_capture_calls','maximum_export_chunks',
        'chunk_bytes','actual_adb_wire_bytes','automatic_retry','native_case_created',
        'phone_writes_limited_to_evidence_output'}
    need(set(p)==fields and p['schema']=='hepta.root.non-native-capture-plan.v1'
        and p['label']==LABEL and p['nonce']==NONCE and p['out']==str(HOST_OUT)
        and p['maximum_capture_calls']==1 and p['maximum_export_chunks']==MAX_CHUNKS
        and p['chunk_bytes']==CHUNK and p['automatic_retry'] is False
        and p['native_case_created'] is False and p['phone_writes_limited_to_evidence_output'] is True,
        'fixed Root read-only capture plan differs')
    fixed={'transport_source':TRANSPORT,'transport_source_package':TRANSPORT_PACKAGE,
        'original_root_plan':ROOT_PLAN,'original_root_failure':ROOT_FAILURE,
        'prepared_material':MATERIAL,'actual_lease':LEASE,'capture_source':CAPTURE}
    need(all(p[k]==v for k,v in fixed.items()),'Root capture input identity differs')
    need(p['driver_source']['path']==str(Path(__file__))
        and o.pin(p['driver_source'])==o.read(Path(__file__),1024*1024),'driver self source differs')
    source,v,_root,_lease=source_and_inputs(o)
    cap_plan=o.pin(p['capture_plan']);request=strict(o.pin(p['capture_request']))
    wanted,wire,bootstrap=phone_request(source,cap_plan)
    need(request==wanted and o.pin(p['capture_bootstrap'])==bootstrap
        and wire==p['actual_adb_wire_bytes'],'prepared actual phone request changed')
    cap_value=strict(cap_plan)
    need(cap_value['source']=={'bytes':len(source),'sha256':sha(source)}
        and cap_value['root_plan']==ROOT_PLAN and cap_value['root_failure']==ROOT_FAILURE,
        'capture request original identity changed')
    m=module(o,TRANSPORT,'frozen_r5_root_transport_only')
    o.recheck()
    transport_plan={'schema':'hepta.root.non-native-capture-transport.v1','label':LABEL,
        'nonce':NONCE,'out':str(HOST_OUT),'source_package':TRANSPORT_PACKAGE,
        'root_capture_plan':descriptor(Path(a.plan),raw),'native_chain_run_is_called':False}
    chain=m.Chain(transport_plan,enc(transport_plan))
    deadline=time.monotonic()+600;phone_tags=[];operations=[];chunks=[]
    try:
        put(HOST_OUT/'CAPTURE-DRIVER.original.py',o.pin(p['driver_source']))
        put(HOST_OUT/'ROOT-CAPTURE-PLAN.original.json',raw)
        put(HOST_OUT/'CAPTURE-PLAN.original.json',cap_plan)
        put(HOST_OUT/'PHONE-CAPTURE-REQUEST.original.json',enc(request))
        tags=['nn05-capture01']+['nn05-export-%03d'%i for i in range(MAX_CHUNKS)]
        code="from pathlib import Path\nimport errno,json\nT=Path("+repr(chain.remote_root)+")\n"
        code+="labels="+repr([('ng-'+NONCE+'-'+tag,tag) for tag in tags])+"\n"
        code+=r'''missing=[]
for label,tag in labels:
 for p in (Path('/home/alex/razr60-local-model-v150/requests')/(label+'.json'),
           Path('/home/alex/razr60-local-model-v150/operations')/label,
           T/('phone-'+tag)):
  try:p.lstat()
  except OSError as e:assert e.errno==errno.ENOENT;missing.append(str(p))
  else:raise ValueError('one-use capture/export namespace already exists')
print(json.dumps({'state':'ALL_EXACT_ONCE_NAMES_ABSENT','paths':missing,'phone_calls':0},sort_keys=True))
'''
        chain.remote('nn05-namespace-preflight',code,40)
        def call(tag,req):
            need(time.monotonic()+req['timeout_seconds']+100<deadline,'Root capture/export total budget expired')
            phone_tags.append(tag)
            value=chain.phone(tag,req)
            envelope,op=independent_wrapper(chain,m,tag,HOST_OUT)
            ph=envelope['wrapper']['phone']
            need(ph['rc']==0 and ph['stderr']=='' and strict(ph['stdout'])==value,
                 'actual phone result original differs')
            operations.append({'phase':tag,'operation':op,'phone_stdout_sha256':sha(ph['stdout'].encode())})
            put(HOST_OUT/(tag+'.RESULT.original.json'),ph['stdout'].encode())
            return value
        result=call('nn05-capture01',request)
        need(result['schema']=='hepta.native-guard.non-native-snapshot-result.v1'
            and result['state']=='ORIGINAL_PRE_NATIVE_CAPTURE_ARCHIVED_NOT_CLOSED' and result['nonce']==NONCE
            and result['label']==LABEL and result['capture_source']=={'bytes':CAPTURE['bytes'],'sha256':CAPTURE['sha256']}
            and result['capture_plan']=={'bytes':len(cap_plan),'sha256':sha(cap_plan)}
            and result['capture_path']==PHONE_OUT+'/CAPTURE.json'
            and result['archive_path']==PHONE_OUT+'/ORIGINALS.tar.gz'
            and result['native_case_created'] is False and result['component_qualified'] is False,
            'actual fixed non-native capture result differs')
        need(0<result['archive']['bytes']<=MAX_ARCHIVE,'original archive exceeds fixed bound')
        count=(result['archive']['bytes']+CHUNK-1)//CHUNK
        need(0<count<=MAX_CHUNKS,'original chunk count bound')
        archive_meta=capture_meta=None
        for i in range(count):
            row=call('nn05-export-%03d'%i,chunk_request(result,i))
            need(row['schema']=='hepta.native-guard.non-native-export-chunk.v1'
                and row['index']==i and row['count']==count and row['archive']==result['archive']
                and row['capture']==result['capture'] and row['offset']==i*CHUNK,
                'actual read-only export index differs')
            body=base64.b64decode(row['raw_b64'],validate=True)
            need(base64.b64encode(body).decode()==row['raw_b64']
                and len(body)==row['bytes']==min(CHUNK,result['archive']['bytes']-i*CHUNK)
                and sha(body)==row['sha256'],'actual raw chunk differs')
            if archive_meta is None:archive_meta=row['archive_metadata'];capture_meta=row['capture_metadata']
            need(row['archive_metadata']==archive_meta and row['capture_metadata']==capture_meta,
                 'published original changed between chunks')
            chunks.append(body)
        archive=b''.join(chunks);cap_raw,members=decode_archive(archive,result)
        put(HOST_OUT/'ORIGINALS.tar.gz',archive);put(HOST_OUT/'CAPTURE.original.json',cap_raw)
        o.recheck()
        summary={'schema':'hepta.root.non-native-capture-execution.v1',
            'state':'ORIGINAL_NON_NATIVE_CAPTURE_AND_EXPORT_COMPLETE_NOT_CLOSED',
            'label':LABEL,'nonce':NONCE,'source':p['driver_source'],'capture_source':CAPTURE,
            'root_capture_plan':descriptor(Path(a.plan),raw),'original_root_plan':ROOT_PLAN,
            'original_root_failure':ROOT_FAILURE,'actual_lease':LEASE,
            'archive':descriptor(HOST_OUT/'ORIGINALS.tar.gz',archive),
            'capture':descriptor(HOST_OUT/'CAPTURE.original.json',cap_raw),
            'phone_archive_original':{'path':result['archive_path'],**result['archive'],'metadata':archive_meta},
            'phone_capture_original':{'path':result['capture_path'],**result['capture'],'metadata':capture_meta},
            'archive_members':members,'operations':operations,'steps':chain.steps,
            'phone_phase_names':phone_tags,'capture_calls':1,'export_calls':count,
            'native_case_created':False,'native_submissions':0,'ui_actions':0,'signals':0,
            'component_qualified':False,'business_qualified':False,'automatic_retry':False,
            'original_sender_and_restore_not_yet_host_closed':True}
        body=enc(summary);put(HOST_OUT/'ROOT-CAPTURE-RESULT.json',body)
        print(json.dumps({'state':summary['state'],'result':descriptor(HOST_OUT/'ROOT-CAPTURE-RESULT.json',body),
            'archive':summary['archive'],'capture':summary['capture'],'native_case_created':False},sort_keys=True),flush=True)
        return 0
    except BaseException as error:
        body=enc({'schema':'hepta.root.non-native-capture-failure.v1',
            'state':'ORIGINAL_CAPTURE_OR_EXPORT_FAILED_OR_UNKNOWN_PRESERVED',
            'error_type':type(error).__name__,'detail':str(error)[:2048],
            'phone_phase_names_attempted':phone_tags,'operations':operations,'steps':chain.steps,
            'automatic_retry':False,'native_case_created':False,'component_qualified':False,
            'instruction':'Reconcile the same originals. Never repeat the capture operation.'})
        put(HOST_OUT/'CAPTURE-FAILURE.json',body)
        raise


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--plan');p.add_argument('--plan-sha256')
    g=p.add_mutually_exclusive_group()
    g.add_argument('--prepare-host-inputs-once',action='store_true')
    g.add_argument('--execute-root-capture-once',action='store_true')
    a=p.parse_args()
    if a.prepare_host_inputs_once:
        need(a.plan is None and a.plan_sha256 is None,'host preparation takes fixed actual inputs only')
        return prepare()
    if a.execute_root_capture_once:
        need(a.plan and a.plan_sha256,'explicit actual Root capture plan required')
        return execute(a)
    print(json.dumps({'state':'PREVIEW_ONLY','phone_calls':0,'host_reads':0,'host_writes':0,
        'native_submissions':0,'nonces_generated':0,'prepared_output':str(PREPARED),
        'capture_output':str(HOST_OUT)},sort_keys=True))
    return 0


if __name__=='__main__':raise SystemExit(main())
