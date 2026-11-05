import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import time
import zlib

B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
LABEL = 'root-r10-neg01-20261105-09'
PID = 80237
OUT = B/'fixed19-external09-1ad3-readonly-evidence01'
ACTOR = B/(LABEL+'.preview.actor.py')
COMPONENT = B/'native-guard-root-chains-r10-r1'/LABEL/'material/component-inputs.tar.gz'
META = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')

def need(v,message):
    if not v:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def enc(value):
    return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()

def meta(value):
    return [getattr(value,key) for key in META]

def desc(path,raw):
    return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}

def read_fixed(path,size,digest):
    need(path.is_absolute() and path.resolve(strict=True)==path,'canonical fixed original required')
    fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==size,'exact single-link original required')
        with os.fdopen(fd,'rb',closefd=False) as stream:
            raw = stream.read(size+1)
        need(len(raw)==size and sha(raw)==digest,'fixed original byte pin differs')
        need(meta(before)==meta(os.fstat(fd))==meta(path.lstat()),'fixed original changed during read')
        return raw,meta(before)
    finally:
        os.close(fd)

actor,actor_meta = read_fixed(ACTOR,82909,'34c1534d5985bd643c74361a5009b980e5684d6f1373b2e34eed7fcbde283e04')
compressed,component_meta = read_fixed(COMPONENT,469839,'79106cab8e032e60958419e26506d80e78f7127a22300e9668949d573c0ff07c')
decoder = zlib.decompressobj(31)
plain = decoder.decompress(compressed,16*1024*1024+1)
need(len(plain)<=16*1024*1024 and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
     'bounded single original gzip stream required')
members = {}
with tarfile.open(fileobj=io.BytesIO(plain),mode='r:') as archive:
    for item in archive:
        path = Path(item.name)
        need(item.isreg() and not item.pax_headers and not path.is_absolute() and str(path)==item.name
             and '..' not in path.parts and item.name not in members and len(members)<56,
             'exact regular bounded original component archive required')
        need(item.uid==item.gid==0 and item.mode==0o600 and item.mtime==0 and 0<=item.size<=8*1024*1024,
             'original component tar metadata differs')
        raw = archive.extractfile(item).read(item.size+1)
        need(len(raw)==item.size,'short original component member')
        members[item.name] = raw
need(len(members)==56 and sum(map(len,members.values()))<=8*1024*1024,'complete bounded56 component originals required')
need(len(members['LEASE.json'])==2496 and sha(members['LEASE.json'])=='02b64a4875aa432d3d0f890bb176d500b2eb3ce9faac7892bf51a2d427531745',
     'original external09 lease differs from retained PREPARED')
lease = json.loads(members['LEASE.json'])
need(lease['label']==LABEL and lease['nonce']=='7c79195945d64e569a191166ac122a08'
     and lease['package_sha256']=='67dc40470b8ecb1e10cb57f8953a3d0b6db309b45079216eb24cd65f0760107c',
     'actual lease label/nonce/runtime crosslink differs')
xz = lzma.compress(plain,format=lzma.FORMAT_XZ,check=lzma.CHECK_CRC64,preset=6)
need(lzma.decompress(xz)==plain,'lossless original tar xz mirror differs')
observations = []
ps_blobs = {}
for index in range(2):
    start = time.time_ns()
    result = subprocess.run(['/bin/ps','-axo','pid=,ppid=,pgid=,sess=,lstart=,command='],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=False)
    need(result.returncode==0 and len(result.stdout)<=2*1024*1024 and len(result.stderr)<=65536,'bounded successful ps observation required')
    matching = []
    for line in result.stdout.decode('utf8',errors='strict').splitlines():
        fields = line.split(None,9)
        need(len(fields)==10 and all(x.isdigit() for x in fields[:3]),'unparsed ps process row')
        if fields[0]==str(PID) or fields[2]==str(PID) or LABEL in fields[9]:
            matching.append(line)
    stdout_name = 'PS-'+str(index)+'.stdout.original'
    stderr_name = 'PS-'+str(index)+'.stderr.original'
    ps_blobs[stdout_name] = result.stdout;ps_blobs[stderr_name] = result.stderr
    observations.append({'index':index,'started_unix_ns':start,'finished_unix_ns':time.time_ns(),
        'ps_argv':['/bin/ps','-axo','pid=,ppid=,pgid=,sess=,lstart=,command='],
        'ps_returncode':result.returncode,'stdout':desc(OUT/stdout_name,result.stdout),
        'stderr':desc(OUT/stderr_name,result.stderr),
        'owned_pid_or_group_or_exact_label_rows':matching,'matching_process_count':len(matching)})
    if index==0:
        time.sleep(1)
actor2,actor_meta2 = read_fixed(ACTOR,82909,sha(actor))
compressed2,component_meta2 = read_fixed(COMPONENT,469839,sha(compressed))
need(actor2==actor and actor_meta2==actor_meta and compressed2==compressed and component_meta2==component_meta,
     'Mac original actor/archive changed during observations')
need(OUT.parent.resolve(strict=True)==OUT.parent and not OUT.exists() and not OUT.is_symlink(),
     'new independent Mac evidence directory required')
os.mkdir(OUT,0o700)

def syncdir(path):
    fd = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def put(name,raw):
    path = OUT/name
    fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    need(path.read_bytes()==raw,'new read-only evidence mirror differs')
    return desc(path,raw)

source_row = put('COLLECTOR.original.py',COLLECTOR_SOURCE)
actor_copy = put('SENDER-ACTOR.original.py',actor)
xz_row = put('component-inputs.original.tar.xz',xz)
lease_row = put('LEASE.original.json',members['LEASE.json'])
for name,raw in sorted(ps_blobs.items()):
    put(name,raw)
observation = {'schema':'hepta.fixed19.failed-sender-readonly-process-observation.v2',
    'label':LABEL,'original_sender_pid':PID,'original_pgid':PID,'collector_source':source_row,
    'observations':observations,'both_later_observations_absent':all(x['matching_process_count']==0 for x in observations),
    'signals_sent':0,'original_parent_join_proven':False,'original_capture_eof_repaired':False,'case_pass':False}
observation_raw = enc(observation)
observation_row = put('MAC-SENDER-ABSENCE.original.json',observation_raw)
mirror = {'schema':'hepta.fixed19.lossless-component-original-tar-mirror.v1',
    'state':'SAME_ORIGINAL_COMPONENT_TAR_BYTES_RETAINED_WITH_XZ',
    'source_archive':dict(desc(COMPONENT,compressed),metadata=component_meta),
    'tar_plaintext':{'bytes':len(plain),'sha256':sha(plain)},'archive':xz_row,
    'files':[desc(name,raw) for name,raw in sorted(members.items())],
    'actor_source':dict(desc(ACTOR,actor),metadata=actor_meta),'actor_copy':actor_copy,
    'lease_original':lease_row,'regular_members':len(members),
    'full9_source_bookends_equal':True,'original_files_changed':False,'phone_calls':0,'case_pass':False}
mirror_row = put('COMPONENT-XZ-MIRROR-RESULT.original.json',enc(mirror))
# This small archive contains only the collector's new evidence copies and raw ps output.
evidence = dict(ps_blobs,**{'COLLECTOR.original.py':COLLECTOR_SOURCE,'SENDER-ACTOR.original.py':actor,
    'LEASE.original.json':members['LEASE.json'],'MAC-SENDER-ABSENCE.original.json':observation_raw,
    'COMPONENT-XZ-MIRROR-RESULT.original.json':enc(mirror)})
buf = io.BytesIO()
with tarfile.open(fileobj=buf,mode='w',format=tarfile.USTAR_FORMAT) as archive:
    for name,raw in sorted(evidence.items()):
        info = tarfile.TarInfo(name);info.size=len(raw);info.mode=0o600;info.uid=info.gid=0;info.mtime=0
        archive.addfile(info,io.BytesIO(raw))
evidence_plain = buf.getvalue()
evidence_xz = lzma.compress(evidence_plain,format=lzma.FORMAT_XZ,check=lzma.CHECK_CRC64,preset=6)
need(lzma.decompress(evidence_xz)==evidence_plain,'evidence mirror differs')
evidence_row = put('MAC-ORIGINALS-AND-OBSERVATIONS.tar.xz',evidence_xz)
syncdir(OUT);syncdir(OUT.parent)
result = {'schema':'hepta.fixed19.external09-readonly-mac-collection.v1',
    'state':'FIXED_ACTOR_AND_COMPONENT_ORIGINALS_MIRRORED_LATER_PROCESS_OBSERVATIONS_RETAINED',
    'collector_source':source_row,'actor_source':mirror['actor_source'],'actor_copy':actor_copy,
    'source_component_archive':mirror['source_archive'],'component_tar_xz':xz_row,
    'component_mirror_result':mirror_row,'lease_original':lease_row,'sender_observations':observation_row,
    'evidence_archive':evidence_row,'evidence_tar_plaintext':{'bytes':len(evidence_plain),'sha256':sha(evidence_plain)},
    'evidence_files':[desc(name,raw) for name,raw in sorted(evidence.items())],
    'both_later_observations_absent':observation['both_later_observations_absent'],
    'phone_calls':0,'signals_sent':0,'case_pass':False,'original_parent_join_proven':False,
    'original_capture_eof_repaired':False,'original_files_changed':False}
put('RESULT.json',enc(result));syncdir(OUT)
print(enc(result).decode(),end='')
