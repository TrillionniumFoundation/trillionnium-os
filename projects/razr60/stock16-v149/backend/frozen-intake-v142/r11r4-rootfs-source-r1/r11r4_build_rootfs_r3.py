"""Fresh host-only official stager+two EROFS builds, unchanged original runtime libs."""
from pathlib import Path
import os,json,hashlib,subprocess,time,signal,uuid,stat
B=Path('/home/alex/razr-flash-validation-canonical-20261014');S=B/'staging/rog-r57-count8-source-and-build';OLD=B/'evidence/r11r4-baseline-public-rootfs-extract-9ef442f6-2877-4c08-b5e9-875b1228b918/root';MAN=B/'evidence/coldprocess-r3-four-part-candidate-91437687-0e3c-4da0-ba8a-e39816bd0eb0/offline-audit-b21ffc5d-7fa2-489e-86b0-3a7e3c7d4823/components/rootfs_manifest.bin';N=S/'inputs/lower_count5_completed_current_upper/host/linux-x86';TOOLS=S/'inputs/source_7/tools/owner-open';R=B/'tools/r11r4-rootfs-source-r1';NEWCORE=B/'evidence/r11r4-gnu-core-crossbuild-r1-704684640487/bin/trillionnium-owner-open-r5-core';BROKER=B/'evidence/r11r4-gnu-core-crossbuild-r1-704684640487/source/proposed/tools/owner-open/owner_open_broker_admission_v2.py';REPLACEMENTS={'/usr/libexec/trillionnium/owner-open/owner_open_rootlinux_supervisor.py':(R/'supervisor.py','/replacements/supervisor.py','de9f5cb8af02bb523384df35c4263655faa940fe85d43782ccbe90ee254ad42f'),'/etc/trillionnium/owner-open/rootlinux-supervisor.json':(R/'rootfs-supervisor.json','/replacements/rootfs-supervisor.json','1c2852ca77ff54f85d72e1230f7507f9e6be60935952dfd638f9414b3a235462'),'/usr/libexec/trillionnium/trillionnium-owner-open-r5-core':(NEWCORE,'/new-core','7046846404871ceffe1cc3241fc6aa2da6c281eb8832595dc26b283e307b4031'),'/usr/libexec/trillionnium/owner-open/owner_open_broker_admission_v2.py':(BROKER,'/new-broker.py','76131b9d99e8b51affea4680e79c00236992a48d13f20ddf8541a539e6995d15')}
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for q in iter(lambda:f.read(1024**2),b''):h.update(q)
 return h.hexdigest()
def pin(p):
 s=p.lstat();assert stat.S_ISREG(s.st_mode)and p.resolve()==p;v={'path':str(p),'bytes':s.st_size,'sha256':sha(p),'metadata9':{k:getattr(s,k)for k in ['st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns']}};z=p.lstat();assert all(v['metadata9'][k]==getattr(z,k)for k in v['metadata9']);return v
def mem():return int(next(x.split()[1]for x in Path('/proc/meminfo').read_text().splitlines()if x.startswith('MemAvailable:')))*1024
assert mem()>=8*1024**3;os.umask(0o077);os.sched_setaffinity(0,sorted(os.sched_getaffinity(0))[:4]);O=B/'evidence'/('r11r4-rootfs-build-'+str(uuid.uuid4()));O.mkdir();(O/'logs').mkdir();r={'schema':'razr.r11r4.actual-official-erofs-build.v1','pass':False,'commands':[],'phone_operations':0,'old_images_mutated':False,'P0_qualified':False,'P1_qualified':False,'all_original_runtime_libraries_kept':False};inputs={}
def track(p):inputs[str(p)]=pin(p);return inputs[str(p)]
def cap(args):
 return ['/usr/bin/bwrap','--unshare-all','--die-with-parent','--cap-drop','ALL','--ro-bind','/usr','/usr','--ro-bind','/bin','/bin','--ro-bind','/lib','/lib','--ro-bind','/lib64','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--ro-bind',str(OLD),'/baseline','--ro-bind',str(R),'/replacements','--ro-bind',str(NEWCORE),'/new-core','--ro-bind',str(BROKER),'/new-broker.py','--ro-bind',str(TOOLS),'/scripts','--ro-bind',str(N),'/tools','--bind',str(O),'/work','--clearenv','--setenv','PATH','/usr/bin:/bin','--setenv','LD_LIBRARY_PATH','/tools/lib64','--setenv','LANG','C.UTF-8','--setenv','SOURCE_DATE_EPOCH','0','--']+args
def run(label,args):
 cmd=cap(args);t=time.monotonic();so=O/'logs'/(label+'.stdout');se=O/'logs'/(label+'.stderr');failure=None;peak=0
 with so.open('xb')as a,se.open('xb')as b:
  p=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=a,stderr=b,start_new_session=True,umask=0o022)
  while p.poll()is None:
   rss=0
   for z in Path('/proc').iterdir():
    if not z.name.isdigit():continue
    try:
     if os.getpgid(int(z.name))==p.pid:rss+=sum(int(q.split()[1])*1024 for q in(z/'status').read_text().splitlines()if q.startswith('VmRSS:'))
    except OSError:pass
   peak=max(peak,rss)
   if peak>8*1024**3 or mem()<8*1024**3 or time.monotonic()-t>180:failure='finite4CPU/8GiB/180s boundary';os.killpg(p.pid,signal.SIGKILL);break
   time.sleep(.1)
  code=p.wait()
 row={'label':label,'argv':cmd,'native_exit_code':code,'failure':failure,'duration_seconds':time.monotonic()-t,'peak_RSS':peak,'stdout':pin(so),'stderr':pin(se)};r['commands'].append(row);assert code==0 and failure is None,label
try:
 track(Path(__file__));track(MAN)
 for q in ['stage_owner_open_rootfs_payload_release.py','build_owner_open_erofs_release.py','build_owner_open_rootfs_image_release.py']:track(TOOLS/q)
 for q in ['bin/mkfs.erofs','bin/fsck.erofs','lib64/libc++.so','lib64/libbase.so','lib64/liblog.so','lib64/libcutils.so','lib64/libselinux.so','lib64/libpcre2.so']:track(N/q)
 copy=O/'mkfs.erofs';copy.write_bytes((N/'bin/mkfs.erofs').read_bytes());copy.chmod(0o555);track(copy)
 assert sha(N/'bin/mkfs.erofs')=='b254640c783f9626b81b90d483c35d0e998c42113ba1259d1f3f5accfd0dc8e0'
 original=json.loads(MAN.read_text());entries=[];changes={}
 for row in original['entries']:
  d=row['destination'];old=OLD/d.lstrip('/');oldref=track(old);assert oldref['sha256']==row['sha256']and oldref['bytes']==row['bytes']
  source='/baseline'+d;h=row['sha256']
  if d in REPLACEMENTS:
   p,source,h=REPLACEMENTS[d];newref=track(p);assert newref['sha256']==h;changes[d]={'before':oldref,'after':newref}
  entries.append({'role':row['role'],'source':source,'destination':d,'mode':row['mode'],'uid':0,'gid':0,'expected_sha256':h,'require_aarch64_elf':row['elf']is not None})
 assert len(entries)==931 and len(changes)==4
 plan={'schema':'org.trillionnium.owner-open.rootfs-payload-plan.v1','payload_id':'r57-r11-r4-native-boot-scoped-codex-host-relay','architecture':'aarch64','libc':'glibc','entries':entries}
 with(O/'payload-plan.json').open('x')as f:json.dump(plan,f,indent=2);f.write('\n')
 (O/'payload-plan.json').chmod(0o444);track(O/'payload-plan.json')
 run('official-stage',['/usr/bin/python3','-B','-E','/scripts/stage_owner_open_rootfs_payload_release.py','--execute','--plan','/work/payload-plan.json','--output','/work/staged','--json'])
 run('official-two-erofs-build',['/usr/bin/python3','-B','-E','/scripts/build_owner_open_erofs_release.py','--execute','--staging','/work/staged','--output','/work/erofs','--mkfs','/work/mkfs.erofs','--expected-mkfs-sha256','b254640c783f9626b81b90d483c35d0e998c42113ba1259d1f3f5accfd0dc8e0'])
 run('actual-erofs-fs-and-extract',['/tools/bin/fsck.erofs','--extract=/work/extracted','/work/erofs/owner-open-rootfs.erofs'])
 m=json.loads((O/'erofs/owner-open-rootfs.image-manifest.json').read_text());assert m['entry_count']==931 and m['reproducibility_runs']==2 and m['reproducible']is True
 actual={}
 for row in m['entries']:
  d=row['destination'];p=O/'extracted'/d.lstrip('/');q=pin(p);assert q['sha256']==row['sha256']and q['bytes']==row['bytes'];actual[d]=q
 for d,p in actual.items():assert p['sha256']==(REPLACEMENTS[d][2]if d in REPLACEMENTS else inputs[str(OLD/d.lstrip('/'))]['sha256'])
 r.update(outputs={n:pin(O/'erofs'/n)for n in ['owner-open-rootfs.erofs','owner-open-rootfs.erofs.sha256','owner-open-rootfs.image-manifest.json']},allowed_four_payload_changes=changes,all_931_current_payloads_actually_extracted=actual,two_normalized_builds_byte_identical=True,all_original_runtime_libraries_kept=True,original_r5_host_unchanged=True,unmodified_payload_count=927)
 r['pass']=True
except BaseException as e:r['failure']={'type':type(e).__name__,'message':str(e)}
r['inputs_before']=inputs
try:r['inputs_after']={p:pin(Path(p))for p in inputs};assert r['inputs_before']==r['inputs_after']
except BaseException as e:r['pass']=False;r['input_guard_failure']=str(e)
with(O/'receipt.json').open('x')as f:json.dump(r,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
print(json.dumps({'out':str(O),'receipt':pin(O/'receipt.json'),'pass':r['pass'],'failure':r.get('failure'),'outputs':r.get('outputs')}))
