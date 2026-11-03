"""Fresh source-only QA: exact original clang syntax, small official context checker."""
from pathlib import Path
import json,hashlib,subprocess,os,time,uuid,shlex,signal
B=Path('/home/alex/razr-flash-validation-canonical-20261014');S=B/'staging/rog-r57-count8-source-and-build';C=S/'inputs/source_3';OWNER=S/'inputs/source_7/android-integration/working-tree/vendor/trillionnium/owner-open';CL=S/'inputs/source_11/linux-x86/clang-r584948b';N=S/'inputs/lower_count5_completed_current_upper/host/linux-x86';U=S/'private/count8-native-636cdc93-1aaf-4c49-8c0d-88922aec6943/upper';SRC=B/'tools/r11r4-native-source-review-r4';POLS=U/'soong/.intermediates/system/sepolicy/precompiled_sepolicy/android_common/leap/precompiled_sepolicy';SEPOL=U/'soong/.intermediates/external/selinux/libsepol/libsepol/linux_glibc_x86_64_static/libsepol.a'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for q in iter(lambda:f.read(1024**2),b''):h.update(q)
 return h.hexdigest()
def pin(p):
 s=p.stat();q={'path':str(p),'sha256':sha(p),'bytes':s.st_size,'ino':s.st_ino,'dev':s.st_dev,'mtime':s.st_mtime_ns,'ctime':s.st_ctime_ns};z=p.stat();assert(s.st_size,s.st_ino,s.st_dev,s.st_mtime_ns,s.st_ctime_ns)==(z.st_size,z.st_ino,z.st_dev,z.st_mtime_ns,z.st_ctime_ns);return q
def mem():return int(next(x.split()[1]for x in Path('/proc/meminfo').read_text().splitlines()if x.startswith('MemAvailable:')))*1024
assert mem()>=8*1024**3
os.umask(0o077);os.sched_setaffinity(0,sorted(os.sched_getaffinity(0))[:4]);O=B/'evidence'/('r11r4-native-sourceqa-'+str(uuid.uuid4()));O.mkdir();(O/'logs').mkdir();r={'schema':'razr.r11r4.native-sourceqa.v1','pass':False,'phone_operations':0,'image_mutations':0,'module_builds':0,'small_official_host_checker_build':True,'commands':[]};inputs={}
def track(p):inputs[str(p)]=pin(p)
def capsule(args,extra=()):
 cmd=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--cap-drop','ALL','--ro-bind','/usr','/usr','--ro-bind','/bin','/bin','--ro-bind','/lib','/lib','--ro-bind','/lib64','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--ro-bind',str(C),'/src','--tmpfs','/src/prebuilts','--ro-bind',str(SRC/'native'),'/src/vendor/trillionnium/owner-open/native','--ro-bind',str(N),'/tools','--ro-bind',str(SEPOL),'/libsepol.a','--ro-bind',str(POLS),'/cached-policy','--ro-bind',str(SRC/'property_contexts.proposed'),'/new-owner-property-contexts','--bind',str(O),'/work','--chdir','/src','--clearenv','--setenv','PATH','/usr/bin:/bin','--setenv','LD_LIBRARY_PATH','/tools/lib64','--setenv','LANG','C.UTF-8','--setenv','TMPDIR','/tmp'];
 for part in sorted((C/'prebuilts').iterdir()):
  if part.name!='clang':cmd+=['--ro-bind',str(part),'/src/prebuilts/'+part.name]
 cmd+=['--ro-bind',str(CL),'/src/prebuilts/clang/host/linux-x86/clang-r584948b']
 return cmd+list(extra)+['--']+args
def run(label,args,expected=0,timeout=120):
 cmd=capsule(args);so=O/'logs'/(label+'.stdout');se=O/'logs'/(label+'.stderr');t=time.monotonic();peak=0;failure=None
 with so.open('xb')as a,se.open('xb')as b:
  p=subprocess.Popen(cmd,stdout=a,stderr=b,stdin=subprocess.DEVNULL,start_new_session=True)
  while p.poll()is None:
   rss=0
   for proc in Path('/proc').iterdir():
    if not proc.name.isdigit():continue
    try:
     if os.getpgid(int(proc.name))==p.pid:rss+=sum(int(v.split()[1])*1024 for v in(proc/'status').read_text().splitlines()if v.startswith('VmRSS:'))
    except (OSError,ProcessLookupError):pass
   peak=max(peak,rss)
   if peak>8*1024**3 or mem()<8*1024**3 or time.monotonic()-t>timeout:failure='finite resource/time boundary';os.killpg(p.pid,signal.SIGKILL);break
   time.sleep(.1)
  code=p.wait();a.flush();b.flush();os.fsync(a.fileno());os.fsync(b.fileno())
 row={'label':label,'argv':cmd,'native_exit_code':code,'expected_exit_code':expected,'duration_seconds':time.monotonic()-t,'peak_RSS':peak,'failure':failure,'stdout':pin(so),'stderr':pin(se)};r['commands'].append(row);assert failure is None and(code==expected if expected is not None else code!=0),label;return so.read_text(),se.read_text()
try:
 sources=['owner_open_bootstrap.proposed.cpp','owner_open_ingress_proxy.proposed.cpp','owner_open_kernel_boot.h','property_contexts.proposed','trillionnium-owner-open.proposed.rc']
 for n in sources:track(SRC/n)
 for p in (SRC/'native').iterdir():track(p)
 for p in [POLS,SEPOL,CL/'bin/clang-22',N/'lib64/libbase.so',N/'lib64/libc++.so',N/'lib64/liblog.so']:track(p)
 log=S/'private/count8-native-636cdc93-1aaf-4c49-8c0d-88922aec6943/logs/compiledcommands.stdout';track(log)
 for source in ['owner_open_bootstrap.cpp','owner_open_ingress_proxy.cpp']:
  line=next(x for x in log.read_text().splitlines()if ' -c 'in x and x.rstrip().endswith('native/'+source));tokens=shlex.split(line);tokens=[x for x in tokens if not x.startswith('PWD=')];out=[];skip=False
  for n,t in enumerate(tokens):
   if skip:skip=False;continue
   if t in ('-o','-MF'):skip=True;continue
   if t in ('-MD','-MMD'):continue
   out.append('-fsyntax-only'if t=='-c'else t)
  run('actual-clang-syntax-'+source,out,timeout=90)
 # The official checker sources are unchanged; only this fresh host runtime
 # closure uses existing AOSP host shared libbase/log and static libsepol.
 parser='system/core/property_service/libpropertyinfoparser';ser='system/core/property_service/libpropertyinfoserializer';checker='system/core/property_service/property_info_checker/property_info_checker.cpp'
 cc=[checker,parser+'/property_info_parser.cpp',*[ser+'/'+n+'.cpp'for n in ['property_info_file','property_info_serializer','trie_builder','trie_serializer']]]
 for n in cc:track(C/n)
 args=['prebuilts/clang/host/linux-x86/clang-r584948b/bin/clang++','-std=c++20','-O2','-stdlib=libc++','-nostdlib++','-I'+parser+'/include','-I'+ser+'/include','-Isystem/libbase/include','-Iexternal/selinux/libsepol/include',*cc,'/libsepol.a','-L/tools/lib64','-Wl,-rpath,/tools/lib64','-lbase','-llog','-lc++','-ldl','-lpthread','-lm','-o','/work/property_info_checker']
 run('official-property-info-checker-build',args,timeout=120)
 for n in ['system/etc/selinux/plat_property_contexts','system_ext/etc/selinux/system_ext_property_contexts']:track(U/'target/product/leap'/n)if(U/'target/product/leap'/n).is_file()else track(S/'inputs/lower_count5_completed_current_upper/target/product/leap'/n)
 # Check the exact new owner declarations against the existing compiled policy;
 # final image audit additionally proves the original policy type/rules unchanged.
 run('official-property-contexts-positive',['/work/property_info_checker','/cached-policy','/new-owner-property-contexts'])
 (O/'bad-contexts').write_text('trillionnium.owner_open.diag.run u:object_r:nonexistent_r11r4_property_type:s0 exact string\n')
 run('official-property-contexts-negative-unknown-type',['/work/property_info_checker','/cached-policy','/work/bad-contexts'],expected=None)
 r['checker']=pin(O/'property_info_checker');r['pass']=True
except BaseException as e:r['failure']={'type':type(e).__name__,'message':str(e)}
r['inputs_before']=inputs
try:
 r['inputs_after']={k:pin(Path(k))for k in inputs};assert r['inputs_before']==r['inputs_after']
except BaseException as e:r['pass']=False;r['input_guard_failure']=str(e)
with(O/'receipt.json').open('x')as f:json.dump(r,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
print(json.dumps({'out':str(O),'receipt':pin(O/'receipt.json'),'pass':r['pass'],'failure':r.get('failure'),'last_command':r['commands'][-1]if r['commands']else None}))
