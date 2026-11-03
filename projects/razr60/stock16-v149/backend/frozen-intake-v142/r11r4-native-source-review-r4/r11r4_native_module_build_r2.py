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
os.umask(0o077);os.sched_setaffinity(0,sorted(os.sched_getaffinity(0))[:4]);O=B/'evidence'/('r11r4-native-module-build-'+str(uuid.uuid4()));O.mkdir();(O/'logs').mkdir();r={'schema':'razr.r11r4.actual-isolated-native-modules.v1','pass':False,'phone_operations':0,'image_mutations':0,'module_builds':2,'whole_platform_build':False,'old_count8_job_replayed':False,'commands':[]};inputs={}
def track(p):inputs[str(p)]=pin(p)
def capsule(args,extra=()):
 cmd=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--cap-drop','ALL','--ro-bind','/usr','/usr','--ro-bind','/bin','/bin','--ro-bind','/lib','/lib','--ro-bind','/lib64','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--tmpfs','/src']
 for part in sorted(C.iterdir()):
  if part.name not in ('prebuilts','out-native'):cmd+=['--ro-bind',str(part),'/src/'+part.name]
 cmd+=['--tmpfs','/src/prebuilts']
 for part in sorted((C/'prebuilts').iterdir()):
  if part.name!='clang':cmd+=['--ro-bind',str(part),'/src/prebuilts/'+part.name]
 cmd+=['--ro-bind',str(CL),'/src/prebuilts/clang/host/linux-x86/clang-r584948b','--ro-bind',str(SRC/'native'),'/src/vendor/trillionnium/owner-open/native','--ro-bind',str(N),'/tools','--ro-bind',str(O/'deps'),'/src/out-native','--bind',str(O),'/work','--chdir','/src','--clearenv','--setenv','PATH','/usr/bin:/bin','--setenv','LD_LIBRARY_PATH','/tools/lib64','--setenv','LANG','C.UTF-8','--setenv','TMPDIR','/tmp']
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
 for p in [CL/'bin/clang-22',CL/'bin/llvm-strip']:track(p)
 log=S/'private/count8-native-636cdc93-1aaf-4c49-8c0d-88922aec6943/logs/compiledcommands.stdout';track(log)
 ninja=S/'inputs/lower_count5_completed_current_upper/soong/build.trillionnium_leap.9.ninja';track(ninja)
 (O/'deps').mkdir();r['modules']={}
 # Original captured command leaves and explicitly new RSPs are retained.
 for module,source in [('trillionnium-owner-open-bootstrap','owner_open_bootstrap.cpp'),('trillionnium-owner-open-ingress','owner_open_ingress_proxy.cpp')]:
  compile_line=link_line=None
  for line in log.open():
   if 'clang++'not in line:continue
   if ' -c 'in line and line.rstrip().endswith('native/'+source):compile_line=line.rstrip()
   if ' -c 'not in line and '/'+module+'/'in line and '@out-native/'in line:link_line=line.rstrip()
  assert compile_line and link_line,'actual old commands present '+module
  (O/(module+'.original-compile.txt')).write_text(compile_line+'\n');(O/(module+'.original-link.txt')).write_text(link_line+'\n')
  active=False;libflags=None
  for line in ninja.open():
   if line.startswith('# Module:'):active=line.strip()=='# Module:  '+module
   if active and line.lstrip().startswith('libFlags = '):libflags=line.split('=',1)[1].strip();break
  assert libflags and '$'not in libflags,'explicit resolved frozen library list'
  deps=[x for x in shlex.split(libflags)if x.startswith('out-native/')]
  for token in shlex.split(link_line):
   if token.startswith('out-native/')and token.endswith('.o'):deps.append(token)
  for rel in sorted(set(deps)):
   original=U/rel.removeprefix('out-native/');track(original);dest=O/'deps'/rel.removeprefix('out-native/');dest.parent.mkdir(parents=True,exist_ok=True)
   if not dest.exists():
    with dest.open('xb')as f:f.write(original.read_bytes());f.flush();os.fsync(f.fileno())
   assert sha(dest)==sha(original);track(dest)
  tokens=[x for x in shlex.split(compile_line)if not x.startswith('PWD=')];out=[];skip=False
  for t in tokens:
   if skip:skip=False;continue
   if t in ('-o','-MF'):skip=True;continue
   if t in ('-MD','-MMD'):continue
   out.append(t)
  dependency_args=[('-M'if t=='-c'else t)for t in out]+['-MF','/work/'+module+'.headers.d']
  run('discover-headers-'+module,dependency_args)
  raw=(O/(module+'.headers.d')).read_text().replace('\\\n',' ')
  dependencies=shlex.split(raw.split(':',1)[1]);assert dependencies
  headers=[]
  for dep in dependencies:
   assert not dep.startswith('/')and '..'not in Path(dep).parts,'canonical bounded source header path'
   if dep.startswith('vendor/trillionnium/owner-open/native/'):actual=SRC/'native'/Path(dep).name
   elif dep.startswith('prebuilts/clang/host/linux-x86/clang-r584948b/'):actual=CL/dep.removeprefix('prebuilts/clang/host/linux-x86/clang-r584948b/')
   else:actual=C/dep
   track(actual);headers.append(inputs[str(actual)])
  out+=['-o','/work/'+module+'.o'];run('compile-'+module,out)
  rsp=O/(module+'.new.rsp');rsp.write_text('/work/'+module+'.o '+libflags+'\n');track(rsp)
  tokens=shlex.split(link_line);out=[];skip=False
  for t in tokens:
   if skip:skip=False;continue
   if t=='-o':skip=True;continue
   if t.startswith('@out-native/'):out.append('@/work/'+rsp.name)
   else:out.append(t)
  out+=['-o','/work/'+module+'.unstripped'];run('link-'+module,out)
  run('strip-'+module,['prebuilts/clang/host/linux-x86/clang-r584948b/bin/llvm-strip','--strip-debug','-o','/work/'+module,'/work/'+module+'.unstripped'])
  so,se=run('readelf-'+module,['/usr/bin/readelf','-h','-l','-d','--wide','/work/'+module]);assert 'AArch64'in so and '/system/bin/linker64'in so
  binary=O/module;assert binary.read_bytes()[:6]==b'\x7fELF\x02\x01'
  r['modules'][module]={'source':pin(SRC/('owner_open_bootstrap.proposed.cpp'if module.endswith('bootstrap')else'owner_open_ingress_proxy.proposed.cpp')),'binary':pin(binary),'object':pin(O/(module+'.o')),'unstripped':pin(O/(module+'.unstripped')),'new_explicit_RSP':pin(rsp),'original_compile_line_sha256':hashlib.sha256(compile_line.encode()).hexdigest(),'original_link_line_sha256':hashlib.sha256(link_line.encode()).hexdigest(),'frozen_rule_library_flags':libflags,'strip_scope':'official llvm-strip --strip-debug, no source/code mutation','dependencies_from_cached_upper_readonly':deps,'actual_preprocessor_header_inputs':headers,'all_header_inputs_pinned_before_compile_and_after':True}
 r['pass']=True
except BaseException as e:r['failure']={'type':type(e).__name__,'message':str(e)}
r['inputs_before']=inputs
try:
 r['inputs_after']={k:pin(Path(k))for k in inputs};assert r['inputs_before']==r['inputs_after']
except BaseException as e:r['pass']=False;r['input_guard_failure']=str(e)
with(O/'receipt.json').open('x')as f:json.dump(r,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
print(json.dumps({'out':str(O),'receipt':pin(O/'receipt.json'),'pass':r['pass'],'failure':r.get('failure'),'modules':r.get('modules'), 'last_command_label':r['commands'][-1]['label']if r['commands']else None}))
