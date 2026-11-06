#!/usr/bin/env python3
"""Proposed complete private forks; an unbound packet stops before any mutation.

Only declared ordinary source transformations are written in exclusive local
clones. Full tracked/LFS/gitlink and source-surface observations remain mandatory.
No compile, CVE/device applicability, source BOM or release approval is produced.
"""
import argparse,datetime,hashlib,json,os,resource,stat,sys,time,types
from pathlib import Path
HERE=Path(__file__).absolute().parent
CATALOG_HELPER_SHA='fea8c1d1fb459f5f124fb11d563cc6282cee0bc9b49608c0412b8b3c904036c4'
PROVENANCE_SHA='053b906f9a347e7018e978d52ddf323c7d52de4b8d2a4eea15e56a64212869dc'
SURFACE_SHA='7d0f3d51d913317f01c75ee6d25cb56e3748ed79ea1a59635b4ca32bc929839b'
SOURCE=Path('/media/qian-qi/TOSHIBA_DEV_1TB/TrillionniumOS/rootfs/home/qian-qi/android/lineage-fogos')
MAX_METADATA=2*1024**3
IDENTITY=('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')
def need(ok,message):
 if not ok:raise RuntimeError(message)
def budget(deadline):
 if time.monotonic()>=deadline:raise TimeoutError('whole fullfork preparation deadline')
def ident(s):return [getattr(s,k) for k in IDENTITY]
def directory(path):
 path=Path(path);need(path.is_absolute() and '..' not in path.parts,'exact absolute directory');fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  for name in path.parts[1:]:
   old=os.stat(name,dir_fd=fd,follow_symlinks=False);child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);need(ident(os.fstat(child))==ident(old),'directory entry differs from held FD');os.close(fd);fd=child
  return fd
 except BaseException:os.close(fd);raise

def read(path,maximum,deadline,expected=None,with_identity=False):
 path=Path(path);parent=directory(path.parent);fd=None
 try:
  budget(deadline);entry=os.stat(path.name,dir_fd=parent,follow_symlinks=False);need(stat.S_ISREG(entry.st_mode) and entry.st_nlink==1 and 0<=entry.st_size<=maximum,'ordinary single-link source input bound')
  fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent);before=ident(os.fstat(fd));need(before==ident(entry),'held input before first read');chunks=[];n=0
  while True:
   budget(deadline);part=os.read(fd,min(65536,maximum-n+1))
   if not part:break
   n+=len(part);need(n<=entry.st_size and n<=maximum,'source input grew');chunks.append(part)
  raw=b''.join(chunks);need(before==ident(os.fstat(fd))==ident(os.stat(path.name,dir_fd=parent,follow_symlinks=False)) and n==entry.st_size,'stable source input FD9')
  d=dict(path=str(path),bytes=n,sha256=hashlib.sha256(raw).hexdigest())
  if expected is not None:need(d==expected,'fixed actual input descriptor differs')
  if with_identity:d['fd9']=before
  return raw,d
 finally:
  if fd is not None:os.close(fd)
  os.close(parent)
def bind(name,path,pin,deadline):
 need(type(pin) is str and len(pin)==64,'helper PIN remains unbound');raw,d=read(path,256*1024,deadline);need(d['sha256']==pin,'helper PIN != actual retained body')
 obj=types.ModuleType(name);obj.__file__=str(path);sys.modules[name]=obj
 try:exec(compile(raw,str(path),'exec'),obj.__dict__)
 except BaseException:sys.modules.pop(name,None);raise
 need(read(path,256*1024,deadline)[0]==raw,'helper changed during raw compile/exec');return obj

def write_new(path,raw,deadline):
 budget(deadline);parent=directory(Path(path).parent)
 try:
  fd=os.open(Path(path).name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
  try:
   view=memoryview(raw)
   while view:budget(deadline);n=os.write(fd,view);need(n>0,'owned write progress');view=view[n:]
  finally:os.close(fd)
 finally:os.close(parent)
 return read(path,max(len(raw),1),deadline)[1]

def metadata_snapshot(root,deadline):
 """All HEAD/index/packed/refs; bounded NOFOLLOW metadata, no Git/config write."""
 root=Path(root);fd=directory(root);initial=ident(os.fstat(fd));result={};total=0;pending=[(root,'')];directories=[]
 try:
  for name in ('HEAD','index','packed-refs'):
   try:raw,d=read(root/name,64*1024*1024,deadline,with_identity=True)
   except FileNotFoundError:continue
   total+=len(raw);need(total<=64*1024*1024,'whole metadata snapshot byte bound');result[name]=d
  try:refs=directory(root/'refs');os.close(refs);pending=[(root/'refs','refs')]
  except FileNotFoundError:pending=[]
  while pending:
   path,relative=pending.pop();held=directory(path);old=ident(os.fstat(held));directories.append((path,old))
   try:
    names=sorted(os.listdir(held));need(len(names)<=8192,'metadata directory entry bound')
    for name in names:
     budget(deadline);s=os.stat(name,dir_fd=held,follow_symlinks=False);rel=relative+'/'+name
     if stat.S_ISDIR(s.st_mode):pending.append((path/name,rel));continue
     need(stat.S_ISREG(s.st_mode),'metadata alias/special ref held');raw,d=read(path/name,65536,deadline,with_identity=True);need(d['fd9']==ident(s),'ref entry differs before retained read');total+=len(raw);need(total<=64*1024*1024 and len(result)<8192,'metadata full refs byte/entry bound');result[rel]=d
    need(ident(os.fstat(held))==old,'metadata directory changed during traversal')
   finally:os.close(held)
  for path,old in directories:
   h=directory(path)
   try:need(ident(os.fstat(h))==old,'metadata directory changed across snapshot')
   finally:os.close(h)
  reopened=directory(root)
  try:need(ident(os.fstat(fd))==initial==ident(os.fstat(reopened)),'metadata root endpoint changed')
  finally:os.close(reopened)
  return dict(root=str(root),root_fd9=initial,files=result,bytes_read=total,complete=True,sequential_not_atomic=True)
 finally:os.close(fd)

def git_pointer(root,metadata_root,deadline):
 """Exact selected .git entry, never follow an arbitrary pointer."""
 budget(deadline);root=Path(root);parent=directory(root)
 try:
  old=os.stat('.git',dir_fd=parent,follow_symlinks=False);fd=os.open('.git',os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
  try:
   need(ident(old)==ident(os.fstat(fd)),'selected .git held entry differs')
   if stat.S_ISLNK(old.st_mode):
    target=os.readlink('.git',dir_fd=parent);need(not target.startswith('/') and os.path.normpath(str(root/target))==str(metadata_root),'selected .git target differs from exact metadata root');row=dict(kind='relative_symlink_to_bound_metadata',raw_target=target,fd9=ident(old))
   else:
    need(stat.S_ISDIR(old.st_mode) and str(root/'.git')==str(metadata_root),'selected metadata pointer must be exact ordinary directory or declared relative symlink');row=dict(kind='ordinary_private_metadata_directory',raw_target=None,fd9=ident(old))
   need(ident(os.fstat(fd))==ident(os.stat('.git',dir_fd=parent,follow_symlinks=False))==ident(old),'selected .git entry changed during observation');return row
  finally:os.close(fd)
 finally:os.close(parent)

def clone_equivalent(catalog,original,clone):
 a=catalog.logical_inventory(original);b=catalog.logical_inventory(clone)
 for value in (a,b):
  for ref in value['gitlinks']:ref.pop('state');ref.pop('absent_path')
 need(a==b,'complete clone differs from selected tracked/LFS/Git reference inputs')

def object_closure(clone,deadline):
 root=clone/'.git/objects';fd=directory(root);os.close(fd);need(not (root/'info/alternates').exists(),'private object alternates held');pending=[root];files=total=0
 while pending:
  budget(deadline);path=pending.pop();held=directory(path)
  try:
   for name in os.listdir(held):
    budget(deadline);s=os.stat(name,dir_fd=held,follow_symlinks=False)
    if stat.S_ISDIR(s.st_mode):pending.append(path/name)
    else:need(stat.S_ISREG(s.st_mode) and s.st_nlink==1,'private Git object hardlink/alias/special held');files+=1;total+=s.st_size
    need(files<=250000 and total<=64*1024**3,'private object store finite byte/file boundary')
  finally:os.close(held)
 return dict(files=files,bytes=total,no_hardlinks_or_alternates=True)

def _produce_project(spec,source,output,p,catalog,surface,control,deadline,save,sample):
 """Complete-clone mechanism also exercised on an isolated real local fixture."""
 source_root=Path(source['root']);initial=directory(source_root)
 try:
  root_id=ident(os.fstat(initial));need(root_id==source['root_fd9'],'source root current identity');beforepointer=git_pointer(source_root,source['metadata_root'],deadline);need(beforepointer==source['git_pointer'],'bound selected .git pointer current identity differs');beforemap=metadata_snapshot(source['metadata_root'],deadline)
  before=p.collect_git_checkout(source_root,source['head'],source['tree'],deadline,spec['path'],120);s=surface.project_surface(p,source_root,before,deadline);need(s['accepted'] is True,'original source unknown/untracked/ignored surface held')
  before_desc=save('original-before',before);before_surface=save('original-surface-before',s);sample('original-before-content-complete')
  need(not output.exists() and not output.is_symlink(),'exclusive complete clone output already exists')
  process=p.bounded_module(deadline);env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_OPTIONAL_LOCKS':'0','GIT_NO_REPLACE_OBJECTS':'1','GIT_NO_LAZY_FETCH':'1','GIT_TERMINAL_PROMPT':'0','GIT_LFS_SKIP_SMUDGE':'1','GIT_ALLOW_PROTOCOL':'file','GIT_ATTR_NOSYSTEM':'1'}
  options=['-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','-c','gc.auto=0','-c','maintenance.auto=false','-c','core.attributesFile=/dev/null','-c','credential.helper=',*p.GIT_PACK_OPTIONS]
  for kind,value in (('clean',''),('smudge',''),('process',''),('required','false')):options+=['-c','filter.lfs.'+kind+'='+value]
  def git(args,path=output,seconds=120):
   budget(deadline);r=process.run_bounded(['/usr/bin/git',*options,'-C',str(path),*args],timeout_seconds=min(seconds,deadline-time.monotonic()),maximum_output=32*1024*1024,env=env);need(r.returncode==0,p.git_query_failure('private fork query failed',spec['path'],path,args,r));return r.stdout
  upload='git -c pack.threads=1 -c pack.windowMemory=128m -c pack.deltaCacheSize=128m -c core.bigFileThreshold=16m -c core.packedGitWindowSize=32m -c core.packedGitLimit=128m -c core.hooksPath=/dev/null -c core.fsmonitor=false -c gc.auto=0 -c maintenance.auto=false upload-pack'
  empty=output.parent/'empty-template';empty.mkdir(mode=0o700,exist_ok=True)
  args=['/usr/bin/git',*options,'-c','pack.threads=1','-c','pack.windowMemory=128m','-c','pack.deltaCacheSize=128m','clone','--no-local','--no-hardlinks','--no-checkout','--template='+str(empty),'--upload-pack='+upload,str(source_root),str(output)]
  r=process.run_bounded(args,timeout_seconds=min(600,deadline-time.monotonic()),maximum_output=32*1024*1024,env=env);need(r.returncode==0,p.git_query_failure('complete private clone failed',spec['path'],source_root,args,r));sample('complete-object-clone')
  git(['checkout','--detach',source['head']]);objects=object_closure(output,deadline)
  # Disabled smudge leaves LFS pointers. Never call that a hydrated input tree.
  # A complete inventory holds such a clone until separately modeled hydration.
  clone_before=p.collect_git_checkout(output,source['head'],source['tree'],deadline,spec['path'],120);clone_equivalent(catalog,before,clone_before);cb_surface=surface.project_surface(p,output,clone_before,deadline);need(cb_surface['accepted'] is True,'private clone source surface unknown')
  clone_before_desc=save('clone-before',clone_before);clone_before_surface=save('clone-surface-before',cb_surface)
  for f in spec['files']:
   raw,desc=read(output/f['path'],catalog.MAX_FILE,deadline,with_identity=True);need(desc['bytes']==f['before']['bytes'] and desc['sha256']==f['before']['sha256'] and catalog.blob(raw)==f['before']['git_blob_sha1'],'private preimage current body differs')
   patch,_=read(control/f['patch']['canonical_path'],catalog.MAX_FILE,deadline);after=catalog.apply_exact(raw,patch,f);parent=directory((output/f['path']).parent)
   try:
    fd=os.open(Path(f['path']).name,os.O_WRONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
    try:
     expected=os.stat(Path(f['path']).name,dir_fd=parent,follow_symlinks=False);need(ident(os.fstat(fd))==ident(expected)==desc['fd9'] and expected.st_nlink==1,'owned clone leaf identity before rewrite');os.ftruncate(fd,0);view=memoryview(after)
     while view:budget(deadline);n=os.write(fd,view);need(n>0,'owned transformation write progress');view=view[n:]
     os.fchmod(fd,0o755 if f['git_mode']=='100755' else 0o644)
    finally:os.close(fd)
   finally:os.close(parent)
   measured,_=read(output/f['path'],catalog.MAX_FILE,deadline);need(measured==after,'owned full resulting body differs');sample('exact-declared-transformation')
  paths=[f['path'] for f in spec['files']];changed=git(['diff','--name-only','-z','--no-renames']).split(b'\0')[:-1];need(sorted(x.decode() for x in changed)==sorted(paths),'complete private unstaged changed set differs')
  git(['add','--',*paths]);commit_env=dict(env,GIT_AUTHOR_NAME='Trillionnium Source Audit',GIT_AUTHOR_EMAIL='source-audit@trillionnium.invalid',GIT_COMMITTER_NAME='Trillionnium Source Audit',GIT_COMMITTER_EMAIL='source-audit@trillionnium.invalid',GIT_AUTHOR_DATE='2026-10-03T00:00:00Z',GIT_COMMITTER_DATE='2026-10-03T00:00:00Z')
  r=process.run_bounded(['/usr/bin/git',*options,'-C',str(output),'commit','-m','Apply declared source-local ASB compatibility transforms'],timeout_seconds=min(120,deadline-time.monotonic()),maximum_output=8*1024*1024,env=commit_env);need(r.returncode==0,p.git_query_failure('private source commit failed',spec['path'],output,['commit'],r))
  head=git(['rev-parse','HEAD']).decode().strip();tree=git(['rev-parse','HEAD^{tree}']).decode().strip();changed=git(['diff','--name-only','-z','--no-renames',source['head'],head]).split(b'\0')[:-1];need(sorted(x.decode() for x in changed)==sorted(paths),'committed whole changed set differs')
  final=p.collect_git_checkout(output,head,tree,deadline,spec['path'],120);catalog.compare_fork(spec,clone_before,final);ca_surface=surface.project_surface(p,output,final,deadline);need(ca_surface['accepted'] is True,'final full clone namespace held');final_desc=save('clone-after',final);clone_after_surface=save('clone-surface-after',ca_surface)
  original_after=p.collect_git_checkout(source_root,source['head'],source['tree'],deadline,spec['path'],120);need(catalog.logical_inventory(before)==catalog.logical_inventory(original_after),'original full source contents changed');after_desc=save('original-after',original_after);s=surface.project_surface(p,source_root,original_after,deadline);need(s['accepted'] is True,'original after unknown source surface held');after_surface=save('original-surface-after',s);objects=object_closure(output,deadline)
  afterpointer=git_pointer(source_root,source['metadata_root'],deadline);need(afterpointer==beforepointer,'selected .git entry/target changed');aftermap=metadata_snapshot(source['metadata_root'],deadline);need(beforemap==aftermap,'original refs/index maps changed');reopened=directory(source_root)
  try:need(ident(os.fstat(initial))==root_id==ident(os.fstat(reopened)),'original physical root endpoint changed')
  finally:os.close(reopened)
  sample('whole-project-before-after-complete')
  return dict(path=spec['path'],private_repository=str(output),private_head=head,private_tree=tree,original_before=before_desc,original_after=after_desc,clone_before=clone_before_desc,clone_after=final_desc,original_surface_before=before_surface,original_surface_after=after_surface,clone_surface_before=clone_before_surface,clone_surface_after=clone_after_surface,exact_changed_paths=paths,original_git_pointer_before=beforepointer,original_git_pointer_after=afterpointer,original_metadata_before=beforemap,original_metadata_after=aftermap,original_root_fd9_before_after=root_id,complete_git_objects=objects,complete=True)
 finally:os.close(initial)

def validate_packet(q,p,catalog):
 need(type(q) is dict and q.get('schema')=='org.trillionnium.owner-asb24-private-preparation-input.v1','distinct producer input')
 cat_keys=('schema','execution_admitted','candidate','profile_id','attempt','stage','NV_root_fd5','NV_fsid','current_source4_composition','current_source4_defensive','source_roots','protected_generation_roots','control_root','catalog','current_manifest_metadata_root')
 catalog.exact(q,cat_keys,'producer packet')
 need(q.get('execution_admitted') is True,'actual execution admission remains null/false')
 p.validate_candidate(q['candidate']);need(q['profile_id']==p.PROFILE and p.PRIVATE_COUNT==38 and p.ORIGINAL_COUNT==1131 and p.PRIVATE_PROJECT_PATHS==catalog.PRIVATE_PROJECTS,'current exact38 consumer profile required')
 c=q['candidate'];attempt=q.get('attempt');need(type(attempt) is int and 1<=attempt<=9,'finite exact producer attempt');stage=Path('/var/lib/codex-trillionnium-private-source-'+c['commit'][:7]+'-20261003-r'+str(attempt));need(q.get('stage')==str(stage),'exact candidate-owned NV root')
 need(type(q.get('NV_root_fd5')) is list and len(q['NV_root_fd5'])==5 and all(type(x) is int for x in q['NV_root_fd5']) and type(q.get('NV_fsid')) is int,'actual NV filesystem/root identity remains unbound')
 need(type(q.get('current_source4_composition')) is dict and type(q.get('current_source4_defensive')) is dict,'new actual source4 receipts remain unbound')
 need(type(q.get('source_roots')) is list and [x.get('project') for x in q['source_roots']]==sorted(catalog.AFFECTED_PROJECTS),'exact24 current complete source roots required')
 need(type(q.get('protected_generation_roots')) is dict and set(q['protected_generation_roots'])=={'baseline:'+x for x in catalog.AFFECTED_PROJECTS}|{'prior:'+x for x in catalog.PRIOR_PRIVATE_PROJECTS}|{'control','manifest'},'all original24/prior16/control/manifest protected raw maps required')
 return stage

def main():
 a=argparse.ArgumentParser();a.add_argument('packet',type=Path);args=a.parse_args();deadline=time.monotonic()+3600
 need(os.getuid()==1000 and os.getgid()==1000 and os.getgroups()==[],'ordinary UID/GID1000 and empty groups required before source prep');state=dict(x.split(':',1) for x in Path('/proc/self/status').read_text().splitlines() if ':' in x);need(state['NoNewPrivs'].strip()=='1' and all(int(state[k],16)==0 for k in ('CapPrm','CapEff','CapAmb')),'ordinary NNP1 Prm/Eff/Amb0; Inh/Bnd retained');os.umask(0o077);resource.setrlimit(resource.RLIMIT_AS,(4*1024**3,4*1024**3))
 p=bind('owner_fork_source',HERE/'owner_source_provenance.py',PROVENANCE_SHA,deadline);cat=bind('owner_fork_catalog',HERE/'owner_asb_fork_catalog.py',CATALOG_HELPER_SHA,deadline);surface=bind('owner_fork_surface',HERE/'owner_source_surface.py',SURFACE_SHA,deadline);raw,packet_desc=read(args.packet,8*1024*1024,deadline);q=cat.parse(raw);stage=validate_packet(q,p,cat)
 control=Path(q['control_root']);need(control==stage/'control','new canonical control root');catalograw,cd=read(control/cat.CATALOG_PATH,cat.MAX_INPUT_BYTES,deadline,q['catalog']);catalog=cat.validate_catalog(cat.parse(catalograw))
 for f in [x for row in catalog['projects'] for x in row['files']]:
  raw,_=read(control/f['patch']['canonical_path'],cat.MAX_FILE,deadline);need(len(raw)==f['patch']['bytes'] and cat.digest(raw)==f['patch']['sha256'],'all80 declared patches measured before any output mutation')
 scoped_evidence=[]
 for spec in catalog['scoped_evidence']:
  raw,d=read(control/spec['canonical_path'],cat.MAX_FILE,deadline);need(d['bytes']==spec['bytes'] and d['sha256']==spec['sha256'],'all declared scoped witness bodies measured before mutation');scoped_evidence.append(d)
 source4={}
 for key in ('current_source4_composition','current_source4_defensive'):
  v,_=read(q[key]['path'],8*1024*1024,deadline,q[key]);source4[key]=cat.parse(v)
 source4_by=cat.validate_source4_baselines(source4['current_source4_composition'],source4['current_source4_defensive'],q['candidate'])
 rows={r['path']:r for r in catalog['projects']}
 for source in q['source_roots']:
  cat.exact(source,('project','root','metadata_root','head','tree','root_fd9','git_pointer'),'complete source root input');spec=rows[source['project']];need(type(source['root']) is str and Path(source['root']).is_absolute() and type(source['metadata_root']) is str and Path(source['metadata_root']).is_absolute(),'actual source/metadata roots')
  p.hexvalue(source['head'],p.HEX40,'bound source head');p.hexvalue(source['tree'],p.HEX40,'bound source tree')
  if spec['baseline_kind']=='previous_complete_private':
   r=source4_by[spec['path']];need((source['root'],source['head'],source['tree'])==(r['private_repository'],r['private_head'],r['private_tree']) and source['tree']==spec['historical_source_tree'],'actual new private baseline content generation differs')
  else:need(source['root']==str(SOURCE/spec['path']) and source['head']==spec['historical_source_head'],'actual selected original generation differs')
  expected_meta=str(Path(source['root'])/'.git') if spec['baseline_kind']=='previous_complete_private' else str(SOURCE/'.repo/projects'/(spec['path']+'.git'))
  need(source['metadata_root']==expected_meta and q['protected_generation_roots']['baseline:'+spec['path']]['metadata_root']==expected_meta,'baseline metadata physical mapping differs')
 for project,r in source4_by.items():need(q['protected_generation_roots']['prior:'+project]['metadata_root']==str(Path(r['private_repository'])/'.git'),'all prior private metadata mapping differs')
 need(q['protected_generation_roots']['control']['metadata_root']==str(control/'.git') and q['protected_generation_roots']['manifest']['metadata_root']==q['current_manifest_metadata_root'],'control/manifest protected root mapping differs')
 rootfd=directory(stage);root=os.fstat(rootfd);v=os.fstatvfs(rootfd);fd5=lambda s:[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid];need(fd5(root)==q['NV_root_fd5'] and root.st_uid==root.st_gid==1000 and stat.S_IMODE(root.st_mode)==0o700 and v.f_fsid==q['NV_fsid'],'actual exclusive NV root identity/fs');startfree=v.f_bavail*v.f_frsize;need(startfree>=80*1024**3,'unchanged80GiB source admission');samples=[]
 def sample(phase):
  budget(deadline);v=os.fstatvfs(rootfd);available=v.f_bavail*v.f_frsize;need(fd5(os.fstat(rootfd))==q['NV_root_fd5'] and v.f_fsid==q['NV_fsid'] and available>=64*1024**3 and startfree-available<=16*1024**3,'sampled80/16/64 finite source budget or root identity');need(len(samples)<4096,'space sample bound');samples.append(dict(phase=phase,available_bytes=available,available_delta_not_attributed=startfree-available,not_hard_quota_or_peak=True))
 protected=q['protected_generation_roots'];before={k:metadata_snapshot(v['metadata_root'],deadline) for k,v in sorted(protected.items())};outputs=stage/'asb-forks';outputs.mkdir(mode=0o700);evidence=stage/'asb-fork-evidence';evidence.mkdir(mode=0o700);files=[];metadata_bytes=0;projects=[];failure=None
 def save(project,label,value):
  nonlocal metadata_bytes
  raw=p.canonical(value);metadata_bytes+=len(raw);need(len(raw)<=128*1024*1024 and metadata_bytes<=MAX_METADATA,'complete retained source inventories/surfaces2GiB bound');path=evidence/(project.replace('/','__')+'-'+label+'.json');d=write_new(path,raw,deadline);files.append(d);return d
 try:
  for source in q['source_roots']:
   project=source['project'];parent=outputs
   for part in Path(project).parts[:-1]:parent=parent/part;parent.mkdir(mode=0o700,exist_ok=True)
   projects.append(_produce_project(rows[project],source,outputs/project,p,cat,surface,control,min(deadline,time.monotonic()+1800),lambda label,value:save(project,label,value),sample))
 except Exception as e:failure=dict(type=type(e).__name__,message=str(e),completed_projects=len(projects))
 after={};endpoint_errors=[]
 for k,v in sorted(protected.items()):
  try:after[k]=metadata_snapshot(v['metadata_root'],deadline)
  except Exception as e:endpoint_errors.append(dict(root=k,type=type(e).__name__,message=str(e)))
 if endpoint_errors or before!=after:failure=dict(type='SourceMetadataClosureError',message='protected raw metadata after incomplete/different',prior_failure=failure,endpoint_errors=endpoint_errors)
 try:sample('terminal-source-map-complete')
 except Exception as e:failure=dict(type=type(e).__name__,message=str(e),prior_failure=failure)

 report=dict(schema=cat.RECEIPT_SCHEMA,source_commit=q['candidate']['commit'],source_tree=q['candidate']['tree'],source_archive_sha256=q['candidate']['archive_sha256'],catalog_sha256=cd['sha256'],catalog_descriptor=cd,scoped_evidence_descriptors=scoped_evidence,source4_composition_descriptor=q['current_source4_composition'],source4_defensive_descriptor=q['current_source4_defensive'],stage=str(stage),attempt=q['attempt'],input_descriptor=packet_desc,projects=projects,completed_project_count=len(projects),complete=failure is None and len(projects)==24,actual_error=failure,all_original_and_retained_metadata_before=before,all_original_and_retained_metadata_after=after,actual_space_samples=samples,point_samples_not_peak_or_quota=True,retained_metadata_bytes=metadata_bytes,actual_ordinary_state={k:state[k].strip() for k in ('Uid','Gid','Groups','NoNewPrivs','CapPrm','CapEff','CapAmb','CapInh','CapBnd')},original_source_or_metadata_written=False,full_ASB_coverage_qualified=False,source_bom_qualified=False,compiled=False,installed=False,production_ready=False)
 report_raw=p.canonical(report);need(len(report_raw)<=32*1024*1024,'whole completed/partial fork receipt32MiB publication bound');write_new(stage/'actual-asb24-private-forks.json',report_raw,deadline);os.close(rootfd);return 0 if report['complete'] else 1
if __name__=='__main__':raise SystemExit(main())
