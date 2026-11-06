#!/usr/bin/env python3
"""Proposed exact source-only 24-fork catalog, not CVE/build/release authority.

The 80 paths are ordinary tracked production/build files. Ancillary tests,
packaging, pKVM absence and API/device applicability stay separate UNKNOWNs.
No candidate tuple or completed fork is inferred from a local preview.
"""
import hashlib,json,re
from pathlib import PurePosixPath

CATALOG_SCHEMA='org.trillionnium.owner-asb-fullfork-catalog.v1'
RECEIPT_SCHEMA='org.trillionnium.audit.actual-asb24-complete-private-forks.v1'
CATALOG_PATH='android-integration/security-patches/owner-asb-fork-catalog.v1.json'
AFFECTED_PROJECTS=frozenset({'art','bionic','external/exfatprogs','external/freetype',
 'external/libcupsfilters','external/libhevc','external/libpng','external/libppd',
 'external/wpa_supplicant_8','frameworks/av','frameworks/base','hardware/interfaces',
 'hardware/nxp/secure_element','kernel/motorola/sm6375','packages/apps/Settings',
 'packages/apps/TV','packages/modules/Bluetooth','packages/modules/Nfc',
 'packages/modules/Uwb','packages/modules/Wifi','packages/providers/MediaProvider',
 'packages/providers/TelephonyProvider','packages/services/Telephony','system/core'})
PRIOR_PRIVATE_PROJECTS=frozenset({'build/make','device/motorola/fogos',
 'device/motorola/sm6375-common','device/trillionnium/sepolicy','external/aws-sdk-java-v2',
 'external/libopenapv','frameworks/base','frameworks/layoutlib','packages/apps/Seedvault',
 'packages/apps/TrillionniumAiAuthority','packages/apps/TrillionniumAiShell',
 'packages/modules/adb','packages/modules/Nfc','system/extras','trillionnium-sdk',
 'vendor/trillionnium'})
PRIVATE_PROJECTS=PRIOR_PRIVATE_PROJECTS|AFFECTED_PROJECTS
HEX40=re.compile('[0-9a-f]{40}');HEX64=re.compile('[0-9a-f]{64}')
MAX_FILE=16*1024*1024;MAX_INPUT_BYTES=128*1024*1024

def need(ok,message):
 if not ok:raise ValueError(message)
def exact(value,keys,label):need(type(value) is dict and set(value)==set(keys),label+' exact fields')
def relative(value):
 need(type(value) is str and value and len(value.encode())<=4096,'relative path bound')
 p=PurePosixPath(value)
 need(not p.is_absolute() and str(p)==value and '\\' not in value and
      all(x not in ('','.','..','.git') for x in p.parts) and
      not any(ord(x)<32 or ord(x)==127 for x in value),'canonical source path')
 return value
def digest(raw):return hashlib.sha256(raw).hexdigest()
def blob(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def canonical(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def parse(raw):
 need(type(raw) is bytes and len(raw)<=MAX_INPUT_BYTES,'catalog/receipt input bound')
 def pairs(items):
  out={}
  for k,v in items:need(k not in out,'duplicate catalog/receipt key');out[k]=v
  return out
 return json.loads(raw.decode('utf-8'),object_pairs_hook=pairs,
  parse_constant=lambda x:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def content_descriptor(value):
 exact(value,('bytes','sha256','git_blob_sha1'),'source content descriptor')
 need(type(value['bytes']) is int and 0<=value['bytes']<=MAX_FILE,'ordinary source byte bound')
 need(type(value['sha256']) is str and HEX64.fullmatch(value['sha256']) and
      type(value['git_blob_sha1']) is str and HEX40.fullmatch(value['git_blob_sha1']),'source hash syntax')
def validate_catalog(value):
 exact(value,('schema','prior_private_project_paths','affected_project_paths','private_project_paths',
  'manifest_count','private_count','original_count','control_count','projects','scoped_evidence',
  'pending_qualification'),'fork catalog')
 need(value['schema']==CATALOG_SCHEMA,'distinct fork catalog schema')
 for key,expected in (('prior_private_project_paths',PRIOR_PRIVATE_PROJECTS),
   ('affected_project_paths',AFFECTED_PROJECTS),('private_project_paths',PRIVATE_PROJECTS)):
  need(type(value[key]) is list and value[key]==sorted(expected),'exact ordered '+key)
 for key,n in (('manifest_count',1170),('private_count',38),('original_count',1131),('control_count',1)):
  need(type(value[key]) is int and value[key]==n,'exact namespace arithmetic '+key)
 pending=value['pending_qualification'];exact(pending,('whole_CVE','whole_ASB','cumulative_ASB',
  'compiled','device_applicability','source_bom','installed','production_ready'),'pending qualification')
 need(all(v is False for v in pending.values()),'source-local catalog exceeds scope')
 need(type(value['scoped_evidence']) is list and 1<=len(value['scoped_evidence'])<=16,'scoped evidence list')
 for evidence in value['scoped_evidence']:
  exact(evidence,('canonical_path','bytes','sha256','scope'),'declared scoped evidence')
  path=relative(evidence['canonical_path']);need(path.startswith('android-integration/security-patches/owner-asb-forks/evidence/'),'evidence input namespace')
  need(type(evidence['bytes']) is int and 0<evidence['bytes']<=MAX_FILE and type(evidence['sha256']) is str and HEX64.fullmatch(evidence['sha256']),'bounded evidence descriptor')
  need(type(evidence['scope']) is str and evidence['scope'],'explicit scoped evidence')
 projects=value['projects'];need(type(projects) is list and len(projects)==24,'exact affected project count')
 need([r.get('path') for r in projects]==sorted(AFFECTED_PROJECTS),'exact affected project set')
 files=0;paths=set();bytes_=0
 for row in projects:
  exact(row,('path','historical_source_head','historical_source_tree','baseline_kind','files'),'fork project')
  relative(row['path']);need(type(row['historical_source_head']) is str and HEX40.fullmatch(row['historical_source_head']),'historical source HEAD')
  need(row['historical_source_tree'] is None or (type(row['historical_source_tree']) is str and HEX40.fullmatch(row['historical_source_tree'])),'historical tree is exact or UNKNOWN')
  need(row['baseline_kind']==('previous_complete_private' if row['path'] in ('frameworks/base','packages/modules/Nfc') else 'original_selected'),'exact original/private baseline kind')
  need(row['baseline_kind']!='previous_complete_private' or row['historical_source_tree'] is not None,'complete prior private baseline tree required')
  need(type(row['files']) is list and row['files'] and [f.get('path') for f in row['files']]==sorted(f.get('path') for f in row['files']),'ordered source paths')
  seen=set()
  for f in row['files']:
   exact(f,('path','git_mode','before','after','patch'),'declared fork transformation');relative(f['path'])
   need(f['path'] not in seen,'duplicate changed path');seen.add(f['path'])
   need(f['git_mode'] in ('100644','100755'),'ordinary tracked transformation only')
   content_descriptor(f['before']);content_descriptor(f['after']);need(f['before']!=f['after'],'declared no-op source transformation')
   patch=f['patch'];exact(patch,('canonical_path','bytes','sha256','old_label','new_label'),'declared patch')
   relative(patch['canonical_path']);need(re.fullmatch(r'android-integration/security-patches/owner-asb-forks/patches/[0-9]{3}\.diff',patch['canonical_path']),'fixed patch namespace')
   need(patch['canonical_path'] not in paths,'duplicate patch input');paths.add(patch['canonical_path'])
   need(type(patch['bytes']) is int and 0<patch['bytes']<=MAX_FILE and type(patch['sha256']) is str and HEX64.fullmatch(patch['sha256']),'bounded patch descriptor')
   need(patch['old_label']=='actual-captured/'+row['path']+'/'+f['path'] and patch['new_label']=='owned-final/'+row['path']+'/'+f['path'],'source-specific patch labels')
   files+=1;bytes_+=patch['bytes']
 need(files==80 and bytes_<=MAX_INPUT_BYTES,'exact 77 platform plus 3 kernel transformations')
 need(paths=={'android-integration/security-patches/owner-asb-forks/patches/'+str(i).zfill(3)+'.diff' for i in range(80)},'complete fixed patch input set')
 return value
def apply_exact(before,patch,spec):
 """Replay every line-numbered context exactly, without fuzz/offset/Git filters."""
 content_descriptor(spec['before']);content_descriptor(spec['after'])
 need(type(before) is bytes and len(before)==spec['before']['bytes'] and digest(before)==spec['before']['sha256'] and blob(before)==spec['before']['git_blob_sha1'],'exact original body required')
 d=spec['patch'];need(type(patch) is bytes and len(patch)==d['bytes'] and digest(patch)==d['sha256'],'exact declared patch body')
 lines=patch.splitlines(keepends=True)
 need(lines[:2]==[('--- '+d['old_label']+'\n').encode(),('+++ '+d['new_label']+'\n').encode()],'exact patch headers')
 original=before.splitlines(keepends=True);out=[];cursor=0;pos=2;hunks=0
 while pos<len(lines):
  m=re.fullmatch(rb'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n',lines[pos]);need(m is not None,'strict hunk header')
  oldstart,oldcount,newstart,newcount=int(m[1]),int(m[2] or b'1'),int(m[3]),int(m[4] or b'1');pos+=1
  oldoffset=oldstart if oldcount==0 else oldstart-1;newoffset=newstart if newcount==0 else newstart-1
  need(cursor<=oldoffset<=len(original),'ordered nonoverlapping hunk positions')
  out.extend(original[cursor:oldoffset]);need(len(out)==newoffset,'exact new hunk line position');cursor=oldoffset
  old=[];new=[]
  while pos<len(lines) and not lines[pos].startswith(b'@@ '):
   line=lines[pos];pos+=1;need(line[:1] in (b' ',b'-',b'+') and line.endswith(b'\n'),'complete text patch line')
   if line[:1] in (b' ',b'-'):old.append(line[1:])
   if line[:1] in (b' ',b'+'):new.append(line[1:])
  need(len(old)==oldcount and len(new)==newcount and original[cursor:cursor+oldcount]==old,'exact full hunk context')
  cursor+=oldcount;out.extend(new);hunks+=1
 need(hunks>0,'nonempty strict text transformation');out.extend(original[cursor:]);result=b''.join(out)
 need(len(result)==spec['after']['bytes'] and digest(result)==spec['after']['sha256'] and blob(result)==spec['after']['git_blob_sha1'],'complete resulting body differs')
 return result
def logical_inventory(value):
 return {'head':value['head'],'tree':value['tree'],'source_files':value['source_files'],
  'gitlinks':[{k:r[k] for k in ('path','git_mode','git_commit','submodule_content_measured')}|
   {'state':r['worktree_before']['state'],'absent_path':r['worktree_before']['absent_path']} for r in value['gitlinks']]}
def compare_fork(project,before,after):
 """Every unchanged blob, LFS payload and gitlink reference stays identical."""
 a={r['path']:r for r in before['source_files']};b={r['path']:r for r in after['source_files']}
 need(set(a)==set(b),'fork tracked payload namespace changed')
 need(logical_inventory(before)['gitlinks']==logical_inventory(after)['gitlinks'],'fork gitlink reference/state changed')
 changed={f['path']:f for f in project['files']}
 need(set(changed)<=set(a),'transformation path absent from complete raw tree')
 for path,old in a.items():
  new=b[path]
  if path not in changed:need(old==new,'unexpected changed tracked body: '+path);continue
  f=changed[path]
  need(old['lfs'] is new['lfs'] is None and old['symlink_target'] is new['symlink_target'] is None,'declared patch must be ordinary non-LFS source')
  for observed,key in ((old,'before'),(new,'after')):
   need(observed['git_mode']==f['git_mode'] and observed['bytes']==f[key]['bytes'] and observed['sha256']==f[key]['sha256'] and observed['git_blob']==f[key]['git_blob_sha1'],'full fork pre/post body differs: '+path)
 return True

def clone_equivalent(original,clone):
 a=logical_inventory(original);b=logical_inventory(clone)
 # Missing and empty remain explicit unmaterialized references in both proofs.
 # Their physical inode/state may differ after an exclusive complete clone.
 for v in (a,b):
  for r in v['gitlinks']:r.pop('state');r.pop('absent_path')
 need(a==b,'full clone changes selected tracked/LFS/reference inputs')
 return True

def validate_fork_receipt(value,candidate,catalog,read_inventory,read_surface,current_inventories=None,source4=None):
 """Bind every full pre/post inventory; current graph must use exact new heads.

Readers retain/reverify all raw descriptors under the unchanged whole metadata
ceiling. This is source-only proof, not acceptance of a CVE/build/release claim.
"""
 need(type(value) is dict and value.get('schema')==RECEIPT_SCHEMA and value.get('complete') is True and value.get('completed_project_count')==24 and type(value.get('completed_project_count')) is int and value.get('actual_error') is None,'all24 completed full forks required')
 need((value.get('source_commit'),value.get('source_tree'),value.get('source_archive_sha256'))==(candidate['commit'],candidate['tree'],candidate['archive_sha256']),'current fork receipt tuple differs')
 for name in ('original_source_or_metadata_written','full_ASB_coverage_qualified','source_bom_qualified','compiled','installed','production_ready'):
  need(value.get(name) is False,'fork receipt exceeds measured source scope')
 tags={'baseline:'+x for x in AFFECTED_PROJECTS}|{'prior:'+x for x in PRIOR_PRIVATE_PROJECTS}|{'control','manifest'}
 before=value.get('all_original_and_retained_metadata_before');after=value.get('all_original_and_retained_metadata_after')
 need(type(before) is dict and set(before)==tags and before==after,'all42 retained metadata roots missing/changed')
 for row in before.values():need(row.get('complete') is True and type(row.get('files')) is dict and type(row.get('root_fd9')) is list and len(row['root_fd9'])==9,'raw retained metadata map incomplete')
 need(type(source4) is dict and set(source4)==PRIOR_PRIVATE_PROJECTS,'validated current source4 actual16 required')
 for path,r in source4.items():need(before['prior:'+path]['root']==r['private_repository']+'/.git','retained prior16 raw map physical root differs')
 projects=value.get('projects');need(type(projects) is list and [r.get('path') for r in projects]==sorted(AFFECTED_PROJECTS),'exact24 ordered fork receipt namespace')
 attempt=value.get('attempt');need(type(attempt) is int and 1<=attempt<=9,'exact finite fullfork attempt')
 stage='/var/lib/codex-trillionnium-private-source-'+candidate['commit'][:7]+'-20261003-r'+str(attempt);need(value.get('stage')==stage and value['catalog_descriptor']['path']==stage+'/control/'+CATALOG_PATH,'same-candidate fullfork stage/catalog physical mapping differs')
 specs={r['path']:r for r in catalog['projects']}
 for row in projects:
  project=row['path'];spec=specs[project];need(row.get('complete') is True and row.get('exact_changed_paths')==[f['path'] for f in spec['files']],'whole committed changed path set differs')
  need(type(row.get('private_repository')) is str and row['private_repository']==stage+'/asb-forks/'+project,'exclusive fork physical source mapping differs')
  objects=row.get('complete_git_objects');need(type(objects) is dict and objects.get('no_hardlinks_or_alternates') is True and type(objects.get('files')) is int and 0<objects['files']<=250000 and type(objects.get('bytes')) is int and 0<objects['bytes']<=64*1024**3,'complete private object-store closure missing')
  original_before=read_inventory(row['original_before']);original_after=read_inventory(row['original_after']);clone_before=read_inventory(row['clone_before']);clone_after=read_inventory(row['clone_after'])
  need(logical_inventory(original_before)==logical_inventory(original_after),'original full source inputs changed')
  need(original_before['root']==original_after['root'] and clone_before['root']==clone_after['root']==row['private_repository'],'fork source physical roots differ')
  if spec['baseline_kind']=='original_selected':need(original_before['head']==spec['historical_source_head'],'selected original generation differs')
  else:need(original_before['tree']==spec['historical_source_tree'] and (original_before['root'],original_before['head'],original_before['tree'])==(source4[project]['private_repository'],source4[project]['private_head'],source4[project]['private_tree']),'fresh source4 baseline exact generation differs')
  need(spec['historical_source_tree'] is None or original_before['tree']==spec['historical_source_tree'],'bound full baseline tree differs')
  clone_equivalent(original_before,clone_before);compare_fork(spec,clone_before,clone_after)
  need((clone_after['head'],clone_after['tree'])==(row.get('private_head'),row.get('private_tree')),'fork actual head/tree differs')
  import base64
  commit=base64.b64decode(clone_after['raw_commit_base64'],validate=True);header=commit.split(b'\n\n',1)[0].splitlines();parents=[x[7:].decode() for x in header if x.startswith(b'parent ')]
  need(parents==[clone_before['head']],'complete fork must have exactly selected baseline parent')
  for label,inv in (('original_surface_before',original_before),('original_surface_after',original_after),('clone_surface_before',clone_before),('clone_surface_after',clone_after)):
   s=read_surface(row[label]);need(s.get('schema')=='org.trillionnium.audit.actual-project-source-surface.v2' and s.get('complete') is True and s.get('accepted') is True and s.get('unknown_entries')==[] and s.get('unknown_content_diagnostics')==[] and (s.get('root'),s.get('head'),s.get('tree'))==(inv['root'],inv['head'],inv['tree']) and s.get('tracked_files')==len(inv['source_files']) and s.get('before_namespace_sha256')==s.get('after_namespace_sha256') and s.get('source_bom_qualified') is False,'full physical source surface not closed')
  need(row.get('original_git_pointer_before')==row.get('original_git_pointer_after') and type(row.get('original_git_pointer_before')) is dict,'selected .git alias changed/unobserved')
  need(row.get('original_metadata_before')==row.get('original_metadata_after')==before['baseline:'+project],'project retained metadata differs from all-generation maps')
  if current_inventories is not None:need(logical_inventory(clone_after)==logical_inventory(current_inventories[project]),'whole current graph substitutes another private generation')
 return True

def compose_private38(prior_receipt,fork_receipt,candidate):
 """Exact final-binding selector; full receipt verification is still mandatory.

This does not construct a manifest repository, native payload or graph proof.
The final binder must validate the complete fork receipt and current carrier
before using these rows; source4/native/composition cannot inherit old tuples.
"""
 tuple_=candidate['commit'],candidate['tree'],candidate['archive_sha256']
 for r in (prior_receipt,fork_receipt):need((r.get('source_commit'),r.get('source_tree'),r.get('source_archive_sha256'))==tuple_,'selection may not inherit a historical source tuple')
 need(prior_receipt.get('schema')=='org.trillionnium.audit.actual-exact-private-android-source-binding.v1' and prior_receipt.get('actual_refreshed13_composition_candidate_bound') is True and prior_receipt.get('private_project_count')==16,'actual current carrier/native prior16 precursor required')
 prior=prior_receipt.get('private_projects');need(type(prior) is list and len(prior)==16 and {r.get('path') for r in prior}==PRIOR_PRIVATE_PROJECTS,'exact current16 precursor namespace')
 need(fork_receipt.get('schema')==RECEIPT_SCHEMA and fork_receipt.get('complete') is True and fork_receipt.get('completed_project_count')==24,'all24 actual fork precursor required')
 forks=fork_receipt.get('projects');need(type(forks) is list and len(forks)==24 and {r.get('path') for r in forks}==AFFECTED_PROJECTS,'exact24 actual fork precursor namespace')
 rows={r['path']:dict(path=r['path'],private_head=r['private_head'],private_tree=r['private_tree'],private_repository=r['private_repository']) for r in prior}
 for r in forks:rows[r['path']]=dict(path=r['path'],private_head=r['private_head'],private_tree=r['private_tree'],private_repository=r['private_repository'])
 need(set(rows)==PRIVATE_PROJECTS and len(rows)==38,'exact prior16 union affected24 must have two overlaps')
 for r in rows.values():
  need(type(r['private_head']) is str and HEX40.fullmatch(r['private_head']) and type(r['private_tree']) is str and HEX40.fullmatch(r['private_tree']),'bound actual private head/tree')
  need(type(r['private_repository']) is str and r['private_repository'].startswith('/var/lib/codex-trillionnium-') and '..' not in PurePosixPath(r['private_repository']).parts,'actual exclusive private physical root')
 return [rows[p] for p in sorted(rows)]

def validate_source4_baselines(composition,defensive,candidate):
 """Exact actual13 plus actual3 current tuple, before any ASB clone mutation."""
 specs=((composition,'org.trillionnium.audit.actual-next-candidate-private13-source-composition.v1',PRIOR_PRIVATE_PROJECTS-{'external/libopenapv','frameworks/base','packages/modules/Nfc'}),(defensive,'org.trillionnium.audit.actual-complete-defensive-private-forks.v1',{'external/libopenapv','frameworks/base','packages/modules/Nfc'}));rows=[]
 for value,schema,names in specs:
  need(type(value) is dict and value.get('schema')==schema and value.get('complete') is True,'exact complete source4 stage schema')
  need((value.get('source_commit'),value.get('source_tree'),value.get('source_archive_sha256'))==(candidate['commit'],candidate['tree'],candidate['archive_sha256']),'source4 current tuple differs')
  need(all(value.get(k) is False for k in ('source_bom_qualified','original_source_or_git_writes_performed','installed','production_ready')),'source4 precursor exceeds scope')
  part=value.get('projects');need(type(part) is list and len(part)==len(names) and {r.get('path') for r in part}==set(names),'source4 exact independent13/3 namespaces')
  for r in part:
   need(type(r.get('private_head')) is str and HEX40.fullmatch(r['private_head']) and type(r.get('private_tree')) is str and HEX40.fullmatch(r['private_tree']),'source4 actual complete generation')
   need(type(r.get('private_repository')) is str and r['private_repository'].startswith('/') and '..' not in PurePosixPath(r['private_repository']).parts,'source4 exact physical repository')
   need(r.get('private_clean_status_verified') is True if value is composition else r.get('complete') is True,'source4 whole private row incomplete');rows.append(r)
 need(len(rows)==16 and {r['path'] for r in rows}==PRIOR_PRIVATE_PROJECTS,'source4 full prior16 closure')
 return {r['path']:r for r in rows}

def validate_control_catalog(catalog,catalog_raw,inventory):
 """Every catalog/patch/scoped witness is an ordinary selected control input."""
 rows=inventory.get('source_files');need(type(rows) is list,'complete canonical control inventory missing');control={r['path']:r for r in rows};need(len(control)==len(rows),'duplicate canonical control source path')
 r=control.get(CATALOG_PATH);need(r is not None and r.get('git_mode')=='100644' and r.get('bytes')==len(catalog_raw) and r.get('sha256')==digest(catalog_raw) and r.get('git_blob')==blob(catalog_raw) and r.get('lfs') is r.get('symlink_target') is None,'catalog not ordinary measured canonical Git input')
 for spec in [f['patch'] for p in catalog['projects'] for f in p['files']]+catalog['scoped_evidence']:
  r=control.get(spec['canonical_path']);need(r is not None and r.get('git_mode')=='100644' and r.get('bytes')==spec['bytes'] and r.get('sha256')==spec['sha256'] and r.get('lfs') is r.get('symlink_target') is None,'declared patch/scoped witness absent or differs from measured canonical control inventory')
 return True
