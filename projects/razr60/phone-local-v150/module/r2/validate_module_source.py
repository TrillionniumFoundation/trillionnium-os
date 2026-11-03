#!/usr/bin/env python3
"""Bounded host-only syntax and previous-release admission checks; no phone use."""
import ast,hashlib,json,pathlib,re,subprocess,tempfile,datetime
root=pathlib.Path(__file__).resolve().parent
result={'schema':'hepta.module-r2-static-validation.v1','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'Host-only source syntax and release-marker predicate; no service or phone execution','checks':[],'files':[]}
for rel in ['module-root/service.sh','module-root/role_guard.sh','module-root/module.prop','module-root/skip_mount','seal_module.py']:
 p=root/rel;b=p.read_bytes()
 result['files'].append({'path':rel,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
for rel in ['module-root/service.sh','module-root/role_guard.sh']:
 c=subprocess.run(['/bin/sh','-n',str(root/rel)],capture_output=True,timeout=5)
 assert c.returncode==0,(rel,c.stderr.decode(errors='replace'))
 result['checks'].append({'name':rel+' shell syntax','status':'PASS'})
ast.parse((root/'seal_module.py').read_text())
result['checks'].append({'name':'sealer Python syntax','status':'PASS'})
service=(root/'module-root/service.sh').read_text()
guard=(root/'module-root/role_guard.sh').read_text()
assert 'PARENT_ID=$(identity "$$")' in service
assert 'own_id=$(identity "$$")' in guard
assert service.index('trap finish EXIT') < service.index('PARENT_ID=$(identity "$$")')
assert 'HISTORY=/data/adb/trillionnium-hepta-phone-local-v150-r2\n' in service
assert '/data/adb/trillionnium-hepta-phone-local-v150-r2/*' in guard
for source,label in [(service,'service'),(guard,'role_guard')]:
 m=re.search(r'(?ms)^previous_release_disabled\(\) \{\n.*?^\}\n',source)
 assert m,label
 predicate=m.group(0)
 with tempfile.TemporaryDirectory(prefix='prior-release-fixture-',dir=root) as tmp:
  base=pathlib.Path(tmp)
  absent=base/'absent'
  enabled=base/'enabled';enabled.mkdir()
  disabled=base/'disabled';disabled.mkdir();(disabled/'disable').write_text('')
  removed=base/'removed';removed.mkdir();(removed/'remove').write_text('')
  linked=base/'linked';linked.symlink_to(disabled,target_is_directory=True)
  linkedflag=base/'linkedflag';linkedflag.mkdir();(linkedflag/'disable').symlink_to(disabled/'disable')
  for name,path,expected in [('absent',absent,0),('enabled',enabled,1),('disabled',disabled,0),('remove',removed,0),('symlink_module',linked,1),('symlink_flag',linkedflag,1)]:
   test=predicate+'\nPRIOR=$1\nprevious_release_disabled\n'
   c=subprocess.run(['/bin/sh','-c',test,'predicate-fixture',str(path)],capture_output=True,timeout=3)
   assert c.returncode==expected,(label,name,c.returncode,expected)
   result['checks'].append({'name':label+' '+name,'expected_exit':expected,'actual_exit':c.returncode,'status':'PASS'})
assert not (root/'module-root/SEALED').exists()
result['checks'].append({'name':'unsealed source cannot be installed as sealed release','status':'PASS'})
result['status']='PASS_STATIC_ONLY_NOT_PHONE_QUALIFIED'
with (root/'STATIC-VALIDATION-v150-r2.json').open('x',encoding='utf-8') as f:json.dump(result,f,ensure_ascii=False,indent=2);f.write('\n')
print(json.dumps({'status':result['status'],'checks':len(result['checks']),'output':str(root/'STATIC-VALIDATION-v150-r2.json')}))
