#!/usr/bin/env python3
"""Seal reviewed static launch argv and observed payload pins into a new module directory.
This tool never installs a module, starts a process, contacts a phone, or supplies a task.
"""
import argparse,hashlib,json,pathlib,re,shlex,shutil,os
p=argparse.ArgumentParser()
p.add_argument('--bindings',required=True)
p.add_argument('--output',required=True)
a=p.parse_args()
source=pathlib.Path(__file__).resolve().parent/'module-root'
out=pathlib.Path(a.output)
binding=json.loads(pathlib.Path(a.bindings).read_text(encoding='utf-8'))
assert binding['schema']=='org.trillionnium.hepta.phone-local-module-bindings.v1'
assert binding['reviewed_for_installation'] is True
assert binding['module_release']=='v150-r3'
assert binding['prior_release_must_be_disabled'] is True
assert binding['native_profile']=='leap-stock16-codex-host-relay-v1'
assert binding['automatic_tasks'] is False and binding['automatic_resume'] is False
assert binding['automatic_redispatch'] is False
assert binding['replay_unknown_effects'] is False
assert not out.exists() and not out.is_symlink()
def safe(s):
 assert isinstance(s,str) and s and '\x00' not in s and '\n' not in s and '\r' not in s
 return s
files=binding['payloads']
assert isinstance(files,list) and files
seen=set()
for entry in files:
 path=safe(entry['path'])
 assert path.startswith(('/data/local/tmp/hepta-phone-local-v150-r1/','/data/trillionnium/owner-open/state/phone-local-v150/','/data/adb/modules/trillionnium_hepta_phone_local_v150_r3/'))
 assert '/..' not in path and ' ' not in path and '\\' not in path and path not in seen
 assert re.fullmatch('[0-9a-f]{64}',entry['sha256'])
 assert isinstance(entry['bytes'],int) and entry['bytes']>=0
 seen.add(path)
assert set(binding['roles'])=={'model','sidecar','provider'}
for role in ['model','sidecar']:
 assert binding['roles'][role]['argv'][0] in seen
required_inside=[
 '/var/lib/trillionnium/owner-open/phone-local-v150/tool_client.py',
 '/var/lib/trillionnium/owner-open/phone-local-v150/local-config-r3.json',
 '/var/lib/trillionnium/owner-open/phone-local-v150/retained-claims.json',
 '/var/lib/trillionnium/owner-open/phone-local-v150/provider-r3/source/daily_phone_local.py']
for inner in required_inside:
 outer=inner.replace('/var/lib/trillionnium/owner-open/','/data/trillionnium/owner-open/state/',1)
 assert outer in seen
for row in binding['roles'].values():
 for arg in row['argv']:
  assert 'REPLACE_WITH_' not in arg and 'ROOT_SELECT_' not in arg
model_argv=binding['roles']['model']['argv']
assert model_argv[model_argv.index('-m')+1] in seen
assert model_argv[model_argv.index('--mmproj')+1] in seen
assert model_argv[model_argv.index('--host')+1]=='127.0.0.1'
key_path=model_argv[model_argv.index('--api-key-file')+1]
assert key_path in seen
provider_key='/data/trillionnium/owner-open/state/phone-local-v150/private/llama-api.key'
assert provider_key in seen
pins_by_path={x['path']:x for x in files}
assert pins_by_path[key_path]['sha256']==pins_by_path[provider_key]['sha256']
assert pins_by_path[key_path]['bytes']==pins_by_path[provider_key]['bytes'] and pins_by_path[key_path]['bytes']>0
assert binding['roles']['provider']['argv'][0]=='/data/adb/magisk/busybox'
assert binding['roles']['provider']['argv'][1:3]==['chroot','/data/trillionnium/owner-open/root']
assert binding['roles']['provider']['argv'][3]=='/usr/bin/python3'
for role,data in binding['roles'].items():
 argv=data['argv'];assert isinstance(argv,list) and argv and safe(argv[0]).startswith('/')
 for x in argv:safe(x)
 # Secret values must be in separately protected payload configuration, not argv.
 assert '--api-key' not in argv and not any(x.startswith('--api-key=') for x in argv)
 assert 'LLAMA_API_KEY' not in data.get('environment',{})
 for key,val in data.get('environment',{}).items():
  assert re.fullmatch('[A-Z][A-Z0-9_]*',key)
  safe(val)
 assert data.get('send_task_on_start',False) is False
policy=source/'sepolicy.rule'
if policy.exists():
 assert policy.is_file() and not policy.is_symlink()
 assert binding.get('policy_source_sha256')==hashlib.sha256(policy.read_bytes()).hexdigest()
 assert binding.get('policy_change_evidence')
else:
 assert not binding.get('policy_source_sha256')
out.mkdir(mode=0o700,parents=True)
for name in ['module.prop','skip_mount','service.sh','role_guard.sh']:
 src=source/name;assert src.is_file() and not src.is_symlink()
 shutil.copyfile(src,out/name)
 os.chmod(out/name,0o700 if name=='service.sh' else 0o600)
if policy.exists():
 shutil.copyfile(policy,out/'sepolicy.rule')
 os.chmod(out/'sepolicy.rule',0o600)
for role,data in binding['roles'].items():
 env=data.get('environment',{})
 # BusyBox is static: it can enter the verified GNU root before Python's ELF loader runs.
 cmd=['/data/adb/magisk/busybox','env','-i']+[k+'='+v for k,v in sorted(env.items())]+data['argv']
 text='#!/system/bin/sh\nset -eu\numask 077\nexec '+shlex.join(cmd)+'\n'
 (out/f'launch-{role}.sh').write_text(text,encoding='utf-8')
 os.chmod(out/f'launch-{role}.sh',0o600)
(out/'payload-inputs.sha256').write_text(''.join(e['sha256']+'  '+e['path']+'\n' for e in sorted(files,key=lambda r:r['path'])),encoding='utf-8')
(out/'seal-binding.json').write_text(json.dumps(binding,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
pins=[]
for file in sorted(out.iterdir()):
 assert file.is_file() and not file.is_symlink()
 pins.append(hashlib.sha256(file.read_bytes()).hexdigest()+'  '+file.name+'\n')
(out/'module-inputs.sha256').write_text(''.join(pins),encoding='utf-8')
(out/'SEALED').write_text('HEPTA_PHONE_LOCAL_V150_INPUTS_BOUND\n',encoding='utf-8')
for file in out.iterdir():
 if file.name!='service.sh':os.chmod(file,0o600)
print(json.dumps({'status':'SEALED_STATIC_FILES_NOT_INSTALLED','output':str(out),'module_input_sha256':hashlib.sha256((out/'module-inputs.sha256').read_bytes()).hexdigest(),'phone_readback_required':True,'payload_pin_origin':'root-reviewed binding; service checks actual phone bytes before startup'}))
