#!/usr/bin/env python3
"""Offline source controls only. Never contacts a phone or constructs a sender actor."""
import base64, copy, hashlib, importlib.util, json, pathlib, shlex, subprocess, sys, tempfile
ROOT=pathlib.Path(__file__).resolve().parent
BASE=ROOT/'projects/razr60/phone-local-v150/acceptance/r10-fixed19-1ad3-20261105/followthrough-20261106-fc33'
SOURCE=BASE/'actual-e2e-bound-source/actual/shared/provider/source'
sys.path.insert(0,str(SOURCE))
import phone_task_guards as g
from provider_openai_compatible import ProviderError
B64=lambda s:base64.b64encode(s.encode()).decode()
TOKEN='a'*32
page='\n'.join(['Display: mDisplayId=0','mTopFocusedDisplayId=0','mCurrentFocus=Window{a u0 '+g.HEPTA_COMPONENT+'}', 'mFocusedApp=ActivityRecord{b u0 '+g.HEPTA_COMPONENT+' t1}', 'isKeyguardShowing=false','topResumedActivity=ActivityRecord{b u0 '+g.HEPTA_COMPONENT+' t1}'])
launch='Status: ok\nActivity: '+g.HEPTA_COMPONENT+'\n'
receipt={'schema':'hepta.return-receipt.v149.1','operation_id':TOKEN,'launch_exit_code':0,'launch_b64':B64(launch),'page_b64':B64(page),'viewport_b64':B64('fixture viewport separately checked by caller')}
results=[]
def rejection(name, mutate):
 value=copy.deepcopy(receipt);mutate(value)
 try:g.verify_return(value,TOKEN)
 except ProviderError as e:results.append({'name':name,'passed':True,'rejection':str(e)})
 else:raise AssertionError(name+' accepted invalid receipt')
assert g.verify_return(receipt,TOKEN)[0]['component']==g.HEPTA_FULL_COMPONENT
results.append({'name':'complete exact launch/focus/resumed accepted','passed':True})
rejection('nonzero launch',lambda r:r.update(launch_exit_code=137))
rejection('boolean launch exit',lambda r:r.update(launch_exit_code=False))
rejection('wrong operation',lambda r:r.update(operation_id='b'*32))
rejection('missing launch Activity',lambda r:r.update(launch_b64=B64('Status: ok\n')))
rejection('duplicate launch status',lambda r:r.update(launch_b64=B64(launch+'Status: ok\n')))
rejection('wrong Activity same package',lambda r:r.update(launch_b64=B64(launch.replace('OwnerOpenShellActivity','OtherActivity'))))
rejection('launch error alongside ok',lambda r:r.update(launch_b64=B64(launch+'Error: refused\n')))
rejection('top resumed disagreement',lambda r:r.update(page_b64=B64(page.replace('topResumedActivity=ActivityRecord{b u0 '+g.HEPTA_COMPONENT,'topResumedActivity=ActivityRecord{b u0 other.app/.Main'))))
rejection('current window disagreement',lambda r:r.update(page_b64=B64(page.replace('mCurrentFocus=Window{a u0 '+g.HEPTA_COMPONENT,'mCurrentFocus=Window{a u0 other.app/.Main'))))
rejection('focused app disagreement',lambda r:r.update(page_b64=B64(page.replace('mFocusedApp=ActivityRecord{b u0 '+g.HEPTA_COMPONENT,'mFocusedApp=ActivityRecord{b u0 other.app/.Main'))))
rejection('external focused display',lambda r:r.update(page_b64=B64(page.replace('mTopFocusedDisplayId=0','mTopFocusedDisplayId=1'))))
rejection('keyguard active',lambda r:r.update(page_b64=B64(page.replace('isKeyguardShowing=false','isKeyguardShowing=true'))))
rejection('missing actual resumed',lambda r:r.update(page_b64=B64('\n'.join(x for x in page.splitlines() if not x.startswith('topResumedActivity=')))))
rejection('extra receipt field',lambda r:r.update(unverified=True))
# Execute only local shell function mocks. A nonzero dump must not read partial XML.
with tempfile.TemporaryDirectory(prefix='navigation-review-') as td:
 td=pathlib.Path(td);xml=td/'capture.xml';attempt=td/'attempt';calls=td/'calls'
 shell='dumpsys() { return 0; }; uiautomator() { printf x >> '+shlex.quote(str(calls))+'; printf partial > "$2"; printf "Killed\\n" >&2; return 137; }; '
 shell+=g.public_text_command('',TOKEN,'test.app',str(xml))
 proc=subprocess.run(['/bin/sh','-c',shell],capture_output=True,timeout=5)
 assert proc.returncode==73 and calls.read_bytes()==b'x' and not xml.exists() and not proc.stdout and b'Killed' in proc.stderr
 results.append({'name':'public collector dump137 single attempt no receipt own XML removed','passed':True,'exit_code':proc.returncode})
# Return launch is exactly one effect; a failed launch remains nonzero after read-only observations.
with tempfile.TemporaryDirectory(prefix='navigation-review-') as td:
 td=pathlib.Path(td);calls=td/'calls'
 shell='am() { printf x >> '+shlex.quote(str(calls))+'; printf "Error: refused\\n"; return 17; }; dumpsys() { return 0; }; '
 proc=subprocess.run(['/bin/sh','-c',shell+g.return_command('',TOKEN)],capture_output=True,timeout=5)
 payload=json.loads(proc.stdout)
 assert proc.returncode==17 and calls.read_bytes()==b'x' and payload['launch_exit_code']==17
 results.append({'name':'failed return launch remains nonzero and is not retried','passed':True,'exit_code':proc.returncode})
pins={str(p.relative_to(ROOT)):{'bytes':len(p.read_bytes()),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in SOURCE.glob('*.py')}
report={'schema':'hepta.navigation-readonly-source-review.v1','source_commit':'ca3f26100c57579bcb740488e4a7f9ec8b912e4d','phone_calls':0,'native_dispatches':0,'sender_actor_constructions':0,'production_source_changes':0,'physical_qualification':False,'fixed19_credit':0,'passed':len(results),'total':len(results),'controls':results,'source_files':pins}
(ROOT/'NAVIGATION-SOURCE-CONTROLS.json').write_text(json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
print(json.dumps({k:report[k] for k in ('source_commit','phone_calls','production_source_changes','physical_qualification','fixed19_credit','passed','total')},sort_keys=True))
