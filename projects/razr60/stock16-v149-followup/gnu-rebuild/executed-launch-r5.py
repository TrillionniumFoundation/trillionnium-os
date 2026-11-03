import json,datetime,hashlib,subprocess,sys
from pathlib import Path
b=Path('/home/qian-qi/razr60-independent-gnu-session-v149-20261103')
old=Path('/home/qian-qi/Documents/Codex/2026-10-15/rog-moto-razr-60-ultra-p0/work/latecancel-source-review')
new=b/'r5-canonical-base'
source=Path('/home/qian-qi/razr60-backend-source-closure-v149-20261103/prepared/workspace')
assert not old.exists(),'historical host directory unexpectedly exists'
assert Path('/home/qian-qi/Documents').is_dir()
new.mkdir(mode=0o700,exist_ok=False)
(new/'proposed-4b687742').mkdir(mode=0o700)
r4=json.loads((b/'BUILD-LAUNCH-R4-INTENT.json').read_text())
argv=r4['argv']
i=argv.index('--proc')
mounts=['--tmpfs','/home/qian-qi/Documents','--dir',str(old),'--bind',str(new),str(old),'--ro-bind',str(source),str(old/'proposed-4b687742')]
argv[i:i]=mounts
argv[argv.index('--source')+1]=str(old/'proposed-4b687742')
argv[argv.index('--out')+1]=str(old/'gnu-actual239-r1')
intent={'schema':'razr60.gnu.canonical-path-r5-launch.v1','utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'argv':argv,'basis':'Original ELF contains 22 cargo-home registry source prefixes at this exact historical path; original recipe/tool manifest bind the same BASE and output. No source or flags or binary edits.','host_historical_directory_absent_before':True,'new_owned_physical_output':str(new),'mounts_only_in_bwrap_namespace':mounts,'source_mounted_read_only':True,'network_namespace_isolated':True,'phone_operations':0,'service_changes':0,'dependency_downloads':0,'driver_sha256':hashlib.sha256((b/'rebuild_gnu_core.py').read_bytes()).hexdigest(),'previous_attempt_r4_preserved':True,'cargo_timeout_seconds':180,'process_virtual_memory_bytes':8*1024**3,'cpu_affinity_count':4}
(b/'BUILD-LAUNCH-R5-INTENT.json').write_text(json.dumps(intent,indent=2)+'\n')
print(json.dumps({'launch_r5':'canonical_path_bound_in_namespace_only','physical_new_base':str(new)}),flush=True)
try:
 p=subprocess.run(argv,timeout=360);rc=p.returncode;error=None
except subprocess.TimeoutExpired:
 rc=124;error='outer 360s timeout'
result={'schema':'razr60.gnu.canonical-path-r5-launch-result.v1','utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'launch_rc':rc,'error':error,'host_historical_directory_still_absent':not old.exists(),'intent_sha256':hashlib.sha256((b/'BUILD-LAUNCH-R5-INTENT.json').read_bytes()).hexdigest(),'physical_result_path':str(new/'gnu-actual239-r1/FRESH-GNU-REBUILD-RECEIPT.json'),'phone_operations':0,'service_changes':0}
(b/'BUILD-LAUNCH-R5-RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result),flush=True)
assert result['host_historical_directory_still_absent']
sys.exit(rc)

