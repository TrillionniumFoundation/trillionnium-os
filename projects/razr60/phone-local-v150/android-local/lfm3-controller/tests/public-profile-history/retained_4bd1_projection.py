from pathlib import Path
import json,hashlib,re,sys
def digest(raw):return hashlib.sha256(raw).hexdigest()
if len(sys.argv)!=4:raise ValueError('supply the archived task folder, maintenance receipt folder and an unused projection path')
raw=Path(sys.argv[1]);d=Path(sys.argv[2])
GEN='7ae2aca9-a4b4-47d9-83cd-3738cdb35a21'
CMDS=('display','activities','containers','recents','processes','window')
expected='8d82c3539ecc7e12d62656063518317c1c9b53f4d4d76b5b4ca22a02b1cd38eb'
assert digest((d/'RESULT.json').read_bytes())==expected
bb=raw/('background-broker-'+GEN+'.bin')
assert digest(bb.read_bytes())=='d67a2c2f8a158dee6d87432dbea9163433cbe055bac3f4d85255333ef213aef3'
lines=bb.read_bytes().splitlines();assert len(lines)==2 and lines[0]==lines[1]
old=json.loads(lines[0]);leaf=old['profile_last_leaf_validation'];detached=old['public_surface_detach']
assert old['state']=='CLEANUP_UNKNOWN' and old['profile_custody_retained'] and old['public_scope_admission_retired']
assert leaf['valid'] and leaf['retained_task_identity_matches'] and leaf['actual_task_token_equal_to_retained'] is True
assert (leaf['observed_task_id'],leaf['observed_parent_id'],leaf['observed_display_id'],leaf['observed_user_id'],leaf['observed_full_uid'])==(1000068,1854,526,10,1010485)
assert detached['worker_finished'] and detached['api_returned'] and not detached['deadline_exceeded']
r=json.loads((d/'RESULT.json').read_bytes()); states=[];ages=[];paths=[]
for i,(name,proof) in enumerate(zip(('before-1','before-2','after-1','after-2'),r['samples'])):
    samples={k:(d/name/(k+'.txt')).read_bytes() for k in CMDS}
    assert {k:digest(v) for k,v in samples.items()}==proof['inventory_hashes']
    container=samples['containers'].decode()
    parts=re.split(r'(?m)^.*?(?:├─|└─) Display ([0-9]+) name="[^"]+".*$',container)
    displays={int(parts[j]):parts[j+1] for j in range(1,len(parts),2)}
    assert len(displays)==len(parts)//2 and set(displays)==({0,1,526} if i<2 else {0,1})
    owned=displays.pop(526,'')
    assert (re.findall(r'\bTask=([0-9]+)\b',owned)==['1854'] and 'ActivityRecord{' not in owned) if i<2 else not owned
    states.append({n:tuple(re.findall(r'Task=\d+|ActivityRecord\{[^}]+\}',section)) for n,section in displays.items()})
    assert all(states[-1].values()) and not any('Task=1000068' in row or 'Task=1854' in row for groups in states[-1].values() for row in groups)
    assert proof['owner_present']==proof['empty_root_present']==proof['owned_display_present']==(i<2)
    ages.append(proof['wall_ns']//1000000)
    paths.append(str(d/name/'recents.txt'))
assert states[0]==states[1]==states[2]==states[3]
out=Path(sys.argv[3]);assert not out.exists()
bootstrap=raw/'background-bootstrap.json'
assert digest(bootstrap.read_bytes())=='e68c45242747ad3c5d690aeb3e5cba98da5aa8d3da761449258db376c7784f79'
out.write_text(json.dumps({'profile_target_wire':json.loads(bootstrap.read_bytes())['profile_target_wire'],'recents_paths':paths,'times_ms':ages,
'original_from_phone':True,'all_four_framework_dumps_bound':True,'owned_leaf_id':leaf['observed_task_id'],'owned_root_id':leaf['observed_parent_id'],'owned_display_id':leaf['observed_display_id'],'physical_and_other_census_bound':proof['physical_and_other_history_sha256'],'archived_termination_not_a_release_proof':True}))
