#!/usr/bin/env python3
"""Exercise the actual preparer main only up to an explicit policy-read fence."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import types

ROOT=Path('/workspace/scratch/1ad3d6f55439')
HERE=Path(__file__).resolve().parent
PKG=HERE/'package'
RT=ROOT/'runtime_prefix_successor_candidate01/delivery-final01/package/runtime'
OUT=HERE/'validation/preparer-bounds01'
OUT.mkdir(parents=True,exist_ok=False)


def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def enc(v):return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()


def load(p):
    m=types.ModuleType('local_source_only_preparer');m.__file__=str(p)
    exec(compile(p.read_bytes(),str(p),'exec'),m.__dict__)
    return m


class PolicyReadFence(Exception):pass


preparer_path=PKG/'preparer/prepare_final_cascade.py'
runtime_raw=(RT/'MANIFEST.json').read_bytes()
runtime=json.loads(runtime_raw)
freeze_raw=(ROOT/'actual_r8_external_freeze/FREEZE-RESULT.json').read_bytes()
freeze=json.loads(freeze_raw)
base_row={'path':str(load(preparer_path).B/'native-guard-r10-r1-operator-r8/FREEZE-RESULT.json'),**pin(freeze_raw)}
rows=[]


def run(name,mutate,expected,oversized_descriptor=False):
    m=load(preparer_path);value=copy.deepcopy(runtime);mutate(value);raw=enc(value)
    successor_path=str(m.B/'native-guard-r10-r1-operator-r8-inventory-prefix-1ad3-01/runtime/MANIFEST.json')
    successor=dict(path=successor_path,**pin(raw))
    if oversized_descriptor:successor['bytes']=65537
    mapping={
        base_row['path']:freeze_raw,
        m.SOURCE['path']:(PKG/'source/derive_final_cascade_property_r8.py').read_bytes(),
        m.INTERFACE['path']:(PKG/'source/write_final_seal_interface_property_r8.py').read_bytes(),
        m.GENERATOR_MANIFEST['path']:(PKG/'GENERATOR-SOURCE-MANIFEST.json').read_bytes(),
        m.TEMPLATE_MANIFEST['path']:(ROOT/'lossless_bundle_source_cache/SOURCE-MANIFEST.json').read_bytes(),
        freeze['source']['path']:(ROOT/'actual_r8_external_freeze/FREEZE-SOURCE.original.py').read_bytes(),
        freeze['runtime_manifest']['path']:(ROOT/'runtime_prefix_successor_candidate01/reference/runtime32/MANIFEST.json').read_bytes(),
        successor_path:raw,
    }
    for n,item in m.TEMPLATE_OVERRIDES.items():mapping[item['successor']['path']]=(PKG/'templates'/n).read_bytes()
    for item in runtime['files']:
        mapping[str(Path(successor_path).parent/item['path'])]=(RT/item['path']).read_bytes()
    seen=[];writes=[]
    class Originals:
        def read(self,row):
            seen.append(row['path'])
            if row['path']==freeze['policy_adoption']['path']:raise PolicyReadFence()
            data=mapping[row['path']]
            assert pin(data)=={k:row[k] for k in ('bytes','sha256')},('unexpected IO fixture access',row)
            return data
        def recheck(self):raise AssertionError('past policy fence')
    m.Originals=Originals
    def reject_write(*a,**kw):writes.append(True);raise AssertionError('write reached')
    m.create=reject_write
    argv=sys.argv;sys.argv=[str(preparer_path),'--runtime-freeze-result-desc',json.dumps(base_row),
        '--runtime-successor-manifest-desc',json.dumps(successor),'--out',str(OUT/'NEVER-CREATED')]
    outcome=None
    try:
        m.main()
        raise AssertionError('expected policy or resource refusal')
    except PolicyReadFence:
        assert expected=='policy_read_fence';outcome='policy_read_fence'
    except ValueError as exc:
        assert expected in str(exc),(expected,str(exc));outcome=str(exc)
    finally:sys.argv=argv
    reads=[s for s in seen if s.startswith(str(Path(successor_path).parent)+'/') and s!=successor_path]
    if expected=='policy_read_fence':assert len(reads)==32
    else:assert len(reads)==0
    assert not writes and not (OUT/'NEVER-CREATED').exists()
    rows.append(dict(name=name,status='PASS',outcome=outcome,runtime_member_reads=len(reads),writes=0))


run('actual_runtime32_reaches_policy_read_after_all_source_gates',lambda v:None,'policy_read_fence')
run('33_rows_rejected_before_member_reads',lambda v:v['files'].append(dict(v['files'][0])), 'exact32 bounded')
run('oversized_member_rejected_before_member_reads',lambda v:v['files'][0].update(bytes=8*1024*1024+1), 'exact bounded runtime row')
run('oversized_manifest_descriptor_rejected_before_manifest_read',lambda v:None,'one explicit inventory-prefix',True)
report={'schema':'hepta.inventory-prefix.preparer-resource-wiring-checks.v1',
 'state':'PASS_LOCAL_BOUNDED_PREPARER_MAIN_PREFIX_ONLY','checks':rows,'passed':4,'total':4,
 'preparer':pin(preparer_path.read_bytes()),'runtime':pin(runtime_raw),
 'scope':{'IO_replaced_by_exact_original_byte_map':True,'target_runtime_executed':False,
          'policy_verifier_executed':False,'policy_adoption_read_fenced':True,
          'new_files_from_preparer':0,'Mac_P4_phone_operations':0,'case_credit':False}}
raw=enc(report);(OUT/'RESULT.json').write_bytes(raw)
print(json.dumps(dict(path=str(OUT/'RESULT.json'),**pin(raw),checks=4),sort_keys=True))
