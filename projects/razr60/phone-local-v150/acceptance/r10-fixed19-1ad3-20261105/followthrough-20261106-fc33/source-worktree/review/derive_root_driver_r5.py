#!/usr/bin/env python3
"""Exact source-only driver delta; final runtime SHA remains unbound."""
from pathlib import Path
import ast, difflib, hashlib, json, re

BASE=Path(__file__).resolve().parent
PARENT=BASE/'R4'
OUT=BASE/'R5-root'
FROZEN='/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-fc33-native-v3-r5'

def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

def main():
    rows=json.loads((PARENT/'root-chain/SOURCE-MANIFEST.json').read_bytes())['files']
    parents={r['path']:{k:r[k] for k in ('bytes','sha256')} for r in rows}
    path='source/run_component_root_once.py';original=(PARENT/'root-chain'/path).read_bytes()
    assert pin(original)==parents[path]
    source=original.decode();edits=[]
    def change(old,new):
        nonlocal source
        assert source.count(old)==1,(old,'unique whole source match')
        source=source.replace(old,new,1);edits.append((old,new))
    def constant(name,new):
        matches=re.findall(r'^'+re.escape(name)+r'\s*=.*$',source,re.M)
        assert len(matches)==1,(name,'one bound constant')
        change(matches[0],name+' = '+new)
    constant('PKG','None')
    constant('COMBINATION',repr('7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'))
    constant('SHARED',repr('cc7eb624333216e510b540c3af8277e948aa689a108950fa78e8d01c2177e5b1'))
    constant('CONFIG',repr('5ff00467e8432d7119ba72a700ce07cb20f16555d3dc0c90de7cbfc388103f48'))
    constant('SERVICE',repr('273db17098e5de6c67ded208e120e3910531ab1c7a778faa76824d453ddddd58'))
    constant('MATERIAL_ROOT','Path('+repr(FROZEN+'/shared')+')')
    for name,filename in [('SENDER','send_new_native_guard_task_r10_r4.py'),('READY_HELPER','sender_native_guard_ready_r10_r4.py')]:
        constant(name,repr(pin((OUT/'runtime/source'/filename).read_bytes())['sha256']))
    change("         and not reader.is_diagnostic_parent_ancestor(boundary),\n         'final native component generation cannot bypass exact closed actual_v3_diagnostic')\n    parent=reader.is_v3_runtime_diagnostic_ancestor(boundary)\n    if parent:\n        need(p['case_id']=='NEG-01' and prior==reader.reviewed_v3_runtime_diagnostic_ancestor()['boundary']\n             and p['previous']['bytes']==1434\n             and p['previous']['sha256']=='35cc7f4b24379781dae7f181704218b612d9a42313b7efee9a52d649f37e1099',\n             'the new generation must enter through exact closed actual_v3_diagnostic; older ancestors cannot substitute')\n",
           "         and not reader.is_diagnostic_parent_ancestor(boundary)\n         and not reader.is_v3_runtime_diagnostic_ancestor(boundary),\n         'new source tuple must retain its exact closed source-parent head')\n    parent=reader.is_source_parent_ancestor(boundary)\n    source_parent=reader.reviewed_source_parent_records()[0]\n    if parent:\n        need(p['case_id']=='NEG-01' and prior==source_parent['boundary']\n             and p['previous']==source_parent['closed_previous'],\n             'the new source tuple must enter through its exact actual closed source-parent head')\n")
    change("        need(home==Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01'),\n             'actual_v3_diagnostic originals must retain their original Root namespace')\n",
           "        need(home==Path(source_parent['closed_previous']['path']).parent,\n             'source-parent originals must retain their actual original Root namespace')\n")
    change("    need(len(selected['roots'])in(41,44)and len(selected['roots'])<=47,'current retained-stage cumulative roots differ')\n",
           "    expected_roots=reader.SOURCE_PARENT_INVENTORY_ROOT_COUNT+(0 if parent else 3)\n    need(len(selected['roots'])==expected_roots\n         and expected_roots<reader.MAX_CURRENT_INVENTORY_ROOTS,\n         'current roots must retain the actual source parent and exact new component growth')\n")
    change("    expected_closer=reader.V3_RUNTIME_DIAGNOSTIC_CLOSURE_SHA256 if parent else closers[0]['sha256']\n",
           "    expected_closer=source_parent['closure_source_sha256'] if parent else closers[0]['sha256']\n")
    change("    need((p['case_id']==boundary['case_id'] and failed)\n         or (not parent and boundary['case_id']=='NEG-01' and p['case_id']=='NEG-02' and passed),\n         'only a closed unqualified same-case failure or current qualified NEG01-to-NEG02 progression is allowed')\n",
           "    need((parent and p['case_id']=='NEG-01' and passed)\n         or (not parent and p['case_id']==boundary['case_id'] and failed)\n         or (not parent and boundary['case_id']=='NEG-01' and p['case_id']=='NEG-02' and passed),\n         'only the exact source-parent entry or current closed NEG01-to-NEG02 progression is allowed')\n")
    inverse=source
    for old,new in reversed(edits):
        assert inverse.count(new)==1
        inverse=inverse.replace(new,old,1)
    assert inverse.encode()==original
    ast.parse(source)
    candidate=source.encode();(OUT/'root-chain'/path).write_bytes(candidate)
    patch=''.join(difflib.unified_diff(original.decode().splitlines(keepends=True),source.splitlines(keepends=True),fromfile='R4/root-chain/'+path,tofile='R5/root-chain/'+path))
    (OUT/'reviewed-deltas/run_component_root_once.py.patch').write_text(patch)
    bridge_path='source/phone_chain_bridge.py';bridge_original=(PARENT/'root-chain'/bridge_path).read_bytes()
    assert pin(bridge_original)==parents[bridge_path]
    old="PKG = '72d6dcb4c20547549debad6ef55001aa5c8d115574ac222312b158f9722e2515'"
    assert bridge_original.count(old.encode())==1
    bridge=bridge_original.replace(old.encode(),b'PKG = None',1)
    assert bridge.replace(b'PKG = None',old.encode(),1)==bridge_original
    ast.parse(bridge);(OUT/'root-chain'/bridge_path).write_bytes(bridge)
    proof={'schema':'hepta.fc33.root-driver-source-parent-delta.v1','state':'RUNTIME_PACKAGE_SHA_PENDING',
        'fixed_material_root':FROZEN+'/shared','source_parent_count':1,
        'source_parent_credit_for_new_tuple':False,'phone_calls':0,'new_nonces':0,
        'root':{'parent':pin(original),'candidate':pin(candidate),'exact_whole_byte_inverse':True,'replacement_count':len(edits)},
        'bridge':{'parent':pin(bridge_original),'candidate':pin(bridge),'exact_whole_byte_inverse':True},
        'only_unbound_runtime_constant':'PKG'}
    raw=(json.dumps(proof,sort_keys=True,indent=2)+'\n').encode()
    (OUT/'ROOT-DRIVER-DELTA.json').write_bytes(raw)
    print(json.dumps({'result':pin(raw),'root':pin(candidate),'bridge':pin(bridge),'phone_calls':0}))

if __name__=='__main__':main()
