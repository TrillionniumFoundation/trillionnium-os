#!/usr/bin/env python3
"""Local byte/AST and bounded decoder checks. Never execute candidate runtime."""
import ast
import base64
import copy
import hashlib
import json
from pathlib import Path
import zlib

ROOT=Path('/workspace/scratch/1ad3d6f55439')
HERE=Path(__file__).resolve().parent
SOURCE=HERE/'source/verify_explicit_inventory_reader_once.py'
raw=SOURCE.read_bytes();parent=(HERE/'reference/verify_actual_retired_once.118d.original.py').read_bytes()
staged=(ROOT/'runtime_prefix_successor_candidate01/reference/runtime32/source/late_boundary.py').read_bytes()
candidate=(HERE/'reference/late_boundary.147cf.original.py').read_bytes()
OUT=HERE/'validation/source-check01';OUT.mkdir(exist_ok=False)
checks=[]


def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())


def check(name,fn):
    try:
        detail=fn();checks.append(dict(name=name,passed=True,detail=detail))
    except BaseException as exc:
        checks.append(dict(name=name,passed=False,error=type(exc).__name__,detail=str(exc)))


def spans(data):
    lines=data.splitlines(keepends=True);out={}
    for n in ast.parse(data).body:
        if isinstance(n,ast.FunctionDef):
            lo=sum(map(len,lines[:n.lineno-1]))+n.col_offset
            hi=sum(map(len,lines[:n.end_lineno-1]))+n.end_col_offset
            out[n.name]=data[lo:hi]
    return out


def unchanged():
    old,new=spans(parent),spans(raw)
    keep=sorted(set(old)-{'main'})
    assert all(old[n]==new[n] for n in keep)
    assert set(new)-set(old)=={'explicit_candidate_source','load_explicit_candidate_late'}
    return dict(byte_identical_original_helpers=keep,only_new_helpers=sorted(set(new)-set(old)))


check('all_original_bootstrap_and_owned_cleanup_helpers_byte_identical',unchanged)
tree=ast.parse(raw)
main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')


def call_and_cleanup():
    oldmain=next(n for n in ast.parse(parent).body if isinstance(n,ast.FunctionDef) and n.name=='main')
    def find_call(tree):
        return [n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
                and isinstance(n.func.value,ast.Name) and n.func.value.id=='L' and n.func.attr=='verify_retired']
    newcalls,oldcalls=find_call(main),find_call(oldmain)
    assert len(newcalls)==len(oldcalls)==1 and ast.dump(newcalls[0])==ast.dump(oldcalls[0])
    def final(tree):
        return next(n.finalbody for n in ast.walk(tree) if isinstance(n,ast.Try) and any(
            isinstance(c,ast.Call) and isinstance(c.func,ast.Name) and c.func.id=='release_owned_verifier_lock'
            for s in n.finalbody for c in ast.walk(s)))
    assert [ast.dump(n) for n in final(main)]==[ast.dump(n) for n in final(oldmain)]
    attrs={n.attr for n in ast.walk(tree) if isinstance(n,ast.Attribute)}
    assert not {'settrace','setprofile','alarm','setitimer','kill','killpg'} & attrs
    assert b'OBSERVED_CALL_SECONDS=180\n' in raw
    return 'One original call and original finally are AST identical; no tracing/signals;180 remains post-return.'


check('one_original_lifecycle_call_and_exact_finally',call_and_cleanup)


def no_clearance_or_module_override():
    pairs=[]
    for n in ast.walk(main):
        if isinstance(n,ast.Dict):
            pairs.extend((k.value,v) for k,v in zip(n.keys,n.values) if isinstance(k,ast.Constant) and type(k.value) is str)
    for field in ('original_verification_complete','original_global_clearance_evidence'):
        values=[v for k,v in pairs if k==field]
        assert len(values)==2 and all(isinstance(v,ast.Constant) and v.value is False for v in values)
    assert 'hepta.native-guard.expired-lease-explicit-reader-diagnostic.v1' in raw.decode()
    loader=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='load_explicit_candidate_late')
    assert not any(isinstance(n,ast.Assign) and any(isinstance(t,ast.Subscript)
        and isinstance(t.value,ast.Attribute) and t.value.attr=='modules' for t in n.targets) for n in ast.walk(loader))
    assert not any(isinstance(n,ast.Assign) and any(isinstance(t,ast.Attribute)
        and t.attr in {'__reviewed_source_sha256__','__reviewed_package_sources__'} for t in n.targets) for n in ast.walk(loader))
    compile_calls=[n for n in ast.walk(loader) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='compile']
    assert len(compile_calls)==1 and isinstance(compile_calls[0].args[1],ast.Name)
    assert compile_calls[0].args[1].id=='CANDIDATE_COMPILE_FILENAME'
    return 'New result namespace cannot grant original clearance; no sys.modules/source-map/self-source override.'


check('diagnostic_identity_and_resource_anchor_are_separate',no_clearance_or_module_override)

names={'STAGED_LATE_PIN','EXECUTED_LATE_PIN','CANDIDATE_COMPILE_FILENAME','CANDIDATE_ZLIB_PIN',
       'CANDIDATE_ZLIB_B64','OLD_INVENTORY_EXPRESSION','NEW_INVENTORY_EXPRESSION','PACKAGE_PIN'}
nodes=[]
for n in tree.body:
    if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in names:nodes.append(n)
    if isinstance(n,ast.FunctionDef) and n.name in {'need','sha','explicit_candidate_source'}:nodes.append(n)
pure={'base64':base64,'zlib':zlib,'hashlib':hashlib}
exec(compile(ast.Module(body=nodes,type_ignores=[]),'<only-pure-decoder-extracted>','exec'),pure)
defaults={name:pure[name] for name in names}
files={'source/late_boundary.py':staged}


def valid():
    before=dict(files);body,proof=pure['explicit_candidate_source'](files)
    assert body==candidate and files==before
    assert proof['executed_late']==pin(candidate) and proof['staged_late']==pin(staged)
    assert proof['whole_source_inverse_matches_actual_staged_bytes'] is True
    assert proof['reference_file_reads_redirected_to_memory'] is False and proof['memoization_added'] is False
    return dict(decoded=pin(body),staged=pin(staged),target_module_compiled_or_executed=False)


check('bounded_decode_exact147cf_and_full_inverse_c50a',valid)


def reject(change,why):
    pure.update(defaults);local=dict(files);change(pure,local)
    try:
        try:pure['explicit_candidate_source'](local)
        except (ValueError,TypeError) as exc:
            assert why in str(exc),(why,str(exc));return str(exc)
        raise AssertionError('must refuse')
    finally:pure.update(defaults)


check('changed_staged_original_refused',lambda:reject(lambda g,f:f.update({'source/late_boundary.py':staged+b'\n'}),'stagedc50a'))
check('encoding_budget_refused_before_decode',lambda:reject(lambda g,f:g.update(CANDIDATE_ZLIB_B64='A'*131073),'bounded fixed'))


def packed_mutation(extra):
    def change(g,f):
        packed=base64.b64decode(g['CANDIDATE_ZLIB_B64'])+extra
        g['CANDIDATE_ZLIB_B64']=base64.b64encode(packed).decode()
        g['CANDIDATE_ZLIB_PIN']=(len(packed),hashlib.sha256(packed).hexdigest())
    return change


check('second_zlib_stream_refused_even_with_test_only_matching_compressed_pin',lambda:reject(packed_mutation(zlib.compress(b'x')),'one complete bounded'))


def bigger(g,f):
    packed=zlib.compress(b'x'*(g['EXECUTED_LATE_PIN'][0]+1))
    g['CANDIDATE_ZLIB_B64']=base64.b64encode(packed).decode()
    g['CANDIDATE_ZLIB_PIN']=(len(packed),hashlib.sha256(packed).hexdigest())


check('declared_decoded_budget_refused_even_with_test_only_matching_compressed_pin',lambda:reject(bigger,'one complete bounded'))
report={'schema':'hepta.explicit-reader-diagnostic.source-checks.v1',
 'state':'PASS_SOURCE_AND_PURE_DECODER_ONLY' if all(x['passed'] for x in checks) else 'FAIL_RETAIN_ORIGINALS',
 'source':dict(path=str(SOURCE),**pin(raw)),'parent':pin(parent),'checks':checks,
 'passed':sum(x['passed'] for x in checks),'total':len(checks),
 'target_runtime_module_compiled_or_executed':False,'main_invoked':False,
 'original_lifecycle_invoked':False,'remote_or_phone_operations':0,
 'optimized_phone_duration_measured':False,'clearance_or_case_credit':False}
body=(json.dumps(report,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
(OUT/'RESULT.json').write_bytes(body)
assert SOURCE.read_bytes()==raw
print(json.dumps(dict(path=str(OUT/'RESULT.json'),**pin(body),passed=report['passed'],total=report['total']),sort_keys=True))
if report['passed']!=report['total']:raise SystemExit(1)
