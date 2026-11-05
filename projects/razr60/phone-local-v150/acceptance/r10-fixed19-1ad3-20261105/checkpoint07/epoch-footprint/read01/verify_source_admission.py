#!/usr/bin/env python3
import ast
import base64
import hashlib
import json
from pathlib import Path
import zlib

BASE = Path('/workspace/scratch/1ad3d6f55439/epoch_footprint_observer_candidate01/delivery-final01/package')
OUT = Path('/workspace/scratch/1ad3d6f55439/actual_epoch_retained_footprint_read01')

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def functions(raw):
    lines = raw.splitlines(keepends=True)
    return {n.name:b''.join(lines[n.lineno-1:n.end_lineno]) for n in ast.parse(raw).body
            if isinstance(n,ast.FunctionDef)}

mfraw=(BASE/'SOURCE-MANIFEST.json').read_bytes()
assert len(mfraw)==4555 and sha(mfraw)=='11a14a83a1f15336ea468ea96698aea8b88a802818f9afed7f489049ea34d78b'
mf=json.loads(mfraw);names={'SOURCE-MANIFEST.json'}
for row in mf['files']:
    raw=(BASE/row['path']).read_bytes()
    assert row['path'] not in names and len(raw)==row['bytes'] and sha(raw)==row['sha256']
    names.add(row['path'])
assert names=={str(p.relative_to(BASE)) for p in BASE.rglob('*') if p.is_file()} and len(names)==24
source=(BASE/'source/observe_fixed_epoch_footprint_once.py').read_bytes()
assert len(source)==57213 and sha(source)=='2a3e0b1d40afdf8ce535975e5fdb7068bd0d4c56429f2d6492f755f441719b98'
caller=(BASE/'operator/P4-LAUNCHER.py').read_bytes()
assert len(caller)==123662 and sha(caller)=='380baa2c9d3547e9b48dbc2d5939b0a28340f497080de8e9fca4b9a477aa6a63'
cr=json.loads((BASE/'validation/CALLER-SOURCE-REVIEW.json').read_bytes())
old=Path(cr['parent']['path']).read_bytes()
assert sha(old)==cr['parent']['sha256'] and len(old)==cr['parent']['bytes']
inverse=caller
for row in sorted(cr['exact_seven_splices'],key=lambda r:r['new_start'],reverse=True):
    newpart=caller[row['new_start']:row['new_end']];oldpart=old[row['start']:row['end']]
    assert len(newpart)==row['new']['bytes'] and sha(newpart)==row['new']['sha256']
    assert len(oldpart)==row['old']['bytes'] and sha(oldpart)==row['old']['sha256']
    inverse=inverse[:row['new_start']]+oldpart+inverse[row['new_end']:]
assert inverse==old
sr=json.loads((BASE/'validation/SOURCE-DERIVATION.json').read_bytes())
parent=Path(sr['parent']['path']).read_bytes();assert sha(parent)==sr['parent']['sha256']
a,b=functions(parent),functions(source)
assert len(sr['unchanged_whole_functions'])==11 and all(a[n]==b[n] for n in sr['unchanged_whole_functions'])
values={n.targets[0].id:ast.literal_eval(n.value) for n in ast.parse(source).body
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)
        and n.targets[0].id in ('FOOTPRINT_PIN','FOOTPRINT_PACKET')}
packet=values['FOOTPRINT_PACKET'];compressed=base64.b64decode(packet['data'],validate=True)
assert {'bytes':len(compressed),'sha256':sha(compressed)}==packet['packed']
decoder=zlib.decompressobj();raw=decoder.decompress(compressed,packet['raw']['bytes']+1)
assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
assert raw==(BASE/'reference/FOOTPRINT.original.json').read_bytes()
assert len(raw)==176976 and sha(raw)==values['FOOTPRINT_PIN']['sha256']=='6bb6a8466bd8bcb2d7bb2aa6e376113d481dab27ca919a5f419fa19c07d0d40f'
values={n.targets[0].id:ast.literal_eval(n.value) for n in ast.parse(caller).body
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)
        and n.targets[0].id in ('PROBE','REQ')}
assert values['PROBE']==source
request_raw=(BASE/'operator/CONTROLLER-REQUEST.json').read_bytes()
assert len(request_raw)==127964 and sha(request_raw)=='ab2a3bc86f3ef7e3d8233fbbed31a78a870d1d681d091f708cbbca54f6dac818'
request=json.loads(request_raw)
assert request['stdin'].encode()==caller and request['host']=='pocket4' and 'timeout_seconds' not in request
req=json.loads((BASE/'operator/PHONE-REQUEST.original.json').read_bytes())
assert req==values['REQ'] and set(req)=={'kind','root','command','timeout_seconds'}
assert req['kind']=='shell' and req['root'] is True and req['timeout_seconds']==210
marker='FIXED_EPOCH_FOOTPRINT_2A3E'
head,body=req['command'].split("<<'"+marker+"'\n",1)
assert body.endswith('\n'+marker+'\n') and body[:-len(marker)-1].encode()==source
review_path=Path('/workspace/scratch/1ad3d6f55439/property_diagnostic/reviews/epoch-footprint-observer-independent01/REVIEW.json')
review_raw=review_path.read_bytes()
assert len(review_raw)==5490 and sha(review_raw)=='d8dff521a84e4f3113a3d3885b850794dfa700037606e625b5499c8c49589c36'
report={'schema':'hepta.epoch.footprint-root-source-admission.v1',
    'state':'EXACT_FIXED_READONLY_OBSERVER_AND_CALLER_REVIEWED_FOR_ONE_INVOCATION',
    'source':{'bytes':len(source),'sha256':sha(source)},'caller':{'bytes':len(caller),'sha256':sha(caller)},
    'request':{'bytes':len(request_raw),'sha256':sha(request_raw)},'source_members':24,
    'original_helpers_whole_equal':11,'caller_seven_splice_whole_inverse':True,
    'complete_footprint_body_exact':True,'phone_source_exact_heredoc_including_trailing_LF':True,
    'phone_readonly_observations_max':1,'new_case_nonce_or_lease':False,'outer_timeout':False,
    'owned_child_passive_wait_seconds':240,'phone_timeout_seconds':210,'shared_observer_seconds':30,
    'independent_review':{'path':str(review_path),'bytes':len(review_raw),'sha256':sha(review_raw)},
    'case_credit':False,'already_executed':False}
with (OUT/'ROOT-SOURCE-ADMISSION.json').open('x') as f:
    json.dump(report,f,sort_keys=True,indent=2);f.write('\n')
print(json.dumps(report,indent=2))
