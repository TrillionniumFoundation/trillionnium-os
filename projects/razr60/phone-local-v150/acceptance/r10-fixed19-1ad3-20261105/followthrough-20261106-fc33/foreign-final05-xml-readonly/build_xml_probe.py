#!/usr/bin/env python3
"""Build a finite read-only XML request; no phone or publication action."""
from pathlib import Path
import ast,base64,hashlib,json,shlex,zlib
D=Path(__file__).resolve().parent
P=D.parent/'R5-final05-probe01'
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
def put(n,b):
    p=D/n
    if p.exists():assert p.read_bytes()==b
    else:p.write_bytes(b)
def pin(n):
    b=(D/n).read_bytes();return {'path':str(D/n),'bytes':len(b),'sha256':sha(b)}
public=(P/'SENDER-XML-EXPECTED-PUBLIC.json').read_bytes()
assert len(public)==11024 and sha(public)=='1fbd5617faca1b85a47318a87b30578fe18111bb9db4129d85740aa3848de0cf'
original=json.loads(public);rows=original['rows'];assert len(rows)==11 and [r['sequence'] for r in rows]==list(range(1,12))
for r in rows:
    assert r['root_path']=='/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg02-a1055-final05-v150-'+str(r['sequence'])+'.xml'
    assert r['expected_bytes']<=262144 and r['recorded_phone_rc']==0
inputs={'schema':'hepta.fc33.final05.xml-readonly-inputs.v1','source_public_manifest':{'bytes':len(public),'sha256':sha(public)},
 'sender_private_originals':original['private_preservation'],
 'rows':[{k:r[k] for k in ('root_path','sequence','expected_bytes','expected_sha256','pin_basis','command_source')} for r in rows]}
inputraw=enc(inputs);put('INPUTS.json',inputraw)
header='''#!/usr/bin/env python3
"""Read the eleven exact sender-owned XML paths, never create/dump/UI/clean them."""
import base64,errno,hashlib,json,os,signal,stat,sys,time,zlib
from pathlib import Path
'''
header+='INPUTS_RAW='+repr(inputraw)+'\nINPUTS_SHA='+repr(sha(inputraw))+'\nINPUTS=json.loads(INPUTS_RAW)\nassert hashlib.sha256(INPUTS_RAW).hexdigest()==INPUTS_SHA\n'
header+="BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'\nLABEL='root-r10-neg02-a1055-final05'\nNONCE='9b37081161d7bcbc3adf76d2e6ec7841'\nPARENT='/proc/1/root/data/local/tmp'\nEXPECTED_PATHS={r['root_path'] for r in INPUTS['rows']}\nassert len(EXPECTED_PATHS)==11\nMAX_FILE=262144\nMAX_READ=8*1024*1024\nSTATE=None\n\n"
raw=(header+(D/'xml_probe_extension.py').read_text()).encode();compile(raw,'<readonly-xml>','exec');put('SOURCE.py',raw)
compressed=zlib.compress(raw,9)
payload="import base64,hashlib,zlib\nc=base64.b64decode(%r,validate=True)\nassert len(c)==%d and hashlib.sha256(c).hexdigest()==%r\nd=zlib.decompressobj();r=d.decompress(c,%d)\nassert d.eof and not d.unused_data and not d.unconsumed_tail\nassert len(r)==%d and hashlib.sha256(r).hexdigest()==%r\nexec(compile(r,'<fc33-final05-exact-xml-readonly>','exec'),{'__name__':'__main__'})\n"%(base64.b64encode(compressed).decode(),len(compressed),sha(compressed),len(raw)+1,len(raw),sha(raw))
old=json.loads((P/'PHONE-REQUEST.json').read_bytes());outer=shlex.split(old['command']);inner=shlex.split(outer[2])
assert inner[-5:-1]==['/usr/bin/python3','-I','-B','-c']
command=shlex.join(inner[:-1]+[payload])+'\n' # actor root=True supplies the one outer su layer.
request=enc({'kind':'shell','root':True,'timeout_seconds':30,'command':command});assert len(request)<=65535
put('PHONE-REQUEST.json',request);put('PHONE-COMMAND.sh',command.encode())
manifest={'schema':'hepta.fc33.final05.xml-readonly-plan.v1','state':'REVIEWABLE_SOURCE_NOT_DISPATCHED',
 'source':pin('SOURCE.py'),'inputs':pin('INPUTS.json'),'request':pin('PHONE-REQUEST.json'),
 'operation_label':'ng-fc33-final05-owned-xml-readonly01','idempotency_key':'fc33-final05-owned-xml-readonly01',
 'request_path':'/home/alex/razr60-local-model-v150/requests/ng-fc33-final05-owned-xml-readonly01.json',
 'actor':{'path':'/home/alex/razr60-local-model-v150/ops/phone_once.py','bytes':5652,'sha256':'179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'},
 'finite_path_count':11,'source_sender_file_count':144,'full_windows':2,'glob_or_prefix_read_authorization':False,
 'xml_body_output':'private P4 operation/result packet only; never publish to Git or chat',
 'existing_XML_behavior':'read all bytes/full9/label and require exact original UTF-8 stdout-suffix hash; preserve changed bytes as UNKNOWN',
 'missing_XML_behavior':'bookended ENOENT only, no inference of historical cleanup or effect',
 'deadline_seconds':20,'actor_timeout_seconds':30,'wire_cap':65535,'stdout_cap':8388608,
 'phone_calls_by_builder':0,'ui_calls':0,'deletion_authorized':False,'scope_closure':False,
 'remaining_conditions':['original sender host child join and synchronous remote actor terminal must be independently bound',
 'this supplement does not refresh the original44/private home or role liveness; any later recovery must recheck every exact target and role under locks before mutation',
 'full XML/body preservation and public hash-only reader result must finish before any recovery decision'],
 'actual_publication':None,'actual_dispatch':None,'actual_result':None}
put('MANIFEST.json',enc(manifest));print(json.dumps({'source':manifest['source'],'inputs':manifest['inputs'],'request':manifest['request'],'phone_calls':0}))
