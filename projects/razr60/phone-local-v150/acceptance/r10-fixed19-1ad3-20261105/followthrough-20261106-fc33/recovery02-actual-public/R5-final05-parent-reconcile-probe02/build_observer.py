#!/usr/bin/env python3
"""Construct one exact small read-only observer. No phone/publication action."""
from pathlib import Path
import ast,base64,hashlib,json,lzma,shlex
D=Path(__file__).resolve().parent
P=D.parent/'R5-final05-recovery01'
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
def put(name,b):
    p=D/name
    if p.exists():assert p.read_bytes()==b,'create-only source mismatch '+name
    else:p.write_bytes(b)
    return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
cap=(D.parent/'R5-final05-probe01/SOURCE.py').read_bytes();assert len(cap)==63646 and sha(cap)=='70c4dc710368da58f609208879f1fb83af5e0b428b712cfd31b8bced1907bc44'
target=(P/'TARGETS.original.json').read_bytes();assert len(target)==183176 and sha(target)=='0aad40b0feac77b963547d90b27ed49eb260d3a2c14fd9a9dbfe4a61550597d1'
t=json.loads(target);prefix='/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg02-a1055-final05-v150-'
files=[r for r in t['files'] if r['path'].startswith(prefix)]
files.sort(key=lambda r:int(r['path'].removeprefix(prefix).removesuffix('.xml')))
assert len(files)==11 and [r['path'] for r in files]==[prefix+str(i)+'.xml' for i in range(1,12)]
stage='/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-staging-r10-r1'
inputs={'schema':'hepta.fc33.final05.parent-reconciliation-inputs.v1','original_target':{'bytes':len(target),'sha256':sha(target)},
 'parent_identity_references':t['surviving_parents'],'reference_parent_times_and_names_are_not_admission':True,
 'xml_files':files,'fixture_path':'/proc/1/root/data/local/tmp/hepta-native-guard-9b37081161d7bcbc3adf76d2e6ec7841',
 'foreign_audit_paths':[stage+'/root-r10-neg01-74ec-final05.SECONDARY4-CLEANUP-INTENT-74ec02.json',stage+'/root-r10-neg01-74ec-final05.SECONDARY4-CLEANUP-RESULT-74ec02.json'],
 'reference_failure':{'path':'/home/alex/razr60-local-model-v150/operations/ng-fc33-final05-owned-scope-recovery01/result.json','bytes':1064600,'sha256':'383d96006dc169f9289a4ea39a8ee9b6e9944c33271f6a2c59916a0719e242bc'},
 'reference_failure_preflight':{'path':'/home/alex/razr60-local-model-v150/fc33-final05-recovery01-failure-analysis01/FRESH-PREFLIGHT.original.json','bytes':5683048,'sha256':'dc3b3d7abba577edec6d845169aa8f054064f035043164b12e558f4989393f86'},
 'mutation_authority_granted':False}
ir=enc(inputs);ip=put('INPUTS.json',ir)
header='''#!/usr/bin/env python3
"""Read exact parent profiles/XML/audit originals. Does not clean or retry recovery."""
import base64,errno,hashlib,json,os,signal,stat,sys,time,types,zlib
from pathlib import Path
'''
header+='CAP_SOURCE_RAW='+repr(cap)+'\n'
header+="assert len(CAP_SOURCE_RAW)==63646 and hashlib.sha256(CAP_SOURCE_RAW).hexdigest()=='70c4dc710368da58f609208879f1fb83af5e0b428b712cfd31b8bced1907bc44'\n"
header+="C=types.ModuleType('fc33_original_readonly_helpers_70c4dc')\nC.__file__='<unchanged-reviewed-readonly-helpers>'\nexec(compile(CAP_SOURCE_RAW,C.__file__,'exec'),C.__dict__)\n"
header+='INPUTS_RAW='+repr(ir)+'\nINPUTS_SHA='+repr(sha(ir))+'\nassert hashlib.sha256(INPUTS_RAW).hexdigest()==INPUTS_SHA\nINPUTS=C.strict(INPUTS_RAW)\n'
extension=(D/'observer_extension.py').read_bytes();raw=header.encode()+extension+b"\nif __name__=='__main__':raise SystemExit(observer_main())\n";ast.parse(raw);sp=put('SOURCE.py',raw)
xz=lzma.compress(raw,format=lzma.FORMAT_XZ,check=lzma.CHECK_CRC64,preset=6)
loader="import base64,hashlib,lzma\nc=base64.b64decode(%r,validate=True)\nassert len(c)==%d and hashlib.sha256(c).hexdigest()==%r\nd=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=32*1024*1024)\nr=d.decompress(c,max_length=%d)\nassert d.eof and not d.unused_data and len(r)==%d and hashlib.sha256(r).hexdigest()==%r\nexec(compile(r,'<fc33-final05-parent-readonly02>','exec'),{'__name__':'__main__'})\n"%(base64.b64encode(xz).decode(),len(xz),sha(xz),len(raw)+1,len(raw),sha(raw))
old=json.loads((P/'candidate02/PHONE-REQUEST.json').read_bytes());args=shlex.split(old['command']);assert args[-5:-1]==['/usr/bin/python3','-I','-B','-c']
command=shlex.join(args[:-1]+[loader])+'\n';request=enc({'kind':'shell','root':True,'timeout_seconds':50,'command':command});assert len(request)<=65535
rp=put('PHONE-REQUEST.json',request);put('PHONE-COMMAND.sh',command.encode())
manifest={'schema':'hepta.fc33.final05.parent-reconciliation-observer-plan.v1','state':'READONLY_SOURCE_READY_FOR_ROOT_REVIEW','source':sp,'inputs':ip,'request':rp,
 'extension':{'bytes':len(extension),'sha256':sha(extension)},'original_cap_source':{'bytes':len(cap),'sha256':sha(cap),'capture_or_main_called':False},
 'operation_label':'ng-fc33-final05-surviving-parents-readonly02','idempotency_key':'fc33-final05-surviving-parents-readonly02',
 'request_path':'/home/alex/razr60-local-model-v150/requests/ng-fc33-final05-surviving-parents-readonly02.json',
 'phone_actor':{'path':'/home/alex/razr60-local-model-v150/ops/phone_once.py','bytes':5652,'sha256':'179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'},
 'scope':{'parent_profiles':5,'xml_files':11,'foreign_audit_files':2,'fixture_absence':1,'windows':2,'held_existing_lock_groups':15,'held_lock_aliases':28},
 'bounds':{'source_bytes':len(raw),'xz_bytes':len(xz),'request_bytes':len(request),'wire_cap':65535,'stdout_cap':8388608,'raw_packet_cap':33554432,'body_seconds':30,'actor_timeout_seconds':50,'foreign_original_max_bytes_each':4194304},
 'phone_calls_by_builder':0,'file_deletes':0,'ui_calls':0,'native_dispatches':0,'all97_current_originals_proven':False,'all44_files_refreshed':False,'known_role_liveness_refreshed':False,
 'scope_closure':False,'deletion_authorized':False,'business_qualified':False,'component_qualified':False,'foreign_cleanup_success_inferred':False,
 'private_body_destination':'P4 private operation/result and host preservation only; no Git or chat body publication','actual_publication':None,'actual_dispatch':None,'actual_result':None}
put('MANIFEST.json',enc(manifest));print(json.dumps({'source':sp,'inputs':ip,'request':rp,'bounds':manifest['bounds']},sort_keys=True))
