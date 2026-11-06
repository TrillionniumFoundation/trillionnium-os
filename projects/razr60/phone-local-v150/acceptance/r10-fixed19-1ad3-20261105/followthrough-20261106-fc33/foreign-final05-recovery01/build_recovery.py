#!/usr/bin/env python3
"""Bind existing reviewed originals into a single recovery request; never dispatch."""
from pathlib import Path
import ast,base64,hashlib,json,lzma,shlex,zlib
D=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
def pinned(path,size,digest):
    b=path.read_bytes();assert (len(b),sha(b))==(size,digest);return b
def put(name,b):
    p=D/name
    if p.exists():assert p.read_bytes()==b,'create-only candidate mismatch '+name
    else:p.write_bytes(b)
    return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
cap=pinned(D.parent/'R5-final05-probe01/SOURCE.py',63646,'70c4dc710368da58f609208879f1fb83af5e0b428b712cfd31b8bced1907bc44')
target=pinned(D/'TARGETS.original.json',183176,'0aad40b0feac77b963547d90b27ed49eb260d3a2c14fd9a9dbfe4a61550597d1')
preserve=pinned(D/'PRESERVATION.original.json',39397,'c9b92b2ff119466d95ba5b32ef99e009616e319385b064cb63433c83b863afcf')
t=json.loads(target);p=json.loads(preserve)
authority={'schema':'hepta.fc33.final05.exact-recovery-authority.v1','scope_report':t['scope_report'],'scope_packet':t['scope_packet'],'xml_report':t['xml_report'],
 'sender_private_preservation':t['sender_private_preservation'],'sender_terminal_proof':t['sender_terminal_proof'],
 'targets':{'path':'/home/alex/razr60-local-model-v150/fc33-final05-recovery-inputs01/TARGETS.json','bytes':len(target),'sha256':sha(target),
    'metadata':[66306,39846600,33152,1000,1000,1,183176,1793990364709986368,1793990364709986368]},
 'preservation':{'path':'/home/alex/razr60-local-model-v150/fc33-final05-recovery-inputs01/PRESERVATION.json','bytes':len(preserve),'sha256':sha(preserve)},
 'recovery_authorization_is_separate_from_business_request':True,'component_or_business_credit':False,'old_request_replay':False,
 'host_preservation_recheck_required_before_dispatch':True}
auth=enc(authority);put('AUTHORITY.json',auth)
header='''#!/usr/bin/env python3
"""One finite failed-scope recovery. Root dispatches once after independent review."""
import base64,errno,hashlib,json,os,signal,stat,sys,time,types,zlib
from pathlib import Path
'''
header+='CAP_SOURCE_RAW='+repr(cap)+'\n'
header+="assert len(CAP_SOURCE_RAW)==63646 and hashlib.sha256(CAP_SOURCE_RAW).hexdigest()=='70c4dc710368da58f609208879f1fb83af5e0b428b712cfd31b8bced1907bc44'\n"
header+="C=types.ModuleType('fc33_original_readonly_capture_70c4dc')\nC.__file__='<unchanged-reviewed-readonly-capture>'\nexec(compile(CAP_SOURCE_RAW,C.__file__,'exec'),C.__dict__)\n"
header+='TARGETS_RAW='+repr(target)+'\nTARGETS_SHA='+repr(sha(target))+'\nassert hashlib.sha256(TARGETS_RAW).hexdigest()==TARGETS_SHA\nTARGETS=C.strict(TARGETS_RAW)\n'
header+='AUTHORITY_RAW='+repr(auth)+'\nAUTHORITY=C.strict(AUTHORITY_RAW)\n'
header+="OPERATION_LABEL='ng-fc33-final05-owned-scope-recovery01'\n\n"
extension=(D/'recovery_extension.py').read_bytes();raw=header.encode()+extension+b"\nif __name__=='__main__':raise SystemExit(cleanup_main())\n"
ast.parse(raw);sourcepin=put('SOURCE.py',raw)
z=zlib.compress(raw,9);xz=lzma.compress(raw,format=lzma.FORMAT_XZ,check=lzma.CHECK_CRC64,preset=6)
# One declared XZ representation. There is no runtime fallback/retry codec.
payload="import base64,hashlib,lzma\nc=base64.b64decode(%r,validate=True)\nassert len(c)==%d and hashlib.sha256(c).hexdigest()==%r\nd=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=32*1024*1024)\nr=d.decompress(c,max_length=%d)\nassert d.eof and not d.unused_data and len(r)==%d and hashlib.sha256(r).hexdigest()==%r\nexec(compile(r,'<fc33-final05-exact-owned-recovery>','exec'),{'__name__':'__main__'})\n"%(base64.b64encode(xz).decode(),len(xz),sha(xz),len(raw)+1,len(raw),sha(raw))
old=json.loads((D.parent/'R5-final05-xml-probe01/PHONE-REQUEST.json').read_bytes());parts=shlex.split(old['command'])
assert parts[-5:-1]==['/usr/bin/python3','-I','-B','-c'] and not any('/su' in v for v in parts[:-1])
command=shlex.join(parts[:-1]+[payload])+'\n'
request=enc({'kind':'shell','root':True,'timeout_seconds':80,'command':command})
assert len(request)<=65535 and len(command.encode())<=65535,'wire cap before publication'
requestpin=put('PHONE-REQUEST.json',request);put('PHONE-COMMAND.sh',command.encode())
measure={'source_bytes':len(raw),'zlib_compressed_bytes':len(z),'xz_compressed_bytes':len(xz),'chosen_codec':'xz','xz_decompression_memlimit':33554432,'command_bytes':len(command.encode()),'request_bytes':len(request),'wire_cap':65535,'wire_headroom':65535-len(request)}
put('SOURCE-COMPRESSION.json',enc(measure))
manifest={'schema':'hepta.fc33.final05.exact-recovery-plan.v1','state':'HOST_BOUND_CANDIDATE_NO_PHONE_EXECUTION',
 'source':sourcepin,'request':requestpin,'extension':{'bytes':len(extension),'sha256':sha(extension)},'targets':authority['targets'],'authority':{'bytes':len(auth),'sha256':sha(auth)},
 'p4_request_path':'/home/alex/razr60-local-model-v150/requests/ng-fc33-final05-owned-scope-recovery01.json',
 'operation_label':'ng-fc33-final05-owned-scope-recovery01','idempotency_key':'fc33-final05-owned-scope-recovery01',
 'p4_actor':{'path':'/home/alex/razr60-local-model-v150/ops/phone_once.py','bytes':5652,'sha256':'179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'},
 'reused_original_capture':{'bytes':len(cap),'sha256':sha(cap),'new_module_original_globals':True,'main_called':False,'capture_called_only_by_root_recovery':True},
 'scope':{'files':97,'private_files':82,'transport_files':4,'sender_XML_files':11,'directories':10,'target_file_bytes':sum(r['bytes'] for r in t['files']),'original_blob_count':88,'surviving_parent_aliases':5},
 'bounds':{**measure,'body_seconds':55,'phone_timeout_seconds':80,'output_bytes':8388608,'original_capture_read_bytes':167772160,
           'additional_exact_post_read_bytes':44353573+sum(r['bytes'] for r in t['files'])+131072},
 'no_new_business_request':True,'phone_calls_by_builder':0,'cleanup_executed':False,'component_qualified':False,'business_qualified':False,
 'actual_dispatch':None,'actual_result':None,'independent_review':None,'pure_host_controls':None,
 'required_before_root_dispatch':['Exact public TARGETS/PRESERVATION and all private P4 original files re-read under canonical full9 bookends','Independent source review and finite negative controls','Root reviews final exact source/request/data pins and uniquely dispatches; no replay after UNKNOWN']}
put('MANIFEST.json',enc(manifest));print(json.dumps({'source':sourcepin,'request':requestpin,'measure':measure},sort_keys=True))
