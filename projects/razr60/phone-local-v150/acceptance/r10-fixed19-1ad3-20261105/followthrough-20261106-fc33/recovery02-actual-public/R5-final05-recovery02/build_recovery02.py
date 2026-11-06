#!/usr/bin/env python3
"""Bind one fixed parent reconciliation into unchanged finite recovery semantics."""
from pathlib import Path
import ast,base64,difflib,hashlib,json,lzma,shlex
D=Path(__file__).resolve().parent
OLD=D.parent/'R5-final05-recovery01'
OBS=D.parent/'R5-final05-parent-reconcile-probe02'
O=D/'candidate01';O.mkdir(exist_ok=True)
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
def pinned(p,n,h):
    b=p.read_bytes();assert (len(b),sha(b))==(n,h);return b
def put(name,b):
    p=O/name
    if p.exists():assert p.read_bytes()==b,'create-only candidate mismatch '+name
    else:p.write_bytes(b)
    return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
old_source=pinned(OLD/'candidate02/SOURCE.py',275947,'30172f90d4cd2cb3042a6c998a3e501d0eaba1ba3bf83bf1198a6fa19821a622')
target=pinned(OLD/'TARGETS.original.json',183176,'0aad40b0feac77b963547d90b27ed49eb260d3a2c14fd9a9dbfe4a61550597d1')
rec=pinned(OBS/'HOST-VERIFICATION.PUBLIC.original.json',72764,'3f07757cf054f697e2a81ad1ce0752c6e1aa5ca6a7b09488cb122363b76b038a')
cap=pinned(D.parent/'R5-final05-probe01/SOURCE.py',63646,'70c4dc710368da58f609208879f1fb83af5e0b428b712cfd31b8bced1907bc44')
reader=pinned(OBS/'import_parent_observer_host_v4.py',22485,'cebb4cbe8244826208c17011e1838a31c24349dc3dd3ce37cc3f2cae5c8c9d0d')
old_ext=pinned(OLD/'candidate02/recovery_extension.py',23959,'4e1d4053c73af74543a15beb03b536e45eb5f857e673bc2babc55502c8078f30')
projection=(D/'reconciliation_extension.py').read_bytes();ast.parse(projection)
g={'__name__':'complete_old_source_definitions_only'};exec(compile(old_source,'<original-reviewed-recovery01>','exec'),g)
g['RECONCILIATION_RAW']=rec;g['RECONCILIATION_SHA']=sha(rec)
exec(compile(projection,'<fixed-parent-projection>','exec'),g)
derived=g['derive_reconciled_targets'](json.loads(target),json.loads(rec));derived_raw=enc(derived);derived_sha=sha(derived_raw)
put('DERIVED-TARGETS.EXPECTATION-ONLY.json',derived_raw)
authority=json.loads((OLD/'candidate02/AUTHORITY.json').read_bytes())
reconciliation_pin={'path':'/home/alex/razr60-local-model-v150/fc33-final05-surviving-parents-readonly02-import03/HOST-VERIFICATION.PUBLIC.json',
 'bytes':len(rec),'sha256':sha(rec),'metadata':[66306,39846765,33152,1000,1000,1,72764,1793993617663384901,1793993617663384901]}
authority.update({'parent_reconciliation':reconciliation_pin,'derived_targets_sha256':derived_sha,
 'previous_rejected_recovery':{'path':'/home/alex/razr60-local-model-v150/operations/ng-fc33-final05-owned-scope-recovery01/result.json','bytes':1064600,'sha256':'383d96006dc169f9289a4ea39a8ee9b6e9944c33271f6a2c59916a0719e242bc',
     'metadata':[66306,59119865,33152,1000,1000,1,1064600,1793991681544552948,1793991681544552948]},
 'previous_rejected_request':{'path':'/home/alex/razr60-local-model-v150/requests/ng-fc33-final05-owned-scope-recovery01.json','bytes':43834,'sha256':'243f961660aab37fa2c8e7b23e6936379fabddc42d5304704b05907f30f8898a'},
 'reconciliation_host_verifier':{'bytes':len(reader),'sha256':sha(reader)},
 'reconciliation_does_not_authorize_foreign_cleanup':True,'derived_targets_are_expectation_only':True,'previous_rejected_namespace_must_not_be_replayed':True})
auth=enc(authority);put('AUTHORITY.json',auth)
ext=old_ext.decode()
a="'targets_sha256':TARGETS_SHA,'authority':AUTHORITY,"
b="'targets_sha256':TARGETS_SHA,'reconciliation_sha256':RECONCILIATION_SHA,'derived_targets_sha256':DERIVED_TARGETS_SHA,'authority':AUTHORITY,"
assert ext.count(a)==2;ext=ext.replace(a,b).encode();put('recovery_extension.py',ext)
patch=''.join(difflib.unified_diff(old_ext.decode().splitlines(True),ext.decode().splitlines(True),fromfile='recovery01-candidate02/recovery_extension.py',tofile='recovery02-candidate01/recovery_extension.py'))
put('EXTENSION.patch',patch.encode());put('RECONCILIATION.original.json',rec);put('reconciliation_extension.py',projection)
header='''#!/usr/bin/env python3
"""Separate recovery02 after known zero-effect rejection; no old request replay."""
import base64,errno,hashlib,json,os,signal,stat,sys,time,types,zlib
from pathlib import Path
'''
header+='CAP_SOURCE_RAW='+repr(cap)+'\n'
header+="assert len(CAP_SOURCE_RAW)==63646 and hashlib.sha256(CAP_SOURCE_RAW).hexdigest()=='70c4dc710368da58f609208879f1fb83af5e0b428b712cfd31b8bced1907bc44'\n"
header+="C=types.ModuleType('fc33_original_readonly_capture_70c4dc')\nC.__file__='<unchanged-reviewed-readonly-capture>'\nexec(compile(CAP_SOURCE_RAW,C.__file__,'exec'),C.__dict__)\n"
header+='TARGETS_RAW='+repr(target)+'\nTARGETS_SHA='+repr(sha(target))+'\nassert hashlib.sha256(TARGETS_RAW).hexdigest()==TARGETS_SHA\n'
header+='RECONCILIATION_RAW='+repr(rec)+'\nRECONCILIATION_SHA='+repr(sha(rec))+'\nassert hashlib.sha256(RECONCILIATION_RAW).hexdigest()==RECONCILIATION_SHA\n'
header+='RECONCILIATION=C.strict(RECONCILIATION_RAW)\nDERIVED_TARGETS_SHA='+repr(derived_sha)+'\n'
header+='AUTHORITY_RAW='+repr(auth)+'\nAUTHORITY=C.strict(AUTHORITY_RAW)\n'
header+="OPERATION_LABEL='ng-fc33-final05-owned-scope-recovery02'\n\n"
tail=b"\nTARGETS=derive_reconciled_targets(C.strict(TARGETS_RAW),RECONCILIATION)\nassert C.sha(C.encoded(TARGETS))==DERIVED_TARGETS_SHA\nif __name__=='__main__':raise SystemExit(cleanup_main())\n"
raw=header.encode()+projection+b'\n'+ext+tail;ast.parse(raw)
n={'__name__':'new_source_definitions_only'};exec(compile(raw,'<recovery02-pure-loading>','exec'),n)
assert n['C'].STATE is None and n['TARGETS']==derived and n['TARGETS_RAW']==target
files,dirs,parents=n['finite_plan']();assert len(files)==97 and len(dirs)==10 and len(parents)==5
sourcepin=put('SOURCE.py',raw)
xz=lzma.compress(raw,format=lzma.FORMAT_XZ,check=lzma.CHECK_CRC64,preset=6)
loader="import base64,hashlib,lzma\nc=base64.b64decode(%r,validate=True)\nassert len(c)==%d and hashlib.sha256(c).hexdigest()==%r\nd=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=32*1024*1024)\nr=d.decompress(c,max_length=%d)\nassert d.eof and not d.unused_data and len(r)==%d and hashlib.sha256(r).hexdigest()==%r\nexec(compile(r,'<fc33-final05-exact-owned-recovery02>','exec'),{'__name__':'__main__'})\n"%(base64.b64encode(xz).decode(),len(xz),sha(xz),len(raw)+1,len(raw),sha(raw))
old_request=json.loads((OLD/'candidate02/PHONE-REQUEST.json').read_bytes());argv=shlex.split(old_request['command'])
assert argv[-5:-1]==['/usr/bin/python3','-I','-B','-c']
command=shlex.join(argv[:-1]+[loader])+'\n';request=enc({'kind':'shell','root':True,'timeout_seconds':80,'command':command})
assert len(request)<=65535 and len(command.encode())<=65535
requestpin=put('PHONE-REQUEST.json',request);put('PHONE-COMMAND.sh',command.encode())
measure={'source_bytes':len(raw),'xz_bytes':len(xz),'xz_memlimit':33554432,'request_bytes':len(request),'command_bytes':len(command.encode()),'wire_cap':65535,'wire_headroom':65535-len(request)}
put('SOURCE-COMPRESSION.json',enc(measure))
oldmanifest=json.loads((OLD/'candidate02/MANIFEST.json').read_bytes())
old_bounds={k:v for k,v in oldmanifest['bounds'].items() if k not in ('zlib_compressed_bytes','xz_compressed_bytes')}
manifest={**oldmanifest,'state':'SEPARATE_RECONCILED_EXPECTATION_CANDIDATE_NO_PHONE_EXECUTION','source':sourcepin,'request':requestpin,
 'extension':{'bytes':len(ext),'sha256':sha(ext)},'projection':{'bytes':len(projection),'sha256':sha(projection)},'reconciliation':reconciliation_pin,
 'derived_targets_expectation':{'bytes':len(derived_raw),'sha256':derived_sha},'authority':{'bytes':len(auth),'sha256':sha(auth)},
 'p4_request_path':'/home/alex/razr60-local-model-v150/requests/ng-fc33-final05-owned-scope-recovery02.json',
 'operation_label':'ng-fc33-final05-owned-scope-recovery02','idempotency_key':'fc33-final05-owned-scope-recovery02',
 'bounds':{**old_bounds,**measure},'strict_same_parent_profile_for_absent_fixture':True,'original_targets_raw_unchanged':True,
 'finite_mutation_and_fresh_preflight_functions_unchanged':True,'only_core_extension_change':'two explicit provenance hashes in preflight and final envelope',
 'actual_dispatch':None,'actual_result':None,'independent_review':None,'pure_host_controls':None}
put('MANIFEST.json',enc(manifest))
print(json.dumps({'source':sourcepin,'request':requestpin,'derived_target_sha256':derived_sha,'measure':measure},sort_keys=True))
