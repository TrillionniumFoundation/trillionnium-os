#!/usr/bin/env python3
"""Host admission and exact bounded requests for physical NEG04/05/07."""
import ast,base64,copy,gzip,hashlib,json,os,re,shlex,stat,sys,time,types,zlib
from pathlib import Path
B=Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
BASE='/var/lib/trillionnium/owner-open/phone-local-v150'
P4='/home/alex/razr60-local-model-v150'
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
MAX_ORIGINAL=64*1024*1024
FINAL_DEPENDENCIES=None
CASE_IDS=('NEG-04','NEG-05','NEG-07')
SENDER_PIN=(41355, 'f90c6ffbf3278b22bf3a48bf055c5ca1cf43c3073c5cc7a852dd09a4cf2eab73')
CAPTURE_PIN=(29065,'f12a251542894d0e8c0dedc9d62eb96d4f39e2b1d563f849c2f60e6ee02580e3')
PROTOCOL_PIN=(37318,'c573959e59fd9fbe7a850d6d2d6d747e3135718493f15de4a8acde850bad93b0')
def need(value,message):
    if not value:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def enc(value):
    return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()

def strict(raw):
    def pairs(rows):
        result={}
        for key,value in rows:
            need(key not in result,'duplicate JSON key')
            result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))

def desc(path,raw):
    return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}

def b64(raw):
    return base64.b64encode(raw).decode()

def decode(value,maximum):
    need(isinstance(value,str) and len(value)<=4*((maximum+2)//3),'bounded base64 string required')
    raw=base64.b64decode(value,validate=True)
    need(len(raw)<=maximum and b64(raw)==value,'canonical bounded base64 required')
    return raw

class Originals:
    def __init__(self):
        self.seen={}
    def read(self,row,maximum=MAX_ORIGINAL):
        need(type(row) is dict and set(row)=={'path','bytes','sha256'} and type(row['bytes']) is int
            and 0<=row['bytes']<=maximum and isinstance(row['sha256'],str)
            and re.fullmatch('[0-9a-f]{64}',row['sha256']),'exact bounded descriptor required')
        p=Path(row['path'])
        need(p.is_absolute() and '..' not in p.parts and p.resolve(strict=True)==p,'canonical original required')
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            before=os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==row['bytes'],
                'single-link regular original differs')
            with os.fdopen(fd,'rb',closefd=False) as stream:
                raw=stream.read(row['bytes']+1)
            metadata=tuple(getattr(before,k) for k in META)
            need(len(raw)==row['bytes'] and sha(raw)==row['sha256'] and
                metadata==tuple(getattr(os.fstat(fd),k) for k in META)
                ==tuple(getattr(p.lstat(),k) for k in META),'original bytes or identity changed')
        finally:
            os.close(fd)
        record={'descriptor':copy.deepcopy(row),'metadata':metadata}
        need(str(p) not in self.seen or self.seen[str(p)]==record,'original changed across reads')
        self.seen[str(p)]=record
        return raw
    def known(self,path,maximum=MAX_ORIGINAL):
        p=Path(path)
        need(p.is_absolute() and p.resolve(strict=True)==p,'canonical discovered original required')
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            before=os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=maximum,
                'bounded discovered regular original required')
            with os.fdopen(fd,'rb',closefd=False) as stream:
                raw=stream.read(before.st_size+1)
            metadata=tuple(getattr(before,k) for k in META)
            need(len(raw)==before.st_size and metadata==tuple(getattr(os.fstat(fd),k) for k in META)
                ==tuple(getattr(p.lstat(),k) for k in META),'discovered original changed')
        finally:
            os.close(fd)
        row=desc(p,raw)
        record={'descriptor':row,'metadata':metadata}
        need(str(p) not in self.seen or self.seen[str(p)]==record,'discovered original changed across reads')
        self.seen[str(p)]=record
        return row,raw
    def recheck(self):
        for record in list(self.seen.values()):
            self.read(record['descriptor'])

def relative(name):
    p=Path(name)
    need(isinstance(name,str) and str(p)==name and not p.is_absolute()
        and '..' not in p.parts and name not in ('','.'),'canonical relative member required')
    return p

def module(raw,path,name):
    m=types.ModuleType(name)
    m.__file__=str(path)
    m.__reviewed_source_sha256__=sha(raw)
    exec(compile(raw,str(path),'exec'),m.__dict__)
    return m

def load_members(originals,row,field='files'):
    raw=originals.read(row,262144)
    mf=strict(raw)
    rows=mf[field]
    need(type(rows) is list and 1<=len(rows)<=128 and len({r['path'] for r in rows})==len(rows),
        'bounded unique complete manifest required')
    need(all(type(r) is dict and type(r.get('bytes')) is int and 0<=r['bytes']<=32*1024*1024 for r in rows)
         and sum(r['bytes'] for r in rows)<=32*1024*1024,'complete_source_package_32MiB_budget')
    root=Path(row['path']).parent
    bodies={}
    for member in rows:
        need(type(member) is dict and set(member)=={'path','bytes','sha256'},'exact manifest row required')
        name=member['path']
        bodies[name]=originals.read({'path':str(root/relative(name)),
            'bytes':member['bytes'],'sha256':member['sha256']})
    return mf,bodies


def final_dependencies():
    value=FINAL_DEPENDENCIES
    fields={'fault_package_sha256','active_source_sha256','runtime_package_sha256',
        'consumer_sha256','readiness_sha256','policy_adoption_sha256','combination_sha256','live_policy'}
    need(type(value) is dict and set(value)==fields,'future_actual_fault_dependencies_are_unfrozen')
    need(all(type(value[k]) is str and re.fullmatch('[0-9a-f]{64}',value[k])
        for k in fields-{'live_policy'}),'actual_final_dependency_hashes')
    policy=value['live_policy']
    need(type(policy) is dict and set(policy)=={'bytes','sha256'} and type(policy['bytes']) is int and
         0<policy['bytes']<=16*1024*1024 and re.fullmatch('[0-9a-f]{64}',policy['sha256']),
         'actual_exported_policy_descriptor_required')
    return value


def literal(raw,name):
    rows=[n.value for n in ast.parse(raw).body if isinstance(n,ast.Assign) and len(n.targets)==1
        and isinstance(n.targets[0],ast.Name) and n.targets[0].id==name]
    need(len(rows)==1,'one_reviewed_literal_'+name)
    return ast.literal_eval(rows[0])


def generation_inputs(plan,originals):
    """Check exact source relationships; independent adoption is a prerequisite."""
    runtime,unused=load_members(originals,plan['runtime_package'])
    consumer=originals.read(plan['consumer'],4*1024*1024)
    readiness=originals.read(plan['readiness'],4*1024*1024)
    policy=originals.read(plan['actual_policy'],16*1024*1024)
    adoption_raw=originals.read(plan['policy_adoption'],16*1024*1024)
    adoption=strict(adoption_raw)
    need(runtime.get('revision')=='r10-r1-fc33-native-bound-v3-r6' and len(runtime['files'])==38 and
         runtime.get('actual_combination_generated') is True and
         runtime.get('current_policy_sha256')==sha(policy) and
         runtime.get('current_combination_sha256')==plan['combination_sha256'] and
         runtime.get('explicit_policy_adoption_sha256')==plan['policy_adoption']['sha256'],
         'actual_reviewed_R6_runtime_manifest_generation')
    need(literal(consumer,'PACKAGE_SHA')==plan['runtime_package']['sha256'] and
         literal(consumer,'CURRENT_POLICY_SHA')==sha(policy) and
         literal(consumer,'CURRENT_POLICY_ADOPTION_SHA')==plan['policy_adoption']['sha256'] and
         literal(readiness,'BOUNDARY_CONSUMER_SHA256')==sha(consumer),
         'actual_consumer_and_readiness_source_relationships')
    need(adoption.get('schema')=='hepta.parent-dir.policy-adoption.v1' and
         adoption.get('release_id')=='v150-parent-dir-getattr-r1' and adoption.get('boot_id')==BOOT and
         adoption.get('actual_export')==plan['actual_policy'],'actual_current_parent_dir_adoption_descriptor_relationship')
    # The current consumer pins the complete file-callback-only adoption
    # verifier. Its exact proof validates the retained parent, complete rule,
    # one declared getattr delta, actual live capture and full post-live proof.
    # This is the same API used by that consumer, never a schema union or a
    # fabricated top-level list of the old generation's permission atoms.
    verifier_sha=literal(consumer,'POLICY_VERIFIER_SHA')
    verifier_bytes=literal(consumer,'POLICY_VERIFIER_BYTES')
    need(type(verifier_sha)is str and re.fullmatch('[0-9a-f]{64}',verifier_sha) and
         type(verifier_bytes)is int and 0<verifier_bytes<=131072,'exact_current_adoption_verifier_source_pin')
    matches=[row for row in adoption['verification_originals'] if type(row)is dict and
             row.get('sha256')==verifier_sha and row.get('bytes')==verifier_bytes]
    need(len(matches)==1,'one_current_consumer_reviewed_adoption_verifier_original')
    verifier_raw=originals.read(matches[0],131072)
    need(len(verifier_raw)==verifier_bytes and sha(verifier_raw)==verifier_sha,
         'complete_current_adoption_verifier_original')
    verifier=module(verifier_raw,matches[0]['path'],'negative_current_policy_adoption')
    summary=verifier.verify_adoption(adoption_raw,read_pinned=originals.read)
    need(summary['current_adoption_sha256']==sha(adoption_raw)==plan['policy_adoption']['sha256'] and
         summary['runtime_policy']=={'bytes':len(policy),'sha256':sha(policy)} and
         summary['full_rule']==adoption['full_rule'] and
         summary['root_scope_decision_sha256']==literal(consumer,'CURRENT_SCOPE_DECISION_SHA'),
         'actual_current_adoption_complete_proof_matches_consumer_and_export')
    need(summary['root_decision']==adoption['root_decision'] and
         summary['current_policy_adoption']['schema']=='hepta.parent-dir.policy-adoption.v1' and
         summary['current_policy_adoption']['boot_id']==BOOT and
         summary['service_start_admitted']is False and summary['component_qualified']is False and
         type(summary['phone_calls'])is int and summary['phone_calls']==0 and
         type(summary['policy_writes'])is int and summary['policy_writes']==0,
         'strict_actual_adoption_verification_does_not_grant_runtime_admission')
    return runtime


def admit(plan,originals,files):
    final=final_dependencies()
    fields={'schema','case_id','label','nonce','out','watch_plan','fault_package','runtime_package',
        'consumer','readiness','policy_adoption','actual_policy','combination_sha256','sender_source',
        'sender_inputs','configuration','service'}
    need(type(plan) is dict and set(plan)==fields and plan['schema']=='hepta.physical-fault.root-plan.v1'
        and plan['case_id'] in CASE_IDS and re.fullmatch('[0-9a-f]{32}',plan['nonce'])
        and re.fullmatch('[a-z0-9][a-z0-9-]{5,69}',plan['label']),'fixed_physical_fault_plan')
    need(plan['out']==str(B/'physical-faults-r10-r1'/plan['label']) and
        plan['combination_sha256']==final['combination_sha256'],'actual_case_namespace_and_combination')
    generation_inputs(plan,originals)
    for name,key in (('fault_package','fault_package_sha256'),('runtime_package','runtime_package_sha256'),
        ('consumer','consumer_sha256'),('readiness','readiness_sha256'),('policy_adoption','policy_adoption_sha256')):
        need(plan[name]['sha256']==final[key],'actual_final_dependency_'+name)
        originals.read(plan[name],16*1024*1024)
    policy_raw=originals.read(plan['actual_policy'],16*1024*1024)
    need({k:plan['actual_policy'][k] for k in ('bytes','sha256')}==final['live_policy'],
         'actual_exported_policy_bytes')
    adoption=strict(originals.read(plan['policy_adoption'],16*1024*1024))
    need(adoption.get('schema')=='hepta.parent-dir.policy-adoption.v1' and
         adoption.get('release_id')=='v150-parent-dir-getattr-r1' and
         adoption.get('actual_export')==plan['actual_policy'] and
         adoption.get('root_decision',{}).get('schema')=='hepta.root.parent-dir.actual-policy-adoption-decision.v1' and
         adoption['root_decision'].get('decision')=='ADOPT_INDEPENDENTLY_VERIFIED_ACTUAL_EXPORTED_POLICY' and
         adoption['root_decision'].get('actual_policy_sha256')==plan['actual_policy']['sha256'],
         'actual_current_parent_dir_adoption_descriptor_relationship')
    fault,fb=load_members(originals,plan['fault_package'],'runtime_sources')
    need(fault.get('schema')=='hepta.r10.signal-fault-package.v1' and len(fb)==8 and
         sha(fb['source/active_runtime_r10.py'])==final['active_source_sha256'] and
         sha(fb['source/signal_fault_once_r10.py'])=='cd5100c0f12dc77b275a55893aa31fdc7d6b5ec61839635b70c0c9a11f0cbb1e',
         'exact_final_fault_operator_package')
    need(sha(files['source/owned_capture.py'])==CAPTURE_PIN[1] and
         len(files['source/owned_capture.py'])==CAPTURE_PIN[0],'unchanged_owned_capture_source')
    sender=originals.read(plan['sender_source'],65536)
    need((len(sender),sha(sender))==SENDER_PIN and
         plan['sender_source']['path']==str(B/'send_new_native_task_r5_fc33_r6.py'),'unchanged_production_sender')
    watch_raw=originals.read(plan['watch_plan'],65536);watch=strict(watch_raw)
    W=module(files['source/watch_physical_fault_once.py'],'watch_physical_fault_once.py','fault_watch_admission')
    owner=W.validate_plan(watch)
    need(watch['case_id']==plan['case_id'] and watch['nonce']==plan['nonce'] and watch['sender_label']==plan['label']
        and watch['fault_package_sha256']==final['fault_package_sha256'] and watch['expected_boot']==BOOT,
         'actual_watch_case_inputs')
    expected_watch={k:v for k,v in final.items() if k not in ('combination_sha256','live_policy')}
    expected_watch['live_policy_sha256']=final['live_policy']['sha256']
    need(W.FINAL_DEPENDENCIES==expected_watch,'watch_source_final_dependencies')
    inputs=plan['sender_inputs']
    need(type(inputs) is dict and set(inputs)=={'request','previous','preserved_draft','retirement_resolution',
        'registration_result'},'unchanged_sender_input_fields')
    need(originals.read(inputs['request'],16000)==owner,'sender_owner_is_exact_registered_watch_owner')
    previous=strict(originals.read(inputs['previous'],262144))
    need(previous['identity']==watch['previous_scope'] and
         previous.get('terminal',{}).get('status') in ('completed','provider_failed','cancelled'),
         'actual_closed_previous_selection')
    draft=strict(originals.read(inputs['preserved_draft'],262144))
    original_draft=decode(draft['exact_utf8_b64'],16000)
    need(original_draft and original_draft!=owner and sha(original_draft)==draft['utf8_sha256'],
         'exact_nonempty_preserved_draft')
    originals.read(inputs['retirement_resolution'],4*1024*1024)
    registration=strict(originals.read(inputs['registration_result'],4*1024*1024))
    need(registration.get('rc')==0 and registration.get('unconsumed_template_read_back') is True and
         registration.get('request_sha256')==sha(owner),'actual_unconsumed_registration_original')
    for name,pin in (('configuration','5ff00467e8432d7119ba72a700ce07cb20f16555d3dc0c90de7cbfc388103f48'),
                      ('service','273db17098e5de6c67ded208e120e3910531ab1c7a778faa76824d453ddddd58')):
        need(sha(originals.read(plan[name],262144))==pin,'current_shared_material_'+name)
    bundle={'manifest_b64':b64(originals.read(plan['fault_package'],262144)),
        'sources':{name:b64(raw) for name,raw in fb.items()}}
    # This is a pure bundle load: it imports the pinned functions but does not
    # enter installed()/current() or perform any phone observation on this host.
    A,_=W.load_actor(bundle,expected_watch)
    A.active.validate_runtime_binding(watch['runtime_binding'],watch['expected_boot'])
    A.active.validate_task_expectations(watch,owner)
    if watch['case_id']=='NEG-04':
        need(all(watch[k] is None for k in ('expected_probe_component','android_shell_exe','android_shell_sha256','busybox_sha256')),
             'predispatch_fault_has_no_probe_or_helper')
    else:
        need(watch['expected_probe_component'] in A.PROBES and watch['android_shell_exe']==A.STOCK_SHELL and
             watch['android_shell_sha256']==A.STOCK_SHELL_SHA and
             watch['busybox_sha256']==(A.STOCK_BUSYBOX_SHA if watch['case_id']=='NEG-05' else None),
             'exact_original_probe_and_readonly_helper_fields')
        need(any(A.projection.component(row['component'])==watch['expected_probe_component']
             for row in watch['app_scope']['apps']),'probe_in_exact_registered_scope')
    need(A.active.role_rows(strict(decode(watch['runtime_binding']['readiness']['raw_b64'],32768)))==watch['roles'],
         'watch_roles_are_actual_registered_READY')
    originals.recheck()
    return {'final':final,'watch':watch,'watch_raw':watch_raw,'owner':owner,
            'operator_bundle':bundle,'operator_sources':fb,'fault_manifest':fault}


def python_request(program,timeout):
    command='/data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -I -B -c '+shlex.quote(program)
    wire=('shell,v2,raw:/debug_ramdisk/su -c '+shlex.quote(command)).encode()
    need(len(wire)<65536,'unchanged_exclusive_ADB_wire_budget')
    return {'kind':'shell','root':True,'timeout_seconds':timeout,'command':command}


def p4_plan_stage_program(inp,body_sha):
    need(re.fullmatch(re.escape(P4+'/fault-p4-capture-inputs-r1/')+'[0-9a-f]{32}',inp)
        and re.fullmatch('[0-9a-f]{64}',body_sha),'fixed_P4_capture_plan_stage')
    code="import os,sys,hashlib\nfrom pathlib import Path\nr=Path("+repr(inp)+");os.umask(0o077)\n"
    code+="if not r.parent.exists():r.parent.mkdir(mode=0o700)\nassert r.parent.resolve(strict=True)==r.parent\nr.mkdir(mode=0o700)\nb=sys.stdin.buffer.read(65537)\nassert len(b)<=65536 and hashlib.sha256(b).hexdigest()=="+repr(body_sha)+"\nf=os.open(r/'PLAN.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\nwith os.fdopen(f,'wb') as s:s.write(b);s.flush();os.fsync(s.fileno())\nf=os.open(r,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(f);os.close(f)\nprint('STAGED_EXACT_PLAN_NO_PHONE')\n"
    return code


def p4_archive_chunk_program(archive,index):
    need(type(archive) is dict and set(archive)=={'path','bytes','sha256'} and
         re.fullmatch(re.escape(P4+'/fault-p4-original-captures-r1/')+'[0-9a-f]{32}/ORIGINALS.tar.gz',archive['path'])
         and type(archive['bytes']) is int and 0<archive['bytes']<=64*1024*1024 and
         re.fullmatch('[0-9a-f]{64}',archive['sha256']) and type(index) is int and
         0<=index<128 and index*524288<archive['bytes'],'fixed_bounded_P4_archive_chunk')
    code="import os,hashlib,json,base64,stat\nfrom pathlib import Path\np=Path("+repr(archive['path'])+");assert p.resolve(strict=True)==p\nf=os.open(p,os.O_RDONLY|os.O_NOFOLLOW);a=os.fstat(f)\n"
    code+="try:\n assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size=="+repr(archive['bytes'])+"\n os.lseek(f,"+str(index*524288)+",0);parts=[];total=0\n while total<524288:\n  b=os.read(f,524288-total)\n  if not b:break\n  parts.append(b);total+=len(b)\n b=b''.join(parts);z=os.fstat(f);n=p.lstat()\n names=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')\n assert tuple(getattr(a,k) for k in names)==tuple(getattr(z,k) for k in names)==tuple(getattr(n,k) for k in names)\nfinally:os.close(f)\n"
    code+="print(json.dumps({'offset':"+str(index*524288)+",'base64':base64.b64encode(b).decode(),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}))\n"
    return code


def operator_bundle_bytes(bundle):
    return enc({'manifest_utf8':decode(bundle['manifest_b64'],262144).decode('utf-8'),
        'sources_utf8':{name:decode(body,262144).decode('utf-8') for name,body in bundle['sources'].items()}})


def operator_stage_request(bundle,nonce):
    need(re.fullmatch('[0-9a-f]{32}',nonce),'bounded_fresh_bundle_namespace')
    body=operator_bundle_bytes(bundle);need(len(body)<=262144,'unchanged_static_bundle_unpack_budget')
    path=BASE+'/fault-source-bundles-r10-r1/'+nonce+'/OPERATOR-BUNDLE.original.json'
    row=desc(path,body);packed=gzip.compress(body,compresslevel=9,mtime=0)
    program="import os,sys,stat,hashlib,json,base64,zlib\nfrom pathlib import Path\np=Path("+repr(path)+")\n"
    program+="z=zlib.decompressobj(31);b=z.decompress(base64.b64decode("+repr(b64(packed))+",validate=True),262145)\n"
    program+="assert len(b)<=262144 and z.eof and not z.unused_data and not z.unconsumed_tail\nassert len(b)=="+str(len(body))+" and hashlib.sha256(b).hexdigest()=="+repr(sha(body))+"\n"
    program+="assert os.getuid()==os.geteuid()==0\nos.umask(0o077)\nq=p.parent.parent\nif not q.exists():q.mkdir(mode=0o700)\nassert q.resolve(strict=True)==q and q.stat().st_uid==0 and stat.S_IMODE(q.stat().st_mode)==0o700\np.parent.mkdir(mode=0o700)\nassert p.parent.resolve(strict=True)==p.parent\nf=os.open(p,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\ntry:\n with os.fdopen(f,'wb',closefd=False) as s:s.write(b);s.flush();os.fsync(f)\n a=os.fstat(f);os.lseek(f,0,0);r=b''\n while True:\n  x=os.read(f,65536)\n  if not x:break\n  r+=x\n  assert len(r)<=262144\n names=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')\n assert r==b and tuple(getattr(a,k) for k in names)==tuple(getattr(os.fstat(f),k) for k in names)==tuple(getattr(p.lstat(),k) for k in names)\nfinally:os.close(f)\nf=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(f);os.close(f)\n"
    program+="print(json.dumps({'state':'EXACT_STATIC_OPERATOR_BUNDLE_STAGED_NO_TASK','original':"+repr(row)+",'new_send':0,'new_signal':0},sort_keys=True))\n"
    return python_request(program,30),row


def source_request(source,plan_raw,mode,operator_bundle=None):
    need(type(source) is bytes and 0<len(source)<=65536 and 0<len(plan_raw)<=65536,
         'bounded_exact_phone_source_and_plan')
    packet={'source_utf8':source.decode('utf-8'),'plan_utf8':plan_raw.decode('utf-8'),
        'source_sha256':sha(source),'plan_sha256':sha(plan_raw)}
    if operator_bundle is not None:packet['operator_bundle_ref']=operator_bundle
    # UTF-8 source strings avoid gratuitous base64 expansion inside the bounded
    # envelope; the actor receives the exact original UTF-8 bytes on decode.
    body=enc(packet);need(len(body)<=262144,'unchanged_phone_unpack_budget')
    packed=gzip.compress(body,compresslevel=9,mtime=0)
    program="import base64,hashlib,json,sys,zlib\np=base64.b64decode("+repr(b64(packed))+",validate=True)\n"
    program+="d=zlib.decompressobj(31);r=d.decompress(p,262145)\nassert len(r)<=262144 and d.eof and not d.unused_data and not d.unconsumed_tail\n"
    program+="assert hashlib.sha256(r).hexdigest()=="+repr(sha(body))+"\nv=json.loads(r)\ns=v['source_utf8'].encode('utf-8');q=v['plan_utf8'].encode('utf-8')\n"
    program+="assert len(s)<=65536 and len(q)<=65536 and hashlib.sha256(s).hexdigest()==v['source_sha256'] and hashlib.sha256(q).hexdigest()==v['plan_sha256']\nv['plan_b64']=base64.b64encode(q).decode()\n"
    if mode=='watch':
        need(operator_bundle is not None,'watch_requires_exact_fault_bundle')
        need(set(operator_bundle)=={'path','bytes','sha256'} and 0<operator_bundle['bytes']<=262144,
             'exact_staged_operator_bundle_descriptor')
        program+="import os,stat\nfrom pathlib import Path\nw=json.loads(q);d=v['operator_bundle_ref'];p=Path(d['path'])\nassert str(p)=="+repr(BASE+'/fault-source-bundles-r10-r1/')+"+w['nonce']+'/OPERATOR-BUNDLE.original.json' and p.resolve(strict=True)==p\nf=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)\ntry:\n a=os.fstat(f);assert stat.S_ISREG(a.st_mode) and a.st_uid==0 and a.st_nlink==1 and stat.S_IMODE(a.st_mode)==0o600 and a.st_size==d['bytes']<=262144\n r=b''\n while True:\n  x=os.read(f,65536)\n  if not x:break\n  r+=x;assert len(r)<=262144\n names=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')\n assert len(r)==d['bytes'] and hashlib.sha256(r).hexdigest()==d['sha256'] and tuple(getattr(a,k) for k in names)==tuple(getattr(os.fstat(f),k) for k in names)==tuple(getattr(p.lstat(),k) for k in names)\nfinally:os.close(f)\nq=json.loads(r);v['operator_bundle']={'manifest_b64':base64.b64encode(q['manifest_utf8'].encode()).decode(),'sources':{k:base64.b64encode(x.encode()).decode() for k,x in q['sources_utf8'].items()}}\n"
        program+="sys.argv=['watch_physical_fault_once.py','--execute-watch-once']\n"
        timeout=260
    else:
        need(mode=='capture' and operator_bundle is None,'separate_fixed_phone_capture_mode')
        program+="sys.argv=['capture_fault_phone.py','--plan-b64',v['plan_b64'],'--plan-sha256',v['plan_sha256'],'--reviewed-source-sha256',v['source_sha256'],'--execute-read-once']\n"
        timeout=120
    program+="exec(compile(s,'reviewed_physical_fault.py','exec'),{'__name__':'__main__','__file__':'reviewed_physical_fault.py','_REVIEWED_SOURCE_BYTES':s,'_REVIEWED_PACKET':v})\n"
    return python_request(program,timeout)


def armed_request(watch,source,plan_raw):
    expected={'case_id':watch['case_id'],'nonce':watch['nonce'],'owner_request_sha256':watch['owner_request_sha256'],
        'watch_source_sha256':sha(source),'watch_plan_sha256':sha(plan_raw),
        'fault_package_sha256':watch['fault_package_sha256']}
    p=BASE+'/fault-watch-r10-r1/'+watch['owner_request_sha256']+'/ARMED.json'
    program="import os,json,time,stat,hashlib\nfrom pathlib import Path\np=Path("+repr(p)+");end=time.monotonic()+20\n"
    program+="while not p.exists():\n assert time.monotonic()<end,'original watch did not arm'\n time.sleep(.05)\n"
    program+="assert p.resolve(strict=True)==p\nf=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)\na=os.fstat(f);r=os.read(f,65537);z=os.fstat(f);os.close(f)\n"
    program+="keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')\nassert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and len(r)==a.st_size<=65536 and all(getattr(a,k)==getattr(z,k)==getattr(p.lstat(),k) for k in keys)\nv=json.loads(r)\ne="+repr(expected)+"\n"
    program+="assert all(v[k]==x for k,x in e.items()) and v['signals']==v['send_attempts']==0\nassert v['absolute_deadline_monotonic_ns']-time.monotonic_ns()>180000000000,'watch admission margin elapsed'\n"
    program+="assert not (p.parent/'FAILURE.json').exists() and not (p.parent/'RESULT.json').exists()\nprint(json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':')))\n"
    return python_request(program,30)


def archive_chunk_request(row,index):
    need(type(index) is int and 0<=index<128 and 0<row['bytes']<=64*1024*1024,
         'bounded_original_archive_chunk')
    program="import os,hashlib,base64,json,stat\np="+repr(row['path'])+"\nf=os.open(p,os.O_RDONLY|os.O_NOFOLLOW);a=os.fstat(f)\n"
    program+="assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size=="+repr(row['bytes'])+"\nh=hashlib.sha256()\nwhile True:\n b=os.read(f,1048576)\n if not b:break\n h.update(b)\n"
    program+="assert h.hexdigest()=="+repr(row['sha256'])+"\no="+repr(index*524288)+";os.lseek(f,o,0);b=os.read(f,524288);z=os.fstat(f);os.close(f)\n"
    program+="ks=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns');assert all(getattr(a,k)==getattr(z,k)==getattr(os.lstat(p),k) for k in ks)\n"
    program+="print(json.dumps({'offset':o,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'base64':base64.b64encode(b).decode()},sort_keys=True))\n"
    return python_request(program,30)
