#!/usr/bin/env python3
"""Pure host audit of the exact attempt05 sender failure before Send.

This is an independent non-native verifier. It never calls the frozen sender,
touches a device, creates a native identity, or claims a parent wait receipt.
Private draft/request values and native request digests are compared in memory
and are never included in the result.
"""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import types

B = Path("/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1")
LABEL = 'root-r10-neg01-20261105-05'
NONCE = 'e4c3ccb0b2d706be3b7bf105ae772405'
F = B/'native-guard-root-chains-r10-r1'/LABEL
D = B/'native-guard-attempt05-startup-diagnostic-r1'
E = D/'sender-originals-01'
HOST = D/'host-sender-closure-01'
P4 = '/home/alex/codex-hepta-natural-'+LABEL+'-root-v150'
RUNTIME = B/'native-guard-r10-r1-operator-r5/runtime'
ROOT_CHAIN = B/'native-guard-r10-r1-operator-r5/root-chain'
SCHEMA = 'hepta.native-guard.attempt05.sender-no-send-plan.v1'
HASH = re.compile(r'[0-9a-f]{64}\Z')
MAX = 8*1024*1024
EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

def need(ok, reason):
    if not ok:
        raise ValueError(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def enc(value):
    return (json.dumps(value,sort_keys=True,ensure_ascii=False,
                       separators=(',',':'),allow_nan=False)+'\n').encode()

def strict(raw):
    def pairs(items):
        result = {}
        for key,value in items:
            need(key not in result,'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError('nonfinite JSON')))

def meta(info):
    return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
            info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]

def descriptor(path, size, digest):
    return {'path':str(path),'bytes':size,'sha256':digest}

ROOT_PLAN = descriptor(F/'ROOT-PLAN.original.json',4737,
    '30f50baff1418464d6abef24744f61ba88de927185208679a3a19cb3dbfa62f6')
INDEX = descriptor(E/'INDEX.json',38358,
    '6a5eb974928c5617f1e052e4259229132e8636e2427641a305d7b8475761e52c')
HOST_CLOSURE = descriptor(HOST/'RESULT.json',5107,
    'b5380dea6338d126c3f010e215f57e049f5e8e58c790ab1d1777b87d28c248a2')
ROOT_FAILURE = descriptor(F/'ROOT-FAILURE.json',10082,
    'ae8f5bc9d8897c561adcc901b93e1fd12e997afe655eeb0de44eb32a7263f857')
ACTOR = descriptor(B/(LABEL+'.actor.py'),82909,
    '24e6d73dfd8fa17fdc980ae6a2b4aa687e8b6ebc04b2c13912f5c366262fe086')
ONCE = descriptor(B/(LABEL+'.local-once.json'),1178,
    '9a5d85e0b8a1a90d26735633c6c2a766ad0fd5c52e4a4db0089a018b13bc8471')
SEND_RESULT = descriptor(B/(LABEL+'.send-result.json'),676,
    '35c29bfe953c5e3a7c463d9657952ff66e66b8510a5f27bae7027474b788c442')
RUNTIME_MANIFEST = descriptor(RUNTIME/'MANIFEST.json',6253,
    '9c2e08ce171d8212b5f21abbc97ded5ba2fb578e221a8579db8aef3568ff969e')
CHAIN_MANIFEST = descriptor(ROOT_CHAIN/'SOURCE-MANIFEST.json',2168,
    'e45cfa522f75f2ad51973fafa302b784832217b6c609ed4427a82f068a9f2629')
SENDER_PIN = (40952,'aafd40345c6dc35b7b7d34ab8b04c860ebf17d326d842ed733d0404cd0a051ad')
DECODER_PIN = (4116,'a3e619926a4688ebfefd55ad1074cb386240f9828613781b7fd547bcf0c70073')
COORDINATOR_PIN = (45756,'f2134edd87a21ae3cde5f461c6f9c8163cd9597c90c60a98b98bdbb0970ecc34')

def default_plan():
    return {'schema':SCHEMA,'root_plan':dict(ROOT_PLAN),'sender_index':dict(INDEX),
            'host_sender_closure':dict(HOST_CLOSURE)}

def validate_plan(plan):
    need(type(plan) is dict and set(plan)=={'schema','root_plan','sender_index','host_sender_closure'}
         and plan==default_plan(),'only the fixed original attempt05 sender plan is supported')
    return plan

def file_descriptor(row):
    need(type(row) is dict and set(row)=={'path','bytes','sha256'}
         and isinstance(row['path'],str) and Path(row['path']).is_absolute()
         and type(row['bytes']) is int and 0<=row['bytes']<=MAX
         and isinstance(row['sha256'],str) and HASH.fullmatch(row['sha256']),
         'explicit bounded original descriptor required')
    return row

def full_metadata(value, directory=False):
    need(type(value) is list and len(value)==9 and all(type(n) is int for n in value)
         and value[0]>=0 and value[1]>0 and value[3]>=0 and value[4]>=0
         and value[5]>=1 and value[6]>=0
         and (stat.S_ISDIR(value[2]) if directory else stat.S_ISREG(value[2])),
         'original nine-field metadata differs')
    if not directory:
        need(value[5]==1,'single-link original file required')
    return value

def directory_original(originals,path,names,expected_metadata=None):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True)==path,
         'canonical original directory required')
    before=path.lstat()
    need(stat.S_ISDIR(before.st_mode) and not stat.S_ISLNK(before.st_mode),
         'original directory required')
    actual=sorted(os.listdir(path))
    need(actual==sorted(names) and len(actual)==len(set(actual)) and len(actual)<=128,
         'original directory contains missing or additional entries')
    after=path.lstat()
    need(meta(before)==meta(after),'original directory changed during name census')
    if expected_metadata is not None:
        need(meta(before)==full_metadata(expected_metadata,True),
             'original directory no longer matches its recorded metadata')
    record={'metadata':meta(before),'names':actual}
    cache=getattr(originals,'sender_no_send_directories',None)
    if cache is None:
        cache={}; originals.sender_no_send_directories=cache
    need(str(path) not in cache or cache[str(path)]==record,
         'original sender directory changed between audit stages')
    cache[str(path)]=record

def recheck_sender_directories(originals):
    for path,row in dict(getattr(originals,'sender_no_send_directories',{})).items():
        directory_original(originals,path,row['names'],row['metadata'])

def source_top_assignments(raw):
    tree=ast.parse(raw)
    keys={'label','expected','preserved_draft','previous_identity','previous_digest',
          'previous_status','known_all_prior_tools_confirmed','evidence_mode',
          'component_binding','retirement_binding','retirement_prior','reset_probe',
          'COMPONENT_READY_PROBE_SOURCE'}
    values={}
    for node in tree.body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            key=node.targets[0].id
            if key in keys:
                need(key not in values,'generated actor reassigns a bound input')
                values[key]=ast.literal_eval(node.value)
    need(set(values)==keys,'generated actor binding inventory differs')
    return tree,values

def source_send_order(tree):
    rendezvous=[n for n in ast.walk(tree) if isinstance(n,ast.Call)
                and isinstance(n.func,ast.Name) and n.func.id=='wait_component_rendezvous']
    taps=[n for n in ast.walk(tree) if isinstance(n,ast.Call)
          and isinstance(n.func,ast.Name) and n.func.id=='tap'
          and len(n.args)==1 and isinstance(n.args[0],ast.Name) and n.args[0].id=='send']
    def saves(name):
        return [n for n in ast.walk(tree) if isinstance(n,ast.Call)
                and isinstance(n.func,ast.Name) and n.func.id=='save' and n.args
                and isinstance(n.args[0],ast.Constant) and n.args[0].value==name]
    once=saves('SEND.once.json'); intent=saves('SEND.MONOTONIC-INTENT.json')
    need(len(rendezvous)==len(taps)==len(once)==len(intent)==1,
         'unique original rendezvous and Send sites required')
    main=[n for n in tree.body if isinstance(n,ast.Try) and
          n.lineno<rendezvous[0].lineno<taps[0].lineno<=n.end_lineno]
    need(len(main)==1 and rendezvous[0].lineno<once[0].lineno<intent[0].lineno<taps[0].lineno,
         'original Send is not strictly after the component rendezvous')
    branches=[n for n in ast.walk(main[0]) if isinstance(n,ast.If)
              and isinstance(n.test,ast.Compare)
              and ast.unparse(n.test)=='component_binding is not None'
              and any(rendezvous[0] is child for child in ast.walk(n))]
    need(len(branches)==1 and branches[0].end_lineno<once[0].lineno,
         'component rendezvous does not dominate the unique Send path')
    functions={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
    ready=functions['read_component_ready']
    asserts=[n for n in ast.walk(ready) if isinstance(n,ast.Assert)
             and isinstance(n.msg,ast.Constant)
             and n.msg.value=='Fixed component ready observation failed; no Send']
    need(len(asserts)==1 and ast.unparse(asserts[0].test)=="result['rc'] == 0",
         'original ready failure no longer raises before Send')
    return {'unique_send_tap_sites':1,'rendezvous_call_line':rendezvous[0].lineno,
            'send_once_line':once[0].lineno,'send_intent_line':intent[0].lineno,
            'send_tap_line':taps[0].lineno,'ready_nonzero_raises_before_send':True}

def unicode_wire(wire,operation,wanted,allowed_before):
    need(type(wire) is dict and set(wire)=={'command','rc','route','stdout','stderr'}
         and type(wire['rc']) is int and wire['rc']==0 and wire['stderr']==''
         and wire['route']==[5037,'23'],
         'original Unicode input wire did not return zero')
    args=shlex.split(wire['command'])
    prefix=['CLASSPATH=/data/local/tmp/hepta-unicode-v148-r2/input.jar','app_process',
            '/system/bin','org.trillionnium.hepta.input.UnicodeInput','set-text']
    names=['--operation-id','--display','--package','--view-id','--expected-text-b64','--text-b64']
    need(args[:5]==prefix and len(args)==5+2*len(names)
         and args[5::2]==names,'original Unicode command argument shape differs')
    options=dict(zip(args[5::2],args[6::2]))
    def decode(value):
        return b'' if value=='-' else base64.b64decode(value,validate=True)
    before=decode(options['--expected-text-b64'])
    target=decode(options['--text-b64'])
    need(options['--operation-id']==operation and options['--display']=='0'
         and options['--package']=='org.trillionnium.owneropen'
         and options['--view-id']=='org.trillionnium.owneropen:id/ui_prompt'
         and target==wanted and before in allowed_before,
         'original Unicode command did not preserve the exact intended CAS')
    answer=strict(wire['stdout'])
    need(answer.get('schema')=='hepta.focused-unicode-input.v1'
         and answer.get('status') in ('set_verified','already_exact')
         and answer.get('operation_id')==operation and answer.get('display_id')==0
         and answer.get('package')=='org.trillionnium.owneropen'
         and answer.get('view_id')=='org.trillionnium.owneropen:id/ui_prompt'
         and answer.get('own_automation_disconnected') is True
         and answer.get('requested_utf8_sha256')==answer.get('after_utf8_sha256')==sha(wanted)
         and answer.get('before_utf8_sha256')==sha(before)
         and base64.b64decode(answer['readback_text_b64'],validate=True)==wanted,
         'original Unicode independent readback/CAS differs')
    return {'wire_returncode':0,'exact_target_and_readback_equal':True,
            'exact_expected_before_digest_equal':True,
            'own_automation_disconnected':True}

def verify_sender_no_send(originals, plan):
    validate_plan(plan)
    source_sha=globals().get('__reviewed_source_sha256__')
    need(isinstance(source_sha,str) and HASH.fullmatch(source_sha),
         'caller must inject the hash of the exact compiled verifier source')
    used={}
    def read(row):
        file_descriptor(row)
        p=Path(row['path'])
        need(p.resolve(strict=True)==p,'noncanonical original input')
        before=p.lstat()
        raw=originals.pinned(row)
        after=p.lstat()
        need(type(raw) is bytes and len(raw)==row['bytes'] and sha(raw)==row['sha256']
             and stat.S_ISREG(before.st_mode) and before.st_nlink==1
             and meta(before)==meta(after),'original input bytes or metadata changed')
        record=dict(row,metadata=meta(before))
        need(str(p) not in used or used[str(p)]==record,'original input changed during audit')
        used[str(p)]=record
        return raw
    root=strict(read(plan['root_plan']))
    need(root['label']==LABEL and root['nonce']==NONCE and root['case_id']=='NEG-01'
         and root['package']==RUNTIME_MANIFEST and root['source_package']==CHAIN_MANIFEST,
         'fixed attempt05 Root plan/package changed')
    request=read(root['request'])
    previous=strict(read(root['previous']))
    preserved=strict(read(root['preserved_draft']))
    resolution_raw=read(root['sender_retirement_resolution'])
    need(root['previous']['bytes']==1428
         and root['previous']['sha256']=='7ed4ccc75cc4ebc999af0da37e10e3d10173c2bf93e66f01b01042b890a4d9a4'
         and previous['terminal']['status']=='provider_failed'
         and previous['component_qualified'] is False
         and previous['known_all_dispatched_tools_confirmed_terminal'] is True
         and previous['automatic_replay'] is False,'actual previous04 original differs')
    identity=previous['identity']; digest=previous['request_sha256']
    need(type(identity) is dict and set(identity)=={'session_id','profile_id','task_id','turn_id','turn_stream_id'}
         and isinstance(digest,str) and HASH.fullmatch(digest),'previous native binding differs')
    draft=base64.b64decode(preserved['exact_utf8_b64'],validate=True)
    draft.decode('utf-8');request.decode('utf-8')
    need(bool(draft) and sha(draft)==preserved['utf8_sha256'] and draft!=request,
         'nonempty original draft binding differs')
    idx=strict(read(plan['sender_index']))
    need(idx['schema']=='hepta.attempt05.sender-original-index.v1' and idx['file_count']==42
         and idx['send_artifact_names_observed']==[] and idx['automatic_retry'] is False
         and idx['draft_content_printed'] is False and idx['phone_calls_in_this_job']==0,
         'fixed sender original index differs')
    catalog=strict(read(idx['catalog']))
    export=strict(read(idx['raw_export']))
    need(catalog['schema']=='hepta.attempt05.sender-directory-catalog.v1'
         and export['schema']=='hepta.attempt05.sender-original-export.v1'
         and catalog['path']==export['path']==P4
         and catalog['directory_metadata']==export['directory_metadata']
         and catalog['file_count']==export['file_count']==42
         and catalog['total_bytes']==export['total_bytes']==idx['total_bytes']==814165
         and catalog['phone_calls']==catalog['native_sends']==export['phone_calls']==0
         and export['automatic_retry'] is False,'source sender catalog/export differs')
    full_metadata(catalog['directory_metadata'],True)
    names=[x['name'] for x in catalog['files']]
    need(len(names)==42 and names==sorted(set(names))
         and all(Path(name).name==name and name not in ('.','..') for name in names)
         and not any(name.startswith('SEND') or re.fullmatch(r'LATENCY-[0-9]+\.original-read\.json',name)
                     for name in names),'original sender name census contains a Send artifact')
    directory_original(originals,E/'files',names)
    need(len(export['files'])==len(idx['files'])==42,'complete raw export required')
    raws={}
    for c,e,i in zip(catalog['files'],export['files'],idx['files']):
        need(set(c)=={'name','bytes','sha256','metadata'}
             and set(e)=={'name','bytes','sha256','metadata','base64'}
             and set(i)=={'original','retained'}
             and {k:e[k] for k in c}==c
             and i['original']==dict(c,path=P4+'/'+c['name'])
             and i['retained']==descriptor(E/'files'/c['name'],c['bytes'],c['sha256']),
             'raw export/catalog/original-retained binding differs')
        full_metadata(c['metadata'])
        need(c['metadata'][6]==c['bytes'],'original file metadata size differs')
        raw=read(i['retained'])
        need(base64.b64decode(e['base64'],validate=True)==raw,
             'retained file differs from original exported bytes')
        raws[c['name']]=raw
    need(sum(map(len,raws.values()))==814165,'retained sender byte total differs')
    def value(name):
        need(name in raws,'required original sender receipt absent')
        return strict(raws[name])
    actor_raw=read(ACTOR); actor_tree,assign=source_top_assignments(actor_raw)
    need({k:assign[k] for k in ('label','expected','preserved_draft','previous_identity','previous_digest','evidence_mode')}
         =={'label':LABEL,'expected':request.decode(),'preserved_draft':draft.decode(),
            'previous_identity':identity,'previous_digest':digest,'evidence_mode':'component'}
         and assign['previous_status']=='provider_failed'
         and assign['known_all_prior_tools_confirmed'] is True
         and assign['reset_probe'] is False,'generated actor original bound inputs differ')
    order=source_send_order(actor_tree)
    component=assign['component_binding']; retirement=assign['retirement_binding']
    need(type(component) is dict and component['contract']['nonce']==NONCE
         and component['contract']['owner_request_sha256']==sha(request)
         and retirement['resolution_sha256']==sha(resolution_raw),
         'generated actor component/retirement binding differs')
    once=strict(read(ONCE))
    need(once==dict(task=LABEL,prompt=request.decode(),prompt_sha256=sha(request),
         previous_identity=identity,previous_digest=digest,
         retirement_resolution_sha256=sha(resolution_raw),
         retirement_prior_admission=assign['retirement_prior'],evidence_root_mode='component',
         supplied_app_commands=False,supplied_app_coordinates=False,automatic_replay=False),
         'original local once intent differs')
    host_raw=read(SEND_RESULT);host=strict(host_raw)
    need(set(host)=={'rc','stdout','stderr'} and type(host['rc']) is int and host['rc']==2
         and host['stderr']=='' and isinstance(host['stdout'],str),
         'original SSH return receipt must be known rc2')
    lines=host['stdout'].strip().splitlines()
    need(len(lines)==1,'one actual original actor terminal required')
    terminal=strict(lines[0])
    need(terminal==dict(state='PRE_SEND_OR_ACTOR_FAILURE',native_status=None,out=P4,
         route=[5037,'23'],prompt_sha256=sha(request),
         draft_restore=dict(state='ORIGINAL_DRAFT_RESTORED',restore_attempts=1,original_draft_submitted=False),
         send_attempt_count=0,automatic_replay=False,business_success_verified=False,
         independent_collector_required=True,retirement_resolution_sha256=sha(resolution_raw)),
         'original actor terminal is not the exact no-Send failure')
    manifest=strict(read(RUNTIME_MANIFEST))
    source_rows={x['path']:x for x in manifest['files']}
    need(len(source_rows)==len(manifest['files'])==25,'original R5 source manifest differs')
    def package_source(name,pin):
        row=source_rows[name]
        need((row['bytes'],row['sha256'])==pin,'fixed R5 source row differs')
        return read(descriptor(RUNTIME/name,*pin))
    sender_source=package_source('source/send_new_native_guard_task_r10_r4.py',SENDER_PIN)
    need(read(descriptor(B/'send_new_native_guard_task_r10_r4.py',*SENDER_PIN))==sender_source,
         'actual sender alias differs from original package source')
    decoder_raw=package_source('reference/decode_client_state.py',DECODER_PIN)
    chain=strict(read(CHAIN_MANIFEST))
    rows={x['path']:x for x in chain['files']}
    c=rows['source/run_component_root_once.py']
    need((c['bytes'],c['sha256'])==COORDINATOR_PIN,'original coordinator source row differs')
    read(descriptor(ROOT_CHAIN/c['path'],*COORDINATOR_PIN))
    sender_text=sender_source.decode()
    ordered=["result = subprocess.run(ssh, input=source.encode(), capture_output=True, timeout=600)",
             "receipt = {'rc': result.returncode",
             "with (BASE / (label + '.send-result.json')).open('x') as out:",
             "print(json.dumps(receipt, ensure_ascii=False, indent=2))"]
    positions=[sender_text.index(x) for x in ordered]
    need(positions==sorted(positions) and len(set(positions))==4,
         'actual original SSH-return/source persistence order differs')
    prepared=value('COMPONENT-PREPARED-NO-SEND.json')
    need(prepared['schema']=='hepta.native-guard.sender-prepared.v1' and prepared['state']=='PREPARED_NO_SEND'
         and prepared['nonce']==NONCE and prepared['owner_request_sha256']==sha(request)
         and prepared['contract_sha256']==component['contract_sha256']
         and prepared['provider_source_sha256']==component['source_sha256']
         and prepared['ready_path']==component['phone_ready_path']
         and prepared['provider_started_by_sender'] is False
         and prepared['socket_connections']==prepared['send_attempt_count']==0,
         'actual original no-Send rendezvous differs')
    ready_names=[name for name in names if re.fullmatch(r'COMPONENT-READY-[0-9]{4}\.original-read\.json',name)]
    need(ready_names==['COMPONENT-READY-%04d.original-read.json'%i for i in range(1,15)],
         'all fourteen original rendezvous reads required')
    command='/data/adb/magisk/busybox timeout -s TERM -k 1 6 /data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -I -B -c '+shlex.quote(assign['COMPONENT_READY_PROBE_SOURCE'])
    command='/debug_ramdisk/su -c '+shlex.quote(command)
    last_end=prepared['prepared_monotonic_ns']
    for index,name in enumerate(ready_names,1):
        observation=value(name); wire=observation['original_wire_receipt']
        need(set(observation)=={'read_start_monotonic_ns','read_end_monotonic_ns','original_wire_receipt',
             'observation','read_only','socket_connections','service_launches'}
             and observation['read_only'] is True
             and observation['socket_connections']==observation['service_launches']==0
             and all(type(observation[k]) is int for k in ('read_start_monotonic_ns','read_end_monotonic_ns'))
             and last_end<=observation['read_start_monotonic_ns']<=observation['read_end_monotonic_ns']
             and wire['command']==command and wire['route']==[5037,'23'],
             'actual component readiness wire/time binding differs')
        last_end=observation['read_end_monotonic_ns']
        if index<14:
            result=observation['observation']
            need(type(wire['rc']) is int and wire['rc']==0 and wire['stderr']==''
                 and strict(wire['stdout'])==result and result['state']=='waiting_for_ready'
                 and result['nonce']==NONCE and result['owner_request_sha256']==sha(request)
                 and result['contract_sha256']==component['contract_sha256']
                 and result['claim_absent'] is True and result['ended_absent'] is True,
                 'original preceding rendezvous read was not waiting without a claim')
        else:
            need(type(wire['rc']) is int and wire['rc']==1 and wire['stdout']==''
                 and len(wire['stderr'].encode())==158 and observation['observation'] is None,
                 'actual final readiness failure was not before Send')
    need(value('ACTOR-FAILURE.json')==dict(error_type='AssertionError',
         error='Fixed component ready observation failed; no Send',automatic_send_retry=False),
         'actual actor failure branch differs')
    original_draft=value('PRESERVED-USER-DRAFT.json')
    need(original_draft['exact_text'].encode()==draft
         and original_draft['utf8_sha256']==sha(draft)
         and original_draft['restore_required'] is True
         and original_draft['submitted_original_draft'] is False,
         'actual preserved user draft differs')
    restore=value('DRAFT-RESTORE-RESULT.json')
    need(restore==dict(state='ORIGINAL_DRAFT_RESTORED',utf8_sha256=sha(draft),
         original_draft_submitted=False,model_business_credit=False,restore_attempts=1),
         'original draft restoration was not completed exactly once')
    restore_proof=unicode_wire(value('PRESERVED-DRAFT-RESTORE.original.json'),
         'root-restore-'+LABEL,draft,(b'',request,draft))
    input_wire=value('OPERATOR-CHINESE-PROMPT-INPUT.json')
    input_proof=unicode_wire(input_wire,'root-prompt-'+LABEL,request,(b'',draft,request))
    module=types.ModuleType('reviewed_attempt05_identity_decoder')
    module.__file__=str(RUNTIME/'reference/decode_client_state.py')
    exec(compile(decoder_raw,module.__file__,'exec',optimize=0),module.__dict__)
    selected_names=['FINAL-PRE-SEND-SELECTED.original-read.json',
                    'RESTORE-SELECTED.original-read.json','RESTORE-SELECTED-FINAL.original-read.json']
    for name in selected_names:
        wire=value(name)
        need(type(wire['rc']) is int and wire['rc']==0 and wire['stderr']=='',
             'selected-identity original wire was not complete')
        raw=base64.b64decode(''.join(wire['stdout'].split()),validate=True)
        selected=module.decode_client_state(raw)
        need(selected['checksum_valid'] is True
             and all(selected[k]==identity[k] for k in ('session_id','task_id','turn_id'))
             and selected['turn_request_sha256']==digest,
             'actual previous04 selected identity changed')
    need(len({raws[name] for name in selected_names})==1,
         'the three exact original selected-state receipts differ')
    gate=value('RESTORE-GLOBAL-GATE.original-read.json')
    wire=gate['original_wire_receipt'];g=strict(wire['stdout'])
    need(gate['read_only'] is True and gate['no_retry'] is True
         and type(wire['rc']) is int and wire['rc']==0 and wire['stderr']==''
         and g.get('state')=='original_retirement_verified'
         and g.get('global_action_gate_clear') is True
         and g.get('resolution_sha256')==sha(resolution_raw),
         'restoration bypassed the original global action gate')
    host_closed=strict(read(plan['host_sender_closure']))
    need(host_closed['schema']=='hepta.attempt05.host-sender-ended-observation.v1'
         and host_closed['state']=='ORIGINAL_SENDER_RETURN_AND_MAC_GROUP_ABSENCE_OBSERVED'
         and host_closed['source_coordinator_sha256']==COORDINATOR_PIN[1]
         and host_closed['host_parent_wait_receipt_available'] is False
         and host_closed['host_child_wait_returned_claimed'] is False
         and host_closed['actual_p4_ssh_returncode']==2
         and host_closed['native_send_attempt_count']==0 and host_closed['native_status'] is None
         and host_closed['draft_restore_state']=='ORIGINAL_DRAFT_RESTORED'
         and host_closed['original_host_result_stdout_exact'] is True
         and host_closed['automatic_retry'] is False
         and host_closed['phone_calls_in_this_job']==host_closed['signals']==0,
         'independent host-ended observation differs')
    phase=F/'sender-execute';phase_names=['CHILD.json','INTENT.json','stderr.original','stdout.original']
    need(host_closed['original_directory']==str(phase)
         and host_closed['names']==phase_names,'original sender host phase differs')
    directory_original(originals,phase,phase_names,host_closed['directory_metadata'])
    directory_original(originals,HOST/'sender-files',phase_names)
    phase_raw={}
    need(len(host_closed['original_files'])==4,'complete original host phase required')
    for row,name in zip(host_closed['original_files'],phase_names):
        need(set(row)=={'path','bytes','sha256','metadata'} and row['path']==str(phase/name),
             'original host phase file binding differs')
        full_metadata(row['metadata'])
        body=read({k:row[k] for k in ('path','bytes','sha256')})
        need(meta(Path(row['path']).lstat())==row['metadata']
             and read(descriptor(HOST/'sender-files'/name,row['bytes'],row['sha256']))==body,
             'host phase original metadata or preserved copy differs')
        phase_raw[name]=body
    need(phase_raw['stdout.original']==host_raw and phase_raw['stderr.original']==b'',
         'sender stdout is not the original complete SSH-return receipt')
    child=strict(phase_raw['CHILD.json']); intent=strict(phase_raw['INTENT.json'])
    need(child['pid']==child['pgid']==child['sid']==26986 and child['maximum_starts']==1
         and child['source_intent_sha256']==sha(phase_raw['INTENT.json']),
         'actual started host sender identity differs')
    expected_argv=['/usr/bin/python3','-I','-B',str(B/'send_new_native_guard_task_r10_r4.py'),
         LABEL,root['request']['path'],root['previous']['path'],'--preserved-draft',
         root['preserved_draft']['path'],'--retirement-resolution',
         root['sender_retirement_resolution']['path'],'--evidence-root','component',
         '--component-contract',str(F/'material/tree/sender-contract.json'),
         '--component-package',RUNTIME_MANIFEST['path'],'--component-package-sha256',
         RUNTIME_MANIFEST['sha256'],'--execute-once']
    need(intent==dict(schema='hepta.native-guard.root-host-command.v1',phase='sender-execute',
         argv=expected_argv,stdin_sha256=None,maximum_starts=1,maximum_wait_seconds=600,
         signals_on_timeout=False,automatic_retry=False),
         'original host sender execution intent differs')
    observations=host_closed['independent_mac_absence_observations']
    need(type(observations) is list and len(observations)==2,
         'two independent complete Mac process censuses required')
    last=0
    for index,observation in enumerate(observations):
        need(observation['original_pid']==observation['original_pgid']==26986
             and observation['returncode']==0
             and observation['matching_pid_or_pgid_rows']==[]
             and type(observation['read_start_monotonic_ns']) is int
             and type(observation['read_end_monotonic_ns']) is int
             and last<observation['read_start_monotonic_ns']<=observation['read_end_monotonic_ns'],
             'independent Mac absence observation order differs')
        last=observation['read_end_monotonic_ns']
        need(observation['stdout']['path']==str(HOST/('PS-%02d.stdout.original'%index))
             and observation['stderr']['path']==str(HOST/('PS-%02d.stderr.original'%index)),
             'exact original Mac census stream paths differ')
        raw=read(observation['stdout']);need(read(observation['stderr'])==b'','Mac ps original error')
        rows=[]
        for line in raw.decode('ascii').splitlines():
            fields=line.split()
            need(len(fields)==4 and all(re.fullmatch(r'[0-9]+',v) for v in fields[:3])
                 and fields[3] and len(fields[3])<=16,'complete Mac process row differs')
            pid,ppid,pgid=map(int,fields[:3])
            need(pid>0 and ppid>=0 and pgid>=0,'Mac process identity invalid')
            rows.append((pid,ppid,pgid,fields[3]))
        need(0<len(rows)<=16384 and len({x[0] for x in rows})==len(rows)
             and any(x[0]==1 for x in rows)
             and len(rows)==observation['numeric_pid_rows']
             and all(row[0]!=26986 and row[2]!=26986 for row in rows),
             'the original sender PID or owned group remains present')
    read(ROOT_FAILURE)
    originals.recheck(); recheck_sender_directories(originals)
    return {'schema':'hepta.native-guard.attempt05.sender-no-send-proof.v1',
        'state':'ORIGINAL_SENDER_NO_SEND_AND_DRAFT_RESTORATION_VERIFIED',
        'label':LABEL,'nonce':NONCE,'verifier_source_sha256':source_sha,
        'source_actor':ACTOR,'source_sender':descriptor(RUNTIME/'source/send_new_native_guard_task_r10_r4.py',*SENDER_PIN),
        'source_decoder':descriptor(RUNTIME/'reference/decode_client_state.py',*DECODER_PIN),
        'original_sender_ssh_returncode':2,'original_actor_terminal_state':'PRE_SEND_OR_ACTOR_FAILURE',
        'host_parent_wait_receipt_available':False,'host_child_wait_returned_claimed':False,
        'mac_sender_pid':26986,'mac_sender_group_absence_observations':2,
        'native_status':None,'native_scope_created':False,'send_attempt_count':0,
        'original_sender_files':42,'original_sender_total_bytes':814165,
        'full_source_catalog_and_export_equal':True,'source_send_order':order,
        'readiness_waiting_original_count':13,'final_original_readiness_returncode':1,
        'selected_previous04_checksum_and_identity_verified':True,
        'selected_previous04_original_count':3,'exact_original_draft_restored':True,
        'draft_restore_attempts':1,'original_draft_submitted':False,
        'original_input_CAS':input_proof,'original_restore_CAS':restore_proof,
        'original_UI_activity_performed':True,'UI_zero_claimed':False,
        'UI_effect_count_claimed':False,'business_qualified':False,'component_qualified':False,
        'phone_calls_by_verifier':0,'native_submissions_by_verifier':0,'signals_by_verifier':0,
        'private_values_or_inner_digests_disclosed':False,
        'input_originals':[used[path] for path in sorted(used)],
        'directory_originals':dict(getattr(originals,'sender_no_send_directories',{})),
        'independent_phone_lifecycle_closure_still_required':True}
