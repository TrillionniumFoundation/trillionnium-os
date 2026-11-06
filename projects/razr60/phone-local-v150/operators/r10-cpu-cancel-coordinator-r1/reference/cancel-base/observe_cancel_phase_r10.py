"""Root-only read of one new native task, its real effect receipt and model slot.

No cancellation, signal, UI, POST, task creation or original-file write occurs.
The enclosing operator embeds the reviewed pure guard/audit sources and pins.
"""
import base64
import active_runtime_r10 as active
import importlib
import os
from pathlib import Path
import re
import stat
import sys
import time
from cancel_phase import KEYS,MUTATIONS,need,sha,strict,encoded,validate_plan,scope,native_request_digest

BASE=Path('/var/lib/trillionnium/owner-open/phone-local-v150')
PROVIDER=BASE/'provider-r10-r1'
RUNTIME_ROOT=BASE/'model-runtime-r10-r1'
NATIVE=BASE.parent/'turn-events.jsonl.segments'
RUNTIME_BINARY_SHA='dbca8b3c6d024c414d018146e73df996cae51b18c8cf5d3bdab6b776318a348c'
PROTOCOL='trillionnium.owner-open.provider-jsonl.v1'


def stable(path,limit=1048576):
    path=Path(path)
    need(path.parent.resolve(strict=True)==path.parent, 'noncanonical original parent')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_uid==a.st_gid==0 and
            0<=a.st_size<=limit, 'original type/ownership/size differs')
        with os.fdopen(fd,'rb',closefd=False) as stream: raw=stream.read(limit+1)
        b,n=os.fstat(fd),path.lstat()
        fields=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink','st_uid','st_gid')
        need(len(raw)==a.st_size and all(getattr(a,k)==getattr(b,k)==getattr(n,k) for k in fields), 'original changed during read')
        return raw
    finally:os.close(fd)


def original(path,limit=1048576):
    raw=stable(path,limit)
    return {'source':str(path),'bytes':len(raw),'sha256':sha(raw),'raw_b64':base64.b64encode(raw).decode()}


def jlines(raw):
    need(raw==b'' or raw.endswith(b'\n'), 'partial original JSONL line')
    return [strict(line) for line in raw.splitlines()]


def production(plan):
    state=active.current(plan['runtime_binding'],plan['expected_boot'])
    need(_REVIEWED_PRODUCTION_PINS==active._REVIEWED_PRODUCTION_PINS,
         'shared observer and actual production pins differ')
    return state['config']


def native_records(actual):
    need(NATIVE.resolve(strict=True)==NATIVE, 'native journal parent differs')
    files=sorted(NATIVE.glob('*.jsonl'))
    need(0<len(files)<=1024, 'native journal segment count')
    audit={};exec(compile(_REVIEWED_NATIVE_AUDIT_SOURCE,'reviewed-native-journal-audit','exec'),audit)
    records=[]; originals=[]; total=0
    needle=actual['turn_id'].encode()
    for path in files:
        raw=stable(path,16*1024*1024);total+=len(raw)
        need(total<=64*1024*1024, 'native scan byte bound')
        offset=0
        for line in raw.splitlines(keepends=True):
            here=offset;offset+=len(line)
            if not line.endswith(b'\n'): continue
            if needle not in line:continue
            row=strict(line)
            if row.get('scope')!=actual:continue
            payload_hash,record_hash=audit['record_hashes'](row)
            need(payload_hash==row['payload_sha256'] and record_hash==row['record_sha256'], 'native raw hash differs')
            records.append(row);originals.append({'source':str(path),'offset':here,'bytes':len(line),
                'sha256':sha(line),'raw_b64':base64.b64encode(line).decode()})
    ordered=sorted(zip(records,originals),key=lambda pair:pair[0]['turn_seq'])
    records=[a for a,b in ordered];originals=[b for a,b in ordered]
    need(records and [r['turn_seq'] for r in records]==list(range(len(records))), 'native turn sequence gap')
    frames=[r['payload']['frame'] for r in records]
    need(frames[0]['kind']=='turn.accepted' and [f['host_seq'] for f in frames]==list(range(len(frames))), 'native admission/order differs')
    digest=records[0]['payload']['request_sha256']
    need(re.fullmatch('[0-9a-f]{64}',digest), 'native digest malformed')
    for row,frame in zip(records,frames):
        need({k:frame.get(k) for k in KEYS}==actual and frame.get('kind')==row['kind']
            and frame.get('event_id')==row['event_id'] and row['payload']['request_sha256']==digest
            and frame.get('payload',{}).get('turn_request_sha256')==digest, 'native frame/durable scope differs')
    ends=[f for f in frames if f['kind']=='turn.end']
    need(len(ends)<=1 and (not ends or frames[-1]==ends[0]), 'native terminal order differs')
    cancels=[f for f in frames if f['kind']=='turn.cancel.accepted']
    return dict(native_accepted=True,native_request_sha256=digest,native_terminal=ends[0] if ends else None,
        cancel_acceptances=len(cancels),cancel_acceptance_frames=cancels,native_originals=originals)


def dispatches(run,actual,incoming,outgoing):
    guards=importlib.import_module('phone_task_guards')
    phone=importlib.import_module('phone_observation_tools')
    recovery=importlib.import_module('retirement_recovery')
    calls=[]; originals=[]
    for frame in outgoing:
        if frame['kind']!='tool.call':continue
        wire=frame['call'];call_id=wire['call_id']
        semantic_path=run/('semantic-'+sha(call_id.encode())+'.json')
        semantic_raw=stable(semantic_path);semantic=strict(semantic_raw)
        argv=wire['argv']
        need(wire['tool']=='shell.exec' and len(argv)==9 and argv[:3]==['/usr/bin/python3',str(BASE/'tool_client_r6.py'),'execute']
            and argv[3]=='--action-id' and argv[5]=='--command-b64' and argv[7]=='--timeout-ms', 'original r6 call shape differs')
        action=argv[4];command=base64.b64decode(argv[6],validate=True)
        need(re.fullmatch('[0-9a-f]{32}',action) and semantic['capture_id']==action and
            semantic['call_id']==call_id and semantic['wire_call']==wire and semantic['turn']==actual, 'semantic original differs')
        if semantic['semantic_tool']=='phone.open_app':
            resolved=strict(stable(run/'task-app-scope.json',65536))
            tuples={r['alias']:r['component'] for r in resolved['apps']}
            need(semantic.get('alias') in tuples and semantic.get('component')==tuples[semantic['alias']],
                 'actual app-open alias/component exceeds the verified task subset')
        row={'call_id':call_id,'action_id':action,'semantic_tool':semantic['semantic_tool'],
            'component':guards.component(semantic['component']) if semantic.get('component') else None,
            'command_sha256':sha(command),'verified_app_open':False}
        originals.append(original(semantic_path))
        results=[f for f in incoming if f['kind']=='tool.result' and f.get('call_id')==call_id]
        need(len(results)<=1, 'duplicate original tool result')
        if semantic['semantic_tool'] in MUTATIONS:
            ip=BASE/'provider-state/evidence/action-ledger'/(action+'.intent.json')
            intent=strict(stable(ip));originals.append(original(ip))
            need(intent['action_id']==action and intent['command_sha256']==sha(command)
                and intent['semantic_identity']=={k:actual[k] for k in KEYS[:-1]} and
                intent['automatic_replay'] is False, 'durable mutation reservation differs')
        if semantic['semantic_tool']=='phone.open_app' and results:
            rp=BASE/'executor-r6/actions'/action/'receipt.json'
            receipt=strict(stable(rp));recovery.require_r6_terminal(receipt)
            need(receipt['action_id']==action and receipt['command_sha256']==sha(command) and
                receipt['state']=='completed' and receipt['can_redispatch'] is False, 'original open executor receipt differs')
            typed=strict(phone.native_streams(results[0],call_id,'shell.exec'))
            page,viewport=guards.verify_app_open(typed,action,semantic['component'])
            phone.validate_viewport(viewport)
            row['verified_app_open']=True;row['verified_component']=page['component']
            originals.append(original(rp))
        calls.append(row)
    return calls,originals


def business_marker(run):
    path=run/'health-contract.json'
    raw=stable(path,65536)
    need(strict(raw)=={'status':'no_health_contract'}, 'cancellation case requires normal business, not a HEALTH task')
    return {'source':str(path),'bytes':len(raw),'sha256':sha(raw),'raw_b64':base64.b64encode(raw).decode()}


def model_observation(plan,run,config):
    model=importlib.import_module('model_slot_cleanup')
    runtime=RUNTIME_ROOT/plan['expected_boot']
    ready_raw=stable(runtime/'READY-BOUND.json',1048576);ready=strict(ready_raw)
    bp=Path(ready['binding']['path'])
    need(bp.parent==runtime/'bindings', 'binding outside actual boot runtime')
    binding_raw=stable(bp,65536)
    need(sha(binding_raw)==ready['binding']['sha256'], 'actual ready binding differs')
    binding=model.load_binding(bp)
    need(binding['server_binary_sha256']==RUNTIME_BINARY_SHA and binding['server_domain']=='u:r:magisk:s0'
        and binding['server_identity']['boot_id']==plan['expected_boot'] and binding['endpoint']==config['endpoint']
        and binding['model_claim']==str(runtime/'model.identity'), 'actual server binding differs')
    identity=model.verify_identity(binding,hash_binary=True)
    need(os.readlink('/proc/'+str(identity['pid'])+'/exe')=='/data/local/tmp/hepta-phone-local-v150-r10-r1/bin/llama-server',
        'original server executable path differs')
    identities=sorted(run.glob('local-[0-9][0-9].request-identity.json'))
    if not identities:return None
    need(len(identities)<=8, 'model round count bound')
    ip=identities[-1];round_number=int(ip.name[6:8]);prefix=run/('local-%02d'%round_number)
    rid_raw=stable(ip);rid=strict(rid_raw)
    need(rid['schema']=='hepta.original-wire-request.v1' and rid['automatic_retry'] is False,
        'original request reservation differs')
    body_raw=stable(prefix.with_suffix('.request.json'),2*1024*1024);body=strict(body_raw)
    need(sha(body_raw)==rid['request_sha256'] and len(body_raw)==rid['request_bytes'], 'original wire body differs')
    grammar=body.get('response_format',{})
    need(grammar.get('type')=='json_schema' and grammar.get('json_schema',{}).get('name')=='hepta_mobile_use_action'
        and grammar['json_schema'].get('strict') is True, 'cancellation case is not an actual business model request')
    image_raw=stable(prefix.with_suffix('.images.json'));images=strict(image_raw)
    need(images['request_id']==rid['request_id'] and images['old_images_attached'] is False,
        'current image attachment ownership differs')
    content=[item for message in body['messages'] if isinstance(message.get('content'),list)
        for item in message['content'] if item.get('type')=='image_url']
    need(len(content)==len(images['images'])<=1, 'image attachment count differs')
    for part,row in zip(content,images['images']):
        url=part['image_url']['url'];need(url.startswith('data:image/jpeg;base64,'), 'image type differs')
        raw=base64.b64decode(url.split(',',1)[1],validate=True)
        need(sha(raw)==row['sha256'] and len(raw)==row['bytes'] and row['attached_round']==round_number,
            'actual attached image bytes differ')
    deadline=time.monotonic()+1.6
    receipt,http1=model.get_json(config,'/hepta/requests/'+rid['request_id'],min(deadline,time.monotonic()+.75))
    slots,http2=model.get_json(config,'/slots',deadline)
    need(all(r['complete'] is True and r['http_status']==200 and r['error'] is None for r in (http1,http2)), 'original model GET observation incomplete')
    assessment=model.assess_original(rid['request_id'],identity,receipt,slots,rid['request_sha256'],rid['request_bytes'])
    decoded=model.validate_original_records(rid['request_id'],identity,receipt,rid['request_sha256'],rid['request_bytes'])
    safe_point=decoded.get('cancel-processed.json',{}).get('details',{}).get('safe_point')
    model.verify_identity(binding)
    slot=slots[0]
    active=(slot['is_processing'] is True and receipt['state'] not in ('completed','cancelled','failed') and
        receipt.get('terminal_durable') is False and receipt.get('slot_release_observed') is False)
    return dict(round=round_number,request_id=rid['request_id'],request_sha256=rid['request_sha256'],
        request_bytes=rid['request_bytes'],image_count=len(content),server_identity=identity,
        task_id=receipt['task_id'],slot_id=receipt['slot_id'],original_active=active,
        ready_sha256=sha(ready_raw),binding_sha256=sha(binding_raw),request_identity_original=original(ip),
        images_original=original(prefix.with_suffix('.images.json')),body_original_sha256=sha(body_raw),
        original_http=[http1,http2],assessment=assessment,original_cancel_safe_point=safe_point)


def _observe_active(plan,scope_hint=None):
    owner=validate_plan(plan);began=time.monotonic_ns()
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(boot==plan['expected_boot'] and os.getuid()==os.geteuid()==0, 'actual boot/root observation required')
    config=production(plan);evidence=BASE/'provider-state/evidence'
    dirs=sorted(p for p in evidence.iterdir() if re.fullmatch('[0-9]{8}-[0-9]{6}-[0-9a-f]{32}',p.name))
    need(len(dirs)<=512, 'provider run search bound')
    matches=[]
    for run in dirs:
        try:raw=stable(run/'provider-in.jsonl',4*1024*1024)
        except FileNotFoundError:continue
        first=raw.split(b'\n',1)[0]
        if not first:continue
        frame=strict(first);turn=frame.get('turn',{})
        if frame.get('kind')=='turn.start' and isinstance(turn.get('user_input'),str) and turn['user_input'].encode()==owner:
            matches.append((run,raw,frame))
    answer=dict(schema='hepta.r10.cancel-phase-observation.v1',boot_id=boot,
        owner_request_sha256=sha(owner),phone_monotonic_started_ns=began,
        state='NO_MATCHING_ACCEPTED_TASK',model_requests=0,task_submissions=0,tool_calls=0,
        ui_actions=0,signals=0,original_file_writes=0,physical_case_pass=False,
        runtime_observation=active.current(plan['runtime_binding'],plan['expected_boot'])['last_observation'])
    need(len(matches)<=1, 'fresh exact request has multiple admissions')
    if not matches:
        need(scope_hint is None, 'accepted scope vanished')
        return answer
    run,inraw,start=matches[0];actual=scope({k:start['turn'][k] for k in KEYS})
    need(actual!=plan['previous_scope'] and (scope_hint is None or actual==scope_hint), 'actual original scope changed')
    incoming=jlines(inraw);out_raw=stable(run/'provider-out.jsonl',4*1024*1024);outgoing=jlines(out_raw)
    for rows in (incoming,outgoing):
        need(all(row.get('protocol')==PROTOCOL and type(row.get('seq')) is int and row['seq']==i
            for i,row in enumerate(rows)), 'provider protocol/sequence differs')
    claim_key=sha(__import__('json').dumps([actual[k] for k in KEYS[:-1]],separators=(',',':')).encode())
    claim_path=evidence/'claims'/claim_key;claim_raw=stable(claim_path);claim=strict(claim_raw)
    need(claim['identity']==actual and claim['request_sha256']==sha(owner) and claim['state']=='accepted_no_redispatch'
        and claim['run_dir']==str(run), 'durable consumed original claim differs')
    native=native_records(actual)
    need(native['native_request_sha256']==native_request_digest(actual,owner), 'native accepted digest is not the exact owner request')
    business=business_marker(run)
    task_scope=active.contract_originals(run,actual,owner,plan,config)
    calls,action_originals=dispatches(run,actual,incoming,outgoing)
    model=model_observation(plan,run,config)
    # Re-read the dispatch prefix/claim after the GETs. Any advance is a new read,
    # never permission to apply this stale phase. Cancellation is still elsewhere.
    need(stable(run/'provider-in.jsonl',4*1024*1024)==inraw and
        stable(run/'provider-out.jsonl',4*1024*1024)==out_raw and stable(claim_path)==claim_raw,
        'live dispatch prefix changed during phase observation')
    need(business_marker(run)==business, 'business/health contract mode changed during observation')
    need(active.contract_originals(run,actual,owner,plan,config)==task_scope,
         'actual task app-scope originals changed during observation')
    native_after=native_records(actual)
    need(native_after==native, 'native control/terminal advanced during phase observation')
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==boot, 'boot changed during phase observation')
    runtime_observation=active.verify_current(active.current(plan['runtime_binding'],plan['expected_boot']))
    answer.update(state='BOUND_ORIGINAL_PHASE_OBSERVED',scope=actual,run=run.name,claim_consumed=True,
        task_scope_originals=task_scope,runtime_observation=runtime_observation,
        claim_original=original(claim_path),provider_input_original={'sha256':sha(inraw),'bytes':len(inraw),
            'raw_b64':base64.b64encode(inraw).decode()},provider_output_original={'sha256':sha(out_raw),'bytes':len(out_raw),
            'raw_b64':base64.b64encode(out_raw).decode()},calls=calls,action_originals=action_originals,model=model,
        health_contract_original=business,phone_monotonic_finished_ns=time.monotonic_ns(),**native)
    return answer


def observe(plan,scope_hint=None):
    validate_plan(plan)
    active._REVIEWED_PRODUCTION_PINS=_REVIEWED_PRODUCTION_PINS
    with active.verified_runtime(plan['runtime_binding'],plan['expected_boot']):
        return _observe_active(plan,scope_hint)
