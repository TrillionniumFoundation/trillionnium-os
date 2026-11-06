"""Independent reconstruction of original per-request ledger prefixes.

No source reserve/resolve function is called. Final inventory is used only to
check completeness, never to construct an earlier model round. Missing evidence
after a durable original reservation stays UNKNOWN and cannot qualify 0 tools.
"""
import ast
import base64
import datetime
import hashlib
import json
from pathlib import Path
import re

from native_journal_audit import strict_loads

SCOPE = ('session_id','profile_id','task_id','turn_id','turn_stream_id')
MUTATIONS = {'phone.open_app','phone.tap','phone.input_text','phone.focus_input_text','phone.return_hepta'}


def require(ok,message):
    if not ok: raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=False,
                      separators=(',',':'),allow_nan=False).encode()


def exact(a,b):
    return canonical(a)==canonical(b)


def inventory(entries):
    return [{k:entries[n][k] for k in ('name','bytes','sha256')} for n in sorted(entries)]


def entry(value):
    require(isinstance(value,dict) and set(value)=={'name','bytes','sha256','raw_base64'},
            'raw intent entry fields differ')
    require(isinstance(value['name'],str)
            and re.fullmatch(r'[0-9a-f]{32}\.intent\.json',value['name'])
            and type(value['bytes']) is int and 0<value['bytes']<=16384,
            'raw intent name/size differs')
    raw=base64.b64decode(value['raw_base64'],validate=True)
    require(base64.b64encode(raw).decode()==value['raw_base64']
            and len(raw)==value['bytes'] and sha(raw)==value['sha256'],
            'raw intent original bytes/hash differ')
    obj=strict_loads(raw)
    require(isinstance(obj,dict) and obj.get('schema') in
            {'hepta.action-intent.v150.1','hepta.action-intent.v150.2'}
            and obj.get('action_id')+'.intent.json'==value['name']
            and obj.get('automatic_replay') is False,
            'original intent schema/identity differs')
    return obj,raw


def auxiliary_entry(value):
    require(isinstance(value,dict) and isinstance(value.get('name'),str)
            and re.fullmatch(r'[0-9a-f]{32}\.(resolution|inspection|retirement-proof)\.json',value['name']),
            'baseline auxiliary name differs')
    if value.get('state')=='absent':
        require(set(value)=={'name','state','lookup_errno'} and value['lookup_errno']==2,
                'baseline auxiliary absence is not explicit ENOENT')
        return None
    require(value.get('state')=='captured'
            and set(value)=={'name','state','bytes','sha256','raw_base64'},
            'baseline auxiliary original fields differ')
    limit=262144 if value['name'].endswith('.retirement-proof.json') else 16384
    require(type(value['bytes']) is int and 0<value['bytes']<=limit,
            'baseline auxiliary original size differs')
    raw=base64.b64decode(value['raw_base64'],validate=True)
    require(base64.b64encode(raw).decode()==value['raw_base64']
            and len(raw)==value['bytes'] and sha(raw)==value['sha256']
            and isinstance(strict_loads(raw),dict),'baseline auxiliary original bytes/hash differ')
    return raw


def common(value,scope,owner,baseline=None):
    require(value.get('scope')==scope and value.get('owner_request_sha256')==owner
            and value.get('observation_only') is True and value.get('automatic_replay') is False,
            'ledger record original scope/owner/observation binding differs')
    if baseline is not None:
        require(value.get('baseline_sha256')==baseline,'ledger baseline digest differs')


def original_absence(capture,source):
    rows=[r for r in capture['files'] if r.get('source_path')==source]
    return len(rows)==1 and rows[0].get('state')=='absent' and rows[0].get('lookup_errno')==2


def reservation_authority(snapshot,provider_source,seal):
    selected={Path(r['path']).name:r for r in seal['production_files']}
    parsed={}
    for name in ('action_ledger.py','retirement_recovery.py'):
        row=selected[name]
        raw=snapshot.read(Path(provider_source)/name)
        require(len(raw)==row['bytes'] and sha(raw)==row['sha256'],
                'original reservation authority source bytes differ')
        parsed[name]=ast.parse(raw)
    functions=[n for n in parsed['action_ledger.py'].body
               if isinstance(n,ast.FunctionDef) and n.name=='fingerprint']
    require(len(functions)==1,'original fingerprint function absent')
    api={'json':json,'sha':sha}
    exec(compile(ast.Module(body=functions,type_ignores=[]),'<pinned original fingerprint>','exec'),api)
    bindings=[n for n in parsed['retirement_recovery.py'].body if isinstance(n,ast.Assign)
        and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='EXECUTOR_BINDING']
    require(len(bindings)==1,'original executor binding absent')
    # Execute only the frozen pure retirement validators. Their original read
    # is supplied already capture-bound bytes, never a later local replacement.
    retired={'datetime':datetime,'Path':Path,'ProviderError':ValueError,
             'strict_json':strict_loads,'hashlib':hashlib,'re':re}
    for node in parsed['retirement_recovery.py'].body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            retired[node.targets[0].id]=ast.literal_eval(node.value)
    selected=[n for n in parsed['retirement_recovery.py'].body if isinstance(n,ast.FunctionDef)
              and n.name in {'require','sha','validate_proof','validate_retired_resolution'}]
    require(len(selected)==4,'original retirement validators absent')
    exec(compile(ast.Module(body=selected,type_ignores=[]),'<pinned original retirement validators>','exec'),retired)
    def validate_retired(directory,intent,digest,resolution,proof_raw):
        expected=Path(directory)/(intent['action_id']+'.retirement-proof.json')
        def read_bound(path):
            require(Path(path)==expected and proof_raw is not None,
                    'baseline retirement proof original binding absent')
            return proof_raw
        retired['read_private_proof']=read_bound
        return retired['validate_retired_resolution'](directory,intent,digest,resolution)
    return api['fingerprint'],ast.literal_eval(bindings[0].value),validate_retired


def audit(snapshot,run,state,scope,request,seal,capture_path,calls,provider_source):
    result={'status':'INCOMPLETE','complete_prefix_reconstruction':False,
            'unaccounted_original_intents':[],'reservation_only_actions':[],
            'rounds':{},'issues':[],'phone_operations':0,'model_requests':0,
            'final_inventory_is_historical_prefix':False}
    try:
        _audit(snapshot,run,state,scope,request,seal,capture_path,calls,result,provider_source)
        result.update(status='PASS',complete_prefix_reconstruction=True)
    except (OSError,ValueError,TypeError,KeyError,IndexError,AttributeError) as error:
        result['issues'].append({'error_class':type(error).__name__,'reason':str(error)})
    return result


def _audit(snapshot,run,state,scope,request,seal,capture_path,calls,result,provider_source):
    fingerprint,executor_binding,validate_retired=reservation_authority(snapshot,provider_source,seal)
    require(set(scope)==set(SCOPE),'five-field original scope required')
    owner=sha(request);root=run/'ledger-prefix'
    baseline_raw=snapshot.read(root/'baseline.json')
    baseline=strict_loads(baseline_raw);base_sha=sha(baseline_raw)
    common(baseline,scope,owner)
    require(baseline.get('schema')=='hepta.ledger-baseline.v150.2'
            and baseline.get('semantic_identity')=={k:scope[k] for k in SCOPE[:-1]}
            and baseline.get('same_lock_as_original_reservation') is True,
            'locked complete baseline identity differs')
    source_rows={Path(x['path']).name:x for x in seal['production_files']}
    source_names=('ledger_round_evidence.py','provider_phone_local.py','action_ledger.py')
    require(baseline.get('source_sha256')=={n:source_rows[n]['sha256'] for n in source_names},
            'baseline source bytes not selected sealed source')
    original_run=baseline.get('original_run_dir')
    require(isinstance(original_run,str) and Path(original_run).name==run.name,
            'baseline original run differs')
    original_ledger=str(Path(original_run).parent/'action-ledger')
    capture=snapshot.json(capture_path)
    require(capture.get('schema')=='hepta.physical-fault.phone-original-capture.v1'
            and capture.get('state')=='CAPTURED_NEGATIVE_ORIGINALS_UNQUALIFIED'
            and capture.get('export_complete') is True and capture.get('issues')==[]
            and capture.get('selected_scope')==scope and capture.get('owner_request_sha256')==owner
            and capture.get('bindings',{}).get('complete_action_ledger_intent_inventory') is True
            and capture.get('bindings',{}).get('reservation_originals_enumerated') is True
            and capture.get('bindings',{}).get('complete_action_ledger_auxiliary_originals') is True,
            'complete original ledger capture is missing or partial')
    require(capture.get('actual_run')==run.name and capture.get('actual_run_dir')==original_run,
            'captured original run path differs from baseline')
    def bound_run_read(path,raw):
        rel=str(path.relative_to(run))
        original=original_run+'/'+rel
        exported='provider-state/evidence/'+run.name+'/'+rel
        matches=[r for r in capture['files'] if r.get('export_relative_path')==exported]
        require(len(matches)==1 and matches[0].get('state')=='captured'
                and matches[0].get('source_path')==original
                and matches[0].get('bytes')==len(raw) and matches[0].get('sha256')==sha(raw)
                and matches[0].get('eof') is True,
                'ledger/request evidence is not the original captured run file')
        return raw
    bound_run_read(root/'baseline.json',baseline_raw)
    directories=[r for r in capture['directories'] if r.get('source_path')==original_ledger]
    require(1<=len(directories)<=2 and all(exact(row,directories[0]) for row in directories)
            and directories[0].get('state')=='observed',
            'negative collector ledger directory observations differ')
    # This exact collector visits the same ledger in capture_actions and
    # capture_remaining_ledger. Preserve both raw rows; only equal views coalesce.
    directories=directories[:1]
    names=directories[0]['names']
    require(isinstance(names,list) and names==sorted(set(names))
            and all(isinstance(n,str) for n in names),'original directory inventory malformed')
    final_names=[n for n in names if n.endswith('.intent.json')]
    require(len(final_names)<=256 and all(re.fullmatch(r'[0-9a-f]{32}\.intent\.json',n)
                                        for n in final_names),'original intent inventory bound/name differs')
    declared=capture.get('ledger_intent_inventory')
    require(isinstance(declared,list) and [r['name'] for r in declared]==final_names,
            'capture intent inventory is not the full directory intent set')
    local_names=sorted(p.name for p in (state/'evidence/action-ledger').glob('*.intent.json'))
    require(local_names==final_names,'copied original intent inventory differs')
    final={}
    for row in declared:
        require(set(row)=={'name','bytes','sha256'},'capture intent descriptor fields differ')
        relative='provider-state/evidence/action-ledger/'+row['name']
        originals=[r for r in capture['files'] if r.get('export_relative_path')==relative]
        require(len(originals)==1 and originals[0].get('state')=='captured'
                and originals[0].get('source_path')==original_ledger+'/'+row['name']
                and originals[0].get('sha256')==row['sha256']
                and originals[0].get('bytes')==row['bytes'] and originals[0].get('eof') is True,
                'original capture intent descriptor is incomplete')
        raw=snapshot.read(state/'evidence/action-ledger'/row['name'])
        value={**row,'raw_base64':base64.b64encode(raw).decode()}
        entry(value);final[row['name']]=value
    result['original_final_intent_count']=len(final)
    entries={}
    initial=baseline.get('initial_intents')
    require(isinstance(initial,list) and len(initial)<=256,'baseline intent count differs')
    for value in initial:
        _obj,_raw=entry(value);name=value['name']
        require(name not in entries and final.get(name)==value,
                'baseline intent missing/changed in retained final originals')
        entries[name]=value
    require([r['name'] for r in initial]==sorted(entries)
            and exact(baseline.get('initial_inventory'),inventory(entries))
            and baseline.get('inventory_sha256')==sha(canonical(inventory(entries))),
            'complete baseline inventory/digest differs')

    auxiliary_names=sorted(n[:-len('.intent.json')]+suffix for n in final
        for suffix in ('.resolution.json','.inspection.json','.retirement-proof.json'))
    declared_aux=capture.get('ledger_auxiliary_inventory')
    require(isinstance(declared_aux,list) and [r['name'] for r in declared_aux]==auxiliary_names,
            'complete final ledger auxiliary inventory differs')
    final_aux={}
    for row in declared_aux:
        name=row['name'];relative='provider-state/evidence/action-ledger/'+name
        originals=[r for r in capture['files'] if r.get('export_relative_path')==relative]
        require(len(originals)==1 and originals[0].get('source_path')==original_ledger+'/'+name,
                'ledger auxiliary capture original path differs')
        original=originals[0]
        raw=snapshot.read(state/'evidence/action-ledger'/name,required=False)
        if row.get('state')=='captured':
            require(set(row)=={'name','state','bytes','sha256'}
                    and original.get('state')=='captured' and original.get('eof') is True
                    and original.get('bytes')==row['bytes'] and original.get('sha256')==row['sha256']
                    and raw is not None and len(raw)==row['bytes'] and sha(raw)==row['sha256'],
                    'ledger auxiliary is not the original captured bytes')
            value={**row,'raw_base64':base64.b64encode(raw).decode()}
        else:
            require(set(row)=={'name','state','lookup_errno'} and row.get('state')=='absent'
                    and row.get('lookup_errno')==2 and original.get('state')=='absent'
                    and original.get('lookup_errno')==2 and raw is None,
                    'ledger auxiliary current absence is not original ENOENT')
            value=dict(row)
        auxiliary_entry(value);final_aux[name]=value
    require(sorted(n for n in names if re.fullmatch(
        r'[0-9a-f]{32}\.(resolution|inspection|retirement-proof)\.json',n))==
        sorted(n for n,v in final_aux.items() if v['state']=='captured'),
        'unexplained original ledger auxiliary file remains')
    initial_aux=baseline.get('initial_auxiliary_originals')
    expected_aux=sorted(n[:-len('.intent.json')]+suffix for n in entries
        for suffix in ('.resolution.json','.inspection.json','.retirement-proof.json'))
    require(isinstance(initial_aux,list) and [r['name'] for r in initial_aux]==expected_aux
            and baseline.get('auxiliary_absence_is_initial_observation_only') is True
            and baseline.get('initial_auxiliary_inventory_sha256')==sha(canonical([
                {k:v for k,v in row.items() if k!='raw_base64'} for row in initial_aux])),
            'initial complete auxiliary inventory/digest differs')
    initial_raw={}
    for value in initial_aux:
        raw=auxiliary_entry(value);initial_raw[value['name']]=raw
        if raw is not None:
            require(final_aux.get(value['name'])==value,
                    'initial auxiliary changed/omitted from original final capture')
        # Initial ENOENT stays an initial observation; a later resolution is
        # never inserted into the original earlier round or its authority.
    for name,value in entries.items():
        intent,_raw=entry(value);token=intent['action_id']
        resolution_raw=initial_raw[token+'.resolution.json']
        if resolution_raw is not None:
            resolution=strict_loads(resolution_raw)
            require(resolution.get('action_id')==token
                    and resolution.get('intent_sha256')==value['sha256']
                    and resolution.get('automatic_replay') is False
                    and resolution.get('business_verified') is False,
                    'baseline resolution lost its original intent binding')
            if resolution.get('schema')=='hepta.action-resolution.v150.2':
                validate_retired(Path(original_ledger),intent,value['sha256'],resolution,
                                 initial_raw[token+'.retirement-proof.json'])
            else:
                require(resolution.get('schema')=='hepta.action-resolution.v150.1',
                        'baseline resolution schema differs')
    result['initial_auxiliary_original_count']=sum(v is not None for v in initial_raw.values())
    result['initial_auxiliary_absences_not_backfilled']=True
    result['original_baseline_intent_count']=len(entries)
    result['unaccounted_original_intents']=sorted(set(final)-set(entries))
    paths=sorted(run.glob('local-*.request.json'))
    require(len(paths)<=8 and [p.name for p in paths]==
            ['local-%02d.request.json'%n for n in range(1,len(paths)+1)],
            'actual model request sequence differs')
    event_paths=sorted(root.glob('reservation-*.json'))
    require(len(event_paths)<=7 and [p.name for p in event_paths]==
            ['reservation-%03d.json'%n for n in range(1,len(event_paths)+1)],
            'reservation sequence is missing/extra')
    events=[]
    for path in event_paths:
        raw=bound_run_read(path,snapshot.read(path));value=strict_loads(raw)
        common(value,scope,owner,base_sha)
        require(value.get('schema')=='hepta.ledger-reservation-event.v150.1'
                and type(value.get('round')) is int and 1<=value['round']<=len(paths)
                and value.get('phase')=='original_reserve_durable_before_native_tool_frame'
                and value.get('native_dispatch_asserted') is False
                and value.get('execution_success_asserted') is False,
                'reservation event phase/request differs')
        events.append((path.name,sha(raw),value))
    require([v['round'] for _n,_s,v in events]==sorted(set(v['round'] for _n,_s,v in events)),
            'more than one mutation reservation per model round')
    previous_binding=None;head=base_sha;prefix=[];used=0
    call_by_id={c['call_id']:c for c in calls}
    require(len(call_by_id)==len(calls),'duplicate native calls')
    reserved_call_ids=set()
    for number,path in enumerate(paths,1):
        body_raw=bound_run_read(path,snapshot.read(path));body=strict_loads(body_raw)
        boundary_path=root/('round-%02d-boundary.json'%number)
        boundary_raw=bound_run_read(boundary_path,snapshot.read(boundary_path))
        boundary=strict_loads(boundary_raw)
        binding_path=root/('round-%02d-request.json'%number)
        binding_raw=bound_run_read(binding_path,snapshot.read(binding_path))
        binding=strict_loads(binding_raw);binding_sha=sha(binding_raw)
        for value in (boundary,binding):common(value,scope,owner,base_sha)
        request_id=boundary.get('request_id')
        require(isinstance(request_id,str) and re.fullmatch('[0-9a-f]{32}',request_id),
                'round original request identity differs')
        call_id='r%02d_%s'%(number,request_id[:16])
        require(boundary.get('schema')=='hepta.ledger-round-boundary.v150.1'
                and boundary.get('round')==number and boundary.get('allowed_call_id')==call_id
                and boundary.get('previous_request_binding_sha256')==previous_binding
                and boundary.get('reservation_prefix')==prefix
                and boundary.get('reservation_chain_head_sha256')==head
                and exact(boundary.get('intent_inventory'),inventory(entries))
                and boundary.get('inventory_sha256')==sha(canonical(inventory(entries)))
                and boundary.get('boundary')=='original_locked_intents_before_request_file_and_http',
                'request boundary is not its complete earlier reservation prefix')
        exclusions_path=run/('local-%02d.open-replay-exclusions.json'%number)
        clock_path=run/('local-%02d.schema-clock.json'%number)
        exclusions_raw=bound_run_read(exclusions_path,snapshot.read(exclusions_path))
        clock_raw=bound_run_read(clock_path,snapshot.read(clock_path))
        require(binding.get('schema')=='hepta.ledger-request-binding.v150.1'
                and binding.get('round')==number and binding.get('request_id')==request_id
                and binding.get('allowed_call_id')==call_id
                and binding.get('boundary_sha256')==sha(boundary_raw)
                and binding.get('request_file')==path.name and binding.get('request_sha256')==sha(body_raw)
                and binding.get('request_bytes')==len(body_raw)
                and binding.get('exclusions_sha256')==sha(exclusions_raw)
                and binding.get('schema_clock_sha256')==sha(clock_raw)
                and binding.get('binding_before_http_worker_spawn') is True,
                'original request bytes not bound before HTTP admission')
        excluded=strict_loads(exclusions_raw)
        require(excluded.get('schema')=='hepta.open-replay-schema-context.v150.1'
                and excluded.get('round')==number and excluded.get('request_id')==request_id
                and excluded.get('ledger_boundary_sha256')==sha(boundary_raw)
                and excluded.get('authorizes_dispatch') is False,
                'open exclusions lost their original request prefix binding')
        result['rounds'][number]={'request_id':request_id,'allowed_call_id':call_id,
            'boundary_sha256':sha(boundary_raw),'request_binding_sha256':binding_sha,
            'intent_rows':[(entry(entries[n])[0],entries[n]['sha256'],None) for n in sorted(entries)],
            'declared_exclusions':excluded['excluded'],'clock':strict_loads(clock_raw),
            'reservation_prefix_count':len(prefix)}
        for name,digest,event in events:
            if event['round']!=number:continue
            used+=1
            require(event.get('event_number')==used and event.get('previous_event_sha256')==head
                    and event.get('request_id')==request_id
                    and event.get('request_binding_sha256')==binding_sha
                    and event.get('request_sha256')==sha(body_raw) and event.get('call_id')==call_id,
                    'reservation event is not linked to the preceding actual request')
            intent,raw_intent=entry(event['intent']);intent_name=event['intent']['name']
            require(intent_name not in entries and final.get(intent_name)==event['intent'],
                    'reservation is duplicate or absent from final original inventory')
            semantic_name='semantic-'+sha(call_id.encode())+'.json'
            semantic_raw=bound_run_read(run/semantic_name,snapshot.read(run/semantic_name))
            semantic=strict_loads(semantic_raw)
            require(intent.get('schema')=='hepta.action-intent.v150.2'
                    and intent.get('executor_binding')==executor_binding
                    and intent.get('effect_fingerprint')==fingerprint(semantic),
                    'new reservation schema/executor/original semantic fingerprint differs')
            require(event.get('semantic_file')==semantic_name
                    and event.get('semantic_sha256')==sha(semantic_raw)
                    and semantic.get('call_id')==call_id and semantic.get('turn')==scope
                    and event.get('semantic_tool')==semantic.get('semantic_tool') in MUTATIONS
                    and event.get('action_id')==semantic.get('capture_id')==intent.get('action_id')
                    and intent.get('semantic_identity')=={k:scope[k] for k in SCOPE[:-1]}
                    and intent.get('call_id')==call_id and intent.get('semantic_tool')==semantic['semantic_tool']
                    and intent.get('run_dir')==original_run
                    and intent.get('state')=='reserved_before_native_dispatch_result_unknown',
                    'original intent/event/semantic binding differs')
            wire=semantic['wire_call'];argv=wire['argv']
            command=base64.b64decode(argv[6],validate=True)
            require(wire.get('tool')=='shell.exec' and len(argv)==9
                    and argv[:3]==['/usr/bin/python3',
                       '/var/lib/trillionnium/owner-open/phone-local-v150/tool_client_r6.py','execute']
                    and argv[3]=='--action-id' and argv[4]==intent['action_id']
                    and argv[5]=='--command-b64' and argv[7]=='--timeout-ms'
                    and intent.get('wire_tool')=='shell.exec' and intent.get('command_sha256')==sha(command)
                    and event.get('wire_call_canonical_sha256')==sha(canonical(wire)),
                    'original reservation command/native binding differs')
            if call_id in call_by_id:
                require(call_by_id[call_id]==wire,'original reservation differs from native frame')
            else:
                token=intent['action_id']
                resolution_path=state/'evidence/action-ledger'/(token+'.resolution.json')
                resolution_raw=snapshot.read(resolution_path,required=False)
                resolution=None if resolution_raw is None else strict_loads(resolution_raw)
                resolution_rows=[r for r in capture['files'] if
                    r.get('export_relative_path')=='provider-state/evidence/action-ledger/'+token+'.resolution.json']
                require(resolution_raw is not None and len(resolution_rows)==1
                        and resolution_rows[0].get('state')=='captured'
                        and resolution_rows[0].get('source_path')==original_ledger+'/'+token+'.resolution.json'
                        and resolution_rows[0].get('bytes')==len(resolution_raw)
                        and resolution_rows[0].get('sha256')==sha(resolution_raw)
                        and resolution_rows[0].get('eof') is True,
                        'reservation-only resolution is not the original captured file')
                require(resolution is not None
                        and resolution.get('schema')=='hepta.action-resolution.v150.1'
                        and resolution.get('action_id')==token
                        and resolution.get('intent_sha256')==sha(raw_intent)
                        and resolution.get('state')=='known_not_dispatched'
                        and resolution.get('phase')=='provider_before_native_tool_frame'
                        and resolution.get('reason') in {'cancel_before_native_tool_frame',
                                                        'transport_closed_before_native_tool_frame'}
                        and resolution.get('automatic_replay') is False
                        and resolution.get('business_verified') is False,
                        'reservation without native frame is unresolved/UNKNOWN')
                base=str(Path(original_run).parents[2])
                # An explicit original ENOENT is required; a missing export is not absence.
                require(original_absence(capture,base+'/client-receipts/'+token+'.claim.json')
                        and original_absence(capture,base+'/executor-r6/actions/'+token+'/intent.json')
                        and snapshot.read(state.parent/'client-receipts'/(token+'.claim.json'),required=False) is None,
                        'pre-frame cancellation/closure has possible client execution evidence')
                result['reservation_only_actions'].append({
                    'action_id':token,'call_id':call_id,'state':'known_not_dispatched',
                    'reason':resolution['reason'],'automatic_replay':False})
            entries[intent_name]=event['intent']
            require(event.get('inventory_after_sha256')==sha(canonical(inventory(entries))),
                    'reservation event complete after-inventory differs')
            reserved_call_ids.add(call_id);head=digest;prefix.append({'name':name,'sha256':digest})
            result['unaccounted_original_intents']=sorted(set(final)-set(entries))
        previous_binding=binding_sha
    require(used==len(events),'unconsumed reservation evidence')
    result['unaccounted_original_intents']=sorted(set(final)-set(entries))
    require(entries==final,'final original ledger has missing/untracked reservation; UNKNOWN')
    for call in calls:
        semantic=snapshot.json(run/('semantic-'+sha(call['call_id'].encode())+'.json'))
        if semantic.get('semantic_tool') in MUTATIONS:
            require(call['call_id'] in reserved_call_ids,'native mutation lacks original pre-frame reservation event')
    result.update(baseline_sha256=base_sha,reservation_event_count=used,
                  actual_request_count=len(paths),original_inventory_complete=True)
