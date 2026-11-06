"""Rebuild new prompt context with the byte-pinned original receipt parsers.

No mapper, reservation, network, subprocess or model call is invoked. All
derivations are written only below the new collector output directory.
"""
import ast
import base64
import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import sys
from types import SimpleNamespace

from native_journal_audit import strict_loads
from ledger_prefix_audit import canonical, exact, require, sha
from business_fact_recheck import validate_contract


def exclusive(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())


def read_initial_messages(source,user_input):
    tree=ast.parse(source)
    cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Adapter')
    method=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='_run')
    assign=next(n for n in method.body if isinstance(n,ast.Assign)
        and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='messages')
    require(all(isinstance(n,(ast.List,ast.Dict,ast.Constant,ast.Name,ast.Load))
                for n in ast.walk(assign.value)),'initial messages AST has new behavior')
    return eval(compile(ast.Expression(assign.value),'<pinned initial messages>','eval'),
                {'__builtins__':{}},{'user_input':user_input})


def recovery_observations(snapshot,run,values,prefix_rows,executor_binding):
    require(isinstance(values,list),'recovery observation list differs')
    originals={value['action_id']:value for value,_digest,_resolution in prefix_rows}
    seen=set()
    for value in values:
        require(isinstance(value,dict) and set(value)=={
            'action_id','semantic_tool','observed_execution_state','resolved_process_outcome',
            'business_verified','old_effect_replay_forbidden'}
            and value['action_id'] not in seen and value['action_id'] in originals
            and value['semantic_tool']==originals[value['action_id']]['semantic_tool']
            and value['business_verified'] is False and value['old_effect_replay_forbidden'] is True
            and type(value['resolved_process_outcome']) is bool,
            'recovery context has no earlier original intent')
        seen.add(value['action_id']);token=value['action_id']
        if originals[token].get('executor_binding')!=executor_binding:
            original=snapshot.json(run/('recovery-unresolved-'+token+'.json'))
            require(original.get('action_id')==token
                    and original.get('error_type')=='legacy_executor_requires_original_retirement_proof'
                    and value['observed_execution_state']=='legacy_executor_unknown'
                    and value['resolved_process_outcome'] is False,
                    'legacy recovery observation differs')
        elif value['resolved_process_outcome']:
            original=snapshot.json(run/('recovery-inspection-'+token+'.json'))
            receipt=original.get('receipt',{})
            require(receipt.get('action_id')==token
                    and receipt.get('command_sha256')==originals[token]['command_sha256']
                    and receipt.get('terminal') is True
                    and receipt.get('state')==value['observed_execution_state'],
                    'recovery context differs from its original inspection')
        else:
            original=snapshot.json(run/('recovery-unresolved-'+token+'.json'))
            require(original.get('action_id')==token
                    and original.get('error_type')==value['observed_execution_state']
                    and original.get('automatic_retry') is False
                    and original.get('new_effect_allowed') is False,
                    'unknown recovery context differs from original error')
    # These legacy inspection records are individually verified. They do not
    # supply the complete mutation inventory or any app/business success fact.
    return values


def schema_window(provider,allowed,number,parser,apps,aliases,before,after):
    original_time=provider.time
    schemas=[]
    try:
        for moment in (before,after):
            provider.time=SimpleNamespace(monotonic=lambda value=moment:value)
            schemas.append(provider.business_decision_schema(
                allowed,number,parser,apps,excluded_open_aliases=aliases))
    finally:
        provider.time=original_time
    require(exact(schemas[0],schemas[1]),
            'schema clock straddles eligibility boundary; original request retained, proof incomplete')
    return schemas[0]


def rebuild(snapshot,provider_source,seal,config,scope,request,run,calls,results,prefix_audit):
    require(prefix_audit.get('complete_prefix_reconstruction') is True,
            'unverified ledger prefix cannot support a model request')
    trusted=snapshot.out/'history-parser-source';trusted.mkdir(mode=0o700)
    sources={}
    for row in seal['production_files']:
        relative=Path(row['path'])
        require(len(relative.parts)==2 and relative.parts[0]=='source' and relative.suffix=='.py',
                'history parser source path differs')
        raw=snapshot.read(Path(provider_source)/relative.name)
        require(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'history parser source pin differs')
        exclusive(trusted/relative.name,raw);sources[relative.name]=raw
    names={Path(n).stem for n in sources}
    require(not names.intersection(sys.modules),'history parser requires a fresh source namespace')
    before=list(sys.path);sys.path.insert(0,str(trusted));sys.dont_write_bytecode=True
    try:
        provider=importlib.import_module('provider_phone_local')
        local=importlib.import_module('phone_local_tools')
        phone=importlib.import_module('phone_observation_tools')
        tasks=importlib.import_module('task_postconditions')
        derived=snapshot.out/'history-derived';derived.mkdir(mode=0o700)
        def record(path,value):
            require(path.parent==derived,'history parser write escaped private derivation directory')
            exclusive(path,json.dumps(value,ensure_ascii=False,separators=(',',':')).encode())
        parser=local.PhoneLocalTools.__new__(local.PhoneLocalTools)
        phone.PhoneTools.__init__(parser,derived,record)
        parser.apps=local.validate_apps(config['approved_apps'])
        parser.executor=dict(config['executor'])
        parser.allowed_packages={v['component'].split('/')[0] for v in parser.apps.values()}
        parser.local_observations={}
        parser.bind(scope)
        contract=snapshot.json(run/'task-contract.json')
        require(isinstance(contract,dict) and 'contract' in contract,'original business contract required')
        validate_contract(tasks,contract,scope,request,config['approved_apps'])
        resolved_scope=parser.configure_task_app_scope(contract,sha(request))
        require(exact(snapshot.json(run/'task-app-scope.json'),resolved_scope),
                'original task app scope is not reproduced from accepted contract and registry')
        parser.visual_read_constraints=[c for c in contract['contract']['postconditions']
            if c['kind']=='visual_receipt_matches_challenge']
        messages=read_initial_messages(sources['provider_openai_compatible.py'],
                                       request.decode('utf-8',errors='strict'))
        contexts={};original_captures={};prior_calls=[]
        ordered={int(c['call_id'][1:3]):c for c in calls}
        require(len(ordered)==len(calls),'native tool rounds are not unique')
        for number,ledger in prefix_audit['rounds'].items():
            if number>1:
                call=ordered.get(number-1)
                require(call is not None and call['call_id'] in results,
                        'a later model request lacks the preceding original native result')
                decision=snapshot.json(run/('local-%02d.decision.json'%(number-1)))
                require(decision.get('kind')=='tool.call' and decision.get('call_id')==call['call_id'],
                        'prior model decision/native call differ')
                semantic=snapshot.json(run/('semantic-'+sha(call['call_id'].encode())+'.json'))
                require(semantic.get('wire_call')==call and semantic.get('turn')==scope,
                        'prior original semantic/native scope differs')
                parser.calls[call['call_id']]=semantic
                assistant={'role':'assistant','content':decision['summary'],'tool_calls':[
                    {'type':'function','id':call['call_id'],'function':{
                        'name':'shell_exec' if call['tool']=='shell.exec' else 'adb_exec',
                        'arguments':json.dumps({'argv':call['argv']})}}]}
                reply=results[call['call_id']]
                original=snapshot.json(run/('result-'+sha(call['call_id'].encode())+'.json'))
                require(exact(original,reply),'saved original result differs from provider input')
                messages.extend([assistant,{'role':'tool','tool_call_id':call['call_id'],
                    'content':json.dumps(reply,ensure_ascii=False,separators=(',',':'))}])
                prior_calls.append(call)
            # These are the original parser functions, not copied success logic.
            prepared,paths=parser.prepare(messages,provider.model_transcript(messages),number)
            for call_id,image in parser.images.items():
                call=parser.calls[call_id]
                original=snapshot.json(run/('capture-'+call['capture_id']+'.json'))
                ignored={'path','received_monotonic'}
                require(exact({k:v for k,v in image.items() if k not in ignored},
                              {k:v for k,v in original.items() if k not in ignored}),
                        'reparsed screenshot provenance differs from original capture')
                require(Path(original['path']).parent==Path(
                    snapshot.json(run/'ledger-prefix/baseline.json')['original_run_dir'])
                    and snapshot.read(run/Path(original['path']).name)==Path(image['path']).read_bytes(),
                    'reparsed screenshot original bytes/path differ')
                moment=original.get('received_monotonic')
                require(type(moment) in (int,float) and math.isfinite(moment) and moment>=0,
                        'original screenshot monotonic observation missing')
                image['received_monotonic']=moment;original_captures[call_id]=moment
            if parser.latest:
                require(parser.latest['call_id'] in original_captures,'latest screenshot is not original')
                parser.latest['received_monotonic']=original_captures[parser.latest['call_id']]
            body=snapshot.json(run/('local-%02d.request.json'%number))
            actual_context=strict_loads(body['messages'][1]['content'])
            exclusions=provider.open_replay_exclusions(
                ledger['intent_rows'],scope,config['approved_apps'])
            require(exact(exclusions,ledger['declared_exclusions']),
                    'open mask omitted/added an original prefix intent or component alias')
            aliases=sorted({r['alias'] for r in exclusions})
            parser.set_durable_open_exclusions(aliases)
            for value,digest,_resolution in ledger['intent_rows']:
                if value['call_id'] in parser.calls:
                    require(value['effect_fingerprint']==provider.action_effect_fingerprint(
                        parser.calls[value['call_id']]),'original mutation fingerprint differs')
            clock=ledger['clock']
            require(isinstance(clock,dict) and set(clock)=={
                'schema','request_id','round','clock','before','after',
                'latest_image_call_id','latest_received_monotonic'}
                and clock['schema']=='hepta.business-schema-clock.v150.1'
                and clock['request_id']==ledger['request_id'] and clock['round']==number
                and clock['clock']=='CLOCK_MONOTONIC'
                and all(type(clock[k]) in (int,float) and math.isfinite(clock[k])
                        and clock[k]>=0 for k in ('before','after'))
                and clock['before']<=clock['after'],
                'original schema clock window differs')
            latest=parser.latest
            require(clock['latest_image_call_id']==(latest['call_id'] if latest else None)
                    and clock['latest_received_monotonic']==(
                        latest['received_monotonic'] if latest else None),
                    'schema clock lost original current-image binding')
            legacy=schema_window(provider,ledger['allowed_call_id'],number,parser,
                                 parser.task_apps,aliases,clock['before'],clock['after'])
            mobile=provider.mobile_use_schema(legacy)
            content=[]
            for path in paths:
                raw=parser._read_image(Path(path))
                content.append({'type':'image_url','image_url':{
                    'url':'data:image/jpeg;base64,'+base64.b64encode(raw).decode()}})
            recovery=recovery_observations(snapshot,run,
                actual_context.get('prior_action_inspections_no_old_text'),
                ledger['intent_rows'],provider.EXECUTOR_BINDING)
            context={'allowed_call_id':ledger['allowed_call_id'],'round':number,
                'tools_remaining':max(0,8-number),
                'approved_apps':{key:{'label':value['label'],'package':value['component'].split('/')[0],
                                'component':value['component']} for key,value in parser.task_apps.items()},
                'task_app_scope':resolved_scope,
                'prior_action_inspections_no_old_text':recovery,
                'reserved_open_aliases_not_repeatable':aliases,
                'postconditions':contract['contract']['postconditions']}
            expected=provider.compose_local_messages(messages,prepared,parser,context,content,
                config['max_prompt_bytes'],decision_schema=mobile,health_mode=False)
            require(exact(body['messages'],expected),
                    'original owner/history/continuation/current-image prompt is not reproduced')
            require(exact(body['response_format'],{'type':'json_schema','json_schema':{
                'name':'hepta_mobile_use_action','strict':True,'schema':mobile}}),
                'original decoder is not the full per-round eligible tool set')
            contexts[number]={'messages':expected,'legacy_schema':legacy,
                'excluded_open_aliases':aliases,
                'continuation_context':provider.business_continuation(parser,content),
                'task_app_scope':resolved_scope,
                'request_bound_app_scope_verified':True,
                'request_binding_sha256':ledger['request_binding_sha256'],
                'complete_earlier_ledger_prefix_verified':True,
                'original_receipt_history_reparsed':True,
                'schema_clock_endpoints_agree':True}
        return contexts
    finally:
        sys.path[:]=before
        for name in names:
            module=sys.modules.get(name)
            if module is not None and Path(getattr(module,'__file__','')).parent==trusted:
                sys.modules.pop(name,None)
