#!/usr/bin/env python3
"""Read-only independent closure of five actual host-isolated original trees.

No production imports, process creation, phone operations or qualification of a
physical case. Assertions are reconstructed from raw streams, effects, claims,
capture receipts, phase observations and the complete original inventory.
"""
import base64
import hashlib
import json
from pathlib import Path
import re
import stat

IDS = ('NEG-04','NEG-05','NEG-07','NEG-08','NEG-09')
KEYS = ('session_id','profile_id','task_id','turn_id','turn_stream_id')
PROTOCOL = 'trillionnium.owner-open.provider-jsonl.v1'
TERMINAL = {'turn.complete','turn.fail','turn.cancelled'}


def need(value, code):
    if not value:
        raise ValueError('host original verification: '+code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()


class Originals:
    def __init__(self, root, inventory_sha, H):
        self.root, self.H = root, H
        raw = H.pinned(root/'ORIGINAL-FILES.json',inventory_sha)
        manifest = H.strict(raw)
        need(manifest['schema']=='hepta.fixed19.host-lifecycle-original-inventory.v1'
            and manifest['layer']=='host_isolated' and manifest['physical_case_pass'] is False,
            'original inventory scope')
        self.manifest = manifest
        self.rows, self.bodies = {}, {}
        total = 0
        for row in manifest['files']:
            name = row['path']
            need(set(row)=={'path','bytes','sha256'} and type(name) is str
                and re.fullmatch(r'[A-Za-z0-9._/-]{1,1024}',name) and not name.startswith('/')
                and all(x not in ('','.','..') for x in name.split('/')) and name not in self.rows,
                'unique bounded original member')
            body = H.pinned(root/name,row['sha256'])
            need(type(row['bytes']) is int and row['bytes']==len(body),'original byte count')
            self.rows[name], self.bodies[name] = row, body
            total += len(body)
            need(total<=32*1024*1024 and len(self.rows)<=2048,'original pool bound')
        need(total==manifest['bytes'] and len(self.rows)==manifest['files_count'],'inventory aggregate')
        expected_excluded = {cid+'/config/synthetic-only-api.key' for cid in IDS}
        excluded = manifest['excluded']
        need(len(excluded)==5 and {r['path'] for r in excluded}==expected_excluded
            and all(set(r)=={'path','reason'} for r in excluded),'only five synthetic keys excluded')
        seen = set()
        for p in root.rglob('*'):
            st = p.lstat()
            need(not stat.S_ISLNK(st.st_mode),'evidence symlink')
            if stat.S_ISDIR(st.st_mode):
                continue
            need(stat.S_ISREG(st.st_mode) and st.st_nlink==1,'evidence regular single link')
            name = str(p.relative_to(root))
            if name in expected_excluded:
                need(st.st_size==49 and stat.S_IMODE(st.st_mode)==0o600,'excluded synthetic key shape')
            seen.add(name)
        allowed = set(self.rows)|expected_excluded|{'ORIGINAL-FILES.json'}
        need(seen in (allowed,allowed|{'HOST-VERIFICATION.json'}),'complete original tree inventory')
        self.env = self.json('OUTER-ENV.json')
    def raw(self,name):
        need(name in self.bodies,'required original absent: '+name)
        return self.bodies[name]
    def json(self,name):
        return self.H.strict(self.raw(name))
    def relocate(self,value):
        p = Path(value)
        need(p.is_absolute() and str(p)==value and '..' not in p.parts,'original absolute source path')
        for parent in (Path('/work'),Path(self.env['output_root'])):
            try:
                name = str(p.relative_to(parent))
            except ValueError:
                continue
            need(name in self.rows,'source path absent from complete original tree')
            return name
        raise ValueError('source path outside owned evidence tree')
    def bound(self,row):
        need(set(row)=={'path','bytes','sha256'},'exact retained descriptor')
        name = self.relocate(row['path'])
        body = self.raw(name)
        need(row['bytes']==len(body) and row['sha256']==sha(body),'retained descriptor differs')
        return body
    def lines(self,name):
        raw = self.raw(name)
        need(not raw or raw.endswith(b'\n'),'complete JSONL termination')
        lines = raw.splitlines(keepends=True)
        need(len(lines)<=128 and all(0<len(x)<=1024*1024 for x in lines),'frame count/byte bound')
        rows = [self.H.strict(line) for line in lines]
        need(all(v['protocol']==PROTOCOL and type(v['seq']) is int and v['seq']==i
            for i,v in enumerate(rows)),'original protocol sequence')
        return rows
    def beneath(self,prefix,suffix=None):
        return sorted(name for name in self.rows if name.startswith(prefix)
            and (suffix is None or name.endswith(suffix)))
    def recheck(self):
        for name,body in self.bodies.items():
            need(self.H.bounded(self.root/name)==body,'original changed at final bookend')


def capture(o, prefix, label, expected_argv=None):
    base = prefix+label
    joined = o.json(base+'-JOIN.json')
    spawn = o.json(base+'-SPAWN.json')
    intent_raw = o.raw(base+'/INTENT.json')
    intent = o.H.strict(intent_raw)
    child = o.json(base+'/CHILD.json')
    receipt = o.json(base+'/OUTPUT-CAPTURE.json')
    ident = spawn['observed_identity']
    need(type(joined['pid']) is int and joined['pid']>1 and ident==joined['original_identity']
        and ident['pid']==ident['pgid']==ident['sid']==joined['pid']==spawn['pid']==child['pid']
        and ident['ppid']>0 and ident['start_ticks']>0,'original owned child identity')
    need(spawn['argv']==intent['argv'] and (expected_argv is None or intent['argv']==expected_argv)
        and intent['phase']==label and intent['maximum_starts']==1 and intent['automatic_retry'] is False
        and intent['stdin_sha256'] is None and child['source_intent_sha256']==sha(intent_raw),
        'one exact original child start')
    need(joined['actual_direct_child_wait_returned'] is True and joined['returncode']==0
        and joined['group_after']=={'group':joined['pid'],'members':[],'kernel':'ESRCH'}
        and joined['both_output_eof_and_capture_worker_joined'] is True,
        'original actual wait, zero return and empty owned group')
    need(receipt['schema']=='hepta.native-guard.host-output-capture.v1'
        and receipt['phase']==label and receipt['pid']==joined['pid']
        and receipt['source_intent_sha256']==sha(intent_raw)
        and receipt['worker_joined'] is True and receipt['child_wait_returned'] is True
        and receipt['child_returncode']==0 and receipt['stdout_eof'] is True and receipt['stderr_eof'] is True
        and receipt['prefix_only_or_unknown'] is False and receipt['error'] is None
        and receipt['persist_errors']==receipt['pipe_close_errors']==[]
        and receipt['automatic_retry'] is False and receipt['remote_terminal_or_cleanup_proven'] is False,
        'complete capture without unknown or fabricated remote cleanup')
    deadline = receipt['execution_deadline_monotonic']
    need(receipt['child_join_observed_monotonic']<=deadline
        and all(type(v) in (int,float) and v<=deadline for v in receipt['eof_observed_monotonic'].values()),
        'original deadline covered join and EOF')
    for stream in ('stdout','stderr'):
        row = joined['outputs'][stream]
        raw = o.bound(row['captured_original'])
        need(o.bound(row['compatibility_copy'])==raw==o.raw(base+'.'+stream), 'full output compatibility copy')
        need(receipt['captured'][stream]=={'bytes':len(raw),'sha256':sha(raw)},'capture digest/bytes')
        file_row = receipt['files'][stream]
        need(file_row['path']==row['captured_original']['path'] and file_row['bytes']==len(raw)
            and file_row['sha256']==sha(raw) and file_row['metadata']['st_size']==len(raw)
            and file_row['metadata']['st_nlink']==1 and file_row['original_created_inode_bound'] is True,
            'held-inode capture receipt')
    need(joined['capture_transport_sha256']==o.H.CAPTURE_SHA
        and spawn['capture_transport_sha256']==o.H.CAPTURE_SHA,'reviewed transport source binding')
    return joined


def live_original(row, expected_pid):
    raw = base64.b64decode(row['stat_base64'],validate=True)
    need(0<len(raw)<=4096 and sha(raw)==row['stat_sha256'],'phase live proc original digest')
    fields = raw[raw.rfind(b')')+2:].split()
    value = {'pid':int(raw.split(b' ',1)[0]),'ppid':int(fields[1]),'pgid':int(fields[2]),
        'sid':int(fields[3]),'start_ticks':int(fields[19])}
    need(value==row['identity'] and value['pid']==expected_pid and value['pid']>1
        and fields[0] not in (b'Z',b'X'),'actual live original phase identity')


def case(o, cid, generation, input_sha, config):
    p = cid+'/'
    result = o.json(p+'RESULT.json')
    need(result['case_id']==cid and result['layer']=='host_isolated' and result['status']=='PASS'
        and result['error'] is None and result['input_manifest_sha256']==input_sha
        and result['phone_calls']==result['real_model_requests']==result['real_native_host_calls']==0
        and result['fixed19_whole_case_closed'] is False and result['deployment_source_seal_sha256'] is None
        and result['future_deployment_binding_qualified'] is False
        and result['bound_server_cleanup_branch_qualified'] is False
        and result['physical_qualification']=='NOT_ESTABLISHED_BY_THIS_HOST_SAMPLE'
        and all(result[key]==value for key,value in generation.items()),'case identity and host-only scope')
    need(result['checks'] and all(r['passed'] is True for r in result['checks']),'case runtime assertions')
    resources = result['resources']
    before, after = resources['before'], resources['after']
    need(before['fd_count']==after['fd_count'] and before['thread_count']==after['thread_count']
        and 0<=resources['elapsed_seconds']==after['monotonic']-before['monotonic']<90
        and result['model_usage'] is None and result['model_cost'] is None,'bounded resources and honest usage')
    fixture_cfg = o.json(p+'config/config.json')
    changed = {k for k in set(config)|set(fixture_cfg) if config.get(k)!=fixture_cfg.get(k)}
    need(changed=={'endpoint','api_key_file','model'}
        and fixture_cfg['endpoint']=='http://127.0.0.1:18099/v1/chat/completions'
        and fixture_cfg['api_key_file']=='/work/'+p+'config/synthetic-only-api.key'
        and fixture_cfg['model']=='synthetic-fixture-no-real-inference','only three fixture configuration overrides')
    declaration = o.json(p+'config/FIXTURE-DECLARATION.json')
    need(declaration['slot_cleanup_binding_supplied'] is False
        and declaration['bound_server_cleanup_branch_qualified'] is False
        and declaration['real_model_requests']==declaration['phone_calls']==0,'optional cleanup branch scope')
    wrapper = o.json(p+'ORIGINAL-TURN.json')
    start = wrapper['frame']
    tx,rx = o.lines(p+'original-transport.tx.jsonl'),o.lines(p+'original-transport.rx.jsonl')
    need(tx and tx[0]==start and start['kind']=='turn.start' and start['seq']==0,'one original start frame')
    scope = {k:start['turn'][k] for k in KEYS}
    owner_sha = sha(start['turn']['user_input'].encode())
    need(all(type(v) is str and v for v in scope.values()),'fresh host scope')
    state = p+'config/state/evidence/'
    claim_key = sha(json.dumps([scope[k] for k in KEYS[:-1]],separators=(',',':')).encode())
    claim_name = state+'claims/'+claim_key
    claim = o.json(claim_name)
    need(claim['identity']==scope and claim['request_sha256']==owner_sha
        and claim['state']=='accepted_no_redispatch','actual consumed original claim')
    run = str(Path(o.relocate(claim['run_dir']+'/terminal.json')).parent)+'/'
    need(run.startswith(state) and len(o.beneath(state+'claims/'))==2,'exact owner plus retained seed claims')
    need(o.json(run+'health-contract.json')=={'status':'no_health_contract'},'ordinary business channel')
    incoming,outgoing = o.lines(run+'provider-in.jsonl'),o.lines(run+'provider-out.jsonl')
    need(incoming and incoming[0]==start,'persisted original provider start')
    terminal,business = o.json(run+'terminal.json'),o.json(run+'business-outcome.json')
    expected = 'turn.cancelled' if cid in ('NEG-08','NEG-09') else 'turn.fail'
    terminals = [v for v in outgoing if v['kind'] in TERMINAL]
    need(terminal['kind']==expected and terminal['claimed'] is True and len(terminals)==1
        and terminals[0]['kind']==expected and business['business_verified'] is False
        and business['emitted_protocol_terminal']==expected and business['identity']==scope,
        'persisted conservative terminal and no business success')
    need(not any(v['kind']=='turn.complete' for v in outgoing+rx),'no fake completion')
    intervention = o.json(p+'INTERVENTION.json')
    posts = o.beneath(p+'fixture/POST-')
    need({Path(n).name for n in posts}=={'POST-001.json','POST-TERMINAL.json'},'single HTTP POST')
    post = o.json(p+'fixture/POST-001.json')
    http = o.json(p+'fixture/POST-TERMINAL.json')
    need(post['actual_model_inference'] is False and http['actual_model_inference'] is False
        and post['request_id']==http['request_id'],'original synthetic HTTP lifecycle')
    workers = [n for n in o.beneath(state) if re.search(r'/local-[0-9]{2}\.spawned\.json$',n)]
    need(workers==[run+'local-01.spawned.json'],'exactly one actual original HTTP worker')
    spawned,joined = o.json(workers[0]),o.json(run+'local-01.joined.json')
    worker_result = o.json(run+'local-01.worker-result.json')
    slot = o.json(run+'local-01.slot-after.json')
    census = o.json(p+'HTTP-WORKER-CENSUS.json')
    need(spawned['actual_spawn'] is True and spawned['pid']==spawned['process_group']==joined['pid']
        and joined['child_wait_returned'] is True and joined['dedicated_process_group_absent'] is True
        and census=={'group':spawned['pid'],'members':[],'kernel':'ESRCH'}
        and slot['observed'] is True and slot['idle'] is True and slot['slot']['is_processing'] is False,
        'HTTP worker actual join/group absence and independently observed fixture idle')
    need(worker_result['request_id']==post['request_id'] and worker_result['request_sha256']==post['request_sha256']
        and worker_result['request_bytes']==post['request_bytes'] and type(worker_result['returncode']) is int
        and worker_result['automatic_retry'] is False,'worker/HTTP exact original body identity')
    count = 0 if cid in ('NEG-04','NEG-08') else 1
    dispatches = [n for n in o.beneath(state) if re.search(r'/dispatch-[0-9]{3}\.json$',n)]
    semantics = [n for n in o.beneath(state) if re.search(r'/semantic-[^/]+\.json$',n)]
    intents = o.beneath(state+'action-ledger/','.intent.json')
    calls = [v['call'] for v in outgoing if v['kind']=='tool.call']
    need(len(dispatches)==len(semantics)==len(intents)==len(calls)==count
        and not o.beneath(state+'action-ledger/','.resolution.json'), 'exact dispatch/intent count with no fabricated resolution')
    baseline = o.json(run+'ledger-prefix/baseline.json')
    need(baseline['scope']==scope and baseline['owner_request_sha256']==owner_sha
        and baseline['initial_intents']==baseline['initial_inventory']==baseline['initial_auxiliary_originals']==[]
        and baseline['source_sha256']=={n:o.H.PRODUCTION_PINS[n] for n in
            ('ledger_round_evidence.py','provider_phone_local.py','action_ledger.py')},'current-source empty initial ledger prefix')
    if count:
        call = calls[0]
        dispatch,intent = o.json(dispatches[0]),o.json(intents[0])
        counter_intent,counter,receipt = [o.json(p+n) for n in ('COUNTER-INTENT.json','COUNTER.json','COUNTER-RECEIPT.json')]
        argv = call['argv']
        need(call['tool']=='shell.exec' and len(argv)==9 and argv[:4]==['/usr/bin/python3',
            str(o.H.CLIENT),'execute','--action-id'] and argv[5]=='--command-b64' and argv[7:]==['--timeout-ms','60000'],
            'actual typed dispatch only recorded for synthetic counter')
        command = base64.b64decode(argv[6],validate=True)
        need(dispatch['call']==call and dispatch['call_sha256']==sha(json.dumps(call,sort_keys=True,separators=(',',':')).encode())
            and counter_intent['original_call']==call and counter_intent['phone_command_executed'] is False
            and counter_intent['action_id']==intent['action_id']==counter['action_id']==receipt['action_id']==argv[4]
            and intent['semantic_identity']=={k:scope[k] for k in KEYS[:-1]}
            and intent['automatic_replay'] is False and intent['state']=='reserved_before_native_dispatch_result_unknown'
            and intent['command_sha256']==counter['command_sha256']==receipt['command_sha256']==sha(command),
            'same original semantic effect and unresolved action')
        need(counter['value']==receipt['value']==1 and counter['phone_effects']==0
            and counter['synthetic_only'] is True and receipt['phone_command_executed'] is False
            and receipt['counter_sha256']==sha(o.raw(p+'COUNTER.json'))
            and receipt['intent_sha256']==sha(o.raw(p+'COUNTER-INTENT.json'))
            and o.raw(p+'counter-effect.stdout')==b'HOST-ONLY-COUNTER=1\n'
            and o.raw(p+'counter-effect.stderr')==b'','one real disposable host effect and original output')
        delay = '1200' if cid=='NEG-07' else '500' if cid=='NEG-05' else '0'
        counter_join = capture(o,p,'counter-effect',['/usr/bin/python3','-I','-B',
            '/harness/counter_effect.py','--intent','/work/'+p+'COUNTER-INTENT.json','--delay-ms',delay])
        counter_claim = o.json(p+'COUNTER-CLAIM.json')
        need(counter_claim['pid']==receipt['pid']==counter_join['pid'] and counter_claim['can_redispatch'] is False
            and counter_claim['action_id']==argv[4] and counter['committed_monotonic']<=intervention['monotonic'],
            'counter observed before intervention')
        if cid in ('NEG-05','NEG-07'):
            live_original(intervention['counter_live_original'],counter_join['pid'])
        if cid=='NEG-09':
            need(counter_join['monotonic']<=intervention['monotonic']
                and intervention['receipt_sha256']==sha(o.raw(p+'COUNTER-RECEIPT.json'))
                and intervention['result_delivered_to_provider'] is False,'after-effect cancel exact original join fence')
    else:
        need(not o.beneath(p+'COUNTER') and intervention['worker_pid']==spawned['pid']
            and intervention['read_claim_sha256']==sha(o.raw(claim_name)),'pre-dispatch zero effects')
        live_original(intervention['worker_live_original'],spawned['pid'])
    if cid in ('NEG-04','NEG-05'):
        need(intervention['kind']=='transport_close' and len(tx)==len(incoming)==1
            and not any(v['kind'] in TERMINAL for v in rx)
            and 'accepted outcome unknown' in terminal.get('error',''),'lost transport remains explicitly unknown')
    elif cid in ('NEG-08','NEG-09'):
        need(intervention['kind']=='turn.cancel' and len(tx)==len(incoming)==2
            and tx[1]==incoming[1]=={'protocol':PROTOCOL,'kind':'turn.cancel','seq':1}
            and [v['kind'] for v in rx if v['kind'] in TERMINAL]==['turn.cancelled'],
            'one original cancel and acknowledgement')
    else:
        need(intervention['kind']=='unknown_tool_result' and intervention['deadline_seconds']==.2
            and len(incoming)==2 and incoming[1]['kind']=='tool.result' and incoming[1]['status']=='unknown'
            and incoming[1]['call_id']==calls[0]['call_id'] and 'not confirmed completed' in terminal.get('error',''),
            'real deadline reported unknown, not complete')
        fence = o.json(p+'PRE-LATE-FENCE.json')
        wanted = {run+'terminal.json',run+'provider-in.jsonl',run+'provider-out.jsonl',claim_name}
        need(len(fence['originals'])==4 and {o.relocate(r['live_path']) for r in fence['originals']}==wanted
            and fence['automatic_redispatch'] is False,'complete before-late original fence')
        for row in fence['originals']:
            need(o.bound(row['before'])==o.raw(o.relocate(row['live_path'])),'late result rewrote original terminal or stream')
        late = o.json(p+'LATE-ORIGINAL-RESULT-OBSERVATION.json')
        need(late['original_call_id']==calls[0]['call_id'] and late['actual_child_joined'] is True
            and late['automatic_redispatch'] is False and late['observed_after_original_provider_terminal'] is True
            and late['original_counter_receipt_sha256']==sha(o.raw(p+'COUNTER-RECEIPT.json')),
            'late real original retained without semantic replay')
    duplicate_tx = o.lines(p+'explicit-duplicate-stream.tx.jsonl')
    duplicate_rx = o.lines(p+'explicit-duplicate-stream.rx.jsonl')
    need(len(duplicate_tx)==1 and duplicate_tx[0]['kind']=='turn.start'
        and all(duplicate_tx[0]['turn'][k]==scope[k] for k in KEYS[:-1])
        and duplicate_tx[0]['turn']['turn_stream_id']!=scope['turn_stream_id']
        and not any(v['kind']=='tool.call' for v in duplicate_rx)
        and len([v for v in duplicate_rx if v['kind'] in TERMINAL])==1
        and duplicate_rx[-1]['kind']=='turn.fail'
        and 'turn identity already accepted' in duplicate_rx[-1].get('error',''),
        'same semantic identity with new stream rejected before a new effect/request')
    seed_raw = o.raw(p+'config/retained.json')
    daily_join = capture(o,p,'daily-provider',['/usr/bin/python3','-I','-B',
        '/suite/provider/source/daily_phone_local.py','--state','/work/'+p+'config/state',
        '--config','/work/'+p+'config/config.json','--port','18101','--workers','1','--timeout','10',
        '--retained-claims','/work/'+p+'config/retained.json','--retained-claims-sha256',sha(seed_raw)])
    server_join = capture(o,p,'fixture-server',['/usr/bin/python3','-I','-B',
        '/harness/fixture_server.py','--out','/work/'+p+'fixture','--mode',
        'hold' if cid in ('NEG-04','NEG-08') else 'open'])
    ready = o.json(p+'DAILY-READY.original.json')
    need(ready['source_sha256']==o.H.PRODUCTION_PINS['daily_phone_local.py']
        and ready['http_worker_sha256']==o.H.PRODUCTION_PINS['phone_local_http_worker.py']
        and ready['workers']==1 and ready['accepting'] is True
        and ready['pid']==daily_join['pid'] and ready['config_sha256']==sha(o.raw(p+'config/config.json')),
        'actual current daily entry original')
    stopped = o.json(p+'config/state/ready.json')
    need(stopped['accepting'] is False and stopped['pid']==daily_join['pid']
        and stopped['instance']==ready['instance'],'same original daily instance stopped accepting')
    exit_record = o.json(p+'fixture/EXIT.json')
    need(exit_record['post_count']==1 and exit_record['active'] is False
        and exit_record['actual_model_inference'] is False,'fixture joined with one request and no active work')
    need(len(result['owned_processes'])==2+count
        and {x['pid'] for x in result['owned_processes']}=={daily_join['pid'],server_join['pid']}|
            ({counter_join['pid']} if count else set()),'all actual owned children accounted')
    return {'case_id':cid,'qualification_layer':'host_isolated','host_case_pass':True,
        'physical_case_pass':False,'fixed19_whole_case_closed':False,'effect_counter':count,
        'semantic_claim_sha256':sha(o.raw(claim_name)),'terminal_sha256':sha(o.raw(run+'terminal.json')),
        'result_original':o.rows[p+'RESULT.json'],'elapsed_seconds':resources['elapsed_seconds']}


def verify(evidence,inputs,input_sha,inventory_sha,package_root,package_sha,H):
    o = Originals(evidence,inventory_sha,H)
    input_manifest = H.strict(H.pinned(inputs/'INPUT-MANIFEST.json',input_sha))
    generation = input_manifest['host_material_generation']
    need(input_manifest['source_package_manifest_sha256']==package_sha
        and o.manifest['input_manifest_sha256']==input_sha and o.manifest['source_manifest_sha256']==package_sha
        and o.env['input_manifest_sha256']==input_sha and o.env['source_manifest_sha256']==package_sha,
        'original source/input identity')
    need(o.json('INPUT-PINS-BEFORE.json')==o.json('INPUT-PINS-AFTER.json')==input_manifest['files'],
        'readonly complete input originals unchanged')
    outer = o.json('OUTER-RESULT.json')
    need(outer['state']=='ORIGINAL_NAMESPACE_JOINED' and outer['returncode']==0 and outer['error'] is None
        and outer['source_input_pins_preserved'] is True and outer['inner_status']=='PASS'
        and outer['phone_calls']==outer['real_model_requests']==outer['production_changes']==0
        and outer['automatic_retry'] is False and outer['namespace_free_fallback'] is False
        and outer['physical_case_pass'] is False and outer['deployment_binding_qualified'] is False,
        'outer original namespace terminal')
    execution = o.json('EXECUTION-INTENT.json')
    argv = execution['argv']
    need(argv==outer['original_argv'] and execution['maximum_namespace_starts']==1
        and execution['inner_deadline_seconds']==90 and execution['outer_capture_deadline_seconds']==105
        and execution['automatic_retry'] is False and execution['namespace_free_fallback'] is False,
        'one bounded namespace start')
    expected_argv = ['/usr/bin/bwrap','--unshare-user','--uid','0','--gid','0','--unshare-pid',
        '--unshare-net','--unshare-ipc','--unshare-uts','--die-with-parent','--new-session',
        '--ro-bind','/usr','/usr','--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64',
        '--symlink','usr/bin','/bin','--symlink','usr/sbin','/sbin','--proc','/proc','--dev','/dev',
        '--tmpfs','/tmp','--dir','/var/lib/trillionnium/owner-open/phone-local-v150',
        '--ro-bind',o.env['input_root'],'/suite','--ro-bind',o.env['package_root']+'/source','/harness',
        '--bind',o.env['output_root'],'/work','--ro-bind',o.env['input_root']+'/client/tool_client_r6.py',
        '/var/lib/trillionnium/owner-open/phone-local-v150/tool_client_r6.py',
        '--clearenv','--setenv','PATH','/usr/bin:/bin','--setenv','LANG','C.UTF-8',
        '--setenv','PYTHONDONTWRITEBYTECODE','1','--chdir','/work','--cap-drop','ALL','--',
        '/usr/bin/python3','-I','-B','/harness/run_fault_cases.py','--execute-once',
        '--server-sha256','4848e66e94115f64baddc47b575aab53f34d947e7cebc89173f604870504a049',
        '--counter-sha256','53aa97adbba5ad9df7fe9e21a00bd5fadcf41aa3d2211521826e6dd00b80f59b']
    need(argv==expected_argv,
        'network/pid/user/mount isolation and only owned writable mount')
    namespace_join = capture(o,'','namespace',argv)
    need(namespace_join==outer['actual_join'],'original namespace wait/capture proof')
    suite = o.json('RESULT.json')
    ns = suite['actual_namespace']
    need(ns['uid']==ns['gid']==0 and ns['netns']!=o.env['host_netns']
        and ns['mntns']!=o.env['host_mntns'] and ns['pidns']!=o.env['host_pidns']
        and suite['status']=='PASS' and suite['absolute_deadline_expired'] is False
        and 0<=suite['elapsed_seconds']<90 and suite['unstarted_cases']==[]
        and suite['physical_qualification_not_inferred'] is True
        and [r['case_id'] for r in suite['cases']]==list(IDS),'actual isolated five-case suite')
    cfg = H.strict(H.pinned(inputs/'production-config.json',H.CONFIG_SHA))
    rows = [case(o,cid,generation,input_sha,cfg) for cid in IDS]
    for original, row in zip(suite['cases'], rows):
        need(o.bound(original['result'])==o.raw(row['case_id']+'/RESULT.json'),'suite case raw binding')
    o.recheck()
    return {'schema':'hepta.fixed19.r10.host-lifecycle-original-verification.v1',
        'state':'FIVE_CURRENT_SOURCE_HOST_LAYERS_VERIFIED','host_cases':rows,
        'source_manifest_sha256':package_sha,'input_manifest_sha256':input_sha,
        'original_inventory_sha256':inventory_sha,'host_material_generation':generation,
        'host_case_count':5,'phone_calls':0,'physical_case_pass':False,
        'fixed19_whole_cases_closed':False,'deployment_source_seal_sha256':None,
        'future_deployment_binding_qualified':False,'bound_server_cleanup_branch_qualified':False,
        'model_usage':None,'model_cost':None,'automatic_retry':False,
        'limits':{'inner_seconds':90,'outer_seconds':105,'per_original_bytes':4*1024*1024,
            'original_pool_bytes':32*1024*1024,'original_members':2048},
        'physical_followup':'Required separately for each of the five cases; no host counter or fixture is physical evidence.'}
