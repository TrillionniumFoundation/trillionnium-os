#!/usr/bin/env python3
"""Prepare one final NEG component plan using actual frozen/adopted originals.

No phone or process calls are permitted. Preview verifies the complete actual
freeze and calls the exact final Root validator with a discarded historical
identity. Creation reserves a fresh input directory before drawing one nonce.
The actual Root execution and fresh phone/rollback admission remain separate.
"""
import argparse,copy,hashlib,json,os,re,secrets,stat,sys,types
from pathlib import Path
sys.dont_write_bytecode=True
MAC=Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
SOURCE_HOME=MAC/'final-runtime-actual-adoption-source-a1055-r1'
HELPER=MAC/'library-checkpoint02-resume-a1055-r1/restored/integration-review/diagnostic-root-plan-candidate01/source/prepare_diagnostic_root_plan_once.py'
HELPER_PIN={'bytes':35690,'sha256':'4708d037d58fd5b40e2a15210887ce58d9e7d0857ef27057855031591ee7faf9'}
FROZEN=MAC/'native-guard-r10-r1-operator-final-v3-getattr-a1055-r4'
FREEZER_PIN={"bytes":63506,"sha256":"bb0c8f73f465c4d0e1271d79e1dcf9171a260f50fe5b617512c0479209585866"}
CLEANUP_READER={"bytes":37739,"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/owned-unstarted-stage-cleanup-final03-a1055-candidate01/source/verify_owned_unstarted_stage_cleanup_v2.py","sha256":"8558e2ae43dd017cc9bd4ee49cb97922506d90f72c9bbf59c851426191204749"}
CLEANUP_INPUTS={"bytes":705,"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/owned-unstarted-stage-cleanup-final03-a1055-candidate01/cleanup-strong-closure01/INPUTS.json","sha256":"b7c97f7274814773a181ceed9b9552df81b516aab9626acfdf2c9e01293b9379"}
POST_CLEANUP_CURRENT41_READER={"bytes":35246,"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/art-source-a1055-parent-getattr-resume01/rollback_retained_stage_after_cleanup_candidate02/bound01/actual01/verify_postcleanup_current41.py","sha256":"ee42120c420b7684c1986dc0e4b7a05ed0c33604d060574252f45dbc6611b535"}
POST_CLEANUP_CURRENT41_PROOF={"bytes":22415,"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/art-source-a1055-parent-getattr-resume01/rollback_retained_stage_after_cleanup_candidate02/bound01/actual01/POSTCLEANUP-PROOF.json","sha256":"3101f464e956dd931679fe7dc35bab941718f4a265e96efc78813a76178fded7"}
VERIFIER_PIN={'bytes':65591,'sha256':'6a3a9f8278ccf4b29724d9d034b4a349127a77d0adfd4daa8066ef6aa8d6c35b'}
POLICY={'bytes':2667752,'sha256':'69aa6433a11ac4cffb2f1d349cc9f36ec2349a601911c173ebe7d92fff9e0c5b'}
PARENT_POLICY='f8219f9c3ad2e1d16a95fda8d5f0bc7612a31e00c0a661e53bf9a6e921c49d70'
V3HOME=MAC/'native-guard-root-chains-r10-r1/root-r10-neg01-a1055-v3stack01'
V3PLAN={'path':str(V3HOME/'ROOT-PLAN.original.json'),'bytes':4847,'sha256':'a05482b2e5b973de801038613b6448d8ba0aef0fe2dfa38d2936e7bf732f269c'}
V3PREVIOUS={'path':str(V3HOME/'ACTUAL-PREVIOUS-INPUT.json'),'bytes':1434,'sha256':'35cc7f4b24379781dae7f181704218b612d9a42313b7efee9a52d649f37e1099'}
V3BOUNDARY='fd7766538b0ff88bea73ce66e0de4728caf3771f88c8441bb4d2844fb13b6c66'
REVISION='r10-r1-final-a1055-v3getattr04'
LABELS={'NEG-01':'root-r10-neg01-a1055-final04','NEG-02':'root-r10-neg02-a1055-final04'}
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
MAX_OUTPUT=33554432

FINAL03_CAPTURE={'path':str(MAC/'final03-failed-preview-originals-a1055-r2/CAPTURE.json'),
    'bytes':185979,'sha256':'6e65a9cbb99553f2a3f112a52a851bd98edb1b30bb007dab003cb9e6cc6d5c9d'}
FINAL03_NONCE='006ad72b76f813f9ded1b045e961dbf4'
FINAL03_JOB='1a1af80c9a9-fc05-692c'
FINAL03_CASE=MAC/'native-guard-root-chains-r10-r1/root-r10-neg01-a1055-final03'
FINAL03_INPUT=MAC/'native-guard-root-inputs-r10-r1/root-r10-neg01-a1055-final03'
FINAL03_PHASES=(('prepare-material',9453),('host-stage-material',9469),
    ('phone-push-material',9486),('phone-copy-material',9504),
    ('phone-push-stage-source',9511),('phone-copy-stage-source',9523),
    ('phone-stage',9545),('sender-preview',9916))
KEYS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')

def need(ok,message):
    if not ok:raise ValueError(message)
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def initial_read(path,expected):
    path=Path(path);need(path.is_absolute() and path.resolve(strict=True)==path,'canonical helper source')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);before=[getattr(a,k) for k in KEYS]
        need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==expected['bytes'],'exact helper type and size')
        with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(expected['bytes']+1)
        need(pin(raw)==expected and before==[getattr(os.fstat(fd),k) for k in KEYS]
             ==[getattr(path.lstat(),k) for k in KEYS],'helper changed')
        return raw
    finally:os.close(fd)
def relative(name):
    p=Path(name);need(type(name)is str and not p.is_absolute() and '..' not in p.parts
                     and str(p)==name and name not in ('','.'),
                     'canonical frozen relative member');return p
def load_helpers():
    raw=initial_read(HELPER,HELPER_PIN)
    h=types.ModuleType('exact_diagnostic_plan_helpers');h.__file__=str(HELPER)
    exec(compile(raw,str(HELPER),'exec'),h.__dict__)
    return h,raw

def verify_frozen(h,o,freeze_row):
    need(freeze_row['path']==str(FROZEN/'FREEZE-RESULT.json'),'one selected actual final freeze')
    raw=o.read(freeze_row);f=h.strict(raw)
    need(f['schema']=='hepta.final-component.actual-host-freeze-result.v1'
         and f['state']=='FROZEN_FOR_NEG01_THEN_NEG02_NOT_QUALIFIED'
         and f['all_inputs_bookended'] is True and f['all_output_files_read_back'] is True
         and f['phone_calls']==f['native_submissions']==f['policy_loads']==0
         and f['full19_qualified'] is False and f['production_ready'] is False
         and f['rollback_admission_is_separate_required_gate'] is True
         and f['output']==str(FROZEN) and f['actual_policy']==POLICY,
         'complete actual final candidate required')
    source=f['source'];need({k:source[k] for k in ('bytes','sha256')}==FREEZER_PIN
         and source['path']==str(SOURCE_HOME/'source/freeze_final_component_runtime_v6.py'),
         'exact reviewed final freeze source required')
    need(type(f['actual_input_files'])is dict and f['actual_input_files'],'complete actual input identities required')
    for path,row in f['actual_input_files'].items():
        need(path==row['path'] and set(row)=={'path','bytes','sha256','metadata'},'actual input identity shape')
        o.read({k:row[k] for k in ('path','bytes','sha256')})
        need(o.rows[path]==row,'final freezer actual input no longer has its original full9 identity')
    need(source['path'] in f['actual_input_files'],'executed final freezer source omitted from input bookends')
    outputs={}
    for name,row in f['files'].items():
        need(row['path']==str(FROZEN/relative(name)),'frozen member left selected output')
        outputs[name]=o.read(row)
    need(pin(outputs['FINAL-FREEZER-SOURCE.original.py'])==FREEZER_PIN,'frozen executed source differs')
    intent_raw=o.raw(FROZEN/'FREEZE-INTENT.json',1048576);intent=h.strict(intent_raw)
    need(intent=={'schema':'hepta.final-component.freeze-intent.v1','source':FREEZER_PIN,'output':str(FROZEN),
        'actual_adoption':f['actual_adoption'],'actual_policy':POLICY,'phone_calls':0,'automatic_retry':False},
        'complete actual freeze intent differs')
    need(sum(map(len,outputs.values()))==f['payload_bytes'] and len(intent_raw)==f['intent_bytes']
         and len(raw)==f['result_bytes']
         and f['payload_bytes']+len(intent_raw)+len(raw)==f['complete_directory_bytes']<=MAX_OUTPUT
         and f['maximum_complete_directory_bytes']==MAX_OUTPUT,
         'complete final directory exceeds reviewed32MiB or accounting differs')
    required={'runtime/MANIFEST.json':37,'root-chain/SOURCE-MANIFEST.json':3,'shared/SHARED-MATERIALS.json':17}
    for name,count in required.items():
        m=h.strict(outputs[name]);rows=m['files'];need(len(rows)==count and len({r['path'] for r in rows})==count,
                                                     'complete exact frozen member count')
        for row in rows:
            body=outputs[str(Path(name).parent/relative(row['path']))]
            need(pin(body)=={k:row[k] for k in ('bytes','sha256')},'complete frozen source member differs')
    runtime=h.strict(outputs['runtime/MANIFEST.json']);root=h.strict(outputs['root-chain/SOURCE-MANIFEST.json'])
    checks=h.strict(outputs['HOST-VALIDATION.json'])
    need(checks==f['checks'] and checks['case_order']==['NEG-01','NEG-02']
         and checks['adoption_verifier']==VERIFIER_PIN and checks['actual_policy']==POLICY
         and checks['native_history_count']==9 and checks['non_native_branch_count']==2
         and checks['component_history_roles']==33 and checks['baseline_inventory_roots']==41
         and checks['historical_v3_inventory_roots']==39
         and checks['native_chain_cap']==11 and checks['component_role_cap']==39
         and checks['fixture_root_cap']==13 and checks['inventory_roots_after_two_cases']==47
         and checks['same_fifteen_production_bytes'] is True and checks['same_configuration_and_service_bytes'] is True
         and checks['parent_seven_full_template_inverses_retained'] is True,
         'actual complete final source/history contract differs')
    need(runtime['revision']==root['revision']==REVISION and runtime['diagnostic_only'] is False
         and root['diagnostic_only'] is False and root['root_fixture_phases']==['setup','before-guard','after-guard']
         and runtime['current_combination_sha256']==root['current_combination_sha256']==f['combination']['sha256']
         and f['runtime_manifest']==f['files']['runtime/MANIFEST.json']
         and f['root_chain_manifest']==f['files']['root-chain/SOURCE-MANIFEST.json']
         and f['combination']==f['files']['COMBINATION.json'],'one exact actual tuple required')
    combo=h.strict(outputs['COMBINATION.json'])
    need(combo['live_policy_sha256']==POLICY['sha256'],'actual policy differs in final combination')
    actual_adoption=o.read(f['actual_adoption'])
    need(actual_adoption==outputs['POLICY-ADOPTION.original.json'],'actual adoption original differs from retained bytes')
    row=next(r for r in root['files'] if r['path']=='source/run_component_root_once.py')
    entry=f['files']['root-chain/'+row['path']];entry_raw=o.read(entry)
    return f,outputs,entry,entry_raw

def selected_context(h,o,args,freeze_row):
    f,outputs,entry,entry_raw=verify_frozen(h,o,freeze_row)
    label=LABELS[args.case];directory,out=h.require_unused(label)
    previous_row={'path':args.previous,'bytes':args.previous_bytes,'sha256':args.previous_sha256}
    h.descriptor(previous_row);previous_raw=o.read(previous_row);previous=h.strict(previous_raw)
    home=Path(previous_row['path']).parent
    need(Path(previous_row['path'])==home/'ACTUAL-PREVIOUS-INPUT.json'
         and home.parent==MAC/'native-guard-root-chains-r10-r1'
         and previous['known_all_dispatched_tools_confirmed_terminal'] is True,'actual closed Root predecessor required')
    if args.case=='NEG-01':
        need(previous_row==V3PREVIOUS and home==V3HOME,'first final case must follow exact actual closed v3')
        parent_raw=o.read(V3PLAN)
    else:
        need(home.name==LABELS['NEG-01'],'second final case must follow this exact final NEG01 namespace')
        parent_raw=o.raw(home/'ROOT-PLAN.original.json',1048576)
    parent=h.strict(parent_raw)
    need(parent['case_id']=='NEG-01' and parent['nonce']!=None and parent['boot_id']==BOOT
         and previous['identity']['profile_id']=='owner-open'
         and previous['identity']['session_id']==parent['session_id'],
         'actual parent plan/session/profile differs')
    if args.case=='NEG-01':
        need(parent['live_policy_sha256']==PARENT_POLICY
             and previous['late_boundary']['sha256']==V3BOUNDARY
             and previous['component_qualified'] is False
             and previous['terminal']=={'status':'provider_failed'},'actual v3 parent state differs')
    else:
        need(parent['live_policy_sha256']==POLICY['sha256'] and parent['package']==f['runtime_manifest']
             and parent['source_package']==f['root_chain_manifest']
             and parent['policy_adoption']==f['actual_adoption']
             and previous['component_qualified'] is True and previous['terminal']=={'status':'completed'},
             'current qualified NEG01 must precede NEG02')
    owner=o.read(parent['request'])
    need(len(owner)==317 and owner.count(parent['nonce'].encode())==1 and b'\0' not in owner,
         'exact retained public request required')
    boundary_raw=o.raw(home/'LATE-BOUNDARY.original.json',16777216)
    descriptor_raw=o.raw(home/'LATE-BOUNDARY-DESCRIPTOR.json',1048576)
    descriptor=h.strict(descriptor_raw);boundary=h.strict(boundary_raw)
    need(previous['late_boundary']==descriptor
         and {k:descriptor[k] for k in ('bytes','sha256')}==pin(boundary_raw)
         and boundary['nonce']==parent['nonce'] and boundary['scope']==previous['identity'],
         'complete actual predecessor originals differ')
    prior_descriptor={'path':str(home/'LATE-BOUNDARY-DESCRIPTOR.json'),**pin(descriptor_raw)}
    prior_original={'path':str(home/'LATE-BOUNDARY.original.json'),**pin(boundary_raw)}
    shared=f['files']['shared/SHARED-MATERIALS.json']
    updates={'case_id':args.case,'package':f['runtime_manifest'],'source_package':f['root_chain_manifest'],
        'shared_materials':shared,'shared_root':str(FROZEN/'shared'),'artifacts':f['files']['ARTIFACTS.json'],
        'policy_adoption':f['actual_adoption'],'live_policy_sha256':POLICY['sha256'],
        'previous':previous_row,'prior_boundary_descriptor':prior_descriptor,'prior_boundary_original':prior_original}
    nonces=set(h.CONSUMED_NONCES)|{parent['nonce']}
    for name,body in outputs.items():
        if re.fullmatch(r'retained-history/native-\d\d/boundary.original.json',name):
            nonces.add(h.strict(body)['nonce'])
    for b in h.strict(outputs['runtime/MANIFEST.json'])['non_native_sidebranches']:nonces.add(b['nonce'])
    return {'directory':directory,'out':out,'parent':parent,'parent_raw':parent_raw,'owner':owner,
        'freeze':f,'outputs':outputs,'entry':entry,'root_raw':entry_raw,'updates':updates,
        'prior_descriptor':descriptor,'selected_label':label,'consumed_nonces':nonces,
        'actual_previous':previous_row,'case_id':args.case}

def create_plan(h,o,c,source_row,source_raw,freeze_row,preview):
    directory,out=h.require_unused(c['selected_label'])
    need(directory==c['directory'] and out==c['out'],'selected host namespaces changed')
    _final03_directories(h,o);o.recheck();os.umask(0o077);h.reserve(directory);attempts=0;generated=0
    try:
        h.put(directory/'GENERATION-INTENT.json',h.enc({
            'schema':'hepta.final-component.root-plan-generation-intent.v1','source':source_row,
            'actual_freeze':freeze_row,'case_id':c['case_id'],'label':c['selected_label'],
            'prior':c['actual_previous'],'maximum_nonce_generations':1,'automatic_retry':False,
            'phone_calls':0,'root_executions':0}))
        attempts=1;nonce=secrets.token_hex(16);generated=1
        need(re.fullmatch('[0-9a-f]{32}',nonce) and nonce not in c['consumed_nonces'],
             'one generated nonce collides with a retained identity; no retry')
        identity=h.put(directory/'IDENTITY.original.json',h.enc({
            'schema':'hepta.final-component.root-plan-identity.v1','label':c['selected_label'],'case_id':c['case_id'],
            'nonce':nonce,'generation_count':1,'automatic_retry':False,'phone_calls':0}))
        parent=c['parent'];old=c['owner'];owner=old.replace(parent['nonce'].encode(),nonce.encode())
        need(len(owner)==317 and owner.count(nonce.encode())==1
             and owner.replace(nonce.encode(),parent['nonce'].encode())==old,
             'only the existing public request nonce may change')
        request={'path':str(directory/'REQUEST.txt'),**pin(owner)}
        plan=copy.deepcopy(parent);plan.update(c['updates'])
        plan.update(label=c['selected_label'],nonce=nonce,out=str(out),request=request)
        allowed={'case_id','label','nonce','out','request','package','source_package','shared_materials','shared_root',
            'artifacts','policy_adoption','live_policy_sha256','previous','prior_boundary_descriptor','prior_boundary_original'}
        need(set(plan)==set(parent) and all(plan[k]==parent[k] for k in parent if k not in allowed),
             'unreviewed parent plan field changed')
        h.put(directory/'REQUEST.txt',owner)
        actual=h.validate_current_plan(o,h.enc(plan),c);o.recheck()
        plan_row=h.put(directory/'ROOT-PLAN.json',h.enc(plan))
        h.put(directory/'PREPARE.original.py',source_raw)
        evidence=h.put(directory/'PREPARATION-EVIDENCE.json',h.enc({
            'schema':'hepta.final-component.actual-root-plan-preparation.v1','source':source_row,
            'actual_freeze':freeze_row,'actual_previous':c['actual_previous'],'identity_original':identity,
            'historical_preview':preview,'actual_pure_validation':actual,
            'retained_host_preparation_failure':c['retained_host_preparation_failure'],
            'retained_unstarted_stage':c['retained_unstarted_stage'],
            'retained_final03_preview_failure':c['retained_final03_preview_failure'],
            'cleanup_and_postcleanup_current41':c['cleanup_and_postcleanup_current41'],
            'changed_fields':sorted(k for k in parent if plan[k]!=parent[k]),'only_public_request_nonce_changed':True,
            'actual_input_files':copy.deepcopy(o.rows),'complete_tuple_originals_bookended':True,
            'private_draft_read_scope':'exact pinned Root.validate_plan only','private_draft_bytes_or_digest_output':False,
            'new_nonces':1,'phone_calls':0,'root_executions':0,'automatic_retry':False,
            'fresh_phone_admission_verified':False,'latest_head_rollback_admission_verified':False,
            'fixed19_credit':False}))
        o.recheck()
        result={'schema':'hepta.final-component.root-plan-preparation-result.v1',
            'state':'ONE_FINAL_COMPONENT_PLAN_PREPARED_NO_PHONE_EXECUTION','source':source_row,'plan':plan_row,
            'entry':c['entry'],'evidence':evidence,'actual_freeze':freeze_row,'actual_previous':c['actual_previous'],
            'case_id':c['case_id'],'label':c['selected_label'],'nonce':nonce,
            'retained_host_preparation_failure':c['retained_host_preparation_failure'],
            'retained_unstarted_stage':c['retained_unstarted_stage'],
            'retained_final03_preview_failure':c['retained_final03_preview_failure'],
            'cleanup_and_postcleanup_current41':c['cleanup_and_postcleanup_current41'],
            'actual_pure_validate_plan_passed':True,'fresh_phone_and_latest_head_rollback_admission_required':True,
            'phone_calls':0,'root_executions':0,'automatic_retry':False,'fixed19_credit':False,
            'exact_argv':['/usr/bin/python3','-I','-B',c['entry']['path'],'--plan',plan_row['path'],
                          '--plan-sha256',plan_row['sha256'],'--execute-root-chain-once']}
        result_row=h.put(directory/'RESULT.json',h.enc(result));return dict(result,result=result_row)
    except BaseException as error:
        h.put(directory/'PREPARATION-FAILURE.json',h.enc({
            'schema':'hepta.final-component.root-plan-preparation-failure.v1',
            'state':'HOST_GENERATION_RETAINED_NO_AUTOMATIC_RETRY','source':source_row,'label':c['selected_label'],
            'error_type':type(error).__name__,'nonce_generation_count':generated,'nonce_generation_attempts':attempts,
            'phone_calls':0,'root_executions':0,'automatic_retry':False}))
        raise

def verify_retained_host_preparation_failure(h,o):
    """Retain the fully joined first host phase; never infer from a missing log."""
    directory=Path("/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-final01")
    rows=[{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-final01/CHAIN-INTENT.json","bytes":365,"sha256":"390227b12bb9f103d2d973497ce8218ad6024f147d4e0c1e5b26efa2b100bcf4"},{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-final01/ROOT-PLAN.original.json","bytes":4882,"sha256":"a3cc4f25b9af304574c5d3b88b34b52135f68e2cdc0f6ed0492c7083d9fce4b8"},{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-final01/ROOT-FAILURE.json","bytes":1503,"sha256":"c2a105364e7be75f85ce40a899ac2d22745be85d84b2d634f1e497cef72e2a16"},{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-final01/prepare-material/INTENT.json","bytes":4395,"sha256":"b91bc358938c510beb71422ac1dcfe2da89062690f730c7b0a3c9d402b00b504"},{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-final01/prepare-material/RESULT.json","bytes":797,"sha256":"c1fa4f095a1633e88210fa3ab370135cc85a2cbaa0a51a19aaa7f54f9b8611af"},{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-final01/prepare-material/stdout.original","bytes":0,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-final01/prepare-material/stderr.original","bytes":1150,"sha256":"d5e6e7e26b6b952f5e2940ca38d95862cdfe5e45b6f7a9dd152456d36021f00e"},{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-final01/prepare-material/CHILD.json","bytes":906,"sha256":"cbf0caba780994fd4cbbac7197c398ae20a97de984548ec215d2df92420c2e55"},{"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-a1055-final01/prepare-material/OUTPUT-CAPTURE.json","bytes":2514,"sha256":"dc668bfaeb802d3300e7e470393336928f18a0752353689e7011b32f5e6b092a"}]
    bodies={row['path']:o.read(row) for row in rows}
    need(sorted(str(p) for p in directory.rglob('*') if p.is_file())
         ==sorted(bodies),'complete original rejected host attempt file set changed')
    get=lambda name:h.strict(bodies[str(directory/name)])
    failure=get('ROOT-FAILURE.json');child=get('prepare-material/RESULT.json')
    capture=get('prepare-material/OUTPUT-CAPTURE.json')
    old_plan=get('ROOT-PLAN.original.json')
    need(failure['state']=='FAILED_OR_UNKNOWN_ORIGINALS_PRESERVED_NO_AUTOMATIC_CONTINUATION'
         and failure['detail']=='original phase failed; no replay: prepare-material'
         and failure['steps']==[child] and failure['root_fixture_attempts']==[]
         and failure['host_cleanup']=={'host_children':[],'stream_cleanup_errors':[]}
         and failure['model_requests']==failure['policy_changes']==failure['signals_sent_by_coordinator']==0,
         'only the exact fully closed first host preparation failure can be superseded')
    need(child['phase']=='prepare-material' and child['state']=='ORIGINAL_HOST_CHILD_JOINED'
         and child['returncode']==1 and child['pid']==26888 and capture['pid']==child['pid']
         and capture['child_returncode']==1 and capture['child_wait_returned'] is True
         and capture['stdout_eof'] is True and capture['stderr_eof'] is True
         and capture['worker_joined'] is True and capture['error'] is None
         and capture['persist_errors']==capture['pipe_close_errors']==[]
         and capture['signals_sent']==0 and capture['prefix_only_or_unknown'] is False
         and bodies[str(directory/'prepare-material/stdout.original')]==b'',
         'original child wait, streams or capture ownership is incomplete')
    need(old_plan['nonce']=='43fc09e1582bb522f95a68b6eb31f939'
         and old_plan['label']=='root-r10-neg01-a1055-final01',
         'exact rejected host identity required; never recycle it')
    return {'state':'EXACT_HOST_PREPARATION_FAILURE_RETAINED_BEFORE_PHONE_PHASE',
        'root_failure':next(r for r in rows if r['path']==str(directory/'ROOT-FAILURE.json')),
        'original_child_wait_returncode':1,'original_stdout_stderr_complete':True,
        'retired_host_only_nonce':old_plan['nonce'],'host_label':old_plan['label'],
        'native_case_credit':0,'same_phone_head_unchanged_by_this_host_failure':True}


def verify_retained_stage_history(h,o,c):
    """Read historical closure originals; this is never fresh phone admission."""
    d=MAC/'expired-unstarted-stage-retention-final02-a1055-candidate01'
    closure_row={'path':str(d/'strong-closure01/CLOSURE.json'),'bytes':65567,
                 'sha256':'38a93ca265e0bb1b35ae80ab8309f389991e8c9a300700508e09841df3313e76'}
    closure_raw=o.read(closure_row);closed=h.strict(closure_raw)
    need(closed['schema']=='hepta.expired-unstarted-stage.host-closure.v1'
         and closed['state']=='EXPIRED_UNSTARTED_STAGE_RETAINED'
         and closed['label']=='root-r10-neg01-a1055-final02'
         and closed['nonce']=='d11e31c9ac94920d47998ca88a97e98f'
         and closed['boot_id']==BOOT,'one exact historical retained unstarted scope')
    for row in closed['all_host_originals']:
        o.read({k:row[k] for k in ('path','bytes','sha256')})
        need(o.rows[row['path']]==row,'complete historical closure original full9 changed')
    need(closed['facts']['original_Mac_sender_wait']=='UNKNOWN_UNCHANGED'
         and closed['facts']['sender_Send_count']==0
         and closed['facts']['original_draft_restored_once'] is True
         and closed['facts']['new_native_case_count']==closed['facts']['new_component_role_generation_count']
             ==closed['facts']['new_fixture_count']==closed['facts']['fixed19_credit']==0,
         'historical failure may grant no native/role/fixture credit or repair old wait')
    outputs=c['outputs'];manifest=h.strict(outputs['runtime/MANIFEST.json'])
    root_manifest=h.strict(outputs['root-chain/SOURCE-MANIFEST.json'])
    binding=manifest['retained_unstarted_stage']
    need(type(binding) is dict and binding==root_manifest['retained_unstarted_stage']
         and binding['nonce']==closed['nonce'] and binding['label']==closed['label']
         and binding['closure']==pin(closure_raw),'same exact typed historical stage binding')
    selected=[row for row in manifest['files'] if row['sha256']==binding['reader_source_sha256']]
    need(len(selected)==1 and selected[0]['path'].startswith('reference/'),'one exact added typed reader')
    reader_row=selected[0];reader_raw=outputs['runtime/'+reader_row['path']]
    need(pin(reader_raw)=={k:reader_row[k] for k in ('bytes','sha256')},'typed reader complete source identity')
    reader=types.ModuleType('exact_reviewed_retained_stage_history')
    reader.__file__=str(FROZEN/'runtime'/reader_row['path'])
    reader.__reviewed_source_sha256__=pin(reader_raw)['sha256']
    exec(compile(reader_raw,reader.__file__,'exec'),reader.__dict__)
    root=types.ModuleType('exact_reviewed_current_root_for_history')
    root.__file__=c['entry']['path']
    exec(compile(c['root_raw'],root.__file__,'exec'),root.__dict__)
    late=root.prior_reader(FROZEN/'runtime',manifest)
    original=outputs['retained-history/native-00/inventory.original.json']
    prior_descriptor=manifest['v3_runtime_diagnostic_ancestor']['inventory']
    need(pin(original)=={k:prior_descriptor[k] for k in ('bytes','sha256')}
         and pin(original)=={'bytes':1182289,
          'sha256':'bd880b6dbfe1a870eab9d0dc6e3916e8bc539d115975c5b983c65742fbab6242'},
         'complete exact actual v3 old39 inventory source')
    def exact_prior(row):
        need(row==prior_descriptor,'only the exact historical old39 descriptor can be read')
        return original
    state=reader.verify_retained_unstarted_stage(read_pinned=exact_prior,
                                                validate_inventory=late.inventory_value)
    actual_row={'path':str(d/'execution-import01/packet/AFTER-INVENTORY.json'),'bytes':1206630,
                'sha256':'fe8f37a3e4fb5ce46514e14c80b4e5ef8986d4653a8ad4a991bc463caaf78aa6'}
    actual_raw=o.read(actual_row)
    need(state['binding']==binding and state['inventory_raw']==actual_raw
         and len(state['inventory']['roots'])==41
         and len(state['private_roots'])==2
         and state['original_sender_wait']=='UNKNOWN_UNCHANGED',
         'complete actual41 reconstruction and new runtime typed binding')
    return {'closure':closure_row,'binding':binding,'actual_inventory_original':actual_row,
        'consumed_nonce':closed['nonce'],'original_sender_wait':'UNKNOWN_UNCHANGED',
        'new_native_case_count':0,'new_component_role_generation_count':0,'new_fixture_count':0,
        'fixed19_credit':0,'historical_evidence_only':True,'fresh_phone_admission_claimed':False}



def _full9(value):
    need(type(value) is list and len(value)==len(KEYS)
         and all(type(x) is int for x in value),'complete integer full9 identity required')
    return value


def _exact3(row):
    return {key:row[key] for key in ('path','bytes','sha256')}


def _final03_directories(h,o):
    capture=h.strict(o.read(FINAL03_CAPTURE));rows=capture['host_directory_bookends']
    need(type(rows) is list and len(rows)==17 and len({r['path'] for r in rows})==17,
         'complete final03 directory census required')
    for row in rows:
        need(set(row)=={'path','metadata','names'},'final03 directory observation shape')
        path=Path(row['path']);before=_full9(row['metadata'])
        need((path==FINAL03_CASE or FINAL03_CASE in path.parents or path==FINAL03_INPUT)
             and path.resolve(strict=True)==path and stat.S_ISDIR(before[2])
             and row['names']==sorted(set(row['names']))
             and all(type(n) is str and n not in ('','.','..') and '/' not in n for n in row['names']),
             'one exact canonical final03 host directory')
        need([getattr(path.lstat(),k) for k in KEYS]==before
             and sorted(os.listdir(path))==row['names']
             and [getattr(path.lstat(),k) for k in KEYS]==before,
             'final03 original directory identity or complete names changed')
    return rows


def _verify_final03_phase(h,name,bodies,rows,expected_pid):
    directory=FINAL03_CASE/name
    getraw=lambda leaf:bodies[str(directory/leaf)]
    intent_raw=getraw('INTENT.json');intent=h.strict(intent_raw)
    child_raw=getraw('CHILD.json');child=h.strict(child_raw)
    output=h.strict(getraw('OUTPUT-CAPTURE.json'));result=h.strict(getraw('RESULT.json'))
    expected_rc=1 if name=='sender-preview' else 0
    need(intent['schema']=='hepta.native-guard.root-host-command.v1'
         and intent['phase']==name and intent['maximum_starts']==1
         and intent['automatic_retry'] is False and intent['signals_on_timeout'] is False
         and intent['hard_bound_on_filesystem_spawn_or_cleanup'] is False
         and intent['deadline_scope']=='popen_start_through_child_join_pipe_eof_and_output_verification'
         and intent['input_transport']=='retained_readonly_regular_fd_child_reads_within_execution_budget'
         and intent['output_transport']=='owned_nonblocking_pipe_capture_worker_bounded_memory_main_thread_persistence'
         and intent['output_limit_bytes_per_stream']==67108864
         and type(intent['maximum_wait_seconds']) in (int,float)
         and 0<intent['maximum_wait_seconds']<=145,
         'original final03 command and deadline semantics differ')
    need(child['pid']==child['pgid']==child['sid']==expected_pid
         and child['maximum_starts']==1 and child['source_intent_sha256']==pin(intent_raw)['sha256']
         and child['deadline_validity']=='this_running_coordinator_only'
         and child['identity_missing_only_if_actual_child_already_joined'] is False,
         'original final03 child must retain its actual process identity and intent')
    need(output['schema']=='hepta.native-guard.host-output-capture.v1'
         and output['phase']==name and output['pid']==expected_pid
         and output['source_intent_sha256']==pin(intent_raw)['sha256']
         and output['child_returncode']==expected_rc and type(output['child_returncode']) is int
         and output['child_wait_returned'] is True
         and output['stdout_eof'] is True and output['stderr_eof'] is True
         and output['worker_started'] is True and output['worker_joined'] is True
         and output['error'] is None and output['persist_errors']==output['pipe_close_errors']==[]
         and output['signals_sent']==0 and output['automatic_retry'] is False
         and output['prefix_only_or_unknown'] is False
         and output['pipe_reader_owner']=='closed_by_worker'
         and output['remote_terminal_or_cleanup_proven'] is False
         and output['output_limit_bytes_per_stream']==67108864
         and output['deadline_validity']=='this_running_coordinator_only'
         and output['execution_deadline_monotonic']==child['execution_deadline_monotonic'],
         'original final03 wait or complete pipe capture is unproven')
    deadline=child['execution_deadline_monotonic']
    need(type(deadline) in (int,float) and 0<deadline<10**12,
         'original running-coordinator deadline must be finite')
    for observed in [output['child_join_observed_monotonic'],
                     output['eof_observed_monotonic']['stdout'],output['eof_observed_monotonic']['stderr']]:
        need(type(observed) in (int,float) and 0<=observed<=deadline,
             'actual wait and both EOF must have occurred within the original deadline')
    need(result['state']=='ORIGINAL_HOST_CHILD_JOINED' and result['phase']==name
         and result['pid']==expected_pid and type(result['returncode']) is int
         and result['returncode']==expected_rc and result['automatic_retry'] is False,
         'final03 joined result differs from original capture')
    for stream in ('stdout','stderr'):
        path=str(directory/(stream+'.original'));raw=bodies[path];file=output['files'][stream]
        need(output['captured'][stream]==pin(raw)
             and result[stream]=={'path':path,**pin(raw)}
             and _exact3(file)==result[stream] and file['original_created_inode_bound'] is True
             and set(file['metadata'])==set(KEYS)
             and [file['metadata'][k] for k in KEYS]==rows[path]['metadata'],
             'complete final03 stream bytes or full9 identity differ')
        original=child['original_output_identities'][stream]
        need(set(original)==set(KEYS) and all(type(original[k]) is int for k in KEYS)
             and all(original[k]==file['metadata'][k] for k in KEYS[:6])
             and original['st_size']==0 and original['st_nlink']==1
             and stat.S_ISREG(original['st_mode']),
             'final03 stream was not persisted to its original created inode')
    stdin_path=str(directory/'stdin.original')
    if name in ('prepare-material','sender-preview'):
        need(intent['stdin_sha256'] is None and stdin_path not in bodies,
             'unexpected stdin in original no-input phase')
    else:
        need(stdin_path in bodies and pin(bodies[stdin_path])['sha256']==intent['stdin_sha256'],
             'complete original phase stdin differs')
    return {'phase':name,'pid':expected_pid,'returncode':expected_rc,
            'intent':pin(intent_raw),'child':pin(child_raw),'result':pin(getraw('RESULT.json')),
            'stdin_retained':intent['stdin_sha256'] is not None,'original_join_record_bound':True},result


def _verify_final03_durable(h,retained,plan,entry):
    base=Path(FINAL03_CAPTURE['path']).parent/'process'
    getraw=lambda name:retained[str(base/name)]
    get=lambda name:h.strict(getraw(name))
    request=get('ROOT-EXECUTION-REQUEST.original.json')
    start=get('ROOT-PROCESS-START.original.mcp.json')
    status=get('ROOT-PROCESS-STATUS.original.mcp.json')
    read=get('ROOT-PROCESS-READ.original.mcp.json')
    expected_argv=['-I','-B',entry['path'],'--plan',str(FINAL03_INPUT/'ROOT-PLAN.json'),
                   '--plan-sha256',plan['sha256'],'--execute-root-chain-once']
    key='a1055-root-final03-neg01-component-execute-once01'
    need(request=={'host':'mac','executable':'/usr/bin/python3','args':expected_argv,'idempotency_key':key},
         'original final03 dispatch command differs')
    job=start['job']
    need(start['audit_recorded'] is True and start['reused'] is False
         and start['local_record_pending'] is False and start['launch']['ok'] is True
         and job['id']==FINAL03_JOB and job['host']=='mac'
         and job['args']==expected_argv and job['executable']==request['executable']
         and job['idempotency_key']==key and job['launch_state']=='launched'
         and job['launch_error'] is None and job['env_keys']==[]
         and job['cwd'] is None and job['execution_mode']=='operator'
         and job['system_jobctl'] is False,
         'original final03 durable launch authority differs')
    need(status['job_id']==read['job_id']==FINAL03_JOB and status['state']=='failed'
         and type(status['exit_code']) is int and status['exit_code']==1
         and status['output_complete'] is True and status['output_durable'] is True
         and status['terminal_publication_confirmed'] is True
         and status['cancelled'] is False and status['timed_out'] is False
         and status['automatic_retry'] is False,
         'original final03 terminal failure authority is incomplete')
    for stream,count in (('stdout',0),('stderr',1486)):
        observed=read[stream];raw=getraw('ROOT-'+stream.upper()+'.original')
        need(observed['offset']==0 and observed['eof'] is True
             and observed['next_offset']==observed['size']==len(raw)==count
             and bytes.fromhex(observed['bytes_hex'])==raw==observed['text'].encode('utf-8')
             and status['log_bytes'][stream]=={'seen':count,'stored':count}
             and status['log_truncated'][stream] is False
             and status['log_errors'][stream] is None and status['log_synced'][stream] is True,
             'original final03 durable full stream differs')
    need(b'original phase failed; no replay: sender-preview' in getraw('ROOT-STDERR.original'),
         'original Root error no longer identifies the failed preview')
    return {'job_id':FINAL03_JOB,'exit_code':1,'original_durable_dual_EOF':True,
            'execution_request':{'path':str(base/'ROOT-EXECUTION-REQUEST.original.json'),
                                 **pin(getraw('ROOT-EXECUTION-REQUEST.original.json'))}}


def verify_retained_final03_preview_failure(h,o):
    """Read the actual failed host scope. Phone cleanup is a separate gate."""
    capture_raw=o.read(FINAL03_CAPTURE);capture=h.strict(capture_raw)
    need(capture['schema']=='hepta.root.final03.failed-preview-originals.v1'
         and capture['state']=='ORIGINAL_FAILED_PREVIEW_RETAINED_NO_REPLAY_NO_QUALIFICATION'
         and capture['consumed_nonce']==FINAL03_NONCE and capture['root_job_id']==FINAL03_JOB
         and capture['root_exit_code']==1 and capture['root_complete_durable_dual_EOF'] is True
         and capture['fixed19_credit']==0 and capture['sender_execute_started'] is False
         and capture['detached_launch_started'] is False
         and capture['phone_stage_state']=='PRIVATE_COMPONENT_INPUTS_STAGED_NO_ROLES'
         and capture['phone_stage_members']==61
         and capture['phone_cleanup']=='SEPARATE_EXACT_OWNED_REVIEW_AND_EXECUTION_REQUIRED'
         and capture['phone_fresh_observation']=='NOT_PERFORMED_BY_THIS_HOST_READER'
         and capture['old_655c_sender_original_wait']=='UNKNOWN_UNCHANGED',
         'exact failed preview must retain its separate phone cleanup requirement')
    dirs=_final03_directories(h,o)
    retained={}
    for row in capture['retained_files']:
        path=h.descriptor(row)
        need(Path(FINAL03_CAPTURE['path']).parent in path.parents and row['path'] not in retained,
             'one exact retained final03 member')
        retained[row['path']]=o.read(row)
    need(len(retained)==146,'complete 146 retained final03 originals required')
    originals=capture['host_originals'];rows={};bodies={}
    need(type(originals) is list and len(originals)==127,'complete127 original final03 host files required')
    for row in originals:
        need(set(row)=={'path','bytes','sha256','metadata','retained'},'original and retained full9 shape')
        path=h.descriptor(_exact3(row));_full9(row['metadata'])
        need((FINAL03_CASE in path.parents or FINAL03_INPUT in path.parents)
             and row['path'] not in bodies,'one exact host original in the failed scope')
        raw=o.read(_exact3(row));expected={k:row[k] for k in ('path','bytes','sha256','metadata')}
        need(o.rows[row['path']]==expected,'failed final03 current original lost its captured full9 identity')
        copy_path=row['retained']['path']
        prefix='case-originals' if FINAL03_CASE in path.parents else 'plan-originals'
        parent=FINAL03_CASE if prefix=='case-originals' else FINAL03_INPUT
        need(copy_path==str(Path(FINAL03_CAPTURE['path']).parent/prefix/path.relative_to(parent))
             and row['retained']=={'path':copy_path,**pin(raw)}
             and retained[copy_path]==raw,'retained final03 copy differs from actual original')
        rows[row['path']]=expected;bodies[row['path']]=raw
    expected_paths={str(Path(d['path'])/name) for d in dirs for name in d['names']}
    need(set(bodies)==expected_paths-{d['path'] for d in dirs}
         and sum(map(len,bodies.values()))==capture['original_tree_bytes']==11162734
         and capture['original_tree_files']==127,'complete final03 directory tree census differs')
    sources={}
    r3=MAC/'native-guard-r10-r1-operator-final-v3-getattr-a1055-r3'
    for row in capture['source_originals']:
        need(set(row)=={'path','bytes','sha256','metadata','retained'},'original R3 source identity shape')
        path=h.descriptor(_exact3(row));_full9(row['metadata'])
        need(r3 in path.parents and row['path'] not in sources,'one actual immutable R3 source')
        raw=o.read(_exact3(row))
        need(o.rows[row['path']]=={k:row[k] for k in ('path','bytes','sha256','metadata')}
             and row['retained']['path']==str(Path(FINAL03_CAPTURE['path']).parent/'r3-originals'/path.relative_to(r3))
             and row['retained']=={'path':row['retained']['path'],**pin(raw)}
             and retained[row['retained']['path']]==raw,'actual R3 source or retained copy differs')
        sources[row['path']]=raw
    expected_sources={
        'FREEZE-RESULT.json':{'bytes':487233,'sha256':'0b0ceac8e5cc7462750d3297a80aa9bff5a01786ad790860f1d3202fa17eb80e'},
        'runtime/MANIFEST.json':{'bytes':46296,'sha256':'5d35225532a679a9c5cbac151b84c06c0e455dc2dee72255a0420414a6712e66'},
        'root-chain/SOURCE-MANIFEST.json':{'bytes':39604,'sha256':'9e8a144a66371e7192dc3b0725160f29416d6364acea3d60a58e4d6cc0a32544'},
        'root-chain/source/run_component_root_once.py':{'bytes':78511,'sha256':'a2ca4b070cc09d71bdfaa6870e3273704e769c2cd7109dae6c42b84e38789ffd'},
        'runtime/source/send_new_native_guard_task_r10_r4.py':{'bytes':41080,'sha256':'2ed23a550e3afba234c1cc6c21f310384a3f152b00158af5d756cc35daaeb71d'},
        'runtime/source/sender_native_guard_ready_r10_r4.py':{'bytes':25040,'sha256':'a6fa2690dea61134cd51b162d86453e064c547571241959ad45f660905a542b6'}}
    need(set(sources)=={str(r3/name) for name in expected_sources}
         and all(pin(sources[str(r3/name)])==row for name,row in expected_sources.items()),
         'exact executed R3 source family required')
    get=lambda name:h.strict(bodies[str(FINAL03_CASE/name)])
    plan=get('ROOT-PLAN.original.json');chain=get('CHAIN-INTENT.json');failure=get('ROOT-FAILURE.json')
    plan_raw=bodies[str(FINAL03_CASE/'ROOT-PLAN.original.json')]
    input_raw=bodies[str(FINAL03_INPUT/'ROOT-PLAN.json')]
    identity=h.strict(bodies[str(FINAL03_INPUT/'IDENTITY.original.json')])
    generation=h.strict(bodies[str(FINAL03_INPUT/'GENERATION-INTENT.json')])
    preparation=h.strict(bodies[str(FINAL03_INPUT/'RESULT.json')])
    need(plan_raw==input_raw and pin(plan_raw)=={'bytes':4882,'sha256':'59c337c5b22e06688ed312d672cdd68b02754618596705013fd0c0b69b6afb0a'}
         and plan['nonce']==chain['nonce']==identity['nonce']==preparation['nonce']==FINAL03_NONCE
         and plan['label']==chain['label']==identity['label']==generation['label']==preparation['label']==FINAL03_CASE.name
         and plan['case_id']==chain['case_id']==identity['case_id']==generation['case_id']==preparation['case_id']=='NEG-01'
         and plan['boot_id']==BOOT and plan['out']==str(FINAL03_CASE)
         and plan['package']=={'path':str(r3/'runtime/MANIFEST.json'),**expected_sources['runtime/MANIFEST.json']}
         and plan['source_package']=={'path':str(r3/'root-chain/SOURCE-MANIFEST.json'),**expected_sources['root-chain/SOURCE-MANIFEST.json']}
         and plan['previous']==V3PREVIOUS and plan['prior_boundary_original']['sha256']==V3BOUNDARY
         and plan['live_policy_sha256']==POLICY['sha256']
         and plan['policy_adoption']['sha256']=='98b5db3d2c9680fff13e50bf64b18ddf9822689641427d204fded84f690d04c7',
         'failed final03 plan, generation, chain and prior identity differ')
    owner=bodies[str(FINAL03_INPUT/'REQUEST.txt')]
    need(plan['request']=={'path':str(FINAL03_INPUT/'REQUEST.txt'),**pin(owner)}
         and len(owner)==317 and owner.count(FINAL03_NONCE.encode())==1 and b'\0' not in owner
         and chain['schema']=='hepta.native-guard.root-chain-intent.v1'
         and chain['lease_expires_unix_ms']==capture['original_lease_expires_unix_ms']==1793946423978
         and chain['maximum_native_sends']==chain['maximum_detached_launches']==1
         and chain['automatic_retry'] is False and chain['automatic_lease_extension'] is False
         and chain['model_requests']==0 and identity['generation_count']==1
         and identity['automatic_retry'] is False and identity['phone_calls']==0,
         'consumed final03 request or original one-use lease differs')
    need(failure['state']=='FAILED_OR_UNKNOWN_ORIGINALS_PRESERVED_NO_AUTOMATIC_CONTINUATION'
         and failure['detail']=='original phase failed; no replay: sender-preview'
         and failure['error_type']=='ValueError'
         and failure['host_cleanup']=={'host_children':[],'stream_cleanup_errors':[]}
         and failure['root_fixture_attempts']==[]
         and all(failure[k] is False for k in ('automatic_retry','business_qualified','component_qualified','new_identity_retry','send_again'))
         and failure['model_requests']==failure['policy_changes']==failure['signals_sent_by_coordinator']==0,
         'original failed final03 outcome must remain failed and fully joined')
    joins=[];results=[]
    for name,pid in FINAL03_PHASES:
        joined,result=_verify_final03_phase(h,name,bodies,rows,pid);joins.append(joined);results.append(result)
    need(joins==capture['original_host_phase_joins'] and results==failure['steps'],
         'all eight original child joins must be retained in their original order')
    sender=h.strict(bodies[str(FINAL03_CASE/'sender-preview/INTENT.json')])
    expected_sender=['/usr/bin/python3','-I','-B',str(r3/'runtime/source/send_new_native_guard_task_r10_r4.py'),
        plan['label'],plan['request']['path'],plan['previous']['path'],'--preserved-draft',plan['preserved_draft']['path'],
        '--retirement-resolution',plan['sender_retirement_resolution']['path'],'--evidence-root','component',
        '--component-contract',str(FINAL03_CASE/'material/tree/sender-contract.json'),
        '--component-package',plan['package']['path'],'--component-package-sha256',plan['package']['sha256']]
    need(sender['argv']==expected_sender and sender['maximum_wait_seconds']==20
         and bodies[str(FINAL03_CASE/'sender-preview/stdout.original')]==b''
         and pin(bodies[str(FINAL03_CASE/'sender-preview/stderr.original')])==
             {'bytes':528,'sha256':'866198efeea1c2cd08ccbe09d7687e12b03e65075b293aec950f150209779d9b'},
         'only the exact original sender preview assertion failure may be retired')
    stage_operation=h.strict(bodies[str(FINAL03_CASE/'phone-stage/stdout.original')])
    need(stage_operation['actor_rc']==stage_operation['wrapper']['phone']['rc']==0,
         'actual original phone staging result required')
    stage_raw=stage_operation['wrapper']['phone']['stdout'].encode('utf-8');stage=h.strict(stage_raw)
    need(stage['state']=='PRIVATE_COMPONENT_INPUTS_STAGED_NO_ROLES' and stage['members']==61
         and stage_raw==retained[str(Path(FINAL03_CAPTURE['path']).parent/'derived/PHONE-STAGE-STDOUT.original.json')],
         'phone staging was real; host preview failure does not erase it')
    entry={'path':str(r3/'root-chain/source/run_component_root_once.py'),
           **expected_sources['root-chain/source/run_component_root_once.py']}
    durable=_verify_final03_durable(h,retained,{'path':str(FINAL03_INPUT/'ROOT-PLAN.json'),**pin(plan_raw)},entry)
    need(preparation['exact_argv']==['/usr/bin/python3',*h.strict(retained[str(Path(FINAL03_CAPTURE['path']).parent/'process/ROOT-EXECUTION-REQUEST.original.json')])['args']]
         and preparation['entry']==entry and preparation['actual_freeze']==generation['actual_freeze']
         and generation['actual_freeze']=={'path':str(r3/'FREEZE-RESULT.json'),**expected_sources['FREEZE-RESULT.json']},
         'original prepared command and actual failed Root dispatch differ')
    _final03_directories(h,o);o.recheck()
    return {'state':'EXACT_FINAL03_FAILED_PREVIEW_RETAINED_SEPARATE_PHONE_CLEANUP_REQUIRED',
        'capture':FINAL03_CAPTURE,'consumed_nonce':FINAL03_NONCE,'host_label':FINAL03_CASE.name,
        'root_failure':_exact3(capture['original_failure']),'original_root_process':durable,
        'original_host_phase_count':8,'original_host_file_count':127,'retained_copy_count':146,
        'all_original_waits_and_dual_EOF_verified':True,'phone_staging_was_written':True,
        'sender_execute_started':False,'detached_launch_started':False,
        'phone_cleanup_verified_by_this_reader':False,'fresh_phone_admission_claimed':False,
        'old_655c_sender_original_wait':'UNKNOWN_UNCHANGED','fixed19_credit':0}


def _load_required_pure_reader(h,o,row,name):
    h.descriptor(row);raw=o.read(row);module=types.ModuleType(name);module.__file__=row['path']
    exec(compile(raw,row['path'],'exec'),module.__dict__)
    return module


def verify_cleanup_and_postcleanup41(h,o,c):
    """Independent cleanup and post-cleanup current41 gates; never reuse old689a."""
    cleanup_api=_load_required_pure_reader(h,o,CLEANUP_READER,'exact_owned_stage_cleanup_reader')
    cleanup=cleanup_api.verify_owned_unstarted_stage_cleanup(o.read(CLEANUP_INPUTS),read_pinned=o.read)
    need(cleanup['schema']=='hepta.native-guard.owned-unstarted-stage-cleanup-verification.v1'
         and cleanup['state']=='VERIFIED_OWNED_UNSTARTED_STAGE_CLEANUP'
         and cleanup['consumed_nonce']==FINAL03_NONCE and cleanup['boot_id']==BOOT,
         'actual exact-owned final03 cleanup required')
    h.descriptor(cleanup['closure']);h.descriptor(cleanup['after_inventory'])
    need(cleanup['retained_inventory']==c['retained_unstarted_stage']['binding']['inventory']
         and cleanup['new_native_case_count']==cleanup['new_component_role_generation_count']
             ==cleanup['new_fixture_count']==0,
         'cleanup cannot delete history or grant a native, role or fixture generation')
    fresh_api=_load_required_pure_reader(h,o,POST_CLEANUP_CURRENT41_READER,'exact_postcleanup_current41_reader')
    def fresh_read_pinned(row):
        need(type(row) is dict and set(row)=={'path','bytes','sha256','metadata'}
             and type(row['metadata']) is list and len(row['metadata'])==9
             and all(type(value) is int for value in row['metadata']),
             'fresh original exact4 descriptor with full9 required')
        raw=o.read({key:row[key] for key in ('path','bytes','sha256')})
        need(o.rows[row['path']]==row,'fresh original complete observed full9 differs from proof')
        return raw
    fresh=fresh_api.verify_postcleanup_current41(o.read(POST_CLEANUP_CURRENT41_PROOF),read_pinned=fresh_read_pinned)
    need(fresh['schema']=='hepta.current41.postcleanup-original-verification.v1'
         and fresh['state']=='VERIFIED_POSTCLEANUP_CURRENT41' and fresh['boot_id']==BOOT
         and fresh['runtime_policy']==POLICY
         and fresh['current_adoption_sha256']==c['freeze']['actual_adoption']['sha256']
         and fresh['prior_boundary_sha256']==V3BOUNDARY
         and fresh['cleanup_closure']==cleanup['closure'] and fresh['consumed_nonce']==FINAL03_NONCE
         and fresh['native_generation_count']==9 and fresh['component_role_count']==33
         and fresh['retired_role_count']==4 and fresh['inventory_root_count']==41
         and fresh['final03_required_absence_verified'] is True
         and fresh['observed_after_cleanup'] is True and fresh['all_16_gates_verified'] is True
         and fresh['candidate_runtime_qualified_on_phone'] is False
         and fresh['original_sender_wait']=='UNKNOWN_UNCHANGED' and fresh['native_case_credit']==0,
         'new post-cleanup current41 actual strong proof required')
    need(fresh['cleanup_after_inventory']==cleanup['after_inventory'],
         'fresh gate must bind the independently verified cleanup inventory without equating different observations')
    h.descriptor(fresh['fresh_inventory']);o.read(cleanup['after_inventory']);o.read(fresh['fresh_inventory'])
    need(fresh['fresh_inventory']['path']!=cleanup['after_inventory']['path']
         and fresh['fresh_inventory']['path']!=c['retained_unstarted_stage']['actual_inventory_original']['path']
         and fresh['cleanup_and_fresh_inventory_values_equal'] is True
         and cleanup['after_inventory_value']==fresh['fresh_inventory_value'],
         'independent cleanup and fresh complete inventory views must agree, without reusing historical raw')
    view_pin=pin(h.enc(fresh['fresh_inventory_value']))
    cleanup_summary={k:v for k,v in cleanup.items() if k not in ('after_inventory_value','after_inventory_raw')}
    fresh_summary={k:v for k,v in fresh.items() if k!='fresh_inventory_value'}
    return {'cleanup_reader':CLEANUP_READER,'cleanup_inputs':CLEANUP_INPUTS,'cleanup':cleanup_summary,
        'postcleanup_reader':POST_CLEANUP_CURRENT41_READER,'postcleanup_proof':POST_CLEANUP_CURRENT41_PROOF,
        'postcleanup_current41':fresh_summary,'complete_inventory_view_canonical_pin':view_pin,
        'selected_case':c['case_id'],
        'current_selected_case_fresh_head_claimed':c['case_id']=='NEG-01',
        'NEG02_requires_separate_actual_qualified_NEG01_head_and_fresh44_admission':True,
        'runtime_tuple_from_actual_freeze':c['freeze']['runtime_manifest'],
        'phone_calls':0,'fixed19_credit':False}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--reviewed-source-sha256',required=True)
    ap.add_argument('--freeze-sha256',required=True);ap.add_argument('--freeze-bytes',type=int,required=True)
    ap.add_argument('--case',choices=['NEG-01','NEG-02'],required=True)
    ap.add_argument('--previous',required=True);ap.add_argument('--previous-sha256',required=True)
    ap.add_argument('--previous-bytes',type=int,required=True)
    ap.add_argument('--create-host-plan-once',action='store_true')
    args=ap.parse_args()
    need(all(value is not None for value in (FREEZER_PIN,CLEANUP_READER,CLEANUP_INPUTS,
         POST_CLEANUP_CURRENT41_READER,POST_CLEANUP_CURRENT41_PROOF)),
         'UNBOUND_FREEZER_OR_CLEANUP_OR_POSTCLEANUP_CURRENT41_NO_IO_PLAN_OR_NONCE')
    h,helper_raw=load_helpers();sys.addaudithook(h.audit);o=h.Originals()
    need(o.read({'path':str(HELPER),**HELPER_PIN})==helper_raw,'executed helper changed')
    source_path=Path(__file__).absolute()
    need(source_path==SOURCE_HOME/'source/prepare_final_component_plan_v4.py','fixed actual preparer path')
    source_raw=o.raw(source_path,1048576)
    need(re.fullmatch('[0-9a-f]{64}',args.reviewed_source_sha256)
         and pin(source_raw)['sha256']==args.reviewed_source_sha256,'exact reviewed preparer source required')
    source_row={'path':str(source_path),**pin(source_raw)}
    freeze_row={'path':str(FROZEN/'FREEZE-RESULT.json'),'bytes':args.freeze_bytes,'sha256':args.freeze_sha256}
    retained_failure=verify_retained_host_preparation_failure(h,o)
    retained_preview=verify_retained_final03_preview_failure(h,o)
    c=selected_context(h,o,args,freeze_row);c['retained_host_preparation_failure']=retained_failure
    c['retained_final03_preview_failure']=retained_preview
    retained_stage=verify_retained_stage_history(h,o,c);c['retained_unstarted_stage']=retained_stage
    c['consumed_nonces']=set(c['consumed_nonces'])|{retained_failure['retired_host_only_nonce'],
        retained_stage['consumed_nonce'],retained_preview['consumed_nonce']}
    c['cleanup_and_postcleanup_current41']=verify_cleanup_and_postcleanup41(h,o,c)
    preview=h.historical_validation_carrier(o,c)
    _final03_directories(h,o);o.recheck();h.require_unused(c['selected_label'])
    if not args.create_host_plan_once:
        print(h.enc({'schema':'hepta.final-component.root-plan-preparation-preview.v1',
            'state':'ACTUAL_FINAL_TUPLE_AND_PURE_ROOT_VALIDATION_CHECKED_NO_NEW_IDENTITY',
            'source':source_row,'actual_freeze':freeze_row,'actual_previous':c['actual_previous'],
            'case_id':c['case_id'],'label':c['selected_label'],'historical_validation':preview,
            'retained_final03_preview_failure':retained_preview,
            'cleanup_and_postcleanup_current41':c['cleanup_and_postcleanup_current41'],
            'consumed_nonces':sorted(c['consumed_nonces']),
            'original_count':len(o.rows),'new_nonces':0,'phone_calls':0,'root_executions':0,
            'fresh_phone_and_latest_head_rollback_admission_required':True,'fixed19_credit':False}).decode(),end='')
        return 0
    result=create_plan(h,o,c,source_row,source_raw,freeze_row,preview)
    print(h.enc(result).decode(),end='');return 0
if __name__=='__main__':raise SystemExit(main())
