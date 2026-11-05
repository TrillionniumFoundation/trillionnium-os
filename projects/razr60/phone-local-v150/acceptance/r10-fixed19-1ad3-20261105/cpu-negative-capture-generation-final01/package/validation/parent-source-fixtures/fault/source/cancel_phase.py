"""Pure guards for one original HEPTA cancellation; no transport or effects."""
import base64
import active_runtime_r10 as active
import hashlib
import json
import re
import xml.etree.ElementTree as ET

KEYS = ('session_id','profile_id','task_id','turn_id','turn_stream_id')
HEPTA = 'org.trillionnium.owneropen/org.trillionnium.owneropen.OwnerOpenShellActivity'
MUTATIONS = {'phone.open_app','phone.tap','phone.input_text','phone.focus_input_text','phone.return_hepta'}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(items):
        out = {}
        for key,value in items:
            need(key not in out, 'duplicate JSON key')
            out[key] = value
        return out
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def encoded(value):
    return (json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()


def scope(value):
    need(isinstance(value,dict) and set(value)==set(KEYS), 'exact five-field scope required')
    need(all(isinstance(value[k],str) and re.fullmatch('[A-Za-z0-9_.:-]{1,256}',value[k]) for k in KEYS), 'invalid native scope')
    need(value['profile_id']=='owner-open', 'unexpected native profile')
    return value


def native_request_digest(actual, owner):
    value={'config_generation':None,'context_ref':None,'profile_id':'owner-open',
        'protocol':'trillionnium.agent.turn.v1','protocol_version':1,
        'schema':'trillionnium.owner-open.turn-request-digest.v1',
        'session_id':actual['session_id'],'task_id':actual['task_id'],
        'turn_id':actual['turn_id'],'user_input':owner.decode('utf-8')}
    return sha(json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode())


def validate_plan(p):
    need(set(p)=={'schema','label','sender_label','case_id','nonce','expected_boot','request_b64',
        'owner_request_sha256','previous_scope','source_seal_sha256','configuration_sha256',
        'service_inputs_sha256','require_image_cancel','probe_component','wait_seconds',
        'app_scope','task_template_sha256','runtime_binding'}, 'plan fields differ')
    need(p['schema']=='hepta.r10.native-cancel-once-plan.v1', 'plan schema differs')
    need(p['case_id'] in ('NEG-08','NEG-09'), 'unapproved cancellation case')
    need(all(re.fullmatch('[a-z0-9-]{1,70}',p[x]) for x in ('label','sender_label')), 'invalid operator label')
    need(re.fullmatch('[0-9a-f]{32}',p['nonce']) and
        re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',p['expected_boot']), 'nonce or boot malformed')
    need(all(re.fullmatch('[0-9a-f]{64}',p[x]) for x in ('owner_request_sha256','source_seal_sha256',
        'configuration_sha256','service_inputs_sha256')), 'release/request SHA malformed')
    owner = base64.b64decode(p['request_b64'],validate=True)
    need(20<=len(owner)<=16000 and owner.decode().count(p['nonce'])==1 and
        sha(owner)==p['owner_request_sha256'], 'fresh exact request/nonce binding differs')
    scope(p['previous_scope'])
    need(type(p['require_image_cancel']) is bool and type(p['wait_seconds']) is int and
        15<=p['wait_seconds']<=180, 'finite wait/image flag required')
    need(isinstance(p['probe_component'],str) and re.fullmatch('[A-Za-z][A-Za-z0-9_.$]*/[A-Za-z][A-Za-z0-9_.$]*',p['probe_component'])
        and p['probe_component']!=HEPTA, 'exact public probe component required')
    need(p['case_id']=='NEG-09' or p['require_image_cancel'] is False, 'NEG08 image request cannot precede all tools')
    active.validate_task_expectations(p,owner)
    return owner


def selected_matches(selected, observation):
    actual = scope(observation['scope'])
    need(selected.get('checksum_valid') is True and all(selected.get(k)==actual[k] for k in ('session_id','task_id','turn_id'))
        and selected.get('turn_request_sha256')==observation['native_request_sha256'], 'durable selected task changed; no target substitution')
    return True


def phase_ready(plan, observation, previous=None):
    """Return only an action precondition. Physical PASS always needs late originals."""
    validate_plan(plan)
    need(observation.get('schema')=='hepta.r10.cancel-phase-observation.v1' and
        observation.get('boot_id')==plan['expected_boot'] and observation.get('owner_request_sha256')==plan['owner_request_sha256'], 'live phase binding differs')
    if observation.get('state')=='NO_MATCHING_ACCEPTED_TASK':
        need(previous is None, 'accepted task disappeared')
        return False
    actual = scope(observation['scope'])
    need(actual!=plan['previous_scope'] and observation.get('native_accepted') is True,
        'not a new actual accepted task')
    need(not observation.get('native_terminal') and observation.get('cancel_acceptances')==0,
        'task already terminal/cancelled; no Cancel request')
    need(observation.get('claim_consumed') is True, 'durable original claim absent')
    calls=observation['calls']; mutations=[c for c in calls if c['semantic_tool'] in MUTATIONS]
    need(len(calls)<=7 and len({c['call_id'] for c in calls})==len(calls), 'dispatch budget or duplicate identity')
    if plan['case_id']=='NEG-08':
        need(not calls, 'first tool already dispatched; before-dispatch sample missed')
    else:
        need(len(mutations)<=1 and all(c['semantic_tool'] in {'phone.open_app','phone.screenshot'} for c in calls),
            'task advanced beyond the single open effect')
        if not mutations:
            need(previous is None, 'observed open effect disappeared')
            return False
        need(calls[0] is mutations[0] and mutations[0]['semantic_tool']=='phone.open_app' and
            mutations[0]['component']==plan['probe_component'], 'first effect is not the approved probe open')
        need(sum(c['semantic_tool']=='phone.screenshot' for c in calls)<=1, 'multiple screenshot dispatches')
        if mutations[0].get('verified_app_open') is not True:
            need(previous is None, 'confirmed app-open receipt disappeared')
            return False
    model=observation.get('model')
    if not model or model.get('original_active') is not True:
        need(previous is None, 'original inference finished/changed before Cancel')
        return False
    if plan['require_image_cancel'] and model.get('image_count')!=1:
        need(previous is None, 'image request changed before Cancel')
        return False
    if previous is not None:
        need(observation['scope']==previous['scope'] and observation['run']==previous['run'] and
            observation['native_request_sha256']==previous['native_request_sha256'] and
            calls==previous['calls'], 'native identity or dispatch prefix advanced before Cancel')
        for key in ('request_id','request_sha256','request_bytes','round','image_count','server_identity','task_id','slot_id'):
            need(model.get(key)==previous['model'].get(key), 'original model ownership changed: '+key)
    return True


def unique_ui_node(xml, resource_id):
    need(isinstance(xml,str) and len(xml.encode())<=262144 and '\0' not in xml, 'UI XML bound')
    tree=ET.fromstring(xml[xml.index('<?xml'):])
    hits=[n for n in tree.iter('node') if n.attrib.get('resource-id')==resource_id]
    need(len(hits)==1, 'UI action absent or ambiguous: '+resource_id)
    node=hits[0]
    need(node.attrib.get('package')=='org.trillionnium.owneropen' and node.attrib.get('enabled')=='true'
        and node.attrib.get('clickable')=='true', 'UI action not uniquely enabled/clickable')
    m=re.fullmatch(r'\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]',node.attrib.get('bounds',''))
    need(m is not None, 'UI bounds malformed')
    x1,y1,x2,y2=map(int,m.groups())
    need(0<=x1<x2<=1224 and 0<=y1<y2<=2992, 'UI action outside qualified inner display')
    return {'resource_id':resource_id,'bounds':[x1,y1,x2,y2],'x':(x1+x2)//2,'y':(y1+y2)//2}
