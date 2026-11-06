#!/usr/bin/env python3
"""Root operator: one frozen readiness recheck, then optional one-time registration.

Root supplies the exact sealed release pins, prior ready observation and already
materialized request. This program never generates a nonce or sends a task.
"""
import base64,hashlib,json,os,re,stat,subprocess,sys
from pathlib import Path

B=Path('/var/lib/trillionnium/owner-open/phone-local-v150')
def need(value,message):
    if not value:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(v):return (json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def strict(raw):
    def pairs(rows):
        v={}
        for k,x in rows:need(k not in v,'duplicate JSON field');v[k]=x
        return v
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def read(p,maximum=262144):
    need(p.parent.resolve()==p.parent,'noncanonical private parent')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==s.st_gid==0
             and stat.S_IMODE(s.st_mode)==0o600 and 0<=s.st_size<=maximum,'private input metadata differs')
        with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(maximum+1)
        z,n=os.fstat(fd),p.lstat()
        need(len(raw)==s.st_size and all(getattr(s,k)==getattr(z,k)==getattr(n,k)
             for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_nlink')),'private input changed')
        return raw
    finally:os.close(fd)
def put(p,raw):
    need(p.parent.resolve()==p.parent,'noncanonical output parent')
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

def readiness(payload):
    pins=payload['release_pins'];prior=payload['ready']
    for key in ('component_boundary_inputs_sha256','policy_adoption_inputs_sha256'):
        need(isinstance(pins.get(key),str) and re.fullmatch('[0-9a-f]{64}',pins[key])
             and pins[key]==prior.get(key),'explicit readiness boundary input differs: '+key)
    p=B/'provider-r10-r1/collect_r10_readiness.py'
    need(sha(read(p))==payload['readiness_helper_sha256'],'frozen readiness helper changed')
    need(sha(read(B/'provider-r10-r1/SOURCE-SEAL-v150-r10.json'))==pins['source_seal_sha256'],'selected source seal changed')
    args=['/usr/bin/python3','-B',str(p),'--expected-boot',prior['boot_id'],
        '--source-seal-sha256',pins['source_seal_sha256'],'--configuration-sha256',pins['configuration_sha256'],
        '--module-manifest-sha256',pins['module_manifest_sha256'],
        '--component-boundary-inputs-sha256',pins['component_boundary_inputs_sha256'],
        '--policy-adoption-inputs-sha256',pins['policy_adoption_inputs_sha256']]
    r=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,timeout=30)
    need(r.returncode==0 and r.stderr==b'','original readiness recheck did not complete zero')
    actual=strict(r.stdout)
    need(actual.get('schema')=='hepta.r10.actual-readiness.v1'
         and actual.get('state')=='EXACT_COMBINATION_READY_TRANSPORT_ONLY','actual ready state differs')
    for key in ('boot_id','source_seal_sha256','configuration_sha256','module_manifest_sha256','service_inputs_sha256','component_boundary_inputs_sha256','policy_adoption_inputs_sha256','actual_binding'):
        need(actual.get(key)==prior.get(key),'actual ready selection changed: '+key)
    need(set(actual['roles'])==set(prior['roles'])=={'supervisor','model','sidecar','provider'},'four original roles required')
    for name in actual['roles']:
        a,b=actual['roles'][name],prior['roles'][name]
        need(a['state']!='Z' and all(a[k]==b[k] for k in ('identity','domain','uid','gid','no_new_privs','exe')),
             'actual role changed: '+name)
    need(all(actual['provider_ready'][k]==prior['provider_ready'][k] for k in
         ('accepting','pid','port','source_sha256','config_sha256','service_manifest_sha256')),'provider accepting identity changed')
    return actual,r.stdout

def main():
    need(os.getuid()==os.geteuid()==0,'root operator required');os.umask(0o077)
    need(len(sys.argv)==2 and len(sys.argv[1])<=1024*1024,'one bounded payload required')
    p=strict(base64.b64decode(sys.argv[1],validate=True));need(p['operation'] in ('check','register'),'operation')
    ready,ready_raw=readiness(p)
    if p['operation']=='check':
        print(json.dumps({'state':'EXACT_ORIGINAL_READY_RECHECKED','ready':ready,
            'original_ready_stdout_b64':base64.b64encode(ready_raw).decode(),'original_ready_stdout_sha256':sha(ready_raw),
            'registration_calls':0,'send_attempts':0,'model_requests':0,'automatic_retry':False},sort_keys=True));return 0
    nonce=p['nonce'];need(re.fullmatch('[0-9a-f]{32}',nonce),'fresh material nonce shape')
    parent=B/'cases-r10-r1'
    if not parent.exists():parent.mkdir(mode=0o700)
    s=parent.lstat();need(parent.resolve()==parent and stat.S_ISDIR(s.st_mode)
        and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700,'private case parent')
    d=parent/nonce;d.mkdir(mode=0o700)
    put(d/'READINESS-RECHECK.original.json',ready_raw)
    files={}
    for name,row in p['files'].items():
        need(re.fullmatch('[A-Za-z0-9._-]+',name) and name not in ('.','..'),'material filename')
        raw=base64.b64decode(row['raw_b64'],validate=True)
        need(len(raw)==row['bytes'] and len(raw)<=262144 and sha(raw)==row['sha256'],'material body pin differs')
        put(d/name,raw);need(read(d/name)==raw,'staged bytes differ');files[name]=raw
    raw=files['request.txt'];meta=strict(files['material.json']);conditions=strict(files['postconditions.json']) if 'postconditions.json' in files else None
    need(sha(raw)==p['request_sha256']==meta['request_sha256'] and raw.decode().count(nonce)==1
        and meta['nonce']==nonce and meta['kind']==p['kind']
        and meta.get('release_id')=='v150-r10-r1','exact request/material binding')
    need(sha(files['combination.json'])==meta['combination_manifest_sha256'],'raw combination binding')
    app_scope=None
    if p['kind']=='health':
        need('app-scope.json' not in files and 'app_scope' not in meta
             and meta.get('template_schema') is None,'HEALTH cannot carry business app authority')
    else:
        need(meta.get('template_schema')=='hepta.task-template.v150.3'
             and 'app-scope.json' in files and len(files['app-scope.json'])<=16384,
             'explicit scoped business contract is required')
        sys.path.insert(0,str(B/'provider-r10-r1/source'))
        from task_postconditions import validate_app_scope,app_scope_hash
        config_raw=read(B/'local-config-r10-r1.json')
        need(sha(config_raw)==p['release_pins']['configuration_sha256'],'actual reviewed app registry pin differs')
        app_scope=strict(files['app-scope.json'])
        validate_app_scope(app_scope,sha(raw),strict(config_raw)['approved_apps'])
        need(app_scope==meta.get('app_scope') and app_scope_hash(app_scope)==meta.get('app_scope_sha256'),
             'material app scope bytes/metadata differ')
    helper='register_health_contract.py' if p['kind']=='health' else 'register_task_contract.py'
    reg=B/'provider-r10-r1'/helper
    need(sha(read(reg))==p['registrar_sha256'],'frozen registrar source changed')
    scope={k:p['previous']['identity'][k] for k in ('session_id','profile_id')}
    args=['/usr/bin/python3','-B',str(reg),'--state',str(B/'provider-state'),'--request-file',str(d/'request.txt'),
          '--session-id',scope['session_id'],'--profile-id',scope['profile_id'],'--nonce',nonce]
    contract='health-contracts' if p['kind']=='health' else 'task-contracts'
    if p['kind']!='health':args+=['--postconditions-file',str(d/'postconditions.json'),'--coverage','entire_request',
                                '--template-schema',meta['template_schema'],'--app-scope-file',str(d/'app-scope.json')]
    put(d/'REGISTER-INTENT.json',encoded({'argv':args,'previous_input_sha256':p['previous_input_sha256'],
        'actual_ready_stdout_sha256':sha(ready_raw),'registration_attempts':1,'send_attempts':0,'automatic_retry':False}))
    r=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,timeout=15)
    put(d/'register.stdout',r.stdout);put(d/'register.stderr',r.stderr)
    result={'schema':'hepta.root-registration-once.v150.r10.1','kind':p['kind'],'case':meta['case'],'nonce':nonce,
        'request_sha256':sha(raw),'combination_manifest_sha256':meta['combination_manifest_sha256'],
        'combination_sha256':meta['combination_sha256'],'previous_input_sha256':p['previous_input_sha256'],
        'expected_scope':scope,'release_pins':p['release_pins'],'rc':r.returncode,'registration_attempts':1,
        'stdout_sha256':sha(r.stdout),'stderr_sha256':sha(r.stderr),'send_attempts':0,'model_requests':0,
        'automatic_retry':False,'frozen_sender_checks_required':True,'unconsumed_template_read_back':False}
    if r.returncode==0:
        need(r.stderr==b'','registration stderr');v=strict(r.stdout)
        target=B/'provider-state'/contract/'templates'/(sha(raw)+'.json')
        need(v['path']==str(target) and v['request_sha256']==sha(raw),'registration original path/hash')
        template_raw=read(target);template=strict(template_raw)
        expected={'schema':'hepta.health-template.v150.3','expected_scope':scope,'request_sha256':sha(raw),
                  'nonce':nonce,'mode':'final_only_zero_phone_tools'} if p['kind']=='health' else {
            'schema':meta['template_schema'],'expected_scope':scope,'request_sha256':sha(raw),'nonce':nonce,
            'postconditions':conditions,'coverage':'entire_request','app_scope':app_scope}
        if app_scope is not None:
            need(v.get('app_scope_sha256')==meta['app_scope_sha256'],'registrar app scope digest differs')
        need(template==expected and sha(template_raw)==v['template_sha256'],'registered actual template differs')
        consumed=B/'provider-state'/contract/'bindings'/target.name
        need(not consumed.exists() and not consumed.is_symlink(),'registered template already consumed')
        result.update(registration=v,template_original_sha256=sha(template_raw),unconsumed_template_read_back=True)
    put(d/'REGISTRATION-RESULT.json',encoded(result));print(json.dumps(result,sort_keys=True));return r.returncode
if __name__=='__main__':raise SystemExit(main())
