#!/usr/bin/env python3
"""Fresh one-use contract race, evidence-capacity boundary and resource fixtures."""
from pathlib import Path
import datetime, hashlib, importlib.util, json, os, secrets, socket, subprocess, sys, tempfile, threading, time, traceback
BASE=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(BASE/'source'))
sys.path.insert(0,str(BASE/'tests'))
from task_postconditions import load_contract, write_exclusive, request_hash
from provider_openai_compatible import ProviderError,MAX_LINE
from local_capacity_race_checks import main as capacity_checks

OUT=BASE/'validation'/('contracts-capacity-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+secrets.token_hex(8))
OUT.mkdir(mode=0o700)
report={'schema':'hepta.phone-local-contract-capacity.v150.1','layer':'host_isolated_fixture',
        'physical_phone_actions':0,'real_model_requests':0,'checks':{},'cases':[]}
def check(n,v=True):
    assert v,n
    report['checks'][n]=True
def rejected(fn):
    try:fn()
    except Exception:return True
    return False

def contract_race():
    d=OUT/'contracts'
    for p in [d,d/'templates',d/'bindings']:p.mkdir(mode=0o700)
    nonce=secrets.token_hex(16);request='fresh isolated one-use request '+nonce
    scope={'session_id':'session-'+secrets.token_hex(16),'profile_id':'fixture-profile'}
    template={'schema':'hepta.task-template.v149.1','expected_scope':scope,
              'request_sha256':request_hash(request),'nonce':nonce,'coverage':'entire_request',
              'postconditions':[{'id':'return','kind':'foreground_hepta'}]}
    write_exclusive(d/'templates'/(request_hash(request)+'.json'),template)
    wrong={**scope,'profile_id':'wrong','task_id':'wrong-'+secrets.token_hex(8),'turn_id':'wrong-'+secrets.token_hex(8)}
    check('wrong known scope rejected',rejected(lambda:load_contract(d,wrong,request)))
    check('wrong scope does not consume template',len(list((d/'bindings').iterdir()))==0)
    barrier=threading.Barrier(2);outcomes=[];lock=threading.Lock()
    def attempt():
        identity={**scope,'task_id':'task-'+secrets.token_hex(16),'turn_id':'turn-'+secrets.token_hex(16)}
        barrier.wait()
        try:value=load_contract(d,identity,request);result={'accepted':True,'identity':identity,'contract':value}
        except ProviderError as error:result={'accepted':False,'identity':identity,'error':str(error)}
        with lock:outcomes.append(result)
    threads=[threading.Thread(target=attempt) for _ in range(2)]
    for t in threads:t.start()
    for t in threads:t.join(3)
    check('both competing admissions joined',all(not t.is_alive() for t in threads))
    check('exactly one O_EXCL template binding',sum(x['accepted'] for x in outcomes)==1 and len(list((d/'bindings').iterdir()))==1)
    binding=next((d/'bindings').iterdir());before=binding.read_bytes()
    new={**scope,'task_id':'new-'+secrets.token_hex(16),'turn_id':'new-'+secrets.token_hex(16)}
    check('new semantic turn cannot reuse old nonce',rejected(lambda:load_contract(d,new,request)))
    winner=next(x['identity'] for x in outcomes if x['accepted'])
    check('replacement stream cannot consume again',rejected(lambda:load_contract(d,{**winner,'turn_stream_id':'stream-'+secrets.token_hex(16)},request)))
    check('consumed binding unchanged and retained',binding.read_bytes()==before)
    (OUT/'contract-race-evidence.json').write_text(json.dumps(outcomes,ensure_ascii=False,indent=2))

def service_boundary(kind):
    root=OUT/kind;root.mkdir(mode=0o700)
    state=root/'state';state.mkdir(mode=0o700)
    evidence=state/'evidence';evidence.mkdir(mode=0o700)
    run=evidence/('20261103-120000-'+secrets.token_hex(16));run.mkdir(mode=0o700)
    key=root/'fixture-api.key';key.write_text(secrets.token_hex(32));key.chmod(0o600)
    config={'schema':'hepta.phone-local-provider.v150.1','endpoint':'http://127.0.0.1:18099/v1/chat/completions',
            'api_key_file':str(key),'model':'fixture-only-no-request','service_manifest_sha256':'f'*64,
            'max_tokens':256,'max_prompt_bytes':65536,
            'approved_apps':{'probe':{'component':'org.trillionnium.hepta.controlprobe/.VisualChallengeActivity','label':'fixture'}},
            'inference_location':'phone','expected_parallel_slots':1,'executor':{'mode':'adb_legacy'}}
    conf=root/'config.json';conf.write_text(json.dumps(config));conf.chmod(0o600)
    identity={'session_id':'s-'+secrets.token_hex(16),'profile_id':'fixture','task_id':'t-'+secrets.token_hex(16),'turn_id':'u-'+secrets.token_hex(16)}
    retained=root/'retained.json';raw=json.dumps([{'identity':identity,'origin_receipt_sha256':'e'*64}]).encode();retained.write_bytes(raw);retained.chmod(0o600)
    large=None
    if kind=='orphan':
        intent=run/'local-01.spawn-intent.json';intent.write_text('{"fixture":"owned unjoined intent"}')
    else:
        large=run/'sparse-capacity.bin'
        with large.open('wb') as f:f.truncate(1024*MAX_LINE)
    sock=socket.socket();sock.bind(('127.0.0.1',0));port=sock.getsockname()[1];sock.close()
    argv=[sys.executable,'-B',str(BASE/'source'/'daily_phone_local.py'),'--state',str(state),
          '--config',str(conf),'--port',str(port),'--max-evidence-bytes',str(1024*MAX_LINE),
          '--retained-claims',str(retained),'--retained-claims-sha256',hashlib.sha256(raw).hexdigest()]
    before=len(os.listdir('/dev/fd'))
    started=time.monotonic()
    result=subprocess.run(argv,capture_output=True,timeout=8)
    after=len(os.listdir('/dev/fd'))
    (root/'daemon.stdout').write_bytes(result.stdout);(root/'daemon.stderr').write_bytes(result.stderr)
    check(kind+' startup fails closed',result.returncode!=0)
    expected=b'unjoined prior inference-client round' if kind=='orphan' else b'evidence capacity reached'
    check(kind+' exact rejection reason',expected in result.stderr)
    check(kind+' retained accepted claim remains',len(list((evidence/'claims').iterdir()))==1)
    check(kind+' no model client was spawned',len(list(evidence.glob('*/local-*.spawned.json')))==0)
    check(kind+' parent fd baseline restored',after==before)
    if kind=='orphan':
        check('unjoined intent retained for inspection',intent.exists())
    else:
        ready=json.loads((state/'ready.json').read_text())
        check('capacity ready state stops accepting',ready['accepting'] is False)
        report['sparse_capacity_fixture']={'declared_bytes':large.stat().st_size,'allocated_bytes':large.stat().st_blocks*512,
                                          'removed_after_observation':True}
        large.unlink()
    return {'returncode':result.returncode,'elapsed_seconds':time.monotonic()-started,'fds_before':before,'fds_after':after}

try:
    start=time.monotonic();contract_race()
    report['cases'].append({'id':'NEG-13','status':'PASS','layer':'host_isolated_fixture','elapsed_seconds':time.monotonic()-start})
    start=time.monotonic();r=capacity_checks();report['checks'].update({'rename:'+k:v for k,v in r['checks'].items()})
    report['orphan_service']=service_boundary('orphan')
    report['capacity_service']=service_boundary('capacity')
    report['cases'].append({'id':'NEG-14','status':'PASS','layer':'host_isolated_fixture','elapsed_seconds':time.monotonic()-start})
    report['status']='PASS'
except Exception as e:
    report.update(status='FAIL',error_type=type(e).__name__,error=str(e),traceback=traceback.format_exc())
report['completed_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
raw=json.dumps(report,ensure_ascii=False,indent=2).encode();(OUT/'RESULT.json').write_bytes(raw)
print(json.dumps({'status':report['status'],'checks':len(report['checks']),'cases':report['cases'],'result':str(OUT/'RESULT.json'),'sha256':hashlib.sha256(raw).hexdigest()}))
sys.exit(0 if report['status']=='PASS' else 1)
