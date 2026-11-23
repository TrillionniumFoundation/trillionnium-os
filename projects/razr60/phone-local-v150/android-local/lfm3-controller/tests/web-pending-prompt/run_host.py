#!/usr/bin/env python3
"""Fresh production receipt/waiting/progress host replay; no device/model access."""
import argparse,hashlib,importlib.util,json,os,signal,subprocess,sys,time
from pathlib import Path
D='src/org/trillionnium/hepta/local/WebFlightDomain.java'
OLD='c61938db4efa4df6faa33de2be23e8bfc9086fe95bcb6af0269f6d98505bfc01'
NEW='1b1a27d8c4bb410b92827a85621904e2db2fdc8287730d01c0a5af3d5e7826b5'
def sha(b):return hashlib.sha256(b).hexdigest()
def need(v,s):
 if not v:raise RuntimeError(s)
def put(p,b):
 p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('xb') as f:f.write(b)
def enc(o):return (json.dumps(o,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
def command(out,name,argv):
 t=time.monotonic();p=subprocess.Popen(list(map(str,argv)),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
 try:o,e=p.communicate(timeout=120)
 except BaseException:
  for sig in (signal.SIGTERM,signal.SIGKILL):
   try:os.killpg(p.pid,sig)
   except ProcessLookupError:pass
  o,e=p.communicate(timeout=10);put(out/(name+'.stdout'),o);put(out/(name+'.stderr'),e);raise
 put(out/(name+'.stdout'),o);put(out/(name+'.stderr'),e)
 return dict(name=name,exit_code=p.returncode,seconds=time.monotonic()-t,stdout_sha256=sha(o),stderr_sha256=sha(e),stderr_bytes=len(e))
def main():
 p=argparse.ArgumentParser(description=__doc__)
 fixture_names=('calendar_dom','calendar_ax','home_capture','original_prompt','unavailable_binding','unavailable_request','unavailable_reply','pending_prompt')
 for n in ('baseline','candidate','output','test','java-home','json-jar','json-source',*[n.replace('_','-') for n in fixture_names]):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();need(all(v.is_absolute() and not any(x.is_symlink() for x in (v,*v.parents)) for v in vars(a).values()),'ordinary absolute paths required')
 need(not a.output.exists() and a.baseline not in a.output.parents and a.candidate not in a.output.parents,'exclusive output outside sources')
 originals={};roles={}
 def bound(path,role):
  b=path.read_bytes();originals[path]=b;roles[path]=role;return b
 loader=a.baseline/'tests/web-flight/run_query_host_tests.py';bound(loader,'factory_loader');spec=importlib.util.spec_from_file_location('query_factories',loader);q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)
 sources={n:bound(a.baseline/n,'baseline/'+n) for n in q.PURE_PATHS}
 need(D in sources and sha(sources[D])==OLD and sha(bound(a.candidate/D,'candidate/'+D))==NEW,'exact r2 Domain pair')
 raw=sources[q.RETAINED_QUERY['path']];need(len(raw)==q.RETAINED_QUERY['bytes'] and sha(raw)==q.RETAINED_QUERY['sha256'],'unchanged query factories')
 generated=[];factories=[]
 json_source=bound(a.json_source,'upstream_JSON_java_20240303_JSONObject')
 need(sha(json_source)=='e7ff98437abfc67e18765f4e810247ce9a908328b39dfe999d61a8eb17dca49c','pinned upstream JSON source')
 old='''                    this.map.put(String.valueOf(e.getKey()), wrap(value, recursionDepth + 1, jsonParserConfiguration));
                }
'''
 new='''                    this.map.put(String.valueOf(e.getKey()), wrap(value, recursionDepth + 1, jsonParserConfiguration));
                } else {
                    // Host-only Android JSONObject(Map) compatibility: preserve explicit null entries.
                    this.map.put(String.valueOf(e.getKey()), NULL);
                }
'''
 need(json_source.decode().count(old)==1,'one Map null compatibility site')
 compatibility=json_source.decode().replace(old,new).encode()
 generated.append(('generated/org/json/JSONObject.java',compatibility))
 for pin in q.FACTORY_SPECS:
  raw,record=q.factory_projection(bound(a.baseline/pin['path'],'factory/'+pin['path']),pin);generated.append((pin['generated']['path'],raw));factories.append(record)
 session=bound(a.baseline/'src/org/trillionnium/hepta/local/WebFlightSession.java','baseline/Session dispatch blocks');methods=[]
 for pin in q.METHOD_PINS:
  s=q.java_block(session,pin['signature']);need(len(s.encode())==pin['bytes'] and sha(s.encode())==pin['sha256'],'unchanged dispatch block');methods.append(s)
 generated.append(('generated/org/trillionnium/hepta/local/WebFlightDispatchProjection.java',q.PROJECTION.replace('/* EXACT_METHODS */','\n'.join(methods)).encode()))
 test=bound(a.test,'pending_prompt_test');jar=bound(a.json_jar,'json_dependency');need(sha(jar)=='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed','pinned JSON')
 for name in fixture_names:bound(getattr(a,name),'original/'+name)
 a.output.mkdir(mode=0o700)
 r=dict(schema='hepta.flight-pending-goal-host-pair.v1',all_pass=False,phone_actions=0,model_executed=False,business_verified=False,production_methods_executed=['WebEvidenceReceipt.verify','WebFlightDomain.waiting','WebFlightDomain.withProgress','WebFlightProgress transitions'],actual_receipt_metadata_only=True,actual_native_frame_synthetic=True,other_stage_envelopes_synthetic=True,session_loop_executed=False,original_query_test_main_executed=False,baseline_domain_sha256=OLD,candidate_domain_sha256=NEW,test_sha256=sha(test),factory_projections=factories,runs=[])
 r['host_json_map_null_compatibility']=dict(upstream_source_sha256=sha(json_source),generated_sha256=sha(compatibility),scope='Only JSONObject(Map) null entries are retained to match Android; original evidence and production files stay byte-identical.',upstream_url='https://github.com/stleary/JSON-java/blob/20240303/src/main/java/org/json/JSONObject.java')
 try:
  fp=[]
  for n,b in generated:t=a.output/n;put(t,b);fp.append(t)
  results={}
  for side in ('baseline','candidate'):
   out=a.output/side;out.mkdir();cl=out/'classes';cl.mkdir();prod=[a.candidate/n if side=='candidate' and n==D else a.baseline/n for n in q.PURE_PATHS]
   c=command(out,'compile',[a.java_home/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-cp',a.json_jar,'-d',cl,*prod,*fp,a.test]);r['runs'].append(dict(side=side,compile=c));need(c['exit_code']==0,'fresh production compile '+side)
   run=command(out,'stages',[a.java_home/'bin/java','-Xmx768m','-cp',str(cl)+os.pathsep+str(a.json_jar),'org.trillionnium.hepta.local.WebFlightPendingGoalHostTest',a.calendar_dom,a.calendar_ax,a.home_capture,a.original_prompt,out/'CASES.json',a.unavailable_binding,a.unavailable_request,a.unavailable_reply,a.pending_prompt]);r['runs'][-1]['stages']=run
   need(run['exit_code']==(2 if side=='baseline' else 0) and run['stderr_bytes']==0,'precise baseline red/candidate green '+side)
   raw=(out/'CASES.json').read_bytes();v=json.loads(raw);results[side]=v;need(v['stages_count']==22 and v['actual_unavailable_receipt_verified_with_production_verifier'] is True,'stage and real receipt coverage')
   checks=v['desired_home_and_pending_checks'];need(len(checks)==5,'exact behavior checks');failed=[x['name'] for x in checks if not x['pass']]
   need(failed==(['capture_pending_retains_wait_goal','actual_capture_pending_retains_wait_goal'] if side=='baseline' else []),'only the two expected pending hint failures')
   r['runs'][-1].update(stages_count=v['stages_count'],assertions=v['assertions'],desired_checks=5,failed_expected_behavior_checks=failed,private_cases_sha256=sha(raw))
  old=results['baseline'];new=results['candidate'];need(old['assertions']==new['assertions'],'same invariant checks');changes=[]
  for l,z in zip(old['stages'],new['stages']):
   need(l['name']==z['name'],'same stage order')
   if l!=z:
    need(l['name'] in ('capture_pending','actual_capture_pending'),'unexpected changed stage');c=json.loads(json.dumps(l));c['current']['next_goal']=z['current']['next_goal'];need(c==z,'only pending next_goal may differ');changes.append(l['name'])
  need(changes==['capture_pending','actual_capture_pending'],'exact prompt deltas')
  r.update(all_pass=True,stages_per_side=22,invariant_assertions_per_side=new['assertions'],desired_checks_per_side=5,baseline_expected_failures=2,candidate_behavior_failures=0,only_two_pending_next_goal_values_changed=True,changed_stages=changes)
 except Exception as e:r['error']=type(e).__name__+': '+str(e)
 finally:
  r['originals_unchanged']=all(p.read_bytes()==b for p,b in originals.items());r['all_pass'] &= r['originals_unchanged'];r['bound_inputs']=[dict(role=roles[p],bytes=len(b),sha256=sha(b)) for p,b in originals.items()];raw=enc(r);put(a.output/'RESULT.json',raw);print(json.dumps({k:r.get(k) for k in ('all_pass','error','stages_per_side','invariant_assertions_per_side','baseline_expected_failures','candidate_behavior_failures','originals_unchanged')}|{'result_sha256':sha(raw)}))
 return 0 if r['all_pass'] else 1
if __name__=='__main__':
 sys.dont_write_bytecode=True
 raise SystemExit(main())
