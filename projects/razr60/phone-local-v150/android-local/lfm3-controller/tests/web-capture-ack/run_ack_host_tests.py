#!/usr/bin/env python3
"""Host ACK integration; full actual client/receipt/journal/files, exact Session method blocks, explicit platform doubles."""
import argparse,ast,hashlib,importlib.util,json,os,pathlib,subprocess,time
def need(ok,msg):
 if not ok:raise RuntimeError(msg)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def enc(v):return (json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
def main():
 a=argparse.ArgumentParser();a.add_argument('--source',type=pathlib.Path,required=True);a.add_argument('--helper-source',type=pathlib.Path,required=True);a.add_argument('--output',type=pathlib.Path,required=True);a.add_argument('--java-home',type=pathlib.Path,required=True);a.add_argument('--json-jar',type=pathlib.Path,required=True);a.add_argument('--retained-helper-tests',type=pathlib.Path,required=True);args=a.parse_args()
 source=args.source;helper=args.helper_source;test=source/'tests/web-capture-ack';out=args.output;out.mkdir(parents=True,exist_ok=False);gen=out/'generated';gen.mkdir();classes=out/'classes';classes.mkdir();tracked={}
 def bound(p):
  p=pathlib.Path(p);raw=p.read_bytes();tracked[str(p)]=raw;return raw
 def put(p,raw):p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
 result={'schema':'hepta.helper7-capture-ack-host.v1','all_pass':False,'started_epoch':time.time(),'phone_operations':0,'platform_boundaries':['Android Context/PM UID and Binder transport are deterministic host doubles','WebView callbacks are retained synthetic factories','Linux file bytes/modes/hardlinks/symlinks are real','Directory fsync is logged/fault-injected, not an Android durability claim'],'steps':[]}
 try:
  qr=source/'tests/web-flight/run_query_host_tests.py';bound(qr);spec=importlib.util.spec_from_file_location('retained_query_contract',qr);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  paths=[source/p for p in module.PURE_PATHS if p!='tests/web-flight/WebFlightQueryHostTest.java']
  ack_source=source/'src/org/trillionnium/hepta/webprotocol/WebCaptureAcknowledgement.java'
  if ack_source not in paths:paths.append(ack_source) # Current query pure closure also names this shared production class.
  paths += [source/'src/org/trillionnium/hepta/local/WebEvidenceClient.java',source/'src/org/trillionnium/hepta/local/WebEvidenceJournal.java',source/'src/org/trillionnium/hepta/local/MobiMindPrivateFiles.java']
  paths += [helper/('src/org/trillionnium/hepta/webhelper/'+n+'.java') for n in ['Jsons','EvidenceFiles','RemoteReply','ObservedLinkPermit']]
  paths += [args.retained_helper_tests/'tests/scoped-navigation/WebScopedNavigationHostTest.java']
  factory_spec=next(x for x in module.FACTORY_SPECS if x['name']=='WebFlightEvidenceHostTest')
  factory_data,factory_receipt=module.factory_projection(bound(source/factory_spec['path']),factory_spec)
  factory_path=gen/'org/trillionnium/hepta/local/WebFlightEvidenceHostTest.java';put(factory_path,factory_data);paths.append(factory_path);result['retained_synthetic_factory']=factory_receipt
  session=bound(helper/'src/org/trillionnium/hepta/webhelper/EvidenceSession.java')
  signatures=['private void requireSame(RemoteReply reply)','private void consume(RemoteReply reply)','private JSONArray closeHistory()','private JSONObject closeRequests()','private void preservePrevious()','private void capture(final RemoteReply reply)','private void captureFailed(RemoteReply reply,long startedEpoch,String reason)','private void acknowledgeCapture(final RemoteReply reply)','private void armObservedLink(final RemoteReply reply)','private String currentJournalState()','private void persist(String state)','private void send(RemoteReply reply,String status,String reason,EvidenceFiles.Record raw,JSONObject close)','private JSONObject base(RemoteReply reply,String status,String reason)','private void replyFailure(RemoteReply reply,String status,String reason)','private static boolean allCleanup(JSONObject value)','private static String message(Exception failure)','private static String bounded(String text)','private static void requireUi()']
  blocks=[module.java_block(session,s) for s in signatures];head=bound(test/'AckSessionProjection.header').decode()
  projection=(head+'\n\n'.join(blocks)+'\n}\n').encode();proj=gen/'org/trillionnium/hepta/webhelper/AckSessionProjection.java';put(proj,projection);paths.append(proj)
  result['session_projections']=[{'signature':sig,'sha256':sha(block.encode()),'bytes':len(block.encode()),'modified':False} for sig,block in zip(signatures,blocks)]
  result['session_full_source_sha256']=sha(session);result['projection_sha256']=sha(projection)
  paths += sorted((test/'fixtures').rglob('*.java'));paths += [test/'CaptureAckHostTest.java']
  need(len(paths)==len(set(paths)),'duplicate Java inputs')
  for p in paths:bound(p)
  need(sha(bound(args.json_jar))=='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed','JSON dependency')
  for filename in ['WebEvidenceProtocol.java','WebCaptureAcknowledgement.java']:
   need(bound(helper/'src/org/trillionnium/hepta/webprotocol'/filename)==bound(source/'src/org/trillionnium/hepta/webprotocol'/filename),'shared source bytes')
  commands=[('javac',[str(args.java_home/'bin/javac'),'--release','8','-encoding','UTF-8','-proc:none','-classpath',str(args.json_jar),'-d',str(classes),*map(str,paths)]),('ack-integration',[str(args.java_home/'bin/java'),'-cp',str(classes)+os.pathsep+str(args.json_jar),'org.trillionnium.hepta.local.CaptureAckHostTest',str(out/'CASES.json'),str(out/'files')])]
  for name,argv in commands:
   started=time.monotonic();p=subprocess.run(argv,capture_output=True,timeout=120);put(out/(name+'.stdout'),p.stdout);put(out/(name+'.stderr'),p.stderr);result['steps'].append({'name':name,'argv':argv,'exit_code':p.returncode,'elapsed_seconds':time.monotonic()-started,'stdout_sha256':sha(p.stdout),'stderr_sha256':sha(p.stderr)})
   if p.returncode:raise RuntimeError(name+' exited '+str(p.returncode)+'\n'+p.stderr.decode()[-12000:])
  result['cases']=json.loads((out/'CASES.json').read_text());need(result['cases']['all_pass'] is True,'cases pass');result['all_pass']=True
 except Exception as e:
  import traceback
  result['error']=str(e);put(out/'ERROR.txt',traceback.format_exc().encode())
 finally:
  result['originals_unchanged']=all(pathlib.Path(p).read_bytes()==raw for p,raw in tracked.items());result['all_pass']=result['all_pass'] and result['originals_unchanged'];result['source_inputs']=[{'path':p,'bytes':len(raw),'sha256':sha(raw)} for p,raw in sorted(tracked.items())];result['finished_epoch']=time.time();put(out/'RESULT.json',enc(result));print(json.dumps({'all_pass':result['all_pass'],'error':result.get('error'),'cases':result.get('cases',{}).get('cases'),'assertions':result.get('cases',{}).get('assertions'),'result':str(out/'RESULT.json'),'result_sha256':sha(enc(result))},ensure_ascii=False))
 return 0 if result['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
