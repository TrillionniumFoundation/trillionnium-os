#!/usr/bin/env python3
"""Actual private calendar Adapter/Session/fresh/ActionSlot/BG/form connection with explicit native and Android IO ports."""
import argparse,hashlib,importlib.util,json,os,re,stat,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
PKG=Path('src/org/trillionnium/hepta/local')
def sha(b):return hashlib.sha256(b).hexdigest()
def ref(p):
 p=Path(p).resolve();b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':sha(b),'mode':stat.S_IMODE(p.stat().st_mode)}
def load(p,n):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def section(t,a,b):
 if t.count(a)!=1 or t.count(b)!=1:raise RuntimeError('nonunique section: '+a)
 i=t.index(a);return t[i:t.index(b,i)]
def body(t,a):
 if t.count(a)!=1:raise RuntimeError('nonunique actual member: '+a)
 start=t.index(a);i=t.index('{',start);depth=0;state='code';q=''
 while i<len(t):
  c=t[i];n=t[i+1] if i+1<len(t) else ''
  if state=='line':
   if c=='\n':state='code'
  elif state=='comment':
   if c=='*' and n=='/':state='code';i+=1
  elif state=='string':
   if c=='\\':i+=1
   elif c==q:state='code'
  elif c=='/' and n=='/':state='line';i+=1
  elif c=='/' and n=='*':state='comment';i+=1
  elif c in ('"',"'"):state='string';q=c
  elif c=='{':depth+=1
  elif c=='}':
   depth-=1
   if depth==0:return t[start:i+1]
  i+=1
 raise RuntimeError('unterminated member: '+a)
def main():
 ap=argparse.ArgumentParser(description=__doc__)
 for k in ('source','output','java-home','json-jar'):ap.add_argument('--'+k,type=Path,required=True)
 a=ap.parse_args();S=a.source.resolve();O=a.output.resolve();J=a.java_home.resolve();jar=a.json_jar.resolve()
 if O.exists() or S in O.parents:raise RuntimeError('fresh independent output required')
 O.mkdir(parents=True,mode=0o700)
 if sha(jar.read_bytes())!='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed':raise RuntimeError('real pinned JSON jar required')
 tools=[J/'bin/java',J/'bin/javac',J/'lib/modules',J/'lib/ct.sym',jar,Path(sys.executable).resolve()]
 report={'schema':'hepta.calendar-action-connection-focus.v1','all_pass':False,'source':str(S),'phone_actions':0,'model_executions':0,'android_inputs':0,'stages':[],'started_host_wall_ms':int(time.time()*1000)}
 originals=[]
 def whole():return [ref(p) for p in sorted(S.rglob('*')) if p.is_file()]
 report['whole_source_before']=whole()
 try:
  helper=S/'tests/native-calendar-date-model/run_host.py';base=load(helper,'calendar_fresh_base')
  paths,originals,closure=base.prepare(S,O);selected={base.classname(p):p for p in paths}
  originals=list(dict.fromkeys(originals+[helper,Path(__file__).resolve()]))
  out=O/'fresh-bridge';out.mkdir()
  def generated(rel,t):
   p=out/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(t);selected[base.classname(p)]=p;return p
  H=(S/PKG/'HeptaAccessibilityService.java').read_text();L=(S/PKG/'LocalTaskController.java').read_text()
  Q=(S/PKG/'QualificationScopeConfig.java').read_text();extracted=[]
  def member(owner,t,a):
   b=body(t,a);extracted.append({'source':str(S/PKG/owner),'anchor':a,'bytes':len(b.encode()),'sha256':sha(b.encode()),'verbatim':True});return b
  def block(owner,t,a,b):
   v=section(t,a,b);extracted.append({'source':str(S/PKG/owner),'start':a,'end':b,'bytes':len(v.encode()),'sha256':sha(v.encode()),'verbatim':True});return v
  ha=[]
  # The actual null-submission path is shared by the calendar read admission.
  # Keep its cleanup/activation methods verbatim; this fixture cannot mint a
  # post-effect retry proof or a NativeReadIdentity.
  for field in ['    private final Object postEffectSamplingLock=new Object();',
                '    private PostEffectSamplingRetry pendingPostEffectSampling;']:
   if H.count(field)!=1:raise RuntimeError('one exact sampling tracker field required')
   ha.append(field)
   extracted.append({'source':str(S/PKG/'HeptaAccessibilityService.java'),'field':field,
    'bytes':len(field.encode()),'sha256':sha(field.encode()),'verbatim':True})
  for anchor in [
   '    private static final class PostEffectSamplingRetry {',
   '    private void discardPostEffectSampling(PostEffectSamplingRetry expected){',
   '    private boolean postEffectSamplingCurrent(PostEffectSamplingRetry pending,long now){',
   '    private PostEffectSamplingRetry postEffectSamplingHandoff(PostEffectObservationRetryProof proof){',
   '    private void discardPostEffectSamplingSubmission(PostEffectObservationRetryProof proof){',
   '    private void activateObservationRequest(ObservationRequest request){']:
   ha.append(member('HeptaAccessibilityService.java',H,anchor))
  ha.append(member('HeptaAccessibilityService.java',H,'    public interface ObservationCallback {'))
  ha.append('    public interface Cancellation {boolean isCancelled();}')
  ha.append(block('HeptaAccessibilityService.java',H,'    private static final class ObservationEventWatermark {','    /** Legacy untyped events'))
  ha.append(block('HeptaAccessibilityService.java',H,'    /** One typed read, using the existing observation request/PNG publication.','    public void observe(final String taskId,final File evidenceDirectory,final Cancellation cancel,'))
  ha.append(block('HeptaAccessibilityService.java',H,'    public void observe(final String taskId,final File evidenceDirectory,final Cancellation cancel,','    private synchronized void recordObservationAdmission('))
  for anchor in [
   '    private synchronized void recordObservationAdmission(ObservationRequest request){',
   '    private boolean observationActive(ObservationRequest request){',
   '    private void requireObservationWork(ObservationRequest request){',
   '    private GraphBudget observationBudget(final ObservationRequest request){',
   '    private static ObservationStabilityGate.FrameKey frameKey(Graph graph){',
   '    private void captureObservation(final ObservationRequest request){',
   '    private void processScreenshot(final ObservationRequest request,final CaptureIdentity identity,final ScreenshotResult result){',
   '    private void acceptScreenshot(ObservationRequest request,ObservationProduct product,boolean retry,String error){',
   '    private void writeObservationPng(final ObservationRequest request,Bitmap bitmap,FileOutputStream stream)throws Exception{',
   '    private static Bitmap copyScreenshot(ScreenshotResult result) {',
   '    private void clearSnapshot(){',
   '    private synchronized boolean owns(String taskId) {',
   '    private synchronized boolean ownsBackground(String id,BackgroundSession background){',
   '    private synchronized boolean ownsAuthorization(String id,TaskAuthorization.Gate auth){',
   '    private synchronized BackgroundSession backgroundFor(String taskId){',
   '    void requireTaskAuthorization(String id,TaskAuthorization.Gate auth){',
   '    void requireScopeObservation(String taskId,PhoneObservation observation){',
   '    void requireAuthorizationObservation(String id,TaskAuthorization.Gate auth,PhoneObservation obs){',
   '    void requireBackgroundObservation(String id,PhoneObservation observed){',
   '    private static void requireHistoricalProfileWindow(BackgroundSession background,PhoneObservation frame){',
   '    void requireVisualFrameOwnership(LocalTaskController expectedController,String id,',
   '    void verifyBackgroundRemote(String id)throws Exception{',
   '    JSONObject qualificationScopeEvidence(String taskId){',
   '    JSONObject backgroundEvidence(String id){',
   '    private synchronized QualificationScopeConfig.Bound scopeFor(String taskId){',
   '    private static void requireSameProfileOwner(WindowOwnership original,WindowOwnership actual){',
   '    private static String fileSha256(File file)throws Exception{',
   '    String observationTimeoutMessage(String taskId){']:
   ha.append(member('HeptaAccessibilityService.java',H,anchor))
  ha.append(block('HeptaAccessibilityService.java',H,'    interface CalendarActionCallback {','    public void perform(final String taskId,final PhoneObservation expected,final ActionDecision decision,\n                        final ObservedTargetLabels targets,final TaskAuthorization.Gate expectedAuthorization,final String modelRunId,'))
  for anchor in [
   '    private final class ActionWork {',
   '    boolean actionWorkPending(){',
   '    void retireActionWork(String taskId,String reason){',
   '    private synchronized boolean ownsScope(String taskId,QualificationScopeConfig.Bound scope){',
   '    private JSONObject callbackAuthorizationEvidence(TaskAuthorization.Gate auth,boolean current,boolean stopped){',
   '    private static JSONObject callbackScopeEvidence(String taskId,QualificationScopeConfig.Bound captured,boolean currentLease,boolean cancelled){',
   '    private static JSONObject actionDiagnosticEvidence(ActionWork work){',
   '    private Cancellation actionCancellation(final ActionWork work,final Cancellation original){',
   '    private static void actionCheck(ActionWork work){',
   '    private void requireLiveProfileBeforeEffect(ActionWork work){',
   '    private void enterActionEffect(ActionWork work){',
   '    private static void actionEffectReturned(ActionWork work,Boolean accepted){',
   '    private static final class SearchEvents {',
   '    private static boolean sameSearchEvents(NativeSearchPlanning.EventMark a,NativeSearchPlanning.EventMark b){',
   '    private void noteNativeSearchEvent(int display,int window,String pkg,boolean content,boolean typed){',
   '    void requireNativeCalendarSourceOwnership(LocalTaskController controller,NativeAppSession nativeTask,',
   '    void requireExperimentalModelScope(LocalTaskController expectedController,String id,TaskAuthorization.Gate auth,']:
   ha.append(member('HeptaAccessibilityService.java',H,anchor))
  graph='\n'.join(member('HeptaAccessibilityService.java',H,a) for a in [
    '        boolean sameWindow(Graph other){','        boolean sameWindowAndTree(Graph other){','        Graph copyForAction(String nodeId,WebRegionNativeBridge region){'])
  oldport=selected['org.trillionnium.hepta.local.HeptaAccessibilityService'].read_text()
  oldtypes=[member('HeptaAccessibilityService.java',H,'    public static final class ActionOutcome {')]
  for name in ['NativeSearchReadRetryProof','NativeSearchNoEffectReplanProof','NativeSearchSamplingExhaustionProof','NativeSearchFinalCensusResampleProof']:
   m=re.search(r'(?:public )?static final class '+name+r'\s*\{',oldport)
   if not m:raise RuntimeError('missing already refusing old proof '+name)
   oldtypes.append(body(oldport,m.group()))
  here=S/'tests/native-calendar-date-actions'
  for n in ['HeptaActionHost.template','ControllerActionHost.template']:originals.append(here/n)
  ht=(here/'HeptaActionHost.template').read_text().replace('@@OLD_TYPES@@','\n'.join(oldtypes)).replace('@@ACTUAL_HA@@','\n'.join(ha)).replace('@@ACTUAL_GRAPH@@',graph)
  # Exact old shape replacement; no successful proof/identity port is added.
  prior_proof='    static final class PostEffectObservationRetryProof {}'
  refusing_proof='    // Only type closure for the unavailable post-effect route. A valid proof\n    // is never created by this calendar host fixture.\n    static final class PostEffectObservationRetryProof {\n        final Object issuer=null,samplingHandoff=null;\n        final NativeReadIdentity identity=null;\n        final String taskId=null,requestId=null;\n        final long deadline=-1,transitionDeadline=-1;\n        final AtomicBoolean consumed=new AtomicBoolean(false);\n        private PostEffectObservationRetryProof(){\n            throw new AssertionError("post-effect retry proof unavailable in calendar fixture");\n        }\n    }'
  prior_stale='    static final class StaleObservation extends RuntimeException {private static final long serialVersionUID=1L;StaleObservation(){}StaleObservation(String s){super(s);}}'
  if ht.count(prior_proof)!=1 or ht.count(prior_stale)!=1:raise RuntimeError('exact prior calendar proof/failure ports required')
  ht=ht.replace(prior_proof,refusing_proof,1).replace(prior_stale,member('HeptaAccessibilityService.java',H,'    private static final class StaleObservation extends IllegalStateException {'),1)
  extracted.append({'fixture_type_port':'PostEffectObservationRetryProof','private_throwing_constructor':True,
   'cannot_issue_post_effect_proof':True,'native_read_identity_port_still_refuses':True,
   'prior_bytes':len(prior_proof.encode()),'prior_sha256':sha(prior_proof.encode()),
   'bytes':len(refusing_proof.encode()),'sha256':sha(refusing_proof.encode())})
  generated('org/trillionnium/hepta/local/HeptaAccessibilityService.java',ht)
  lt=[member('LocalTaskController.java',L,'    private static NotesCompletionEvidence.Frame completionFrame(PhoneObservation o){'),
      block('LocalTaskController.java',L,'    void requireNativeCalendarFreshOwner(NativeAppSession.CalendarFreshRead read){','    private PhoneObservation awaitObservation(final String id,final File directory,final TaskAuthorization.Gate authorization,final long deadline)throws Exception{'),
      block('LocalTaskController.java',L,'    private PhoneObservation awaitObservationRaw(String id,File directory,TaskAuthorization.Gate authorization,long deadline)throws Exception{','    /** Optional values join the one existing result.json write after original cleanup.'),
      member('LocalTaskController.java',L,'    private void checkActive(long deadline)throws Stopped{'),
      member('LocalTaskController.java',L,'    private static final class Stopped extends Exception {'),
      member('LocalTaskController.java',L,'    private static void record(File directory,String name,JSONObject value)throws Exception{')]
  lt.append(block('LocalTaskController.java',L,'    private static final String NATIVE_CALENDAR_SYSTEM=', '    private ModelAnswer awaitModel('))
  generated('org/trillionnium/hepta/local/LocalTaskController.java',(here/'ControllerActionHost.template').read_text().replace('@@ACTUAL_LTC@@','\n'.join(lt)))
  qc=selected['org.trillionnium.hepta.local.QualificationScopeConfig'].read_text()
  additions=[member('QualificationScopeConfig.java',Q,'    static final class Bound {')]
  for anchor in ['    private static JSONObject pathDiagnostics(Context context,FilesRoot root){','    private static void diagnosticPath(JSONObject out,String name,File path)throws Exception{','    private static String boundedPath(String path){','    static Object nullable(Object value){']:
   additions.append(member('QualificationScopeConfig.java',Q,anchor))
  additions.append('    static String home(Context c){throw new AssertionError("configured HOME path unavailable in unconfigured public-task scope");}')
  qc=qc.replace('import android.content.Context;','import org.json.JSONObject;import android.content.Context;')
  qc=qc[:qc.rfind('}')]+ '\n'.join(additions)+'\n}\n'
  generated('org/trillionnium/hepta/local/QualificationScopeConfig.java',qc)
  bp=selected['android.graphics.Bitmap'];bt=bp.read_text()
  bt=bt[:bt.rfind('}')]+"""
 public byte[] encoded;
 // Unknown color metadata retains the pre-existing encoded-byte IO endpoint.
 public android.graphics.ColorSpace getColorSpace(){return null;}
 public Config getConfig(){return Config.ARGB_8888;}
 public boolean isMutable(){return false;}
 public boolean hasGainmap(){return false;}
 public int getGenerationId(){return 1;}
 public boolean isRecycled(){return recycled;}
 public enum CompressFormat {PNG}
 public static Bitmap wrapHardwareBuffer(android.hardware.HardwareBuffer b,Object color){return b.bitmap;}
 public Bitmap copy(Config c,boolean mutable){Bitmap value=new Bitmap(image);value.encoded=encoded==null?null:encoded.clone();return value;}
 public boolean compress(CompressFormat f,int quality,java.io.OutputStream out){
  try{if(encoded!=null){out.write(encoded);return true;}return javax.imageio.ImageIO.write(image,"png",out);}catch(java.io.IOException e){return false;}}
}
"""
  generated('android/graphics/Bitmap.java',bt)
  for name in ['android.graphics.ColorSpace','android.os.Build']:
   if name not in selected:
    p=S/'tests/observation-png/stubs'/Path(name.replace('.','/')+'.java')
    selected[name]=p;originals.append(p)
  generated('android/hardware/HardwareBuffer.java','package android.hardware;public final class HardwareBuffer {public final android.graphics.Bitmap bitmap;public boolean closed;public static int closes;public HardwareBuffer(android.graphics.Bitmap b){bitmap=b;}public void close(){if(closed)throw new IllegalStateException("hardware buffer double close");closed=true;closes++;}}')
  cp=selected['android.os.SystemClock'];generated('android/os/SystemClock.java',cp.read_text().replace('public static long now=','public static volatile long now=').replace('public static long elapsedRealtime()', 'public static long uptimeMillis(){return now-17;}public static long elapsedRealtime()'))
  generated('android/view/accessibility/AccessibilityWindowInfo.java','package android.view.accessibility;public final class AccessibilityWindowInfo {public static final int TYPE_APPLICATION=1;}')
  for n in ['ObservationDiagnostics','ObservationStabilityGate','ObservationPngEncoder']:
   p=S/PKG/(n+'.java');selected['org.trillionnium.hepta.local.'+n]=p;originals.append(p)
  test=here/'NativeCalendarDateActionHostTest.java';selected[base.classname(test)]=test;originals.append(test)
  originals=list(dict.fromkeys(originals+[S/PKG/'HeptaAccessibilityService.java',S/PKG/'LocalTaskController.java',S/PKG/'QualificationScopeConfig.java']))
  reply=here/'CalendarDateReplyHost.java';selected[base.classname(reply)]=reply;originals.append(reply)
  for n in ['ConservativeTokenBudget']:
   p=S/PKG/(n+'.java');selected[base.classname(p)]=p;originals.append(p)
  generated('android/view/accessibility/AccessibilityNodeInfo.java','package android.view.accessibility;public final class AccessibilityNodeInfo {public boolean recycled;public void recycle(){if(recycled)throw new IllegalStateException("double recycle");recycled=true;}}')
  generated('android/app/KeyguardManager.java','package android.app;public final class KeyguardManager {public boolean locked,secure,deviceSecure,deviceLocked;public boolean isKeyguardLocked(){return locked;}public boolean isKeyguardSecure(){return secure;}public boolean isDeviceSecure(){return deviceSecure;}public boolean isDeviceLocked(){return deviceLocked;}}')
  generated('android/os/Looper.java','package android.os;public final class Looper {private static final Looper MAIN=new Looper();private static final ThreadLocal<Boolean> ui=new ThreadLocal<Boolean>();public static void hostUi(boolean b){ui.set(Boolean.valueOf(b));}public static Looper myLooper(){return Boolean.TRUE.equals(ui.get())?MAIN:null;}public static Looper getMainLooper(){return MAIN;}}')
  generated('android/util/Log.java','package android.util;public final class Log {public static java.util.function.Consumer<String> observer;public static int i(String tag,String message){if(observer!=null)observer.accept(message);return 0;}}')
  socket=selected['android.net.LocalSocket'].read_text()
  socket=socket.replace('public static Reply responder;', 'public static Reply responder;public static Runnable afterPeer;public static int writtenFrames;')
  socket=socket.replace('responder=null;peerUid=', 'responder=null;afterPeer=null;writtenFrames=0;peerUid=')
  socket=socket.replace('return new Credentials(peerUid);', 'if(afterPeer!=null)afterPeer.run();return new Credentials(peerUid);')
  socket=socket.replace('sent=output.toByteArray();try{', 'sent=output.toByteArray();writtenFrames++;try{')
  generated('android/net/LocalSocket.java',socket)
  report['closure']={'prior_actual_model_fixture':closure,'actual_members':extracted,
   'boundary':'Whole actual Session/Adapter/BG/Phone/Frame/TaskAuth and actual private producers, original ActionWork/ActionExecutionState/Slot, all calendar LTC methods, pixel worker/finally/publication and private FORM verification. Android graph/pixel/root, scheduling, native return and full framed socket reply are explicit host ports. No phone/model or actual broker/platform injection qualification; unrelated search and permission workers cannot be constructed.'}
  (O/'ACTUAL-METHODS.json').write_text(json.dumps(extracted,indent=2)+'\n')
  paths=list(selected.values())
  report['source_inputs_before']=[ref(p) for p in originals];report['compile_inputs']=[ref(p) for p in paths];report['tools_before']=[ref(p) for p in tools]
  C=O/'classes';C.mkdir();env={**os.environ,'PATH':str(J/'bin')+':/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'}
  for k in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH'):env.pop(k,None)
  stages=[('compile',[J/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all,-options','-Werror','-cp',jar,'-d',C,*paths]),
   ('actions',[J/'bin/java','-Djava.awt.headless=true','-cp',str(C)+os.pathsep+str(jar),'org.trillionnium.hepta.local.NativeCalendarDateActionHostTest',O,O/'work',S/'tests/vlm-contract/fixtures/gui-owl-chat-template.jinja'])]
  for name,argv in stages:
   t=time.monotonic();p=subprocess.run(list(map(str,argv)),cwd=O,env=env,capture_output=True,timeout=180)
   for kind,b in [('stdout',p.stdout),('stderr',p.stderr)]:(O/(name+'.'+kind)).write_bytes(b)
   report['stages'].append({'name':name,'argv':list(map(str,argv)),'cwd':str(O),'exit_code':p.returncode,'elapsed_seconds':time.monotonic()-t,'stdout':ref(O/(name+'.stdout')),'stderr':ref(O/(name+'.stderr'))})
   if p.returncode:raise RuntimeError('actual stage failed: '+name)
  report['cases']=json.loads((O/'CASES.json').read_text())
  if not report['cases']['all_pass']:raise RuntimeError('necessary fresh cases failed')
  report['all_pass']=True
 except Exception as e:report['error']=type(e).__name__+': '+str(e)
 finally:
  if originals and 'source_inputs_before' in report:
   report['source_inputs_after']=[ref(p) for p in originals];report['tools_after']=[ref(p) for p in tools]
   report['source_inputs_unchanged']=report['source_inputs_before']==report['source_inputs_after'];report['tools_unchanged']=report['tools_before']==report['tools_after']
   report['all_pass'] &= report['source_inputs_unchanged'] and report['tools_unchanged']
  report['whole_source_after']=whole();report['whole_source_unchanged']=report['whole_source_before']==report['whole_source_after'];report['all_pass'] &= report['whole_source_unchanged']
  if (O/'CASES.json').exists():report['cases']=json.loads((O/'CASES.json').read_text())
  report['finished_host_wall_ms']=int(time.time()*1000);report['artifacts']=[ref(p) for p in O.rglob('*') if p.is_file() and p.name!='RESULT.json']
  (O/'RESULT.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'all_pass':report['all_pass'],'error':report.get('error'),'cases':report.get('cases',{}).get('cases'),'assertions':report.get('cases',{}).get('assertions'),'result':str(O/'RESULT.json')}))
 return 0 if report['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
