#!/usr/bin/env python3
"""Real production lifecycle members and slots; explicit host Android/receipt/IO ports."""
import argparse,hashlib,importlib.util,json,re,shutil,stat,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
def sha(b):return hashlib.sha256(b).hexdigest()
def ref(p):
 p=Path(p);b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=sha(b),mode=stat.S_IMODE(p.stat().st_mode))
def section(s,a,b):
 if s.count(a)!=1 or s.count(b)!=1:raise RuntimeError("nonunique extraction")
 return s[s.index(a):s.index(b,s.index(a))]
def member(s,a):
 if s.count(a)!=1:raise RuntimeError("nonunique member: "+a)
 start=s.index(a);depth=0;opened=False
 for t in re.finditer(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/|[{}]',s[start:]):
  if t.group()=="{":depth+=1;opened=True
  elif t.group()=="}":
   depth-=1
   if opened and depth==0:return s[start:start+t.end()]+"\n"
 raise RuntimeError("unclosed member")
def one(s,a,b):
 if s.count(a)!=1:raise RuntimeError("nonunique fixture port")
 return s.replace(a,b,1)
def line(s,prefix):
 rows=[x for x in s.splitlines() if x.startswith(prefix)]
 if len(rows)!=1:raise RuntimeError("nonunique declaration: "+prefix)
 return rows[0]+"\n"
def prepare(source,fixture):
 helper=source/"tests/recovery-application/prepare_engine_fixture.py"
 spec=importlib.util.spec_from_file_location("actual_engine_lifecycle_fixture",helper)
 m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 sources=m.prepare(source,fixture);(fixture/"EXTRACTION.json").rename(fixture/"LEGACY-EXTRACTION.json")
 sources=[p for p in sources if p.name not in {"RecoveryApplicationHostTest.java","LocalTaskSession.java","HeptaAccessibilityService.java"}]
 pkg=source/"src/org/trillionnium/hepta/local"
 texts={n:(pkg/(n+".java")).read_text() for n in ("LocalTaskSession","HeptaAccessibilityService","PublicProfileBusinessRecoveryClient","LocalModelEngine")}
 parts={}
 def take(name,kind,anchor,end=None):
  value=section(texts[kind],anchor,end) if end else member(texts[kind],anchor)
  parts[name]=dict(production_file=ref(pkg/(kind+".java")),bytes=len(value.encode()),sha256=sha(value.encode()),verbatim=True);return value
 engine=fixture/"LocalModelEngine.java"
 start=take("engine_start","LocalModelEngine","    public RunHandle start(","    private void claimProcess(")
 engine.write_text(engine.read_text()[:-2]+"""
 public static final class Request {}
 public interface Listener {void onFinished();}
 private void execute(RunHandle owner,Request request,Listener listener){throw new AssertionError("native IO outside lifecycle test");}
"""+start+"}\n")
 settings=fixture/"LocalModelSettings.java"
 settings.write_text(one(settings.read_text(),' boolean isBusy(){throw new AssertionError("settings UI is outside the legacy recovery fixture");}',' boolean isBusy(){return false;}'))
 session="""package org.trillionnium.hepta.local;
import android.content.Context;import android.os.Handler;import android.os.Looper;
import java.io.IOException;import java.util.concurrent.*;
public final class LocalTaskSession {
 static boolean initialBlocked=true;
 int retainedCalls,publishes;String state="",taskId=HostFacts.TASK,instructionSha=HostFacts.OWNER;
 private final Context context;private final LocalModelEngine engine;
"""
 for prefix in ("    private final Handler main","    private volatile LocalTaskController controller;","    private volatile boolean pending, blocked, recovering;","    private volatile boolean cachedLeaseUnreleased","    private volatile long generation;","    private final ExecutorService recoveryWorker"):
  value=line(texts["LocalTaskSession"],prefix);parts["session_decl_"+prefix]=dict(bytes=len(value.encode()),sha256=sha(value.encode()),verbatim=True);session+=value
 session+=take("actual_serial_journal_queue","LocalTaskSession","    private final SessionJournalQueue journalQueue=","    private RecoveryJournalTransaction.Proof acknowledgedSession;")
 session+="""
 LocalTaskSession(Context context,LocalModelEngine engine){this.context=context;this.engine=engine;blocked=initialBlocked;}
 void hostSeed(LocalTaskController c){controller=c;}
 void hostStart(){reconcileBusinessBackgroundFromOwnerButton();}
 ExecutorService hostExecutor(){return recoveryWorker;}
 SessionJournalQueue hostJournal(){return journalQueue;}
 void hostEpochChange(){generation++;}
 void hostOwnerChange(){instructionSha=HostFacts.OTHER;}
 String hostTask(){return taskId;}String hostOwner(){return instructionSha;}
 void readLeaseState(){cachedLeaseUnreleased=BackgroundSession.hostLeasePresent;}
 void setState(String s){state=s;publish();}void publish(){publishes++;}
 // Existing control callback filesystem endpoint is an explicit port.
 void recoveryLeaseRetained(){retainedCalls++;blocked=true;recovering=false;}
"""
 for name,anchor in [("isRunning","    public boolean isRunning()"),("isBlocked","    public boolean isBlocked()"),("hasLease","    public boolean hasBackgroundLease()"),("isRecovering","    public boolean isRecovering()"),("canAck","    public boolean canAcknowledgeInterruption()"),("owner_cleanup","    private void reconcileBusinessBackgroundFromOwnerButton()")]:
  session+=take(name,"LocalTaskSession",anchor)
 (fixture/"LocalTaskSession.java").write_text(session+"}\n");sources.append(fixture/"LocalTaskSession.java")
 service="""package org.trillionnium.hepta.local;
import java.util.concurrent.atomic.AtomicBoolean;import org.json.JSONObject;
final class HeptaAccessibilityService {
 private static volatile HeptaAccessibilityService live;
 LocalTaskController ownedController;String lease;
 Object activeObservation,activeNativeSearchObservation;boolean capturePending;
 final AtomicBoolean observationIoBusy=new AtomicBoolean();
 final HostPending actionSlot=new HostPending(),nativeCancellationQueue=new HostPending();
 BackgroundSession taskBackground;WebFlightSession taskWeb;
 static HeptaAccessibilityService connected(){return live;}
 static void hostConnect(HeptaAccessibilityService value){live=value;}
 boolean modelSettingsIdle(){throw new AssertionError("settings UI outside lifecycle fixture");}
 static String message(Throwable error){return error.getClass().getSimpleName()+": "+error.getMessage();}
"""
 service+=take("service_idle","HeptaAccessibilityService","    synchronized boolean publicProfileBusinessReconciliationIdle(")
 service+=take("service_accept_prefix","HeptaAccessibilityService","    synchronized void acceptBackgroundReconciliation(BackgroundSession.Cleanup cleanup)","        if(cleanup.personalNotesRecovery!=null){")
 service+=' throw new AssertionError("old recovery branches outside this host fixture");\n }\n'
 for name,anchor in [("accept_web","    synchronized void acceptWebReconciliation("),("observation_pending","    boolean observationReadWorkPending()"),("action_pending","    boolean actionWorkPending()"),("cancel_pending","    boolean nativeCancellationWorkPending()")]:
  service+=take(name,"HeptaAccessibilityService",anchor)
 (fixture/"HeptaAccessibilityService.java").write_text(service+"}\n");sources.append(fixture/"HeptaAccessibilityService.java")
 client="""package org.trillionnium.hepta.local;
import java.io.*;import java.util.concurrent.*;import java.util.concurrent.atomic.AtomicReference;
final class PublicProfileBusinessRecoveryClient {
 private static final AtomicReference<Flight> ACTIVE=new AtomicReference<Flight>();
 private static Process hostProcess;private static Thread hostReader;private static Flight hostFlight;
 // Test transport: owned host JVM waits for stdin. No su, ADB, phone or native model.
 static void hostStartOwnedChecker()throws Exception{
  Flight f=new Flight();if(!ACTIVE.compareAndSet(null,f))throw new IllegalStateException("already owned");
  String java=new File(System.getProperty("java.home"),"bin/java").getPath();
  Process p=new ProcessBuilder(java,"-cp",System.getProperty("java.class.path"),"org.trillionnium.hepta.local.BusinessLifecycleHostTest","--owned-child").start();
  f.process=p;Capture c=new Capture(p.getInputStream());f.capture=c;
  Thread r=new Thread(c,"host-owned-reader");f.reader=r;r.start();hostFlight=f;hostProcess=p;hostReader=r;
 }
 static void hostReleaseOwnedChecker()throws Exception{
  Process p=hostProcess;if(p==null)throw new IllegalStateException("no owned child");
  p.getOutputStream().write(1);p.getOutputStream().flush();p.getOutputStream().close();
  if(!p.waitFor(3,TimeUnit.SECONDS))throw new AssertionError("owned host checker did not exit");
  hostReader.join(3000);if(hostReader.isAlive())throw new AssertionError("owned reader not EOF");
  if(p.exitValue()!=0)throw new AssertionError("owned child failed");
  hostFlight.finishOrDrain();hostProcess=null;hostReader=null;hostFlight=null;
 }
 static void hostAssertDrained(){if(ACTIVE.get()!=null||hostProcess!=null)throw new AssertionError("owned host work remains");}
 // Explicit opaque data port; cannot construct a real production Receipt.
 static final class Receipt {
  final HostRequest request=new HostRequest();boolean persisted=true,originals=true;int persistedChecks,originalChecks;
  void requirePersisted()throws IOException{persistedChecks++;if(!persisted)throw new IOException("fixture receipt mismatch");}
  void requireOriginals(boolean present)throws IOException{originalChecks++;if(!originals||present)throw new IOException("fixture originals mismatch");}
  String receiptSha256(){return HostFacts.RECEIPT;}
 }
"""
 for name,anchor in [("client_pending","    static boolean workPending()"),("client_after_drain","    static void afterOwnedCheckerDrain("),("client_flight","    private static final class Flight {"),("client_capture","    private static final class Capture implements Runnable {")]:
  client+=take(name,"PublicProfileBusinessRecoveryClient",anchor)
 (fixture/"PublicProfileBusinessRecoveryClient.java").write_text(client+"}\n");sources.append(fixture/"PublicProfileBusinessRecoveryClient.java")

 ports=fixture/"HostPorts.java"
 ports.write_text("""package org.trillionnium.hepta.local;
import android.content.Context;import java.io.IOException;import org.json.JSONObject;
final class HostFacts {
 static final String TASK="0123456789abcdef0123456789abcdef",OWNER="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",OTHER="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",RECEIPT="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
 static final byte[] OLD_CONTROL="host-original-blocked-controller".getBytes(java.nio.charset.StandardCharsets.UTF_8);
 static final byte[] OLD_RESULT="host-original-failed-business-result".getBytes(java.nio.charset.StandardCharsets.UTF_8);
 static final byte[] OLD_LATCH="host-original-interruption-latch".getBytes(java.nio.charset.StandardCharsets.UTF_8);
}
final class HostRequest {String taskId=HostFacts.TASK,ownerSha256=HostFacts.OWNER;String source(){return "host-only-receipt-port";}}
final class HostPending {boolean busy;boolean pending(){return busy;}}
final class ProfilePermissionUiSession {static boolean busy;static boolean workPending(){return busy;}}
final class PublicProfileBusinessAbsenceRecovery {static final int MAX_OUTPUT=65536;}
final class LocalTaskController {boolean running;String task=HostFacts.TASK;boolean isRunning(){return running;}String currentTaskId(){return task;}}
final class BackgroundSession {
 interface ReconciliationCheck {void check()throws Exception;}
 interface BusinessReconciliationCheck extends ReconciliationCheck {void checkBusiness(String task,String owner)throws Exception;}
 interface HostWork {Cleanup run(BusinessReconciliationCheck check)throws Exception;}
 static volatile boolean hostLeasePresent=true;static volatile int calls;static volatile HostWork hostWork;
 static volatile Cleanup last;final String taskId=HostFacts.TASK;String ownerSha256=HostFacts.OWNER;boolean eligible=true;int accepts;
 boolean publicProfileRecoveryEligible(){return eligible;}
 void acceptReconciliation(Cleanup cleanup)throws Exception{if(!cleanup.known)throw new IOException("unknown fixture cleanup");accepts++;eligible=false;}
 static Cleanup reconcileBusiness(Context context,BusinessReconciliationCheck check)throws Exception{calls++;return hostWork.run(check);}
 static Cleanup hostKnown()throws Exception{
  hostLeasePresent=false;last=new Cleanup();last.known=true;last.businessRecovery=new PublicProfileBusinessRecoveryClient.Receipt();
  last.evidence=new JSONObject().put("reconciliation_source",last.businessRecovery.request.source()).put("business_receipt_sha256",HostFacts.RECEIPT);
  return last;
 }
 static final class Cleanup {boolean known;JSONObject evidence;Object prelaunchRecovery,postlaunchRecovery,publicProfileRecovery,personalNotesRecovery;PublicProfileBusinessRecoveryClient.Receipt businessRecovery;}
}
final class WebFlightSession {
 static boolean hostKnown=true;int accepts;boolean isReleased=true;
 static final class Cleanup {final boolean known;Cleanup(boolean k){known=k;}}
 static Cleanup reconcile(Context c){return new Cleanup(hostKnown);}
 boolean released(){return isReleased;}
 void acceptReconciliation(Cleanup proof)throws Exception{if(!proof.known)throw new IOException("web unknown");accepts++;}
}
""")
 # Separate explicit host ports into legal single-class compilation units.
 port_source=ports.read_text();header=port_source[:port_source.index("final class HostFacts {")]
 for name in ("HostFacts","HostRequest","HostPending","ProfilePermissionUiSession","PublicProfileBusinessAbsenceRecovery","LocalTaskController","BackgroundSession","WebFlightSession"):
  unit=fixture/(name+".java");unit.write_text(header+member(port_source,"final class "+name+" {"));sources.append(unit)
 ports.unlink()
 jsonfile=fixture/"JSONObject.java";jsonfile.write_text("""package org.json;
public final class JSONObject {
 private final java.util.Map<String,Object> values=new java.util.LinkedHashMap<String,Object>();
 public JSONObject put(String k,Object v){values.put(k,v);return this;}
 public String getString(String k){Object v=values.get(k);if(!(v instanceof String))throw new IllegalStateException("missing typed string");return (String)v;}
}
""");sources.append(jsonfile)
 sources.append(pkg/"SessionJournalQueue.java")
 sources.append(source/"tests/public-profile-business-lifecycle/BusinessLifecycleHostTest.java")
 extraction=dict(schema="hepta.business-lifecycle-extraction.v1",generator=ref(helper),parts=parts,
 original_extraction=ref(fixture/"LEGACY-EXTRACTION.json"),java_inputs=[ref(p) for p in sources],
 actual_application=True,exact_engine_slots_and_executor=True,exact_lts_owner_worker_main_method=True,
 exact_service_typed_idle_and_accept_branch=True,exact_client_flight_and_capture=True,actual_serial_journal_queue=True,
 ports=["Android Context/Looper/Handler","controller/task/web/opaque receipt data and filesystem CAS","service queue occupancy","settings/diagnostic/permission IO","acknowledgement filesystem callback"],
 owned_host_jvm_process_and_reader_exercised=True,phone_operations=0,android_or_native_recovery_authority=False)
 (fixture/"EXTRACTION.json").write_text(json.dumps(extraction,indent=2)+"\n")
 closure=set(sources+[helper,pkg/"LocalModelEngine.java",pkg/"LocalTaskSession.java",pkg/"HeptaAccessibilityService.java",pkg/"PublicProfileBusinessRecoveryClient.java",Path(__file__).resolve()])
 return sources,closure
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--source",type=Path,required=True);ap.add_argument("--output",type=Path,required=True)
 args=ap.parse_args();source=args.source.resolve();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
 fixture=out/"fixture";sources,closure=prepare(source,fixture)
 before={str(p):ref(p) for p in sorted(closure)};tools={n:ref(Path(shutil.which(n)).resolve()) for n in ("java","javac")};tools["python"]=ref(Path(sys.executable).resolve())
 classes=out/"classes";classes.mkdir()
 stages=[];commands=[("compile",[tools["javac"]["path"],"--release","8","-encoding","UTF-8","-Xlint:all","-Werror","-d",str(classes)]+[str(p) for p in sources]),
 ("lifecycle",[tools["java"]["path"],"-cp",str(classes),"org.trillionnium.hepta.local.BusinessLifecycleHostTest"])]
 for name,cmd in commands:
  start=time.monotonic()
  try:
   r=subprocess.run(cmd,cwd=source,capture_output=True,timeout=60)
   (out/(name+".stdout")).write_bytes(r.stdout);(out/(name+".stderr")).write_bytes(r.stderr)
   stages.append(dict(name=name,argv=cmd,exit_code=r.returncode,duration_seconds=time.monotonic()-start,stdout=ref(out/(name+".stdout")),stderr=ref(out/(name+".stderr"))))
   if r.returncode:print(r.stdout.decode(errors="replace")[-5000:]);print(r.stderr.decode(errors="replace")[-12000:]);break
  except (OSError,subprocess.TimeoutExpired) as e:
   stages.append(dict(name=name,argv=cmd,exit_code=None,error=str(e),duration_seconds=time.monotonic()-start));break
 text=(out/"lifecycle.stdout").read_text() if (out/"lifecycle.stdout").exists() else ""
 match=re.search(r"^PASS lifecycle_cases=(\d+) assertions=(\d+)$",text,re.M)
 names=re.findall(r"^PASS case=([a-z_]+) assertions=\d+$",text,re.M)
 after={str(p):ref(p) for p in sorted(closure)};aftertools={n:ref(Path(v["path"])) for n,v in tools.items()}
 cases,assertions=map(int,match.groups()) if match else (0,0)
 report=dict(schema="hepta.business-lifecycle-host.v1",all_pass=len(stages)==2 and all(x["exit_code"]==0 for x in stages) and cases==16 and len(names)==16 and before==after and tools==aftertools,
 source=str(source),cases=cases,assertions=assertions,case_names=names,stages=stages,extraction=ref(fixture/"EXTRACTION.json"),
 inputs_before=before,inputs_after=after,execution_closure_unchanged=before==after,tools_before=tools,tools_after=aftertools,tools_unchanged=tools==aftertools,
 phone_operations=0,actual_application_and_slots=True,actual_lts_method_and_service_branch=True,actual_journal_queue_and_serial_executor=True,owned_host_child_and_reader=True,
 actual_android_recovery_or_receipt=False,scope="Actual lifecycle around explicit Android/filesystem/receipt/controller ports; companion client/policy gates and phone verification remain required.")
 (out/"RESULT.json").write_text(json.dumps(report,indent=2)+"\n")
 print(json.dumps({k:report[k] for k in ("all_pass","cases","assertions","execution_closure_unchanged","tools_unchanged")}))
 return 0 if report["all_pass"] else 1
if __name__=="__main__":sys.exit(main())
