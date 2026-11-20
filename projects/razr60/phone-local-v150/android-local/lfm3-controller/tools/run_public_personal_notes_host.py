#!/usr/bin/env python3
"""Execute actual Notes cleanup/receipt code with explicit inert Android ports."""
import argparse,hashlib,importlib.util,json,pathlib,re,shutil,subprocess

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--source',type=pathlib.Path);ap.add_argument('--output',type=pathlib.Path,required=True);ap.add_argument('--java-home',type=pathlib.Path);ap.add_argument('--release8',action='store_true');args=ap.parse_args()
    source=(args.source or pathlib.Path(__file__).resolve().parent.parent).resolve();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    spec=importlib.util.spec_from_file_location('notes_fixture',source/'tests/background-session/prepare_fixture.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);files,record=module.prepare(source,out/'fixture')
    # Android App UID and matching private-file UID are explicit host ports.
    (out/'fixture/android/os/Process.java').write_text('package android.os;public final class Process {public static int myUid(){return 10123;}public static int myPid(){return 123;}}\n')
    os_file=out/'fixture/android/system/Os.java';os_source=os_file.read_text();assert os_source.count('r.st_uid=((Number)a.get("uid")).intValue();')==1
    os_file.write_text(os_source.replace('r.st_uid=((Number)a.get("uid")).intValue();','r.st_uid=10123;'))
    raw=(source/'src/org/trillionnium/hepta/background/BackgroundDisplayBroker.java').read_text()
    reader_source=source/'src/org/trillionnium/hepta/background/PublicPersonalNotesReader.java'
    reader_raw=reader_source.read_text()
    diagnostics_start='    /** Exact rejected framework row. Serialized fields confer no task authority. */'
    diagnostics_end='    private final Context context;'
    assert reader_raw.count(diagnostics_start)==1 and reader_raw.count(diagnostics_end)==1
    diagnostics_hunk=reader_raw[reader_raw.index(diagnostics_start):reader_raw.index(diagnostics_end)]
    diagnostics_fields=re.findall(r'(?m)^    private final PublicPersonalNotesReader\.FailureAudit publicNotesReadFailures=new PublicPersonalNotesReader\.FailureAudit\(\);$',raw)
    assert len(diagnostics_fields)==1
    diagnostics_field=diagnostics_fields[0]+'\n'
    cleanup_constants=re.findall(r'\bCLEANUP_MS\s*=\s*([0-9]+)\s*;',raw);assert len(cleanup_constants)==1
    cleanup_ms=int(cleanup_constants[0]);assert cleanup_ms==1500
    start='    private void beginPublicNotesCleanup(){';end='    private void beginProfileCleanup(){'
    assert raw.count(start)==1 and raw.count(end)==1;hunk=raw[raw.index(start):raw.index(end)]
    release_start='    private String releasedState() {';release_end='    private void haltAfterBootRead(int exit) {'
    assert raw.count(release_start)==1 and raw.count(release_end)==1
    release_hunk=raw[raw.index(release_start):raw.index(release_end)]
    screen_retire=re.findall(r'(?m)^    private void retirePublicScreenLease\(\)\{[^\n]+\}$',raw)
    assert len(screen_retire)==1
    bg=out/'fixture/org/trillionnium/hepta/background';bg.mkdir(parents=True,exist_ok=True)
    fixture=bg/'NotesCleanupAdapterFixture.java'
    fixture.write_text(('''package org.trillionnium.hepta.background;
import java.io.*;import java.util.*;import java.util.concurrent.*;
final class NotesCleanupAdapterFixture {
 static final long CLEANUP_MS=__ACTUAL_CLEANUP_MS__;final Object dispatchGate=new Object();final CountDownLatch cleanupDone=new CountDownLatch(1);
'''+diagnostics_field+''' volatile PublicPersonalNotesCustody publicNotesCustody;volatile PublicPersonalNotesReader publicNotesReader;
 volatile VirtualDisplay virtual,publicCreateReturnedHandle;volatile boolean createInFlight,effectInFlight,serve;
 volatile String state="CLOSING",terminalReason="",bootReadRetirementFailure;long cleanupAt;int displayId=7;String displayName="owned-session";
 final DisplayManager displays=new DisplayManager();ImageReader surfaceReader;HandlerThread displayThread;
 PublicOwnGroupScreenLease publicScreenLease;
 static final class SystemClock {static long elapsedRealtime(){return java.lang.System.nanoTime()/1000000L;}}
 static final class Display {final int id;final String name;Display(int i,String n){id=i;name=n;}String getName(){return name;}}
 static final class DisplayManager {volatile boolean present=true;Display getDisplay(int id){return id==7&&present?new Display(7,"owned-session"):null;}Display[] getDisplays(){return present?new Display[]{new Display(7,"owned-session")}:new Display[0];}}
 final class VirtualDisplay {int calls;boolean fail;void release()throws Exception{calls++;if(fail)throw new IOException("actual_release_failed");displays.present=false;}}
 static final class ImageReader {void close(){}}
 static final class HandlerThread {void quitSafely(){}}
 static final class LocalServerSocket {void close()throws IOException{}}
 LocalServerSocket server;
 NotesCleanupAdapterFixture()throws Exception{publicNotesCustody=PersonalNotesCustodyHostTest.created();publicNotesCustody.retireAdmission();
  virtual=new VirtualDisplay();publicCreateReturnedHandle=virtual;publicNotesReader=new PublicPersonalNotesReader();}
 void start(){cleanupAt=SystemClock.elapsedRealtime();beginPublicNotesCleanup();}
 void finished()throws Exception{if(!cleanupDone.await(3,TimeUnit.SECONDS))throw new AssertionError("cleanup did not finish");}
'''+release_hunk+hunk+screen_retire[0]+'\n}\n').replace('__ACTUAL_CLEANUP_MS__',str(cleanup_ms)));files.append(fixture)
    files.append(source/'src/org/trillionnium/hepta/background/PublicOwnGroupScreenLease.java')
    reader=bg/'PublicPersonalNotesReader.java'
    reader.write_text('''package org.trillionnium.hepta.background;
import java.util.*;import java.util.concurrent.*;import java.io.IOException;import org.json.JSONObject;
final class PublicPersonalNotesReader {
'''+diagnostics_hunk+'''
 final Object token=new Object();int uid=PersonalNotesCustodyHostTest.UID;String raw=PersonalNotesCustodyHostTest.raw();
 String[] recentsSequence;int recentsReads,liveReads,pendingLiveReads,frameReads;boolean changeLiveToken;
 CountDownLatch entered,proceed;
 PublicPersonalNotesCustody.Frame frame()throws Exception{
  if(entered!=null){entered.countDown();if(!proceed.await(2,TimeUnit.SECONDS))throw new IllegalStateException("fixture blocked");}
  long now=NotesCleanupAdapterFixture.SystemClock.elapsedRealtime();frameReads++;Object actualToken=changeLiveToken&&frameReads>1?new Object():token;
  return new PublicPersonalNotesCustody.Frame(PersonalNotesCustodyHostTest.global(300),Collections.singletonList(
   new PublicPersonalNotesCustody.Node(PersonalNotesCustodyHostTest.task(300,actualToken,uid,PersonalNotesCustodyHostTest.COMP),Collections.emptyList())),now,now);
 }
 ProfileTaskPolicy.Snapshot global()throws Exception{return PersonalNotesCustodyHostTest.global(liveReads++<pendingLiveReads?300:-1);}
 PublicOwnGroupPhysicalFence.RecentCensus recents(){String current=recentsSequence==null?raw:recentsSequence[Math.min(recentsReads,recentsSequence.length-1)];recentsReads++;return PublicOwnGroupPhysicalFence.inspectRecents(current);}
}
''');files.append(reader)
    test=bg/'NotesCleanupAdapterHostTest.java'
    test.write_text('''package org.trillionnium.hepta.background;
import java.util.*;import java.lang.reflect.*;import java.util.concurrent.*;import org.json.*;
public final class NotesCleanupAdapterHostTest {
 static int cases,checks;interface Work{void run()throws Exception;}
 static void yes(boolean value){checks++;if(!value)throw new AssertionError("Notes adapter boundary");}
 static void test(String name,Work work)throws Exception{work.run();cases++;System.out.println("PASS "+name);}
 static void refuse(Work work)throws Exception{try{work.run();}catch(Exception expected){checks++;return;}throw new AssertionError("invalid proof accepted");}
 static final String TASK="11111111111111111111111111111111";
 static PublicOwnGroupPolicy.Scope scope(){return new PublicOwnGroupPolicy.Scope(TASK,PersonalNotesCustodyHostTest.SHA,PersonalNotesCustodyHostTest.GEN,10123,null,0,600000,1);}
 static Object appCheck(JSONObject response,PublicOwnGroupPolicy.Scope scope,int display)throws Exception{
  Class<?> type=Class.forName("org.trillionnium.hepta.local.BackgroundSession");Method method=type.getDeclaredMethod("checkedPersonalNotesCleanup",JSONObject.class,PublicOwnGroupPolicy.Scope.class,String.class,int.class);
  method.setAccessible(true);return method.invoke(null,response,scope,PersonalNotesCustodyHostTest.GEN,display);
 }
 public static void main(String[] args)throws Exception{
  test("actual broker cleanup requires successful own release then two complete reads",()->{NotesCleanupAdapterFixture f=new NotesCleanupAdapterFixture();f.start();f.finished();yes(f.virtual.calls==1&&f.publicNotesCustody.known()&&"RELEASED".equals(f.state));yes(((Number)f.publicNotesCustody.evidence().get("absence_reads")).intValue()==2);});
  test("actual wrong UID stops before any release and retains custody",()->{NotesCleanupAdapterFixture f=new NotesCleanupAdapterFixture();f.publicNotesReader.uid++;f.start();f.finished();yes(f.virtual.calls==0&&f.publicNotesCustody.retain()&&!f.publicNotesCustody.known()&&"CLEANUP_UNKNOWN".equals(f.state));});
  test("replaced VD handle does not release either object",()->{NotesCleanupAdapterFixture f=new NotesCleanupAdapterFixture();NotesCleanupAdapterFixture.VirtualDisplay original=f.virtual;f.virtual=f.new VirtualDisplay();f.start();f.finished();yes(original.calls==0&&f.virtual.calls==0&&f.publicNotesCustody.retain());});
  test("release exception remains unknown with no retry",()->{NotesCleanupAdapterFixture f=new NotesCleanupAdapterFixture();f.virtual.fail=true;f.start();f.finished();yes(f.virtual.calls==1&&f.publicNotesCustody.retain()&&!f.publicNotesCustody.known());});
  test("unproven detached hidden task defeats post-release success",()->{NotesCleanupAdapterFixture f=new NotesCleanupAdapterFixture();f.publicNotesReader.recentsSequence=new String[]{f.publicNotesReader.raw,PersonalNotesCustodyHostTest.hidden(f.publicNotesReader.raw,"Task{ee #300 type=standard}")};f.start();f.finished();yes(f.virtual.calls==1&&!f.publicNotesCustody.known()&&f.publicNotesCustody.retain());});
  test("actual cleanup polls proven live and recents residue then two complete absences",()->{NotesCleanupAdapterFixture f=new NotesCleanupAdapterFixture();String owned=PersonalNotesCustodyHostTest.withOwned(),empty=f.publicNotesReader.raw;f.publicNotesReader.pendingLiveReads=1;f.publicNotesReader.recentsSequence=new String[]{owned,owned,empty,empty};f.start();f.finished();yes(f.virtual.calls==1&&f.publicNotesCustody.known());yes(f.publicNotesReader.recentsReads==4&&((Number)f.publicNotesCustody.evidence().get("pending_owned_reads")).intValue()==1);});
  test("actual cleanup waits on known detached hidden residue without task removal",()->{NotesCleanupAdapterFixture f=new NotesCleanupAdapterFixture();String owned=PersonalNotesCustodyHostTest.withOwned(),empty=f.publicNotesReader.raw,label=PublicOwnGroupPhysicalFence.inspectRecents(owned).records.get(300).label;f.publicNotesReader.recentsSequence=new String[]{owned,PersonalNotesCustodyHostTest.hidden(empty,label),empty,empty};f.start();f.finished();yes(f.virtual.calls==1&&f.publicNotesCustody.known()&&f.publicNotesReader.recentsReads==4);});
  for(final String change:new String[]{"uid","token","history"})test("actual pending "+change+" change is permanent UNKNOWN",()->{NotesCleanupAdapterFixture f=new NotesCleanupAdapterFixture();String owned=PersonalNotesCustodyHostTest.withOwned(),bad="uid".equals(change)?owned.replace("effectiveUid="+PersonalNotesCustodyHostTest.UID,"effectiveUid="+(PersonalNotesCustodyHostTest.UID+1)):"token".equals(change)?owned.replace("Task{cc #300","Task{cd #300"):owned.replace("Task{aa #100","Task{ab #100");f.publicNotesReader.recentsSequence=new String[]{owned,bad,f.publicNotesReader.raw,f.publicNotesReader.raw};f.start();f.finished();yes(f.virtual.calls==1&&!f.publicNotesCustody.known()&&f.publicNotesCustody.retain());yes(f.publicNotesReader.recentsReads==2);});
  test("actual live Binder token replacement does not become pending",()->{NotesCleanupAdapterFixture f=new NotesCleanupAdapterFixture();f.publicNotesReader.pendingLiveReads=1;f.publicNotesReader.changeLiveToken=true;f.publicNotesReader.recentsSequence=new String[]{PersonalNotesCustodyHostTest.withOwned()};f.start();f.finished();yes(f.virtual.calls==1&&!f.publicNotesCustody.known()&&f.publicNotesCustody.retain());});
  test("known owned residue stays bounded by existing cleanup deadline",()->{NotesCleanupAdapterFixture f=new NotesCleanupAdapterFixture();f.publicNotesReader.recentsSequence=new String[]{PersonalNotesCustodyHostTest.withOwned()};long begin=System.nanoTime();f.start();f.finished();long elapsed=(System.nanoTime()-begin)/1000000;yes(elapsed>=NotesCleanupAdapterFixture.CLEANUP_MS-200&&elapsed<NotesCleanupAdapterFixture.CLEANUP_MS+500&&f.virtual.calls==1&&!f.publicNotesCustody.known()&&f.publicNotesCustody.retain());});
  test("unknown watchdog during blocked ownership read prevents late release",()->{NotesCleanupAdapterFixture f=new NotesCleanupAdapterFixture();f.publicNotesReader.entered=new CountDownLatch(1);f.publicNotesReader.proceed=new CountDownLatch(1);f.start();yes(f.publicNotesReader.entered.await(1,TimeUnit.SECONDS));f.publicNotesCustody.unresolved("watchdog");f.publicNotesReader.proceed.countDown();f.finished();yes(f.virtual.calls==0&&f.publicNotesCustody.retain());});
  test("never-created state is distinct and performs no VD API",()->{NotesCleanupAdapterFixture f=new NotesCleanupAdapterFixture();f.publicNotesCustody=PersonalNotesCustodyHostTest.fresh();f.publicNotesCustody.retireAdmission();f.virtual=null;f.publicCreateReturnedHandle=null;f.start();f.finished();yes(f.publicNotesCustody.known()&&!f.publicNotesCustody.retain()&&"RELEASED".equals(f.state));});
  test("app accepts actual completed custody evidence but refuses each missing gate",()->{
   PublicOwnGroupPolicy.Scope s=scope();Object token=new Object();PublicPersonalNotesCustody c=new PublicPersonalNotesCustody(PersonalNotesCustodyHostTest.GEN,s.sha256,PersonalNotesCustodyHostTest.UID,PersonalNotesCustodyHostTest.global(-1),PersonalNotesCustodyHostTest.recents(PersonalNotesCustodyHostTest.raw()));
   c.beforeCreate();c.bindDisplay(7);c.markLaunch();PersonalNotesCustodyHostTest.prepare(c,token);c.enterRelease();c.releaseReturned();PersonalNotesCustodyHostTest.absence(c,PersonalNotesCustodyHostTest.raw(),200);PersonalNotesCustodyHostTest.absence(c,PersonalNotesCustodyHostTest.raw(),250);
   JSONObject proof=new JSONObject(c.evidence()),response=new JSONObject().put("ok",true).put("state","RELEASED").put("display_scope_sha256",s.sha256).put("personal_notes_cleanup",proof);
   yes(appCheck(response,s,7)!=null);
   // Keep the complete legacy v1 contract distinct from actual v2 producer evidence.
   Map<String,Object> legacyEvidence=new LinkedHashMap<String,Object>(c.evidence());legacyEvidence.put("schema","hepta.public-personal-notes-cleanup.v1");
   for(String key:new String[]{"history_preservation_scope","physical_history_frozen","history_preservation_interval","hidden_history_preservation_interval","unrelated_physical_history_changes_observed","recents_presentation_changes_observed","nonphysical_history_preserved","nonphysical_hidden_history_preserved"})legacyEvidence.remove(key);
   JSONObject legacy=new JSONObject(response.toString()).put("personal_notes_cleanup",new JSONObject(legacyEvidence));yes(appCheck(legacy,s,7)!=null);
   for(String key:new String[]{"cleanup_known","create_attempted","pre_release_tasks_verified","release_api_entered","release_api_returned","display_absence_verified","live_tasks_absent","all_recents_sections_absent","prior_hidden_history_preserved"}){
    JSONObject bad=new JSONObject(legacy.toString());JSONObject nested=bad.getJSONObject("personal_notes_cleanup");nested.put(key,false);bad.put("personal_notes_cleanup",nested);refuse(()->appCheck(bad,s,7));
   }
   for(String key:new String[]{"cleanup_known","create_attempted","pre_release_tasks_verified","release_api_entered","release_api_returned","display_absence_verified","live_tasks_absent","all_recents_sections_absent","nonphysical_history_preserved","nonphysical_hidden_history_preserved"}){
    JSONObject bad=new JSONObject(response.toString());JSONObject nested=bad.getJSONObject("personal_notes_cleanup");nested.put(key,false);bad.put("personal_notes_cleanup",nested);refuse(()->appCheck(bad,s,7));
   }
   for(JSONObject version:new JSONObject[]{legacy,response}){
    JSONObject lone=new JSONObject(version.toString());JSONObject nested=lone.getJSONObject("personal_notes_cleanup");nested.put("absence_reads",1);lone.put("personal_notes_cleanup",nested);refuse(()->appCheck(lone,s,7));
    refuse(()->appCheck(version,s,8));
   }
   JSONObject callerFlag=new JSONObject().put("ok",true).put("state","RELEASED").put("display_scope_sha256",s.sha256).put("owned_task_retirement_required",true);refuse(()->appCheck(callerFlag,s,7));
   // A real v2 custody transition may change only a resolved unrelated physical hidden row.
   String raw=PersonalNotesCustodyHostTest.raw(),hidden=PersonalNotesCustodyHostTest.hidden(raw,PersonalNotesCustodyHostTest.recents(raw).records.get(100).label);
   PublicPersonalNotesCustody concurrent=new PublicPersonalNotesCustody(PersonalNotesCustodyHostTest.GEN,s.sha256,PersonalNotesCustodyHostTest.UID,PersonalNotesCustodyHostTest.global(-1),PersonalNotesCustodyHostTest.recents(raw));
   concurrent.beforeCreate();concurrent.bindDisplay(7);concurrent.markLaunch();PersonalNotesCustodyHostTest.prepare(concurrent,new Object());concurrent.enterRelease();concurrent.releaseReturned();PersonalNotesCustodyHostTest.absence(concurrent,hidden,200);PersonalNotesCustodyHostTest.absence(concurrent,hidden,250);
   JSONObject changed=new JSONObject(concurrent.evidence());yes(!changed.getBoolean("prior_hidden_history_preserved")&&changed.getBoolean("unrelated_physical_history_changes_observed")&&changed.getBoolean("nonphysical_history_preserved")&&changed.getBoolean("nonphysical_hidden_history_preserved"));
   yes(appCheck(new JSONObject(response.toString()).put("personal_notes_cleanup",changed),s,7)!=null);
  });
  System.out.println("{\\"cases\\":"+cases+",\\"assertions\\":"+checks+",\\"passed\\":true,\\"phone_contacted\\":false,\\"actual_broker_cleanup_hunk\\":true,\\"full_app_session_receipt_check\\":true}");
 }
}
''');files.append(test)
    names=['BrokerProtocol','PublicPermissionControllerUi','FixedIntentTools','FixedIntentTarget','ProfileIdentity','ProfileTarget','BackgroundOwnedTaskPolicy','BackgroundOwnedSingleTask','ProfileTaskPolicy','PublicOwnGroupPolicy','PublicOwnGroupPhysicalFence','PublicPersonalNotesCustody']
    files += [source/'src/org/trillionnium/hepta/background'/(name+'.java') for name in names]
    files += [source/'tests/public-own-group-policy'/(name+'.java') for name in ['PublicPhysicalAuditHostTest','PersonalNotesCustodyHostTest','PersonalNotesSessionHostTest']]
    files=list(dict.fromkeys(pathlib.Path(p).resolve() for p in files));classes=out/'classes';classes.mkdir()
    if args.java_home:
        java=str(args.java_home.resolve()/'bin/java');compiler=[str(args.java_home.resolve()/'bin/javac')]
        if not pathlib.Path(java).is_file() or not pathlib.Path(compiler[0]).is_file():raise SystemExit('Java home must contain java and javac')
    else:java=shutil.which('java') or 'java';compiler=[shutil.which('javac')] if shutil.which('javac') else [java,'-m','jdk.compiler/com.sun.tools.javac.Main']
    flags=['--release','8','-Xlint:all'] if args.release8 else ['-source','8','-target','8','-Xlint:all,-options']
    stages=[('compile',compiler+flags+['-Werror','-d',str(classes),*map(str,files)]),('notes-cleanup',[java,'-cp',str(classes),'org.trillionnium.hepta.background.NotesCleanupAdapterHostTest']),('notes-session',[java,'-cp',str(classes),'org.trillionnium.hepta.local.PersonalNotesSessionHostTest'])]
    pins={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    provenance_paths=[source/'src/org/trillionnium/hepta/background/BackgroundDisplayBroker.java',reader_source,source/'src/org/trillionnium/hepta/local/BackgroundSession.java',pathlib.Path(__file__).resolve()]
    provenance={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in provenance_paths}
    report={'schema':'hepta.personal-notes.adapter-host.v1','phone_contacted':False,'status':'NOT_DEPLOYED','actual_cleanup_deadline_ms':cleanup_ms,'actual_broker_hunk_sha256':hashlib.sha256(hunk.encode()).hexdigest(),'actual_reader_diagnostics_hunk_sha256':hashlib.sha256(diagnostics_hunk.encode()).hexdigest(),'actual_broker_diagnostics_field_sha256':hashlib.sha256(diagnostics_field.encode()).hexdigest(),'source_sha256':pins,'extraction_provenance_sha256':provenance,'fake_ports':['VD release','DisplayManager','TaskInfo and Binder tokens','full recents input','root transport','Android App UID and corresponding private-file UID','owned Process wait/destroy'],'fixture_extraction':record,'stages':[]}
    for name,argv in stages:
        run=subprocess.run(argv,capture_output=True,text=True,timeout=40);(out/(name+'.stdout')).write_text(run.stdout);(out/(name+'.stderr')).write_text(run.stderr)
        report['stages'].append({'name':name,'exit_code':run.returncode});print(name,run.returncode,run.stdout[-2000:])
        if run.returncode:print(run.stderr[-7000:]);break
    report['source_unchanged']=all(hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()==h for p,h in list(pins.items())+list(provenance.items()))
    report['passed']=len(report['stages'])==len(stages) and all(r['exit_code']==0 for r in report['stages']) and report['source_unchanged']
    (out/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':report['passed'],'phone_contacted':False}));return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
