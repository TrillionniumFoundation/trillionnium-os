package org.trillionnium.hepta.local;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Rect;
import android.net.LocalSocket;
import android.os.SystemClock;
import android.view.Display;
import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.json.JSONObject;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.PublicOwnGroupPolicy;
import org.trillionnium.hepta.background.WindowOwnership;

/** Complete actual Session/Adapter private model proof -> actual HA pixel
 * worker/finally/main publisher -> actual LTC raw waiter -> private fresh Permit.
 * Android graphs/pixels, native process return and clock/lifecycle are explicit
 * host inputs. No private authority constructor is invoked or modified. */
public final class NativeCalendarDateActionHostTest {
    static final long START=NativeCalendarDateSessionHostTest.START;
    static final String TASK=NativeCalendarDateSessionHostTest.TASK,OWNER=NativeCalendarDateSessionHostTest.OWNER;
    static Path out,work;static byte[] png;static int checks;
    static final List<Map<String,Object>> cases=new ArrayList<Map<String,Object>>();
    interface Work{void run()throws Exception;}
    static int total(){return checks+NativeCalendarDateModelHostTest.checks+NativeCalendarDateSessionHostTest.assertions;}
    static void check(boolean v,String why){checks++;if(!v)throw new AssertionError(why);}
    static void reject(Work w)throws Exception{boolean rejected=false;try{w.run();}catch(IllegalArgumentException|IllegalStateException|IOException expected){rejected=true;}check(rejected,"expected fail-closed refusal");}
    static void one(String name,Work w){Map<String,Object> r=new LinkedHashMap<String,Object>();r.put("name",name);int before=total();
        try{w.run();r.put("passed",true);}catch(Throwable e){r.put("passed",false);r.put("error",e.toString());StringWriter s=new StringWriter();e.printStackTrace(new PrintWriter(s));r.put("stack",s.toString());}
        r.put("assertions",total()-before);cases.add(r);}
    static String id(){return UUID.randomUUID().toString().replace("-","");}
    static String hash(String s){return NativeAppEvidence.hash(s);}
    static Object field(Object o,String n)throws Exception{return NativeCalendarDateModelHostTest.field(o,n);}
    static void port(Object o,String n,Object v)throws Exception{NativeCalendarDateModelHostTest.field(o,n,v);}
    static Object call(Object o,String n,Object...a)throws Exception{return NativeCalendarDateModelHostTest.call(o,n,a);}
    static byte[] bytes(String s){return s.getBytes(StandardCharsets.UTF_8);}
    static final class Signal implements NativeAppSession.CalendarModelSignal {int ready,failed;public void onModelReady(){ready++;}public void onModelFailure(String detail,boolean cleanup){failed++;}}
    static final class Delivery implements VlmInferenceAdapter.AcceptedRequestCallback {
        final VlmInferenceAdapter.AcceptedRequestCallback actual;VlmInferenceAdapter.AcceptedRequest proof;final Signal signal=new Signal();
        Delivery(NativeAppSession.CalendarOffer offer)throws Exception{actual=offer.modelCallback(signal);}
        public void onAcceptedRequest(VlmInferenceAdapter.AcceptedRequest p){proof=p;actual.onAcceptedRequest(p);}
        public void onSuccess(String raw,String run){actual.onSuccess(raw,run);}
        public void onFailure(String why,boolean known){actual.onFailure(why,known);}
    }
    static final class Env implements AutoCloseable {
        final Path files,directory,image;final Context context;
        final ProfileTarget profile=NativeProfileIdentityHostTest.ctrip();
        final BackgroundSession background;final PublicOwnGroupPolicy.Scope publicScope;final NativeAppSession session;final TaskAuthorization.Gate gate;
        final NativeAppGoal goal;final HeptaAccessibilityService service;final LocalTaskController controller;
        final NativeCalendarDateModelHostTest.ManualExecutor executor=new NativeCalendarDateModelHostTest.ManualExecutor();
        final LocalModelEngine engine;final VlmInferenceAdapter adapter;final NativeAppSession.CalendarOffer offer;
        final LocalInference.CurrentFrame source;DecisionGrammar grammar;final PhoneObservation sourcePhone;
        final List<String> journals=new ArrayList<String>();
        final NativeCalendarDateProtocol.Clock clock=()->SystemClock.elapsedRealtime();
        final String windowToken="33333333-3333-4333-8333-333333333333";
        boolean sourceRetired,failPermitJournal,ageOnPermitJournal,deadlineOnPermitJournal,expectReceiptTamper;
        boolean failInputJournal,failSelectionJournal,unknownReply,wrongReply,selectedWrongDate,malformedReply,expireOnSelectionJournal;
        int calendarWrites;WindowOwnership lastWindow;HeptaAccessibilityService.CalendarActionResult actionResult;
        byte[] raw;Object round;Delivery delivery;NativeAppSession.CalendarModelRequest model;
        int installedChecks;
        Env()throws Exception{this(true);}
        Env(boolean reserveOffer)throws Exception{
            LocalModelEngine.fixtureReset();OwnedGenerationScope.reset();LocalSocket.reset();android.util.Log.observer=null;android.system.Os.failFsyncPath=null;
            SystemClock.now=START;
            files=Files.createTempDirectory(work,"files-").toRealPath();context=new Context(files.toFile());
            Path tasks=Files.createDirectory(files.resolve("control-tasks"));directory=Files.createDirectory(tasks.resolve(TASK));
            image=directory.resolve("calendar-source.png");NativeCalendarDateSessionHostTest.privateWrite(image,png);
            BackgroundSession.Selection selected=NativeProfileIdentityHostTest.selection(OWNER,profile);
            background=BackgroundSession.experimentalPublicOwnGroup(context,TASK,OWNER,selected,new QualificationScopeConfig.FilesRoot(context));
            publicScope=PublicOwnGroupPolicy.Scope.fromWire(background.evidence().getString("public_own_group_scope_wire"));
            Display ownedDisplay=new Display(7,background.displayName);ownedDisplay.flags=7040;context.displays.displays.put(7,ownedDisplay);
            Display mainDisplay=new Display(0,"physical-main"),coverDisplay=new Display(1,"physical-cover");mainDisplay.flags=0;coverDisplay.flags=0;
            context.displays.displays.put(0,mainDisplay);context.displays.displays.put(1,coverDisplay);
            LocalSocket.responder=wire->{
                JSONObject q=ProfileClientPort.decode(wire),r=reply(wire);
                if("calendar_date".equals(q.getString("op"))){
                    calendarWrites++;
                    if(unknownReply)throw new IOException("explicit lost post-send response");
                    byte[] returned=CalendarDateReplyHost.reply(wire,background,profile,lastWindow);
                    if(malformedReply)return ProfileClientPort.frame(bytes("{malformed"));
                    if(wrongReply){JSONObject bad=ProfileClientPort.decode(returned);bad.put("request_id","wrong-request");return ProfileClientPort.frame(bytes(bad.toString()));}
                    return returned;
                }
                if("window".equals(q.getString("op"))){
                    WindowOwnership w=new WindowOwnership(profile,background.generation,background.displayId(),q.getInt("window_id"),q.getInt("task_id"),
                        1200,windowToken,UUID.randomUUID().toString(),profile.profile.userId,profile.profile.serial,profile.fullUid,SystemClock.now,SystemClock.now+1000);
                    lastWindow=w;r.put("window_ownership_wire",w.wire());
                }
                return ProfileClientPort.frame(bytes(r.toString()));
            };
            JSONObject response=(JSONObject)ProfileClientPort.invoke(background,"call",new Class<?>[]{String.class,String.class,int.class},"create",null,3000);
            ProfileClientPort.invoke(background,"accept",new Class<?>[]{JSONObject.class,boolean.class},response,true);background.requireActive();
            TaskAuthorization auth=TaskAuthorization.parse(OWNER).forExecutionSelection(background.selection);gate=auth.bind(TASK);goal=background.selection.taskTarget.nativeGoal;
            session=new NativeAppSession(TASK,gate,background.selection,new NativeAppEvidence.Installed(profile),NativeAppObservation.selectionSha(background.selection),
                background.generation,background.displayId(),()->{installedChecks++;},
                (leaf,value)->{
                    journals.add(leaf);if(failPermitJournal&&"native-calendar-permit-attempt.json".equals(leaf))throw new IOException("explicit durable journal failure");
                    if(failInputJournal&&"native-calendar-input-attempt.json".equals(leaf))throw new IOException("explicit input journal refusal");
                    if(failSelectionJournal&&"native-calendar-selection-evidence.json".equals(leaf))throw new IOException("explicit selection journal refusal");
                    try{NativeCalendarDateSessionHostTest.privateWrite(directory.resolve(leaf),bytes(new JSONObject(value).toString(2)));}
                    catch(IOException e){throw e;}catch(Exception e){throw new IOException(e);}
                    if(expireOnSelectionJournal&&"native-calendar-selection-evidence.json".equals(leaf))SystemClock.now=((Number)model.evidence().get("original_action_deadline_elapsed_ms")).longValue();
                    if("native-calendar-permit-attempt.json".equals(leaf)){
                        if(ageOnPermitJournal)SystemClock.now=serviceClockCapture()+2001;
                        if(deadlineOnPermitJournal)SystemClock.now=((Number)model.evidence().get("original_action_deadline_elapsed_ms")).longValue();
                    }
                });
            PhoneObservation form=phone(NativeCalendarDateSessionHostTest.formNodes(),START,"form",image);
            NativeAppEvidence.Frame before=copy(form);session.observed(before);
            String year=session.domain().clickIds.iterator().next();
            ActionDecision action=NativeCalendarDateSessionHostTest.action(before,"click",null,year);String run=id();
            session.beforeModelAction(1,action,run,START+50);
            // Prior YEAR navigation is an explicit host setup outcome, never Android input.
            session.modelActionOutcome(action,run,true,true,false,hash("host-prior-year-navigation"),START+100);
            SystemClock.now=START+200;sourcePhone=phone(NativeCalendarDateSessionHostTest.calendarNodes(),SystemClock.now,"calendar",image);
            NativeAppEvidence.Frame actual=copy(sourcePhone);session.observed(actual);
            service=new HeptaAccessibilityService(context);controller=new LocalTaskController(service,session,background);
            service.ownedController=controller;service.lease=TASK;service.taskAuthorization=gate;service.taskBackground=background;
            service.taskScope=new QualificationScopeConfig.Bound(context,TASK,null,new QualificationScopeConfig.FilesRoot(context));
            service.current=sourcePhone;service.currentGraph=new HeptaAccessibilityService.Graph(service,sourcePhone,START+200,START+200);
            service.currentBitmap=bitmap();
            source=new LocalInference.CurrentFrame(image.toFile(),TASK,goal.ownerSha256,sourcePhone.id,background.generation,profile.packageName,
                sourcePhone.screenshotSha256,1224,2992,background.displayId(),96,0,sourcePhone.capturedElapsedMillis,bytes(OWNER),()->{
                    if(sourceRetired)throw new IllegalStateException("host source lifetime retired");
                    if(grammar==null){service.requireTaskAuthorization(TASK,gate);service.requireBackgroundObservation(TASK,sourcePhone);}
                    else service.requireVisualFrameOwnership(controller,TASK,gate,background,sourcePhone,grammar);
                });
            engine=new LocalModelEngine(context,NativeCalendarDateSessionHostTest.gui(),executor);adapter=new VlmInferenceAdapter(context,engine);
            NativeCalendarDateEnvelope envelope=NativeCalendarDateEnvelope.capture(goal,actual,source,profile,adapter.configuration(),clock);
            offer=reserveOffer?session.offerCalendarDate(envelope,adapter,clock,START+30000):null;grammar=offer==null?null:offer.grammar();
            controller.inference=adapter;
            raw=bytes("\n"+NativeCalendarDateSessionHostTest.raw(envelope)+" \n");
            adapter.beginTask(TASK);
            service.graphProvider=()->new HeptaAccessibilityService.Graph(service,phone(NativeCalendarDateSessionHostTest.calendarNodes(),SystemClock.now,"calendar",image),SystemClock.now,SystemClock.now);
            service.screenshotProvider=()->bitmap();
        }
        long serviceClockCapture(){return service.current.capturedElapsedMillis;}
        JSONObject reply(byte[] wire)throws Exception{
            JSONObject request=ProfileClientPort.decode(wire);
            PublicOwnGroupPolicy.Privileges privileges=new PublicOwnGroupPolicy.Privileges(0,0,0,0);
            PublicOwnGroupPolicy.Credentials credentials=new PublicOwnGroupPolicy.Credentials(0,false,
                new PublicOwnGroupPolicy.UserState(0,0,false,false,false),new PublicOwnGroupPolicy.UserState(publicScope.targetUserId,0,false,false,false));
            PublicOwnGroupPolicy.DisplayState display=new PublicOwnGroupPolicy.DisplayState(7,background.displayName,"virtual:host-calendar",0,"com.android.shell",7040,2,0,0,1,1,2,2);
            Map<Integer,String> physical=new LinkedHashMap<Integer,String>();physical.put(0,hash("host-main"));physical.put(1,hash("host-cover"));
            Map<Integer,String> facts=new LinkedHashMap<Integer,String>();facts.put(0,"{\"state\":1,\"rotation\":0}");facts.put(1,"{\"state\":1,\"rotation\":0}");
            PublicOwnGroupPolicy.Readback actual=new PublicOwnGroupPolicy.Readback(publicScope,request.getString("request_id"),SystemClock.now,SystemClock.now,privileges,credentials,display,new PublicOwnGroupPolicy.PhysicalDisplays(physical,facts));
            return new JSONObject().put("version",request.getInt("version")).put("request_id",request.getString("request_id"))
                .put("generation",background.generation).put("operation",request.getString("op")).put("display_scope_sha256",publicScope.sha256)
                .put("public_scope_admission_retired",false).put("public_scope_closing",false).put("ok",true).put("state","ACTIVE")
                .put("display_id",7).put("display_name",background.displayName).put("flags",7040).put("expires_elapsed_ms",background.expiresElapsed)
                .put("dispatched",false).put("profile_target_wire",profile.wire()).put("profile_current_identity_verified",true)
                .put("public_own_group_readback_wire",actual.wire());
        }
        WindowOwnership window(long now)throws Exception{SystemClock.now=now;return background.verifyProfileWindow(96,1234,()->false,now+4000);}
        Bitmap bitmap(){BitmapFactory.Options options=new BitmapFactory.Options();options.inPreferredConfig=Bitmap.Config.ARGB_8888;Bitmap b=BitmapFactory.decodeByteArray(png,0,png.length,options);b.encoded=png.clone();return b;}
        PhoneObservation phone(List<NativeAppEvidence.Node> facts,long captured,String treeName,Path file)throws Exception{
            WindowOwnership owned=window(captured);List<PhoneObservation.Node> nodes=new ArrayList<PhoneObservation.Node>();
            for(NativeAppEvidence.Node n:facts)nodes.add(new PhoneObservation.Node(n.id,n.packageName,n.className,n.viewId,n.text,n.description,
                new Rect(n.left,n.top,n.right,n.bottom),n.clickable,n.editable,n.scrollable,n.enabled,false,n.password,
                ObservedChildText.notApplicable(),ObservedScrollActions.observed(n.scrollDirections),ObservedImeEnter.ABSENT,null,false,n.signature,n.path,n.parentClass,
                n.selected,n.checkable,n.checked));
            String tree=hash("synthetic-complete-"+treeName);
            PhoneObservation.CollectionStats stats=new PhoneObservation.CollectionStats(1536,512,6144,nodes.size(),nodes.size(),200,0,0,0,0L,80L);
            ObservedWindowMetadata metadata=ObservedWindowMetadata.observed(new int[]{0,0,1224,2992},"android.widget.FrameLayout",1,background.displayId(),
                new int[]{0,0,1224,2992},"explicit complete host calendar window");
            return new PhoneObservation(id(),profile.packageName,captured,1224,2992,0,96,new Rect(0,0,1224,2992),file.toFile(),MobiMindContract.sha(png),tree,
                new ObservationState(tree,ImeVisibility.HIDDEN),metadata,false,nodes,background.generation,profile.packageName,background.selection.allowedPackages,stats,
                background.selection.json(),goal.ownerSha256,null,owned);
        }
        NativeAppEvidence.Frame copy(PhoneObservation p)throws Exception{
            byte[] record=bytes(p.toEvidenceJson().toString(2));Path f=directory.resolve("setup-"+p.id+".json");NativeCalendarDateSessionHostTest.privateWrite(f,record);
            return NativeAppObservation.copy(TASK,gate,background,p,LocalTaskController.hostCompletion(p),MobiMindContract.sha(record));
        }
        NativeAppSession.CalendarModelRequest register()throws Exception{
            delivery=new Delivery(offer);
            adapter.generateObserved("固定日期协议","host native-return boundary; no actual model",source,grammar,256,120000,delivery);
            finishNativeReturn();
            check(delivery.proof!=null&&delivery.signal.ready==1&&delivery.signal.failed==0,"actual Adapter private producer must reach actual registry");
            SystemClock.now=START+5200;model=offer.registerModelReply();return model;
        }
        void finishNativeReturn()throws Exception{
            executor.take();round=field(field(adapter,"task"),"current");
            call(adapter,"prepareInputs",round);
            Object parent=call(Class.forName("org.trillionnium.hepta.local.VlmInferenceAdapter$Parent"),"read");port(round,"parent",parent);
            String generation=(String)field(round,"generation"),token=(String)field(round,"token");
            OwnedGenerationScope scope=new OwnedGenerationScope(files.toFile(),files.resolve("host-no-native-worker").toFile(),generation,TASK,token);port(round,"scope",scope);
            NativeCalendarDateModelHostTest.FakeProcess process=new NativeCalendarDateModelHostTest.FakeProcess(false,0);port(round,"process",process);
            OwnedWorkerCancellation cancel=(OwnedWorkerCancellation)field(round,"cancellation");cancel.attach(process,generation,TASK);
            Object owner=field(round,"owner");LocalModelEngine.TaskExternalLease lease=(LocalModelEngine.TaskExternalLease)field(owner,"lease");lease.attach(process,cancel);
            port(round,"exitObserved",true);port(round,"exitCode",0);
            NativeCalendarDateModelHostTest.environmentRaw.put(round,raw);NativeCalendarDateModelHostTest.nativeOutputs(round,scope);
            SystemClock.now=START+5000;call(adapter,"finishRequest",round,null);
        }
        void finishControllerNativeReturn()throws Exception{
            executor.take();round=field(field(adapter,"task"),"current");
            NativeAppSession.CalendarOffer actual=(NativeAppSession.CalendarOffer)field(session,"calendarDateOffer");
            raw=bytes("\n"+NativeCalendarDateSessionHostTest.raw(actual.source)+" \n");
            call(adapter,"prepareInputs",round);
            Object parent=call(Class.forName("org.trillionnium.hepta.local.VlmInferenceAdapter$Parent"),"read");port(round,"parent",parent);
            String generation=(String)field(round,"generation"),token=(String)field(round,"token");
            OwnedGenerationScope scope=new OwnedGenerationScope(files.toFile(),files.resolve("host-no-native-worker").toFile(),generation,TASK,token);port(round,"scope",scope);
            NativeCalendarDateModelHostTest.FakeProcess process=new NativeCalendarDateModelHostTest.FakeProcess(false,0);port(round,"process",process);
            OwnedWorkerCancellation cancel=(OwnedWorkerCancellation)field(round,"cancellation");cancel.attach(process,generation,TASK);
            Object owner=field(round,"owner");LocalModelEngine.TaskExternalLease lease=(LocalModelEngine.TaskExternalLease)field(owner,"lease");lease.attach(process,cancel);
            port(round,"exitObserved",true);port(round,"exitCode",0);
            NativeCalendarDateModelHostTest.environmentRaw.put(round,raw);NativeCalendarDateModelHostTest.nativeOutputs(round,scope);
            SystemClock.now=START+5000;call(adapter,"finishRequest",round,null);
        }
        HeptaAccessibilityService.CalendarActionResult act(NativeAppSession.CalendarPermit permit)throws Exception{
            AtomicReference<HeptaAccessibilityService.CalendarActionResult> value=new AtomicReference<HeptaAccessibilityService.CalendarActionResult>();
            AtomicReference<Throwable> error=new AtomicReference<Throwable>();
            Thread w=new Thread(()->{try{value.set(controller.hostAction(permit));}catch(Throwable e){error.set(e);}},"actual-calendar-action-waiter");
            w.start();service.hostRunAdmission();
            if(service.hostActionQueue()>0){service.hostRunActionWorker();service.hostRunPublication();}
            w.join(5000);check(!w.isAlive(),"actual action waiter finished");
            if(error.get()!=null)throw new AssertionError("actual action wait failed",error.get());
            actionResult=value.get();check(actionResult!=null,"actual action callback delivered");return actionResult;
        }
        HeptaAccessibilityService.CalendarActionResult directAction(NativeAppSession.CalendarPermit permit)throws Exception{
            AtomicReference<HeptaAccessibilityService.CalendarActionResult> value=new AtomicReference<HeptaAccessibilityService.CalendarActionResult>();
            service.performNativeCalendarDate(controller,permit,()->controller.cancelled.get(),value::set);
            service.hostRunAdmission();
            if(service.hostActionQueue()>0){service.hostRunActionWorker();service.hostRunPublication();}
            check(value.get()!=null,"actual direct callback delivered");actionResult=value.get();return actionResult;
        }
        PhoneObservation entireRound()throws Exception{
            AtomicReference<PhoneObservation> after=new AtomicReference<PhoneObservation>();AtomicReference<Throwable> error=new AtomicReference<Throwable>();
            Thread worker=new Thread(()->{try{after.set(controller.hostRound(directory.toFile(),OWNER,START+30000,sourcePhone));}catch(Throwable x){error.set(x);}},"actual-controller-GUI-calendar-round");
            worker.start();
            finishControllerNativeReturn();
            service.hostRunAdmission();service.hostRunReadWorker();service.hostRunPublication();
            service.hostRunAdmission();service.hostRunActionWorker();service.hostRunPublication();
            SystemClock.now+=20;
            service.graphProvider=()->new HeptaAccessibilityService.Graph(service,phone(form("11月25日周三"),SystemClock.now,"selected-form",image),SystemClock.now,SystemClock.now);
            service.hostRunAdmission();service.hostRunReadWorker();service.hostRunPublication();
            worker.join(5000);check(!worker.isAlive(),"actual GUI round exited");
            if(error.get()!=null)throw new AssertionError("actual GUI calendar helper failed",error.get());
            check(after.get()!=null,"actual GUI helper returned current FORM");return after.get();
        }
        NativeAppSession.CalendarSelectionEvidence select(NativeAppSession.CalendarPermit permit,HeptaAccessibilityService.CalendarActionResult result,boolean wrong)throws Exception{
            permit.claimSelectionRead(result);
            SystemClock.now+=20;
            service.graphProvider=()->new HeptaAccessibilityService.Graph(service,phone(form(wrong?"11月24日周二":"11月25日周三"),SystemClock.now,"selected-form",image),SystemClock.now,SystemClock.now);
            AtomicReference<PhoneObservation> after=new AtomicReference<PhoneObservation>();AtomicReference<Throwable> error=new AtomicReference<Throwable>();
            Thread w=new Thread(()->{try{after.set(controller.hostLegacyRaw(directory.toFile(),permit.deadlineElapsed));}catch(Throwable e){error.set(e);}},"actual-post-form-waiter");
            w.start();service.hostRunAdmission();service.hostRunReadWorker();service.hostRunPublication();w.join(5000);
            check(!w.isAlive()&&error.get()==null&&after.get()!=null,"actual post-effect pixel publication");
            HeptaAccessibilityService.CalendarSelectionObservation p=service.calendarSelectionObservation(controller,permit,result,after.get(),directory.toFile());
            return permit.acceptSelection(p);
        }
        NativeAppSession.CalendarFreshRead read()throws Exception{return (NativeAppSession.CalendarFreshRead)field(model,"freshRead");}
        NativeAppSession.CalendarPermit await(boolean success)throws Exception{
            AtomicReference<NativeAppSession.CalendarPermit> result=new AtomicReference<NativeAppSession.CalendarPermit>();
            AtomicReference<Throwable> error=new AtomicReference<Throwable>();
            Thread waiter=new Thread(()->{try{result.set(controller.hostAwait(model,directory.toFile()));}catch(Throwable e){error.set(e);}},"actual-controller-fresh-waiter");
            waiter.start();service.hostRunAdmission();
            if(service.observationIo.size()>0){service.hostRunReadWorker();if(!service.inlinePublication)service.hostRunPublication();}
            waiter.join(5000);
            check(!waiter.isAlive(),"actual raw waiter must finish");
            if(success){if(error.get()!=null)throw new AssertionError("fresh chain failed",error.get());check(result.get()!=null,"private Permit missing");}
            else check(error.get()!=null&&result.get()==null,"expected actual fresh refusal");
            return result.get();
        }
        void closeTask()throws Exception{
            if(field(adapter,"task")==null)return;
            AtomicReference<Throwable> error=new AtomicReference<Throwable>();AtomicReference<LocalInference.TaskCleanup> cleanup=new AtomicReference<LocalInference.TaskCleanup>();
            Thread t=new Thread(()->{try{cleanup.set(adapter.endTask(TASK));}catch(Throwable e){error.set(e);}},"actual-calendar-model-finish");t.start();executor.take().run();t.join(5000);
            check(!t.isAlive()&&error.get()==null&&cleanup.get()!=null,"actual host model finalizer must finish");
            LocalInference.TaskCleanup c=cleanup.get();
            Map<String,Object> terminal=new LinkedHashMap<String,Object>();terminal.put("cleanup_known",c.cleanupKnown);terminal.put("process_started",c.processStarted);terminal.put("process_exit_observed",c.processExitObserved);terminal.put("receipt_valid",c.receiptValid);terminal.put("exit_code",c.exitCode);terminal.put("no_request",round==null);terminal.put("deliberate_raw_corruption",expectReceiptTamper);
            Files.write(directory.resolve("host-model-terminal-classification.json"),bytes(new JSONObject(terminal).toString(2)));
            if(round==null)check(c.cleanupKnown&&!c.processStarted&&!c.processExitObserved&&!c.receiptValid,"zero-request actual Adapter task has no process or model receipt");
            else if(expectReceiptTamper)check(!c.receiptValid&&!c.cleanupKnown,"deliberately changed raw cannot be reclassified as valid normal cleanup");
            else check(c.cleanupKnown&&c.processExitObserved&&c.receiptValid,"normal actual host model finalization");
        }
        public void close(){try{closeTask();engine.fixtureAwaitCancel();}catch(Exception e){throw new AssertionError(e);}
            finally{executor.shutdownNow();engine.close();LocalModelEngine.fixtureReset();OwnedGenerationScope.reset();android.util.Log.observer=null;android.system.Os.failFsyncPath=null;LocalSocket.reset();}}
    }
    static List<NativeAppEvidence.Node> form(String date){
        List<NativeAppEvidence.Node> old=NativeCalendarDateSessionHostTest.formNodes(),result=new ArrayList<NativeAppEvidence.Node>();
        for(NativeAppEvidence.Node n:old){
            boolean target=n.text.equals("11月22日周日");
            result.add(new NativeAppEvidence.Node(n.id,n.packageName,n.className,n.viewId,target?date:n.text,n.description,n.path,n.parentClass,
                n.signature,target?date:n.label,n.left,n.top,n.right,n.bottom,n.enabled,n.password,n.clickable,n.editable,n.scrollable,n.selected,n.checkable,n.checked,n.scrollDirections));
        }return result;
    }
    static void append(Path p)throws Exception{Files.write(p,new byte[]{10},StandardOpenOption.APPEND);}
    static void privateTypes(){
        for(Class<?> c:new Class<?>[]{HeptaAccessibilityService.CalendarInputAttempt.class,HeptaAccessibilityService.CalendarActionResult.class,HeptaAccessibilityService.CalendarSelectionObservation.class,NativeAppSession.CalendarSelectionEvidence.class}){
            int ordinary=0;for(Constructor<?> k:c.getDeclaredConstructors())if(!k.isSynthetic()){ordinary++;check(Modifier.isPrivate(k.getModifiers()),"only real producer private ctor: "+c.getSimpleName());}
            check(ordinary==1,"one non-synthetic producer ctor: "+c.getSimpleName());
        }
    }
    static void queuedRefusal(String change)throws Exception{try(Env e=new Env()){
        e.register();NativeAppSession.CalendarPermit permit=e.await(true);
        final Object monitor=field(e.background,"publicScopeIo");
        CountDownLatch locked=new CountDownLatch(1),release=new CountDownLatch(1);
        AtomicReference<Throwable> error=new AtomicReference<Throwable>();AtomicInteger atQueue=new AtomicInteger(-1);
        Thread holder=new Thread(()->{synchronized(monitor){locked.countDown();try{release.await(5,TimeUnit.SECONDS);}catch(InterruptedException x){Thread.currentThread().interrupt();}}},"host-block-original-public-scope-monitor");
        android.util.Log.observer=raw->{try{JSONObject event=new JSONObject(raw);
            if("effect_entered".equals(event.optString("phase"))){holder.start();if(!locked.await(5,TimeUnit.SECONDS))throw new AssertionError("original scope monitor not held");}
        }catch(Exception x){throw new IllegalStateException(x);}};
        Thread steering=new Thread(()->{try{
            if(!locked.await(5,TimeUnit.SECONDS))throw new AssertionError("missing actual effect marker");
            long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
            while((e.service.hostActionThread==null||e.service.hostActionThread.getState()!=Thread.State.BLOCKED)&&System.nanoTime()<end)Thread.yield();
            if(e.service.hostActionThread==null||e.service.hostActionThread.getState()!=Thread.State.BLOCKED)throw new AssertionError("actual worker not queued on original scope lock");
            atQueue.set(LocalSocket.connections);
            if("cancel".equals(change))e.controller.cancelled.set(true);
            else if("deadline".equals(change))SystemClock.now=permit.deadlineElapsed;
            else if("retired".equals(change))call(e.background,"retirePublicScope");
            else throw new AssertionError(change);
        }catch(Throwable x){error.set(x);}finally{release.countDown();}},"host-retire-queued-date-call");
        steering.start();HeptaAccessibilityService.CalendarActionResult result;
        try{result=e.directAction(permit);}finally{release.countDown();steering.join(5000);holder.join(5000);android.util.Log.observer=null;}
        if(error.get()!=null)throw new AssertionError("queued scenario frontier failed",error.get());
        check(!steering.isAlive()&&!holder.isAlive(),"queue coordination completed");
        check(atQueue.get()>=0&&LocalSocket.connections==atQueue.get(),"queued "+change+" has zero further connects");
        check(!result.outcome.accepted&&e.calendarWrites==0,"queued "+change+" has no wire input");
        check(!e.service.hostSlotPending(),"queued refusal real worker drained original slot");
        JSONObject trace=e.background.evidence().getJSONObject("calendar_date_client_transport");
        check(!trace.getBoolean("socket_connected")&&!trace.getBoolean("request_write_attempted"),"trace records no connection/write after queue");
    }}
    /** Explicit full host census built from the actual newly published FORM values.
     * This executes the real QUERY comparator, not an Android query click. */
    static NativeActionSnapshotCheck.Snapshot querySnapshot(PhoneObservation published,
            NativeAppSession.ActionGuard guard,long captured){
        NativeActionSnapshotCheckHostTest.Fixture raw=NativeActionSnapshotCheckHostTest.form(NativeActionSnapshotCheck.QUERY);
        if(raw.nodes.size()!=published.nodes.size())throw new AssertionError("complete same host FORM census required");
        for(PhoneObservation.Node n:published.nodes){
            Map<String,Object> row=raw.nodes.get(n.nativeTreePath);
            if(row==null)throw new AssertionError("same complete FORM path required");
            row.put("package",n.packageName);row.put("window_id",published.windowId);row.put("class",n.className);
            row.put("view_id",n.viewId);row.put("text",n.text);row.put("description",n.description);
            row.put("parent_class",n.nativeParentClass);row.put("label",guard.frame.byId.get(n.id).label);
            row.put("ref_signature_sha256",n.observedAppTreeSignature);
            row.put("bounds",Arrays.asList(n.bounds.left,n.bounds.top,n.bounds.right,n.bounds.bottom));
            row.put("enabled",n.enabled);row.put("clickable",n.clickable);row.put("editable",n.editable);
            row.put("scrollable",n.scrollable);row.put("focused",n.focused);row.put("password",n.password);
            row.put("selected",n.selected);row.put("checkable",n.checkable);row.put("checked",n.checked);
            row.put("scroll_actions",n.scrollActions.fingerprintInput());row.put("ime_enter",n.imeEnter.fingerprintInput());
            row.put("input_sha256",n.inputTextSha256);row.put("action_click",n.clickable);
        }
        raw.link();raw.env.putAll(guard.identity);raw.env.put("package",published.packageName);
        raw.env.put("display_id",published.windowMetadata.displayId);raw.env.put("window_id",published.windowId);
        raw.env.put("rotation",published.rotation);raw.env.put("width",published.width);raw.env.put("height",published.height);
        raw.env.put("window_metadata_sha256",hash(published.windowMetadata.bindFreshness("")));
        raw.env.put("reported_windows_sha256",hash("explicit complete host FORM windows:"+published.windowId));
        raw.env.put("captured_elapsed_ms",captured);return raw.snapshot();
    }
    public static void main(String[] args)throws Exception{
        out=Paths.get(args[0]);work=Paths.get(args[1]);Files.createDirectories(work);
        Path image=work.resolve("host-source.png");
        java.awt.image.BufferedImage pixels=new java.awt.image.BufferedImage(1224,2992,java.awt.image.BufferedImage.TYPE_INT_RGB);
        for(int y=0;y<pixels.getHeight();y++)for(int x=0;x<pixels.getWidth();x++)pixels.setRGB(x,y,0x204060|((x%32)<<16)|((y%32)<<8));
        check(javax.imageio.ImageIO.write(pixels,"png",image.toFile()),"host PNG setup");
        png=Files.readAllBytes(image);check(png.length>0,"actual encoded host PNG");
        NativeCalendarDateModelHostTest.template=Files.readAllBytes(Paths.get(args[2]));
        one("private_actual_producer_types_have_no_general_constructor",()->privateTypes());
        one("actual_adapter_fresh_slot_BG_reply_new_FORM_date_evidence",()->{try(Env e=new Env()){
            e.register();NativeAppSession.CalendarPermit permit=e.await(true);
            HeptaAccessibilityService.CalendarActionResult result=e.act(permit);
            Files.write(e.directory.resolve("host-action-result.json"),bytes(new JSONObject(result.evidence()).toString(2)));
            check(result.outcome.accepted&&result.outcome.dispatched,"actual full BG reply accepted: "+result.outcome.detail);
            check(e.calendarWrites==1&&!e.service.hostSlotPending(),"one socket input and shared slot released");
            check(Boolean.TRUE.equals(result.evidence().get("platform_pair_confirmed"))&&!Boolean.TRUE.equals(result.evidence().get("date_selection_verified")),"platform pair is not date proof");
            NativeAppSession.CalendarSelectionEvidence selected=e.select(permit,result,false);
            check(selected!=null&&e.session.domain().phase.equals(NativeCtripFlightPage.FORM),"new FORM admitted after private date verification");
            Map<String,Object> evidence=selected.evidence();
            check(Boolean.TRUE.equals(evidence.get("date_selection_verified"))&&!Boolean.TRUE.equals(evidence.get("business_verified")),"date only, never business completion");
            check(Collections.frequency(e.journals,"native-calendar-input-attempt.json")==1&&Collections.frequency(e.journals,"native-calendar-selection-evidence.json")==1,"durable one-use and selection journals");
            check(e.calendarWrites==1,"post FORM does not input");
        }});
        one("changed_complete_graph_refuses_before_any_socket_input",()->{try(Env e=new Env()){
            e.register();NativeAppSession.CalendarPermit permit=e.await(true);
            e.service.graphProvider=()->new HeptaAccessibilityService.Graph(e.service,e.phone(NativeCalendarDateSessionHostTest.calendarNodes(),SystemClock.now,"changed-calendar",e.image),SystemClock.now,SystemClock.now);
            HeptaAccessibilityService.CalendarActionResult result=e.act(permit);
            check(!result.outcome.accepted&&!result.outcome.dispatched&&e.calendarWrites==0,"changed graph zero input");
            check(!e.service.hostSlotPending(),"refused worker drained original slot");
        }});
        one("durable_input_journal_failure_spends_quota_without_input",()->{try(Env e=new Env()){
            e.register();NativeAppSession.CalendarPermit permit=e.await(true);e.failInputJournal=true;
            HeptaAccessibilityService.CalendarActionResult result=e.act(permit);
            check(!result.outcome.accepted&&!result.outcome.dispatched&&e.calendarWrites==0,"journal error before effect");
            reject(()->e.service.performNativeCalendarDate(e.controller,permit,()->false,r->{}));
            check(e.calendarWrites==0,"failed journal cannot replay");
        }});
        one("actual_LTC_GUI_round_one_model_one_input_new_FORM_continuation",()->{try(Env e=new Env(false)){
            check(e.controller.hostCalendarBranch(e.sourcePhone),"actual branch selects existing GUI tools calendar");
            PhoneObservation after=e.entireRound();
            check(e.calendarWrites==1&&e.session.domain().frame.observationId.equals(after.id),"single effect then actual session consumes new FORM");
            check(!e.controller.hostCalendarBranch(after),"new FORM exits calendar branch");
            try(java.util.stream.Stream<Path> files=Files.list(e.directory)){
                check(files.filter(v->v.getFileName().toString().matches("step-02-model-[0-9]+\\.json")).count()==1,"one actual model request journal; no repair or fallback");
            }
            JSONObject action=new JSONObject(new String(Files.readAllBytes(e.directory.resolve("step-02-action.json")),StandardCharsets.UTF_8));
            check(action.getBoolean("accepted")&&action.getBoolean("dispatched")&&!action.getBoolean("done_success_eligible"),"controller retains pair acknowledgement separate from completion");
            check(Files.exists(e.directory.resolve("step-02-after.json"))&&!e.session.domain().resultReady,"new FORM recorded; no result or business success");
            e.session.requireModelPlanning();
            NativeAppDomain domain=e.session.domain();String query=null;
            for(Map.Entry<String,String> entry:domain.purposes.entrySet())if(NativeActionSnapshotCheck.QUERY.equals(entry.getValue()))query=entry.getKey();
            check(query!=null&&domain.clickIds.contains(query),"new actual FORM offers the real query control");
            Map<?,?> offered=(Map<?,?>)domain.promptEvidence().get("provider");
            check(e.goal.departureDate.toString().equals(offered.get("query_date"))
                    &&Boolean.FALSE.equals(offered.get("exploratory_non_target_query")),"query offered for the requested date");
            ActionDecision next=NativeCalendarDateSessionHostTest.action(domain.frame,"click",null,query);
            domain.requireCurrent(next);e.gate.frame().requireDecision(next);
            long issued=SystemClock.elapsedRealtime();String queryRun=id();
            e.session.beforeModelAction(3,next,queryRun,issued);
            NativeAppSession.ActionGuard guard=e.session.actionGuard(next,queryRun,after.id,issued,issued+8000);
            check(guard!=null&&NativeActionSnapshotCheck.QUERY.equals(guard.purpose)&&guard.frame==domain.frame,"actual journaled query Guard");
            Map<?,?> year=(Map<?,?>)guard.queryHistory.get("calendar_year_round_trip");
            check("hepta.native-calendar-selection-evidence.v1".equals(year.get("schema"))
                    &&e.goal.departureDate.toString().equals(year.get("requested_date"))
                    &&Boolean.TRUE.equals(year.get("date_selection_verified"))
                    &&Boolean.FALSE.equals(year.get("year_independently_observed_in_form")),"new schema keeps calendar year and FORM month/day sources distinct");
            String base=NativeActionSnapshotCheck.hash("synthetic-node-base:"+guard.targetNode.path);
            String full=ObservedImeEnter.UNKNOWN.bindFreshness(ObservedScrollActions.observed(Collections.<String>emptyList())
                    .bindFreshness(ObservedChildText.notApplicable().bind(base)),false,null);
            check(hash(full).equals(guard.targetNode.signature),"original host NodeRef preimage equals actual retained signature");
            NativeActionSnapshotCheck.Intent intent=guard.intent(full);
            NativeActionSnapshotCheck.Snapshot retained=querySnapshot(after,guard,after.capturedElapsedMillis);
            SystemClock.now=issued+1;
            NativeActionSnapshotCheck.Snapshot fresh=querySnapshot(after,guard,SystemClock.elapsedRealtime());
            Map<String,Object> compared=NativeActionSnapshotCheck.compare(intent,retained,fresh,SystemClock.elapsedRealtime());
            check(Boolean.FALSE.equals(compared.get("grants_dispatch"))
                    &&Boolean.FALSE.equals(compared.get("query_history_proved_by_comparator")),"complete QUERY compare accepts bound new history without granting input");
            guard.verifyInstalled();guard.requireOpen(next,queryRun,SystemClock.elapsedRealtime());
            guard.claim(next,queryRun,SystemClock.elapsedRealtime());guard.requireClaimed();
            reject(()->guard.claim(next,queryRun,SystemClock.elapsedRealtime()));
            check(guard.deadline-issued==8000&&e.calendarWrites==1&&!domain.resultReady
                    &&field(e.session,"lastQueryProof")==null,"once query claim does not fabricate a query effect, result or business completion");
            guard.close();
        }});
        one("post_publication_content_event_is_not_reused_for_input",()->{try(Env e=new Env()){
            e.register();NativeAppSession.CalendarPermit permit=e.await(true);e.service.hostEvent();
            HeptaAccessibilityService.CalendarActionResult result=e.directAction(permit);
            check(!result.outcome.accepted&&e.calendarWrites==0,"one real routed event refuses current pixels");
            check(!e.service.hostSlotPending()&&!e.service.hostHasCalendarTracker(),"no lingering input lane or tracker");
        }});
        one("duplicate_producer_closes_original_queued_request",()->{try(Env e=new Env()){
            e.register();NativeAppSession.CalendarPermit permit=e.await(true);
            AtomicReference<HeptaAccessibilityService.CalendarActionResult> value=new AtomicReference<HeptaAccessibilityService.CalendarActionResult>();
            e.service.performNativeCalendarDate(e.controller,permit,()->false,value::set);
            reject(()->e.service.performNativeCalendarDate(e.controller,permit,()->false,r->{}));
            e.service.hostRunAdmission();
            check(value.get()!=null&&!value.get().outcome.accepted&&e.calendarWrites==0,"duplicate closes first queued producer");
            check(e.service.hostActionQueue()==0&&!e.service.hostSlotPending()&&!e.service.hostHasCalendarTracker(),"no worker or capacity after duplicate");
        }});
        one("original_shared_slot_occupied_refuses_new_calendar_without_input",()->{try(Env e=new Env()){
            e.register();NativeAppSession.CalendarPermit permit=e.await(true);ActionExecutionState prior=e.service.hostOccupySlot();
            try{HeptaAccessibilityService.CalendarActionResult result=e.directAction(permit);
                check(!result.outcome.accepted&&e.calendarWrites==0&&e.service.hostSlotPending(),"original competing capacity retained");
            }finally{e.service.hostReleaseSlot(prior);}
            check(!e.service.hostSlotPending(),"only actual owner drain releases occupied slot");
        }});
        one("changed_fresh_PNG_is_rehashed_before_effect_and_not_replayed",()->{try(Env e=new Env()){
            e.register();NativeAppSession.CalendarPermit permit=e.await(true);append(permit.fresh().image.image.toPath());
            HeptaAccessibilityService.CalendarActionResult result=e.directAction(permit);
            check(!result.outcome.accepted&&!result.outcome.dispatched&&e.calendarWrites==0,"changed fresh source has zero input");
            reject(()->e.service.performNativeCalendarDate(e.controller,permit,()->false,r->{}));
        }});
        one("fresh_two_seconds_and_original_callback_eight_seconds_are_not_renewed",()->{
            try(Env e=new Env()){e.register();NativeAppSession.CalendarPermit permit=e.await(true);
                long original=permit.deadlineElapsed;SystemClock.now=permit.sealedElapsed+2001;
                HeptaAccessibilityService.CalendarActionResult result=e.directAction(permit);
                check(!result.outcome.accepted&&e.calendarWrites==0&&permit.deadlineElapsed==original,"fresh capture expiry preserves original deadline");
            }
            try(Env e=new Env()){e.register();NativeAppSession.CalendarPermit permit=e.await(true);
                long original=permit.deadlineElapsed;SystemClock.now=original;
                reject(()->e.service.performNativeCalendarDate(e.controller,permit,()->false,r->{}));
                check(e.calendarWrites==0&&permit.deadlineElapsed==START+13000,"original callback plus eight seconds remains exact");
            }
        });
        one("cancel_after_authenticated_connect_refuses_before_first_write",()->{try(Env e=new Env()){
            e.register();NativeAppSession.CalendarPermit permit=e.await(true);
            LocalSocket.afterPeer=()->{Map<String,Object> state=e.service.hostLastExecution();
                if(state!=null&&Boolean.TRUE.equals(state.get("effect_entered")))e.controller.cancelled.set(true);};
            HeptaAccessibilityService.CalendarActionResult result=e.directAction(permit);
            JSONObject trace=e.background.evidence().getJSONObject("calendar_date_client_transport");
            check(trace.getBoolean("socket_connected")&&trace.getBoolean("root_peer_verified"),"actual connected and root-peer frontier reached");
            check(!trace.getBoolean("request_write_attempted")&&e.calendarWrites==0&&!result.outcome.accepted,"same cancellation rejects immediately before bytes");
        }});
        one("queued_scope_cancel_retire_and_original_deadline_prevent_connect",()->{
            queuedRefusal("cancel");queuedRefusal("retired");queuedRefusal("deadline");
        });
        one("complete_malformed_payload_keeps_actual_bytes_SHA_and_no_valid_receipt",()->{try(Env e=new Env()){
            e.register();NativeAppSession.CalendarPermit permit=e.await(true);e.malformedReply=true;
            HeptaAccessibilityService.CalendarActionResult result=e.directAction(permit);
            JSONObject trace=e.background.evidence().getJSONObject("calendar_date_client_transport");
            check(trace.getBoolean("wire_payload_received")&&!trace.getBoolean("wire_response_validated"),"complete raw payload retained before JSON parse");
            check(trace.getInt("wire_payload_bytes")==bytes("{malformed").length&&MobiMindContract.sha(bytes("{malformed")).equals(trace.getString("wire_payload_sha256")),"exact malformed raw bytes/hash");
            check(trace.getLong("wire_payload_received_elapsed_ms")==SystemClock.now&&!result.outcome.accepted&&result.outcome.dispatched&&e.calendarWrites==1,"unknown possible input retained without success/replay");
            reject(()->permit.claimSelectionRead(result));check(e.calendarWrites==1,"no selection or second wire");
        }});
        one("lost_post_send_response_is_unknown_no_second_DOWN_or_selection",()->{try(Env e=new Env()){
            e.register();NativeAppSession.CalendarPermit permit=e.await(true);e.unknownReply=true;
            HeptaAccessibilityService.CalendarActionResult result=e.directAction(permit);
            check(!result.outcome.accepted&&result.outcome.dispatched&&e.calendarWrites==1,"wire uncertainty remains possible input");
            reject(()->permit.claimSelectionRead(result));
            reject(()->e.service.performNativeCalendarDate(e.controller,permit,()->false,r->{}));
            check(e.calendarWrites==1&&!e.service.hostSlotPending(),"no resend and actual worker drained");
        }});
        one("late_callback_wrong_actual_Gate_preserves_effect_but_refuses_authority",()->{try(Env e=new Env()){
            e.register();NativeAppSession.CalendarPermit permit=e.await(true);
            AtomicReference<HeptaAccessibilityService.CalendarActionResult> value=new AtomicReference<HeptaAccessibilityService.CalendarActionResult>();
            e.service.performNativeCalendarDate(e.controller,permit,()->false,value::set);
            e.service.hostRunAdmission();e.service.hostRunActionWorker();
            e.service.taskAuthorization=e.gate.authorization.bind(TASK);
            e.service.hostRunPublication();HeptaAccessibilityService.CalendarActionResult result=value.get();
            check(result!=null&&!result.outcome.accepted&&result.outcome.dispatched&&e.calendarWrites==1,"late currentness loss does not erase actual pair");
            reject(()->permit.claimSelectionRead(result));
        }});
        one("wrong_date_in_actual_new_FORM_fails_without_query_or_replay",()->{try(Env e=new Env()){
            e.register();NativeAppSession.CalendarPermit permit=e.await(true);HeptaAccessibilityService.CalendarActionResult result=e.act(permit);
            check(result.outcome.accepted,"platform pair precedes verification");
            reject(()->e.select(permit,result,true));
            check(e.calendarWrites==1&&!Files.exists(e.directory.resolve("native-calendar-selection-evidence.json")),"wrong date has no date-success evidence");
            reject(()->e.session.requireModelPlanning());
            reject(()->e.service.performNativeCalendarDate(e.controller,permit,()->false,r->{}));
        }});
        one("selection_journal_IO_failure_never_publishes_date_capability",()->{try(Env e=new Env()){
            e.register();NativeAppSession.CalendarPermit permit=e.await(true);HeptaAccessibilityService.CalendarActionResult result=e.act(permit);e.failSelectionJournal=true;
            reject(()->e.select(permit,result,false));
            check(field(e.session,"calendarSelection")==null&&e.calendarWrites==1,"no private selection on write failure");
            reject(()->e.session.requireModelPlanning());
        }});
        one("deadline_after_selection_file_write_does_not_authorize_continuation",()->{try(Env e=new Env()){
            e.register();NativeAppSession.CalendarPermit permit=e.await(true);HeptaAccessibilityService.CalendarActionResult result=e.act(permit);e.expireOnSelectionJournal=true;
            reject(()->e.select(permit,result,false));
            check(Files.exists(e.directory.resolve("native-calendar-selection-evidence.json"))&&field(e.session,"calendarSelection")==null,"written candidate file alone grants no private result");
            check(SystemClock.now==permit.deadlineElapsed&&e.calendarWrites==1,"original deadline not renewed by FORM/persistence");
            reject(()->e.session.requireModelPlanning());
        }});
        one("pre_permit_journal_failure_retires_registered_same_read_tracker",()->{try(Env e=new Env()){
            e.register();e.failPermitJournal=true;e.await(false);
            check(e.offer.closed()&&!e.service.hostHasCalendarTracker()&&e.calendarWrites==0,"post-publication pre-permit failure releases tracker without input");
            e.read().close();check(!e.service.hostHasCalendarTracker(),"repeated close is inert");
        }});
        one("closed_read_before_publication_cannot_register_late_tracker",()->{try(Env e=new Env()){
            e.register();e.service.beforePublishHook=()->{try{e.read().close();}catch(Exception x){throw new IllegalStateException(x);}};
            e.await(false);check(e.offer.closed()&&!e.service.hostHasCalendarTracker()&&e.calendarWrites==0,"closed read never installs a late tracking reference");
        }});
        boolean ok=true;for(Map<String,Object> r:cases)ok&=Boolean.TRUE.equals(r.get("passed"));
        Map<String,Object> report=new LinkedHashMap<String,Object>();report.put("all_pass",ok);report.put("cases",cases.size());report.put("assertions",total());
        report.put("case_results",cases);report.put("actual_private_adapter_fresh_action_selection_producers",true);
        report.put("actual_shared_action_slot_and_BG_socket_validation",true);report.put("synthetic_android_graph_pixel_window_clock_native_return_and_socket_reply",true);
        report.put("phone_actions",0);report.put("model_executions",0);report.put("actual_platform_input_qualified",false);
        Files.write(out.resolve("CASES.json"),bytes(new JSONObject(report).toString(2)));System.out.println(new JSONObject(report).toString());
        if(!ok)throw new AssertionError("calendar action host cases failed");
    }
}
