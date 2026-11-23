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
import org.trillionnium.hepta.background.WindowOwnership;

/** Complete actual Session/Adapter private model proof -> actual HA pixel
 * worker/finally/main publisher -> actual LTC raw waiter -> private fresh Permit.
 * Android graphs/pixels, native process return and clock/lifecycle are explicit
 * host inputs. No private authority constructor is invoked or modified. */
public final class NativeCalendarDateFreshHostTest {
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
        final BackgroundSession background;final NativeAppSession session;final TaskAuthorization.Gate gate;
        final NativeAppGoal goal;final HeptaAccessibilityService service;final LocalTaskController controller;
        final NativeCalendarDateModelHostTest.ManualExecutor executor=new NativeCalendarDateModelHostTest.ManualExecutor();
        final LocalModelEngine engine;final VlmInferenceAdapter adapter;final NativeAppSession.CalendarOffer offer;
        final LocalInference.CurrentFrame source;DecisionGrammar grammar;final PhoneObservation sourcePhone;
        final List<String> journals=new ArrayList<String>();
        final NativeCalendarDateProtocol.Clock clock=()->SystemClock.elapsedRealtime();
        final String windowToken="33333333-3333-4333-8333-333333333333";
        boolean sourceRetired,failPermitJournal,ageOnPermitJournal,deadlineOnPermitJournal,expectReceiptTamper;
        byte[] raw;Object round;Delivery delivery;NativeAppSession.CalendarModelRequest model;
        int installedChecks;
        Env()throws Exception{
            LocalModelEngine.fixtureReset();OwnedGenerationScope.reset();LocalSocket.reset();android.system.Os.failFsyncPath=null;
            SystemClock.now=START;
            files=Files.createTempDirectory(work,"files-").toRealPath();context=new Context(files.toFile());
            Path tasks=Files.createDirectory(files.resolve("control-tasks"));directory=Files.createDirectory(tasks.resolve(TASK));
            image=directory.resolve("calendar-source.png");NativeCalendarDateSessionHostTest.privateWrite(image,png);
            BackgroundSession.Selection selected=NativeProfileIdentityHostTest.selection(OWNER,profile);
            background=new BackgroundSession(context,TASK,OWNER,selected,new QualificationScopeConfig.FilesRoot(context));
            context.displays.displays.put(7,new Display(7,background.displayName));
            JSONObject request=(JSONObject)ProfileClientPort.invoke(background,"request",new Class<?>[]{String.class,String.class,long.class},"state",null,SystemClock.now+3000);
            JSONObject response=reply(ProfileClientPort.frame(bytes(request.toString())));
            ProfileClientPort.invoke(background,"accept",new Class<?>[]{JSONObject.class,boolean.class},response,true);
            LocalSocket.responder=wire->{
                JSONObject q=ProfileClientPort.decode(wire),r=reply(wire);
                if("window".equals(q.getString("op"))){
                    WindowOwnership w=new WindowOwnership(profile,background.generation,background.displayId(),q.getInt("window_id"),q.getInt("task_id"),
                        1200,windowToken,UUID.randomUUID().toString(),profile.profile.userId,profile.profile.serial,profile.fullUid,SystemClock.now,SystemClock.now+1000);
                    r.put("window_ownership_wire",w.wire());
                }
                return ProfileClientPort.frame(bytes(r.toString()));
            };
            TaskAuthorization auth=TaskAuthorization.parse(OWNER).forExecutionSelection(background.selection);gate=auth.bind(TASK);goal=background.selection.taskTarget.nativeGoal;
            session=new NativeAppSession(TASK,gate,background.selection,new NativeAppEvidence.Installed(profile),NativeAppObservation.selectionSha(background.selection),
                background.generation,background.displayId(),()->{installedChecks++;},
                (leaf,value)->{
                    journals.add(leaf);if(failPermitJournal&&"native-calendar-permit-attempt.json".equals(leaf))throw new IOException("explicit durable journal failure");
                    try{NativeCalendarDateSessionHostTest.privateWrite(directory.resolve(leaf),bytes(new JSONObject(value).toString()));}
                    catch(IOException e){throw e;}catch(Exception e){throw new IOException(e);}
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
            offer=session.offerCalendarDate(envelope,adapter,clock,START+30000);grammar=offer.grammar();
            raw=bytes("\n"+NativeCalendarDateSessionHostTest.raw(envelope)+" \n");
            adapter.beginTask(TASK);
            service.graphProvider=()->new HeptaAccessibilityService.Graph(service,phone(NativeCalendarDateSessionHostTest.calendarNodes(),SystemClock.now,"calendar",image),SystemClock.now,SystemClock.now);
            service.screenshotProvider=()->bitmap();
        }
        long serviceClockCapture(){return service.current.capturedElapsedMillis;}
        JSONObject reply(byte[] wire)throws Exception{return ProfileClientPort.decode(ProfileClientPort.response(wire,"ACTIVE",7,true,false))
            .put("version",2).put("profile_target_wire",profile.wire()).put("profile_current_identity_verified",true).put("expires_elapsed_ms",background.expiresElapsed);}
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
            check(delivery.proof!=null&&delivery.signal.ready==1&&delivery.signal.failed==0,"actual Adapter private producer must reach actual registry");
            SystemClock.now=START+5200;model=offer.registerModelReply();return model;
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
            finally{executor.shutdownNow();engine.close();LocalModelEngine.fixtureReset();OwnedGenerationScope.reset();android.system.Os.failFsyncPath=null;LocalSocket.reset();}}
    }
    static void noEffect(NativeAppSession.CalendarPermit p)throws Exception{
        Map<String,Object> proof=p.evidence();check(Boolean.FALSE.equals(proof.get("grants_android_dispatch"))||Boolean.FALSE.equals(proof.get("android_dispatch_authority"))||Boolean.FALSE.equals(proof.get("grants_dispatch")),"fresh permit must not itself confer effect");
    }
    static void append(Path p)throws Exception{Files.write(p,new byte[]{32},StandardOpenOption.APPEND);}
    static void setup(String[] args)throws Exception{
        out=Paths.get(args[0]);work=Paths.get(args[1]);Files.createDirectory(work);
        NativeCalendarDateModelHostTest.out=out;NativeCalendarDateModelHostTest.root=work;NativeCalendarDateModelHostTest.template=Files.readAllBytes(Paths.get(args[2]));
        check(MobiMindContract.sha(NativeCalendarDateModelHostTest.template).equals(VlmResultContract.GUI_OWL_4B.templateSha256),"actual pinned template");
        java.awt.image.BufferedImage image=new java.awt.image.BufferedImage(1224,2992,java.awt.image.BufferedImage.TYPE_INT_RGB);
        for(int y=0;y<image.getHeight();y++)for(int x=0;x<image.getWidth();x++){int c=(x*31+y*17)&255;image.setRGB(x,y,(c<<16)|(((c+41)&255)<<8)|((c+79)&255));}
        ByteArrayOutputStream encoded=new ByteArrayOutputStream();check(javax.imageio.ImageIO.write(image,"png",encoded),"host PNG encoder");png=encoded.toByteArray();
        NativeCalendarDateSessionHostTest.work=work;NativeCalendarDateSessionHostTest.png=png;
    }
    public static void main(String[] args)throws Exception{
        setup(args);
        one("actual_pixel_finally_main_publication_raw_waiter_and_private_permit",()->{try(Env e=new Env()){
            NativeAppEvidence.Frame original=e.session.domain().frame;e.register();e.service.inlinePublication=true;
            final boolean[] accounting={false};
            e.service.beforePublishHook=()->{int[] c=e.service.hostReadCounters();check(c[0]==1&&c[1]==1&&!e.service.observationIoBusy.get(),"actual finally completes counters and resources before main post");accounting[0]=true;};
            NativeAppSession.CalendarPermit permit=e.await(true);
            check(accounting[0]&&e.service.callbackInsideWorker,"callback can run in Runnable tail; executor return is not claimed");
            check(e.service.hostOriginalWaiterAbandoned()&&!e.controller.cancelled.get(),"successful raw finally sets abandoned without cancelling task");
            check(e.service.graphReads==2&&e.service.captureCalls==1&&e.service.closedGraphs>=3,"two actual full postcapture reads and resource cleanup");
            check(e.session.domain().frame==original,"fresh raw publication must not replace native original domain");
            check(e.service.current!=e.sourcePhone&&e.service.current.screenshot.isFile()&&!e.service.current.screenshot.equals(e.image.toFile()),"fresh actual PNG path and Phone");
            check(Arrays.equals(Files.readAllBytes(e.image),Files.readAllBytes(e.service.current.screenshot.toPath())),"fresh pixels equal original but stored independently");
            e.source.requireCurrent();permit.requireForAction(e.session,e.background);noEffect(permit);
            check(permit.deadlineElapsed==START+13000,"callback plus eight seconds was not renewed");
            for(Constructor<?> c:HeptaAccessibilityService.CalendarFreshObservation.class.getDeclaredConstructors())if(!c.isSynthetic())check(Modifier.isPrivate(c.getModifiers()),"private fresh proof constructor");
            for(Constructor<?> c:NativeAppSession.CalendarPermit.class.getDeclaredConstructors())if(!c.isSynthetic())check(Modifier.isPrivate(c.getModifiers()),"private Permit constructor");
            Files.write(out.resolve("POSITIVE-PERMIT.json"),bytes(new JSONObject(permit.evidence()).toString(2)));
        }});
        one("calendar_null_raw_path_keeps_existing_waiter_and_does_not_issue_private_permit",()->{try(Env e=new Env()){
            AtomicReference<PhoneObservation> result=new AtomicReference<PhoneObservation>();AtomicReference<Throwable> error=new AtomicReference<Throwable>();
            SystemClock.now=START+500;Thread t=new Thread(()->{try{result.set(e.controller.hostLegacyRaw(e.directory.toFile(),START+10000));}catch(Throwable f){error.set(f);}});t.start();
            e.service.hostRunAdmission();e.service.hostRunReadWorker();e.service.hostRunPublication();t.join(5000);
            check(!t.isAlive()&&error.get()==null&&result.get()==e.service.current,"legacy raw branch still returns actual pixel publication");
            check(e.service.hostOriginalWaiterAbandoned()&&!e.journals.contains("native-calendar-fresh-read-attempt.json"),"legacy route has no calendar admission");
        }});
        one("duplicate_actual_HA_submission_closes_read_and_never_queues_second_capture",()->{try(Env e=new Env()){
            e.register();NativeAppSession.CalendarFreshRead read=e.model.beginFreshObservation(e.background);AtomicInteger errors=new AtomicInteger();
            HeptaAccessibilityService.CalendarFreshCallback cb=new HeptaAccessibilityService.CalendarFreshCallback(){public void onFresh(HeptaAccessibilityService.CalendarFreshObservation p){throw new AssertionError("closed duplicate must not publish");}public void onError(String x){errors.incrementAndGet();}};
            e.service.observeNativeCalendarFresh(e.controller,read,e.directory.toFile(),()->false,read.deadlineElapsed,cb);
            reject(()->e.service.observeNativeCalendarFresh(e.controller,read,e.directory.toFile(),()->false,read.deadlineElapsed,cb));
            e.service.hostRunAdmission();check(errors.get()==1&&e.service.captureCalls==0&&e.offer.closed(),"duplicate poisons first pending read; only one request admitted");
            check(e.service.main.queue.size()==0,"duplicate producer did not queue another observation");
        }});
        one("second_fresh_read_attempt_keeps_one_use_journal_and_closes_offer",()->{try(Env e=new Env()){
            e.register();NativeAppSession.CalendarFreshRead read=e.model.beginFreshObservation(e.background);AtomicInteger errors=new AtomicInteger();
            e.service.observeNativeCalendarFresh(e.controller,read,e.directory.toFile(),()->false,read.deadlineElapsed,new HeptaAccessibilityService.CalendarFreshCallback(){
                public void onFresh(HeptaAccessibilityService.CalendarFreshObservation p){throw new AssertionError("duplicate model begin must retire queued producer");}
                public void onError(String why){errors.incrementAndGet();}});
            reject(()->e.model.beginFreshObservation(e.background));e.service.hostRunAdmission();
            check(e.offer.closed()&&read.producerRetired(e.service)&&errors.get()==1&&e.service.captureCalls==0,"original queued Observer sees retired Read through its actual owned cancel");
            check(Collections.frequency(e.journals,"native-calendar-fresh-read-attempt.json")==1,"no fresh retry quota renewal");
        }});
        one("pending_action_lane_refuses_fresh_before_capture",()->{try(Env e=new Env()){
            e.register();e.service.actionBusy=true;e.await(false);check(e.offer.closed()&&e.service.captureCalls==0,"existing action lane remains exclusive");
        }});
        one("wrong_service_identity_cannot_borrow_read_even_equal_lifecycle_values",()->{try(Env e=new Env()){
            e.register();NativeAppSession.CalendarFreshRead read=e.model.beginFreshObservation(e.background);
            HeptaAccessibilityService foreign=new HeptaAccessibilityService(e.context);HeptaAccessibilityService.live=e.service;
            HeptaAccessibilityService.CalendarFreshCallback cb=new HeptaAccessibilityService.CalendarFreshCallback(){public void onFresh(HeptaAccessibilityService.CalendarFreshObservation p){throw new AssertionError("foreign producer");}public void onError(String x){}};
            reject(()->foreign.observeNativeCalendarFresh(e.controller,read,e.directory.toFile(),()->false,read.deadlineElapsed,cb));
            check(e.offer.closed()&&e.service.captureCalls==0,"wrong actual service closes read");
        }});
        one("real_task_cancel_after_success_rejects_permit_while_abandoned_alone_did_not",()->{try(Env e=new Env()){
            e.register();NativeAppSession.CalendarPermit p=e.await(true);e.controller.cancelled.set(true);
            reject(()->p.requireForAction(e.session,e.background));check(e.service.captureCalls==1,"no input or recapture after cancellation");
        }});
        one("cancel_before_final_main_publication_never_issues_permit",()->{try(Env e=new Env()){
            e.register();e.service.beforePublishHook=()->e.controller.cancelled.set(true);e.await(false);
            check(e.offer.closed()&&!e.journals.contains("native-calendar-permit-attempt.json"),"cancelled publication cannot grant permit");
        }});
        one("PNG_change_after_real_hash_before_publication_is_rejected_by_fresh_readback",()->{try(Env e=new Env()){
            e.register();e.service.beforePublishHook=()->{try(java.util.stream.Stream<Path> s=Files.list(e.directory)){for(Path p:s.filter(p->p.toString().endsWith(".png")&&!p.equals(e.image)).toArray(Path[]::new))append(p);}catch(Exception x){throw new IllegalStateException(x);}};
            e.await(false);check(e.offer.closed(),"modified newly published PNG closes offer");
        }});
        one("source_frame_lifetime_retirement_is_not_waived_by_new_pixel_publication",()->{try(Env e=new Env()){
            e.register();e.service.beforePublishHook=()->e.sourceRetired=true;e.await(false);check(e.offer.closed(),"old CurrentFrame provenance remains required");
        }});
        one("successful_publication_replaced_by_another_Phone_cannot_continue",()->{try(Env e=new Env()){
            e.register();NativeAppSession.CalendarPermit p=e.await(true);e.service.current=e.sourcePhone;
            reject(()->p.requireForAction(e.session,e.background));check(e.service.captureCalls==1,"no new currentness was invented");
        }});
        one("duplicate_consumption_closes_same_read_without_second_journal",()->{try(Env e=new Env()){
            e.register();NativeAppSession.CalendarPermit p=e.await(true);NativeAppSession.CalendarFreshRead read=e.read();
            HeptaAccessibilityService.CalendarFreshObservation publication=(HeptaAccessibilityService.CalendarFreshObservation)field(p,"publication");
            reject(()->read.acceptFreshObservation(publication));check(e.offer.closed()&&Collections.frequency(e.journals,"native-calendar-permit-attempt.json")==1,"second acceptance cannot replay");
        }});
        one("durable_permit_journal_failure_consumes_slot_and_never_returns_permit",()->{try(Env e=new Env()){
            e.register();e.failPermitJournal=true;e.await(false);check(e.offer.closed(),"failed one-use journal closes offer");
            reject(()->e.model.beginFreshObservation(e.background));check(e.service.captureCalls==1,"journal failure never recaptures");
        }});
        one("fresh_age_expires_during_durable_IO_and_final_check_refuses",()->{try(Env e=new Env()){
            e.register();e.ageOnPermitJournal=true;e.await(false);
            check(e.offer.closed()&&SystemClock.now<((Number)e.model.evidence().get("original_action_deadline_elapsed_ms")).longValue(),"two-second new capture freshness is independent of original eight seconds");
        }});
        one("original_eight_second_deadline_expires_after_journal_and_is_not_renewed",()->{try(Env e=new Env()){
            e.register();e.deadlineOnPermitJournal=true;e.await(false);check(e.offer.closed()&&SystemClock.now==START+13000,"original callback deadline remains exact");
        }});
        one("changed_native_model_raw_after_fresh_publication_keeps_provenance_required",()->{try(Env e=new Env()){
            e.register();e.expectReceiptTamper=true;e.service.beforePublishHook=()->{try{append(new File((File)field(e.round,"directory"),"raw.txt").toPath());}catch(Exception x){throw new IllegalStateException(x);}};
            e.await(false);check(e.offer.closed(),"changed actual model raw invalidates registered provenance");
        }});
        boolean ok=true;for(Map<String,Object> r:cases)ok&=Boolean.TRUE.equals(r.get("passed"));
        Map<String,Object> report=new LinkedHashMap<String,Object>();report.put("all_pass",ok);report.put("cases",cases.size());report.put("assertions",total());
        report.put("case_results",cases);report.put("actual_complete_pixel_worker_finally_main_publication",true);report.put("actual_private_adapter_and_fresh_producers",true);
        report.put("worker_read_accounting_and_resources_complete_before_callback",true);report.put("executor_runnable_return_before_callback_proven",false);
        report.put("synthetic_android_graph_pixel_window_clock_native_return_and_lifecycle_ports",true);report.put("android_or_model_executions",0);report.put("input_attempts",0);
        Files.write(out.resolve("CASES.json"),bytes(new JSONObject(report).toString(2)));System.out.println(new JSONObject(report).toString());
        if(!ok)throw new AssertionError("calendar fresh host cases failed");
    }
}
