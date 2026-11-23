package org.trillionnium.hepta.local;

import android.content.Context;
import android.graphics.Rect;
import android.net.LocalSocket;
import android.os.SystemClock;
import android.view.Display;
import java.io.*;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;
import org.trillionnium.hepta.background.*;

/** Actual controller consumers and complete BG/Auth/Selection/Phone classes.
 * Android observation, kernel peer, clocks and broker replies are explicit host
 * ports. Their successful values are not ROM, model, input or business evidence. */
public final class ProbeDiagnosticHostTest {
    static final String TASK="11111111111111111111111111111111";
    static final String OTHER="22222222222222222222222222222222";
    static final String OWNER=ProbeDiagnosticHost.CALENDAR_WINDOW_PROBE_OWNER;
    static final HeptaAccessibilityService.Cancellation LIVE=()->false;
    interface Work {void run() throws Exception;}
    interface Change {void apply(JSONObject request,JSONObject response) throws Exception;}
    static final List<JSONObject> rows=new ArrayList<JSONObject>();
    static int assertions;
    static void yes(boolean value,String reason){assertions++;if(!value)throw new AssertionError(reason);}
    static Exception no(Work work,String message)throws Exception{
        try{work.run();}catch(Exception expected){assertions++;return expected;}
        throw new AssertionError("accepted "+message);
    }
    static void test(String name,Work work)throws Exception{
        LocalSocket.reset();SystemClock.now=1000000;android.os.Looper.worker=true;
        android.provider.Settings.Global.boot=10;android.system.Os.failChmod=false;
        android.system.Os.failUnlink=false;HeptaAccessibilityService.live=null;
        int before=assertions;JSONObject row=new JSONObject().put("name",name);
        try{work.run();row.put("passed",true);}catch(Throwable error){row.put("passed",false).put("error",error.toString());}
        row.put("assertions",assertions-before);rows.add(row);System.out.println(row.toString());
    }
    static String hash(char c){char[] value=new char[64];Arrays.fill(value,c);return new String(value);}
    static Object field(Object instance,String name)throws Exception{
        Field f=instance.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(instance);
    }
    static void set(Object instance,String name,Object value)throws Exception{
        Field f=instance.getClass().getDeclaredField(name);f.setAccessible(true);f.set(instance,value);
    }
    static Object invoke(Object instance,String name,Class<?>[] types,Object...args)throws Exception{
        Method m=instance.getClass().getDeclaredMethod(name,types);m.setAccessible(true);
        try{return m.invoke(instance,args);}catch(InvocationTargetException failure){
            Throwable cause=failure.getCause();if(cause instanceof Exception)throw (Exception)cause;
            if(cause instanceof Error)throw (Error)cause;throw new IllegalStateException(cause);
        }
    }
    static JSONObject decode(byte[] bytes)throws Exception{
        DataInputStream in=new DataInputStream(new ByteArrayInputStream(bytes));int n=in.readInt();
        if(n<1||n!=in.available())throw new IOException("bad host frame");byte[] raw=new byte[n];in.readFully(raw);
        return new JSONObject(new String(raw,StandardCharsets.UTF_8));
    }
    static byte[] frame(JSONObject value)throws Exception{
        byte[] raw=value.toString().getBytes(StandardCharsets.UTF_8);ByteArrayOutputStream out=new ByteArrayOutputStream();
        DataOutputStream data=new DataOutputStream(out);data.writeInt(raw.length);data.write(raw);data.flush();return out.toByteArray();
    }
    static ProfileTarget profile(String pkg)throws Exception{
        Map<String,String> apks=new LinkedHashMap<String,String>();apks.put("base",hash('a'));
        String activity=ProfileTarget.CTRIP.equals(pkg)?"ctrip.android.view.SplashActivity":"com.xiaomi.shop.activity.MainTabActivity";
        return new ProfileTarget(new ProfileIdentity(10,20,0,ProfileIdentity.MANAGED),1010367,pkg,pkg+"/"+activity,1779,apks,Collections.singleton(hash('b')));
    }
    static final class Env implements AutoCloseable {
        final Path root,evidence;final Context context;final ProfileTarget target;
        final BackgroundSession.Selection selection;final TaskAuthorization.Gate auth;
        final BackgroundSession session;final PublicOwnGroupPolicy.Scope publicScope;
        final QualificationScopeConfig.Bound scope;final HeptaAccessibilityService service;
        final ProbeDiagnosticHost controller;final List<String> operations=new ArrayList<String>();
        final long deadline;PhoneObservation observed;WindowOwnership receivedWindow;
        Change change;boolean replyRetired;String unique="virtual:host-only";
        Env()throws Exception{
            root=Files.createTempDirectory("hepta-probe-diagnostic-").toRealPath();evidence=Files.createDirectory(root.resolve("evidence"));
            context=new Context(root.toFile());context.keyguard.locked=true;target=profile(ProfileTarget.CTRIP);
            BackgroundTaskTarget task=BackgroundTaskTarget.resolveExplicitSelection(OWNER,target.packageName,Collections.singleton(target.packageName),target);
            selection=new BackgroundSession.Selection(task,true);
            auth=TaskAuthorization.parse(OWNER).forExecutionSelection(selection).bind(TASK);
            QualificationScopeConfig.FilesRoot captured=new QualificationScopeConfig.FilesRoot(context);
            scope=new QualificationScopeConfig.Bound(context,TASK,null,captured);
            session=BackgroundSession.experimentalPublicOwnGroup(context,TASK,OWNER,selection,captured);
            publicScope=(PublicOwnGroupPolicy.Scope)field(session,"publicOwnGroupScope");
            Display display=new Display(7,session.displayName);display.flags=7040;context.displays.displays.put(7,display);
            for(int id:new int[]{0,1}){Display physical=new Display(id,"physical-"+id);physical.flags=0;context.displays.displays.put(id,physical);}
            LocalSocket.responder=this::reply;
            JSONObject activated=(JSONObject)invoke(session,"call",new Class<?>[]{String.class,String.class,int.class},"create",null,3000);
            invoke(session,"accept",new Class<?>[]{JSONObject.class,boolean.class},activated,true);session.requireActive();
            deadline=SystemClock.now+30000;
            receivedWindow=session.verifyProfileWindow(17,1234,LIVE,deadline);
            observed=observation(receivedWindow,stats(0,0,0,0),false);
            service=new HeptaAccessibilityService();HeptaAccessibilityService.live=service;
            service.lease=TASK;service.taskAuthorization=auth;service.taskBackground=session;service.taskScope=scope;
            controller=new ProbeDiagnosticHost(service,TASK);controller.readPort=()->observed;
            operations.clear();LocalSocket.events.clear();LocalSocket.sent=new byte[0];
        }
        PhoneObservation observation(WindowOwnership proof,PhoneObservation.CollectionStats counters,boolean truncated)throws Exception{
            List<PhoneObservation.Node> nodes=Collections.singletonList(new PhoneObservation.Node("n0",target.packageName,
                "android.widget.FrameLayout","","host observed root","",new Rect(0,0,1200,2600),false,false,false,true,false,false,
                ObservedChildText.notApplicable(),ObservedScrollActions.UNKNOWN));
            ObservedWindowMetadata meta=ObservedWindowMetadata.observed(new int[]{0,0,1200,2600},"android.widget.FrameLayout",1,7,new int[]{0,0,1200,2600},"host-only");
            return new PhoneObservation("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",target.packageName,SystemClock.now,1200,2600,0,17,
                new Rect(0,0,1200,2600),null,null,hash('c'),new ObservationState(hash('d'),ImeVisibility.HIDDEN),meta,truncated,nodes,
                session.generation,selection.initialPackage,selection.allowedPackages,counters,selection.json(),auth.authorization.instructionSha256,null,proof);
        }
        byte[] reply(byte[] bytes)throws Exception{
            JSONObject q=decode(bytes);String op=q.getString("op");operations.add(op);
            JSONObject r=new JSONObject().put("version",q.getInt("version")).put("request_id",q.getString("request_id"))
                .put("generation",session.generation).put("operation",op).put("display_scope_sha256",publicScope.sha256)
                .put("public_scope_admission_retired",false).put("public_scope_closing",false).put("ok",true)
                .put("state","ACTIVE").put("display_id",7).put("display_name",session.displayName).put("flags",7040)
                .put("expires_elapsed_ms",session.expiresElapsed).put("dispatched",false)
                .put("profile_target_wire",target.wire()).put("profile_current_identity_verified",true);
            Map<Integer,String> physical=new LinkedHashMap<Integer,String>();physical.put(0,hash('a'));physical.put(1,hash('b'));
            Map<Integer,String> facts=new LinkedHashMap<Integer,String>();facts.put(0,"{\"state\":1}");facts.put(1,"{\"state\":1}");
            PublicOwnGroupPolicy.Readback readback=new PublicOwnGroupPolicy.Readback(publicScope,q.getString("request_id"),SystemClock.now,SystemClock.now,
                new PublicOwnGroupPolicy.Privileges(0,0,0,0),
                new PublicOwnGroupPolicy.Credentials(0,true,new PublicOwnGroupPolicy.UserState(0,0,false,false,false),new PublicOwnGroupPolicy.UserState(10,0,false,false,false)),
                new PublicOwnGroupPolicy.DisplayState(7,session.displayName,unique,0,"com.android.shell",7040,2,0,0,1,1,2,2),
                new PublicOwnGroupPolicy.PhysicalDisplays(physical,facts));
            r.put("public_own_group_readback_wire",readback.wire());
            if("window".equals(op)){
                WindowOwnership proof=new WindowOwnership(target,session.generation,7,q.getInt("window_id"),q.getInt("task_id"),1200,
                    "33333333-3333-4333-8333-333333333333",UUID.randomUUID().toString(),10,20,target.fullUid,
                    SystemClock.now,Math.min(SystemClock.now+1000,q.getLong("deadline_elapsed_ms")));
                r.put("window_ownership_wire",proof.wire());
            }
            if("calendar_probe".equals(op))r.put("calendar_window_probe",probe(q));
            if(change!=null)change.apply(q,r);
            if(replyRetired)set(session,"retired",true);
            return frame(r);
        }
        JSONObject probe(JSONObject q)throws Exception{
            JSONObject isolation=new JSONObject().put("schema","hepta.input-channel-isolation-readonly.v1")
                .put("display_id",7).put("full_uid",target.fullUid).put("target_profile_user_id",10)
                .put("accessibility_namespace_user_id",0).put("package",target.packageName)
                .put("accessibility_window_id",q.getInt("window_id")).put("observed_task_id",q.getInt("task_id"))
                .put("actual_window_token_match_count",1).put("cross_display_input_or_window_token_aliases",0)
                .put("grants_dispatch",false).put("input_attempts",0);
            JSONObject lifecycle=new JSONObject().put("schema","hepta.window-infos-listener-lifecycle.v1")
                .put("registration_returned",true).put("retired",true).put("unregister_returned",true)
                .put("local_callbacks_drained",true).put("retains_current_census",false).put("register_cache_grants_currentness",false)
                .put("callbacks_in_flight",0).put("callback_arrivals",1L).put("callback_finishes",1L)
                .put("grants_dispatch",false).put("input_attempts",0);
            return new JSONObject().put("schema","hepta.calendar-window-probe.v1").put("request_id",q.getString("request_id"))
                .put("generation",session.generation).put("target_sha256",target.sha256).put("display_scope_sha256",publicScope.sha256)
                .put("original_request_deadline_elapsed_ms",q.getLong("deadline_elapsed_ms"))
                .put("probe_deadline_elapsed_ms",q.getLong("deadline_elapsed_ms")).put("entered_elapsed_ms",SystemClock.now)
                .put("read_finished_elapsed_ms",SystemClock.now).put("qualified_elapsed_ms",SystemClock.now)
                .put("qualified",true).put("grants_dispatch",false).put("dispatched",false).put("calendar_date_effect_integrated",false)
                .put("input_attempts",0).put("phase","readonly_window_channel_isolation_verified").put("isolation",isolation)
                .put("listener_lifecycle",lifecycle);
        }
        PhoneObservation run()throws Exception{return controller.probe(TASK,OWNER,evidence.toFile(),auth,session,selection,scope,deadline);}
        JSONObject journal()throws Exception{return new JSONObject(new String(Files.readAllBytes(evidence.resolve("calendar-window-rom-diagnostic.json")),StandardCharsets.UTF_8));}
        int probes(){return Collections.frequency(operations,"calendar_probe");}
        void finite()throws Exception{controller.runFinite(TASK,OWNER,evidence.toFile(),auth,session,selection,scope,deadline);}
        public void close()throws IOException{
            android.system.Os.failChmod=false;LocalSocket.responder=null;
            try(java.util.stream.Stream<Path> walk=Files.walk(root)){for(Path row:walk.sorted(Comparator.reverseOrder()).toArray(Path[]::new))Files.deleteIfExists(row);}
        }
    }
    static PhoneObservation.CollectionStats stats(int pending,long child,int node,int text){
        return new PhoneObservation.CollectionStats(100,100,1000,1,1,0,pending,node,text,child,2);
    }
    static void failedJournal(Env e,String why)throws Exception{
        JSONObject j=e.journal();yes("failed".equals(j.getString("status")),why+" preserves failed diagnostic");
        yes(!j.getBoolean("readonly_qualification_verified")&&!j.getBoolean("business_verified")&&!j.getBoolean("grants_dispatch"),why+" grants nothing");
    }
    public static void main(String[] args)throws Exception{
        test("actual_owner_compiler_and_selection_are_open_wait_without_native_goal",()->{try(Env e=new Env()){
            yes(e.auth.authorization.allowedTools.equals(new TreeSet<String>(Arrays.asList("open","wait"))),"actual bounded owner parser");
            yes(e.selection.taskTarget.nativeGoal==null&&!e.selection.taskTarget.webHelper(),"no business/native goal");
            e.selection.requireTaskTarget(OWNER,e.auth.authorization);
            yes(e.auth.authorization.immutableOwner().equals(OWNER)&&e.selection.independentProfileDisplay,"literal and selection retained");
        }});
        test("finite_entry_returns_partial_before_model_and_uses_real_private_probe_receipt",()->{try(Env e=new Env()){
            e.finite();JSONObject j=e.journal();
            yes("partial".equals(e.controller.finalStatus)&&e.controller.modelBegins==0,"real early return before model sentinel");
            yes(e.controller.observation==e.observed&&e.controller.observationReads==1,"same one host observation callback");
            yes(e.probes()==1&&"readonly_qualification_verified".equals(j.getString("status")),"one actual BG probe exchange");
            yes(j.getJSONObject("probe_request").getString("op").equals("calendar_probe"),"actual request");
            yes(j.getJSONObject("probe_response").getJSONObject("calendar_window_probe").getBoolean("qualified"),"actual validated private receipt evidence");
            for(String k:new String[]{"model_requested","completion_verified","business_verified","grants_dispatch","automatic_resume"})yes(!j.getBoolean(k),k+" false");
            for(String k:new String[]{"native_model_requests","business_steps","target_app_touch_input_attempts"})yes(j.getInt(k)==0,k+" zero");
            yes(j.getLong("original_task_deadline_elapsed_ms")==e.deadline,"original deadline unchanged");
            yes(j.getJSONObject("probe_request").getLong("deadline_elapsed_ms")==SystemClock.now+4000,"existing 4s RPC cap");
            yes(((Number)Files.getAttribute(e.evidence.resolve("calendar-window-rom-diagnostic.json"),"unix:mode")).intValue()%512==0600,"actual record chmod");
            int count=0;for(Constructor<?> c:BackgroundSession.CalendarWindowProbeReceipt.class.getDeclaredConstructors())if(!c.isSynthetic()){count++;yes(Modifier.isPrivate(c.getModifiers()),"receipt source constructor private");}
            yes(count==1,"no successful receipt stub");
        }});
        test("wrong_literal_and_different_selection_instance_reject_before_observation",()->{
            try(Env e=new Env()){no(()->e.controller.requireSelection(TASK,OWNER+" ",e.auth,e.selection,e.deadline),"changed literal");yes(e.operations.isEmpty(),"no RPC");}
            try(Env e=new Env()){BackgroundSession.Selection other=new BackgroundSession.Selection(e.selection.taskTarget,true);
                no(()->e.controller.requireSelection(TASK,OWNER,e.auth,other,e.deadline),"equal-valued different selection");yes(e.operations.isEmpty(),"no replacement RPC");}
        });
        test("unbound_or_replaced_authorization_and_retired_gate_reject",()->{
            try(Env e=new Env()){TaskAuthorization.Gate raw=TaskAuthorization.parse(OWNER).bind(TASK);e.service.taskAuthorization=raw;
                no(()->e.controller.requireSelection(TASK,OWNER,raw,e.selection,e.deadline),"unbound actual authorization");}
            try(Env e=new Env()){TaskAuthorization.Gate other=TaskAuthorization.parse(OWNER).forExecutionSelection(e.selection).bind(TASK);
                no(()->e.controller.requireSelection(TASK,OWNER,other,e.selection,e.deadline),"same-valued Gate replacement");}
            try(Env e=new Env()){e.auth.retire();no(()->e.controller.requireSelection(TASK,OWNER,e.auth,e.selection,e.deadline),"retired Gate");}
        });
        test("wrong_target_modes_and_missing_selection_never_gain_probe_permission",()->{
            try(Env e=new Env()){no(()->e.controller.requireSelection(TASK,OWNER,e.auth,null,e.deadline),"null selection");
                BackgroundSession.Selection ordinary=new BackgroundSession.Selection(e.selection.taskTarget,false);
                no(()->e.controller.requireSelection(TASK,OWNER,e.auth,ordinary,e.deadline),"nonindependent profile");
                BackgroundTaskTarget personal=BackgroundTaskTarget.resolveExplicitSelection(OWNER,ProfileTarget.CTRIP,Collections.singleton(ProfileTarget.CTRIP),null);
                no(()->e.controller.requireSelection(TASK,OWNER,e.auth,new BackgroundSession.Selection(personal,false,true),e.deadline),"personal target");
                no(()->{ProfileTarget xiaomi=profile(NativeAppGoal.XIAOMI_PACKAGE);BackgroundTaskTarget wrong=BackgroundTaskTarget.resolveExplicitSelection(OWNER,xiaomi.packageName,Collections.singleton(xiaomi.packageName),xiaomi);
                    e.controller.requireSelection(TASK,OWNER,e.auth,new BackgroundSession.Selection(wrong,true),e.deadline);},"wrong selected package");
                yes(e.operations.isEmpty(),"no wrong scope RPC");}
        });
        test("current_task_cancel_and_original_deadline_are_rechecked",()->{
            try(Env e=new Env()){e.controller.currentTaskId=OTHER;no(e::run,"different current task");failedJournal(e,"task");yes(e.controller.observationReads==0,"no task-crossing observation");}
            try(Env e=new Env()){e.controller.cancelled.set(true);no(e::run,"already cancelled");failedJournal(e,"cancel");yes(e.operations.isEmpty(),"no cancelled RPC");}
            try(Env e=new Env()){SystemClock.now=e.deadline+1;no(e::run,"original deadline");failedJournal(e,"deadline");yes(e.operations.isEmpty(),"no expired RPC");}
        });
        test("existing_model_or_business_sessions_exclude_the_finite_diagnostic",()->{
            for(String field:new String[]{"activeInference","activeNativeTask","activeNativeSearch","activeWebTask"})try(Env e=new Env()){
                set(e.controller,field,new Object());no(e::run,field);yes(e.operations.isEmpty()&&e.controller.observationReads==0,"no overlap for "+field);failedJournal(e,field);
            }
        });
        test("restricted_or_changed_real_scope_file_stops_before_observation",()->{
            try(Env e=new Env()){e.scope.refuse("host scope changed");no(e::run,"refused scope");yes(e.operations.isEmpty(),"no refused scope RPC");failedJournal(e,"scope");}
            try(Env e=new Env()){Files.write(e.root.resolve(QualificationScope.FILE_NAME),new byte[]{1});
                no(e::run,"actual unrestricted scope file appeared");yes(e.operations.isEmpty(),"real file guard before RPC");failedJournal(e,"scope file");}
        });
        test("null_background_or_different_selection_cannot_use_current_broker",()->{
            try(Env e=new Env()){no(()->e.controller.probe(TASK,OWNER,e.evidence.toFile(),e.auth,null,e.selection,e.scope,e.deadline),"null BG");failedJournal(e,"null BG");yes(e.operations.isEmpty(),"no null lease RPC");}
            try(Env e=new Env()){BackgroundSession.Selection other=new BackgroundSession.Selection(e.selection.taskTarget,true);TaskAuthorization.Gate bound=TaskAuthorization.parse(OWNER).forExecutionSelection(other).bind(TASK);e.service.taskAuthorization=bound;
                no(()->e.controller.probe(TASK,OWNER,e.evidence.toFile(),bound,e.session,other,e.scope,e.deadline),"BG selection object mismatch");yes(e.operations.isEmpty(),"no mismatched lease RPC");}
        });
        test("missing_or_truncated_real_collection_facts_refuse_probe",()->{
            for(int variant=0;variant<6;variant++)try(Env e=new Env()){
                if(variant==0)e.observed=null;
                else if(variant==1)e.observed=e.observation(e.receivedWindow,null,false);
                else {int pending=variant==2?1:0,node=variant==4?1:0,text=variant==5?1:0;long child=variant==3?1:0;
                    e.observed=e.observation(e.receivedWindow,stats(pending,child,node,text),true);}
                no(e::run,"incomplete variant "+variant);yes(e.probes()==0&&e.controller.observationReads==1,"no incomplete probe");failedJournal(e,"collection");
            }
        });
        test("read_action_or_cancellation_work_must_all_be_drained",()->{
            for(String name:new String[]{"readPending","actionPending","cancellationPending"})try(Env e=new Env()){
                set(e.service,name,true);no(e::run,name);yes(e.probes()==0,"no probe with unfinished "+name);failedJournal(e,"pending");
            }
        });
        test("different_generation_profile_and_display_are_refused",()->{
            for(String name:new String[]{"backgroundGeneration","profileTarget","windowMetadata","packageName"})try(Env e=new Env()){
                Object value="backgroundGeneration".equals(name)?UUID.randomUUID().toString():"profileTarget".equals(name)?profile(NativeAppGoal.XIAOMI_PACKAGE):"windowMetadata".equals(name)?ObservedWindowMetadata.observed(new int[]{0,0,1200,2600},"android.widget.FrameLayout",1,8,new int[]{0,0,1200,2600},"host-only"):"wrong.package";
                // Mutation only creates a hostile serialized-looking host value; it cannot register ownership.
                set(e.observed,name,value);no(e::run,name);yes(e.probes()==0,"no mismatched observation RPC");failedJournal(e,"observation identity");
            }
        });
        test("equal_wire_unregistered_window_cannot_replace_received_proof",()->{try(Env e=new Env()){
            WindowOwnership copy=WindowOwnership.fromWire(e.receivedWindow.wire(),e.target);
            e.observed=e.observation(copy,stats(0,0,0,0),false);
            no(e::run,"unregistered same wire");yes(e.probes()==0,"actual historical map refuses cloned proof");failedJournal(e,"window provenance");
        }});
        test("task_gate_and_cancellation_changes_during_observation_stop_before_probe",()->{
            for(int variant=0;variant<3;variant++)try(Env e=new Env()){
                final int v=variant;e.controller.readPort=()->{if(v==0)e.controller.currentTaskId=OTHER;else if(v==1)e.service.taskAuthorization=TaskAuthorization.parse(OWNER).forExecutionSelection(e.selection).bind(TASK);else e.controller.cancelled.set(true);return e.observed;};
                no(e::run,"observation gap "+v);yes(e.probes()==0,"no reauthorized read");failedJournal(e,"callback gap");
            }
        });
        test("invalid_authenticated_probe_cannot_construct_receipt_or_qualify",()->{
            for(String key:new String[]{"grants_dispatch","input_attempts","request_id"})try(Env e=new Env()){
                e.change=(q,r)->{if("calendar_probe".equals(q.getString("op"))){JSONObject p=r.getJSONObject("calendar_window_probe");p.put(key,"request_id".equals(key)?"different":"input_attempts".equals(key)?Integer.valueOf(1):Boolean.TRUE);}};
                no(e::run,key);yes(e.probes()==1,"one refused probe no retry");failedJournal(e,"private receipt");
            }
        });
        test("nonroot_peer_is_refused_before_any_probe_request_bytes",()->{try(Env e=new Env()){
            e.controller.readPort=()->{LocalSocket.peerUid=2000;LocalSocket.events.clear();LocalSocket.sent=new byte[0];return e.observed;};
            no(e::run,"nonroot peer");yes(e.probes()==0&&!LocalSocket.events.contains("output"),"kernel peer port rejected before bytes");failedJournal(e,"peer");
        }});
        test("late_or_cancelled_probe_return_never_qualifies_or_retries",()->{
            for(int variant=0;variant<2;variant++)try(Env e=new Env()){
                final int v=variant;e.change=(q,r)->{if("calendar_probe".equals(q.getString("op"))){if(v==0)SystemClock.now=q.getLong("deadline_elapsed_ms");else e.controller.cancelled.set(true);}};
                no(e::run,"late/cancel return");yes(e.probes()==1,"no RPC retry");failedJournal(e,"late reply");
            }
        });
        test("profile_identity_change_on_final_readback_prevents_qualification",()->{try(Env e=new Env()){
            e.change=(q,r)->{if("calendar_probe".equals(q.getString("op")))e.unique="virtual:changed";};
            no(e::run,"final actual policy identity changed");yes(e.probes()==1,"no second probe");failedJournal(e,"final identity");
        }});
        test("short_task_deadline_is_clipped_without_refresh",()->{try(Env e=new Env()){
            long shortDeadline=SystemClock.now+700;e.controller.probe(TASK,OWNER,e.evidence.toFile(),e.auth,e.session,e.selection,e.scope,shortDeadline);
            JSONObject j=e.journal();yes(j.getLong("original_task_deadline_elapsed_ms")==shortDeadline,"same controller deadline");
            yes(j.getJSONObject("probe_request").getLong("deadline_elapsed_ms")==shortDeadline,"same wire deadline");
        }});
        test("actual_record_collision_preserves_existing_bytes_and_refuses_partial",()->{try(Env e=new Env()){
            Path p=e.evidence.resolve("calendar-window-rom-diagnostic.json");byte[] existing="prior-original".getBytes(StandardCharsets.UTF_8);Files.write(p,existing);
            no(e::finite,"create-only journal collision");yes(Arrays.equals(existing,Files.readAllBytes(p)),"old bytes unchanged");
            yes(e.controller.finalStatus==null&&e.controller.modelBegins==0&&e.probes()==1,"no partial after persistence failure or model fallback");
        }});
        test("original_failure_is_preserved_with_suppressed_record_collision",()->{try(Env e=new Env()){
            Files.write(e.evidence.resolve("calendar-window-rom-diagnostic.json"),new byte[]{1});e.controller.cancelled.set(true);
            Exception error=no(e::run,"cancel and record collision");yes(error.getClass().getSimpleName().equals("Stopped"),"original cancellation retained");
            yes(error.getSuppressed().length==1,"persistence error suppressed once");yes(e.probes()==0,"no retry");
        }});
        test("actual_record_final_chmod_failure_does_not_start_model_or_return_partial",()->{try(Env e=new Env()){
            android.system.Os.failChmod=true;Exception error=no(e::finite,"final chmod failure");
            yes(error.getMessage().contains("final chmod"),"specific final permission failure");
            yes(Files.isRegularFile(e.evidence.resolve("calendar-window-rom-diagnostic.json")),"real write and fsync preceded failed chmod");
            yes(e.controller.finalStatus==null&&e.controller.modelBegins==0&&e.probes()==1,"failure cannot become partial return");
        }});
        boolean all=true;JSONArray values=new JSONArray();for(JSONObject row:rows){values.put(row);all&=row.getBoolean("passed");}
        JSONObject result=new JSONObject().put("schema","hepta.calendar-probe-diagnostic-host-cases.v1").put("all_pass",all)
            .put("cases",rows.size()).put("assertions",assertions).put("rows",values)
            .put("actual_controller_consumers",true).put("actual_full_BackgroundSession",true).put("actual_TaskAuthorization_Selection",true)
            .put("synthetic_first_observation_and_socket_peer_response",true).put("real_broker_or_ROM_qualified",false)
            .put("actual_original_task_finally_executed",false).put("models",0).put("phone_operations",0).put("input_dispatch_calls",0);
        Files.write(Paths.get(args[0]),(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        if(!all)throw new AssertionError("probe diagnostic case failed");
    }
}
