package org.trillionnium.hepta.local;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.*;
import org.json.*;
import org.trillionnium.hepta.background.ProfileIdentity;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.WindowOwnership;

/** Whole production TCG/NativeAppSession/ProfileTarget. Host verifier/worker IO
 * is explicit. Optional original phone JSON is read-only; no phone or model runs. */
final class ProfileTerminalEvidenceHostTest {
    static int checks; static final List<String> cases=new ArrayList<String>();
    interface Test { void run() throws Exception; }
    static void check(boolean ok,String why){checks++;if(!ok)throw new AssertionError(why);}
    static void one(String name,Test t)throws Exception{t.run();cases.add(name);}
    static void immutable(Test t)throws Exception{checks++;try{t.run();}catch(UnsupportedOperationException expected){return;}throw new AssertionError("mutable evidence escaped");}
    static String hash(String s){return NativeAppEvidence.hash(s);}
    static JSONObject read(Path p)throws Exception{return new JSONObject(new String(Files.readAllBytes(p),StandardCharsets.UTF_8));}
    @SuppressWarnings("unchecked") static Map<String,Object> freeze(Map<String,Object> value)throws Exception{
        Method m=TaskCompletionGate.class.getDeclaredMethod("immutableMap",Map.class);m.setAccessible(true);
        try{return (Map<String,Object>)m.invoke(null,value);}catch(InvocationTargetException e){
            Throwable t=e.getCause();if(t instanceof Exception)throw (Exception)t;throw new AssertionError(t);
        }
    }
    static ProfileTarget synthetic(){return new ProfileTarget(new ProfileIdentity(10,10,0,"android.os.usertype.profile.MANAGED"),
            1010367,ProfileTarget.CTRIP,ProfileTarget.CTRIP+"/ctrip.business.splash.CtripSplashActivity",1779,
            Collections.singletonMap("base",NativeCtripFlightPage.BASE_APK_SHA256),
            new LinkedHashSet<String>(Arrays.asList(hash("signer-b"),hash("signer-a"))));}
    static Map<String,Object> wrapped(ProfileTarget p){Map<String,Object> session=new LinkedHashMap<String,Object>();
        session.put("profile_target",p.evidence());Map<String,Object> root=new LinkedHashMap<String,Object>();root.put("native_app_session",session);return root;}
    static String unsupported(Object value,String path){
        if(value==null||value instanceof String||value instanceof Boolean||value instanceof Number)return null;
        if(value instanceof Map<?,?>){for(Map.Entry<?,?> e:((Map<?,?>)value).entrySet()){
            String p=unsupported(e.getValue(),path+"."+e.getKey());if(p!=null)return p;}return null;}
        if(value instanceof List<?>){int i=0;for(Object v:(List<?>)value){String p=unsupported(v,path+"["+(i++)+"]");if(p!=null)return p;}return null;}
        return path+":"+value.getClass().getName();
    }
    static final class Binding implements BackgroundTaskTarget.SelectionBinding {
        final BackgroundTaskTarget target;
        Binding(String owner,ProfileTarget profile){target=BackgroundTaskTarget.resolveExplicitSelection(owner,ProfileTarget.CTRIP,Collections.singleton(ProfileTarget.CTRIP),profile);}
        public BackgroundTaskTarget executionTarget(){return target;}
    }
    static final class Actual {
        final Path root;final ProfileTarget profile;final Binding selection;final TaskAuthorization auth;
        final TaskAuthorization.Gate owner;final TaskCompletionGate completion;final NativeAppSession session;
        final JSONObject binding,attempt,cleanup,worker;final String task,generation,run;final Map<String,Object> cleanupMap;
        NotesCompletionEvidence.Frame frame;WindowOwnership window;int frames;
        Actual(Path root)throws Exception{
            this.root=root;JSONObject recordedOwner=read(root.resolve("task/owner.json"));
            binding=read(root.resolve("task/native-app-binding.json"));task=binding.getString("task_id");generation=binding.getString("background_generation");
            JSONObject background=read(root.resolve("task/background-binding.json"));profile=ProfileTarget.fromWire(background.getString("profile_target_wire"));
            check(profile.sha256.equals(background.getString("profile_target_sha256")),"actual wire/digest unchanged");
            selection=new Binding(recordedOwner.getString("instruction"),profile);auth=TaskAuthorization.parse(recordedOwner.getString("instruction")).forExecutionSelection(selection);owner=auth.bind(task);
            check(selection.target.targetSha256.equals(binding.getString("execution_target_sha256")),"actual execution target binding");
            check(auth.sha256.equals(binding.getString("authorization_sha256")),"actual owner authorization binding");
            completion=new TaskCompletionGate(task,recordedOwner.getString("instruction"),auth,selection);
            session=new NativeAppSession(task,owner,selection,new NativeAppEvidence.Installed(profile),binding.getString("selection_projection_sha256"),generation,binding.getInt("display_id"),
                    new NativeAppSession.InstalledVerifier(){public void verify(){/* host boundary, no PM call */}},
                    new NativeAppSession.Journal(){public void write(String leaf,Map<String,Object> value){/* host boundary, no app write */}});
            completion.bindNativeSession(session);attempt=read(root.resolve("task/native-app-outcome-01.json")).getJSONObject("attempt");run=attempt.getString("model_run_id");
            JSONObject receipt=read(root.resolve("runs/"+run+"/app-receipt.json"));
            worker=read(root.resolve("runs/"+receipt.getString("worker_generation")+"/app-session-receipt.json"));
            cleanup=read(root.resolve("task/background-cleanup.json")).getJSONObject("profile_cleanup");cleanupMap=cleanup.toMap();
        }
        NativeAppEvidence.Frame readFrame(Path path,JSONObject originalNative)throws Exception{
            JSONObject raw=read(path),bg=raw.getJSONObject("background_session"),win=raw.getJSONObject("window"),p=bg.getJSONObject("actual_profile_window");
            window=new WindowOwnership(profile,p.getString("generation"),p.getInt("display_id"),p.getInt("window_id"),p.getInt("task_id"),p.getInt("parent_task_id"),
                    p.getString("task_token_id"),p.getString("proof_id"),p.getInt("user_id"),p.getLong("user_serial"),p.getInt("full_uid"),p.getLong("observed_elapsed_ms"),p.getLong("expires_elapsed_ms"));
            check(window.sha256.equals(p.getString("proof_sha256")),"original window proof scalar replay");
            List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>();List<NotesCompletionEvidence.Node> retained=new ArrayList<NotesCompletionEvidence.Node>();
            JSONArray arr=raw.getJSONArray("nodes");for(int i=0;i<arr.length();i++){
                JSONObject n=arr.getJSONObject(i),pos=n.getJSONObject("native_tree_position"),sel=n.getJSONObject("native_selection_state");JSONArray b=n.getJSONArray("bounds");
                check(!n.has("child_text_status"),"actual retained row has no unprojected child-text evidence");
                String text=n.optString("text",""),desc=n.optString("description","");
                String fullLabel=ObservedChildText.displayLabel(text,desc,ObservedChildText.notApplicable());
                if(text.trim().isEmpty()&&desc.trim().isEmpty())fullLabel="";
                String label=ObservedTargetLabels.project(fullLabel);
                Set<String> dirs=new LinkedHashSet<String>();JSONArray ds=n.getJSONArray("scroll_directions");for(int j=0;j<ds.length();j++)dirs.add(ds.getString(j));
                // Actual PhoneObservation schema emits enabled=false only for a disabled node.
                boolean enabled=n.optBoolean("enabled",true),click=n.optBoolean("clickable",false),edit=n.optBoolean("editable",false),scroll=n.optBoolean("scrollable",false),password=n.optBoolean("password",false);
                NativeAppEvidence.Node node=new NativeAppEvidence.Node(n.getString("id"),n.getString("package"),n.getString("class_name"),n.optString("view_id",""),text,desc,
                        pos.getString("path"),pos.getString("parent_class"),n.getString("node_app_tree_sha256"),label,
                        b.getInt(0),b.getInt(1),b.getInt(2),b.getInt(3),enabled,password,click,edit,scroll,
                        sel.getBoolean("selected"),sel.getBoolean("checkable"),sel.getBoolean("checked"),dirs);
                nodes.add(node);retained.add(new NotesCompletionEvidence.Node(node.id,node.packageName,node.text,fullLabel,node.viewId,n.isNull("input_text_sha256")?null:n.getString("input_text_sha256"),
                        new int[]{node.left,node.top,node.right,node.bottom},node.editable,node.clickable,node.scrollable,node.enabled,node.password,ObservedChildText.notApplicable(),node.signature,node.className,node.path));
            }
            frame=new NotesCompletionEvidence.Frame(raw.getString("observation_id"),raw.getString("package"),raw.getInt("window_id"),bg.getInt("display_id"),generation,win.getInt("type"),true,raw.getBoolean("nodes_truncated"),retained);
            JSONArray b=win.getJSONArray("root_bounds");String frameSha=TaskCompletionGate.webFrameSha(frame);
            if(originalNative!=null)check(frameSha.equals(originalNative.getString("completion_frame_sha256")),"all original node fields recreate exact completion frame hash");
            JSONObject stats=raw.getJSONObject("collection");check(stats.getInt("retained_nodes")==nodes.size()&&stats.getInt("pending_nodes_at_stop")==0&&stats.getJSONArray("truncation_reasons").length()==0,"actual complete retained census");
            String source=hash(new String(Files.readAllBytes(path),StandardCharsets.UTF_8));
            NativeAppEvidence.Frame f=new NativeAppEvidence.Frame(task,auth.instructionSha256,selection.target.targetSha256,auth.sha256,binding.getString("selection_projection_sha256"),
                    raw.getString("observation_id"),raw.getString("package"),generation,raw.getString("app_tree_sha256"),raw.getString("observation_state_sha256"),raw.getString("screen_sha256"),source,frameSha,
                    bg.getInt("display_id"),raw.getInt("window_id"),raw.getInt("rotation"),raw.getInt("screen_width"),raw.getInt("screen_height"),b.getInt(0),b.getInt(1),b.getInt(2),b.getInt(3),raw.getLong("captured_elapsed_ms"),false,true,nodes,win.getInt("type"),true,window);
            frames++;return f;
        }
        void sequence()throws Exception{
            NativeAppEvidence.Frame before=readFrame(root.resolve("task/step-01-before.json"),attempt.getJSONObject("before"));session.observed(before);completion.observed(frame);
            ActionDecision action=ActionDecision.parse(new String(Files.readAllBytes(root.resolve("runs/"+run+"/raw-text.txt")),StandardCharsets.UTF_8),ActionDecision.IME_ACTION_SCHEMA);
            check("done".equals(action.action)&&"failure".equals(action.status),"actual model failure, no click/query");owner.check(action,run);
            session.beforeModelAction(1,action,run,attempt.getLong("dispatch_started_elapsed_ms"));JSONObject ar=attempt.getJSONObject("actual_action_receipt");
            check(ar.getBoolean("accepted")&&!ar.getBoolean("dispatched")&&!ar.getBoolean("stale"),"actual no-effect outcome");
            session.modelActionOutcome(action,run,true,false,false,ar.getString("step_action_record_sha256"),attempt.getLong("dispatch_finished_elapsed_ms"));
            NativeAppEvidence.Frame after=readFrame(root.resolve("task/step-01-after.json"),null);session.observed(after);completion.observed(frame);
            check(!session.ready(frame),"actual privacy/unrecognized page has no completed flight");session.retire();
        }
        Map<String,Object> finish(boolean modelSuccess,boolean cleanupKnown)throws Exception{
            String workerGeneration=worker.getString("worker_generation");
            String receiptHash=hash(new String(Files.readAllBytes(root.resolve("runs/"+workerGeneration+"/app-session-receipt.json")),StandardCharsets.UTF_8));
            return completion.terminalNativeCheck(session,frame,owner.frame(),1,null,modelSuccess,cleanupKnown,true,true,true,false,
                    worker.getBoolean("process_started"),worker.getBoolean("process_exit_observed"),worker.getInt("exit_code"),worker.getBoolean("native_session_binding_valid"),
                    task,workerGeneration,receiptHash,cleanupMap).evidence;
        }
    }
    public static void main(String[] args)throws Exception{
        String mode=args[0];Path out=Paths.get(args[1]);Path actual=args.length>2&&!"-".equals(args[2])?Paths.get(args[2]):null;
        if("baseline".equals(mode)){
            ProfileTarget t=actual==null?synthetic():ProfileTarget.fromWire(read(actual.resolve("task/background-binding.json")).getString("profile_target_wire"));
            String offender=unsupported(wrapped(t),"$");check(offender!=null&&offender.startsWith("$.native_app_session.profile_target.signer_sha256:"),"exact nested Set culprit required");
            try{if(actual==null)freeze(wrapped(t));else{Actual a=new Actual(actual);a.sequence();a.finish(false,true);}}
            catch(IllegalArgumentException expected){check("completion: unsupported mutable result evidence type".equals(expected.getMessage()),"exact old runtime exception");
                JSONObject r=new JSONObject().put("expected_baseline_red",true).put("unsupported_path_and_type",offender).put("full_terminal_called",actual!=null).put("assertions",checks);
                Files.write(out,(r.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);expected.printStackTrace();System.exit(3);return;}
            throw new AssertionError("old source unexpectedly passed");
        }
        one("sorted_signer_projection_is_deeply_immutable_json_list",()->{ProfileTarget t=synthetic();String wire=t.wire(),identity=t.sha256;Map<String,Object> e=t.evidence();Object value=e.get("signer_sha256");
            check(value instanceof List<?>,"evidence must be List, not Set");check(value.equals(new ArrayList<String>(t.signerSha256)),"exact sorted members");
            immutable(()->((List<?>)value).clear());immutable(()->e.clear());immutable(()->((Map<?,?>)e.get("apk_hashes")).clear());immutable(()->((Map<?,?>)e.get("profile")).clear());immutable(()->t.signerSha256.clear());
            check(wire.equals(t.wire())&&identity.equals(t.sha256)&&t.same(ProfileTarget.fromWire(wire)),"wire and target digest unchanged");
            check(unsupported(wrapped(t),"$")==null,"full actual shape has only JSON-safe types");Map<String,Object> copy=freeze(wrapped(t));immutable(()->copy.clear());});
        one("general_mutable_set_is_still_refused_by_completion_gate",()->{Map<String,Object> bad=new LinkedHashMap<String,Object>();bad.put("unknown",new HashSet<String>(Arrays.asList("x")));
            checks++;try{freeze(bad);}catch(IllegalArgumentException expected){check(expected.getMessage().equals("completion: unsupported mutable result evidence type"),"original rejection unchanged");return;}throw new AssertionError("TCG input domain widened");});
        one("mutable_constructor_inputs_cannot_rewrite_projected_identity",()->{Map<String,String> apks=new HashMap<String,String>();apks.put("base",hash("base"));Set<String> signers=new HashSet<String>();signers.add(hash("signer"));
            ProfileTarget t=new ProfileTarget(new ProfileIdentity(10,10,0,"android.os.usertype.profile.MANAGED"),1010367,ProfileTarget.CTRIP,ProfileTarget.CTRIP+"/ctrip.synthetic.Activity",1779,apks,signers);
            String wire=t.wire(),old=new JSONObject(t.evidence()).toString();apks.put("base",hash("changed"));signers.clear();check(wire.equals(t.wire())&&old.equals(new JSONObject(t.evidence()).toString()),"constructor input aliases isolated");});
        if(actual!=null){
            one("actual_profile_done_failure_reaches_full_terminal_without_success",()->{Actual a=new Actual(actual);a.sequence();Map<String,Object> e=a.finish(false,true);
                check(Boolean.FALSE.equals(e.get("completion_verified"))&&Boolean.FALSE.equals(e.get("business_verified")),"failure remains failure");check(Boolean.TRUE.equals(e.get("all_cleanup_known")),"real cleanup retained separately");
                check(a.frames==2,"both original complete frames replayed");immutable(()->e.clear());});
            one("model_success_flag_without_claim_cannot_promote_actual_failure",()->{Actual a=new Actual(actual);a.sequence();Map<String,Object> e=a.finish(true,true);check(Boolean.FALSE.equals(e.get("completion_verified")),"no claim no success");});
            one("unknown_cleanup_cannot_promote_actual_failure",()->{Actual a=new Actual(actual);a.sequence();Map<String,Object> e=a.finish(false,false);check(Boolean.FALSE.equals(e.get("completion_verified"))&&Boolean.FALSE.equals(e.get("all_cleanup_known")),"unknown cleanup retained");});
            one("actual_profile_cleanup_identity_gates_still_bind_exact_window",()->{Actual a=new Actual(actual);a.sequence();check(NativeAppSession.profileCleanupBound(a.profile,a.window,a.cleanupMap),"actual cleanup matches original profile window");
                Map<String,Object> bad=new LinkedHashMap<String,Object>(a.cleanupMap);bad.put("full_uid",10367);check(!NativeAppSession.profileCleanupBound(a.profile,a.window,bad),"same appId wrong user refused");
                bad=new LinkedHashMap<String,Object>(a.cleanupMap);bad.put("user_serial",11);check(!NativeAppSession.profileCleanupBound(a.profile,a.window,bad),"reused user serial refused");
                bad=new LinkedHashMap<String,Object>(a.cleanupMap);bad.put("cleanup_known",false);check(!NativeAppSession.profileCleanupBound(a.profile,a.window,bad),"unknown cleanup refused");});
        }
        JSONObject r=new JSONObject().put("all_pass",true).put("cases",cases.size()).put("assertions",checks).put("case_names",new JSONArray(cases))
                .put("actual_saved_shape_replayed",actual!=null).put("phone_operations",0).put("model_executed",false).put("business_verified",false)
                .put("boundaries","Actual complete pure production methods; optional original JSON and model outcome replay; installed verifier, journal, current worker/cleanup calls are host inputs, not fresh Android authority");
        Files.write(out,(r.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);System.out.println(r.toString());
    }
}
