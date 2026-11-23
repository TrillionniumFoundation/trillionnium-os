package org.trillionnium.hepta.local;

import android.graphics.Rect;
import android.os.SystemClock;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityWindowInfo;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.*;
import org.json.JSONObject;
import static org.trillionnium.hepta.local.QualificationScopeHostTest.*;

import org.json.JSONArray;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Node;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Frame;
import static org.trillionnium.hepta.local.NotesCreateWorkflowHostTest.child;
import static org.trillionnium.hepta.local.NotesCreateWorkflowHostTest.text;
import static org.trillionnium.hepta.local.NotesCreateWorkflowHostTest.nullable;
import static org.trillionnium.hepta.local.NotesCreateWorkflowHostTest.bool;

public final class NotesReopenReadinessHostTest {
    static final int DISPLAY=6;
    private static List<PhoneObservation.Node> readinessRows(String body,boolean ready){
        List<PhoneObservation.Node> out=new ArrayList<PhoneObservation.Node>();
        out.add(new PhoneObservation.Node("n0",NotesCompletionEvidence.NOTES,"android.webkit.WebView","","NoteEditor","",
                new Rect(10,200,1000,1800),false,false,true,true,false,false,ObservedChildText.notApplicable(),
                ObservedScrollActions.UNKNOWN,ObservedImeEnter.UNKNOWN,null,false));
        if(ready)out.add(new PhoneObservation.Node("n1",NotesCompletionEvidence.NOTES,"android.widget.EditText","",""+body,"",
                new Rect(20,300,900,600),false,true,false,true,false,false,ObservedChildText.notApplicable(),
                ObservedScrollActions.UNKNOWN,ObservedImeEnter.UNKNOWN,ObservedImeEnter.hash(body),false));
        return out;
    }
    private static Object readinessField(Object value,String name)throws Exception{
        java.lang.reflect.Field f=value.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(value);
    }
    @SuppressWarnings("unchecked")
    private static void reopenControllerCase(String mode)throws Exception{
        final String pkg=NotesCompletionEvidence.NOTES,body="HostReadiness261e",owner="记一下，"+body;
        try(Env e=new Env(false)){
            BackgroundSession bg=null;
            try{
                android.content.pm.PackageInfo info=new android.content.pm.PackageInfo();info.packageName=pkg;info.version=104;
                info.applicationInfo=new android.content.pm.ApplicationInfo();info.applicationInfo.packageName=pkg;info.applicationInfo.uid=10382;
                java.nio.file.Path apk=e.dir.resolve("installed/notes-readiness.apk");
                QualificationScopeHostTest.write(apk,"synthetic Notes APK, not phone bytes".getBytes(StandardCharsets.UTF_8),0644);
                info.applicationInfo.sourceDir=apk.toString();e.pm.packages.put(pkg,info);
                e.service.prepare(pkg);e.service.root.window.display=DISPLAY;e.service.node=null;
                check(e.service.acquireTask(e.task,()->{}),"readiness synthetic lease acquired");
                e.bound=QualificationScopeConfig.capture(e.service,e.task,null,e.runtime);e.service.bindQualificationScope(e.task,e.bound);
                TaskAuthorization authorization=TaskAuthorization.parse(owner);TaskAuthorization.Gate auth=e.service.bindTaskAuthorization(e.task,authorization);
                bg=BackgroundSession.fixture(e.task,DISPLAY,Collections.singleton(pkg));e.service.bindBackgroundSession(e.task,bg);
                QualificationScopeConfig.CompletionInstalledIdentity installed=QualificationScopeConfig.CompletionInstalledIdentity.captureNotes(e.service);
                TaskCompletionGate completion=new TaskCompletionGate(e.task,owner,authorization);
                completion.bindInstalled(new NotesCompletionEvidence.Installed(installed.packageName,installed.uid,installed.apkHashes));
                final int[] providerCalls={0};
                e.service.observationRows=()->readinessRows(body,mode.equals("immediate")||(!mode.equals("never")&&++providerCalls[0]>1));
                e.service.observe(e.task,e.dir.toFile(),()->false,SystemClock.elapsedRealtime()+10000,new HeptaAccessibilityService.ObservationCallback(){
                    public void onObservation(PhoneObservation o){}public void onError(String why){throw new AssertionError(why);}
                });
                final PhoneObservation initial=e.service.current;
                final java.lang.reflect.Method bridge=LocalTaskController.class.getDeclaredMethod("completionFrame",PhoneObservation.class);bridge.setAccessible(true);
                NotesCompletionEvidence.Frame first=(NotesCompletionEvidence.Frame)bridge.invoke(null,initial);
                NotesCompletionEvidence.Frame before=new NotesCompletionEvidence.Frame("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",pkg,3,DISPLAY,bg.generation,1,true,false,Collections.<NotesCompletionEvidence.Node>emptyList());
                final String run="dddddddddddddddddddddddddddddddd";
                ActionDecision parent=ActionDecision.parse(new JSONObject().put("reason","synthetic host accepted create")
                        .put("action","notes.create").put("app_label","Moto").put("package",pkg).put("observation_id",before.observationId)
                        .put("text",body).toString(),ActionDecision.FIXED_INTENT_ACTION_SCHEMA);
                Map<String,Object> target=new LinkedHashMap<String,Object>();
                org.trillionnium.hepta.background.FixedIntentTools.Profile profile=org.trillionnium.hepta.background.FixedIntentTools.forAction("notes.create");
                target.put("package",pkg);target.put("component",pkg+"/"+profile.className);target.put("action","notes.create");
                target.put("app_label","Moto");target.put("target_uid",10382);
                for(String key:new String[]{"exported","activity_enabled","application_enabled","declared_intent_filter_matched","ordinary_caller_permission_checked"})target.put(key,true);
                Map<String,Object> fixed=new LinkedHashMap<String,Object>();
                fixed.put("schema","hepta.fixed-intent-result.v1");fixed.put("task_id",e.task);fixed.put("model_run_id",run);
                fixed.put("observation_id",before.observationId);fixed.put("source_package",pkg);fixed.put("source_window_id",before.windowId);
                fixed.put("display_id",DISPLAY);fixed.put("background_generation",bg.generation);fixed.put("action","notes.create");
                for(String key:new String[]{"attempt_consumed","dispatch_attempted","api_accepted"})fixed.put(key,true);
                fixed.put("automatic_retry_allowed",false);fixed.put("result","launch_accepted");fixed.put("payload_sha256",ObservedImeEnter.hash(body));
                fixed.put("attempt_ordinal",1);fixed.put("attempt_id",ObservedImeEnter.hash(e.task+"|1|notes.create|"+ObservedImeEnter.hash(body)));fixed.put("target",target);
                List<NotesCompletionEvidence.Node> createdRows=Arrays.asList(
                        new NotesCompletionEvidence.Node("n0",pkg,"NoteEditor","NoteEditor","",null,new int[]{10,200,1000,1800},false,false,true,true,false),
                        new NotesCompletionEvidence.Node("n1",pkg,body,body,"",ObservedImeEnter.hash(body),new int[]{20,300,900,600},true,false,false,true,false));
                final NotesCompletionEvidence.Frame created=new NotesCompletionEvidence.Frame("cccccccccccccccccccccccccccccccc",pkg,first.windowId,DISPLAY,bg.generation,1,true,false,createdRows);
                completion.action(1,run,parent,true,true,false,before,created,fixed);
                check(completion.notesPhase(created).launchProved,"strict synthetic parent receipt is actually admitted");
                final NotesCreateWorkflow.Grant grant=completion.notesCreateWorkflow(1,run,parent,
                        new NotesCreateWorkflow.Observation(created,TaskCompletionGateHostTest.H,0),auth.frame());
                check(grant!=null,"actual parent completion gate mints this fixture workflow grant");
                e.controller=new LocalTaskController(e.service,new QualificationScopeHostTest.CountingModel(e,"done",pkg,null));
                java.nio.file.Path dir=Files.createDirectory(e.dir.resolve("readiness-case"));
                byte[] firstBytes=initial.toJson().toString(2).getBytes(StandardCharsets.UTF_8);
                QualificationScopeHostTest.write(dir.resolve("step-01-after.json"),firstBytes,0600);
                int observationsBefore=e.service.observations;
                if(mode.equals("window"))e.service.cacheClearHook=()->{e.service.root.windowId=8;e.service.root.window.id=8;};
                if(mode.equals("duplicate"))e.service.cacheClearHook=()->e.service.observations--;
                if(mode.equals("changed-apk"))e.service.cacheClearHook=()->{try{QualificationScopeHostTest.write(apk,"changed synthetic APK".getBytes(StandardCharsets.UTF_8),0644);}catch(Exception bad){throw new IllegalStateException(bad);}};
                if(mode.equals("cancel"))e.service.cacheClearHook=()->{try{
                    java.lang.reflect.Field cancelled=LocalTaskController.class.getDeclaredField("cancelled");cancelled.setAccessible(true);
                    ((java.util.concurrent.atomic.AtomicBoolean)cancelled.get(e.controller)).set(true);
                }catch(Exception bad){throw new IllegalStateException(bad);}};
                if(mode.equals("cache-false"))e.service.cacheClearResult=false;
                if(mode.equals("sdk32"))android.os.Build.VERSION.SDK_INT=32;
                final long deadline=mode.equals("expired")?SystemClock.elapsedRealtime()-1:SystemClock.elapsedRealtime()+15000;
                final Object[] box={null};final int[] workflowReads={0},dispatches={0};
                NotesCreateWorkflow.Result workflow=null;
                try{workflow=NotesCreateWorkflow.run(grant,new NotesCreateWorkflow.Observation(created,TaskCompletionGateHostTest.H,0),new NotesCreateWorkflow.IO(){
                    public NotesCreateWorkflow.Observation observe()throws Exception{
                        int n=++workflowReads[0];
                        if(n==1)return new NotesCreateWorkflow.Observation(new NotesCompletionEvidence.Frame("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",pkg,created.windowId,DISPLAY,created.backgroundGeneration,1,true,false,created.nodes),TaskCompletionGateHostTest.H,0);
                        if(n==2){
                            List<NotesCompletionEvidence.Node> list=Arrays.asList(
                                    TaskCompletionGateHostTest.n("n0",pkg,body,"",new int[]{10,100,600,300},false,true,false),
                                    TaskCompletionGateHostTest.n("n1",pkg,"",pkg+":id/view_pager2",new int[]{0,80,1000,2000},false,false,true),
                                    TaskCompletionGateHostTest.n("n2",pkg,"所有笔记",pkg+":id/title_text",new int[]{0,0,300,80},false,false,false));
                            return new NotesCreateWorkflow.Observation(new NotesCompletionEvidence.Frame("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2",pkg,created.windowId,DISPLAY,created.backgroundGeneration,1,true,false,list),TaskCompletionGateHostTest.H,0);
                        }
                        PhoneObservation observed=initial;
                        if(n==4){e.service.observe(e.task,dir.toFile(),()->false,deadline,new HeptaAccessibilityService.ObservationCallback(){
                            public void onObservation(PhoneObservation o){}public void onError(String why){throw new AssertionError(why);}});observed=e.service.current;}
                        if(n>4)throw new AssertionError("no extra child or unbounded observation");
                        return new NotesCreateWorkflow.Observation((NotesCompletionEvidence.Frame)bridge.invoke(null,observed),observed.treeSha256,observed.rotation);
                    }
                    public void checkpoint(String name,Map<String,Object> evidence){}
                    public NotesCreateWorkflow.Dispatch dispatch(NotesCreateWorkflow.ChildCall child,NotesCreateWorkflow.Observation prior){
                        dispatches[0]++;child.enterService(e.task,grant.authorizationSha256,run,prior.frame.observationId);
                        child.requireDispatch(e.task,grant.authorizationSha256,run,child.decision());
                        return new NotesCreateWorkflow.Dispatch(true,true,false,"explicit synthetic Android child effect",true,child.evidence());
                    }
                    public NotesCreateWorkflow.Observation awaitReopenedBody(NotesCreateWorkflow.ChildCall child,NotesCreateWorkflow.Observation firstAfter)throws Exception{
                        check(child.ordinal==2&&"click".equals(child.action)&&firstAfter.frame.observationId.equals(initial.id),"recovery entered only after this exact verified click");
                        java.lang.reflect.Method method=LocalTaskController.class.getDeclaredMethod("awaitNotesReopenedEditor",String.class,File.class,NotesCreateWorkflow.Grant.class,NotesCreateWorkflow.ChildCall.class,TaskAuthorization.Gate.class,TaskCompletionGate.class,QualificationScopeConfig.CompletionInstalledIdentity.class,PhoneObservation.class,long.class);method.setAccessible(true);
                        Object value=method.invoke(e.controller,e.task,dir.toFile(),grant,child,auth,completion,installed,initial,deadline);box[0]=value;
                        Exception failure=(Exception)readinessField(value,"error");if(failure!=null)throw failure;
                        PhoneObservation valueFrame=(PhoneObservation)readinessField(value,"observation");
                        return new NotesCreateWorkflow.Observation((NotesCompletionEvidence.Frame)bridge.invoke(null,valueFrame),valueFrame.treeSha256,valueFrame.rotation);
                    }
                    public void recorded(NotesCreateWorkflow.ChildRecord record){}
                });}catch(Exception failure){if(box[0]==null)throw failure;}
                check(box[0]!=null,"new read recovery is actually called by production workflow after missing first body");
                check(dispatches[0]==2,"one Back and one click only; no app action retry");Object result=box[0];
                Exception error=(Exception)readinessField(result,"error");
                List<NotesCreateWorkflow.Observation> reads=(List<NotesCreateWorkflow.Observation>)readinessField(result,"reads");
                JSONObject receipt=new JSONObject(new String(Files.readAllBytes(dir.resolve((String)readinessField(result,"receiptFile"))),StandardCharsets.UTF_8));
                boolean success=mode.equals("immediate")||mode.equals("delayed")||mode.equals("cache-false")||mode.equals("sdk32");
                check((workflow!=null&&workflow.completeFor(grant))==success,"actual unchanged final workflow proof still required");
                check((error==null)==success&&receipt.getBoolean("body_verified")==success,"actual helper result follows only observed body and current fences: "+mode);
                check(java.util.Arrays.equals(firstBytes,Files.readAllBytes(dir.resolve("step-01-after.json"))),"actual first-after bytes are never overwritten");
                check(e.service.effects()==0&&receipt.getInt("model_requests")==0&&receipt.getInt("app_actions")==0,"readiness dispatches no app/model effect");
                check(reads.size()<=4&&e.service.observations-observationsBefore<=4,"helper at most four frames plus the original separate stable read");
                check(e.service.cacheClears==(mode.equals("immediate")||mode.equals("expired")||mode.equals("sdk32")?0:1),"at most one actual client-cache IO call");
                check(!completion.controllerWorkflowReady((NotesCompletionEvidence.Frame)bridge.invoke(null,(PhoneObservation)readinessField(result,"observation"))),
                        "readiness alone never proves save/list/reopen");
                if(mode.equals("window")||mode.equals("duplicate")){
                    org.json.JSONArray samples=receipt.getJSONArray("samples");check(samples.length()==2,"rejected returned frame stays in actual samples");
                    JSONObject rejected=samples.getJSONObject(1);
                    check(!rejected.getBoolean("validation_accepted")&&receipt.getString("last_observation_file").equals(rejected.getString("observation_file")),
                            "failure receipt points to the rejected raw observation");
                    JSONObject archived=new JSONObject(new String(Files.readAllBytes(dir.resolve(rejected.getString("observation_file"))),StandardCharsets.UTF_8));
                    check(archived.getString("observation_id").equals(rejected.getString("observation_id"))
                            &&archived.getInt("window_id")==rejected.getInt("window_id"),"foreign or repeated raw frame is actually retained before refusal");
                }
                if(mode.equals("never"))check(reads.size()==4&&!receipt.getBoolean("body_verified"),"missing subtree stops at the fixed read bound");
                if(success&&!mode.equals("immediate"))check(reads.size()==2,"a newly complete body stops further reads");
                if(mode.equals("cancel")||mode.equals("changed-apk"))check(e.service.observations==observationsBefore,"cancellation or installed change after reset causes no new read");
                if(mode.equals("sdk32"))check(!receipt.getJSONObject("client_cache_reset").getBoolean("api33_supported"),"unsupported cache API is explicit, never emulated");
                if(mode.equals("cache-false"))check(!receipt.getJSONObject("client_cache_reset").getBoolean("clear_cache_returned"),"false cache return is retained; later actual body decides");
            }finally{android.os.Build.VERSION.SDK_INT=33;if(bg!=null)bg.close();}
        }
    }
    private static String nativePath(JSONObject node)throws Exception{
        JSONObject p=node.optJSONObject("native_tree_position");
        if(p==null)return null;
        check("hepta.native-tree-position.v1".equals(p.getString("schema"))&&"same_bounded_accessibility_traversal".equals(p.getString("source"))&&!p.getBoolean("grants_action_capability"),"raw native ancestry source must retain original identity");
        return p.getString("path");
    }
    static NotesCreateWorkflow.Observation actualObservationCurrent(JSONObject o)throws Exception{
        List<Node> nodes=new ArrayList<Node>();JSONArray all=o.getJSONArray("nodes");
        for(int i=0;i<all.length();i++){
            JSONObject n=all.getJSONObject(i);JSONArray b=n.getJSONArray("bounds");ObservedChildText.Result child=child(n);
            String text=text(n,"text"),description=text(n,"description"),label=ObservedChildText.displayLabel(text,description,child);
            if(text.trim().isEmpty()&&description.trim().isEmpty()&&(child.truncated||!child.status.equals("derived")))label="";
            nodes.add(new Node(n.getString("id"),n.getString("package"),text,label,text(n,"view_id"),nullable(n,"input_text_sha256"),new int[]{((Number)b.get(0)).intValue(),((Number)b.get(1)).intValue(),((Number)b.get(2)).intValue(),((Number)b.get(3)).intValue()},bool(n,"editable",false),bool(n,"clickable",false),bool(n,"scrollable",false),bool(n,"enabled",true),bool(n,"password",false),child,nullable(n,"node_app_tree_sha256"),text(n,"class_name"),nativePath(n)));
        }
        JSONObject w=o.getJSONObject("window"),bg=o.getJSONObject("background_session");
        Frame frame=new Frame(o.getString("observation_id"),o.getString("package"),o.getInt("window_id"),w.getInt("display_id"),bg.getString("generation"),w.getInt("type"),w.getString("metadata_status").equals("observed"),o.getBoolean("nodes_truncated"),nodes);
        return new NotesCreateWorkflow.Observation(frame,o.getString("app_tree_sha256"),o.getInt("rotation"));
    }
    private static int actualReplay(java.nio.file.Path fixtures)throws Exception{
        org.json.JSONArray rows=new JSONObject("{\"rows\":"+new String(Files.readAllBytes(fixtures.resolve("index.json")),StandardCharsets.UTF_8)+"}").getJSONArray("rows");
        for(int i=0;i<rows.length();i++){
            JSONObject row=rows.getJSONObject(i),files=row.getJSONObject("files");Map<String,JSONObject> loaded=new LinkedHashMap<String,JSONObject>();
            for(String role:new String[]{"after","workflow","action"}){
                JSONObject entry=files.getJSONObject(role);byte[] raw=Files.readAllBytes(fixtures.resolve(entry.getString("name")));
                String text=new String(raw,StandardCharsets.UTF_8);check(ObservedImeEnter.hash(text).equals(entry.getString("sha256")),"original fixture bytes pinned: "+role);
                loaded.put(role,new JSONObject(text));
            }
            JSONObject workflow=loaded.get("workflow");Map<String,String> hashes=new LinkedHashMap<String,String>();
            JSONObject apk=workflow.getJSONObject("target_apk_sha256");Iterator<String> keys=apk.keys();while(keys.hasNext()){String key=keys.next();hashes.put(key,apk.getString(key));}
            NotesCompletionEvidence.Installed installed=new NotesCompletionEvidence.Installed(workflow.getString("target_package"),workflow.getInt("target_uid"),hashes);
            NotesCreateWorkflow.Observation actual=actualObservationCurrent(loaded.get("after"));
            String body=loaded.get("action").getJSONObject("action").getString("text");
            check(NotesCompletionEvidence.editor(actual.frame,body,installed).matched==row.getBoolean("body_matches"),"unchanged actual capture body verdict: "+row.getString("id"));
            if(!row.getBoolean("body_matches"))check("reopened_full_body_missing".equals(workflow.getString("stop_reason"))&&!workflow.getBoolean("workflow_verified"),"old phone failure remains failed; no fixture body substitution");
            System.out.println("PASS unchanged_phone_fixture_"+row.getString("id"));
        }
        return rows.length();
    }
    public static void main(String[] args)throws Exception{
        java.nio.file.Path envout=null,actualFixtures=null;
        for(int i=0;i<args.length;i++){
            if("--output".equals(args[i])&&i+1<args.length)envout=java.nio.file.Paths.get(args[++i]);
            else if("--actual-fixtures".equals(args[i])&&i+1<args.length)actualFixtures=java.nio.file.Paths.get(args[++i]);
            else throw new IllegalArgumentException("--output DIR [--actual-fixtures PRIVATE_DIR] required");
        }
        if(envout==null)throw new IllegalArgumentException("--output DIR required");
        Files.createDirectories(envout);QualificationScopeHostTest.output=envout;
        List<String> cases=new ArrayList<String>();
        for(String mode:new String[]{"delayed","never","window","duplicate","changed-apk","cancel","cache-false","sdk32","expired"}){
            reopenControllerCase(mode);cases.add(mode);System.out.println("PASS reopen_"+mode);
        }
        int actualCount=actualFixtures==null?0:actualReplay(actualFixtures);
        JSONObject report=new JSONObject().put("passed",true).put("synthetic_android_helper_cases",cases)
                .put("unchanged_actual_phone_fixtures",actualCount).put("actual_fixture_replay_requested",actualFixtures!=null).put("phone_commands",0).put("new_phone_success_claimed",false)
                .put("scope",actualFixtures==null?"actual workflow and controller/service with synthetic Android IO; no private capture replay requested":"actual workflow and controller/service with synthetic Android IO; original failed/success captures replayed unchanged");
        Files.write(envout.resolve("RESULT.json"),report.toString(2).getBytes(StandardCharsets.UTF_8));
    }
}
