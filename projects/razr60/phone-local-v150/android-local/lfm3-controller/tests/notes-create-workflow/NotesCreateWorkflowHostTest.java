package org.trillionnium.hepta.local;

import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Frame;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Node;

/** Real pure workflow/gate classes. Every child IO positive is synthetic.
 * The archived v50 parent proves only create/body and retains its partial result.
 * No JVM invocation here is a phone test or a native inference verification. */
public final class NotesCreateWorkflowHostTest {
    static final String TASK=TaskCompletionGateHostTest.TASK;
    static final String BODY=TaskCompletionGateHostTest.BODY,OWNER=TaskCompletionGateHostTest.OWNER;
    static final String P=NotesCompletionEvidence.NOTES,H=TaskCompletionGateHostTest.H;
    static final String GENERATION="11111111-2222-3333-4444-555555555555";
    static final String FIXTURE_SHA="6ed45e19b8a6f62746c9b7feb79eeba1293f468d17fdc57d46c9b92259da57b6";
    static int checks,serial=1000;
    static final List<String> cases=new ArrayList<String>();
    interface Checked {void run()throws Exception;}
    static void check(boolean good,String why){checks++;if(!good)throw new AssertionError(why);}
    static void refused(Checked work,String why)throws Exception{
        boolean denied=false;try{work.run();}catch(IllegalArgumentException|IllegalStateException expected){denied=true;}
        check(denied,why);
    }
    static void test(String name,Checked work)throws Exception{work.run();cases.add(name);System.out.println("PASS "+name);}
    static String id(){return TaskCompletionGateHostTest.id(++serial);}
    static String hash(String value){return ObservedImeEnter.hash(value);}
    static String nullable(JSONObject o,String key)throws Exception{return o.has(key)&&!o.isNull(key)?o.getString(key):null;}
    static String text(JSONObject o,String key)throws Exception{String v=nullable(o,key);return v==null?"":v;}
    static boolean bool(JSONObject o,String key,boolean absent)throws Exception{return o.has(key)&&!o.isNull(key)?o.getBoolean(key):absent;}
    static Frame domain(Frame f,int display,String generation){return new Frame(f.observationId,f.packageName,f.windowId,display,generation,f.windowType,f.metadataObserved,f.nodesTruncated,f.nodes);}
    static Frame fresh(Frame f){return new Frame(id(),f.packageName,f.windowId,f.displayId,f.backgroundGeneration,f.windowType,f.metadataObserved,f.nodesTruncated,f.nodes);}
    static NotesCreateWorkflow.Observation observed(Frame f){return new NotesCreateWorkflow.Observation(f,H,0);}
    static Frame anotherBody(Frame f){
        List<Node> nodes=new ArrayList<Node>();
        for(Node n:f.nodes)nodes.add(n.editable?TaskCompletionGateHostTest.n(n.id,P,"different old editor body",n.viewId,n.bounds(),true,true,false):n);
        return new Frame(id(),f.packageName,f.windowId,f.displayId,f.backgroundGeneration,f.windowType,f.metadataObserved,f.nodesTruncated,nodes);
    }
    static Frame duplicateList(Frame f){
        List<Node> nodes=new ArrayList<Node>(f.nodes);Node a=f.nodes.get(0);
        nodes.add(new Node("n9",a.packageName,a.text,a.label,a.viewId,a.inputTextSha256,new int[]{10,400,600,550},false,true,false,true,false));
        return new Frame(id(),f.packageName,f.windowId,f.displayId,f.backgroundGeneration,f.windowType,f.metadataObserved,f.nodesTruncated,nodes);
    }
    static final class Parent {
        final String task,owner,body;
        final TaskAuthorization authorization;final TaskAuthorization.Gate auth;
        final TaskCompletionGate completion;final NotesCompletionEvidence.Installed installed;
        final int display;final String generation;
        Frame before,created;ActionDecision action;String run;Map<String,Object> fixed;
        Parent(int display,String generation)throws Exception{this(TASK,OWNER,BODY,display,generation);}
        Parent(String task,String owner,String body,int display,String generation)throws Exception{
            this.task=task;this.owner=owner;this.body=body;this.display=display;this.generation=generation;
            authorization=TaskAuthorization.parse(owner);auth=authorization.bind(task);
            completion=new TaskCompletionGate(task,owner,authorization);
            installed=new NotesCompletionEvidence.Installed(P,10382,Collections.singletonMap("base",H));completion.bindInstalled(installed);
        }
        Frame editor(){return domain(TaskCompletionGateHostTest.editor(),display,generation);}
        Frame list(){return domain(TaskCompletionGateHostTest.listing(),display,generation);}
        void prepare()throws Exception{
            before=domain(TaskCompletionGateHostTest.initial(),display,generation);created=editor();run=id();
            action=TaskCompletionGateHostTest.action(before,"notes.create",body,null);
            fixed=TaskCompletionGateHostTest.fixed(before,action,run);
            if(!task.equals(TASK))throw new IllegalStateException("synthetic fixed helper is intentionally TASK-bound");
        }
        void launch()throws Exception{prepare();completion.action(1,run,action,true,true,false,before,created,fixed);}
        NotesCreateWorkflow.Grant mint(){return completion.notesCreateWorkflow(1,run,action,observed(created),auth.frame());}
    }
    static final class FakeIO implements NotesCreateWorkflow.IO {
        final NotesCreateWorkflow.Grant grant;final List<NotesCreateWorkflow.Observation> reads;
        final List<NotesCreateWorkflow.ChildCall> calls=new ArrayList<NotesCreateWorkflow.ChildCall>();
        final List<NotesCreateWorkflow.ChildRecord> records=new ArrayList<NotesCreateWorkflow.ChildRecord>();
        final List<String> checkpoints=new ArrayList<String>();
        final Map<String,Map<String,Object>> checkpointValues=new LinkedHashMap<String,Map<String,Object>>();
        int observations,effects;String defect="",cancelAt;int cancelRead=-1;
        FakeIO(NotesCreateWorkflow.Grant grant,NotesCreateWorkflow.Observation... reads){this.grant=grant;this.reads=Arrays.asList(reads);}
        public NotesCreateWorkflow.Observation observe(){
            observations++;
            if(observations==cancelRead)throw new IllegalStateException("synthetic cancellation at read");
            check(observations<=reads.size(),"bounded workflow must not request an invented extra observation");
            return reads.get(observations-1);
        }
        public void checkpoint(String name,Map<String,Object> proof){
            check(!checkpoints.contains(name),"a durable workflow checkpoint is once only");
            checkpoints.add(name);checkpointValues.put(name,new LinkedHashMap<String,Object>(proof));
            if(name.equals(cancelAt))throw new IllegalStateException("synthetic cancellation before effect");
        }
        public NotesCreateWorkflow.Dispatch dispatch(NotesCreateWorkflow.ChildCall child,NotesCreateWorkflow.Observation before){
            check(checkpoints.contains("grant-consumed")&&checkpoints.contains("child-"+child.ordinal+"-planned"),"durable parent/child checkpoint precedes effect");
            check(child.ordinal==calls.size()+1&&child.observationId.equals(before.frame.observationId),"monotonic actual child/current observation");
            ActionDecision d=child.decision();
            check(d.toolChildOrigin==child&&ActionDecision.TOOL_CHILD_SCHEMA.equals(d.actionSchema),"child has internal origin, never a parsed model decision");
            String task="wrong-task".equals(defect)?TaskCompletionGateHostTest.id(991):grant.taskId;
            String auth="wrong-owner".equals(defect)?hash("foreign authorization"):grant.authorizationSha256;
            String run="wrong-run".equals(defect)?TaskCompletionGateHostTest.id(992):grant.parentRunId;
            String observation="wrong-observation".equals(defect)?TaskCompletionGateHostTest.id(993):child.observationId;
            child.enterService(task,auth,run,observation);
            child.requireDispatch(grant.taskId,grant.authorizationSha256,grant.parentRunId,d);
            calls.add(child);if(!"not-dispatched".equals(defect))effects++;
            Map<String,Object> proof=child.evidence();
            if("proof-other-child".equals(defect))proof.put("child_id",hash("borrowed child"));
            if("proof-retired".equals(defect))proof.put("grant_retired",true);
            if("proof-model".equals(defect))proof.put("model_issued",true);
            if(defect.startsWith("proof-field:")){
                String key=defect.substring("proof-field:".length());Object old=proof.get(key);
                if(old instanceof Number)proof.put(key,((Number)old).intValue()+1);
                else if(old instanceof Boolean)proof.put(key,!((Boolean)old));
                else if(old instanceof Map)proof.put(key,Collections.singletonMap("base",hash("different APK")));
                else proof.put(key,"different original identity");
            }
            return new NotesCreateWorkflow.Dispatch(!"not-accepted".equals(defect),!"not-dispatched".equals(defect),
                    "stale".equals(defect),"synthetic service IO",!"lease-lost".equals(defect),"no-proof".equals(defect)?null:proof);
        }
        public void recorded(NotesCreateWorkflow.ChildRecord row){records.add(row);}
    }
    static NotesCreateWorkflow.Result run(Parent p,FakeIO io)throws Exception{return NotesCreateWorkflow.run(io.grant,observed(p.created),io);}
    static void assertRejected(Parent p,FakeIO io,NotesCreateWorkflow.Result result,String why)throws Exception{
        check(!result.completeFor(io.grant)&&Boolean.FALSE.equals(result.evidence().get("workflow_verified")),why);
        check(!p.completion.notesCreateWorkflowCompleted(result,result.current.frame),"rejected child sequence cannot advance completion");
        check(!p.completion.controllerWorkflowReady(result.current.frame),"rejected sequence cannot request controller success");
        check(Boolean.TRUE.equals(io.grant.evidence().get("grant_retired")),"all paths retire the one-use grant");
    }
    static void positive(int display,String generation,int backs)throws Exception{
        Parent p=new Parent(display,generation);p.launch();NotesCreateWorkflow.Grant grant=p.mint();check(grant!=null,"exact parent create/body mints supported grant");
        check(grant.createdObservationId.equals(p.created.observationId)&&grant.workflowInitialObservationId.equals(p.created.observationId),"immediate path preserves identical parent-after and workflow initial identities");
        Frame editor=fresh(p.created),list=p.list(),reopened=p.editor(),stable=fresh(reopened);
        List<NotesCreateWorkflow.Observation> reads=new ArrayList<NotesCreateWorkflow.Observation>();
        reads.add(observed(backs==0?list:editor));if(backs==2)reads.add(observed(fresh(editor)));if(backs>0)reads.add(observed(list));
        reads.add(observed(reopened));reads.add(observed(stable));
        FakeIO io=new FakeIO(grant,reads.toArray(new NotesCreateWorkflow.Observation[0]));NotesCreateWorkflow.Result result=run(p,io);
        check(result.completeFor(grant)&&io.effects==backs+1&&io.observations==backs+3,"only bounded observed Back/list/same-item/reopen/stable sequence completes");
        check(io.calls.get(io.calls.size()-1).action.equals("click")&&io.calls.get(io.calls.size()-1).nodeId.equals("n0"),"click exact currently observed unique item");
        check(p.completion.notesCreateWorkflowCompleted(result,stable),"real pure gate accepts synthetic proven child chain");
        check(p.completion.controllerWorkflowReady(stable)&&p.completion.verified(stable),"controller eligibility only on consumed same stable frame");
        check(!p.completion.controllerWorkflowReady(fresh(stable)),"equivalent-looking foreign observation ID is not the recorded stable readback");
        check("tool_child".equals(p.completion.evidence(stable).get("reopen_actor_kind")),"reopen actor is not falsely attributed to the model");
        check(Boolean.FALSE.equals(result.evidence().get("model_issued"))&&Boolean.FALSE.equals(result.evidence().get("model_done_synthesized")),"no model decision or done is synthesized");
        check("draft_opened".equals(result.evidence().get("fixed_intent_outcome_unchanged")),"fixed intent does not become a save API");
        check(Boolean.FALSE.equals(result.evidence().get("persistent_storage_bytes_verified")),"no database byte claim");
        refused(()->p.completion.notesCreateWorkflowCompleted(result,stable),"result is consumed once");
        refused(()->NotesCreateWorkflow.run(grant,observed(p.created),io),"same grant cannot replay children");
        NotesCreateWorkflow.ChildCall child=io.calls.get(0);
        refused(()->child.enterService(grant.taskId,grant.authorizationSha256,grant.parentRunId,child.observationId),"completed child cannot re-enter service");
        refused(()->child.requireDispatch(grant.taskId,grant.authorizationSha256,grant.parentRunId,child.decision()),"retired child cannot dispatch");
        check(io.effects==backs+1,"refusal never replays effects");
    }
    static void parentAndAuthority()throws Exception{
        for(String mode:Arrays.asList("not-accepted","not-dispatched","stale","no-fixed","wrong-run","wrong-payload")){
            Parent p=new Parent(0,null);p.prepare();Map<String,Object> fixed=new LinkedHashMap<String,Object>(p.fixed);
            if(mode.equals("wrong-run"))fixed.put("model_run_id",id());if(mode.equals("wrong-payload"))fixed.put("payload_sha256",hash("other body"));
            p.completion.action(1,p.run,p.action,!mode.equals("not-accepted"),!mode.equals("not-dispatched"),mode.equals("stale"),p.before,p.created,mode.equals("no-fixed")?null:fixed);
            check(p.mint()==null,"unverified actual parent cannot mint: "+mode);
        }
        Parent p=new Parent(0,null);p.launch();
        check(p.completion.notesCreateWorkflow(1,p.run,p.action,observed(p.created),p.authorization.bind(id()).frame())==null,"foreign task authorization frame refused");
        check(p.completion.notesCreateWorkflow(1,p.run,p.action,observed(p.created),TaskAuthorization.parse(OWNER).bind(TASK).frame())==null,"a separate authorization object cannot borrow the task capability");
        check(p.completion.notesCreateWorkflow(1,id(),p.action,observed(p.created),p.auth.frame())==null,"foreign parent run refused");
        check(p.completion.notesCreateWorkflow(2,p.run,p.action,observed(p.created),p.auth.frame())==null,"foreign parent ordinal refused");
        check(p.completion.notesCreateWorkflow(1,p.run,p.action,observed(fresh(p.created)),p.auth.frame())==null,"foreign created observation refused");
        check(p.mint()!=null&&p.mint()==null,"one parent can mint at most one workflow");
        refused(()->TaskAuthorization.parse("请只打开笔记草稿，不要保存。"),"malformed only-tool restriction remains strictly rejected");
        for(String owner:Arrays.asList("只允许 notes.create、等待和结束。"+OWNER,TaskCompletionGateHostTest.DRAFT_OWNER,"读出当前页面标题，不要点击或输入。")){
            TaskAuthorization auth=TaskAuthorization.parse(owner);TaskCompletionGate gate=new TaskCompletionGate(TASK,owner,auth);
            check(!gate.notesCreateWorkflowRequested(auth.bind(TASK).frame()),"unknown/draft/restricted owner does not acquire child authority");
        }
    }
    static void noAckAndWrongIdentities()throws Exception{
        List<String> negatives=new ArrayList<String>(Arrays.asList("not-accepted","not-dispatched","stale","lease-lost","no-proof","proof-other-child","proof-retired","proof-model"));
        for(String field:Arrays.asList("parent_observation_id","created_observation_id","parent_create_after_observation_id","workflow_initial_observation_id","parent_step","child_ordinal","owner_sha256",
                "task_authorization_sha256","contract_sha256","body_sha256","target_package","target_uid","target_apk_sha256",
                "display_id","background_generation","grants_tool_authority","parent_model_run_id","parent_fixed_intent_attempt_id"))negatives.add("proof-field:"+field);
        for(String defect:negatives){
            Parent p=new Parent(11,GENERATION);p.launch();FakeIO io=new FakeIO(p.mint(),observed(fresh(p.created)));io.defect=defect;
            NotesCreateWorkflow.Result r=run(p,io);assertRejected(p,io,r,defect+" cannot count as a completed child");
            check(io.calls.size()==1&&io.observations==1&&io.records.size()==1&&io.records.get(0).after==null,"failed dispatched child is not retried/reobserved as success: "+defect);
        }
        for(String defect:Arrays.asList("wrong-task","wrong-owner","wrong-run","wrong-observation")){
            Parent p=new Parent(11,GENERATION);p.launch();FakeIO io=new FakeIO(p.mint(),observed(fresh(p.created)));io.defect=defect;
            refused(()->run(p,io),"service identity mismatch fails before effect: "+defect);
            check(io.effects==0&&Boolean.TRUE.equals(io.grant.evidence().get("grant_retired")),"wrong service identity retires grant with no effect");
        }
    }
    static void navigationAndStability()throws Exception{
        for(String mode:Arrays.asList("old-editor","foreign-display","foreign-generation","wrong-package","truncated","duplicate-list")){
            Parent p=new Parent(11,GENERATION);p.launch();Frame next=p.created;
            if(mode.equals("old-editor"))next=anotherBody(next);
            if(mode.equals("foreign-display"))next=domain(next,12,GENERATION);
            if(mode.equals("foreign-generation"))next=domain(next,11,"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
            if(mode.equals("wrong-package"))next=new Frame(id(),"com.android.settings",7,11,GENERATION,1,true,false,next.nodes);
            if(mode.equals("truncated"))next=new Frame(id(),P,7,11,GENERATION,1,true,true,next.nodes);
            if(mode.equals("duplicate-list"))next=duplicateList(p.list());
            FakeIO io=new FakeIO(p.mint(),observed(next));NotesCreateWorkflow.Result r=run(p,io);
            assertRejected(p,io,r,"fresh unsupported surface cannot be navigated: "+mode);check(io.effects==0,"no guessed effect on unsupported current surface");
        }
        Parent stuck=new Parent(0,null);stuck.launch();
        FakeIO noList=new FakeIO(stuck.mint(),observed(fresh(stuck.created)),observed(fresh(stuck.created)),observed(fresh(stuck.created)));
        NotesCreateWorkflow.Result stopped=run(stuck,noList);assertRejected(stuck,noList,stopped,"two Back calls alone never prove saved/list/reopened");
        check(noList.effects==2&&noList.calls.stream().allMatch(c->c.action.equals("back")),"hard bound is two actual Back, no blind third or click");
        for(String defect:Arrays.asList("tree","rotation","window","body","display","generation")){
            Parent p=new Parent(11,GENERATION);p.launch();Frame list=p.list(),reopened=p.editor(),stable=fresh(reopened);
            String tree=defect.equals("tree")?hash("changed tree"):H;int rotation=defect.equals("rotation")?1:0;
            if(defect.equals("window"))stable=new Frame(stable.observationId,P,999,11,GENERATION,1,true,false,stable.nodes);
            if(defect.equals("body"))stable=anotherBody(stable);
            if(defect.equals("display"))stable=domain(stable,12,GENERATION);
            if(defect.equals("generation"))stable=domain(stable,11,"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
            FakeIO io=new FakeIO(p.mint(),observed(list),observed(reopened),new NotesCreateWorkflow.Observation(stable,tree,rotation));
            NotesCreateWorkflow.Result r=run(p,io);assertRejected(p,io,r,"unstable or foreign final readback refused: "+defect);check(io.effects==1,"failed stable verification does not repeat click");
        }
    }
    static void cancelReuseAndCollision()throws Exception{
        for(String point:Arrays.asList("grant-consumed","child-1-planned")){
            Parent p=new Parent(0,null);p.launch();FakeIO io=new FakeIO(p.mint(),observed(fresh(p.created)));io.cancelAt=point;
            refused(()->run(p,io),"synthetic cancellation propagates before effect");
            check(io.effects==0&&Boolean.TRUE.equals(io.grant.evidence().get("grant_retired")),"cancelled grant retires without automatic dispatch");
        }
        Parent p=new Parent(0,null);p.launch();FakeIO cancelled=new FakeIO(p.mint(),observed(fresh(p.created)));cancelled.cancelRead=2;
        refused(()->run(p,cancelled),"cancel during after-read does not invent acknowledgement");
        check(cancelled.effects==1&&cancelled.records.isEmpty(),"one effect retained; no fake after/next child");
        for(String surface:Arrays.asList("editor","list","duplicate-list")){
            Parent collision=new Parent(0,null);collision.prepare();
            collision.before=surface.equals("editor")?collision.editor():surface.equals("list")?collision.list():duplicateList(collision.list());
            collision.action=TaskCompletionGateHostTest.action(collision.before,"notes.create",BODY,null);
            collision.fixed=TaskCompletionGateHostTest.fixed(collision.before,collision.action,collision.run);
            collision.completion.action(1,collision.run,collision.action,true,true,false,collision.before,collision.created,collision.fixed);
            check(collision.mint()==null&&!collision.completion.verified(collision.created),"visible same-body predecessor cannot mint or complete: "+surface);
            check(Boolean.TRUE.equals(collision.completion.evidence(collision.created).get("prior_visible_body_collision")),"collision fact retained without guessing database uniqueness");
        }
        Parent a=new Parent(0,null),b=new Parent(0,null);a.launch();b.launch();
        Frame list=a.list(),reopened=a.editor(),stable=fresh(reopened);FakeIO io=new FakeIO(a.mint(),observed(list),observed(reopened),observed(stable));
        NotesCreateWorkflow.Result result=run(a,io);check(b.mint()!=null,"second explicit test task gate has its own different grant");
        refused(()->b.completion.notesCreateWorkflowCompleted(result,stable),"equal-shaped but different grant object cannot borrow child result");
        a.completion.invalidateInstalled("synthetic identity changed");
        check(!a.completion.notesCreateWorkflowCompleted(result,stable)&&!a.completion.controllerWorkflowReady(stable),"post-workflow actual installed identity failure removes completion");
    }

    static Map<String,Object> objectMap(JSONObject o)throws Exception{
        Map<String,Object> out=new LinkedHashMap<String,Object>();Iterator<String> keys=o.keys();
        while(keys.hasNext()){String key=keys.next();Object v=o.get(key);if(v==null||v==JSONObject.NULL)v=null;else if(v instanceof JSONObject)v=objectMap((JSONObject)v);out.put(key,v);}return out;
    }
    /** Reconstruct only the fully retained source parts whose raw text hashes can
     * be proved from this fixture. No synthetic labels or source hashes enter it. */
    static ObservedChildText.Result child(JSONObject n)throws Exception{
        String status=text(n,"child_text_status");if(status.isEmpty()||status.equals("not_applicable"))return ObservedChildText.notApplicable();
        if(!status.equals("derived"))return new ObservedChildText.Result("",status,bool(n,"child_text_truncated",false),n.getInt("child_text_visited"),Collections.<ObservedChildText.Source>emptyList());
        check(!n.getBoolean("child_text_truncated")&&n.getBoolean("child_text_sources_complete"),"fixture derived text has complete actual sources");
        String label=n.getString("child_text");String[] parts=label.split(" · ",-1);JSONArray source=n.getJSONArray("child_text_sources");
        check(parts.length==source.length(),"each full label component has one exact source");
        List<ObservedChildText.Source> sources=new ArrayList<ObservedChildText.Source>();List<int[]> spans=new ArrayList<int[]>();int offset=0;
        for(int i=0;i<parts.length;i++){
            JSONObject s=source.getJSONObject(i);check(hash(parts[i]).equals(s.getString("text_sha256")),"full original child bytes independently match their source SHA");
            sources.add(new ObservedChildText.Source(s.getString("descendant_path"),s.getString("property"),parts[i],s.getString("node_signature"),s.getString("view_id")));
            spans.add(new int[]{offset,offset+parts[i].length()});offset+=parts[i].length()+3;
        }
        Constructor<ObservedChildText.Result> c=ObservedChildText.Result.class.getDeclaredConstructor(String.class,String.class,boolean.class,int.class,List.class,List.class,String.class,boolean.class);c.setAccessible(true);
        ObservedChildText.Result r=c.newInstance(label,status,false,n.getInt("child_text_visited"),sources,spans,n.getString("child_text_root_signature"),true);
        check(r.bind(r.rootSignature).equals(n.getString("node_app_tree_sha256")),"actual root/source fingerprint rebinds the original node signature");return r;
    }
    static NotesCreateWorkflow.Observation actualObservation(JSONObject o)throws Exception{
        List<Node> nodes=new ArrayList<Node>();JSONArray all=o.getJSONArray("nodes");
        for(int i=0;i<all.length();i++){
            JSONObject n=all.getJSONObject(i);JSONArray b=n.getJSONArray("bounds");ObservedChildText.Result child=child(n);
            String text=text(n,"text"),description=text(n,"description"),label=ObservedChildText.displayLabel(text,description,child);
            if(text.trim().isEmpty()&&description.trim().isEmpty()&&(child.truncated||!child.status.equals("derived")))label="";
            nodes.add(new Node(n.getString("id"),n.getString("package"),text,label,text(n,"view_id"),nullable(n,"input_text_sha256"),new int[]{((Number)b.get(0)).intValue(),((Number)b.get(1)).intValue(),((Number)b.get(2)).intValue(),((Number)b.get(3)).intValue()},bool(n,"editable",false),bool(n,"clickable",false),bool(n,"scrollable",false),bool(n,"enabled",true),bool(n,"password",false),child,nullable(n,"node_app_tree_sha256")));
        }
        JSONObject w=o.getJSONObject("window"),bg=o.getJSONObject("background_session");
        Frame frame=new Frame(o.getString("observation_id"),o.getString("package"),o.getInt("window_id"),w.getInt("display_id"),bg.getString("generation"),w.getInt("type"),w.getString("metadata_status").equals("observed"),o.getBoolean("nodes_truncated"),nodes);
        return new NotesCreateWorkflow.Observation(frame,o.getString("app_tree_sha256"),o.getInt("rotation"));
    }
    static void realParentOnly(Path fixture)throws Exception{
        byte[] bytes=Files.readAllBytes(fixture);check(hash(new String(bytes,StandardCharsets.UTF_8)).equals(FIXTURE_SHA),"exact immutable real-parent fixture bytes");
        JSONObject f=new JSONObject(new String(bytes,StandardCharsets.UTF_8));JSONArray records=f.getJSONArray("records");Map<String,JSONObject> raw=new LinkedHashMap<String,JSONObject>();
        check(records.length()==8,"eight explicitly indexed original raw files");
        for(int i=0;i<records.length();i++){
            JSONObject row=records.getJSONObject(i);String name=row.getString("path"),source=row.getString("raw_utf8");
            check(source.getBytes(StandardCharsets.UTF_8).length==row.getInt("bytes")&&hash(source).equals(row.getString("sha256"))&&!raw.containsKey(name),"raw original bytes and unique member identity: "+name);
            raw.put(name,new JSONObject(source));
        }
        JSONObject owner=raw.get("evidence/task/owner.json"),action=raw.get("evidence/task/step-01-action.json"),after=raw.get("evidence/task/step-01-after.json"),terminal=raw.get("evidence/task/result.json"),installed=raw.get("evidence/task/completion-installed-identity.json");
        JSONObject decision=action.getJSONObject("action");String task=owner.getString("task_id"),instruction=owner.getString("instruction"),body=decision.getString("text"),run=action.getString("model_run_id");
        check("459bed75947f44599bea8f4b0fece4e5".equals(task)&&"partial".equals(terminal.getString("status"))&&terminal.getInt("steps")==2&&!terminal.getBoolean("completion_verified"),"real v50 terminal remains partial2, never rewritten as workflow success");
        check(action.getBoolean("model_issued")&&action.getBoolean("accepted")&&action.getBoolean("dispatched")&&!action.getBoolean("stale")&&"notes.create".equals(decision.getString("action")),"archived real accepted model parent, not an invented child");
        check(objectMap(raw.get("evidence/runs/7e3e682d8c764925bdd889d929b39a57/raw-text.txt")).equals(objectMap(decision)),"raw native choice exactly equals recorded parent decision");
        TaskAuthorization auth=TaskAuthorization.parse(instruction);TaskCompletionGate gate=new TaskCompletionGate(task,instruction,auth);
        Map<String,String> apks=new LinkedHashMap<String,String>();apks.put("base",installed.getJSONObject("apk_hashes").getString("base"));
        gate.bindInstalled(new NotesCompletionEvidence.Installed(installed.getString("package"),installed.getInt("uid"),apks));
        NotesCreateWorkflow.Observation before=actualObservation(raw.get("evidence/task/step-01-before.json")),created=actualObservation(after);
        check(created.frame.displayId==11&&"3be5dca4-0edb-4131-bd9d-84e8bf73d0b7".equals(created.frame.backgroundGeneration),"actual owned nonzero display/generation retained");
        ActionDecision parent=ActionDecision.parse(decision.toString(),ActionDecision.FIXED_INTENT_ACTION_SCHEMA);
        gate.action(1,run,parent,true,true,false,before.frame,created.frame,objectMap(action.getJSONObject("fixed_intent")));
        NotesCreateWorkflow.Grant grant=gate.notesCreateWorkflow(1,run,parent,created,auth.bind(task).frame());
        check(grant!=null&&body.equals(gate.contract.body)&&grant.displayId==11,"the actual create and full-body facts meet only the new workflow trigger");
        check(!gate.verified(created.frame)&&!gate.controllerWorkflowReady(created.frame),"actual parent alone is still not saved/reopened completion");
        FakeIO noPhone=new FakeIO(grant);noPhone.cancelAt="grant-consumed";
        refused(()->NotesCreateWorkflow.run(grant,created,noPhone),"real fixture replay stops before any child observation/effect");
        check(noPhone.effects==0&&noPhone.observations==0,"no real child positive is fabricated from the old partial run");
    }

    /** Synthetic delayed provider data uses the real completion gate. The
     * initial after remains the parent source; no successful child is inferred. */
    static Parent pendingEditor()throws Exception{
        Parent p=new Parent(11,GENERATION);p.prepare();
        List<Node> nodes=new ArrayList<Node>();for(Node n:p.created.nodes)if(!n.editable)nodes.add(n);
        p.created=new Frame(p.created.observationId,P,p.created.windowId,11,GENERATION,1,true,false,nodes);
        p.completion.action(1,p.run,p.action,true,true,false,p.before,p.created,p.fixed);
        check(p.completion.notesPhase(p.created).launchProved&&!p.completion.notesPhase(p.created).currentBody,
                "actual synthetic create is recorded while its first after has no editable body");
        return p;
    }
    static NotesCreateWorkflow.Grant readyGrant(Parent p,List<NotesCreateWorkflow.Observation> reads,long start,long end){
        if(reads!=null&&!reads.isEmpty())p.completion.observed(reads.get(reads.size()-1).frame);
        return p.completion.notesCreateWorkflowAfterReadiness(1,p.run,p.action,reads,p.auth.frame(),start,end);
    }
    static void delayedEditorPositive()throws Exception{
        Parent p=pendingEditor();Frame initial=p.created,ready=fresh(p.editor());
        check(p.mint()==null,"original immediate-after guard still refuses a missing body");
        List<NotesCreateWorkflow.Observation> reads=Arrays.asList(observed(initial),observed(ready));
        NotesCreateWorkflow.Grant grant=readyGrant(p,reads,1000,1400);
        check(grant!=null&&grant.createdObservationId.equals(initial.observationId)&&grant.workflowInitialObservationId.equals(ready.observationId),
                "original create-after is retained while the distinct later frame consumes readiness");
        check(initial.observationId.equals(grant.evidence().get("created_observation_id"))
                &&initial.observationId.equals(grant.evidence().get("parent_create_after_observation_id"))
                &&ready.observationId.equals(grant.evidence().get("workflow_initial_observation_id")),
                "serialized grant never relabels the ready frame as original model after");
        check(p.created==initial&&!p.completion.verified(ready),"first after remains unchanged and ready body alone is not saved/reopened");
        Frame list=p.list(),reopened=p.editor(),stable=fresh(reopened);
        FakeIO io=new FakeIO(grant,observed(list),observed(reopened),observed(stable));
        NotesCreateWorkflow.Result result=NotesCreateWorkflow.run(grant,observed(ready),io);
        check(p.completion.notesCreateWorkflowCompleted(result,stable)&&p.completion.controllerWorkflowReady(stable),
                "original list/click/reopen/stable proof remains necessary after delayed readiness");
        boolean found=false;Object proofRows=p.completion.evidence(stable).get("proofs");
        for(Object value:(List<?>)proofRows){
            Map<?,?> proof=(Map<?,?>)value;
            if("notes_created_editor_readiness".equals(proof.get("kind"))){
                found=true;check(initial.observationId.equals(proof.get("original_create_after_observation_id"))
                        &&Boolean.TRUE.equals(proof.get("original_create_after_unchanged"))
                        &&ready.observationId.equals(proof.get("workflow_initial_observation_id")),"proof distinguishes the original first after and later body");
            }
        }
        check(found,"bounded read evidence is retained separately");
    }
    static void delayedEditorBindings()throws Exception{
        for(String field:Arrays.asList("created_observation_id","parent_create_after_observation_id","workflow_initial_observation_id")){
            Parent p=pendingEditor();Frame ready=fresh(p.editor());
            NotesCreateWorkflow.Grant grant=readyGrant(p,Arrays.asList(observed(p.created),observed(ready)),1000,1200);
            check(grant!=null,"delayed synthetic parent grants before callback corruption");
            FakeIO io=new FakeIO(grant,observed(fresh(ready)));io.defect="proof-field:"+field;
            NotesCreateWorkflow.Result result=NotesCreateWorkflow.run(grant,observed(ready),io);
            assertRejected(p,io,result,"delayed child cannot replace either original-after or workflow-initial identity: "+field);
            check(io.calls.size()==1&&io.observations==1&&io.records.get(0).after==null,
                    "actual consumed delayed grant refuses corrupted child receipt before another observation");
        }
        for(String defect:Arrays.asList("first-id","first-source","duplicate","window","rotation","display","generation",
                "package","truncated","body","count-one","count-five","expired","backwards","negative-time","intervening-action","installed")){
            Parent p=pendingEditor();Frame first=p.created,ready=fresh(p.editor());
            List<NotesCreateWorkflow.Observation> reads=new ArrayList<NotesCreateWorkflow.Observation>();
            long start=1000,end=1400;
            if(defect.equals("first-id"))first=fresh(first);
            if(defect.equals("first-source"))first=new Frame(first.observationId,P,first.windowId,11,GENERATION,1,true,false,Collections.<Node>emptyList());
            if(defect.equals("duplicate"))ready=new Frame(first.observationId,P,first.windowId,11,GENERATION,1,true,false,ready.nodes);
            if(defect.equals("window"))ready=new Frame(ready.observationId,P,99,11,GENERATION,1,true,false,ready.nodes);
            if(defect.equals("display"))ready=domain(ready,12,GENERATION);
            if(defect.equals("generation"))ready=domain(ready,11,"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
            if(defect.equals("package"))ready=new Frame(ready.observationId,"com.android.settings",ready.windowId,11,GENERATION,1,true,false,ready.nodes);
            if(defect.equals("truncated"))ready=new Frame(ready.observationId,P,ready.windowId,11,GENERATION,1,true,true,ready.nodes);
            if(defect.equals("body"))ready=anotherBody(ready);
            reads.add(observed(first));reads.add(new NotesCreateWorkflow.Observation(ready,H,defect.equals("rotation")?1:0));
            if(defect.equals("count-one"))reads.remove(1);
            if(defect.equals("count-five"))while(reads.size()<5)reads.add(observed(fresh(ready)));
            if(defect.equals("expired"))end=start+TaskCompletionGate.NOTES_EDITOR_READINESS_MS+1;
            if(defect.equals("backwards"))end=start-1;
            if(defect.equals("negative-time"))start=-1;
            if(defect.equals("installed"))p.completion.invalidateInstalled("synthetic APK changed");
            if(defect.equals("intervening-action")){
                ActionDecision wait=ActionDecision.parse(new JSONObject().put("reason","synthetic actual intervening model wait")
                        .put("action","wait").put("package",P).put("observation_id",p.created.observationId).put("duration_ms",100).toString(),ActionDecision.FIXED_INTENT_ACTION_SCHEMA);
                p.completion.action(2,id(),wait,true,true,false,p.created,p.created,null);
            }
            check(readyGrant(p,reads,start,end)==null,"delayed readiness rejects "+defect);
            check(!p.completion.controllerWorkflowReady(ready),"rejected readiness never requests success");
        }
        Parent p=pendingEditor();Frame ready=fresh(p.editor());p.completion.observed(ready);
        List<NotesCreateWorkflow.Observation> reads=Arrays.asList(observed(p.created),observed(ready));
        check(p.completion.notesCreateWorkflowAfterReadiness(1,id(),p.action,reads,p.auth.frame(),1000,1200)==null,"wrong native run rejected");
        check(p.completion.notesCreateWorkflowAfterReadiness(2,p.run,p.action,reads,p.auth.frame(),1000,1200)==null,"wrong parent step rejected");
        check(p.completion.notesCreateWorkflowAfterReadiness(1,p.run,p.action,reads,p.authorization.bind(id()).frame(),1000,1200)==null,"foreign task authorization rejected");
        NotesCreateWorkflow.Grant grant=readyGrant(p,reads,1000,1200);check(grant!=null,"correct live task can bind once after refusals");
        check(readyGrant(p,reads,1000,1200)==null,"readiness cannot mint twice");
        FakeIO io=new FakeIO(grant);
        refused(()->NotesCreateWorkflow.run(grant,observed(p.created),io),"old first-after credential cannot authorize children on the ready frame");
        check(io.effects==0&&io.observations==0,"wrong initial frame fails before any child IO");
    }
    static void pendingEditorPhase()throws Exception{
        Parent p=pendingEditor();NotesTaskPhaseGuard guard=new NotesTaskPhaseGuard(p.task,p.authorization);
        NotesTaskPhaseGuard.Projection phase=guard.prepare(p.completion,p.created);
        check("await_created_editor".equals(phase.phase)&&phase.toolMask().equals(new java.util.TreeSet<String>(Arrays.asList("wait","done"))),
                "missing created body exposes only read/wait and honest ending");
        check(phase.openPackages(Collections.singleton(P)).isEmpty()&&phase.scrolls(Collections.singletonMap("n0",ObservedScrollActions.observed(Arrays.asList("forward")))).isEmpty(),
                "missing-body phase cannot relaunch or scroll the editor");
        Map<String,org.trillionnium.hepta.background.FixedIntentTarget> fixed=new LinkedHashMap<String,org.trillionnium.hepta.background.FixedIntentTarget>();
        fixed.put("notes.create",new org.trillionnium.hepta.background.FixedIntentTarget("notes.create","Moto",10382,null));
        check(phase.fixedTargets(fixed).isEmpty(),"actual recorded create is never reissued while waiting for its body");
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=2)throw new IllegalArgumentException("fixture path and new output directory required");
        Path fixture=Paths.get(args[0]),out=Paths.get(args[1]);Files.createDirectories(out);
        test("real_v50_create_body_trigger_does_not_promote_partial",()->realParentOnly(fixture));
        test("synthetic_one_back_current_item_stable_foreground",()->positive(0,null,1));
        test("synthetic_two_back_current_item_stable_owned_display",()->positive(11,GENERATION,2));
        test("synthetic_fresh_unique_list_without_guessed_back",()->positive(11,GENERATION,0));
        test("parent_native_action_authority_and_single_grant",()->parentAndAuthority());
        test("child_noack_stale_callback_and_service_identity",()->noAckAndWrongIdentities());
        test("current_domain_unique_list_navigation_bound_and_stability",()->navigationAndStability());
        test("cancellation_grant_reuse_visible_collision_and_installed_change",()->cancelReuseAndCollision());
        test("delayed_editor_preserves_first_after_and_requires_original_save_chain",()->delayedEditorPositive());
        test("delayed_editor_read_source_time_task_window_and_action_fences",()->delayedEditorBindings());
        test("await_created_editor_readonly_phase_never_recreates",()->pendingEditorPhase());
        JSONObject result=new JSONObject().put("all_pass",true).put("checks",checks).put("cases",cases)
                .put("actual_parent_fixture_sha256",FIXTURE_SHA).put("all_child_positive_io_synthetic",true)
                .put("real_parent_terminal_unchanged","partial").put("native_runtime_reverified",false).put("phone_tested",false);
        Files.write(out.resolve("RESULT.json"),result.toString(2).getBytes(StandardCharsets.UTF_8));
        System.out.println("NotesCreateWorkflowHostTest checks="+checks);
    }
}
