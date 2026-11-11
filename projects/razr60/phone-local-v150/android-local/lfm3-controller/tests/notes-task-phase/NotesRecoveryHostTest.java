package org.trillionnium.hepta.local;

import android.graphics.Rect;
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
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
import java.util.Set;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.FixedIntentTarget;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Frame;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Node;

/** Production phase/prompt/grammar/dispatch checks. Default IO is synthetic.
 * Optional externally pinned v46 inputs replay only the failed historical prefix;
 * the recovery continuation is synthetic model/observation IO, never phone proof.
 * No reflection sets completion facts or changes recorded card/leaf capabilities. */
public final class NotesRecoveryHostTest {
    private static final String P=NotesCompletionEvidence.NOTES,H="org.trillionnium.hepta.local";
    private static final LocalRuntimeConfig CONFIG=new LocalRuntimeConfig(ModelProfile.GEMMA4_E4B,"npu",8192,4);
    private static int checks,sequence=8000;
    private static final List<Object> grammarCases=new ArrayList<Object>();
    private static final Map<String,String> readInputs=new LinkedHashMap<String,String>();
    private interface Call {void run()throws Exception;}
    private static void check(boolean ok,String why){checks++;if(!ok)throw new AssertionError(why);}
    private static void denied(Call c,String why)throws Exception{
        try{c.run();throw new AssertionError(why+": accepted");}
        catch(IllegalStateException expected){checks++;}
        catch(ActionDecision.InvalidActionException expected){checks++;}
    }
    private static Set<String> set(String... s){return new TreeSet<String>(Arrays.asList(s));}
    private static String next(){return TaskCompletionGateHostTest.id(++sequence);}
    private static String str(JSONObject o,String k,String fallback)throws Exception{return o.isNull(k)?fallback:o.getString(k);}
    private static int[] ints(JSONArray a)throws Exception{return new int[]{((Number)a.get(0)).intValue(),((Number)a.get(1)).intValue(),((Number)a.get(2)).intValue(),((Number)a.get(3)).intValue()};}
    private static Rect rect(int[] b){return new Rect(b[0],b[1],b[2],b[3]);}
    private static Map<String,Object> map(JSONObject o)throws Exception{
        Map<String,Object> out=new LinkedHashMap<String,Object>();Iterator<String> keys=o.keys();
        while(keys.hasNext()){
            String k=keys.next();Object v=o.get(k);
            if(v==JSONObject.NULL)v=null;
            else if(v instanceof JSONObject)v=map((JSONObject)v);
            else if(v instanceof Map<?,?>)v=map(new JSONObject((Map<?,?>)v));
            out.put(k,v);
        }
        return out;
    }
    private static Object field(Object o,String name)throws Exception{Field f=o.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(o);}
    private static Frame frame(PhoneObservation p)throws Exception{
        Method m=LocalTaskController.class.getDeclaredMethod("completionFrame",PhoneObservation.class);m.setAccessible(true);return (Frame)m.invoke(null,p);
    }
    private static Frame continuation(Frame f){return new Frame(next(),f.packageName,f.windowId,f.displayId,f.backgroundGeneration,f.windowType,f.metadataObserved,f.nodesTruncated,f.nodes);}
    private static PhoneObservation phone(String id,String pkg,int window,List<PhoneObservation.Node> nodes){
        String digest=ObservedImeEnter.hash("synthetic recovery IO:"+id);
        return new PhoneObservation(id,pkg,android.os.SystemClock.elapsedRealtime(),1224,2992,0,window,new Rect(0,0,1224,2992),
                new File("host-recovery-not-a-phone-screenshot"),digest,digest,new ObservationState(digest,ImeVisibility.HIDDEN),
                ObservedWindowMetadata.observed(new int[]{0,0,1224,2992},"FrameLayout",1,0,new int[]{0,0,1224,2992},""),false,nodes);
    }
    private static PhoneObservation.Node row(String id,String text,String view,boolean edit,boolean click,boolean scroll,ObservedChildText.Result child,String bound){
        return new PhoneObservation.Node(id,P,"TextView",view,text,"",new Rect(45,100,1179,600),click,edit,scroll,true,false,false,
                child,ObservedScrollActions.observed(Collections.<String>emptyList()),ObservedImeEnter.UNKNOWN,edit?ObservedImeEnter.hash(text):null,false,bound);
    }
    private static PhoneObservation.Node row(String id,String text,String view,boolean edit,boolean click,boolean scroll){return row(id,text,view,edit,click,scroll,ObservedChildText.notApplicable(),null);}
    private static final class RecordedNode {
        final String text,description,signature,view;final boolean root;final List<RecordedNode> children=new ArrayList<RecordedNode>();
        RecordedNode(String text,String description,String signature,String view,boolean root){this.text=text;this.description=description;this.signature=signature;this.view=view;this.root=root;}
    }
    private static final ObservedChildText.Reader<RecordedNode> READER=new ObservedChildText.Reader<RecordedNode>(){
        public ObservedChildText.Metadata metadata(RecordedNode n){return new ObservedChildText.Metadata(true,true,n.root,n.root,false,false,n.root);}
        public String text(RecordedNode n){return n.text;}public String description(RecordedNode n){return n.description;}
        public String identity(RecordedNode n){return n.signature;}public String viewId(RecordedNode n){return n.view;}
        public int childCount(RecordedNode n){return n.children.size();}public RecordedNode child(RecordedNode n,int i){return n.children.get(i);}
        public void release(RecordedNode n){}
    };
    private static ObservedChildText.Result syntheticCard(String body){
        RecordedNode root=new RecordedNode("","",ObservedImeEnter.hash("synthetic card parent:"+body),P+":id/note_item_content",true);
        String[] texts={"文字笔记","今天",body},views={"note_title","note_date","note_summary"};
        for(int i=0;i<texts.length;i++)root.children.add(new RecordedNode(texts[i],"",ObservedImeEnter.hash("synthetic child:"+i+body),P+":id/"+views[i],false));
        return ObservedChildText.collect(root,READER);
    }
    /** Restore only the complete direct-child shape actually recorded by v46.
     * The source path and independent source/leaf signature identify each child;
     * coordinates are never used to infer ancestry or substitute a card label. */
    private static ObservedChildText.Result recordedChild(JSONObject n,JSONArray rows)throws Exception{
        if(n.isNull("child_text"))return ObservedChildText.notApplicable();
        check("derived".equals(n.getString("child_text_status"))&&!n.getBoolean("child_text_truncated")&&n.getBoolean("child_text_sources_complete"),"recorded child provenance is complete");
        JSONArray sources=n.getJSONArray("child_text_sources");
        check(n.getInt("child_text_visited")==sources.length()&&n.optBoolean("clickable",false)&&str(n,"text","").isEmpty()&&str(n,"description","").isEmpty(),"recorded root shape is preserved");
        RecordedNode root=new RecordedNode("","",n.getString("child_text_root_signature"),str(n,"view_id",""),true);
        for(int i=0;i<sources.length();i++){
            JSONObject source=sources.getJSONObject(i);String property=source.getString("property"),signature=source.getString("node_signature");
            check(Integer.toString(i).equals(source.getString("descendant_path")),"only recorded direct-child source paths are replayed");
            JSONObject leaf=null;
            for(int j=0;j<rows.length();j++){
                JSONObject candidate=rows.getJSONObject(j);
                if(source.getString("view_id").equals(str(candidate,"view_id",""))
                        &&source.getString("text_sha256").equals(ObservedImeEnter.hash(str(candidate,property,"")))
                        &&ObservedChildText.notApplicable().bind(signature).equals(str(candidate,"node_app_tree_sha256",""))){
                    check(leaf==null,"source identifies exactly one original leaf");leaf=candidate;
                }
            }
            check(leaf!=null&&!leaf.optBoolean("clickable",false)&&!leaf.optBoolean("editable",false)&&!leaf.optBoolean("password",false),"original noninteractive leaf required");
            root.children.add(new RecordedNode(str(leaf,"text",""),str(leaf,"description",""),signature,source.getString("view_id"),false));
        }
        ObservedChildText.Result result=ObservedChildText.collect(root,READER);
        check(result.text.equals(n.getString("child_text"))&&result.status.equals(n.getString("child_text_status"))
                &&result.sourcesComplete&&result.visited==n.getInt("child_text_visited")&&result.bind(root.signature).equals(n.getString("node_app_tree_sha256")),"production collector exactly reproduces recorded parent provenance binding");
        return result;
    }
    private static PhoneObservation recordedPhone(JSONObject raw)throws Exception{
        String pkg=raw.getString("package");JSONArray rows=raw.getJSONArray("nodes");List<PhoneObservation.Node> nodes=new ArrayList<PhoneObservation.Node>();
        for(int i=0;i<rows.length();i++){
            JSONObject n=rows.getJSONObject(i);
            nodes.add(new PhoneObservation.Node(n.getString("id"),pkg,"",str(n,"view_id",""),str(n,"text",""),str(n,"description",""),rect(ints(n.getJSONArray("bounds"))),
                    n.optBoolean("clickable",false),n.optBoolean("editable",false),n.optBoolean("scrollable",false),n.optBoolean("enabled",true),n.optBoolean("focused",false),n.optBoolean("password",false),
                    recordedChild(n,rows),ObservedScrollActions.UNKNOWN,ObservedImeEnter.UNKNOWN,str(n,"input_text_sha256",null),false,str(n,"node_app_tree_sha256",null)));
        }
        JSONObject w=raw.getJSONObject("window");check("observed".equals(w.getString("metadata_status"))&&raw.isNull("background_session"),"pinned trace foreground metadata shape");
        return new PhoneObservation(raw.getString("observation_id"),pkg,android.os.SystemClock.elapsedRealtime(),raw.getInt("screen_width"),raw.getInt("screen_height"),raw.getInt("rotation"),raw.getInt("window_id"),
                rect(ints(w.getJSONArray("bounds"))),new File("external-recording-not-a-live-screenshot"),raw.getString("screen_sha256"),raw.getString("observation_state_sha256"),
                new ObservationState(raw.getString("app_tree_sha256"),raw.getBoolean("ime_visible")?ImeVisibility.VISIBLE:ImeVisibility.HIDDEN),
                ObservedWindowMetadata.observed(ints(w.getJSONArray("root_bounds")),w.getString("root_class"),w.getInt("type"),w.getInt("display_id"),ints(w.getJSONArray("bounds")),w.getString("title")),raw.getBoolean("nodes_truncated"),nodes);
    }
    private static JSONObject read(Path dir,JSONObject pins,String name)throws Exception{
        String raw=new String(Files.readAllBytes(dir.resolve(name)),StandardCharsets.UTF_8),sha=ObservedImeEnter.hash(raw);
        check(sha.equals(pins.getString(name)),"exact external input SHA: "+name);readInputs.put(name,sha);return new JSONObject(raw);
    }
    private static final class Fixture {
        String task,owner,body;NotesCompletionEvidence.Installed installed;
        final PhoneObservation[] before=new PhoneObservation[3],after=new PhoneObservation[3];
        final ActionDecision[] actions=new ActionDecision[3];final String[] runs=new String[3];Map<String,Object> fixed;
        static Fixture synthetic()throws Exception{
            Fixture f=new Fixture();f.task=TaskCompletionGateHostTest.TASK;f.body="恢复回归：牛奶、鸡蛋、面包。";f.owner=TaskCompletionGateHostTest.owner(f.body);
            f.installed=new NotesCompletionEvidence.Installed(P,10382,Collections.singletonMap("base",ObservedImeEnter.hash("synthetic installed APK")));
            f.before[0]=phone(next(),"com.motorola.launcher3",7,Collections.<PhoneObservation.Node>emptyList());
            f.after[0]=phone(next(),P,8,Arrays.asList(row("n5","NoteEditor","",false,false,true),row("n11",f.body,"",true,true,false)));
            f.before[1]=f.after[0];f.after[1]=phone(next(),H,9,Collections.<PhoneObservation.Node>emptyList());f.before[2]=f.after[1];
            ObservedChildText.Result child=syntheticCard(f.body);
            f.after[2]=phone(next(),P,10,Arrays.asList(row("n0","所有笔记",P+":id/title_text",false,false,false),row("n1","",P+":id/view_pager2",false,false,true),
                    row("n11","",P+":id/note_item_content",false,true,false,child,child.bind(child.rootSignature)),row("n12","保留的旧笔记",P+":id/note_item_content",false,true,false),
                    row("n16",f.body,P+":id/note_summary",false,false,false)));
            f.actions[0]=decision(frame(f.before[0]),"notes.create",P,null,f.body);f.actions[1]=decision(frame(f.before[1]),"open",H,null,null);f.actions[2]=decision(frame(f.before[2]),"open",P,null,null);
            for(int i=0;i<3;i++)f.runs[i]=next();
            FixedIntentAttemptGuard guard=new FixedIntentAttemptGuard(f.task,value->{});Frame b=frame(f.before[0]);
            FixedIntentAttemptGuard.Attempt attempt=guard.consume(new FixedIntentAttemptGuard.Binding(f.task,f.runs[0],b.observationId,b.packageName,b.windowId,b.displayId,b.backgroundGeneration,f.targets().get("notes.create"),f.body));
            guard.entering(attempt);f.fixed=guard.finished(attempt,true);return f;
        }
        static Fixture actual(Path dir,Path pinsFile)throws Exception{
            JSONObject pins=new JSONObject(new String(Files.readAllBytes(pinsFile),StandardCharsets.UTF_8)).getJSONObject("files");
            Fixture f=new Fixture();JSONObject owner=read(dir,pins,"owner.json"),identity=read(dir,pins,"completion-installed-identity.json");
            f.task=owner.getString("task_id");f.owner=owner.getString("instruction");
            check(ObservedImeEnter.hash(f.owner).equals(owner.getString("instruction_utf8_sha256")),"original immutable owner hash");
            f.body=TaskCompletionGate.Contract.parse(f.owner,TaskAuthorization.parse(f.owner)).body;
            Map<String,String> apks=new LinkedHashMap<String,String>();JSONObject hashes=identity.getJSONObject("apk_hashes");Iterator<String> keys=hashes.keys();
            while(keys.hasNext()){String key=keys.next();apks.put(key,hashes.getString(key));}
            f.installed=new NotesCompletionEvidence.Installed(identity.getString("package"),identity.getInt("uid"),apks);
            for(int i=0;i<3;i++){
                String prefix=String.format(java.util.Locale.ROOT,"step-%02d",i+1);
                f.before[i]=recordedPhone(read(dir,pins,prefix+"-before.json"));f.after[i]=recordedPhone(read(dir,pins,prefix+"-after.json"));
                JSONObject receipt=read(dir,pins,prefix+"-action.json");
                check(receipt.getBoolean("accepted")&&receipt.getBoolean("dispatched")&&!receipt.getBoolean("stale")&&receipt.getBoolean("model_issued"),"original accepted model-issued action receipt");
                f.actions[i]=ActionDecision.parse(receipt.getJSONObject("action").toString(),ActionDecision.FIXED_INTENT_ACTION_SCHEMA);f.runs[i]=receipt.getString("model_run_id");
                if(i==0)f.fixed=map(receipt.getJSONObject("fixed_intent"));
                check(f.actions[i].observationId.equals(f.before[i].id),"original model choice binds before observation");
                if(i>0)check(f.before[i].id.equals(f.after[i-1].id)&&f.before[i].treeSha256.equals(f.after[i-1].treeSha256),"unchanged recorded prefix continuity");
            }
            JSONObject terminal=read(dir,pins,"result.json");
            check("failed".equals(terminal.getString("status"))&&!terminal.getBoolean("completion_verified")&&terminal.getInt("steps")==20,"original fixture is the actual failed 20-step task");
            return f;
        }
        Map<String,FixedIntentTarget> targets(){return Collections.singletonMap("notes.create",new FixedIntentTarget("notes.create","Moto 笔记",installed.uid,null));}
        TaskCompletionGate gate()throws Exception{
            TaskCompletionGate g=new TaskCompletionGate(task,owner,TaskAuthorization.parse(owner));g.bindInstalled(installed);g.observed(frame(before[0]));return g;
        }
        TaskCompletionGate launched()throws Exception{TaskCompletionGate g=gate();g.action(1,runs[0],actions[0],true,true,false,frame(before[0]),frame(after[0]),fixed);return g;}
    }
    private static JSONObject json(Frame f,String tool,String pkg,String node,String payload)throws Exception{
        JSONObject o=new JSONObject().put("reason","host model IO fixture chooses one observed action").put("action",tool).put("observation_id",f.observationId);
        if("open".equals(tool)||"notes.create".equals(tool))o.put("app_label",P.equals(pkg)?"Moto 笔记":"Hepta");
        o.put("package",pkg);
        if("click".equals(tool)){
            String label=null;for(Node n:f.nodes)if(n.id.equals(node))label=ObservedTargetLabels.project(n.label);
            if(label==null)throw new AssertionError("fixture click must name an existing node");o.put("node_label",label).put("node_id",node);
        }
        if("notes.create".equals(tool))o.put("text",payload);
        if("done".equals(tool))o.put("status","success").put("summary","synthetic continuation only");
        return o;
    }
    private static ActionDecision decision(Frame f,String tool,String pkg,String node,String payload)throws Exception{return ActionDecision.parse(json(f,tool,pkg,node,payload).toString(),ActionDecision.FIXED_INTENT_ACTION_SCHEMA);}
    private static Object prompt(Fixture f,PhoneObservation p,TaskCompletionGate completion,NotesTaskPhaseGuard guard,TaskAuthorization.Gate authorization)throws Exception{
        Map<String,String> apps=new LinkedHashMap<String,String>();apps.put(P,"Moto 笔记");apps.put(H,"Hepta");
        for(Method m:LocalTaskController.class.getDeclaredMethods())if("prompt".equals(m.getName())&&m.getParameterTypes()[m.getParameterTypes().length-1]==NotesTaskPhaseGuard.class){
            m.setAccessible(true);return m.invoke(null,f.owner,new AppCatalogueRanker(apps,f.owner).search("",0),p,new JSONArray(),null,null,null,CONFIG,
                    new RepeatActionGuard(),new SameStateNoEffectGuard(),authorization.frame(),null,f.targets(),completion,guard);
        }
        throw new AssertionError("actual production prompt entry missing");
    }
    private static NotesTaskPhaseGuard.Domain domain(Object built)throws Exception{return (NotesTaskPhaseGuard.Domain)field(built,"phaseDomain");}
    private static void grammar(String name,Object built,JSONObject action,boolean accepted)throws Exception{
        Map<String,Object> c=new LinkedHashMap<String,Object>();c.put("name",name);c.put("grammar",((DecisionGrammar)field(built,"grammar")).text);c.put("json",action.toString());c.put("accepted",accepted);grammarCases.add(c);
    }
    private static void recovery(Fixture f)throws Exception{
        TaskCompletionGate g=f.launched();TaskAuthorization auth=TaskAuthorization.parse(f.owner);NotesTaskPhaseGuard guard=new NotesTaskPhaseGuard(f.task,auth);
        Frame editor=frame(f.after[0]),outside=frame(f.after[1]),list=frame(f.after[2]);
        check(g.notesPhase(editor).launchProved&&g.notesPhase(editor).editorObserved&&!g.verified(editor),"actual Gate requires both entry and observed owned body");
        Object leave=prompt(f,f.after[0],g,guard,auth.bind(f.task));NotesTaskPhaseGuard.Domain leaveDomain=domain(leave);
        check("leave_created_editor".equals(leaveDomain.projection.phase)&&leaveDomain.openPackages.isEmpty(),"inside owned Notes has no open domain");
        check(!((DecisionGrammar)field(leave,"grammar")).actions.contains("open")&&((String)field(leave,"text")).contains("\"open_allowed_packages\":[]"),"actual prompt and grammar carry the same empty open set");
        denied(()->leaveDomain.requireCurrent(f.actions[1]),"historical open-Hepta decision rejected after parse");
        denied(()->guard.requireCurrent(f.actions[1]),"historical open-Hepta decision rejected at final phase gate");
        grammar("owned-editor-cannot-open-hepta",leave,json(editor,"open",H,null,null),false);
        grammar("owned-editor-cannot-open-notes",leave,json(editor,"open",P,null,null),false);
        grammar("owned-editor-back",leave,json(editor,"back",P,null,null),true);
        // The next two calls replay OLD accepted history only. The v48 domain
        // above refuses that open; no host code dispatches a repair on the phone.
        g.action(2,f.runs[1],f.actions[1],true,true,false,frame(f.before[1]),outside,null);
        Object away=prompt(f,f.after[1],g,guard,auth.bind(f.task));NotesTaskPhaseGuard.Domain awayDomain=domain(away);
        check(awayDomain.openPackages.equals(set(P))&&awayDomain.projection.openPackages(Collections.<String>emptySet()).isEmpty(),"outside owned Notes can only return through supplied catalogue");
        awayDomain.requireCurrent(f.actions[2]);checks++;
        grammar("away-can-return-notes",away,json(outside,"open",P,null,null),true);
        grammar("away-cannot-open-hepta",away,json(outside,"open",H,null,null),false);
        g.action(3,f.runs[2],f.actions[2],true,true,false,frame(f.before[2]),list,null);
        check(!g.notesPhase(list).listObserved&&!g.notesPhase(list).reopened&&!g.verified(list),"historical create/open/open prefix never became save or reopen proof");
        NotesCompletionEvidence.ListEvidence proof=NotesCompletionEvidence.list(list,f.body);
        check(proof.matched&&"n11".equals(proof.item.nodeId)&&"bound_note_summary_accessibility_text".equals(proof.matchRule),"unique complete summary proof names original clickable parent n11");
        for(Node n:list.nodes)if("n16".equals(n.id))check(!n.clickable,"original summary leaf stays nonclickable");
        Object recover=prompt(f,f.after[2],g,guard,auth.bind(f.task));NotesTaskPhaseGuard.Domain recovery=domain(recover);
        check("recover_created_editor".equals(recovery.projection.phase)&&recovery.clickIds.equals(set("n11"))&&recovery.openPackages.isEmpty(),"recovery grants only the observed matching parent click");
        check(recovery.editIds.isEmpty()&&recovery.submitIds.isEmpty()&&!recovery.fixedActions.contains("notes.create"),"recovery cannot replace text, submit or create another note");
        ActionDecision click=decision(list,"click",P,"n11",null),wrong=decision(list,"click",P,"n12",null);
        recovery.requireCurrent(click);guard.requireCurrent(click);checks++;
        denied(()->recovery.requireCurrent(wrong),"different note rejected after parse");denied(()->guard.requireCurrent(wrong),"different note rejected at final phase gate");
        check(recovery.projection.clicks(set("n12")).isEmpty(),"projection never adds an unoffered node");
        grammar("recover-original-parent",recover,json(list,"click",P,"n11",null),true);
        grammar("recover-other-note-denied",recover,json(list,"click",P,"n12",null),false);
        grammar("recover-summary-leaf-denied",recover,json(list,"click",P,"n16",null),false);
        grammar("recover-open-denied",recover,json(list,"open",H,null,null),false);
        Frame restored=continuation(editor);g.action(4,next(),click,true,true,false,list,restored,null);
        check(!g.notesPhase(restored).listObserved&&!g.notesPhase(restored).reopened&&!g.verified(restored),"recovery click is not a save/reopen success transition");
        check("leave_created_editor".equals(guard.prepare(g,restored).phase),"recovered editor must follow original leave phase");
        Frame saved=continuation(list);g.action(5,next(),decision(restored,"back",P,null,null),true,true,false,restored,saved,null);
        check(g.notesPhase(saved).listObserved&&!g.notesPhase(saved).reopened&&!g.verified(saved),"only subsequent editor-to-list transition establishes list proof");
        Frame reopened=continuation(editor);g.action(6,next(),decision(saved,"click",P,"n11",null),true,true,false,saved,reopened,null);
        check(g.verified(reopened)&&g.successClaim(7,next(),reopened).verified,"unchanged Gate accepts only the complete original chain after recovery");
        Object replacement=prompt(f,f.after[2],g,guard,auth.bind(f.task));check(domain(replacement)!=recovery,"new prompt publishes a new immutable domain");
        denied(()->recovery.requireCurrent(click),"replaced domain cannot be replayed");guard.retire();denied(()->domain(replacement).requireCurrent(click),"retired domain cannot be replayed");
    }
    private static void boundaries(Fixture f)throws Exception{
        Frame before=frame(f.before[0]),editor=frame(f.after[0]),list=frame(f.after[2]),outside=frame(f.after[1]);TaskAuthorization auth=TaskAuthorization.parse(f.owner);
        TaskCompletionGate empty=f.gate();NotesTaskPhaseGuard guard=new NotesTaskPhaseGuard(f.task,auth);
        check(guard.prepare(empty,list).clicks(set("n11")).isEmpty(),"preexisting matching note without this task's entry/body cannot be recovered");
        TaskCompletionGate noBody=f.gate();noBody.action(1,f.runs[0],f.actions[0],true,true,false,before,outside,f.fixed);
        check(noBody.notesPhase(list).launchProved&&!noBody.notesPhase(list).editorObserved&&guard.prepare(noBody,list).clicks(set("n11")).isEmpty(),"entry receipt without body readback cannot unlock a list click");
        for(String key:new String[]{"task_id","model_run_id","observation_id"}){
            Map<String,Object> bad=new LinkedHashMap<String,Object>(f.fixed);bad.put(key,next());TaskCompletionGate g=f.gate();
            g.action(1,f.runs[0],f.actions[0],true,true,false,before,editor,bad);
            check(!g.notesPhase(list).launchProved&&guard.prepare(g,list).clicks(set("n11")).isEmpty(),"foreign "+key+" cannot borrow create proof");
        }
        TaskCompletionGate launched=f.launched();
        Frame foreign=new Frame(next(),P,list.windowId,9,"11111111-1111-1111-1111-111111111111",1,true,false,list.nodes);
        check(guard.prepare(launched,foreign).clicks(set("n11")).isEmpty(),"foreign display/generation cannot acquire recovery");
        launched.observed(foreign);check(guard.prepare(launched,list).clicks(set("n11")).isEmpty(),"observed identity invalidation remains sticky");
        TaskCompletionGate replaced=f.launched();replaced.invalidateInstalled("synthetic installed identity replacement");
        check(guard.prepare(replaced,list).clicks(set("n11")).isEmpty()&&guard.prepare(replaced,list).openPackages(set(P,H)).isEmpty(),"installed identity failure cannot grant recovery or loosen owned-Notes open restriction");
        NotesTaskPhaseGuard other=new NotesTaskPhaseGuard(next(),auth);denied(()->other.prepare(empty,list),"another task cannot borrow completion facts");
        String unknown="打开应用并检查当前页面。";NotesTaskPhaseGuard un=new NotesTaskPhaseGuard(next(),TaskAuthorization.parse(unknown));
        NotesTaskPhaseGuard.Projection p=un.prepare(null,list);
        check(!un.supported()&&p.clicks(set("n11","n12")).equals(set("n11","n12"))&&p.openPackages(set(P,H)).equals(set(P,H)),"unknown goals retain their original action domains");
        Set<String> mutable=set(H);NotesTaskPhaseGuard.Domain d=p.bind(set("n11"),Collections.<String>emptySet(),Collections.<String>emptySet(),Collections.<String,FixedIntentTarget>emptyMap(),mutable);un.publish(d);mutable.add(P);
        denied(()->d.requireCurrent(decision(list,"open",P,null,null)),"published final open set is an immutable snapshot");
        d.requireCurrent(decision(list,"open",H,null,null));checks++;
    }
    private static void serviceDomains()throws Exception{
        Fixture f=Fixture.synthetic();TaskAuthorization authorization=TaskAuthorization.parse(f.owner);
        try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            TaskCompletionGateHostTest.installPackage(e,"notes.create");e.service.launchable.put(P,"Moto 笔记");e.service.launchable.put(H,"Hepta");
            e.service.observationRows=()->f.after[0].nodes;e.service.prepare(P);
            check(e.service.acquireTask(e.task,()->{}),"actual service lease acquired");
            e.service.bindQualificationScope(e.task,QualificationScopeConfig.capture(e.service,e.task,null,e.runtime));
            TaskAuthorization.Gate auth=e.service.bindTaskAuthorization(e.task,authorization);NotesTaskPhaseGuard phase=e.service.notesTaskPhaseFor(e.task,auth);
            TaskCompletionGate g=f.launched();Object built=prompt(f,e.service.current,g,phase,auth);
            check(domain(built).openPackages.isEmpty(),"actual service owns published final empty open set");
            for(String pkg:new String[]{H,P}){
                HeptaAccessibilityService.ActionOutcome result=e.service.execute(decision(frame(e.service.current),"open",pkg,null,null));
                check(!result.accepted&&!result.dispatched&&e.service.effects()==0&&result.detail.contains("notes_task_phase"),"service refuses forged parsed open before any Android effect");
            }
            e.service.releaseTask(e.task);denied(()->domain(built).requireCurrent(decision(frame(e.service.current),"back",P,null,null)),"service release retires its published domain");
        }
        // Actual final dispatch also admits the narrowly offered recovery click.
        // This IO uses the existing exact-text provider path; the prefix above
        // separately exercises composed-card provenance through the real bridge.
        try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            TaskCompletionGateHostTest.installPackage(e,"notes.create");e.service.prepare(P);e.service.node.text=f.body;e.service.node.editable=false;e.service.node.scrollable=false;
            e.service.observationRows=()->Arrays.asList(row("n0",f.body,P+":id/note_item_content",false,true,false),row("n1","所有笔记",P+":id/title_text",false,false,false),row("n2","",P+":id/view_pager2",false,false,true));
            check(e.service.acquireTask(e.task,()->{}),"recovery service lease acquired");e.service.bindQualificationScope(e.task,QualificationScopeConfig.capture(e.service,e.task,null,e.runtime));
            TaskAuthorization.Gate auth=e.service.bindTaskAuthorization(e.task,authorization);NotesTaskPhaseGuard phase=e.service.notesTaskPhaseFor(e.task,auth);
            e.service.observe(e.task,e.dir.toFile(),()->false,Long.MAX_VALUE,new HeptaAccessibilityService.ObservationCallback(){
                public void onObservation(PhoneObservation observation){}public void onError(String message){throw new AssertionError(message);}
            });
            Object built=prompt(f,e.service.current,f.launched(),phase,auth);check(domain(built).clickIds.equals(set("n0")),"actual service recovery domain is only current observed card");
            HeptaAccessibilityService.ActionOutcome result=e.service.execute(decision(frame(e.service.current),"click",P,"n0",null));
            check(result.accepted&&result.dispatched&&e.service.effects()==1,"one model IO choice passes actual service final recovery dispatch");
        }
    }
    public static void main(String[] args)throws Exception{
        Path output=Paths.get(args[0]);Files.createDirectories(output);QualificationScopeHostTest.output=output;
        boolean external=args.length==3;Fixture fixture=external?Fixture.actual(Paths.get(args[2]),Paths.get(args[1])):Fixture.synthetic();
        recovery(fixture);boundaries(fixture);if(!external)serviceDomains();
        Files.write(output.resolve("grammar-cases.json"),new JSONArray(grammarCases).toString().getBytes(StandardCharsets.UTF_8));
        Map<String,Object> result=new LinkedHashMap<String,Object>();result.put("schema","hepta.notes-recovery-host.v1");result.put("passed",true);
        result.put("fixture_mode",external?"external_actual_trace":"synthetic");result.put("input_files_sha256",readInputs);result.put("checks",checks);result.put("grammar_cases",grammarCases.size());
        result.put("historical_prefix_steps",3);result.put("historical_prefix_model_run_ids",Arrays.asList(fixture.runs));result.put("continuation_model_and_observation_io","synthetic");
        result.put("phone_tested",false);result.put("native_inference",false);result.put("fresh_model_task_success",false);result.put("completion_predicate_changed",false);
        Files.write(output.resolve("RESULT.json"),new JSONObject(result).toString().getBytes(StandardCharsets.UTF_8));
        System.out.println("PASS "+checks+" Notes recovery checks; fixture_mode="+(external?"external_actual_trace":"synthetic")+"; phone_tested=false; fresh_model_task_success=false");
    }
}
