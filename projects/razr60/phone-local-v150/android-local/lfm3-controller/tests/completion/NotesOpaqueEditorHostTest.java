package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.json.JSONObject;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Frame;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Node;
import org.trillionnium.hepta.local.NotesCreateWorkflow.Observation;

public final class NotesOpaqueEditorHostTest {
    static final String PKG=NotesCompletionEvidence.NOTES,TASK=TaskCompletionGateHostTest.TASK;
    static final String GEN="11111111-2222-4333-8444-555555555555",BODY="清单新正文";
    static final NotesCompletionEvidence.Installed APK=new NotesCompletionEvidence.Installed(PKG,10382,
            Collections.singletonMap("base",NotesCompletionEvidence.OBSERVED_BASE_APK_SHA256));
    static int serial=8000,assertions,cases;
    static String id(){return TaskCompletionGateHostTest.id(++serial);}
    static String hash(String s){return ObservedImeEnter.hash(s);}
    static void check(boolean b,String why){assertions++;if(!b)throw new AssertionError(why);}
    static Observation obs(Frame f){return new Observation(f,hash("observed editor tree"),0);}
    static Frame fresh(Frame f){return new Frame(id(),f.packageName,f.windowId,f.displayId,f.backgroundGeneration,f.windowType,f.metadataObserved,f.nodesTruncated,f.nodes);}
    static Frame frames(int window,List<Node> nodes){return new Frame(id(),PKG,window,509,GEN,1,true,false,nodes);}
    static Node node(String id,String path,String view,String cls,String txt,int y,int bottom,boolean click,boolean scroll,
            boolean editable,ObservedChildText.Result child,String sig){
        return new Node(id,PKG,txt,txt.isEmpty()&&child!=null?child.text:txt,view.isEmpty()?"":PKG+":id/"+view,
                editable?hash(txt):null,new int[]{0,y,400,bottom},editable,click,scroll,true,false,child,sig,cls,path);
    }
    static ObservedChildText.Result children(final String text){return ObservedChildText.collect(0,new ObservedChildText.Reader<Integer>(){
        public ObservedChildText.Metadata metadata(Integer i){return new ObservedChildText.Metadata(true,true,i==0,i==0,false,false,false);}
        public String text(Integer i){return i==0?"":text;}public String description(Integer i){return "";}
        public String identity(Integer i){return hash("source "+i+" "+text);}public String viewId(Integer i){return PKG+(i==0?":id/note_item_content":":id/note_summary");}
        public int childCount(Integer i){return i==0?1:0;}public Integer child(Integer i,int index){return index==0?1:null;}public void release(Integer i){}
    });}
    static Frame list(String... rows){
        List<Node> n=new ArrayList<Node>();n.add(node("n0","0/0","view_pager2","androidx.viewpager.widget.ViewPager","",0,800,false,true,false,null,hash("pager")));
        n.add(node("n1","0/1","title_text","android.widget.TextView","所有笔记",0,40,false,false,false,null,hash("title")));
        n.add(node("n2","0/0/0","note_grid","androidx.recyclerview.widget.RecyclerView","",40,800,false,false,false,null,hash("grid")));
        for(int i=0;i<rows.length;i++){ObservedChildText.Result c=children(rows[i]);String path="0/0/0/"+i;int top=60+i*100;
            n.add(node("n"+(3+2*i),path,"note_item_content","android.widget.FrameLayout","",top,top+94,true,false,false,c,c.bind(c.rootSignature)));
            n.add(node("n"+(4+2*i),path+"/0","note_summary","android.widget.TextView",rows[i],top+10,top+64,false,false,false,null,c.sources.get(0).nodeSignature));
        }return frames(2100,n);
    }
    static Frame editor(int win,String body){
        List<Node> n=new ArrayList<Node>();n.add(node("n0","0/0/1","title","android.widget.TextView","标题",0,40,false,false,false,null,hash("title")));
        n.add(node("n1","0/1/0","","android.webkit.WebView","NoteEditor",40,800,false,false,false,null,hash("editor")));
        if(body!=null)n.add(node("n2","0/1/0/0","","android.widget.EditText",body,50,750,true,false,true,null,hash("field")));
        return frames(win,n);
    }
    static Observation read(Path dir,String name)throws Exception{
        return NotesReopenReadinessHostTest.actualObservationCurrent(new JSONObject(new String(Files.readAllBytes(dir.resolve(name)),StandardCharsets.UTF_8)));
    }
    static final class Parent{
        final String body,run;final TaskAuthorization a;final TaskAuthorization.Gate auth;final TaskCompletionGate done;
        final ActionDecision action;final List<Observation> reads=new ArrayList<Observation>();final Frame before,first;
        Parent(Frame before,Frame shell,String body,Map<String,Object> original,String originalTask,String originalRun)throws Exception{
            this.before=before;this.first=shell;this.body=body;run=originalRun==null?id():originalRun;
            String task=originalTask==null?TASK:originalTask,owner=TaskCompletionGateHostTest.owner(body);
            a=TaskAuthorization.parse(owner);auth=a.bind(task);done=new TaskCompletionGate(task,owner,a);done.bindInstalled(APK);
            if(originalRun==null)action=TaskCompletionGateHostTest.action(before,"notes.create",body,null);
            else action=ActionDecision.parse(new JSONObject().put("action","notes.create").put("observation_id",before.observationId)
                    .put("app_label",((Map<?,?>)original.get("target")).get("app_label")).put("package",PKG).put("text",body).toString(),ActionDecision.FIXED_INTENT_ACTION_SCHEMA);
            done.observed(before);
            if(original==null)original=TaskCompletionGateHostTest.fixed(before,action,run);
            done.action(1,run,action,true,true,false,before,shell,original);
            for(int i=0;i<4;i++)reads.add(obs(i==0?shell:fresh(shell)));
        }
        NotesCreateWorkflow.Grant grant(){return done.notesOpaqueEditorWorkflow(1,run,action,reads,auth.frame(),100,9200);}
    }
    static void chain(Frame before,Frame shell,Frame added,Frame reopened,String body,boolean success,boolean shouldStore,String name)throws Exception{
        Parent p=new Parent(before,shell,body,null,null,null);
        NotesCreateWorkflow.Grant g=p.grant();check(g!=null,"original parent eligible: "+name);
        NotesCreateWorkflowHostTest.FakeIO io=new NotesCreateWorkflowHostTest.FakeIO(g,obs(fresh(shell)),obs(added),obs(reopened),obs(fresh(reopened)));
        final NotesTaskPhaseGuard guard=new NotesTaskPhaseGuard(TASK,p.a);
        NotesCreateWorkflow.Result result=NotesCreateWorkflow.run(g,p.reads.get(3),new NotesCreateWorkflow.IO(){
            public Observation observe(){Observation o=io.observe();p.done.observed(o.frame);return o;}
            public void checkpoint(String tag,Map<String,Object> evidence){io.checkpoint(tag,evidence);}
            public void recorded(NotesCreateWorkflow.ChildRecord row){io.recorded(row);}
            public NotesCreateWorkflow.Dispatch dispatch(NotesCreateWorkflow.ChildCall c,Observation o)throws Exception{
                NotesTaskPhaseGuard.Projection projection=guard.prepare(p.done,o.frame);
                check((c.ordinal==1?"leave_opaque_created_editor_once":"reopen_newly_inserted_item").equals(projection.phase),"only typed child in provisional phase");
                java.util.Set<String> clicks=projection.clicks(c.nodeId==null?Collections.<String>emptySet():Collections.singleton(c.nodeId));
                NotesTaskPhaseGuard.Domain domain=projection.bind(clicks,Collections.<String>emptySet(),Collections.<String>emptySet(),null);
                guard.publish(domain);domain.requireCurrent(c.decision());
                ActionDecision model=TaskCompletionGateHostTest.action(o.frame,c.action,null,c.nodeId);
                boolean refused=false;try{domain.requireCurrent(model);}catch(ActionDecision.InvalidActionException denied){refused=true;}
                check(refused,"ordinary model decision cannot reuse the provisional child phase");return io.dispatch(c,o);
            }
        });
        check(g.savedToNewRow()==shouldStore,"actual post-return insertion: "+name);
        check(result.completeFor(g)==success,"no completion without independent reopened body: "+name);
        boolean accepted=p.done.notesCreateWorkflowCompleted(result,result.stableReadback==null?result.current.frame:result.stableReadback.frame);
        check(accepted==success,"completion gate "+name);
        check(io.effects==(shouldStore?2:1),"one Back and at most one click: "+name);
        check(p.grant()==null,"consumed parent must not mint a second grant");cases++;
    }
    public static void main(String[] args)throws Exception{
        Frame before=list("旧一","旧二","旧三","旧四"),shell=editor(2101,null),ready=editor(2102,BODY),added=list(BODY,"旧一","旧二","旧三");
        check(NotesCompletionEvidence.opaqueEditor(shell,APK)&&!NotesCompletionEvidence.editor(shell,BODY,APK).matched,"opaque editor gives no text proof");
        check(!NotesCompletionEvidence.opaqueEditor(ready,APK),"already readable is not opaque");cases++;
        chain(before,shell,added,ready,BODY,true,true,"new row and actual reopened body");
        chain(before,shell,before,ready,BODY,false,false,"unchanged list");
        chain(before,shell,list(BODY,"旧二","旧一","旧三"),ready,BODY,false,false,"permuted older rows");
        chain(before,shell,list(BODY,"旧一",BODY,"旧三"),ready,BODY,false,false,"duplicate body");
        chain(before,shell,new Frame(id(),PKG,2200,509,GEN,1,true,false,added.nodes),ready,BODY,false,false,"different list window");
        chain(before,shell,added,editor(2102,"其它正文"),BODY,false,true,"wrong reopened body");
        check(new Parent(list(BODY,"旧二","旧三"),shell,BODY,null,null,null).grant()==null,"prior visible duplicate");cases++;
        Parent stale=new Parent(before,shell,BODY,null,null,null);stale.reads.set(1,stale.reads.get(0));check(stale.grant()==null,"repeated frame");cases++;
        Parent changed=new Parent(before,shell,BODY,null,null,null);changed.reads.set(2,obs(editor(3030,null)));check(changed.grant()==null,"wrong new editor window");cases++;
        Parent replay=new Parent(before,shell,BODY,null,null,null);
        NotesCreateWorkflow.Grant replayGrant=replay.grant();
        NotesCreateWorkflowHostTest.FakeIO frozen=new NotesCreateWorkflowHostTest.FakeIO(replayGrant,replay.reads.get(0));
        NotesCreateWorkflow.Result noEffect=NotesCreateWorkflow.run(replayGrant,replay.reads.get(3),frozen);
        check(frozen.effects==0&&!noEffect.completeFor(replayGrant),"a cached editor sample cannot authorize a return");cases++;
        Parent expired=new Parent(before,shell,BODY,null,null,null);
        check(expired.done.notesOpaqueEditorWorkflow(1,expired.run,expired.action,expired.reads,expired.auth.frame(),100,15101)==null,"unchanged deadline");cases++;
        if(args.length==1)archived(Paths.get(args[0]));
        System.out.println(new JSONObject().put("all_pass",true).put("cases",cases).put("assertions",assertions)
                .put("archive_directory_supplied",args.length==1).put("phone_operations",0));
    }
    static void archived(Path dir)throws Exception{
        String failed="7a449cb7e34e460b87344cf8eee06d32";
        Path d=dir.resolve(failed);if(!Files.isDirectory(d))d=dir.resolve(failed+"-raw");
        Observation before=read(d,"step-01-before.json"),shell=read(d,"step-01-after.json");
        JSONObject raw=new JSONObject(new String(Files.readAllBytes(d.resolve("step-01-action.json")),StandardCharsets.UTF_8));
        String text=raw.getJSONObject("action").getString("text");
        check(NotesCompletionEvidence.orderedSummaryDigests(before.frame).size()==7,"seven actual prior list entries");
        check(NotesCompletionEvidence.opaqueEditor(shell.frame,APK),"actual ten-node WebView has no readable body");
        Parent p=new Parent(before.frame,shell.frame,text,NotesCreateWorkflowHostTest.objectMap(raw.getJSONObject("fixed_intent")),failed,raw.getString("model_run_id"));
        p.reads.set(0,shell);
        for(int i=1;i<4;i++)p.reads.set(i,read(d,"step-01-notes-readiness-observation-"+(i+1)+".json"));
        NotesCreateWorkflow.Grant real=p.grant();check(real!=null&&!real.savedToNewRow()&&!p.done.controllerWorkflowReady(shell.frame),
                "the original four frames allow no saved or reopened claim");cases++;
        for(String id:new String[]{"f0ef81aad2234a58a51b79e5da6b5305","824a8487a5c140fe88bb3c0064db6a95"}){
            Path old=dir.resolve(id);if(!Files.isDirectory(old))old=dir.resolve(id+"-raw");
            Observation orig=read(old,"step-01-before.json"),created=read(old,"step-01-after.json"),
                    list=read(old,"step-01-tool-child-01-after.json"),reopened=read(old,"step-01-tool-child-02-after.json");
            String exact="";List<Node> hidden=new ArrayList<Node>();
            for(Node n:created.frame.nodes){if(n.editable)exact=n.text.trim();else hidden.add(n);}
            check(!exact.isEmpty()&&NotesCompletionEvidence.editor(reopened.frame,exact,APK).matched,"actual reopened text "+id);
            Frame f=created.frame,projected=new Frame(f.observationId,f.packageName,f.windowId,f.displayId,f.backgroundGeneration,f.windowType,f.metadataObserved,f.nodesTruncated,hidden);
            chain(orig.frame,projected,list.frame,reopened.frame,exact,true,true,"real visible rows and reopened body, projected missing first editable");
        }
    }
}
