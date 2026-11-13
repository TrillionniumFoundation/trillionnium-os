package org.trillionnium.hepta.local;

import android.graphics.Rect;
import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.FixedIntentTarget;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Frame;

/** Replays original failed v46 observations and receipts through the production
 * bridge/gate. Any subsequent click/reopen/done is explicitly synthetic host IO,
 * not a missing phone action or a retrospective successful task. */
public final class NotesRecoveryHostTest {
    private static final String FIXTURE_SHA="c253146ad4556d8448df87905f0529846b9fa80b489bdf59c94840afb137ad01";
    private static final String P=NotesCompletionEvidence.NOTES,SELF="org.trillionnium.hepta.local";
    private static final String TASK="3ac1287814414567b655b42030d9911b";
    private static final String BODY="Hepta-v46r1-b14e484e9ff9。购物清单：牛奶、鸡蛋、面包。";
    private static JSONObject files;private static String owner;private static int checks,ids=1000;
    private static final List<Object> grammarCases=new ArrayList<Object>();
    private interface Call {void run()throws Exception;}
    private static void check(boolean ok,String why){checks++;if(!ok)throw new AssertionError(why);}
    private static void denied(Call call,String why)throws Exception{
        try{call.run();throw new AssertionError(why+": accepted");}
        catch(IllegalStateException expected){checks++;}
        catch(ActionDecision.InvalidActionException expected){checks++;}
    }
    private static String id(){return TaskCompletionGateHostTest.id(++ids);}
    private static Set<String> set(String... values){return new TreeSet<String>(Arrays.asList(values));}
    private static JSONObject raw(String name)throws Exception{
        JSONObject row=files.getJSONObject(name);String text=row.getString("raw_utf8");
        check(row.getString("sha256").equals(ObservedImeEnter.hash(text))&&row.getInt("bytes")==text.getBytes(StandardCharsets.UTF_8).length,"original archived bytes: "+name);
        return new JSONObject(text);
    }
    private static String value(JSONObject o,String key,String fallback)throws Exception{return o.has(key)&&o.get(key)!=JSONObject.NULL?o.getString(key):fallback;}
    private static int[] bounds(JSONArray a)throws Exception{return new int[]{((Number)a.get(0)).intValue(),((Number)a.get(1)).intValue(),((Number)a.get(2)).intValue(),((Number)a.get(3)).intValue()};}
    private static Rect rect(int[] v){return new Rect(v[0],v[1],v[2],v[3]);}
    private static Object field(Object object,String name)throws Exception{Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(object);}
    private static JSONArray replace(JSONArray old,int index,Object value){
        JSONArray out=new JSONArray();for(int i=0;i<old.length();i++)out.put(i==index?value:old.get(i));return out;
    }

    private static ObservedChildText.Result child(JSONObject row)throws Exception{
        if(!row.has("child_text_status"))return ObservedChildText.notApplicable();
        List<ObservedChildText.Source> sources=new ArrayList<ObservedChildText.Source>();
        List<int[]> spans=new ArrayList<int[]>();StringBuilder joined=new StringBuilder();boolean complete=true;
        Map<String,String> known=new LinkedHashMap<String,String>();
        for(String text:new String[]{"文字笔记","今天",BODY})known.put(ObservedImeEnter.hash(text),text);
        JSONArray values=row.has("child_text_sources")?row.getJSONArray("child_text_sources"):new JSONArray();
        for(int i=0;i<values.length();i++){
            JSONObject s=values.getJSONObject(i);
            // Archive stores source hashes rather than raw descendant text. This
            // test-only reflection restores those exact serialized facts; it does
            // not create a new production source constructor or infer ancestry.
            ObservedChildText.Source source=new ObservedChildText.Source(s.getString("descendant_path"),s.getString("property"),"",s.getString("node_signature"),s.getString("view_id"));
            Field hash=ObservedChildText.Source.class.getDeclaredField("textSha256");hash.setAccessible(true);hash.set(source,s.getString("text_sha256"));sources.add(source);
            String text=known.get(s.getString("text_sha256"));
            if(text==null)complete=false;
            else{if(joined.length()>0)joined.append(" · ");int start=joined.length();joined.append(text);spans.add(new int[]{start,joined.length()});}
        }
        String text=value(row,"child_text","");
        // Only hash-equal known raw parts restore span IO for text-only prompt
        // tests. Unknown cards have no asserted spans. No composed label is split.
        if(!complete||!joined.toString().equals(text))spans.clear();
        Constructor<ObservedChildText.Result> c=ObservedChildText.Result.class.getDeclaredConstructor(String.class,String.class,boolean.class,int.class,List.class,List.class,String.class,boolean.class);
        c.setAccessible(true);return c.newInstance(text,row.getString("child_text_status"),row.getBoolean("child_text_truncated"),row.getInt("child_text_visited"),sources,spans,
                value(row,"child_text_root_signature",""),row.getBoolean("child_text_sources_complete"));
    }
    private static PhoneObservation phone(JSONObject raw)throws Exception{
        List<PhoneObservation.Node> nodes=new ArrayList<PhoneObservation.Node>();JSONArray rows=raw.getJSONArray("nodes");String pkg=raw.getString("package");
        for(int i=0;i<rows.length();i++){
            JSONObject n=rows.getJSONObject(i);List<String> directions=new ArrayList<String>();
            if(n.optBoolean("scroll_actions_observed",false)){JSONArray d=n.getJSONArray("scroll_directions");for(int j=0;j<d.length();j++)directions.add((String)d.get(j));}
            nodes.add(new PhoneObservation.Node(n.getString("id"),pkg,"",value(n,"view_id",""),value(n,"text",""),value(n,"description",""),rect(bounds(n.getJSONArray("bounds"))),
                    n.optBoolean("clickable",false),n.optBoolean("editable",false),n.optBoolean("scrollable",false),n.optBoolean("enabled",true),n.optBoolean("focused",false),n.optBoolean("password",false),child(n),
                    n.optBoolean("scroll_actions_observed",false)?ObservedScrollActions.observed(directions):ObservedScrollActions.UNKNOWN,
                    ObservedImeEnter.UNKNOWN,value(n,"input_text_sha256",null),false,value(n,"node_app_tree_sha256",null)));
        }
        JSONObject w=raw.getJSONObject("window");ObservedWindowMetadata metadata=ObservedWindowMetadata.observed(bounds(w.getJSONArray("root_bounds")),w.getString("root_class"),w.getInt("type"),w.getInt("display_id"),bounds(w.getJSONArray("bounds")),w.getString("title"));
        return new PhoneObservation(raw.getString("observation_id"),pkg,1,raw.getInt("screen_width"),raw.getInt("screen_height"),raw.getInt("rotation"),raw.getInt("window_id"),rect(bounds(w.getJSONArray("bounds"))),
                new File("archived-v46-observation-not-live-phone-io"),raw.getString("screen_sha256"),raw.getString("observation_state_sha256"),
                new ObservationState(raw.getString("app_tree_sha256"),raw.isNull("ime_visible")?ImeVisibility.UNKNOWN:raw.getBoolean("ime_visible")?ImeVisibility.VISIBLE:ImeVisibility.HIDDEN),metadata,raw.getBoolean("nodes_truncated"),nodes);
    }
    private static Frame frame(JSONObject raw)throws Exception{
        Method bridge=LocalTaskController.class.getDeclaredMethod("completionFrame",PhoneObservation.class);bridge.setAccessible(true);return (Frame)bridge.invoke(null,phone(raw));
    }
    private static Frame copy(Frame f,String pkg,int display,String generation,List<NotesCompletionEvidence.Node> nodes){
        return new Frame(id(),pkg,f.windowId,display,generation,f.windowType,f.metadataObserved,f.nodesTruncated,nodes);
    }
    @SuppressWarnings("unchecked") private static Map<String,Object> map(JSONObject o)throws Exception{
        Method convert=LocalTaskController.class.getDeclaredMethod("completionFixed",JSONObject.class);convert.setAccessible(true);
        return (Map<String,Object>)convert.invoke(null,o);
    }
    private static ActionDecision action(JSONObject receipt)throws Exception{return ActionDecision.parse(receipt.getJSONObject("action").toString(),ActionDecision.FIXED_INTENT_ACTION_SCHEMA);}
    private static TaskCompletionGate gate()throws Exception{
        JSONObject installed=raw("completion-installed-identity.json");Map<String,String> hashes=new LinkedHashMap<String,String>();
        Map<String,Object> m=map(installed.getJSONObject("apk_hashes"));for(Map.Entry<String,Object> e:m.entrySet())hashes.put(e.getKey(),(String)e.getValue());
        TaskCompletionGate g=new TaskCompletionGate(TASK,owner,TaskAuthorization.parse(owner));
        g.bindInstalled(new NotesCompletionEvidence.Installed(installed.getString("package"),installed.getInt("uid"),hashes));return g;
    }
    private static void replay(TaskCompletionGate g,int step)throws Exception{
        JSONObject r=raw(String.format(java.util.Locale.ROOT,"step-%02d-action.json",step));
        g.action(step,r.getString("model_run_id"),action(r),r.getBoolean("accepted"),r.getBoolean("dispatched"),r.getBoolean("stale"),
                frame(raw(String.format(java.util.Locale.ROOT,"step-%02d-before.json",step))),frame(raw(String.format(java.util.Locale.ROOT,"step-%02d-after.json",step))),
                r.isNull("fixed_intent")?null:map(r.getJSONObject("fixed_intent")));
    }
    private static TaskCompletionGate launched()throws Exception{TaskCompletionGate g=gate();replay(g,1);return g;}
    private static TaskCompletionGate recovered()throws Exception{TaskCompletionGate g=launched();replay(g,2);replay(g,3);return g;}
    private static ActionDecision click(Frame list,String node,String label)throws Exception{
        return ActionDecision.parse(new JSONObject().put("reason","synthetic host choice after the recorded failed prefix").put("action","click").put("observation_id",list.observationId)
                .put("package",P).put("node_label",label).put("node_id",node).toString(),ActionDecision.FIXED_INTENT_ACTION_SCHEMA);
    }
    private static Object prompt(String instruction,PhoneObservation observed,TaskAuthorization.Gate auth,TaskCompletionGate completion,NotesTaskPhaseGuard guard,JSONArray history,LastModelDecisionProjection prior)throws Exception{
        Map<String,String> apps=new LinkedHashMap<String,String>();apps.put(P,"Moto 笔记");apps.put(SELF,"Hepta");
        for(Method m:LocalTaskController.class.getDeclaredMethods())if("prompt".equals(m.getName())&&m.getParameterTypes()[m.getParameterTypes().length-1]==NotesTaskPhaseGuard.class){
            m.setAccessible(true);return m.invoke(null,instruction,new AppCatalogueRanker(apps,instruction).search("",0),observed,history,null,prior,null,
                    new LocalRuntimeConfig(ModelProfile.LFM3,"npu",8192,4),new RepeatActionGuard(),new SameStateNoEffectGuard(),auth.frame(),null,
                    Collections.singletonMap("notes.create",new FixedIntentTarget("notes.create","Moto 笔记",10382,null)),completion,guard);
        }
        throw new AssertionError("production prompt entry unavailable");
    }
    private static void grammar(String name,DecisionGrammar grammar,ActionDecision decision,boolean expected)throws Exception{
        Map<String,Object> c=new LinkedHashMap<String,Object>();c.put("name",name);c.put("grammar",grammar.text);
        JSONObject o=new JSONObject().put("reason",decision.reason).put("action",decision.action).put("observation_id",decision.observationId);
        if("open".equals(decision.action))o.put("app_label",decision.appLabel);
        o.put("package",decision.packageName);if(decision.nodeId!=null)o.put("node_label",decision.nodeLabel).put("node_id",decision.nodeId);
        c.put("json",o.toString());c.put("accepted",expected);grammarCases.add(c);
    }
    private static void actualPrefixAndPrompt()throws Exception{
        TaskCompletionGate g=launched();Frame editor=frame(raw("step-01-after.json"));
        check(g.notesPhase(editor).launchProved&&g.notesPhase(editor).editorObserved&&!g.notesPhase(editor).listObserved,"original model-bound create and full body established, not save");
        replay(g,2);Frame other=frame(raw("step-02-after.json"));check(SELF.equals(other.packageName)&&!g.notesPhase(other).listObserved,"opening Hepta itself is not list evidence");
        replay(g,3);PhoneObservation observed=phone(raw("step-03-after.json"));Frame list=frame(raw("step-03-after.json"));
        NotesCompletionEvidence.ListEvidence item=NotesCompletionEvidence.list(list,BODY);
        check(item.matched&&"n11".equals(item.item.nodeId)&&"bound_note_summary_accessibility_text".equals(item.matchRule),"actual full raw summary and same-parent binding match unique list item");
        check(g.notesPhase(list).listObserved&&!g.verified(list),"actual open detour now recovers list evidence without proving reopen or completion");
        TaskAuthorization auth=TaskAuthorization.parse(owner);NotesTaskPhaseGuard guard=new NotesTaskPhaseGuard(TASK,auth);
        JSONObject lastRaw=raw("step-03-action.json");ActionDecision priorAction=action(lastRaw);
        LastModelDecisionProjection prior=LastModelDecisionProjection.fromOutcome(TASK,3,lastRaw.getString("model_run_id"),priorAction.observationId,priorAction,true,true,false);
        JSONArray history=new JSONArray();for(int step=1;step<=3;step++){
            JSONObject r=raw(String.format(java.util.Locale.ROOT,"step-%02d-action.json",step));ActionDecision d=action(r);
            history.put(new JSONObject().put("step",step).put("action",d.action).put("target_package",d.packageName).put("model_issued",true).put("accepted",true).put("dispatched",true).put("stale",false));
        }
        Object built=prompt(owner,observed,auth.bind(TASK),g,guard,history,prior);DecisionGrammar grammar=(DecisionGrammar)field(built,"grammar");
        NotesTaskPhaseGuard.Domain domain=(NotesTaskPhaseGuard.Domain)field(built,"phaseDomain");
        check("reopen_saved_item".equals(domain.projection.phase)&&domain.clickIds.equals(set("n11")),"same actual model prompt/grammar/postparse domain restores only proved list item");
        check(domain.editIds.isEmpty()&&domain.submitIds.isEmpty()&&!domain.fixedActions.contains("notes.create"),"recovery cannot rewrite or re-create");
        ActionDecision good=click(list,"n11",item.item.label),badNode=click(list,"n12",item.item.label),badLabel=click(list,"n11","错误条目");
        domain.requireCurrent(good);guard.requireCurrent(good);checks+=2;
        denied(()->domain.requireCurrent(badNode),"postparse rejects other saved note");denied(()->guard.requireCurrent(badNode),"dispatch rejects other saved note");
        grammar("recovered-current-list-item",grammar,good,true);grammar("other-list-node",grammar,badNode,false);grammar("wrong-list-label",grammar,badLabel,false);
        String text=(String)field(built,"text");JSONObject data=new JSONObject(text.substring("UNTRUSTED_DATA\n".length(),text.indexOf("\nOWNER\n")));
        JSONObject memory=data.getJSONObject("last_model_decision");
        check(!memory.has("reason")&&memory.getInt("step")==3&&"open".equals(memory.getString("action"))&&P.equals(memory.getString("target_package"))&&memory.getBoolean("dispatched"),"real repeated reason is absent while actual last dispatch facts remain");
        check(!text.contains(priorAction.reason)&&text.endsWith("\nOWNER\n"+owner)&&data.getJSONArray("events").length()==3,"reason feedback removed without changing owner or dropping event facts");
        check(priorAction.reason.codePointCount(0,priorAction.reason.length())==96&&priorAction.reason.equals(action(raw("step-02-action.json")).reason),"original v46 repeated capped reason is preserved as failed regression evidence");
        Field sys=LocalTaskController.class.getDeclaredField("SYSTEM");sys.setAccessible(true);String system=(String)sys.get(null);
        check(!system.contains("先引用最近已派发")&&system.contains("不复述OWNER正文或历史reason"),"system requests a current rationale without history recitation");
        List<?> proofs=(List<?>)g.evidence(list).get("proofs");Map<?,?> p=(Map<?,?>)proofs.get(proofs.size()-1);
        check("post_create_observed_list".equals(p.get("kind"))&&editor.observationId.equals(p.get("editor_observation_id"))&&list.observationId.equals(p.get("after_observation_id")),"new observation proof identifies prior body and current source frame");
        check(!((Boolean)domain.projection.evidence().get("automatic_dispatch")).booleanValue(),"phase recovery does not execute any action");
        guard.retire();denied(()->domain.requireCurrent(good),"retired task cannot borrow recovered domain");
        NotesTaskPhaseGuard foreign=new NotesTaskPhaseGuard(id(),auth);denied(()->foreign.prepare(g,list),"other task cannot borrow recovery proof");
    }
    private static void prerequisitesAndInvalidSources()throws Exception{
        Frame list=frame(raw("step-03-after.json")),editor=frame(raw("step-01-after.json"));
        TaskCompletionGate noCreate=gate();noCreate.observed(editor);noCreate.observed(list);check(!noCreate.notesPhase(list).listObserved,"preexisting body/list without actual new create never recovers");
        JSONObject receipt=raw("step-01-action.json");Frame before=frame(raw("step-01-before.json"));ActionDecision create=action(receipt);
        TaskCompletionGate noBody=gate();noBody.action(1,receipt.getString("model_run_id"),create,true,true,false,before,before,map(receipt.getJSONObject("fixed_intent")));
        noBody.observed(list);check(noBody.notesPhase(list).launchProved&&!noBody.notesPhase(list).editorObserved&&!noBody.notesPhase(list).listObserved,"accepted create without body cannot promote a later list");
        for(String key:new String[]{"task_id","model_run_id","payload_sha256"}){
            TaskCompletionGate bad=gate();Map<String,Object> fixed=map(receipt.getJSONObject("fixed_intent"));fixed.put(key,"foreign");
            bad.action(1,receipt.getString("model_run_id"),create,true,true,false,before,editor,fixed);bad.observed(list);check(!bad.notesPhase(list).listObserved,"foreign bound fixed fact refuses recovery: "+key);
        }
        TaskCompletionGate invalid=launched();invalid.invalidateInstalled("synthetic changed APK/UID");invalid.observed(list);check(!invalid.notesPhase(list).domainValid&&!invalid.notesPhase(list).listObserved,"changed installed identity refuses recovery");
        TaskCompletionGate foreign=launched();Frame f=copy(list,P,9,"11111111-1111-1111-1111-111111111111",list.nodes);foreign.observed(f);check(!foreign.notesPhase(f).domainValid&&!foreign.notesPhase(f).listObserved,"foreign display/generation refuses recovery");
        for(String mutation:new String[]{"summary_hash","source_resource","root_binding","duplicate_item","truncated","foreign_package","marker_prefix"}){
            JSONObject changed=raw("step-03-after.json");JSONArray nodes=changed.getJSONArray("nodes");JSONObject card=nodes.getJSONObject(11);
            JSONArray sources=card.getJSONArray("child_text_sources");JSONObject summary=sources.getJSONObject(2);
            if("summary_hash".equals(mutation))summary.put("text_sha256",ObservedImeEnter.hash("unrelated body"));
            if("marker_prefix".equals(mutation))summary.put("text_sha256",ObservedImeEnter.hash("Hepta-v46r1-b14e484e9ff9"));
            if("source_resource".equals(mutation))summary.put("view_id",P+":id/note_title");
            card.put("child_text_sources",replace(sources,2,summary));
            if("root_binding".equals(mutation))card.put("child_text_root_signature",ObservedImeEnter.hash("another parent"));
            nodes=replace(nodes,11,card);
            if("duplicate_item".equals(mutation))nodes.put(new JSONObject(card.toString()).put("id","n99"));
            changed.put("nodes",nodes);
            if("truncated".equals(mutation))changed.put("nodes_truncated",true);
            if("foreign_package".equals(mutation))changed.put("package",SELF);
            Frame badFrame=frame(changed);TaskCompletionGate bad=launched();bad.observed(badFrame);
            check(!bad.notesPhase(badFrame).listObserved,"raw source failure cannot recover: "+mutation);
        }
    }
    private static void laterObservationAndStrictReopen()throws Exception{
        Frame list=frame(raw("step-03-after.json")),originalEditor=frame(raw("step-01-after.json"));
        Frame reopened=copy(originalEditor,P,0,null,originalEditor.nodes);NotesCompletionEvidence.ListEvidence item=NotesCompletionEvidence.list(list,BODY);
        TaskCompletionGate async=launched();replay(async,2);async.observed(list);
        check(async.notesPhase(list).listObserved&&!async.verified(list),"a later actual reobserve can recover without inventing a navigation acknowledgement");
        TaskCompletionGate noClick=recovered();noClick.observed(reopened);check(!noClick.successClaim(5,id(),reopened).verified,"returning to body without same-item model click is insufficient");
        for(boolean[] flags:new boolean[][]{{false,false,false},{true,false,false},{true,true,true}}){
            TaskCompletionGate g=recovered();g.action(4,id(),click(list,item.item.nodeId,item.item.label),flags[0],flags[1],flags[2],list,reopened,null);
            check(!g.verified(reopened),"rejected, undispatched or stale click cannot prove reopen");
        }
        for(ActionDecision wrong:new ActionDecision[]{click(list,"n12",item.item.label),click(list,"n11","错误条目")}){
            TaskCompletionGate g=recovered();g.action(4,id(),wrong,true,true,false,list,reopened,null);check(!g.verified(reopened),"wrong node or label cannot prove reopen");
        }
        TaskCompletionGate g=recovered();g.action(4,id(),click(list,item.item.nodeId,item.item.label),true,true,false,list,reopened,null);
        check(g.verified(reopened),"explicitly synthetic subsequent model click plus full editor can close recovered chain");
        check(!g.successClaim(5,id(),reopened,false).verified&&g.successClaim(6,id(),reopened,true).verified,"actual final stability gate remains required");
        JSONObject original=raw("result.json");check("failed".equals(original.getString("status"))&&!original.getBoolean("completion_verified")&&!original.getJSONObject("completion_evidence").getBoolean("same_list_item_reopened"),"saved phone failure is never rewritten into successful completion");
    }
    private static void explicitSelfOpenRemainsAvailable()throws Exception{
        String request="打开 Hepta（org.trillionnium.hepta.local）。";TaskAuthorization auth=TaskAuthorization.parse(request);
        PhoneObservation observed=phone(raw("step-03-after.json"));TaskCompletionGate g=new TaskCompletionGate(TASK,request,auth);g.observed(frame(raw("step-03-after.json")));
        NotesTaskPhaseGuard guard=new NotesTaskPhaseGuard(TASK,auth);Object built=prompt(request,observed,auth.bind(TASK),g,guard,new JSONArray(),null);
        DecisionGrammar gb=(DecisionGrammar)field(built,"grammar");
        check(!guard.supported()&&gb.appLabels.labels.containsKey(SELF),"explicit request to open Hepta keeps ordinary open authority and catalogue");
        ActionDecision open=ActionDecision.parse(new JSONObject().put("reason","当前在笔记，用户要打开Hepta").put("action","open").put("observation_id",observed.id).put("app_label",gb.appLabels.labels.get(SELF)).put("package",SELF).toString(),ActionDecision.FIXED_INTENT_ACTION_SCHEMA);
        grammar("explicit-self-app-open",gb,open,true);
    }
    public static void main(String[] args)throws Exception{
        Path fixture=Paths.get(args[0]),out=Paths.get(args[1]);Files.createDirectories(out);
        byte[] bytes=Files.readAllBytes(fixture);check(FIXTURE_SHA.equals(ObservedImeEnter.hash(new String(bytes,StandardCharsets.UTF_8))),"frozen original v46 trace");
        JSONObject wrapper=new JSONObject(new String(bytes,StandardCharsets.UTF_8));files=wrapper.getJSONObject("files");owner=raw("owner.json").getString("instruction");
        check(BODY.equals(TaskCompletionGate.Contract.parse(owner,TaskAuthorization.parse(owner)).body),"fixture immutable literal body");
        actualPrefixAndPrompt();prerequisitesAndInvalidSources();laterObservationAndStrictReopen();explicitSelfOpenRemainsAvailable();
        Files.write(out.resolve("grammar-cases.json"),new JSONArray(grammarCases).toString().getBytes(StandardCharsets.UTF_8));
        check(FIXTURE_SHA.equals(ObservedImeEnter.hash(new String(Files.readAllBytes(fixture),StandardCharsets.UTF_8))),"original fixture unchanged");
        System.out.println("PASS "+checks+" notes recovery and reason feedback assertions; recorded_phone_task_still_failed=true; synthetic_reopen_only=true; phone_tested=false");
    }
}
