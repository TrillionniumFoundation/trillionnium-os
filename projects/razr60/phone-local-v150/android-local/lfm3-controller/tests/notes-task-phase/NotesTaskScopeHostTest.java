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

/** Replays original failed v47 observations and receipts through the production
 * bridge/gate. Any subsequent click/reopen/done is explicitly synthetic host IO,
 * not a missing phone action or a retrospective successful task. */
public final class NotesTaskScopeHostTest {
    private static final String FIXTURE_SHA="160346f0506ccac079efc1b86c5f1ec957a7d01cbfa24a83e365ae5787cf5669";
    private static final String P=NotesCompletionEvidence.NOTES,SELF="org.trillionnium.hepta.local";
    private static final String TASK="3a086c73df614b87a0cfd3cc06710942";
    private static final String BODY="Hepta-v47r1-ae39fd13e0d3。购物清单：牛奶、鸡蛋、面包。";
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
                new File("archived-v47-observation-not-live-phone-io"),raw.getString("screen_sha256"),raw.getString("observation_state_sha256"),
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
    private static String originalText(String name)throws Exception{
        JSONObject row=files.getJSONObject(name);String text=row.getString("raw_utf8");
        check(row.getString("sha256").equals(ObservedImeEnter.hash(text))&&row.getInt("bytes")==text.getBytes(StandardCharsets.UTF_8).length,"original archived text: "+name);return text;
    }
    private static JSONObject data(String text)throws Exception{return new JSONObject(text.substring("UNTRUSTED_DATA\n".length(),text.indexOf("\nOWNER\n")));}
    private static Map<String,FixedIntentTarget> targets(){
        Map<String,FixedIntentTarget> out=new LinkedHashMap<String,FixedIntentTarget>();
        out.put("notes.create",new FixedIntentTarget("notes.create","Moto 笔记",10382,null));
        out.put("web.search",new FixedIntentTarget("web.search","浏览器",10383,null));return out;
    }
    private static Object prompt(String instruction,PhoneObservation observed,TaskAuthorization.Gate auth,TaskCompletionGate completion,NotesTaskPhaseGuard guard,JSONArray history,SameStateNoEffectGuard noEffect)throws Exception{
        Map<String,String> apps=new LinkedHashMap<String,String>();apps.put(P,"Moto 笔记");apps.put(SELF,"Hepta");
        apps.put(targets().get("web.search").packageName,"浏览器");
        for(Method m:LocalTaskController.class.getDeclaredMethods())if("prompt".equals(m.getName())&&m.getParameterTypes()[m.getParameterTypes().length-1]==NotesTaskPhaseGuard.class){
            m.setAccessible(true);return m.invoke(null,instruction,new AppCatalogueRanker(apps,instruction).search("",0),observed,history,null,null,null,
                    new LocalRuntimeConfig(ModelProfile.LFM3,"npu",8192,4),new RepeatActionGuard(),noEffect,auth.frame(),null,targets(),completion,guard);
        }
        throw new AssertionError("production prompt entry unavailable");
    }
    private static String decision(Frame f,String tool,String node,String label,String target,String status)throws Exception{
        JSONObject o=new JSONObject().put("reason","explicit synthetic host choice, not an original phone action").put("action",tool).put("observation_id",f.observationId);
        if("open".equals(tool))o.put("app_label",SELF.equals(target)?"Hepta":"Moto 笔记").put("package",target);
        else if(org.trillionnium.hepta.background.FixedIntentTools.isTool(tool)){
            FixedIntentTarget t=targets().get(tool);o.put("app_label",t.appLabel).put("package",t.packageName).put("notes.create".equals(tool)?"text":"query","notes.create".equals(tool)?BODY:"无关查询");
        }else{
            o.put("package",f.packageName);
            if(node!=null)o.put("node_label",label).put("node_id",node);
            if("scroll".equals(tool))o.put("direction","forward");
            if("type".equals(tool))o.put("text","不要改写");
            if("wait".equals(tool))o.put("duration_ms",1000);
            if("find_app".equals(tool))o.put("query","Hepta").put("offset",0);
            if("done".equals(tool))o.put("status",status).put("summary","host-only outcome reporting choice");
        }
        return o.toString();
    }
    private static ActionDecision parsed(String text)throws Exception{return ActionDecision.parse(text,ActionDecision.FIXED_INTENT_ACTION_SCHEMA);}
    private static JSONArray history(JSONArray archived)throws Exception{
        JSONArray out=new JSONArray();
        for(int i=0;i<archived.length();i++){
            JSONObject row=new JSONObject(archived.getJSONObject(i).toString());
            // The lightweight archive JSON IO parses integral numbers as Long;
            // the real controller records step using its Java int loop counter.
            // Restore that IO type without changing its numeric or text facts.
            row.put("step",row.getInt("step"));out.put(row);
        }
        return out;
    }
    private static String canonical(ActionDecision d)throws Exception{
        JSONObject o=new JSONObject().put("reason",d.reason).put("action",d.action).put("observation_id",d.observationId);
        if(d.appLabel!=null)o.put("app_label",d.appLabel);o.put("package",d.packageName);
        if(d.nodeId!=null)o.put("node_label",d.nodeLabel).put("node_id",d.nodeId);
        if(d.text!=null)o.put("text",d.text);if(d.direction!=null)o.put("direction",d.direction);
        if(d.query!=null)o.put("query",d.query);if("find_app".equals(d.action))o.put("offset",d.offset);
        if("wait".equals(d.action))o.put("duration_ms",d.durationMs);
        if("done".equals(d.action))o.put("status",d.status).put("summary",d.summary);
        return o.toString();
    }
    private static void grammar(String name,DecisionGrammar grammar,String json,boolean expected){
        Map<String,Object> c=new LinkedHashMap<String,Object>();c.put("name",name);c.put("grammar",grammar.text);c.put("json",json);c.put("accepted",expected);grammarCases.add(c);
    }
    private static void recordedScopeAndCurrentFacts()throws Exception{
        TaskCompletionGate g=gate();TaskAuthorization auth=TaskAuthorization.parse(owner);TaskAuthorization.Gate authority=auth.bind(TASK);
        NotesTaskPhaseGuard guard=new NotesTaskPhaseGuard(TASK,auth);int lists=0;
        for(int step=1;step<=20;step++){
            String prefix=String.format(java.util.Locale.ROOT,"step-%02d-",step);JSONObject beforeRaw=raw(prefix+"before.json");
            PhoneObservation observed=phone(beforeRaw);Frame before=frame(beforeRaw);g.observed(before);
            JSONObject original=data(originalText(prefix+"prompt.txt"));JSONArray events=original.getJSONArray("events");
            Object built=prompt(owner,observed,authority,g,guard,history(events),new SameStateNoEffectGuard());
            DecisionGrammar gb=(DecisionGrammar)field(built,"grammar");NotesTaskPhaseGuard.Domain domain=(NotesTaskPhaseGuard.Domain)field(built,"phaseDomain");
            String text=(String)field(built,"text");JSONObject now=data(text),phase=now.getJSONObject("task_phase"),completion=now.getJSONObject("completion");
            TaskCompletionGate.NotesPhase facts=g.notesPhase(before);
            check(text.endsWith("\nOWNER\n"+owner)&&now.getJSONArray("events").toString().equals(events.toString()),"complete actual event facts and immutable OWNER retained at step "+step);
            check(text.indexOf("\n\"events\":")<text.indexOf("\n\"screen\":")&&text.indexOf("\n\"screen\":")<text.indexOf("\n\"completion\":")
                    &&text.indexOf("\n\"completion\":")<text.indexOf("\n\"task_phase\":"),"same-frame goal evidence follows current screen after all history");
            check(facts.currentSurface().equals(phase.getString("current_surface"))&&facts.currentSurface().equals(completion.getString("current_surface")),"current surface is the actual provider fact, not historical phase");
            check(completion.getBoolean("current_editor_body_matched")==facts.currentBody&&phase.getBoolean("current_editor_body_matched")==facts.currentBody,"same actual current body predicate in both projections");
            check("cumulative_task_evidence_not_current_screen".equals(completion.getString("progress_scope"))
                    &&completion.getBoolean("editor_body_observed")==facts.editorObserved&&completion.getBoolean("list_observed")==facts.listObserved,"sticky progress facts retain their meaning");
            check(!gb.actions.contains("web.search")&&!domain.fixedActions.contains("web.search"),"supported Notes excludes unrelated web tool at every phase");
            check(domain.openPackages.equals(new TreeSet<String>(gb.appLabels.labels.keySet()))
                    &&domain.openPackages.equals(P.equals(before.packageName)?set():set(P)),"same authorized task package intersection in grammar and dispatch domain");
            check(domain.scrollDirections.equals(gb.scrollDirections),"dispatch stores only the same actual nonempty scroll directions as grammar");
            denied(()->domain.requireCurrent(parsed(decision(before,"web.search",null,null,null,null))),"web direct postparse attempt denied");
            if("reopen_saved_item".equals(domain.projection.phase)){
                lists++;check(set("click","wait","done").equals(new TreeSet<String>(gb.actions))&&set("click","wait","done").equals(domain.toolMask),"verified list tool set is exactly click/wait/done");
                check(domain.clickIds.equals(set("n11"))&&domain.editIds.isEmpty()&&domain.submitIds.isEmpty()&&domain.openPackages.isEmpty()
                        &&domain.fixedActions.isEmpty()&&domain.scrollDirections.isEmpty(),"only current unique target capability survives");
                check("verified_note_list".equals(phase.getString("current_surface"))&&"n11".equals(phase.getString("current_list_item_node_id"))
                        &&!phase.getBoolean("current_editor_body_matched")&&completion.getBoolean("editor_body_observed"),"current list is unambiguously separated from historical editor evidence");
                check(!now.getJSONObject("screen").has("scroll_actions")&&now.getJSONArray("fixed_intent_tools").length()==0&&now.getJSONArray("open_allowed_packages").length()==0,"prompt affordances agree with closed list grammar");
                JSONObject oldBudget=raw(prefix+"budget-0.json");
                check(oldBudget.getJSONArray("grammar_actions").toString().contains("\"click\"")&&oldBudget.getJSONArray("grammar_actions").toString().contains("\"back\""),"original failed model really had target click and loop navigation available");
                JSONObject oldReceipt=raw(prefix+"action.json");ActionDecision oldAction=action(oldReceipt);
                check(!"click".equals(oldAction.action)&&oldReceipt.getBoolean("dispatched"),"original wrong-way action was real and dispatched");
                denied(()->domain.requireCurrent(oldAction),"original loop action is no longer permitted on strict list");
                grammar(prefix+"original-loop",gb,canonical(oldAction),false);
                String label=NotesCompletionEvidence.list(before,BODY).item.label;
                String click=decision(before,"click","n11",label,null,null);domain.requireCurrent(parsed(click));guard.requireCurrent(parsed(click));checks+=2;
                grammar(prefix+"current-item",gb,click,true);
                for(String tool:new String[]{"find_app","back","home","open","scroll","web.search","notes.create","type","submit"}){
                    boolean node="scroll".equals(tool)||"type".equals(tool)||"submit".equals(tool);
                    String deniedJson=decision(before,tool,node?"n11":null,node?label:null,SELF,null);
                    denied(()->domain.requireCurrent(parsed(deniedJson)),"task list domain rejects "+tool);
                    grammar(prefix+"blocked-"+tool,gb,deniedJson,false);
                }
                for(String status:new String[]{"partial","failure","success"}){
                    String done=decision(before,"done",null,null,null,status);domain.requireCurrent(parsed(done));checks++;
                    grammar(prefix+"done-"+status,gb,done,true);
                }
                String wait=decision(before,"wait",null,null,null,null);domain.requireCurrent(parsed(wait));checks++;grammar(prefix+"wait",gb,wait,true);
                check(!g.verified(before),"done branch never manufactures same-item reopen or success");
            }else if("leave_created_editor".equals(domain.projection.phase)){
                check(domain.toolMask==null&&gb.actions.contains("back"),"legitimate editor-to-list navigation remains selectable");
            }
            if(step==12){
                JSONObject old=raw(prefix+"action.json");check("web.search".equals(action(old).action),"original unrelated browser action retained as regression");
                grammar("step12-unrelated-web",gb,canonical(action(old)),false);
            }
            if(step==20)check("observation_required".equals(phase.getString("phase"))&&"verified_note_editor".equals(phase.getString("current_surface"))
                    &&phase.getBoolean("current_editor_body_matched")&&phase.isNull("current_list_item_node_id")
                    &&phase.getString("next_goal").contains("尚缺")&&!g.verified(before),"back-to-editor never becomes verified same-item model reopen, while current body remains truthful");
            // Replay original recorded outcomes to inspect the next original
            // screen. This does not execute or authorize them under v48.
            replay(g,step);
        }
        JSONObject original=raw("result.json");check(lists==5&&"failed".equals(original.getString("status"))&&!original.getBoolean("completion_verified")
                &&!g.verified(frame(raw("step-20-after.json"))),"all five true target-list frames checked; archived failure remains failed");
    }
    private static void emptyCapabilityAndUnknownContracts()throws Exception{
        TaskCompletionGate g=gate();for(int step=1;step<=8;step++)replay(g,step);
        JSONObject rawList=raw("step-09-before.json");PhoneObservation list=phone(rawList);Frame f=frame(rawList);g.observed(f);
        TaskAuthorization auth=TaskAuthorization.parse(owner);NotesTaskPhaseGuard guard=new NotesTaskPhaseGuard(TASK,auth);
        SameStateNoEffectGuard blocked=new SameStateNoEffectGuard();String label=NotesCompletionEvidence.list(f,BODY).item.label;
        ActionDecision click=parsed(decision(f,"click","n11",label,null,null));blocked.observed(click,P,list.state,P,list.state,true,true,false);
        Object b=prompt(owner,list,auth.bind(TASK),g,guard,new JSONArray(),blocked);DecisionGrammar gb=(DecisionGrammar)field(b,"grammar");
        NotesTaskPhaseGuard.Domain domain=(NotesTaskPhaseGuard.Domain)field(b,"phaseDomain");
        check(set("wait","done").equals(new TreeSet<String>(gb.actions))&&domain.clickIds.isEmpty(),"task mask never adds a no-effect-filtered current target");
        denied(()->domain.requireCurrent(click),"suppressed click remains unavailable after parse");
        for(String status:new String[]{"partial","failure"})grammar("empty-domain-"+status,gb,decision(f,"done",null,null,null,status),true);
        for(String request:new String[]{"打开 Hepta（org.trillionnium.hepta.local）。","通过 web.search 网页查询商品信息。"}){
            TaskAuthorization a=TaskAuthorization.parse(request);TaskCompletionGate unknown=new TaskCompletionGate(TASK,request,a);unknown.observed(f);
            NotesTaskPhaseGuard other=new NotesTaskPhaseGuard(TASK,a);Object built=prompt(request,list,a.bind(TASK),unknown,other,new JSONArray(),new SameStateNoEffectGuard());
            String text=(String)field(built,"text");JSONObject d=data(text);DecisionGrammar grammar=(DecisionGrammar)field(built,"grammar");
            check(!other.supported()&&!d.has("task_phase")&&!d.getJSONObject("completion").has("current_surface"),"unknown/WEB does not acquire Notes state or mask");
            check(text.indexOf("\n\"completion\":")<text.indexOf("\n\"events\":")&&text.indexOf("\n\"events\":")<text.indexOf("\n\"screen\":"),"unknown/WEB retains the exact former top-level layout");
            check(grammar.appLabels.labels.containsKey(SELF)&&grammar.actions.contains("web.search")&&grammar.actions.contains("back"),"ordinary self-app open, web and navigation remain available outside Notes contract");
            check(!unknown.verified(f),"unknown/WEB is not granted business completion");
        }
        NotesTaskPhaseGuard.Projection p=guard.prepare(g,f);
        denied(()->p.bind(set("n11"),set(),set(),targets(),set(SELF),Collections.<String,ObservedScrollActions>emptyMap()),"caller cannot reinsert removed open/fixed targets");
        denied(()->p.bind(set("n11"),set(),set(),Collections.<String,FixedIntentTarget>emptyMap(),set(),Collections.singletonMap("n11",ObservedScrollActions.observed(Arrays.asList("forward")))),"caller cannot reinsert real scroll capability");
        NotesTaskPhaseGuard.Domain legacy=p.bind(set("n11"),set(),set(),Collections.<String,FixedIntentTarget>emptyMap());guard.publish(legacy);
        denied(()->legacy.requireCurrent(parsed(decision(f,"open",null,null,P,null))),"legacy bind never grants an unbound Notes launch");
        TaskAuthorization waitOnly=TaskAuthorization.parse("只允许等待和结束。");
        check(!waitOnly.allowedTools.contains("click")&&!waitOnly.allowedTools.contains("open")&&!waitOnly.allowedTools.contains("scroll"),"explicit immutable authority excludes side effects");
        NotesTaskPhaseGuard restrictive=new NotesTaskPhaseGuard(TASK,waitOnly);NotesTaskPhaseGuard.Projection rp=restrictive.prepare(null,f);
        denied(()->rp.bind(set("n11"),set(),set(),Collections.<String,FixedIntentTarget>emptyMap()),"phase bind cannot grant owner-banned click");
        denied(()->rp.bind(set(),set(),set(),Collections.<String,FixedIntentTarget>emptyMap(),set(P),Collections.<String,ObservedScrollActions>emptyMap()),"phase bind cannot grant owner-banned open");
        denied(()->rp.bind(set(),set(),set(),Collections.<String,FixedIntentTarget>emptyMap(),set(),Collections.singletonMap("n11",ObservedScrollActions.observed(Arrays.asList("forward")))),"phase bind cannot grant owner-banned real scroll direction");
        ObservedTargetLabels labels=ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,f.observationId,P,Collections.singletonMap("n11",label));
        DecisionGrammar narrow=DecisionGrammar.createImeAuthorized(f.observationId,P,set(),set("n11"),set(),Collections.<String,ObservedScrollActions>emptyMap(),
                Collections.<String,ObservedImeEnter>emptyMap(),labels,ObservedAppLabels.create(ObservedAppLabels.SCHEMA,f.observationId,P,Collections.<String,String>emptyMap()),waitOnly.bind(TASK).frame(),false,set("click","wait","done"));
        check(set("wait","done").equals(new TreeSet<String>(narrow.actions)),"task tool mask is intersected with immutable owner authority");
        guard.retire();denied(()->legacy.requireCurrent(click),"retired list mask cannot be reused");
    }
    private static void actualServiceDispatchRefusals(Path out)throws Exception{
        QualificationScopeHostTest.output=out;Files.createDirectories(out);
        try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            TaskCompletionGateHostTest.installPackage(e,"notes.create");TaskCompletionGateHostTest.installPackage(e,"web.search");
            e.service.observationRows=()->Arrays.asList(
                    TaskCompletionGateHostTest.row("n0",P,BODY,"",new Rect(10,100,600,300),false,true,false),
                    TaskCompletionGateHostTest.row("n1",P,"",P+":id/view_pager2",new Rect(0,80,1000,2000),false,false,true),
                    TaskCompletionGateHostTest.row("n2",P,"所有笔记",P+":id/title_text",new Rect(0,0,300,80),false,false,false));
            e.service.prepare(P);check(e.service.acquireTask(e.task,()->{}),"service lease acquired");
            e.service.bindQualificationScope(e.task,QualificationScopeConfig.capture(e.service,e.task,null,e.runtime));
            TaskAuthorization auth=TaskAuthorization.parse(owner);TaskAuthorization.Gate a=e.service.bindTaskAuthorization(e.task,auth);
            NotesTaskPhaseGuard guard=e.service.notesTaskPhaseFor(e.task,a);
            JSONObject installed=raw("completion-installed-identity.json");
            TaskCompletionGate g=new TaskCompletionGate(e.task,owner,auth);g.bindInstalled(new NotesCompletionEvidence.Installed(P,installed.getInt("uid"),Collections.singletonMap("base",installed.getJSONObject("apk_hashes").getString("base"))));
            Frame initial=frame(raw("step-01-before.json")),editor=frame(raw("step-01-after.json"));String run=id();ActionDecision create=parsed(decision(initial,"notes.create",null,null,null,null));
            FixedIntentAttemptGuard ledger=new FixedIntentAttemptGuard(e.task,v->{});FixedIntentAttemptGuard.Attempt attempt=ledger.consume(new FixedIntentAttemptGuard.Binding(e.task,run,initial.observationId,initial.packageName,initial.windowId,initial.displayId,initial.backgroundGeneration,targets().get("notes.create"),BODY));
            ledger.entering(attempt);g.action(1,run,create,true,true,false,initial,editor,ledger.finished(attempt,true));
            Method bridge=LocalTaskController.class.getDeclaredMethod("completionFrame",PhoneObservation.class);bridge.setAccessible(true);Frame current=(Frame)bridge.invoke(null,e.service.current);g.observed(current);
            Object built=prompt(owner,e.service.current,a,g,guard,new JSONArray(),new SameStateNoEffectGuard());DecisionGrammar gb=(DecisionGrammar)field(built,"grammar");
            check(set("click","wait","done").equals(new TreeSet<String>(gb.actions)),"actual prompt publishes strict phase on service-owned lease");
            for(String tool:new String[]{"find_app","back","home","open","scroll","web.search"}){
                String payload=decision(current,tool,"scroll".equals(tool)?"n0":null,"scroll".equals(tool)?ObservedTargetLabels.project(BODY):null,SELF,null);
                final HeptaAccessibilityService.ActionOutcome[] result={null};
                e.service.perform(e.task,e.service.current,parsed(payload),gb.targets,targets().get(tool),a,id(),()->false,r->result[0]=r);
                check(result[0]!=null&&!result[0].accepted&&!result[0].dispatched&&result[0].detail.contains("notes_task_phase")&&e.service.effects()==0,"actual service refuses removed tool before any effect: "+tool);
            }
            for(String status:new String[]{"partial","failure"}){
                final HeptaAccessibilityService.ActionOutcome[] result={null};e.service.perform(e.task,e.service.current,parsed(decision(current,"done",null,null,null,status)),gb.targets,null,a,id(),()->false,r->result[0]=r);
                check(result[0]!=null&&result[0].accepted&&!result[0].dispatched&&e.service.effects()==0&&!g.verified(current),"failure/partial reports remain possible without business success or an action");
            }
            e.service.releaseTask(e.task);
        }
    }
    public static void main(String[] args)throws Exception{
        Path fixture=Paths.get(args[0]),out=Paths.get(args[1]);Files.createDirectories(out);
        byte[] bytes=Files.readAllBytes(fixture);check(FIXTURE_SHA.equals(ObservedImeEnter.hash(new String(bytes,StandardCharsets.UTF_8))),"frozen original v47 trace SHA");
        files=new JSONObject(new String(bytes,StandardCharsets.UTF_8)).getJSONObject("files");owner=raw("owner.json").getString("instruction");
        check(BODY.equals(TaskCompletionGate.Contract.parse(owner,TaskAuthorization.parse(owner)).body),"fixture original immutable body");
        recordedScopeAndCurrentFacts();emptyCapabilityAndUnknownContracts();actualServiceDispatchRefusals(out.resolve("service-io"));
        Files.write(out.resolve("grammar-cases.json"),new JSONArray(grammarCases).toString().getBytes(StandardCharsets.UTF_8));
        check(FIXTURE_SHA.equals(ObservedImeEnter.hash(new String(Files.readAllBytes(fixture),StandardCharsets.UTF_8))),"original trace unchanged");
        System.out.println("PASS "+checks+" Notes task scope and current-surface assertions; original_v47_failed=true; synthetic_service_io=true; phone_tested=false");
    }
}
