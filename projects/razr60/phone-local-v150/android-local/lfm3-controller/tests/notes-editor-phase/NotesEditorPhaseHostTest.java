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

/** Replays exact observations/actions from the partial v48 Notes task through
 * real production projection, grammar, postparse and service guards. Candidate
 * actions, service leases and navigation pairings are explicit synthetic host
 * IO; no failed phone trace is upgraded to successful execution. */
public final class NotesEditorPhaseHostTest {
    private static final String FIXTURE_SHA="24d3361fb5f5e30f999dc9781636484211d81db2d16f5626430bc8573bcbe70b";
    private static final String P=NotesCompletionEvidence.NOTES,SELF="org.trillionnium.hepta.local";
    private static final String TASK="567fa300f014405ebc37966308659e69";
    private static final String BODY="Hepta-v48r1-15b0be037be9。购物清单：牛奶、鸡蛋、面包。";
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
    private static String value(JSONObject o,String key,String fallback)throws Exception{return o.has(key)&&!o.isNull(key)?o.getString(key):fallback;}
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
                new File("archived-v48-observation-not-live-phone-io"),raw.getString("screen_sha256"),raw.getString("observation_state_sha256"),
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
    private static void postparse(Object built,ActionDecision action,TaskAuthorization.Gate auth)throws Exception{
        DecisionGrammar gb=(DecisionGrammar)field(built,"grammar");
        @SuppressWarnings("unchecked") Set<String> packages=(Set<String>)field(built,"appPackages");
        NotesTaskPhaseGuard.Domain domain=(NotesTaskPhaseGuard.Domain)field(built,"phaseDomain");
        ActionPolicy.validateAuthorizedDecision(action,domain.projection.packageName,packages,gb.targets,gb.appLabels,auth,gb.authorization,gb.fixedIntentTargets);
        Method clickCheck=built.getClass().getDeclaredMethod("requireTextOnlyClick",ActionDecision.class);clickCheck.setAccessible(true);
        try{clickCheck.invoke(built,action);}
        catch(java.lang.reflect.InvocationTargetException e){if(e.getCause() instanceof Exception)throw (Exception)e.getCause();throw e;}
        gb.requireCompletionStatus(action);
        domain.requireCurrent(action);
        ((CalculatorTaskInputGuard.Domain)field(built,"calculatorDomain")).requireCurrent(action);
    }
    private static JSONArray array(JSONArray rows,int index){
        Object value=rows.get(index);
        if(value instanceof JSONArray)return (JSONArray)value;
        if(value instanceof java.util.Collection<?>)return new JSONArray((java.util.Collection<?>)value);
        throw new AssertionError("actual nested array required");
    }
    private static JSONArray node(JSONArray rows,String id)throws Exception{
        for(int i=0;i<rows.length();i++){JSONArray r=array(rows,i);if(id.equals(r.get(0)))return r;}
        throw new AssertionError("actual projected node missing: "+id);
    }
    private static Set<String> strings(JSONArray rows)throws Exception{
        Set<String> out=new TreeSet<String>();for(int i=0;i<rows.length();i++)out.add((String)rows.get(i));return out;
    }
    private static void allRemovedChoices(Object built,Frame f,TaskAuthorization.Gate authority,String prefix)throws Exception{
        DecisionGrammar gb=(DecisionGrammar)field(built,"grammar");
        NotesTaskPhaseGuard.Domain domain=(NotesTaskPhaseGuard.Domain)field(built,"phaseDomain");
        for(String tool:new String[]{"click","type","submit","scroll","open","home","find_app","notes.create","web.search"}){
            String n=("click".equals(tool)||"type".equals(tool)||"submit".equals(tool))?"n11":"scroll".equals(tool)?"n5":null;
            String label="n5".equals(n)?"NoteEditor":n==null?null:ObservedTargetLabels.project(BODY+"\n");
            String payload=decision(f,tool,n,label,P,null);ActionDecision candidate=parsed(payload);
            grammar(prefix+"-removed-"+tool,gb,payload,false);
            denied(()->domain.requireCurrent(candidate),"current published domain rejects "+tool);
            denied(()->postparse(built,candidate,authority),"real postparse checks reject "+tool);
        }
        String title=decision(f,"click","n1","标题",null,null);
        grammar(prefix+"-title-click",gb,title,false);
        denied(()->postparse(built,parsed(title),authority),"labeled title is not a save action");
    }
    private static void recordedEditorDecisions()throws Exception{
        TaskCompletionGate g=gate();TaskAuthorization auth=TaskAuthorization.parse(owner);TaskAuthorization.Gate authority=auth.bind(TASK);
        NotesTaskPhaseGuard guard=new NotesTaskPhaseGuard(TASK,auth);int narrowed=0;
        for(int step=1;step<=5;step++){
            String prefix=String.format(java.util.Locale.ROOT,"step-%02d-",step);JSONObject beforeRaw=raw(prefix+"before.json");
            Frame before=frame(beforeRaw);g.observed(before);JSONObject oldReceipt=raw(prefix+"action.json");
            JSONObject original=data(originalText(prefix+"prompt.txt"));JSONArray events=original.getJSONArray("events");
            Object built=prompt(owner,phone(beforeRaw),authority,g,guard,history(events),new SameStateNoEffectGuard());
            DecisionGrammar gb=(DecisionGrammar)field(built,"grammar");NotesTaskPhaseGuard.Domain domain=(NotesTaskPhaseGuard.Domain)field(built,"phaseDomain");
            String text=(String)field(built,"text");JSONObject projected=data(text),phase=projected.getJSONObject("task_phase");
            check(text.endsWith("\nOWNER\n"+owner)&&projected.getJSONArray("events").toString().equals(events.toString()),"actual history and literal OWNER retained at "+step);
            check(!phase.getBoolean("automatic_dispatch")&&!phase.getBoolean("grants_tool_authority"),"projection never dispatches or grants authority");
            if(step==2||step==3){
                narrowed++;JSONObject oldPhase=oldReceipt.getJSONObject("task_phase");
                check("leave_created_editor".equals(oldPhase.getString("phase"))&&oldPhase.getBoolean("current_editor_body_matched")&&oldPhase.isNull("task_tool_filter"),"actual old action had full editor proof but no phase tool mask");
                check("leave_created_editor".equals(phase.getString("phase"))&&"verified_note_editor".equals(phase.getString("current_surface"))&&phase.getBoolean("current_editor_body_matched"),"candidate uses the same real current editor evidence");
                check(set("back","wait","done").equals(new TreeSet<String>(gb.actions))&&set("back","wait","done").equals(domain.toolMask)
                        &&set("back","wait","done").equals(strings(phase.getJSONArray("task_tool_filter"))),"grammar, immutable domain and prompt have identical editor tool set");
                check(domain.clickIds.isEmpty()&&domain.editIds.isEmpty()&&domain.submitIds.isEmpty()&&domain.fixedActions.isEmpty()
                        &&domain.openPackages.isEmpty()&&domain.scrollDirections.isEmpty(),"editor phase removes every targeted edit, click, fixed, scroll and launch capability");
                @SuppressWarnings("unchecked") Set<String> finalClicks=(Set<String>)field(built,"clickNodeIds");
                check(finalClicks.equals(domain.clickIds),"PromptFrame final clicks match the published domain");
                JSONArray nodes=projected.getJSONObject("screen").getJSONArray("nodes");
                check("标题".equals(node(nodes,"n1").get(1))&&ObservedTargetLabels.project(BODY+"\n").equals(node(nodes,"n11").get(1)),"actual visible title/body labels remain observations, without inventing save labels");
                for(int j=0;j<nodes.length();j++){
                    String flags=(String)array(nodes,j).get(3);
                    check(flags.indexOf('c')<0&&flags.indexOf('t')<0&&flags.indexOf('s')<0,"no node action flags survive editor mask");
                }
                ActionDecision old=action(oldReceipt);grammar(prefix+"original-accepted-click-now-denied",gb,canonical(old),false);
                denied(()->domain.requireCurrent(old),"original exact model click rejected by current domain");
                denied(()->postparse(built,old,authority),"original exact model click rejected after parse");
                allRemovedChoices(built,before,authority,prefix);
                for(String tool:new String[]{"back","wait"}){
                    String payload=decision(before,tool,null,null,null,null);grammar(prefix+tool,gb,payload,true);
                    postparse(built,parsed(payload),authority);checks++;
                }
                for(String status:new String[]{"success","partial","failure"}){
                    String payload=decision(before,"done",null,null,null,status);boolean eligible=!"success".equals(status);
                    grammar(prefix+"done-"+status,gb,payload,eligible);
                    if(eligible)postparse(built,parsed(payload),authority);
                    else denied(()->postparse(built,parsed(payload),authority),"saved-list and reopen evidence are still absent");
                    check(!g.verified(before),"outcome reporting cannot manufacture completion evidence");
                }
            }else if(step>=4){
                check("observation_required".equals(phase.getString("phase"))&&!phase.getBoolean("current_editor_body_matched")&&domain.toolMask==null,
                        "actual title dialog is not misreported as the prior verified editor");
                int editable=0;boolean bodyStillPresent=false;JSONArray rows=beforeRaw.getJSONArray("nodes");
                for(int i=0;i<rows.length();i++){JSONObject n=rows.getJSONObject(i);if(n.optBoolean("editable",false))editable++;if(value(n,"text","").startsWith(BODY))bodyStillPresent=true;}
                check(editable==2&&bodyStillPresent,"actual title dialog has two editors; provider refusal is not disappearance of the body");
            }else{
                check("create_required".equals(phase.getString("phase"))&&gb.actions.contains("notes.create")&&!gb.actions.contains("type"),"fresh task still requires its model-selected literal-body creation");
            }
            // Replay the old, recorded transition only to inspect the next old
            // frame. It is not a claim the new controller dispatches this choice.
            replay(g,step);
        }
        JSONObject original=raw("result.json");
        check(narrowed==2&&"partial".equals(original.getString("status"))&&original.getInt("steps")==5&&!original.getBoolean("completion_verified"),"original v48 partial status remains unchanged");
        check(!g.verified(frame(raw("step-05-after.json")))&&!g.notesPhase(frame(raw("step-05-after.json"))).listObserved,
                "raw replay never invents saved list or reopened evidence");
        check(!raw("step-04-completion-check.json").getBoolean("completion_verified"),"actual success claim was refused before the model reported partial");
    }
    private static void provenanceAndIntersection()throws Exception{
        Frame editor=frame(raw("step-02-before.json"));TaskAuthorization auth=TaskAuthorization.parse(owner);
        NotesTaskPhaseGuard guard=new NotesTaskPhaseGuard(TASK,auth);TaskCompletionGate fresh=gate();fresh.observed(editor);
        NotesTaskPhaseGuard.Projection existing=guard.prepare(fresh,editor);
        check("create_required".equals(existing.phase)&&existing.toolMask()==null&&existing.clicks(set("n11","n1")).isEmpty(),"preexisting same-body editor cannot inherit a newly-created phase");
        TaskCompletionGate g=launched();g.observed(editor);NotesTaskPhaseGuard.Projection p=guard.prepare(g,editor);
        check("leave_created_editor".equals(p.phase),"task-bound create and actual current complete body enable the narrow phase");
        denied(()->new NotesTaskPhaseGuard(id(),auth).prepare(g,editor),"another task cannot borrow creation evidence");
        denied(()->new NotesTaskPhaseGuard(TASK,TaskAuthorization.parse(owner.replace(BODY,"不同正文。"))).prepare(g,editor),"another immutable owner cannot borrow creation evidence");
        Frame otherDisplay=copy(editor,P,10,"609f2475-8874-4fda-a36e-ef12a028e44b",editor.nodes);
        check("observation_required".equals(guard.prepare(g,otherDisplay).phase),"foreign display/generation cannot retain editor phase");
        check("observation_required".equals(guard.prepare(g,frame(raw("step-01-before.json"))).phase),"actual unrelated browser is not treated as the earlier editor");
        g.invalidateInstalled("synthetic installed identity changed");
        check("observation_required".equals(guard.prepare(g,editor).phase),"invalidated installed identity cannot retain editor phase");
        for(String request:new String[]{"打开 Hepta（org.trillionnium.hepta.local）。","通过 web.search 网页查询商品信息。"}){
            TaskAuthorization a=TaskAuthorization.parse(request);TaskCompletionGate unknown=new TaskCompletionGate(TASK,request,a);unknown.observed(editor);
            NotesTaskPhaseGuard other=new NotesTaskPhaseGuard(TASK,a);Object built=prompt(request,phone(raw("step-02-before.json")),a.bind(TASK),unknown,other,new JSONArray(),new SameStateNoEffectGuard());
            DecisionGrammar gb=(DecisionGrammar)field(built,"grammar");
            check(!other.supported()&&!data((String)field(built,"text")).has("task_phase")&&gb.actions.contains("open")&&gb.actions.contains("click")&&gb.actions.contains("web.search"),"unknown/WEB retains ordinary action availability on same actual screen");
        }
        TaskAuthorization waitOnly=TaskAuthorization.parse("只允许等待和结束。");
        ObservedTargetLabels labels=ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,editor.observationId,P,Collections.<String,String>emptyMap());
        DecisionGrammar narrow=DecisionGrammar.createImeAuthorized(editor.observationId,P,set(),set(),set(),Collections.<String,ObservedScrollActions>emptyMap(),
                Collections.<String,ObservedImeEnter>emptyMap(),labels,ObservedAppLabels.create(ObservedAppLabels.SCHEMA,editor.observationId,P,Collections.<String,String>emptyMap()),waitOnly.bind(TASK).frame(),false,p.toolMask());
        check(set("wait","done").equals(new TreeSet<String>(narrow.actions)),"editor phase intersects, never expands, immutable owner authority");
        grammar("owner-denied-back",narrow,decision(editor,"back",null,null,null,null),false);
        grammar("owner-retained-wait",narrow,decision(editor,"wait",null,null,null,null),true);
        for(String status:new String[]{"partial","failure"})grammar("owner-retained-"+status,narrow,decision(editor,"done",null,null,null,status),true);
        TaskCompletionGate currentGate=launched();currentGate.observed(editor);TaskAuthorization.Gate authority=auth.bind(TASK);
        Object first=prompt(owner,phone(raw("step-02-before.json")),authority,currentGate,guard,new JSONArray(),new SameStateNoEffectGuard());
        NotesTaskPhaseGuard.Domain stale=(NotesTaskPhaseGuard.Domain)field(first,"phaseDomain");ActionDecision oldBack=parsed(decision(editor,"back",null,null,null,null));
        Object replacement=prompt(owner,phone(raw("step-03-before.json")),authority,currentGate,guard,new JSONArray(),new SameStateNoEffectGuard());
        NotesTaskPhaseGuard.Domain live=(NotesTaskPhaseGuard.Domain)field(replacement,"phaseDomain");
        denied(()->stale.requireCurrent(oldBack),"replaced prompt domain cannot be reused after parse");
        denied(()->live.requireCurrent(oldBack),"new domain rejects old observation identity");
        ActionDecision newBack=parsed(decision(frame(raw("step-03-before.json")),"back",null,null,null,null));
        live.requireCurrent(newBack);checks++;guard.retire();
        denied(()->live.requireCurrent(newBack),"retired task domain cannot dispatch a formerly legal back");
    }
    private static void backDoesNotProveSave()throws Exception{
        TaskCompletionGate g=launched();Frame before=frame(raw("step-02-before.json")),after=frame(raw("step-03-before.json"));g.observed(before);
        ActionDecision back=parsed(decision(before,"back",null,null,null,null));
        // Synthetic accepted back joins two recorded body frames. There was no
        // such back in this phone trace, and neither frame is a saved list.
        g.action(2,id(),back,true,true,false,before,after,null);
        TaskCompletionGate.NotesPhase facts=g.notesPhase(after);
        check(facts.currentBody&&facts.editorObserved&&!facts.listObserved&&!facts.reopened&&!g.verified(after),"accepted back with editor still present proves neither saved list nor reopen");
        check(!g.successClaim(3,id(),after).verified,"native success claim remains rejected without list and same-item reopen");
    }
    private static void actualServiceDomain(Path out)throws Exception{
        QualificationScopeHostTest.output=out;Files.createDirectories(out);
        try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            TaskCompletionGateHostTest.installPackage(e,"notes.create");TaskCompletionGateHostTest.installPackage(e,"web.search");
            final List<PhoneObservation.Node> actualNodes=phone(raw("step-02-before.json")).nodes;
            e.service.observationRows=()->actualNodes;e.service.prepare(P);
            check(e.service.acquireTask(e.task,()->{}),"explicit synthetic service lease acquired");
            e.service.bindQualificationScope(e.task,QualificationScopeConfig.capture(e.service,e.task,null,e.runtime));
            TaskAuthorization auth=TaskAuthorization.parse(owner);TaskAuthorization.Gate authority=e.service.bindTaskAuthorization(e.task,auth);
            NotesTaskPhaseGuard guard=e.service.notesTaskPhaseFor(e.task,authority);
            android.content.pm.PackageInfo installed=e.pm.packages.get(P);
            // The archived 40-LF body form is pinned by production to its actual
            // recorded Notes APK identity. Reuse that exact provider metadata;
            // the surrounding service/PackageManager/lease remains explicit
            // synthetic IO, not a fresh package-identity proof on a phone.
            JSONObject providerIdentity=raw("completion-installed-identity.json");
            check(installed.applicationInfo.uid==providerIdentity.getInt("uid")&&P.equals(providerIdentity.getString("package")),"synthetic service target UID matches the recorded provider identity");
            TaskCompletionGate g=new TaskCompletionGate(e.task,owner,auth);g.bindInstalled(new NotesCompletionEvidence.Installed(P,providerIdentity.getInt("uid"),Collections.singletonMap("base",providerIdentity.getJSONObject("apk_hashes").getString("base"))));
            Frame initial=frame(raw("step-01-before.json")),afterCreate=frame(raw("step-01-after.json"));String run=id();
            ActionDecision create=parsed(decision(initial,"notes.create",null,null,null,null));
            FixedIntentAttemptGuard ledger=new FixedIntentAttemptGuard(e.task,v->{});
            FixedIntentAttemptGuard.Attempt attempt=ledger.consume(new FixedIntentAttemptGuard.Binding(e.task,run,initial.observationId,initial.packageName,initial.windowId,initial.displayId,initial.backgroundGeneration,targets().get("notes.create"),BODY));
            ledger.entering(attempt);g.action(1,run,create,true,true,false,initial,afterCreate,ledger.finished(attempt,true));
            Method bridge=LocalTaskController.class.getDeclaredMethod("completionFrame",PhoneObservation.class);bridge.setAccessible(true);
            Frame current=(Frame)bridge.invoke(null,e.service.current);g.observed(current);
            Object built=prompt(owner,e.service.current,authority,g,guard,new JSONArray(),new SameStateNoEffectGuard());DecisionGrammar gb=(DecisionGrammar)field(built,"grammar");
            check(set("back","wait","done").equals(new TreeSet<String>(gb.actions))&&e.service.effects()==0,"real prompt publishes narrow editor domain without any automatic effect: "+new JSONObject(g.prompt(current)).toString());
            for(String tool:new String[]{"click","type","submit","scroll","open","home","find_app","notes.create","web.search"}){
                String n=("click".equals(tool)||"type".equals(tool)||"submit".equals(tool))?"n11":"scroll".equals(tool)?"n5":null;
                String label="n5".equals(n)?"NoteEditor":n==null?null:ObservedTargetLabels.project(BODY+"\n");
                final HeptaAccessibilityService.ActionOutcome[] result={null};
                e.service.perform(e.task,e.service.current,parsed(decision(current,tool,n,label,P,null)),gb.targets,targets().get(tool),authority,id(),()->false,r->result[0]=r);
                check(result[0]!=null&&!result[0].accepted&&!result[0].dispatched&&!result[0].stale&&result[0].detail.contains("notes_task_phase")&&e.service.effects()==0,"actual service denies removed editor action before all effects: "+tool);
            }
            final HeptaAccessibilityService.ActionOutcome[] title={null};
            e.service.perform(e.task,e.service.current,parsed(decision(current,"click","n1","标题",null,null)),gb.targets,null,authority,id(),()->false,r->title[0]=r);
            check(title[0]!=null&&!title[0].accepted&&!title[0].dispatched&&title[0].detail.contains("notes_task_phase")&&e.service.effects()==0,"service independently denies actual titled button, even with a valid label pair");
            for(String status:new String[]{"partial","failure"}){
                final HeptaAccessibilityService.ActionOutcome[] result={null};e.service.perform(e.task,e.service.current,parsed(decision(current,"done",null,null,null,status)),gb.targets,null,authority,id(),()->false,r->result[0]=r);
                check(result[0]!=null&&result[0].accepted&&!result[0].dispatched&&e.service.effects()==0&&!g.verified(current),"partial/failure reporting remains possible without claiming saved evidence");
            }
            final HeptaAccessibilityService.ActionOutcome[] waited={null};
            e.service.perform(e.task,e.service.current,parsed(decision(current,"wait",null,null,null,null)),gb.targets,null,authority,id(),()->false,r->waited[0]=r);
            check(waited[0]!=null&&waited[0].accepted&&!waited[0].dispatched&&e.service.effects()==0,"ordinary wait remains available without automatic navigation");
            final HeptaAccessibilityService.ActionOutcome[] backed={null};
            e.service.perform(e.task,e.service.current,parsed(decision(current,"back",null,null,null,null)),gb.targets,null,authority,id(),()->false,r->backed[0]=r);
            check(backed[0]!=null&&backed[0].accepted&&backed[0].dispatched&&e.service.effects()==1&&e.service.navigations==1&&!g.verified(current),"only an explicit model back dispatches one synthetic navigation; it is not save proof");
        }
    }
    public static void main(String[] args)throws Exception{
        Path fixture=Paths.get(args[0]),out=Paths.get(args[1]);Files.createDirectories(out);
        byte[] bytes=Files.readAllBytes(fixture);check(FIXTURE_SHA.equals(ObservedImeEnter.hash(new String(bytes,StandardCharsets.UTF_8))),"frozen original v48 trace SHA");
        JSONObject document=new JSONObject(new String(bytes,StandardCharsets.UTF_8));files=document.getJSONObject("files");owner=raw("owner.json").getString("instruction");
        check(BODY.equals(TaskCompletionGate.Contract.parse(owner,TaskAuthorization.parse(owner)).body)&&TASK.equals(document.getString("task_id")),"actual immutable owner/body/task bound");
        recordedEditorDecisions();provenanceAndIntersection();backDoesNotProveSave();actualServiceDomain(out.resolve("service-io"));
        Files.write(out.resolve("grammar-cases.json"),new JSONArray(grammarCases).toString().getBytes(StandardCharsets.UTF_8));
        check(FIXTURE_SHA.equals(ObservedImeEnter.hash(new String(Files.readAllBytes(fixture),StandardCharsets.UTF_8))),"original fixture unchanged");
        System.out.println("PASS "+checks+" Notes editor-phase assertions; original_v48_partial=true; synthetic_service_io=true; phone_tested=false");
    }
}
