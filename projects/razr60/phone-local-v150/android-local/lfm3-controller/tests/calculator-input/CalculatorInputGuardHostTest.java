package org.trillionnium.hepta.local;

import android.graphics.Rect;
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
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

/** The frame and failed type decision are original v47 phone bytes.  Installed
 * APK/UID and all subsequent Android/model/effect IO are explicit host fakes.
 * No missing phone after frame or successful calculation is manufactured. */
public final class CalculatorInputGuardHostTest {
    private static final String FIXTURE_SHA="44bc7ee0c74dff2a8772be64b54ef2d2ba1cf9574c6f144320e94582e24e5542";
    private static final String TASK="9f330bb340f8459caa2004aacc0cf9b8";
    private static final String P=CalculatorGoalContract.PACKAGE,SELF="org.trillionnium.hepta.local";
    private static final String HOST_SHA=ObservedImeEnter.hash("explicit synthetic installed Calculator APK for host IO only");
    private static final Set<String> INTEGER_BUTTONS=set("n0","n1","n4","n5","n6","n7","n8","n9","n10","n11","n12","n13","n14","n15","n16","n18","n19");
    private static final List<Object> grammarCases=new ArrayList<Object>();
    private static JSONObject saved;private static String owner;private static int checks;
    private interface Call {void run()throws Exception;}
    private static void check(boolean condition,String why){checks++;if(!condition)throw new AssertionError(why);}
    private static void denied(Call operation,String why)throws Exception{
        try{operation.run();}
        catch(InvocationTargetException wrapped){Throwable cause=wrapped.getCause();if(cause instanceof IllegalStateException||cause instanceof IllegalArgumentException||cause instanceof ActionDecision.InvalidActionException){checks++;return;}throw wrapped;}
        catch(IllegalStateException expected){checks++;return;}
        catch(IllegalArgumentException expected){checks++;return;}
        catch(ActionDecision.InvalidActionException expected){checks++;return;}
        throw new AssertionError("unexpected acceptance: "+why);
    }
    private static Set<String> set(String... values){return new TreeSet<String>(Arrays.asList(values));}
    private static Object field(Object object,String name)throws Exception{Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(object);}
    private static String value(JSONObject o,String key,String fallback)throws Exception{return o.has(key)&&!o.isNull(key)?o.getString(key):fallback;}
    private static JSONObject raw(String name)throws Exception{
        JSONObject row=saved.getJSONObject(name);String text=row.getString("raw_utf8");
        check(row.getString("sha256").equals(ObservedImeEnter.hash(text))&&row.getInt("bytes")==text.getBytes(StandardCharsets.UTF_8).length,"original raw bytes: "+name);
        return new JSONObject(text);
    }
    private static int[] bounds(JSONArray a){return new int[]{((Number)a.get(0)).intValue(),((Number)a.get(1)).intValue(),((Number)a.get(2)).intValue(),((Number)a.get(3)).intValue()};}
    private static Rect rect(int[] b){return new Rect(b[0],b[1],b[2],b[3]);}
    private static PhoneObservation phone(JSONObject raw)throws Exception{
        String pkg=raw.getString("package");List<PhoneObservation.Node> nodes=new ArrayList<PhoneObservation.Node>();JSONArray input=raw.getJSONArray("nodes");
        for(int i=0;i<input.length();i++){
            JSONObject n=input.getJSONObject(i);List<String> directions=new ArrayList<String>();
            if(n.optBoolean("scroll_actions_observed",false)){JSONArray d=n.getJSONArray("scroll_directions");for(int k=0;k<d.length();k++)directions.add((String)d.get(k));}
            // This fixture has no derived child label. No label is invented for
            // its empty switch/formula nodes. Only actual text/description feed
            // the production bridge and prompt projection.
            check(!"derived".equals(value(n,"child_text_status","")),"fixture does not require guessed child label");
            nodes.add(new PhoneObservation.Node(n.getString("id"),pkg,"",value(n,"view_id",""),value(n,"text",""),value(n,"description",""),rect(bounds(n.getJSONArray("bounds"))),
                    n.optBoolean("clickable",false),n.optBoolean("editable",false),n.optBoolean("scrollable",false),n.optBoolean("enabled",true),n.optBoolean("focused",false),n.optBoolean("password",false),
                    ObservedChildText.notApplicable(),n.optBoolean("scroll_actions_observed",false)?ObservedScrollActions.observed(directions):ObservedScrollActions.UNKNOWN,
                    ObservedImeEnter.UNKNOWN,value(n,"input_text_sha256",null),false,value(n,"node_app_tree_sha256",null)));
        }
        JSONObject w=raw.getJSONObject("window");
        ObservedWindowMetadata metadata=ObservedWindowMetadata.observed(bounds(w.getJSONArray("root_bounds")),w.getString("root_class"),w.getInt("type"),w.getInt("display_id"),bounds(w.getJSONArray("bounds")),w.getString("title"));
        String generation=null,initial=null,selectionOwner=null;JSONObject selection=null;List<String> packages=new ArrayList<String>();
        if(raw.has("background_session")&&!raw.isNull("background_session")){
            JSONObject b=raw.getJSONObject("background_session");generation=b.getString("generation");initial=b.getString("bootstrap_package");
            JSONArray a=b.getJSONArray("allowed_packages");for(int i=0;i<a.length();i++)packages.add((String)a.get(i));
            // main() already checks the complete frozen archive and all five raw members.
            // Carry its original seven-field explicit-UI Selection; do not invent
            // the later owner_intent_within_explicit_ui_selection provenance.
            JSONObject bootstrap=new JSONObject(saved.getJSONObject("background-bootstrap.json").getString("raw_utf8"));
            selection=bootstrap.getJSONObject("selection");selectionOwner=bootstrap.getString("owner_sha256");
            if(!TASK.equals(bootstrap.getString("task_id"))||!generation.equals(bootstrap.getString("generation"))
                    ||w.getInt("display_id")!=bootstrap.getInt("display_id")
                    ||!ObservedImeEnter.hash(owner).equals(selectionOwner))
                throw new IllegalArgumentException("original v47 bootstrap identity differs from its frame or OWNER");
        }
        return new PhoneObservation(raw.getString("observation_id"),pkg,1,raw.getInt("screen_width"),raw.getInt("screen_height"),raw.getInt("rotation"),raw.getInt("window_id"),rect(bounds(w.getJSONArray("bounds"))),
                new File("original-v47-calculator-frame-not-live-android-io"),raw.getString("screen_sha256"),raw.getString("observation_state_sha256"),
                new ObservationState(raw.getString("app_tree_sha256"),raw.isNull("ime_visible")?ImeVisibility.UNKNOWN:raw.getBoolean("ime_visible")?ImeVisibility.VISIBLE:ImeVisibility.HIDDEN),metadata,
                raw.getBoolean("nodes_truncated"),nodes,generation,initial,packages,null,selection,selectionOwner);
    }
    private static Frame frame(PhoneObservation phone)throws Exception{
        Method m=LocalTaskController.class.getDeclaredMethod("completionFrame",PhoneObservation.class);m.setAccessible(true);return (Frame)m.invoke(null,phone);
    }
    private static Frame frame(JSONObject raw)throws Exception{return frame(phone(raw));}
    private static NotesCompletionEvidence.Installed installed(){return new NotesCompletionEvidence.Installed(P,10003,Collections.singletonMap("base",HOST_SHA));}
    private static CalculatorTaskInputGuard guard(TaskAuthorization auth){CalculatorTaskInputGuard g=new CalculatorTaskInputGuard(TASK,auth);if(g.supported())g.bindInstalled(installed(),()->{});return g;}
    private static Map<String,FixedIntentTarget> fixed(){
        Map<String,FixedIntentTarget> values=new LinkedHashMap<String,FixedIntentTarget>();
        values.put("notes.create",new FixedIntentTarget("notes.create","Moto 笔记",10382,null));
        values.put("web.search",new FixedIntentTarget("web.search","浏览器",10383,null));return values;
    }
    private static Object prompt(String instruction,PhoneObservation observed,TaskAuthorization.Gate auth,CalculatorTaskInputGuard guard)throws Exception{
        Map<String,String> apps=new LinkedHashMap<String,String>();apps.put(P,"计算器");apps.put(SELF,"Hepta");apps.put("com.zui.browser","浏览器");
        TaskCompletionGate completion=new TaskCompletionGate(auth.taskId,instruction,auth.authorization);completion.observed(frame(observed));
        NotesTaskPhaseGuard notes=new NotesTaskPhaseGuard(auth.taskId,auth.authorization);
        for(Method method:LocalTaskController.class.getDeclaredMethods())if("prompt".equals(method.getName())&&method.getParameterTypes()[method.getParameterTypes().length-1]==CalculatorTaskInputGuard.class){
            method.setAccessible(true);return method.invoke(null,instruction,new AppCatalogueRanker(apps,instruction).search("",0),observed,new JSONArray(),null,null,null,
                    new LocalRuntimeConfig(ModelProfile.LFM3,"npu",8192,4),new RepeatActionGuard(),new SameStateNoEffectGuard(),auth.frame(),null,fixed(),completion,notes,guard);
        }
        throw new AssertionError("actual Calculator prompt entry missing");
    }
    private static JSONObject data(String prompt)throws Exception{
        String prefix="UNTRUSTED_DATA\n";int end=prompt.lastIndexOf("\nOWNER\n");
        check(prompt.startsWith(prefix)&&end>prefix.length(),"actual prompt sections present");return new JSONObject(prompt.substring(prefix.length(),end));
    }
    private static String choice(Frame f,String tool,String node,String label)throws Exception{
        JSONObject o=new JSONObject().put("reason","host IO choice; not a missing phone action").put("action",tool).put("observation_id",f.observationId);
        if("open".equals(tool))o.put("app_label","Hepta").put("package",SELF);
        else if(fixed().containsKey(tool)){
            FixedIntentTarget t=fixed().get(tool);o.put("app_label",t.appLabel).put("package",t.packageName).put("notes.create".equals(tool)?"text":"query","explicit host-only payload");
        }else{
            o.put("package",f.packageName);
            if(node!=null)o.put("node_label",label).put("node_id",node);
            if("type".equals(tool))o.put("text","31*47");
            if("wait".equals(tool))o.put("duration_ms",100);
            if("done".equals(tool))o.put("status","partial").put("summary","host-only incomplete result");
        }
        return o.toString();
    }
    private static ActionDecision parsed(String text)throws Exception{return ActionDecision.parse(text,ActionDecision.FIXED_INTENT_ACTION_SCHEMA);}
    private static void grammar(String name,DecisionGrammar grammar,String json,boolean accept){
        Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name);row.put("grammar",grammar.text);row.put("json",json);row.put("accepted",accept);grammarCases.add(row);
    }
    @SuppressWarnings("unchecked") private static void postparse(Object built,TaskAuthorization.Gate auth,ActionDecision action)throws Exception{
        DecisionGrammar g=(DecisionGrammar)field(built,"grammar");
        ActionPolicy.validateAuthorizedDecision(action,g.targets.packageName,(Set<String>)field(built,"appPackages"),g.targets,g.appLabels,auth,g.authorization,g.fixedIntentTargets);
        Method text=built.getClass().getDeclaredMethod("requireTextOnlyClick",ActionDecision.class);text.setAccessible(true);text.invoke(built,action);
        ((NotesTaskPhaseGuard.Domain)field(built,"phaseDomain")).requireCurrent(action);
        ((CalculatorTaskInputGuard.Domain)field(built,"calculatorDomain")).requireCurrent(action);
    }
    private static Set<String> ids(Frame f){Set<String> out=new TreeSet<String>();for(NotesCompletionEvidence.Node n:f.nodes)out.add(n.id);return out;}
    private static CalculatorTaskInputGuard.Domain bind(CalculatorTaskInputGuard g,Frame f){
        CalculatorTaskInputGuard.Projection p=g.prepare(f);CalculatorTaskInputGuard.Domain d=p.bind(p.clicks(ids(f)),p.edits(ids(f)),p.submits(Collections.singletonMap("n22",Boolean.TRUE)).keySet(),p.fixedTargets(fixed()),p.openPackages(set(P,SELF)),Collections.<String,ObservedScrollActions>emptyMap());g.publish(d);return d;
    }
    private static Object mutable(Object value)throws Exception{
        if(value instanceof Map<?,?>)return mutable(new JSONObject((Map<?,?>)value));
        if(value instanceof List<?>)return mutable(new JSONArray((List<?>)value));
        if(value instanceof JSONObject){JSONObject old=(JSONObject)value,out=new JSONObject();java.util.Iterator<String> keys=old.keys();while(keys.hasNext()){String key=keys.next();out.put(key,mutable(old.get(key)));}return out;}
        if(value instanceof JSONArray){JSONArray old=(JSONArray)value,out=new JSONArray();for(int i=0;i<old.length();i++)out.put(mutable(old.get(i)));return out;}
        return value;
    }
    private static JSONObject copy(JSONObject value)throws Exception{return (JSONObject)mutable(value);}
    private static JSONObject node(JSONObject f,String id)throws Exception{JSONArray rows=f.getJSONArray("nodes");for(int i=0;i<rows.length();i++)if(id.equals(rows.getJSONObject(i).getString("id")))return rows.getJSONObject(i);throw new AssertionError(id);}

    private static void actualFrameDomain()throws Exception{
        JSONObject before=raw("step-01-before.json"),failed=raw("step-01-action.json");PhoneObservation observed=phone(before);Frame f=frame(observed);
        check(f.displayId==10&&"609f2475-8874-4fda-a36e-ef12a028e44b".equals(f.backgroundGeneration)&&f.nodes.size()==25,"real owned display/generation/25 nodes preserved through actual bridge");
        TaskAuthorization auth=TaskAuthorization.parse(owner);CalculatorTaskInputGuard g=guard(auth);check(g.supported(),"actual immutable arithmetic OWNER is recognized");
        TaskAuthorization.Gate gate=auth.bind(TASK);Object built=prompt(owner,observed,gate,g);DecisionGrammar grammar=(DecisionGrammar)field(built,"grammar");
        CalculatorTaskInputGuard.Domain domain=(CalculatorTaskInputGuard.Domain)field(built,"calculatorDomain");
        check(INTEGER_BUTTONS.equals(domain.clickIds)&&domain.clickIds.size()==17,"exact 17 real integer keypad buttons retained");
        check(!grammar.actions.contains("type")&&!grammar.actions.contains("submit")&&!grammar.actions.contains("notes.create")&&!grammar.actions.contains("web.search"),"input/fixed replacements absent from production grammar");
        String text=(String)field(built,"text");JSONObject prompt=data(text);
        check(text.endsWith("\nOWNER\n"+owner)&&!text.contains("1457")&&!prompt.toString().contains("expected_integer"),"no computed answer or automatic action sequence added to model input");
        check(prompt.getJSONObject("calculator_input").getBoolean("direct_text_replacement_allowed")==false,"actual prompt states immutable input restriction");
        Set<String> promptClicks=new TreeSet<String>();JSONArray shown=copy(prompt).getJSONObject("screen").getJSONArray("nodes");
        for(int i=0;i<shown.length();i++){JSONArray row=(JSONArray)shown.get(i);String flags=(String)row.get(3);if(flags.contains("c"))promptClicks.add((String)row.get(0));check(!flags.contains("t"),"prompt has no text replacement affordance");}
        check(promptClicks.equals(domain.clickIds),"prompt clickable flags and frozen dispatch domain are identical");
        for(NotesCompletionEvidence.Node n:f.nodes){
            String click=choice(f,"click",n.id,ObservedTargetLabels.project(n.label));boolean allowed=INTEGER_BUTTONS.contains(n.id);
            grammar("real-node-"+n.id,grammar,click,allowed);
            if(allowed){postparse(built,gate,parsed(click));checks++;}
            else denied(()->postparse(built,gate,parsed(click)),"non-button cannot bypass grammar: "+n.id);
        }
        ActionDecision recorded=ActionDecision.parse(failed.getJSONObject("action").toString(),ActionDecision.FIXED_INTENT_ACTION_SCHEMA);
        check("type".equals(recorded.action)&&"n22".equals(recorded.nodeId)&&"31*47".equals(recorded.text),"original failed decision retained without fabricated after text");
        grammar("original-failed-type",grammar,failed.getJSONObject("action").toString(),false);
        denied(()->postparse(built,gate,recorded),"original failed type rejected after parse");
        for(String tool:new String[]{"type","submit","notes.create","web.search","open"}){
            String a=choice(f,tool,"type".equals(tool)||"submit".equals(tool)?"n22":null,"0");
            grammar("removed-"+tool,grammar,a,false);denied(()->postparse(built,gate,parsed(a)),"removed effect: "+tool);
        }
        for(String tool:new String[]{"back","wait","done"}){String a=choice(f,tool,null,null);grammar("remaining-"+tool,grammar,a,true);postparse(built,gate,parsed(a));checks++;}
        String wrongLabel=choice(f,"click","n16","保存"),wrongObs=choice(f,"click","n16","0").replace(f.observationId,TaskCompletionGateHostTest.id(999));
        grammar("wrong-label",grammar,wrongLabel,false);grammar("wrong-observation",grammar,wrongObs,false);
        denied(()->postparse(built,gate,parsed(wrongLabel)),"current ID cannot borrow another label");denied(()->postparse(built,gate,parsed(wrongObs)),"stale observation cannot borrow domain");
        String another=owner.replace(g.goal.rawExpression,"8+9");check(!another.equals(owner),"comparison OWNER uses another expression");TaskAuthorization otherAuth=TaskAuthorization.parse(another);CalculatorTaskInputGuard other=guard(otherAuth);
        check(other.supported(),"independent supported expression recognized");Object rebuilt=prompt(another,observed,otherAuth.bind(TASK),other);
        check(((CalculatorTaskInputGuard.Domain)field(rebuilt,"calculatorDomain")).clickIds.equals(INTEGER_BUTTONS),"button availability does not encode a particular arithmetic sequence");
        denied(()->prompt(another,observed,gate,g),"new OWNER cannot reuse immutable authorization");
    }

    private static void malformedAndRetired()throws Exception{
        JSONObject actual=raw("step-01-before.json");Frame f=frame(actual);TaskAuthorization auth=TaskAuthorization.parse(owner);
        for(String mutation:new String[]{"wrong-view","wrong-label","missing-signature","malformed-signature","editable-key","password-key","disabled-key","duplicate-id","duplicate-view","blank-key"}){
            JSONObject changed=copy(actual),key=node(changed,"n16");
            if("wrong-view".equals(mutation))key.put("view_id",P+":id/formula_or_result");
            else if("wrong-label".equals(mutation))key.put("text","保存");
            else if("missing-signature".equals(mutation))key.put("node_app_tree_sha256",(Object)null);
            else if("malformed-signature".equals(mutation))key.put("node_app_tree_sha256","not-a-sha");
            else if("editable-key".equals(mutation))key.put("editable",true);
            else if("password-key".equals(mutation))key.put("password",true);
            else if("disabled-key".equals(mutation))key.put("enabled",false);
            else if("blank-key".equals(mutation))key.put("text","").put("description","");
            else{JSONObject duplicate=copy(key);if("duplicate-view".equals(mutation))duplicate.put("id","n25");else duplicate.put("view_id",P+":id/duplicate_other");changed.getJSONArray("nodes").put(duplicate);}
            if("malformed-signature".equals(mutation)){
                boolean refused=false;
                try{frame(changed);}catch(IllegalArgumentException expected){refused=true;}
                check(refused,"actual PhoneObservation rejects a malformed signature before guard construction");
                continue;
            }
            CalculatorTaskInputGuard g=guard(auth);Frame mutant=frame(changed);
            check(!g.prepare(mutant).clicks(ids(mutant)).contains("n16"),"affected button excluded by actual metadata: "+mutation);
        }
        for(boolean truncated:new boolean[]{false,true}){
            Frame unavailable=new Frame(f.observationId,P,f.windowId,f.displayId,f.backgroundGeneration,1,!truncated,truncated,f.nodes);
            if(!truncated)unavailable=new Frame(f.observationId,P,f.windowId,f.displayId,f.backgroundGeneration,2,true,false,f.nodes);
            check(guard(auth).prepare(unavailable).clicks(ids(f)).isEmpty(),"truncated/non-application frame supplies no native buttons");
        }
        Frame missingMetadata=new Frame(f.observationId,P,f.windowId,f.displayId,f.backgroundGeneration,1,false,false,f.nodes);
        check(guard(auth).prepare(missingMetadata).clicks(ids(f)).isEmpty(),"unobserved metadata cannot supply current buttons");
        Frame otherPackage=new Frame(f.observationId,SELF,f.windowId,f.displayId,f.backgroundGeneration,1,true,false,f.nodes);
        check(guard(auth).prepare(otherPackage).clicks(ids(f)).isEmpty(),"foreign package cannot borrow Calculator node IDs");
        CalculatorTaskInputGuard missing=new CalculatorTaskInputGuard(TASK,auth);denied(()->missing.prepare(f),"installed identity required before supported input");
        final boolean[] changed={false};CalculatorTaskInputGuard g=new CalculatorTaskInputGuard(TASK,auth);g.bindInstalled(installed(),()->{if(changed[0])throw new IllegalStateException("synthetic installed APK changed");});
        CalculatorTaskInputGuard.Domain old=bind(g,f);ActionDecision click=parsed(choice(f,"click","n16","0"));old.requireCurrent(click);checks++;
        Frame display=new Frame(f.observationId,P,f.windowId,0,null,1,true,false,f.nodes);
        denied(()->g.prepare(display),"main display cannot replace owned display");
        Frame generation=new Frame(f.observationId,P,f.windowId,10,"11111111-1111-1111-1111-111111111111",1,true,false,f.nodes);
        denied(()->g.prepare(generation),"another generation cannot inherit task");
        CalculatorTaskInputGuard.Domain replacement=bind(g,f);denied(()->old.requireCurrent(click),"repair supersedes former immutable domain");replacement.requireCurrent(click);checks++;
        CalculatorTaskInputGuard foreign=guard(auth);denied(()->foreign.publish(replacement),"foreign guard cannot publish domain");
        changed[0]=true;denied(()->replacement.requireCurrent(click),"live installed verifier rechecked before dispatch");changed[0]=false;
        denied(()->g.prepare(f),"identity invalidation remains sticky");
        CalculatorTaskInputGuard retired=guard(auth);CalculatorTaskInputGuard.Domain finalDomain=bind(retired,f);retired.retire();denied(()->finalDomain.requireCurrent(click),"retired task cannot use old domain");
    }

    private static void unknownAndAuthority()throws Exception{
        JSONObject ordinary=copy(raw("step-01-before.json"));ordinary.put("background_session",(Object)null);ordinary.getJSONObject("window").put("display_id",0);
        PhoneObservation io=phone(ordinary);Frame f=frame(io);
        for(String instruction:new String[]{"查看计算器当前页面。","通过 web.search 网页查询公开商品信息。"}){
            TaskAuthorization a=TaskAuthorization.parse(instruction);CalculatorTaskInputGuard g=guard(a);check(!g.supported(),"unknown/WEB has no arithmetic domain");
            Object built=prompt(instruction,io,a.bind(TASK),g);DecisionGrammar grammar=(DecisionGrammar)field(built,"grammar");
            check(grammar.actions.contains("type")&&grammar.actions.contains("web.search")&&!data((String)field(built,"text")).has("calculator_input"),"unknown/WEB keeps former ordinary capabilities and projection");
        }
        TaskAuthorization limited=TaskAuthorization.parse("只允许等待和结束。");CalculatorTaskInputGuard guard=guard(limited);CalculatorTaskInputGuard.Projection p=guard.prepare(f);
        denied(()->p.bind(set("n16"),set(),set(),Collections.<String,FixedIntentTarget>emptyMap(),set(),Collections.<String,ObservedScrollActions>emptyMap()),"input guard cannot add owner-banned click");
        denied(()->p.bind(set(),set("n22"),set(),Collections.<String,FixedIntentTarget>emptyMap(),set(),Collections.<String,ObservedScrollActions>emptyMap()),"input guard cannot add owner-banned type");
        CalculatorTaskInputGuard supported=guard(TaskAuthorization.parse(owner));CalculatorTaskInputGuard.Projection q=supported.prepare(frame(raw("step-01-before.json")));
        denied(()->q.bind(set("n22"),set(),set(),Collections.<String,FixedIntentTarget>emptyMap(),set(),Collections.<String,ObservedScrollActions>emptyMap()),"caller cannot reinsert readout click");
        denied(()->q.bind(set(),set("n22"),set(),Collections.<String,FixedIntentTarget>emptyMap(),set(),Collections.<String,ObservedScrollActions>emptyMap()),"caller cannot reinsert text replacement");
        denied(()->q.bind(set(),set(),set("n22"),Collections.<String,FixedIntentTarget>emptyMap(),set(),Collections.<String,ObservedScrollActions>emptyMap()),"caller cannot reinsert submit");
        denied(()->q.bind(set(),set(),set(),fixed(),set(),Collections.<String,ObservedScrollActions>emptyMap()),"caller cannot reinsert fixed target");
    }

    private static void serviceCase(String mutation)throws Exception{
        try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            e.service.prepare(P);e.service.node.viewId=P+":id/digit_0";e.service.node.text="0";e.service.node.editable=false;e.service.node.scrollable=false;
            e.service.root.window.display=10;e.service.node.window.display=10;
            e.service.observationRows=()->Collections.singletonList(new PhoneObservation.Node("n0",P,"Button",P+":id/digit_0","0","",new Rect(10,10,500,150),true,false,false,true,true,false,
                    ObservedChildText.notApplicable(),ObservedScrollActions.observed(Collections.<String>emptyList()),ObservedImeEnter.UNKNOWN,null,false,HOST_SHA));
            check(e.service.acquireTask(e.task,()->{}),"host service lease acquired");
            e.service.bindQualificationScope(e.task,QualificationScopeConfig.capture(e.service,e.task,null,e.runtime));
            TaskAuthorization auth=TaskAuthorization.parse(owner);TaskAuthorization.Gate gate=e.service.bindTaskAuthorization(e.task,auth);
            final BackgroundSession background=BackgroundSession.fixture(e.task,10,set(P));
            Throwable primaryFailure=null;
            try{
            e.service.bindBackgroundSession(e.task,background);
            e.service.observe(e.task,e.dir.toFile(),()->false,Long.MAX_VALUE,new HeptaAccessibilityService.ObservationCallback(){public void onObservation(PhoneObservation ignored){}public void onError(String error){throw new AssertionError(error);}});
            CalculatorTaskInputGuard guard=e.service.calculatorInputFor(e.task,gate);
            final QualificationScopeConfig.CompletionInstalledIdentity installed=QualificationScopeConfig.CompletionInstalledIdentity.captureCalculator(e.service);
            guard.bindInstalled(new NotesCompletionEvidence.Installed(installed.packageName,installed.uid,installed.apkHashes),()->installed.verify(e.service));
            Object built=prompt(owner,e.service.current,gate,guard);DecisionGrammar grammar=(DecisionGrammar)field(built,"grammar");Frame f=frame(e.service.current);
            String json=choice(f,"click","n0","0");
            if("type".equals(mutation))json=choice(f,"type","n0","0");
            else if("label".equals(mutation))json=choice(f,"click","n0","保存");
            else if("stale-observation".equals(mutation))json=json.replace(f.observationId,TaskCompletionGateHostTest.id(9999));
            else if("live-node-signature".equals(mutation))e.service.node.text="changed after prompt";
            else if("live-display".equals(mutation))e.service.node.window.display=0;
            else if("installed-uid".equals(mutation))e.pm.packages.get(P).applicationInfo.uid++;
            else if("installed-apk".equals(mutation))QualificationScopeHostTest.write(Paths.get(e.pm.packages.get(P).applicationInfo.sourceDir),"changed host-only installed APK".getBytes(StandardCharsets.UTF_8),0644);
            final HeptaAccessibilityService.ActionOutcome[] box={null};
            e.service.perform(e.task,e.service.current,parsed(json),grammar.targets,null,gate,TaskCompletionGateHostTest.id(765),()->false,result->box[0]=result);
            check(box[0]!=null,"actual production service returned an outcome");
            if("allowed".equals(mutation))check(box[0].accepted&&box[0].dispatched&&e.service.effects()==1&&e.service.node.actions==1,"real production click path accepts one synthetic observed native button");
            else check(!box[0].accepted&&!box[0].dispatched&&e.service.effects()==0,"actual service independently refuses before effects: "+mutation);
            check(box[0].backgroundSession!=null&&box[0].backgroundSession.getInt("display_id")==10,"captured owned-session callback identity retained");
            }catch(Exception|Error failure){primaryFailure=failure;throw failure;}
            finally{
                try{
                    BackgroundSession.Cleanup cleanup=background.close();
                    check(cleanup.known&&background.released(),"synthetic owned display released before Env closes the task lease");
                }catch(RuntimeException|Error cleanupFailure){
                    if(primaryFailure!=null)primaryFailure.addSuppressed(cleanupFailure);else throw cleanupFailure;
                }
            }
        }
    }

    public static void main(String[] args)throws Exception{
        Path fixture=Paths.get(args[0]),out=Paths.get(args[1]);Files.createDirectories(out);
        QualificationScopeHostTest.output=out.resolve("service-io");Files.createDirectories(QualificationScopeHostTest.output);
        String text=new String(Files.readAllBytes(fixture),StandardCharsets.UTF_8);check(FIXTURE_SHA.equals(ObservedImeEnter.hash(text)),"frozen genuine v47 fixture SHA");
        JSONObject archive=new JSONObject(text);check(archive.getBoolean("original_terminal_failed")&&!archive.getBoolean("after_action_frame_present")&&!archive.getBoolean("actual_text_after_failed_set_text_known"),"original failed task and absent after remain unknown");
        saved=archive.getJSONObject("files");for(String name:new String[]{"step-01-before.json","step-01-action.json","background-bootstrap.json","background-cleanup.json","driver-RESULT.json"})raw(name);
        owner=raw("driver-RESULT.json").getString("instruction");
        actualFrameDomain();malformedAndRetired();unknownAndAuthority();
        for(String mutation:new String[]{"allowed","type","label","stale-observation","live-node-signature","live-display","installed-uid","installed-apk"})serviceCase(mutation);
        Files.write(out.resolve("grammar-cases.json"),new JSONArray(grammarCases).toString().getBytes(StandardCharsets.UTF_8));
        Files.write(out.resolve("RESULT.json"),new JSONObject().put("passed",true).put("checks",checks).put("fixture_sha256",FIXTURE_SHA)
                .put("actual_controller_bridge_prompt_and_service",true).put("installed_identity_and_effect_io_are_synthetic",true).put("phone_tested",false)
                .put("original_task_failed",true).put("original_after_text_still_unknown",true).put("business_completion_proved",false).toString(2).getBytes(StandardCharsets.UTF_8));
        System.out.println("PASS "+checks+" Calculator native-button input checks; fixture_sha256="+FIXTURE_SHA+"; phone_tested=false; original_after_text_unknown=true");
    }
}
