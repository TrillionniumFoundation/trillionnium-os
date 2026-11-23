package org.trillionnium.hepta.local;

import android.graphics.Rect;
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

/** Real Domain/grammar/parser/full Controller prompt, with explicit synthetic
 * native frames and result readiness. No model, Android dispatch or device IO. */
public final class NativeTerminalStatusHostTest {
    private static final List<Map<String,Object>> grammarCases=new ArrayList<Map<String,Object>>();
    private static int assertions,mismatches;
    private static boolean baseline;
    private static final String OWNER=SyntheticXiaomiNativeLoginFixture.OWNER;
    private static final String PACKAGE=NativeAppGoal.XIAOMI_PACKAGE;
    private interface Call {void run()throws Exception;}
    private static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    private static boolean denied(Call call)throws Exception{
        try{call.run();return false;}catch(ActionDecision.InvalidActionException expected){return true;}
    }
    private static Object invoke(Method m,Object target,Object... args)throws Exception{
        m.setAccessible(true);try{return m.invoke(target,args);}catch(InvocationTargetException e){
            if(e.getCause() instanceof Exception)throw (Exception)e.getCause();
            if(e.getCause() instanceof Error)throw (Error)e.getCause();throw e;
        }
    }
    private static Object field(Object value,String name)throws Exception{
        Field f=value.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(value);
    }
    private static Set<String> statuses(String... values){return new TreeSet<String>(Arrays.asList(values));}
    private static String sha(String s){return NativeAppEvidence.hash(s);}
    private static final class Binding implements BackgroundTaskTarget.SelectionBinding {
        final BackgroundTaskTarget target=BackgroundTaskTarget.resolveExplicitSelection(OWNER,PACKAGE,Collections.singleton(PACKAGE));
        public BackgroundTaskTarget executionTarget(){return target;}
    }
    private static final class Context {
        final NativeAppEvidence.Frame frame;final PhoneObservation phone;
        final Binding selection=new Binding();final TaskAuthorization auth;
        final TaskAuthorization.Gate gate;final TaskCompletionGate completion;final NativeAppSession session;
        Context()throws Exception{
            NativeAppEvidence.Frame f=SyntheticXiaomiNativeLoginFixture.frame();
            auth=TaskAuthorization.parse(OWNER).forExecutionSelection(selection);gate=auth.bind(f.taskId);
            List<PhoneObservation.Node> nodes=new ArrayList<PhoneObservation.Node>();
            for(NativeAppEvidence.Node n:f.nodes)nodes.add(new PhoneObservation.Node(n.id,n.packageName,n.className,n.viewId,n.text,n.description,
                    new Rect(n.left,n.top,n.right,n.bottom),n.clickable,n.editable,n.scrollable,n.enabled,false,n.password,
                    ObservedChildText.notApplicable(),ObservedScrollActions.UNKNOWN,ObservedImeEnter.UNKNOWN,null,false,n.signature,n.path,n.parentClass,n.selected,n.checkable,n.checked));
            int[] bounds={f.left,f.top,f.right,f.bottom};
            phone=new PhoneObservation(f.observationId,PACKAGE,f.capturedElapsedMs,f.width,f.height,f.rotation,f.windowId,
                    new Rect(f.left,f.top,f.right,f.bottom),null,f.screenshotSha,f.treeSha,new ObservationState(f.treeSha,ImeVisibility.HIDDEN),
                    ObservedWindowMetadata.observed(bounds,"android.widget.FrameLayout",1,f.displayId,bounds,""),false,nodes,f.generation,PACKAGE,
                    Collections.singletonList(PACKAGE),new PhoneObservation.CollectionStats(512,200,16000,16,nodes.size(),76,0,0,0,0L,1L),
                    new BackgroundSession.Selection(selection.target).json(),auth.instructionSha256);
            NotesCompletionEvidence.Frame c=(NotesCompletionEvidence.Frame)invoke(LocalTaskController.class.getDeclaredMethod("completionFrame",PhoneObservation.class),null,phone);
            frame=new NativeAppEvidence.Frame(f.taskId,selection.target.ownerSha256,selection.target.targetSha256,auth.sha256,sha("terminal-selection"),
                    f.observationId,PACKAGE,f.generation,f.treeSha,f.stateSha,f.screenshotSha,f.sourceRecordSha,TaskCompletionGate.webFrameSha(c),
                    f.displayId,f.windowId,f.rotation,f.width,f.height,f.left,f.top,f.right,f.bottom,f.capturedElapsedMs,false,true,f.nodes,1,true);
            completion=new TaskCompletionGate(f.taskId,OWNER,auth,selection);
            session=new NativeAppSession(f.taskId,gate,selection,new NativeAppEvidence.Installed(PACKAGE,12345,20261010L,
                    Collections.singletonMap("base","95883c057eb15bc6e50a82f2e22da13b77980871624f60a2fb9e50cfdf4a8373")),sha("terminal-selection"),f.generation,f.displayId,
                    new NativeAppSession.InstalledVerifier(){public void verify(){}},new NativeAppSession.Journal(){public void write(String leaf,Map<String,Object> value){}});
            completion.bindNativeSession(session);session.observed(frame);completion.observed(c);
            check(NativeXiaomiProductPage.LOGIN.equals(session.domain().phase),"real provider recognizes synthetic login");
        }
        NativeAppDomain domain(String phase,boolean ready)throws Exception{
            Set<String> clicks=NativeXiaomiProductPage.LOGIN.equals(phase)?Collections.singleton("n0"):Collections.<String>emptySet();
            Map<String,String> purposes=clicks.isEmpty()?Collections.<String,String>emptyMap():Collections.singletonMap("n0",NativeXiaomiProductPage.LOGIN_EXIT);
            NativeAppDomain d=new NativeAppDomain(frame,phase,clicks,Collections.<String,String>emptyMap(),purposes,false,
                    Collections.<String,Object>emptyMap(),ready?Collections.<String,Object>singletonMap("explicit_host_readiness",true):null,Collections.<String>emptyList());
            // Explicit host phase fixture; no action, receipt, proof or Android result is created.
            Field current=NativeAppSession.class.getDeclaredField("current");current.setAccessible(true);current.set(session,d);return d;
        }
    }
    private static DecisionGrammar direct(Context c,NativeAppDomain d,boolean fixed,boolean eligible)throws Exception{
        Map<String,String> labels=new LinkedHashMap<String,String>();for(String id:d.clickIds)labels.put(id,c.frame.byId.get(id).label);
        ObservedTargetLabels targets=ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,c.frame.observationId,PACKAGE,labels);
        ObservedAppLabels apps=ObservedAppLabels.create(ObservedAppLabels.SCHEMA,c.frame.observationId,PACKAGE,Collections.<String,String>emptyMap());
        if(NativeXiaomiProductPage.HOME_LOADING.equals(d.phase))return d.boundedWaitGrammar(targets,apps,c.gate.frame(),null);
        List<Object> args=new ArrayList<Object>(Arrays.<Object>asList(c.frame.observationId,PACKAGE,Collections.<String>emptySet(),d.clickIds,d.editValues.keySet(),
                Collections.<String,ObservedScrollActions>emptyMap(),Collections.<String,ObservedImeEnter>emptyMap(),targets,apps,c.gate.frame(),true));
        if(fixed){args.add(Collections.<String,org.trillionnium.hepta.background.FixedIntentTarget>emptyMap());args.add(Collections.<String,String>emptyMap());}
        args.add(d.toolMask(null));args.add(eligible);
        try{args.add(invoke(NativeAppDomain.class.getDeclaredMethod("doneStatuses"),d));}catch(NoSuchMethodException old){check(baseline,"new domain restriction is required");}
        String name=fixed?"createFixedIntentAuthorized":"createImeAuthorized";
        for(Method method:DecisionGrammar.class.getDeclaredMethods())if(name.equals(method.getName())&&method.getParameterTypes().length==args.size())
            return (DecisionGrammar)invoke(method,null,args.toArray());
        throw new AssertionError("exact authorized factory overload unavailable");
    }
    private static Object prompt(Context c,boolean fixed)throws Exception{
        Map<String,String> apps=Collections.singletonMap(PACKAGE,"小米商城");
        Object[] args={OWNER,new AppCatalogueRanker(apps,OWNER).search("",0),c.phone,new JSONArray(),null,null,null,
                new LocalRuntimeConfig(ModelProfile.LFM3,"npu",8192,4),new RepeatActionGuard(),new SameStateNoEffectGuard(),c.gate.frame(),null,
                fixed?Collections.<String,org.trillionnium.hepta.background.FixedIntentTarget>emptyMap():null,c.completion,
                new NotesTaskPhaseGuard(c.frame.taskId,c.auth),new CalculatorTaskInputGuard(c.frame.taskId,c.auth)};
        for(Method m:LocalTaskController.class.getDeclaredMethods())if("prompt".equals(m.getName())&&m.getParameterTypes().length==args.length)return invoke(m,null,args);
        throw new AssertionError("actual full Controller prompt method unavailable");
    }
    private static DecisionGrammar explicitMask(Context c,NativeAppDomain d,Set<String> mask,TaskAuthorization.Frame authority,boolean eligible)throws Exception{
        ObservedTargetLabels labels=ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,c.frame.observationId,PACKAGE,Collections.<String,String>emptyMap());
        ObservedAppLabels apps=ObservedAppLabels.create(ObservedAppLabels.SCHEMA,c.frame.observationId,PACKAGE,Collections.<String,String>emptyMap());
        Object[] args={c.frame.observationId,PACKAGE,Collections.<String>emptySet(),Collections.<String>emptySet(),Collections.<String>emptySet(),
                Collections.<String,ObservedScrollActions>emptyMap(),Collections.<String,ObservedImeEnter>emptyMap(),labels,apps,authority,true,d.toolMask(null),eligible,mask};
        for(Method m:DecisionGrammar.class.getDeclaredMethods())if("createImeAuthorized".equals(m.getName())&&m.getParameterTypes().length==args.length)
            return (DecisionGrammar)invoke(m,null,args);
        throw new AssertionError("domain-aware factory is required");
    }
    @SuppressWarnings("unchecked") private static Set<String> grammarStatuses(DecisionGrammar g)throws Exception{return (Set<String>)field(g,"doneStatuses");}
    private static void legacyAndSnapshot(Context c)throws Exception{
        NativeAppDomain d=c.domain("ordinary_native",true);
        ObservedTargetLabels labels=ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,c.frame.observationId,PACKAGE,Collections.<String,String>emptyMap());
        ObservedAppLabels apps=ObservedAppLabels.create(ObservedAppLabels.SCHEMA,c.frame.observationId,PACKAGE,Collections.<String,String>emptyMap());
        DecisionGrammar old=DecisionGrammar.createImeAuthorized(c.frame.observationId,PACKAGE,Collections.<String>emptySet(),Collections.<String>emptySet(),Collections.<String>emptySet(),
                Collections.<String,ObservedScrollActions>emptyMap(),Collections.<String,ObservedImeEnter>emptyMap(),labels,apps,c.gate.frame(),true);
        compare("legacy-ime-overload",old,d,statuses("failure","partial","success"));
        DecisionGrammar oldFixed=DecisionGrammar.createFixedIntentAuthorized(c.frame.observationId,PACKAGE,Collections.<String>emptySet(),Collections.<String>emptySet(),Collections.<String>emptySet(),
                Collections.<String,ObservedScrollActions>emptyMap(),Collections.<String,ObservedImeEnter>emptyMap(),labels,apps,c.gate.frame(),true,
                Collections.<String,org.trillionnium.hepta.background.FixedIntentTarget>emptyMap());
        compare("legacy-fixed-overload",oldFixed,d,statuses("failure","partial","success"));
        if(baseline)return;
        Set<String> mask=statuses("failure");DecisionGrammar g=explicitMask(c,d,mask,c.gate.frame(),true);String text=g.text;
        mask.add("partial");mask.add("success");
        check(grammarStatuses(g).equals(statuses("failure"))&&text.equals(g.text)&&!g.successAllowed,"caller mask mutation cannot widen immutable grammar snapshot");
        boolean immutable=false;try{grammarStatuses(g).add("partial");}catch(UnsupportedOperationException expected){immutable=true;}
        check(immutable,"published grammar terminal set is immutable");
        check(denied(()->g.requireCompletionStatus(ActionDecision.parse(terminal(g,"partial"),g.schema))),"postparse uses same immutable terminal snapshot");
        boolean unknown=false;try{explicitMask(c,d,statuses("failure","unrecognized"),c.gate.frame(),true);}catch(IllegalArgumentException expected){unknown=true;}
        check(unknown,"unknown restriction status is rejected");
        boolean empty=false;try{explicitMask(c,d,Collections.<String>emptySet(),c.gate.frame(),true);}catch(IllegalArgumentException expected){empty=true;}
        check(empty,"ordinary done branch cannot have empty terminal domain");
        // Use an explicit incomplete method requirement to obtain the original OWNER success gate.
        TaskAuthorization.Gate findFirst=TaskAuthorization.parse("先查找手机上安装的小米商城应用，再打开它。").bind(c.frame.taskId);
        TaskAuthorization.Frame deniedOwner=findFirst.frame();
        check(!deniedOwner.successAllowed(),"explicit OWNER fixture denies success before its method evidence");
        DecisionGrammar owner=explicitMask(c,d,statuses("failure","partial","success"),deniedOwner,true);
        check(!owner.successAllowed&&denied(()->owner.requireCompletionStatus(ActionDecision.parse(terminal(owner,"success"),owner.schema))),
                "supplied domain mask cannot override OWNER success gate");
        DecisionGrammar missing=explicitMask(c,d,statuses("failure","partial","success"),c.gate.frame(),false);
        check(!missing.successAllowed&&denied(()->missing.requireCompletionStatus(ActionDecision.parse(terminal(missing,"success"),missing.schema))),
                "supplied domain mask cannot override incomplete result evidence");
        NativeAppDomain before=c.domain(NativeXiaomiProductPage.LOGIN_BLOCKED,false);DecisionGrammar bound=direct(c,before,false,false);
        c.domain("ordinary_native",true);
        check(grammarStatuses(bound).equals(statuses("failure"))&&!bound.successAllowed,"later domain publication cannot widen an earlier grammar snapshot");
    }
    private static String terminal(DecisionGrammar grammar,String status){
        return "{\"reason\":\"explicit host status test\",\"action\":\"done\",\"observation_id\":\""+grammar.observationId
                +"\",\"package\":\""+grammar.currentPackage+"\",\"status\":\""+status+"\",\"summary\":\"host fixture\"}";
    }
    private static void compare(String name,DecisionGrammar grammar,NativeAppDomain domain,Set<String> expected)throws Exception{
        for(String status:new String[]{"failure","partial","success"}){
            String json=terminal(grammar,status);ActionDecision action=ActionDecision.parse(json,grammar.schema);
            boolean allowed=expected.contains(status),grammarRejected=denied(()->grammar.requireCompletionStatus(action)),domainRejected=denied(()->domain.requireCurrent(action));
            Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name+"-"+status);row.put("grammar",grammar.text);row.put("json",json);
            row.put("accepted",allowed);row.put("postparse_allowed",!grammarRejected);row.put("domain_allowed",!domainRejected);grammarCases.add(row);
            check(domainRejected!=allowed,"independent native validator keeps exact phase policy: "+name+" "+status);
            if(grammarRejected==allowed){mismatches++;check(baseline,"grammar postparse disagrees with domain: "+name+" "+status);}
        }
    }
    public static void main(String[] args)throws Exception{
        Path out=Paths.get(args[0]);Files.createDirectories(out);baseline=args.length>1&&"baseline".equals(args[1]);
        Context c=new Context();String[] restricted={NativeXiaomiProductPage.LOGIN,NativeXiaomiProductPage.LOGIN_BLOCKED,NativeXiaomiProductPage.HOME_LOADING_EXHAUSTED};
        for(String phase:restricted)for(boolean fixed:new boolean[]{false,true}){
            NativeAppDomain d=c.domain(phase,false);DecisionGrammar g=direct(c,d,fixed,false);
            compare(phase+"-direct-"+fixed,g,d,statuses("failure"));
            Object p=prompt(c,fixed);DecisionGrammar pg=(DecisionGrammar)field(p,"grammar");
            String text=(String)field(p,"text");String data=text.substring("UNTRUSTED_DATA\n".length(),text.lastIndexOf("\nOWNER\n"));
            JSONArray declared=new JSONObject(data).getJSONObject("completion").getJSONArray("allowed_done_statuses");
            Set<String> shown=new TreeSet<String>();for(int i=0;i<declared.length();i++)shown.add((String)declared.get(i));
            check(shown.equals(baseline?statuses("failure","partial"):statuses("failure")),"actual full prompt exact terminal set "+phase);
            compare(phase+"-prompt-"+fixed,pg,d,statuses("failure"));
            check(!g.successAllowed&&!pg.successAllowed,"restricted phase cannot grant success");
        }
        for(String phase:new String[]{"ordinary_native","ctrip_login_required"})for(boolean ready:new boolean[]{false,true})for(boolean fixed:new boolean[]{false,true}){
            NativeAppDomain d=c.domain(phase,ready);DecisionGrammar g=direct(c,d,fixed,ready);
            compare(phase+"-ready-"+ready+"-fixed-"+fixed,g,d,ready?statuses("failure","partial","success"):statuses("failure","partial"));
            if(ready){DecisionGrammar noProof=direct(c,d,fixed,false);check(!noProof.successAllowed,"domain readiness cannot replace completion eligibility");
                check(denied(()->noProof.requireCompletionStatus(ActionDecision.parse(terminal(noProof,"success"),noProof.schema))),"success still needs completion proof");}
        }
        NativeAppDomain waiting=c.domain(NativeXiaomiProductPage.HOME_LOADING,false);DecisionGrammar wait=direct(c,waiting,false,false);
        check(wait.actions.equals(Collections.singletonList("wait"))&&!wait.successAllowed,"bounded wait has no done branch");
        for(String status:new String[]{"failure","partial","success"}){
            Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name","loading-no-done-"+status);row.put("grammar",wait.text);row.put("json",terminal(wait,status));row.put("accepted",false);grammarCases.add(row);
        }
        legacyAndSnapshot(c);
        check(!baseline||mismatches==12,"exact R19 counterfactual is 12 partial grammar/postparse versus domain mismatches");
        Files.write(out.resolve("grammar-cases.json"),new JSONArray(grammarCases).toString().getBytes(StandardCharsets.UTF_8));
        JSONObject report=new JSONObject().put("schema","hepta.native-terminal-status-host.v1").put("all_pass",true).put("baseline_counterfactual",baseline)
                .put("assertions",assertions).put("grammar_cases",grammarCases.size()).put("postparse_domain_mismatches",mismatches)
                .put("phone_operations",0).put("model_executed",false).put("business_completion_verified",false);
        Files.write(out.resolve("RESULT.json"),(report.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));System.out.println(report.toString());
    }
}
