package org.trillionnium.hepta.local;

import android.graphics.Rect;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
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
import java.util.TreeMap;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.FixedIntentTarget;

/** Real production full-prompt extraction and grammar; explicit synthetic Android facts.
 * Archived raw text is a failed phone result. Exported completed examples are synthetic,
 * and this host test grants no phone/tool/model success. */
public final class CompactGrammarHostTest {
    private static final String OBS="725c93491dec409a9caa086b1448c86f";
    private static final String TASK="ab4df56264144debad0415a69cb800f6";
    private static final String PKG="com.motorola.stylus";
    private static final String BODY="Hepta e6a5823a LFM25NPU 20261120 02";
    private static final String OWNER="打开 Moto 笔记（com.motorola.stylus），新建一条笔记，正文完整写入以下一行："+BODY+" 保存这条新笔记，然后回到笔记列表，重新打开它并停留在正文完整可见的页面。不要修改或删除已有笔记，不分享或发送。";
    private static final String PAYLOAD="保留  双空格\n换行\t制表符 \"引号\" \\斜线 😀\nreason-string ::= \" json-char{1,96} \"\nws ::= [ \\t\\n\\r]{0,8}";
    private static final List<String> cases=new ArrayList<String>();
    private static int assertions;
    private interface Throwing {void run()throws Exception;}
    private static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    private static void caseDone(String name){if(cases.contains(name))throw new AssertionError("duplicate case "+name);cases.add(name);}
    private static void refused(Throwing body,String why)throws Exception{
        try{body.run();throw new AssertionError(why);}
        catch(InvocationTargetException e){check(e.getCause() instanceof IllegalStateException||e.getCause() instanceof IllegalArgumentException,why+" exact exception");}
        catch(ActionDecision.InvalidActionException expected){check(true,why);}
    }
    private static LocalRuntimeConfig config(ModelProfile p,String compute){
        return new LocalRuntimeConfig(p,compute,8192,4,p==ModelProfile.LFM3_VL_2B);
    }
    private static Method method(String name,Class<?>... parameters)throws Exception{
        Method value=PromptAdmissionFixture.class.getDeclaredMethod(name,parameters);value.setAccessible(true);return value;
    }
    private static DecisionGrammar select(LocalRuntimeConfig cfg,DecisionGrammar grammar)throws Exception{
        return (DecisionGrammar)method("profileGrammar",LocalRuntimeConfig.class,DecisionGrammar.class).invoke(null,cfg,grammar);
    }
    private static String system(LocalRuntimeConfig cfg,boolean nativeApp)throws Exception{
        return (String)method("systemPrompt",LocalRuntimeConfig.class,boolean.class).invoke(null,cfg,nativeApp);
    }
    private static Object field(Object owner,String name)throws Exception{
        Field f=owner.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(owner);
    }
    private static PhoneObservation screen(){
        List<PhoneObservation.Node> nodes=new ArrayList<PhoneObservation.Node>();
        nodes.add(new PhoneObservation.Node("n0",PKG,"android.widget.TextView",PKG+":id/title",
                "笔记列表","",new Rect(0,0,1080,100),false,false,false,true,false,false,
                ObservedChildText.notApplicable(),ObservedScrollActions.observed(Collections.<String>emptyList())));
        int[] bounds={0,0,1080,2400};
        return new PhoneObservation(OBS,PKG,100,1080,2400,0,7,new Rect(0,0,1080,2400),
                null,"synthetic-tree","synthetic-state",new ObservationState("synthetic-state",ImeVisibility.HIDDEN),
                ObservedWindowMetadata.observed(bounds,"android.widget.FrameLayout",1,0,bounds,"合成笔记列表"),
                false,nodes);
    }
    private static Object prompt(LocalRuntimeConfig cfg)throws Exception{
        Method actual=null;
        for(Method candidate:PromptAdmissionFixture.class.getDeclaredMethods())
            if(candidate.getName().equals("prompt")&&candidate.getParameterTypes().length==14){
                if(actual!=null)throw new AssertionError("ambiguous actual prompt");actual=candidate;
            }
        check(actual!=null,"actual complete 14-argument prompt exists");actual.setAccessible(true);
        Map<String,String> apps=Collections.singletonMap(PKG,"Moto 笔记");
        Map<String,FixedIntentTarget> fixed=Collections.singletonMap("notes.create",new FixedIntentTarget("notes.create","Moto 笔记",10482,null));
        TaskAuthorization.Gate bound=TaskAuthorization.parse(OWNER).bind(TASK);
        TaskCompletionGate completion=new TaskCompletionGate(TASK,OWNER,bound.authorization);
        // Explicit synthetic PackageManager facts and the actual observation bridge.
        // No launch/save/list/reopen receipt is supplied, so completion remains false.
        PhoneObservation observed=screen();
        NotesCompletionEvidence.Frame current=(NotesCompletionEvidence.Frame)method("completionFrame",PhoneObservation.class).invoke(null,observed);
        completion.bindInstalled(new NotesCompletionEvidence.Installed(PKG,10482,
                Collections.singletonMap("base","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")));
        completion.observed(current);
        check(completion.notesPhase(current).domainValid&&!completion.verified(current),"synthetic same-domain prerequisite does not claim completion");
        return actual.invoke(null,OWNER,new AppCatalogueRanker(apps,OWNER).search("",0),observed,new JSONArray(),
                null,null,null,cfg,new RepeatActionGuard(),new SameStateNoEffectGuard(),
                bound.frame(),null,fixed,completion);
    }
    private static void sameDomain(DecisionGrammar old,DecisionGrammar compact){
        check(old!=compact,"compact grammar has its own text and hash");
        check(old.observationId==compact.observationId&&old.currentPackage==compact.currentPackage,"observation/package string identity");
        check(old.schema==compact.schema,"exact schema identity, including v3/v4/v5");
        check(old.targets==compact.targets&&old.appLabels==compact.appLabels,"same observed labels and app pairs");
        check(old.authorization==compact.authorization,"same bound OWNER/frame authority");
        check(old.actions==compact.actions,"same immutable action domain");
        check(old.scrollDirections==compact.scrollDirections&&old.submitNodes==compact.submitNodes,"same scroll/submit domain");
        check(old.fixedIntentTargets==compact.fixedIntentTargets,"same installed fixed-intent target domain");
        check(old.doneStatuses==compact.doneStatuses&&old.successAllowed==compact.successAllowed,"same completion predicate");
        String[] before=old.text.split("\n",-1),after=compact.text.split("\n",-1);
        check(before.length==after.length,"format narrowing preserves every complete grammar rule");
        int changed=0;
        for(int i=0;i<before.length;i++){
            if(before[i].startsWith("reason-string ::= ")){
                check(after[i].equals(before[i].replace("json-char{1,96}","json-char{1,24}")),"only reason bound changes");changed++;
            }else if(before[i].startsWith("ws ::= ")){
                check(after[i].equals("ws ::= \"\""),"structural whitespace is exactly empty");changed++;
            }else check(before[i].equals(after[i]),"all nonformat rule bytes retained at "+i);
        }
        check(changed==2,"exactly two complete rule projections");
        check(MobiMindContract.sha(compact.text.getBytes(StandardCharsets.UTF_8)).equals(compact.sha256),"hash binds actual compact text");
        check(!old.sha256.equals(compact.sha256),"original hash is not reused");
    }
    private static Map<String,DecisionGrammar> grammars(){
        Set<String> apps=Collections.singleton("org.example.settings");
        Set<String> clicks=Collections.singleton("n1"),edits=Collections.singleton("n2");
        Map<String,String> labels=new TreeMap<String,String>();labels.put("n1","保存");labels.put("n2","查询");labels.put("n3","列表");
        ObservedTargetLabels targets=ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,OBS,PKG,labels);
        ObservedAppLabels appLabels=ObservedAppLabels.create(ObservedAppLabels.SCHEMA,OBS,PKG,Collections.singletonMap("org.example.settings","设置"));
        ObservedAppLabels noApps=ObservedAppLabels.create(ObservedAppLabels.SCHEMA,OBS,PKG,Collections.<String,String>emptyMap());
        Map<String,ObservedScrollActions> scroll=new TreeMap<String,ObservedScrollActions>();
        scroll.put("n3",ObservedScrollActions.observed(Arrays.asList("forward","backward","down")));
        Map<String,ObservedImeEnter> submits=Collections.<String,ObservedImeEnter>emptyMap();
        TaskAuthorization.Frame auth=TaskAuthorization.parse(OWNER).bind(TASK).frame();
        Map<String,FixedIntentTarget> fixed=Collections.singletonMap("notes.create",new FixedIntentTarget("notes.create","Moto 笔记",10482,null));
        Map<String,DecisionGrammar> out=new LinkedHashMap<String,DecisionGrammar>();
        out.put("v3",DecisionGrammar.create(OBS,PKG,apps,clicks,edits,scroll,targets));
        out.put("v4",DecisionGrammar.createAppLabeled(OBS,PKG,apps,clicks,edits,scroll,targets,appLabels));
        out.put("v5",DecisionGrammar.createImeAuthorized(OBS,PKG,apps,clicks,edits,scroll,submits,targets,appLabels,auth,false));
        out.put("v6",DecisionGrammar.createFixedIntentAuthorized(OBS,PKG,apps,clicks,edits,scroll,submits,targets,appLabels,auth,false,fixed,
                Collections.singletonMap("notes.create",BODY),null,false,new TreeSet<String>(Arrays.asList("failure","partial"))));
        out.put("v6-payload",DecisionGrammar.createFixedIntentAuthorized(OBS,PKG,apps,clicks,edits,scroll,submits,targets,appLabels,auth,false,fixed,
                Collections.singletonMap("notes.create",PAYLOAD),null,false));
        out.put("restricted",DecisionGrammar.createImeAuthorized(OBS,PKG,Collections.<String>emptySet(),
                Collections.<String>emptySet(),Collections.<String>emptySet(),Collections.<String,ObservedScrollActions>emptyMap(),
                submits,targets,noApps,auth,true,new TreeSet<String>(Arrays.asList("wait","done")),false));
        out.put("wait-only",DecisionGrammar.createBoundedWaitAuthorized(OBS,PKG,targets,noApps,auth,Collections.singleton("wait")));
        return out;
    }
    private static void write(Path path,String value)throws Exception{Files.write(path,value.getBytes(StandardCharsets.UTF_8));}
    public static void main(String[] args)throws Exception{
        Path out=Paths.get(args[0]);Files.createDirectories(out);
        boolean baseline="baseline-export".equals(args[1]);
        Map<String,DecisionGrammar> original=grammars();
        JSONArray grammarRows=new JSONArray();
        for(Map.Entry<String,DecisionGrammar> pair:original.entrySet()){
            write(out.resolve(pair.getKey()+"-original.gbnf"),pair.getValue().text);
            if(!baseline){
                DecisionGrammar narrowed=select(config(ModelProfile.LFM25_8B_A1B,"npu"),pair.getValue());
                sameDomain(pair.getValue(),narrowed);write(out.resolve(pair.getKey()+"-compact.gbnf"),narrowed.text);
                final DecisionGrammar already=narrowed;
                refused(new Throwing(){public void run()throws Exception{select(config(ModelProfile.LFM25_8B_A1B,"npu"),already);}},"already compact input cannot be silently reformatted");
                caseDone("unchanged_bound_domain_"+pair.getKey());
            }
            grammarRows.put(new JSONObject().put("name",pair.getKey()).put("schema",pair.getValue().schema).put("sha256",pair.getValue().sha256));
        }
        JSONArray profileRows=new JSONArray();
        int profiles=0;
        for(Field profileField:ModelProfile.class.getFields()){
            if(profileField.getType()!=ModelProfile.class)continue;
            ModelProfile profile=(ModelProfile)profileField.get(null);profiles++;
            for(String compute:profile==ModelProfile.LFM25_8B_A1B?Arrays.asList("npu","gpu"):Collections.singletonList("npu")){
                LocalRuntimeConfig cfg=config(profile,compute);
                Object full=prompt(cfg);DecisionGrammar grammar=(DecisionGrammar)field(full,"grammar");
                String input=(String)field(full,"text");
                ConservativeTokenBudget budget=(ConservativeTokenBudget)field(full,"budget");
                Method bm=full.getClass().getDeclaredMethod("budgetJson");bm.setAccessible(true);
                JSONObject receipt=(JSONObject)bm.invoke(full);
                String system=system(cfg,false),nativeSystem=system(cfg,true);
                String id=profile.id+"-"+compute;
                write(out.resolve(id+".gbnf"),grammar.text);write(out.resolve(id+".system.txt"),system);
                write(out.resolve(id+".native-system.txt"),nativeSystem);write(out.resolve(id+".prompt.txt"),input);
                check(input.endsWith("\nOWNER\n"+OWNER),"complete immutable owner retained");
                check(grammar.authorization!=null&&TASK.equals(grammar.authorization.taskId),"full prompt keeps actual task binding");
                check(grammar.fixedIntentTargets.containsKey("notes.create")&&grammar.actions.contains("notes.create"),"full prompt retains the observed fixed tool for "+profile.id);
                check(receipt.getString("grammar_sha256").equals(grammar.sha256),"prompt evidence uses the very same selected grammar hash");
                check(budget.systemBytesUpper==system.getBytes(StandardCharsets.UTF_8).length,"same selected system reaches budgeting");
                check(LocalRuntimeConfig.GENERATION_TOKENS==256&&ConservativeTokenBudget.GENERATION==256,"generation token bound remains 256");
                if(!baseline){
                    if(profile==ModelProfile.LFM25_8B_A1B){
                        check(grammar.text.contains("json-char{1,24}")&&grammar.text.contains("ws ::= \"\"\n"),"actual full prompt selects compact grammar");
                        check(system.startsWith(PromptAdmissionFixture.system())&&system.endsWith("字符串内的原始标签和OWNER完整正文逐字保留。\n"),"only compact profile appends format instruction");
                        check(nativeSystem.startsWith(VisualPromptProjection.NATIVE_SYSTEM),"native application prompt retains original native contract");
                        check(!grammar.successAllowed,"compact format does not grant completion");
                    }else{
                        DecisionGrammar prior=original.get("v6");
                        check(select(cfg,prior)==prior,"other profile returns exact original grammar object");
                        check(system.equals(profile.visual()?VisualPromptProjection.SYSTEM:PromptAdmissionFixture.system()),"other profile system bytes unchanged");
                        check(nativeSystem.equals(profile.visual()?VisualPromptProjection.SYSTEM:VisualPromptProjection.NATIVE_SYSTEM),"other profile native system bytes unchanged");
                    }
                    caseDone("actual_full_prompt_"+id);
                }
                profileRows.put(new JSONObject().put("profile",profile.id).put("compute",compute).put("grammar_sha256",grammar.sha256)
                        .put("system_sha256",MobiMindContract.sha(system.getBytes(StandardCharsets.UTF_8))).put("native_system_sha256",MobiMindContract.sha(nativeSystem.getBytes(StandardCharsets.UTF_8)))
                        .put("prompt_sha256",MobiMindContract.sha(input.getBytes(StandardCharsets.UTF_8))).put("grammar_schema",grammar.schema)
                        .put("generation_tokens",LocalRuntimeConfig.GENERATION_TOKENS).put("synthetic_observation",true));
            }
        }
        if(!baseline){
            final LocalRuntimeConfig cfg=config(ModelProfile.LFM25_8B_A1B,"npu");
            refused(new Throwing(){public void run()throws Exception{select(null,original.get("v6"));}},"null config rejected");
            refused(new Throwing(){public void run()throws Exception{select(cfg,null);}},"null grammar rejected");
            caseDone("null_profile_context_never_grants_grammar");
        }
        String partial=new String(Files.readAllBytes(Paths.get(args[2])),StandardCharsets.UTF_8);
        refused(new Throwing(){public void run()throws Exception{ActionDecision.parse(partial,ActionDecision.FIXED_INTENT_ACTION_SCHEMA);}},
                "actual archived partial output stays rejected");
        if(!baseline)caseDone("actual_phone_partial_strict_parser_rejection");
        JSONObject report=new JSONObject().put("schema","hepta.case05-compact-grammar-host-java.v1")
                .put("baseline_export_only",baseline).put("profiles",profiles).put("cases",new JSONArray(cases)).put("assertions",assertions)
                .put("grammars",grammarRows).put("profile_rows",profileRows).put("body",BODY).put("synthetic_whitespace_payload",PAYLOAD)
                .put("phone_operations",false).put("model_inference",false).put("synthetic_complete_examples_are_phone_results",false);
        write(out.resolve("JAVA-RESULT.json"),report.toString());
        System.out.println("PASS cases="+cases.size()+" assertions="+assertions+" profiles="+profiles+" baseline_export_only="+baseline);
    }
}
