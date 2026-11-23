package org.trillionnium.hepta.local;

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
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Frame;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Installed;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Node;
import org.trillionnium.hepta.local.CalculatorCompletionEvidence.Match;
import org.trillionnium.hepta.local.CalculatorCompletionEvidence.TaskBinding;

/** Actual pure production classes. Positive observations/identities are explicit
 * synthetic host IO. Archived JSON is kept raw and is never filled with missing
 * live input/source hashes. No native/phone/application-calculation proof. */
public final class CalculatorCompletionHostTest {
    private static final String P=CalculatorGoalContract.PACKAGE;
    private static final String TASK="11111111111111111111111111111111";
    private static final String OTHER="22222222222222222222222222222222";
    private static final String GENERATION="11111111-1111-1111-1111-111111111111";
    private static final String OTHER_GENERATION="22222222-2222-2222-2222-222222222222";
    private static final String H="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static final String H2="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private static int assertions,observations;
    private static final List<String> passed=new ArrayList<String>();
    private interface Checked {void run()throws Exception;}
    private static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    private static void test(String name,Checked body)throws Exception{body.run();passed.add(name);System.out.println("PASS "+name);}
    private static void rejects(Checked body)throws Exception{boolean refused=false;try{body.run();}catch(IllegalArgumentException|IllegalStateException expected){refused=true;}check(refused,"invalid immutable binding rejected");}
    private static String owner(String expression){return "打开计算器，在当前主输入区计算 "+expression+"，确认当前结果框显示计算结果后结束任务。";}
    private static CalculatorGoalContract goal(String expression){String o=owner(expression);return CalculatorGoalContract.parse(o,TaskAuthorization.parse(o));}
    private static boolean unsupportedGoal(String expression){
        try{return goal(expression)==null;}catch(TaskAuthorization.Violation unsupportedOwner){return true;}
    }
    private static Installed installed(){return new Installed(P,10351,Collections.singletonMap("base",H));}
    private static TaskBinding binding(CalculatorGoalContract goal,int display){return new TaskBinding(TASK,goal,installed(),display,display==0?null:GENERATION);}
    private static Node node(String id,String text,String view){return node(id,P,text,view,ObservedImeEnter.completeTextHash(text),H,true,true,false);}
    private static Node node(String id,String pkg,String text,String view,String input,String source,boolean editable,boolean enabled,boolean password){
        return new Node(id,pkg,text,text,view,input,new int[]{10,100,600,250},editable,true,false,enabled,password,ObservedChildText.notApplicable(),source);
    }
    private static Frame frame(int display,String generation,List<Node> nodes){
        return new Frame(String.format(java.util.Locale.ROOT,"%032x",++observations),P,12,display,generation,1,true,false,nodes);
    }
    private static Frame pair(String expression,String result){return frame(7,GENERATION,Arrays.asList(node("n1",expression,CalculatorCompletionEvidence.FORMULA),node("n2",result,CalculatorCompletionEvidence.RESULT)));}
    private static Match inspect(CalculatorGoalContract goal,Frame frame){return CalculatorCompletionEvidence.inspect(binding(goal,7),TASK,goal,frame,installed());}
    private static void no(Match value,String why){check(!value.currentArithmeticObserved,why);check(!value.completionVerified,"UI evidence is never whole completion");}
    private static String digest(byte[] b){try{byte[] d=java.security.MessageDigest.getInstance("SHA-256").digest(b);StringBuilder s=new StringBuilder();for(byte x:d)s.append(String.format(java.util.Locale.ROOT,"%02x",x&255));return s.toString();}catch(java.security.NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}}

    private static void contractCases()throws Exception{
        test("owner_arbitrary_integer_ast_and_exact_big_integer",()->{
            String[][] cases={{"23 乘以 19","437"},{"31×47","1457"},{"17*29","493"},{"2+3*4","14"},{"(2+3)*4","20"},
                    {"7 加上 5 减去 3","9"},{"-12*3","-36"},{"2*-3","-6"},{"2--3","5"},{"0009×4","36"},
                    {"（8−3）×2","10"},{"99999999999999999999999999999999+1","100000000000000000000000000000000"}};
            for(String[] c:cases){CalculatorGoalContract g=goal(c[0]);check(g!=null,"supported arbitrary expression "+c[0]);check(c[1].equals(g.expectedResult),"exact arithmetic "+c[0]);
                check(g.ownerSha256.equals(ObservedImeEnter.hash(owner(c[0]))),"raw owner SHA");check(Boolean.FALSE.equals(g.evidence().get("grants_tool_authority")),"contract cannot grant tools");}
            check(goal("31 乘以 47").matchesFormula("31×47"),"explicit operator spelling alias");
            check(!goal("31×47").matchesFormula("1457"),"answer literal is not the owner expression");
            check(!goal("31×47").matchesFormula("47×31"),"value equality alone cannot replace formula identity");
            check(!goal("2+3*4").matchesFormula("(2+3)*4"),"operator precedence preserved");
            check(goal("(2+3)*4").matchesFormula("((2+3))*4"),"redundant matched parentheses do not change AST");
        });
        test("owner_complete_consumption_and_authorization",()->{
            String good=owner("7*11");TaskAuthorization auth=TaskAuthorization.parse(good);
            check(CalculatorGoalContract.parse(good,auth)!=null,"exact whole OWNER accepted");
            rejects(()->CalculatorGoalContract.parse(owner("7*13"),auth));
            rejects(()->CalculatorGoalContract.parse(good,null));
            for(String s:Arrays.asList("不要"+good,good+"再查询机票。",good+"网页搜索。","记下“"+good+"”",good.replace("确认当前结果框","不要确认当前结果框"),good.replace("结束任务。","结束任务并付款。"))){
                check(CalculatorGoalContract.parse(s,TaskAuthorization.parse(s))==null,"negated/quoted/multiple/partial goal refused");
            }
            String old="打开计算器，计算 23 乘以 19，确认屏幕显示计算结果后结束任务。";
            check(CalculatorGoalContract.parse(old,TaskAuthorization.parse(old))!=null,"documented prior complete owner form");
            TaskCompletionGate untouched=new TaskCompletionGate(TASK,good,auth);
            check(TaskCompletionGate.UNKNOWN.equals(untouched.contract.kind),"pure candidate not integrated into existing completion");
            String web="通过 web.search 网页查询商品价格。";TaskCompletionGate unknownWeb=new TaskCompletionGate(TASK,web,TaskAuthorization.parse(web));
            check(!unknownWeb.verified(pair("7*11","77")),"existing WEB cannot borrow calculator evidence");
        });
        test("bounded_grammar_rejects_unsupported_or_ambiguous_input",()->{
            for(String s:Arrays.asList("", "2", "1/3", "2÷1", "2.5*4", "2%+1", "2^3", "2x3", "2X3", "1e3+1", "1,000+1", "１+2", "二加三", "2+", "(2+3", "（2+3)", "2+3=5", "2+3;4+5", "2\t+3", "2\n+3", "2\u200b+3", "2\u00a0+3", "2\0+3")){
                check(unsupportedGoal(s),"unsupported complete goal "+s.replace('\0','?'));
            }
            check(CalculatorGoalContract.parseExpression("(((((((((1+2)))))))))")==null,"parenthesis depth bounded");
            check(CalculatorGoalContract.parseExpression("---------1+2")==null,"unary depth bounded");
            check(CalculatorGoalContract.parseExpression("111111111111111111111111111111111+1")==null,"literal digits bounded");
            StringBuilder many=new StringBuilder("1");for(int i=0;i<25;i++)many.append("+1");
            check(CalculatorGoalContract.parseExpression(many.toString())==null,"binary count bounded");
            check(CalculatorGoalContract.parseExpression("99999999999999999999999999999999*99999999999999999999999999999999*9")==null,"intermediate magnitude bounded");
        });
    }
    private static void evidenceCases()throws Exception{
        test("synthetic_current_pair_observed_without_claiming_calculation",()->{
            for(String expression:Arrays.asList("23*19","31*47","17*29","-12*3","2+3*4")){
                CalculatorGoalContract g=goal(expression);Match m=inspect(g,pair(expression,g.expectedResult));
                check(m.currentArithmeticObserved,"complete synthetic current expression and integer observed");
                check(!m.completionVerified,"pure matcher never completes task");
                for(String k:Arrays.asList("completion_verified","model_calculation_causality_verified","final_observation_stability_verified","terminal_cleanup_verified","grants_tool_authority","automatic_dispatch"))
                    check(Boolean.FALSE.equals(m.evidence().get(k)),"not inferred from UI-only pair: "+k);
                check(m.formulaTextSha256.equals(ObservedImeEnter.hash(expression)),"complete formula hash retained");
                check(g.contractSha256.equals(m.evidence().get("contract_sha256")),"goal binding retained");
            }
            check(inspect(goal("-12*3"),pair("−12×3","−36")).currentArithmeticObserved,"explicit minus glyph on observed fields");
        });
        test("history_answer_only_wrong_formula_and_ambiguous_fields_rejected",()->{
            CalculatorGoalContract g=goal("23*19");
            no(inspect(g,pair("","437")),"answer in result with no actual formula");
            no(inspect(g,pair("437","437")),"directly entering answer is not formula evidence");
            no(inspect(g,pair("19*23","437")),"unrelated/equivalent expression cannot substitute owner AST");
            no(inspect(g,pair("23*19","438")),"wrong actual arithmetic result");
            no(inspect(g,pair("23*19"," 437 ")),"no trimming a result claim into an integer");
            no(inspect(g,pair("23*19","结果437")),"no substring result match");
            List<Node> rows=new ArrayList<Node>(pair("","0").nodes);
            rows.add(node("n3","23×19",P+":id/item_formula"));rows.add(node("n4","437",P+":id/item_result"));
            no(inspect(g,frame(7,GENERATION,rows)),"genuine history-role trap cannot prove main result");
            no(inspect(g,frame(7,GENERATION,Arrays.asList(node("n3","23×19",P+":id/item_formula"),node("n4","437",P+":id/item_result")))),"historical fields cannot substitute current resources");
            rows=new ArrayList<Node>(pair("23*19","437").nodes);rows.add(node("n3","437",CalculatorCompletionEvidence.RESULT));
            no(inspect(g,frame(7,GENERATION,rows)),"duplicate result field ambiguous");
            no(inspect(g,frame(7,GENERATION,Arrays.asList(node("n1","23*19",CalculatorCompletionEvidence.FORMULA),node("n1","437",CalculatorCompletionEvidence.RESULT)))),"duplicate node IDs invalid");
        });
        test("complete_actual_field_identity_required",()->{
            CalculatorGoalContract g=goal("23*19");Node result=node("n2","437",CalculatorCompletionEvidence.RESULT);
            for(Node f:Arrays.asList(
                    node("n1",P,"23*19",CalculatorCompletionEvidence.FORMULA,null,H,true,true,false),
                    node("n1",P,"23*19",CalculatorCompletionEvidence.FORMULA,H2,H,true,true,false),
                    node("n1",P,"23*19",CalculatorCompletionEvidence.FORMULA,ObservedImeEnter.hash("23*19"),null,true,true,false),
                    node("n1","foreign.app","23*19",CalculatorCompletionEvidence.FORMULA,ObservedImeEnter.hash("23*19"),H,true,true,false),
                    node("n1",P,"23*19",CalculatorCompletionEvidence.FORMULA,ObservedImeEnter.hash("23*19"),H,false,true,false),
                    node("n1",P,"23*19",CalculatorCompletionEvidence.FORMULA,ObservedImeEnter.hash("23*19"),H,true,false,false),
                    node("n1",P,"23*19",CalculatorCompletionEvidence.FORMULA,ObservedImeEnter.hash("23*19"),H,true,true,true),
                    node("n1",P,"23*19…",CalculatorCompletionEvidence.FORMULA,ObservedImeEnter.hash("23*19 and hidden suffix"),H,true,true,false)))
                no(inspect(g,frame(7,GENERATION,Arrays.asList(f,result))),"missing/clipped/foreign/disabled/source-less field");
        });
        test("task_owner_display_generation_and_installation_do_not_leak",()->{
            CalculatorGoalContract g=goal("23*19");TaskBinding b=binding(g,7);Frame f=pair("23*19","437");
            no(CalculatorCompletionEvidence.inspect(b,OTHER,g,f,installed()),"foreign task");
            no(CalculatorCompletionEvidence.inspect(b,TASK,goal("23 乘以 19"),f,installed()),"different raw owner despite same value");
            no(inspect(g,frame(8,GENERATION,f.nodes)),"foreign display");
            no(inspect(g,frame(7,OTHER_GENERATION,f.nodes)),"foreign virtual generation");
            no(inspect(g,frame(7,null,f.nodes)),"unknown virtual generation");
            for(Installed changed:Arrays.asList(new Installed(P,10352,Collections.singletonMap("base",H)),
                    new Installed(P,10351,Collections.singletonMap("base",H2)),new Installed("foreign.app",10351,Collections.singletonMap("base",H)),
                    new Installed(P,10351,Collections.singletonMap("split:only",H))))
                no(CalculatorCompletionEvidence.inspect(b,TASK,g,f,changed),"changed UID/APK/package or missing base");
            Map<String,String> split=new LinkedHashMap<String,String>();split.put("base",H);split.put("split:config",H2);
            no(CalculatorCompletionEvidence.inspect(b,TASK,g,f,new Installed(P,10351,split)),"new split invalidates captured identity");
            rejects(()->new TaskBinding(TASK,g,installed(),0,GENERATION));
            rejects(()->new TaskBinding(TASK,g,installed(),7,null));
            rejects(()->new TaskBinding(TASK,g,new Installed(P,1000,Collections.singletonMap("base",H)),0,null));
            Frame foreground=frame(0,null,f.nodes);
            check(CalculatorCompletionEvidence.inspect(binding(g,0),TASK,g,foreground,installed()).currentArithmeticObserved,"foreground goal has explicit display0/no-generation domain");
        });
        test("incomplete_wrong_window_and_unobserved_metadata_fail",()->{
            CalculatorGoalContract g=goal("23*19");Frame f=pair("23*19","437");
            no(inspect(g,new Frame(f.observationId,P,12,7,GENERATION,1,true,true,f.nodes)),"node truncation");
            no(inspect(g,new Frame(f.observationId,P,12,7,GENERATION,1,false,false,f.nodes)),"unobserved window metadata");
            no(inspect(g,new Frame(f.observationId,P,12,7,GENERATION,2,true,false,f.nodes)),"non-application window");
            no(inspect(g,new Frame(f.observationId,"foreign.app",12,7,GENERATION,1,true,false,f.nodes)),"foreign current app");
            no(inspect(g,new Frame("unknown",P,12,7,GENERATION,1,true,false,f.nodes)),"unknown observation identity");
        });
    }
    private static String currentText(JSONObject frame,String view)throws Exception{
        JSONArray nodes=frame.getJSONArray("nodes");String found=null;int count=0;
        for(int i=0;i<nodes.length();i++){JSONObject n=nodes.getJSONObject(i);if(view.equals(optionalString(n,"view_id"))){found=optionalString(n,"text");count++;}}
        check(count==1,"archived current role is unique");return found;
    }
    private static String optionalString(JSONObject object,String key)throws Exception{return object.has(key)&&!object.isNull(key)?object.getString(key):"";}
    private static Frame legacyFrame(JSONObject raw)throws Exception{
        List<Node> nodes=new ArrayList<Node>();JSONArray entries=raw.getJSONArray("nodes");
        for(int i=0;i<entries.length();i++){
            JSONObject n=entries.getJSONObject(i);JSONArray b=n.getJSONArray("bounds");String text=optionalString(n,"text");
            // Missing raw facts remain missing. In particular the frame package
            // does not invent an archived per-node package or full input SHA.
            nodes.add(new Node(n.getString("id"),optionalString(n,"package"),text,text,optionalString(n,"view_id"),
                    n.has("input_text_sha256")&&!n.isNull("input_text_sha256")?n.getString("input_text_sha256"):null,
                    new int[]{((Number)b.get(0)).intValue(),((Number)b.get(1)).intValue(),((Number)b.get(2)).intValue(),((Number)b.get(3)).intValue()},n.optBoolean("editable",false),n.optBoolean("clickable",false),
                    n.optBoolean("scrollable",false),n.optBoolean("enabled",true),n.optBoolean("password",false),ObservedChildText.notApplicable(),
                    n.has("node_app_tree_sha256")?n.getString("node_app_tree_sha256"):null));
        }
        JSONObject w=raw.getJSONObject("window");
        return new Frame(raw.getString("observation_id"),raw.getString("package"),raw.getInt("window_id"),w.getInt("display_id"),null,w.getInt("type"),
                "observed".equals(optionalString(w,"metadata_status")),raw.optBoolean("nodes_truncated",false),nodes);
    }
    private static void rawArchiveCases(Path fixtures)throws Exception{
        test("real_archived_current_vs_history_roles_preserved_without_fabricated_hashes",()->{
            String[][] files={{"foreground-nanbeige-step05-after.json","df1978596e1d84e77b488a21459f1d7ef96636027ec0968b5ff14ae2fe9ff21c"},
                    {"foreground-qwen35-step01-before.json","e43e983ecf8c2144e2aae2593264938b208882d9539f4503a5094af15038a052"}};
            JSONObject[] originals=new JSONObject[2];CalculatorGoalContract g=goal("23*19");
            for(int i=0;i<files.length;i++){
                byte[] raw=Files.readAllBytes(fixtures.resolve(files[i][0]));check(files[i][1].equals(digest(raw)),"exact original archive bytes");
                originals[i]=new JSONObject(new String(raw,StandardCharsets.UTF_8));
                no(CalculatorCompletionEvidence.inspect(binding(g,0),TASK,g,legacyFrame(originals[i]),installed()),"old missing source/input identities cannot pass new provider");
            }
            check("23×19".equals(currentText(originals[0],CalculatorCompletionEvidence.FORMULA)),"real completed-looking main formula");
            check("437".equals(currentText(originals[0],CalculatorCompletionEvidence.RESULT)),"real current result");
            check("".equals(currentText(originals[1],CalculatorCompletionEvidence.FORMULA)),"real second main formula empty");
            check("0".equals(currentText(originals[1],CalculatorCompletionEvidence.RESULT)),"real second current result zero");
            check("437".equals(currentText(originals[1],P+":id/item_result")),"same expected number only in real history");
        });
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=2)throw new IllegalArgumentException("fixtures and new result path required");
        contractCases();evidenceCases();rawArchiveCases(Paths.get(args[0]));
        JSONObject result=new JSONObject().put("schema","hepta.calculator-pure-host.v1").put("all_pass",true)
                .put("assertions",assertions).put("passed_cases",new JSONArray(passed)).put("positive_observations_are_synthetic_host_io",true)
                .put("causal_gate_implemented",false).put("controller_integrated",false).put("phone_tested",false).put("native_inference",false);
        Files.write(Paths.get(args[1]),(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),java.nio.file.StandardOpenOption.CREATE_NEW);
        System.out.println("CalculatorCompletionHostTest assertions="+assertions+" cases="+passed.size());
    }
}
