import org.trillionnium.hepta.local.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Production parser, grammar, capability and ledger. No Android or model IO. */
public final class ImeSubmitHostTest {
    static final String OBS="f91c685bf5f04f5c9a6a3197eade1fed",PKG="com.example.search",TASK="11111111111111111111111111111111";
    static int assertions;
    interface Call{void run()throws Exception;}
    static void check(boolean yes,String why){assertions++;if(!yes)throw new AssertionError(why);}
    static void rejects(Call body,String why)throws Exception{try{body.run();}catch(Exception expected){assertions++;return;}throw new AssertionError(why);}
    static String raw(String action,String extra){return "{\"reason\":\"观察当前字段\",\"action\":\""+action+"\",\"observation_id\":\""+OBS+"\",\"package\":\""+PKG+"\",\"node_label\":\"query\",\"node_id\":\"n1\""+extra+"}";}
    static SubmitAttemptGuard.Binding binding(String text){return new SubmitAttemptGuard.Binding(TASK,"model-run",OBS,PKG,"n1",7,9,"generation",ObservedImeEnter.hash(text),ObservedImeEnter.present("搜索"));}
    static DecisionGrammar grammar(String owner,boolean background){
        Map<String,String> labels=new LinkedHashMap<String,String>();labels.put("n1","query");labels.put("n2","query");labels.put("n3","");
        ObservedTargetLabels targets=ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,OBS,PKG,labels);
        ObservedAppLabels apps=ObservedAppLabels.create(ObservedAppLabels.SCHEMA,OBS,PKG,Collections.<String,String>emptyMap());
        return DecisionGrammar.createImeAuthorized(OBS,PKG,Collections.<String>emptySet(),labels.keySet(),labels.keySet(),
                Collections.<String,ObservedScrollActions>emptyMap(),Collections.singletonMap("n1",ObservedImeEnter.present("搜索")),targets,apps,
                TaskAuthorization.parse(owner).bind(TASK).frame(),background);
    }
    public static void main(String[] args)throws Exception{
        Path out=Paths.get(args[0]);Files.createDirectories(out);
        for(String label:new String[]{"搜索","搜尋","查询","查詢","查找","search","query","find","  SeArCh  ","ＳＥＡＲＣＨ"})
            check(ObservedImeEnter.present(label).queryAllowed(),"explicit query label "+label);
        for(String label:new String[]{null,"","Enter","↵","Go","Done","Next","确认","提交","发送","支付","付款","下单","购买","搜索并付款","search now","search\u0000","\uD800"})
            check(!ObservedImeEnter.present(label).queryAllowed(),"unknown/commit label must not grant "+label);
        check(!ObservedImeEnter.UNKNOWN.queryAllowed()&&!ObservedImeEnter.ABSENT.queryAllowed(),"absence and unknown cannot grant");
        check(!ObservedImeEnter.UNKNOWN.fingerprintInput().equals(ObservedImeEnter.ABSENT.fingerprintInput()),"unknown is not known absence");
        check(!ObservedImeEnter.present("Search").fingerprintInput().equals(ObservedImeEnter.present("search").fingerprintInput()),"normalization does not erase raw-label freshness");
        String hash=ObservedImeEnter.hash("完整输入😀\n后缀");
        check(hash.equals(ObservedImeEnter.completeTextHash("完整输入😀\n后缀")),"full input uses exact valid UTF-8 without normalization");
        check(ObservedImeEnter.completeTextHash(null)==null,"unknown text cannot become empty input identity");
        check(ObservedImeEnter.completeTextHash("query\uD800")==null,"unpaired high surrogate cannot become replacement input identity");
        check(ObservedImeEnter.completeTextHash("query\uDC00")==null,"unpaired low surrogate cannot become replacement input identity");
        check(!ObservedImeEnter.present("搜索").bindFreshness("node",true,hash).equals(ObservedImeEnter.present("搜索").bindFreshness("node",false,hash)),"input focus is fresh identity");
        check(ObservedImeEnter.present("搜索").projection(hash).get("input_text_sha256").equals(hash),"projection binds complete input hash");
        ActionDecision action=ActionDecision.parse(raw("submit",""),ActionDecision.IME_ACTION_SCHEMA);
        check("submit".equals(action.action)&&"n1".equals(action.nodeId),"v5 accepts exact node action");
        for(String old:new String[]{ObservedTargetLabels.ACTION_SCHEMA,ObservedAppLabels.ACTION_SCHEMA})
            rejects(()->ActionDecision.parse(raw("submit",""),old),"legacy protocol cannot submit");
        for(String extra:new String[]{",\"text\":\"x\"",",\"keycode\":66",",\"action_id\":1",",\"ime_action_id\":3",",\"display_id\":9",",\"x\":10",",\"y\":10",",\"shell\":\"input\"",",\"node_id\":\"n2\""})
            rejects(()->ActionDecision.parse(raw("submit",extra),ActionDecision.IME_ACTION_SCHEMA),"extra dispatch parameter rejected");
        check(ActionDecision.parse(raw("type",",\"text\":\"line\\nline\""),ActionDecision.IME_ACTION_SCHEMA).text.equals("line\nline"),"type remains exact text data");
        DecisionGrammar allowed=grammar("查找当前应用中的商品。",false),denied=grammar("只允许输入和结束。",false),background=grammar("查询航班。",true);
        check(allowed.schema.equals(ActionDecision.IME_ACTION_SCHEMA)&&allowed.allowsSubmit("n1")&&!allowed.allowsSubmit("n2"),"precise observed node domain");
        check(!denied.actions.contains("submit")&&!denied.allowsSubmit("n1"),"type permission does not grant submit");
        check(background.allowsSubmit("n1")&&!background.actions.contains("home"),"background has same node submit without global HOME");
        check(!grammar("禁止提交，查询当前画面。",false).allowsSubmit("n1"),"explicit submit prohibition");
        check(grammar("输入“先提交查询，再查看结果”作为备忘录文字。",false).allowsSubmit("n1"),"quoted sequence does not impose tool order");
        rejects(()->grammar("输入“禁止提交”作为查询词。",false),"existing ambiguous quoted tool restriction remains fail closed");
        check(!grammar("先查找时钟应用，再打开它。",false).allowsSubmit("n1"),"submit cannot bypass discovery order");
        Files.write(out.resolve("submit.gbnf"),allowed.text.getBytes(StandardCharsets.UTF_8));
        Files.write(out.resolve("submit-denied.gbnf"),denied.text.getBytes(StandardCharsets.UTF_8));
        Files.write(out.resolve("submit-background.gbnf"),background.text.getBytes(StandardCharsets.UTF_8));
        final List<Map<String,Object>> journal=new ArrayList<Map<String,Object>>();
        SubmitAttemptGuard guard=new SubmitAttemptGuard(TASK,attempt->journal.add(attempt.journal()));
        check(guard.available(PKG,ObservedImeEnter.hash("query")),"new exact input available");
        check(!guard.available("android",hash)&&!guard.available(null,hash)&&!guard.available(PKG,null),"unknown input/package does not break observation");
        SubmitAttemptGuard.Attempt first=guard.consume(binding("query"));
        check(journal.size()==1&&"consumed_before_call".equals(journal.get(0).get("stage")),"durable attempt precedes entering");
        check(!journal.get(0).containsKey("dispatch_attempted"),"journal cannot falsely prove a call already occurred");
        check(!guard.available(PKG,ObservedImeEnter.hash("query")),"consumption blocks same input before API");
        rejects(()->guard.consume(binding("query")),"same input cannot be consumed twice");
        guard.entering(first);check("unknown".equals(guard.evidence(first).get("result")),"entering becomes uncertain before API returns");
        check(Boolean.TRUE.equals(guard.finished(first,null).get("dispatch_attempted")),"unknown is possibly dispatched");
        check(!guard.available(PKG,ObservedImeEnter.hash("query")),"unknown cannot re-arm input");
        SubmitAttemptGuard.Attempt second=guard.consume(binding("different query"));guard.entering(second);
        check("refused".equals(guard.finished(second,Boolean.FALSE).get("result")),"false result explicit");
        check(!guard.available(PKG,ObservedImeEnter.hash("different query")),"false result does not auto retry");
        SubmitAttemptGuard failed=new SubmitAttemptGuard(TASK,attempt->{throw new java.io.IOException("journal unavailable");});
        rejects(()->failed.consume(binding("query")),"journal failure prevents call");
        check(!failed.available(PKG,ObservedImeEnter.hash("query"))&&"not_dispatched".equals(failed.snapshot().get(0).get("result")),"journal failure preserves consumption without claiming dispatch");
        guard.retire();check(!guard.available(PKG,ObservedImeEnter.hash("new")),"retired task cannot issue");
        SubmitAttemptGuard bounded=new SubmitAttemptGuard(TASK,attempt->{});
        for(int i=0;i<SubmitAttemptGuard.MAX_ATTEMPTS;i++)bounded.consume(binding("query"+i));
        rejects(()->bounded.consume(binding("overflow")),"full ledger cannot evict earlier attempts");
        check(bounded.snapshot().size()==20,"bounded records retained");
        Map<String,Object> history=new LinkedHashMap<String,Object>();history.put("step",1);history.put("action","submit");history.put("node_id","n1");history.put("node_label","query");history.put("dispatched",true);history.put("submit_input_sha256",hash);history.put("submit_result","accepted");history.put("submit_attempt_consumed",true);
        check(RecentActionProjection.project(history).get("submit_input_sha256").equals(hash),"compact history retains input identity");
        check(RecentActionProjection.dispatched(history).get("submit_result").equals("accepted"),"dispatch history retains result distinct from success");
        check(RecentActionProjection.compactEvents(Collections.singletonList(history),0).arguments.get(0).get("submit_input_sha256").equals(hash),"lowest detail keeps submit attempt facts");
        System.out.println("{\"assertions\":"+assertions+",\"passed\":true,\"phone_tested\":false,\"native_inference\":false}");
    }
}
