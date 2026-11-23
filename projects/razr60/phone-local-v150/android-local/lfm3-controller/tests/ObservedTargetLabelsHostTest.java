import org.trillionnium.hepta.local.ActionDecision;
import org.trillionnium.hepta.local.ActionPolicy;
import org.trillionnium.hepta.local.ObservedTargetLabels;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** Real immutable projection, parser and policy; no Android, model or dispatch. */
public final class ObservedTargetLabelsHostTest {
    private static final String OBS="0123456789abcdef0123456789abcdef";
    private static final String PKG="com.example.app";
    private static int checks;
    private interface Attempt { void run() throws Exception; }
    private static void check(boolean yes,String detail){checks++;if(!yes)throw new AssertionError(detail);}
    private static void rejected(String detail,Attempt attempt)throws Exception{
        boolean rejected=false;
        try{attempt.run();}catch(ActionDecision.InvalidActionException|IllegalArgumentException expected){rejected=true;}
        check(rejected,detail);
    }
    private static String quote(String value){
        StringBuilder out=new StringBuilder("\"");
        for(int i=0;i<value.length();i++){
            char c=value.charAt(i);
            if(c=='\"'||c=='\\')out.append('\\').append(c);
            else if(c<32)out.append(String.format(java.util.Locale.ROOT,"\\u%04x",(int)c));
            else out.append(c);
        }
        return out.append('"').toString();
    }
    private static String raw(String action,String label,String id){
        String value="{\"reason\":\"仅解释，不决定目标\",\"action\":"+quote(action)
                +",\"observation_id\":"+quote(OBS)+",\"package\":"+quote(PKG);
        if(label!=null)value+=",\"node_label\":"+quote(label);
        if(id!=null)value+=",\"node_id\":"+quote(id);
        if("type".equals(action))value+=",\"text\":\"输入\"";
        if("scroll".equals(action))value+=",\"direction\":\"down\"";
        return value+"}";
    }
    private static void authorize(String raw,ObservedTargetLabels binding)throws Exception{
        ActionPolicy.validateTextDecision(ActionDecision.parse(raw,ObservedTargetLabels.ACTION_SCHEMA),PKG,
                Collections.<String>emptySet(),binding);
    }
    public static void main(String[] args)throws Exception{
        Map<String,String> source=new LinkedHashMap<String,String>();
        source.put("n12","1");source.put("n13","2");source.put("n14","3");
        source.put("n20","重复");source.put("n21","重复");source.put("n22","");source.put("n23","");
        source.put("n24","引号\"\\\n中文😀");
        final ObservedTargetLabels targets=ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,OBS,PKG,source);
        source.put("n12","changed");source.put("n99","added");
        check("1".equals(targets.labels.get("n12"))&&!targets.labels.containsKey("n99"),"snapshot cannot change with the input map");
        boolean immutable=false;try{targets.labels.put("n12","changed");}catch(UnsupportedOperationException expected){immutable=true;}
        check(immutable,"exposed projection is immutable");
        Map<String,String> reversed=new LinkedHashMap<String,String>();
        for(String id:new String[]{"n24","n23","n22","n21","n20","n14","n13","n12"})reversed.put(id,targets.labels.get(id));
        check(targets.sha256.equals(ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,OBS,PKG,reversed).sha256),"hash is independent of map insertion order");
        check(targets.sha256.matches("[0-9a-f]{64}"),"projection has an exact SHA-256 receipt");
        check("1c9ba0d8ad6b033070d323b5c6c5a21417f43337f1751a52cc25dc6282650fa3".equals(targets.sha256),"canonical hash matches the independent Python UTF-8/BE32 fixture");
        check(!targets.sha256.equals(ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,"f"+OBS.substring(1),PKG,reversed).sha256),"hash binds observation identity");
        check(!targets.sha256.equals(ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,OBS,"com.example.other",reversed).sha256),"hash binds package identity");
        reversed.put("n12","2");
        check(!targets.sha256.equals(ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,OBS,PKG,reversed).sha256),"hash binds the pair, not a bag of labels");
        for(String action:new String[]{"click","type","scroll"}){
            authorize(raw(action,"1","n12"),targets);
            check(true,action+" exact supplied pair accepted");
            rejected(action+" missing label is never recovered",()->ActionDecision.parse(raw(action,null,"n12")));
            rejected(action+" missing ID is not resolved by label",()->ActionDecision.parse(raw(action,"1",null)));
            rejected(action+" cross-product pair is denied",()->authorize(raw(action,"1","n13"),targets));
            rejected(action+" unknown label is denied",()->authorize(raw(action,"unknown","n12"),targets));
            rejected(action+" unshown ID is denied",()->authorize(raw(action,"1","n99"),targets));
            rejected(action+" wrong observation is denied",()->authorize(raw(action,"1","n12").replace(OBS,"f"+OBS.substring(1)),targets));
            rejected(action+" wrong package is denied",()->authorize(raw(action,"1","n12").replace(PKG,"com.example.other"),targets));
            rejected(action+" label order is mandatory",()->ActionDecision.parse(raw(action,"1","n12").replace("\"node_label\":\"1\",\"node_id\":\"n12\"","\"node_id\":\"n12\",\"node_label\":\"1\"")));
        }
        for(String id:new String[]{"n20","n21","n22","n23","n24"}){
            String label=targets.labels.get(id);
            ActionDecision action=ActionDecision.parse(raw("click",label,id));
            authorize(raw("click",label,id),targets);
            check(id.equals(action.nodeId)&&label.equals(action.nodeLabel),"duplicate/empty/escaped labels keep the original explicit ID");
        }
        String selected=raw("click","1","n12");
        ActionDecision conflictingReason=ActionDecision.parse(selected.replace("仅解释，不决定目标","点击文字3的n14"));
        ActionPolicy.validateTextDecision(conflictingReason,PKG,Collections.<String>emptySet(),targets);
        check("n12".equals(conflictingReason.nodeId)&&"1".equals(conflictingReason.nodeLabel),"reason cannot rewrite a valid pair");
        rejected("reason cannot rescue the wrong pair",()->authorize(raw("click","3","n12").replace("仅解释，不决定目标","真实目标是文字3的n14"),targets));
        rejected("labels are not trimmed",()->authorize(raw("click"," 1","n12"),targets));
        rejected("wrong binding package is denied",()->authorize(selected,ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,OBS,"com.example.other",targets.labels)));
        rejected("wrong binding observation is denied",()->authorize(selected,ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,"f"+OBS.substring(1),PKG,targets.labels)));
        rejected("missing binding is denied",()->authorize(selected,null));
        for(String schema:new String[]{"hepta.observed-action-gbnf.v1","hepta.observed-action-gbnf.v2-reason-first","hepta.observed-action-gbnf.v3","",null})
            rejected("unknown/old action schema is not inferred",()->ActionDecision.parse(selected,schema));
        rejected("unknown projection schema is denied",()->ObservedTargetLabels.create("hepta.observed-target-labels.v2",OBS,PKG,targets.labels));
        final String prefix="12345678901234567890123456789012345";
        String projected=ObservedTargetLabels.project(prefix+"😀tail");
        check((prefix+"…").equals(projected),"projection never splits a surrogate at the existing UTF-16 limit");
        check(ObservedTargetLabels.project(prefix+"😀different").equals(projected),"the same truncated visible prefix remains the same supplied string");
        check((prefix+"x").equals(ObservedTargetLabels.project(prefix+"x")),"exactly 36 UTF-16 units are not truncated");
        check((prefix+"x…").equals(ObservedTargetLabels.project(prefix+"xyz")),"truncated ordinary label has exactly the existing ellipsis");
        Map<String,String> longLabels=new LinkedHashMap<String,String>();longLabels.put("n30",projected);longLabels.put("n31",projected);
        ObservedTargetLabels truncated=ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,OBS,PKG,longLabels);
        authorize(raw("click",projected,"n30"),truncated);authorize(raw("click",projected,"n31"),truncated);
        rejected("unprojected original label is not silently truncated",()->authorize(raw("click",prefix+"😀tail","n30"),truncated));
        rejected("replacement ellipsis is not normalized",()->authorize(raw("click",prefix+"...","n30"),truncated));
        rejected("invalid raw Unicode cannot enter the projection",()->ObservedTargetLabels.project("x"+(char)0xD800));
        rejected("invalid decoded Unicode cannot enter a decision",()->ActionDecision.parse(raw("click","x","n12").replace("\"node_label\":\"x\"","\"node_label\":\"\\ud800\"")));
        rejected("unknown schema JSON field is not accepted",()->ActionDecision.parse(selected.replace("{","{\"schema\":\"v3\",")));
        System.out.println("PASS "+checks+" exact-label/parser/policy contracts; android_compiled=false; phone_tested=false; native_grammar_tested=false");
    }
}
