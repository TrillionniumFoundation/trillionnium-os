import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.HashSet;
import org.trillionnium.hepta.local.ActionDecision;
import org.trillionnium.hepta.local.ActionPolicy;
import org.trillionnium.hepta.local.DecisionGrammar;
import org.trillionnium.hepta.local.ObservedAppLabels;
import org.trillionnium.hepta.local.ObservedScrollActions;
import org.trillionnium.hepta.local.ObservedTargetLabels;
import org.trillionnium.hepta.local.RecentActionProjection;

/** Synthetic labels only; exercises the actual parser, policy and emitted grammar. */
public final class ObservedAppLabelsHostTest {
    private static final String OBS="0123456789abcdef0123456789abcdef",CURRENT="org.example.launcher";
    private static int assertions;
    private interface Throwing {void run()throws Exception;}
    private static void check(boolean ok,String message){assertions++;if(!ok)throw new AssertionError(message);}
    private static void denied(Throwing call,String message)throws Exception{
        try{call.run();throw new AssertionError("accepted: "+message);}
        catch(ActionDecision.InvalidActionException|IllegalArgumentException expected){assertions++;}
    }
    private static String q(String value){
        StringBuilder b=new StringBuilder("\"");
        for(int i=0;i<value.length();i++){
            char c=value.charAt(i);
            if(c=='"'||c=='\\')b.append('\\').append(c);
            else if(c<32||c=='\u2028'||c=='\u2029')b.append(String.format(java.util.Locale.ROOT,"\\u%04x",(int)c));
            else b.append(c);
        }
        return b.append('"').toString();
    }
    private static String raw(String label,String pkg){return "{\"reason\":\"原任务说明不替代目标配对\",\"action\":\"open\",\"observation_id\":"+q(OBS)+",\"app_label\":"+q(label)+",\"package\":"+q(pkg)+"}";}
    private static ActionDecision parse(String text)throws Exception{return ActionDecision.parse(text,ObservedAppLabels.ACTION_SCHEMA);}
    private static Map<String,String> labels(){
        Map<String,String> out=new LinkedHashMap<String,String>();
        out.put("org.example.settings","设置");out.put("org.example.contacts","通讯录");
        out.put("org.example.same_a","同名");out.put("org.example.same_b","同名");
        out.put("org.example.empty_a","");out.put("org.example.empty_b","");
        out.put("org.example.escaped","引号\"\\\n中文😀");
        out.put("org.example.project_a",ObservedAppLabels.project("12345678901234567890123456789012345678901234567😀tailA"));
        out.put("org.example.project_b",ObservedAppLabels.project("12345678901234567890123456789012345678901234567😀tailB"));
        return out;
    }
    public static void main(String[] args)throws Exception{
        final Map<String,String> source=labels();
        final ObservedAppLabels apps=ObservedAppLabels.create(ObservedAppLabels.SCHEMA,OBS,CURRENT,source);
        final ObservedTargetLabels nodes=ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,OBS,CURRENT,Collections.<String,String>emptyMap());
        source.put("org.example.settings","changed after create");
        check(apps.labels.get("org.example.settings").equals("设置"),"immutable projection copies caller input");
        for(final Map.Entry<String,String> pair:apps.labels.entrySet()){
            ActionDecision a=parse(raw(pair.getValue(),pair.getKey()));
            ActionPolicy.validateTextDecision(a,CURRENT,apps.labels.keySet(),nodes,apps);
            check(pair.getValue().equals(a.appLabel)&&ObservedAppLabels.ACTION_SCHEMA.equals(a.actionSchema),"actual parsed pair retained");
            for(final String other:new HashSet<String>(apps.labels.values()))if(!other.equals(pair.getValue()))
                denied(()->ActionPolicy.validateTextDecision(parse(raw(other,pair.getKey())),CURRENT,apps.labels.keySet(),nodes,apps),"crossed app pair");
        }
        final String valid=raw("设置","org.example.settings");
        denied(()->parse(valid.replace("\"app_label\":\"设置\",","")),"missing label has no fallback");
        denied(()->parse(valid.replace("\"app_label\":\"设置\",\"package\":\"org.example.settings\"","\"package\":\"org.example.settings\",\"app_label\":\"设置\"")),"label must precede package");
        for(final String replacement:Arrays.asList("null","true","3","\"\\ud800\"","\"\\u0000\""))
            denied(()->parse(valid.replace("\"app_label\":\"设置\"","\"app_label\":"+replacement)),"non-string/invalid label");
        denied(()->parse(valid.replace("\"app_label\":\"设置\"","\"app_label\":\"设置\",\"app_label\":\"设置\"")),"duplicate key");
        denied(()->ActionDecision.parse(valid,ObservedTargetLabels.ACTION_SCHEMA),"v4 field cannot enter v3");
        denied(()->ActionPolicy.validateTextDecision(parse(valid),CURRENT,apps.labels.keySet(),nodes),"v4 cannot use legacy policy");
        final ActionDecision legacy=ActionDecision.parse("{\"action\":\"open\",\"observation_id\":"+q(OBS)+",\"package\":\"org.example.settings\"}",ObservedTargetLabels.ACTION_SCHEMA);
        ActionPolicy.validateTextDecision(legacy,CURRENT,apps.labels.keySet(),nodes);
        denied(()->ActionPolicy.validateTextDecision(legacy,CURRENT,apps.labels.keySet(),nodes,apps),"v3 cannot enter v4 controller policy");
        denied(()->ActionPolicy.validateTextDecision(parse(valid.replace(OBS,"f"+OBS.substring(1))),CURRENT,apps.labels.keySet(),nodes,apps),"wrong observation");
        denied(()->ActionPolicy.validateTextDecision(parse(valid),"org.example.other",apps.labels.keySet(),nodes,apps),"wrong current package");
        denied(()->ActionPolicy.validateTextDecision(parse(raw("设置","org.example.unseen")),CURRENT,apps.labels.keySet(),nodes,apps),"unknown target");
        final Map<String,String> noSettings=new LinkedHashMap<String,String>(apps.labels);noSettings.remove("org.example.settings");
        final ObservedAppLabels restricted=ObservedAppLabels.create(ObservedAppLabels.SCHEMA,OBS,CURRENT,noSettings);
        denied(()->ActionPolicy.validateTextDecision(parse(valid),CURRENT,restricted.labels.keySet(),nodes,restricted),"omitted/blocked app not authorized");
        denied(()->ActionPolicy.validateTextDecision(parse(valid),CURRENT,apps.labels.keySet(),nodes,restricted),"frame allow-list cannot diverge");
        final Map<String,String> current=new LinkedHashMap<String,String>();current.put(CURRENT,"桌面");
        denied(()->ObservedAppLabels.create(ObservedAppLabels.SCHEMA,OBS,CURRENT,current),"current app cannot reopen");
        current.clear();current.put("android","system");
        denied(()->ObservedAppLabels.create(ObservedAppLabels.SCHEMA,OBS,CURRENT,current),"system cannot open");
        check(apps.labels.get("org.example.project_a").equals(apps.labels.get("org.example.project_b")),"projection collisions retain both packages");
        check(apps.labels.get("org.example.project_a").equals("12345678901234567890123456789012345678901234567…"),"48-unit boundary preserves surrogate pair");
        final Map<String,String> invalid=new LinkedHashMap<String,String>();invalid.put("org.example.long",String.join("",Collections.nCopies(50,"x")));
        denied(()->ObservedAppLabels.create(ObservedAppLabels.SCHEMA,OBS,CURRENT,invalid),"projection bound");
        final DecisionGrammar grammar=DecisionGrammar.createAppLabeled(OBS,CURRENT,apps.labels.keySet(),Collections.<String>emptySet(),Collections.<String>emptySet(),Collections.<String,ObservedScrollActions>emptyMap(),nodes,apps);
        check(grammar.schema.equals(ObservedAppLabels.ACTION_SCHEMA)&&grammar.appLabels==apps,"new grammar explicit identity");
        check(grammar.text.contains("open-target ::=")&&!grammar.text.contains("open-package ::="),"whole pairs, no independent package branch");
        denied(()->DecisionGrammar.createAppLabeled(OBS,CURRENT,apps.labels.keySet(),Collections.<String>emptySet(),Collections.<String>emptySet(),Collections.<String,ObservedScrollActions>emptyMap(),nodes,null),"missing metadata cannot downgrade grammar");
        Map<String,Object> history=new LinkedHashMap<String,Object>();history.put("step",1);history.put("action","open");history.put("app_label","设置");history.put("target_package","org.example.settings");history.put("dispatched",true);
        check("设置".equals(RecentActionProjection.project(history).get("app_label")),"compact history preserves app label");
        check("设置".equals(RecentActionProjection.dispatched(history).get("app_label")),"dispatched history preserves app label");
        check("设置".equals(RecentActionProjection.readableEvents(Collections.singletonList(history)).rows.get(0).get("app_label")),"full history preserves app label");
        if(args.length==1){Path out=Paths.get(args[0]);Files.createDirectories(out);Files.write(out.resolve("app-labels.gbnf"),grammar.text.getBytes(StandardCharsets.UTF_8));}
        System.out.println("PASS assertions="+assertions+" app_pair_count="+apps.labels.size()+" app_contract_sha256="+apps.sha256+" legacy_v3_preserved=true phone_tested=false");
    }
}
