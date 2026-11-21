package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Emits actual production GBNF; independent recognition checks the resulting language. */
public final class OwnerGrammarHostTest {
    private static final String OWNER="先只读查找手机上安装的时钟应用，再打开它并停留在主页面；只查找、打开和结束，不点击、不输入，不新建、修改、启停或删除任何闹钟、计时器或秒表。若打开后不是主页面，停止并说明。";
    private static final String OBS="11111111111111111111111111111111";
    private static final String TASK="22222222222222222222222222222222";
    private static final String RUN="33333333333333333333333333333333";
    private static final String CURRENT="org.example.launcher", CLOCK="org.example.clock", OTHER="org.example.mail";
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    private static DecisionGrammar grammar(TaskAuthorization.Frame frame,String current,Map<String,String> catalogue){
        Set<String> packages=frame.openPackages(catalogue.keySet());packages.remove(current);
        Map<String,String> labels=new LinkedHashMap<String,String>();for(String pkg:packages)labels.put(pkg,catalogue.get(pkg));
        Map<String,String> nodes=new LinkedHashMap<String,String>();nodes.put("n1","1");nodes.put("n9","9");nodes.put("n3","同意并继续");
        return DecisionGrammar.createAuthorized(OBS,current,packages,new TreeSet<String>(nodes.keySet()),
                Collections.singleton("n1"),Collections.<String,ObservedScrollActions>emptyMap(),
                ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,OBS,current,nodes),
                ObservedAppLabels.create(ObservedAppLabels.SCHEMA,OBS,current,labels),frame);
    }
    private static void put(Path directory,String name,DecisionGrammar grammar)throws Exception{
        Files.write(directory.resolve(name+".gbnf"),grammar.text.getBytes(StandardCharsets.UTF_8));
    }
    public static void main(String[] args)throws Exception{
        check(args.length==1,"one output directory required");Path out=Paths.get(args[0]);Files.createDirectories(out);
        Map<String,String> apps=new LinkedHashMap<String,String>();apps.put(CLOCK,"时钟");apps.put(OTHER,"邮件");
        TaskAuthorization auth=TaskAuthorization.parse(OWNER);check(auth.allowedTools.equals(new TreeSet<String>(Arrays.asList("find_app","open","done"))),"actual owner whitelist");
        TaskAuthorization.Gate gate=auth.bind(TASK);AppCatalogueRanker catalogue=new AppCatalogueRanker(apps,OWNER);
        gate.bindCatalogue(catalogue.search("",0));put(out,"initial",grammar(gate.frame(),CURRENT,apps));
        ActionDecision find=ActionDecision.parse("{\"reason\":\"执行本次真实查找\",\"action\":\"find_app\",\"observation_id\":\""+OBS+"\",\"package\":\""+CURRENT+"\",\"query\":\"时钟\",\"offset\":0}",ObservedAppLabels.ACTION_SCHEMA);
        gate.found(find,RUN,catalogue.search("时钟",0));put(out,"found",grammar(gate.frame(),CURRENT,apps));
        ActionDecision open=ActionDecision.parse("{\"reason\":\"打开查找结果\",\"action\":\"open\",\"observation_id\":\""+OBS+"\",\"app_label\":\"时钟\",\"package\":\""+CLOCK+"\"}",ObservedAppLabels.ACTION_SCHEMA);
        gate.opened(open,RUN);put(out,"pending-open",grammar(gate.frame(),CURRENT,apps));
        gate.observed(CLOCK,OBS);put(out,"observed-open",grammar(gate.frame(),CLOCK,apps));
        TaskAuthorization keys=TaskAuthorization.parse("打开计算器，清除当前输入，使用计算器按键计算23乘以19，按等号并保留结果。不要直接输入答案。");
        check(keys.allows("click")&&!keys.allows("type"),"key method forbids SET_TEXT without forbidding keys");
        put(out,"keys",grammar(keys.bind(TASK).frame(),CURRENT,apps));
        System.out.println("PASS 5 actual Owner grammar states emitted");
    }
}
