package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

/** Fixed action schema bound to one real observation, never arbitrary caller GBNF. */
public final class DecisionGrammar {
    public static final String SCHEMA="hepta.observed-action-gbnf.v2-reason-first";
    public final String observationId, currentPackage, text, sha256;
    public final List<String> actions;

    private DecisionGrammar(String observationId,String currentPackage,String text,List<String> actions){
        this.observationId=observationId;this.currentPackage=currentPackage;this.text=text;
        this.actions=Collections.unmodifiableList(new ArrayList<String>(actions));
        byte[] bytes=text.getBytes(StandardCharsets.UTF_8);
        if(bytes.length>65536)throw new IllegalArgumentException("observed action grammar exceeds bound");
        try{
            StringBuilder hash=new StringBuilder(64);
            for(byte value:MessageDigest.getInstance("SHA-256").digest(bytes))hash.append(String.format(Locale.ROOT,"%02x",value&255));
            this.sha256=hash.toString();
        }catch(java.security.NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
    }

    public static DecisionGrammar create(String observationId,String currentPackage,Set<String> shownApps,
            Set<String> clickableNodes,Set<String> editableNodes,Set<String> scrollableNodes){
        if(observationId==null||!observationId.matches("[0-9a-f]{32}"))throw new IllegalArgumentException("invalid observed id");
        checkPackage(currentPackage);
        if(shownApps==null||shownApps.size()>40)throw new IllegalArgumentException("invalid application projection");
        TreeSet<String> apps=new TreeSet<String>();
        for(String name:shownApps){checkPackage(name);if(!currentPackage.equals(name)&&!"android".equals(name))apps.add(name);}
        TreeSet<String> clicks=checkedNodes(clickableNodes),edits=checkedNodes(editableNodes),scrolls=checkedNodes(scrollableNodes);
        StringBuilder rules=new StringBuilder();List<String> branches=new ArrayList<String>();
        branches.add("find_app");
        rule(rules,"find-app",prefix("find_app",observationId)+field("package",jsonValue(currentPackage))+comma()+field("query","query-string")+comma()+field("offset","app-offset")+ending());
        if(!apps.isEmpty()){
            branches.add("open");rule(rules,"open",prefix("open",observationId)+field("package","open-package")+ending());
            rule(rules,"open-package",alternatives(apps));
        }
        if(!clicks.isEmpty()){
            branches.add("click");rule(rules,"click",prefix("click",observationId)+field("package",jsonValue(currentPackage))+comma()+field("node_id","click-node")+ending());
            rule(rules,"click-node",alternatives(clicks));
        }
        if(!edits.isEmpty()){
            branches.add("type");rule(rules,"type",prefix("type",observationId)+field("package",jsonValue(currentPackage))+comma()+field("node_id","type-node")+comma()+field("text","text-string")+ending());
            rule(rules,"type-node",alternatives(edits));
        }
        if(!scrolls.isEmpty()){
            branches.add("scroll");rule(rules,"scroll",prefix("scroll",observationId)+field("package",jsonValue(currentPackage))+comma()+field("node_id","scroll-node")+comma()+field("direction","direction")+ending());
            rule(rules,"scroll-node",alternatives(scrolls));
        }
        for(String name:new String[]{"back","home"}){
            branches.add(name);rule(rules,name,prefix(name,observationId)+field("package",jsonValue(currentPackage))+ending());
        }
        branches.add("wait");rule(rules,"wait",prefix("wait",observationId)+field("package",jsonValue(currentPackage))+comma()+field("duration_ms","duration")+ending());
        branches.add("done");rule(rules,"done",prefix("done",observationId)+field("package",jsonValue(currentPackage))+comma()+field("status","status")+comma()+field("summary","summary-string")+ending());
        // A brief state assessment precedes action selection in the generated JSON.
        rule(rules,"direction",alternatives(new TreeSet<String>(java.util.Arrays.asList("forward","backward","up","down","left","right"))));
        rule(rules,"status",alternatives(new TreeSet<String>(java.util.Arrays.asList("success","partial","failure"))));
        rule(rules,"duration","[1-9] [0-9]{2} | "+literal("1")+" [0-9]{3} | "+literal("2000"));
        rule(rules,"app-offset",literal("0")+" | [1-9] [0-9]{0,2} | [1-3] [0-9]{3} | "+literal("40")+" [0-8] [0-9] | "+literal("409")+" [0-5]");
        rule(rules,"query-string",literal("\"")+" json-char{0,64} "+literal("\""));
        rule(rules,"reason-string",literal("\"")+" json-char{1,96} "+literal("\""));
        // At most 1024 Unicode scalar values imply at most 4096 decoded UTF-8 bytes.
        rule(rules,"text-string",literal("\"")+" json-char{0,1024} "+literal("\""));
        rule(rules,"summary-string",literal("\"")+" json-char{1,1024} "+literal("\""));
        rules.append("json-char ::= [^\"\\\\\\x00-\\x1F] | "+literal("\\")+" [\"\\\\/bfnrt]\n");
        rule(rules,"ws","[ \\t\\n\\r]{0,8}");
        List<String> ruleNames=new ArrayList<String>();for(String branch:branches)ruleNames.add(branch.replace('_','-'));
        return new DecisionGrammar(observationId,currentPackage,"root ::= ws ("+join(ruleNames," | ")+") ws\n"+rules.toString(),branches);
    }

    private static void checkPackage(String value){
        if(value==null||value.length()>255||(!"android".equals(value)&&!value.matches("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+")))
            throw new IllegalArgumentException("invalid observed package");
    }
    private static TreeSet<String> checkedNodes(Set<String> values){
        if(values==null||values.size()>200)throw new IllegalArgumentException("invalid node projection");
        TreeSet<String> result=new TreeSet<String>();
        for(String value:values){if(value==null||!value.matches("n[0-9]{1,5}"))throw new IllegalArgumentException("invalid observed node id");result.add(value);}
        return result;
    }
    private static String prefix(String action,String observation){return literal("{")+" ws "+field("reason","reason-string")+comma()+field("action",jsonValue(action))+comma()+field("observation_id",jsonValue(observation))+comma();}
    private static String field(String key,String valueRule){return jsonValue(key)+" ws "+literal(":")+" ws "+valueRule;}
    private static String comma(){return " ws "+literal(",")+" ws ";}
    private static String ending(){return " ws "+literal("}");}
    private static void rule(StringBuilder target,String name,String body){target.append(name).append(" ::= ").append(body).append('\n');}
    private static String alternatives(Iterable<String> values){List<String> parts=new ArrayList<String>();for(String value:values)parts.add(jsonValue(value));return join(parts," | ");}
    private static String join(Iterable<String> values,String separator){StringBuilder out=new StringBuilder();for(String value:values){if(out.length()>0)out.append(separator);out.append(value);}return out.toString();}
    private static String jsonValue(String ascii){return literal("\""+ascii+"\"");}
    private static String literal(String text){return "\""+text.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r").replace("\t","\\t")+"\"";}
}
