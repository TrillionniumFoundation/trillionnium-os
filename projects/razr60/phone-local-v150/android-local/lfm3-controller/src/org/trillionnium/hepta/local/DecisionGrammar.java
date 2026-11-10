package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

/** Fixed action schema bound to one real observation, never arbitrary caller GBNF. */
public final class DecisionGrammar {
    public static final String SCHEMA=ObservedTargetLabels.ACTION_SCHEMA;
    public final String observationId, currentPackage, text, sha256;
    public final List<String> actions;
    public final ObservedTargetLabels targets;
    public final String schema;
    public final ObservedAppLabels appLabels;
    public final TaskAuthorization.Frame authorization;
    public final Map<String,List<String>> scrollDirections;
    public final Set<String> submitNodes;
    public final Map<String,org.trillionnium.hepta.background.FixedIntentTarget> fixedIntentTargets;

    private DecisionGrammar(ObservedTargetLabels targets,String text,List<String> actions,Map<String,List<String>> scrollDirections,ObservedAppLabels appLabels,TaskAuthorization.Frame authorization,Set<String> submits,boolean imeProtocol,Map<String,org.trillionnium.hepta.background.FixedIntentTarget> fixedTargets){
        this.submitNodes=Collections.unmodifiableSet(new TreeSet<String>(submits));
        this.fixedIntentTargets=Collections.unmodifiableMap(new TreeMap<String,org.trillionnium.hepta.background.FixedIntentTarget>(fixedTargets==null?Collections.<String,org.trillionnium.hepta.background.FixedIntentTarget>emptyMap():fixedTargets));
        this.authorization=authorization;this.appLabels=appLabels;this.schema=fixedTargets!=null?ActionDecision.FIXED_INTENT_ACTION_SCHEMA:imeProtocol?ActionDecision.IME_ACTION_SCHEMA:appLabels==null?SCHEMA:ObservedAppLabels.ACTION_SCHEMA;
        this.scrollDirections=Collections.unmodifiableMap(new TreeMap<String,List<String>>(scrollDirections));
        this.targets=targets;this.observationId=targets.observationId;this.currentPackage=targets.packageName;this.text=text;
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
            Set<String> clickableNodes,Set<String> editableNodes,Map<String,ObservedScrollActions> scrollActions,ObservedTargetLabels targets){
        return createInternal(observationId,currentPackage,shownApps,clickableNodes,editableNodes,scrollActions,targets,null,null,false,Collections.<String>emptySet(),false,null);
    }

    /** Explicit v4 entry; missing app metadata never selects the legacy grammar. */
    public static DecisionGrammar createAppLabeled(String observationId,String currentPackage,Set<String> shownApps,
            Set<String> clickableNodes,Set<String> editableNodes,Map<String,ObservedScrollActions> scrollActions,
            ObservedTargetLabels targets,ObservedAppLabels appLabels){
        if(appLabels==null)throw new IllegalArgumentException("observed app pairs are required");
        return createInternal(observationId,currentPackage,shownApps,clickableNodes,editableNodes,scrollActions,targets,appLabels,null,false,Collections.<String>emptySet(),false,null);
    }

    public static DecisionGrammar createAuthorized(String observationId,String currentPackage,Set<String> shownApps,
            Set<String> clickableNodes,Set<String> editableNodes,Map<String,ObservedScrollActions> scrollActions,
            ObservedTargetLabels targets,ObservedAppLabels appLabels,TaskAuthorization.Frame authorization){
        TaskAuthorization.require(authorization!=null,"动作语法缺少用户授权");
        if(appLabels==null)throw new IllegalArgumentException("observed app pairs are required");
        return createInternal(observationId,currentPackage,shownApps,clickableNodes,editableNodes,scrollActions,targets,appLabels,authorization,false,Collections.<String>emptySet(),false,null);
    }

    /** A background display has no global HOME tool. Owner authorization is retained unchanged. */
    public static DecisionGrammar createBackgroundAuthorized(String observationId,String currentPackage,Set<String> shownApps,
            Set<String> clickableNodes,Set<String> editableNodes,Map<String,ObservedScrollActions> scrollActions,
            ObservedTargetLabels targets,ObservedAppLabels appLabels,TaskAuthorization.Frame authorization){
        TaskAuthorization.require(authorization!=null,"后台动作语法缺少用户授权");
        if(appLabels==null)throw new IllegalArgumentException("observed app pairs are required");
        return createInternal(observationId,currentPackage,shownApps,clickableNodes,editableNodes,scrollActions,targets,appLabels,authorization,true,Collections.<String>emptySet(),false,null);
    }

    /** Explicit v5 entry. Legacy grammar entry points cannot acquire submit. */
    public static DecisionGrammar createImeAuthorized(String observationId,String currentPackage,Set<String> shownApps,
            Set<String> clickableNodes,Set<String> editableNodes,Map<String,ObservedScrollActions> scrollActions,
            Map<String,ObservedImeEnter> submitActions,ObservedTargetLabels targets,ObservedAppLabels appLabels,
            TaskAuthorization.Frame authorization,boolean background){
        TaskAuthorization.require(authorization!=null,"IME 动作语法缺少用户授权");
        if(appLabels==null||targets==null||submitActions==null||submitActions.size()>200)
            throw new IllegalArgumentException("observed query action projection required");
        Set<String> submits=checkedNodes(submitActions.keySet());
        for(String id:submits)if(!targets.labels.containsKey(id)||submitActions.get(id)==null||!submitActions.get(id).queryAllowed())
            throw new IllegalArgumentException("submit is not a supplied query-labelled action");
        return createInternal(observationId,currentPackage,shownApps,clickableNodes,editableNodes,scrollActions,
                targets,appLabels,authorization,background,submits,true,null);
    }

    /** Explicit v6: supplied installed targets are separate from launcher-open pairs. */
    public static DecisionGrammar createFixedIntentAuthorized(String observationId,String currentPackage,Set<String> shownApps,
            Set<String> clickableNodes,Set<String> editableNodes,Map<String,ObservedScrollActions> scrollActions,
            Map<String,ObservedImeEnter> submitActions,ObservedTargetLabels targets,ObservedAppLabels appLabels,
            TaskAuthorization.Frame authorization,boolean background,Map<String,org.trillionnium.hepta.background.FixedIntentTarget> fixedTargets){
        // Reuse the exact v5 validation for the existing node/action domain.
        DecisionGrammar checked=createImeAuthorized(observationId,currentPackage,shownApps,clickableNodes,editableNodes,scrollActions,
                submitActions,targets,appLabels,authorization,background);
        if(fixedTargets==null||fixedTargets.size()>2)throw new IllegalArgumentException("installed fixed targets required");
        Map<String,org.trillionnium.hepta.background.FixedIntentTarget> permitted=new TreeMap<String,org.trillionnium.hepta.background.FixedIntentTarget>();
        for(Map.Entry<String,org.trillionnium.hepta.background.FixedIntentTarget> entry:fixedTargets.entrySet()){
            org.trillionnium.hepta.background.FixedIntentTarget target=entry.getValue();
            if(target==null||!entry.getKey().equals(target.action)||!org.trillionnium.hepta.background.FixedIntentTools.isTool(target.action))
                throw new IllegalArgumentException("invalid installed fixed target");
            ObservedAppLabels.requireProjectedLabel(ObservedAppLabels.project(target.appLabel));
            TaskAuthorization.require(authorization.allows(target.action),"fixed intent exceeds owner tool authorization");
            permitted.put(target.action,target);
        }
        return createInternal(observationId,currentPackage,shownApps,clickableNodes,editableNodes,scrollActions,
                targets,appLabels,authorization,background,checked.submitNodes,true,permitted);
    }

    private static DecisionGrammar createInternal(String observationId,String currentPackage,Set<String> shownApps,
            Set<String> clickableNodes,Set<String> editableNodes,Map<String,ObservedScrollActions> scrollActions,
            ObservedTargetLabels targets,ObservedAppLabels appLabels,TaskAuthorization.Frame authorization,boolean background,Set<String> submitNodes,boolean imeProtocol,Map<String,org.trillionnium.hepta.background.FixedIntentTarget> fixedTargets){
        if(observationId==null||!observationId.matches("[0-9a-f]{32}"))throw new IllegalArgumentException("invalid observed id");
        checkPackage(currentPackage);
        if(targets==null||!observationId.equals(targets.observationId)||!currentPackage.equals(targets.packageName))
            throw new IllegalArgumentException("observed label projection belongs to a different window");
        if(shownApps==null||shownApps.size()>40)throw new IllegalArgumentException("invalid application projection");
        TreeSet<String> apps=new TreeSet<String>();
        for(String name:shownApps){checkPackage(name);if(!currentPackage.equals(name)&&!"android".equals(name))apps.add(name);}
        if(appLabels!=null&&(!observationId.equals(appLabels.observationId)||!currentPackage.equals(appLabels.currentPackage)
                ||!apps.equals(appLabels.labels.keySet())))throw new IllegalArgumentException("app pairs differ from the current allowed projection");
        TreeSet<String> clicks=checkedNodes(clickableNodes),edits=checkedNodes(editableNodes),submits=checkedNodes(submitNodes);
        Map<String,List<String>> scrolls=checkedScrollActions(scrollActions,targets);
        if(authorization!=null){
            TaskAuthorization.require(apps.equals(authorization.openPackages(apps)),"打开目标投影超出用户授权");
            if(!authorization.allows("click"))clicks.clear();
            if(!authorization.allows("type"))edits.clear();
            if(!authorization.allows("submit"))submits.clear();
            if(!authorization.allows("scroll"))scrolls.clear();
        }
        StringBuilder rules=new StringBuilder();List<String> branches=new ArrayList<String>();
        if(authorization==null||authorization.allows("find_app")){
            branches.add("find_app");
            String queryRule=authorization!=null&&authorization.authorization.requireFindAppBeforeOpen?jsonValue(authorization.authorization.findQuery):"query-string";
            rule(rules,"find-app",prefix("find_app",observationId)+field("package",jsonValue(currentPackage))+comma()+field("query",queryRule)+comma()+field("offset","app-offset")+ending());
        }
        if(!apps.isEmpty()){
            branches.add("open");
            if(appLabels==null){
                rule(rules,"open",prefix("open",observationId)+field("package","open-package")+ending());
                rule(rules,"open-package",alternatives(apps));
            }else{
                rule(rules,"open",prefix("open",observationId)+"open-target"+ending());
                rule(rules,"open-target",appPairs(appLabels));
            }
        }
        if(fixedTargets!=null)for(org.trillionnium.hepta.background.FixedIntentTarget target:fixedTargets.values()){
            branches.add(target.action);
            rule(rules,target.action.replace('.','-'),prefix(target.action,observationId)
                    +field("app_label",jsonValue(ObservedAppLabels.project(target.appLabel)))+comma()
                    +field("package",jsonValue(target.packageName))+comma()
                    +field("notes.create".equals(target.action)?"text":"query","fixed-payload-string")+ending());
        }
        if(!clicks.isEmpty()){
            branches.add("click");rule(rules,"click",prefix("click",observationId)+field("package",jsonValue(currentPackage))+comma()+"click-target"+ending());
            rule(rules,"click-target",targetPairs(clicks,targets));
        }
        if(!edits.isEmpty()){
            branches.add("type");rule(rules,"type",prefix("type",observationId)+field("package",jsonValue(currentPackage))+comma()+"type-target"+comma()+field("text","text-string")+ending());
            rule(rules,"type-target",targetPairs(edits,targets));
        }
        if(!submits.isEmpty()){
            if(!imeProtocol)throw new IllegalArgumentException("legacy protocol cannot submit");
            branches.add("submit");rule(rules,"submit",prefix("submit",observationId)+field("package",jsonValue(currentPackage))+comma()+"submit-target"+ending());
            rule(rules,"submit-target",targetPairs(submits,targets));
        }
        if(!scrolls.isEmpty()){
            branches.add("scroll");rule(rules,"scroll",prefix("scroll",observationId)+field("package",jsonValue(currentPackage))+comma()+"scroll-target"+ending());
            rule(rules,"scroll-target",scrollPairs(scrolls,targets));
        }
        for(String name:new String[]{"back","home"}){
            if(background&&"home".equals(name))continue;
            if(authorization!=null&&!authorization.allows(name))continue;
            branches.add(name);rule(rules,name,prefix(name,observationId)+field("package",jsonValue(currentPackage))+ending());
        }
        if(authorization==null||authorization.allows("wait")){branches.add("wait");rule(rules,"wait",prefix("wait",observationId)+field("package",jsonValue(currentPackage))+comma()+field("duration_ms","duration")+ending());}
        branches.add("done");rule(rules,"done",prefix("done",observationId)+field("package",jsonValue(currentPackage))+comma()+field("status","status")+comma()+field("summary","summary-string")+ending());
        // A brief state assessment precedes action selection in the generated JSON.
        rule(rules,"status",alternatives(new TreeSet<String>(java.util.Arrays.asList(authorization==null||authorization.successAllowed()?new String[]{"success","partial","failure"}:new String[]{"partial","failure"}))));
        rule(rules,"duration","[1-9] [0-9]{2} | "+literal("1")+" [0-9]{3} | "+literal("2000"));
        rule(rules,"app-offset",literal("0")+" | [1-9] [0-9]{0,2} | [1-3] [0-9]{3} | "+literal("40")+" [0-8] [0-9] | "+literal("409")+" [0-5]");
        rule(rules,"query-string",literal("\"")+" json-char{0,64} "+literal("\""));
        rule(rules,"reason-string",literal("\"")+" json-char{1,96} "+literal("\""));
        // At most 1024 Unicode scalar values imply at most 4096 decoded UTF-8 bytes.
        rule(rules,"text-string",literal("\"")+" json-char{0,1024} "+literal("\""));
        if(fixedTargets!=null)rule(rules,"fixed-payload-string",literal("\"")+" json-char{1,1024} "+literal("\""));
        rule(rules,"summary-string",literal("\"")+" json-char{1,1024} "+literal("\""));
        rules.append("json-char ::= [^\"\\\\\\x00-\\x1F] | "+literal("\\")+" [\"\\\\/bfnrt]\n");
        rule(rules,"ws","[ \\t\\n\\r]{0,8}");
        List<String> ruleNames=new ArrayList<String>();for(String branch:branches)ruleNames.add(branch.replace('_','-').replace('.','-'));
        return new DecisionGrammar(targets,"root ::= ws ("+join(ruleNames," | ")+") ws\n"+rules.toString(),branches,scrolls,appLabels,authorization,submits,imeProtocol,fixedTargets);
    }

    public boolean allowsSubmit(String nodeId){return submitNodes.contains(nodeId);}

    /** A direction cannot migrate to another node that has a different action list. */
    public boolean allowsScroll(String nodeId,String direction){
        List<String> allowed=scrollDirections.get(nodeId);return allowed!=null&&allowed.contains(direction);
    }
    private static Map<String,List<String>> checkedScrollActions(Map<String,ObservedScrollActions> values,ObservedTargetLabels targets){
        if(values==null||values.size()>200)throw new IllegalArgumentException("invalid scroll action projection");
        checkedNodes(values.keySet());Map<String,List<String>> result=new TreeMap<String,List<String>>();
        for(Map.Entry<String,ObservedScrollActions> pair:values.entrySet()){
            if(!targets.labels.containsKey(pair.getKey())||pair.getValue()==null)
                throw new IllegalArgumentException("scroll capability is not bound to a supplied node");
            if(pair.getValue().hasAny())result.put(pair.getKey(),pair.getValue().directions);
        }
        return result;
    }
    private static String scrollPairs(Map<String,List<String>> values,ObservedTargetLabels targets){
        List<String> pairs=new ArrayList<String>();
        for(Map.Entry<String,List<String>> pair:values.entrySet()){
            String id=pair.getKey();
            pairs.add("("+field("node_label",jsonValue(targets.labels.get(id)))+comma()+field("node_id",jsonValue(id))
                    +comma()+field("direction","("+alternatives(pair.getValue())+")")+")");
        }
        return join(pairs," | ");
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
    private static String targetPairs(Iterable<String> ids,ObservedTargetLabels targets){
        List<String> pairs=new ArrayList<String>();
        for(String id:ids){
            if(!targets.labels.containsKey(id))throw new IllegalArgumentException("action node was absent from the supplied label projection");
            pairs.add("("+field("node_label",jsonValue(targets.labels.get(id)))+comma()+field("node_id",jsonValue(id))+")");
        }
        return join(pairs," | ");
    }
    private static String appPairs(ObservedAppLabels apps){
        List<String> pairs=new ArrayList<String>();
        for(Map.Entry<String,String> pair:apps.labels.entrySet())
            pairs.add("("+field("app_label",jsonValue(pair.getValue()))+comma()+field("package",jsonValue(pair.getKey()))+")");
        return join(pairs," | ");
    }
    private static String join(Iterable<String> values,String separator){StringBuilder out=new StringBuilder();for(String value:values){if(out.length()>0)out.append(separator);out.append(value);}return out.toString();}
    private static String jsonValue(String value){
        StringBuilder out=new StringBuilder("\"");
        for(int i=0;i<value.length();i++){
            char c=value.charAt(i);
            switch(c){
                case '\"':out.append("\\\"");break;case '\\':out.append("\\\\");break;
                case '\b':out.append("\\b");break;case '\f':out.append("\\f");break;
                case '\n':out.append("\\n");break;case '\r':out.append("\\r");break;case '\t':out.append("\\t");break;
                default:if(c<32||c=='\u2028'||c=='\u2029')out.append(String.format(Locale.ROOT,"\\u%04x",(int)c));else out.append(c);
            }
        }
        return literal(out.append('\"').toString());
    }
    private static String literal(String text){return "\""+text.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r").replace("\t","\\t")+"\"";}
}
