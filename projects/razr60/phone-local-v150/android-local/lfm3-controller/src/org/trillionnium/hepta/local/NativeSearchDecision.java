package org.trillionnium.hepta.local;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;

/** Separate flat model protocol. A parsed intent cannot enter the old ActionDecision dispatcher. */
final class NativeSearchDecision {
    static final String SCHEMA="hepta.native-search-intent.v1",ACTION="native.open_search";
    final String observationId,packageName,roleId,reason;
    private NativeSearchDecision(String observation,String pkg,String role,String reason){
        observationId=observation;packageName=pkg;roleId=role;this.reason=reason;
    }
    static NativeSearchDecision parse(String raw)throws ActionDecision.InvalidActionException{
        Map<String,Object> f=ActionDecision.strictFields(raw);
        need(f.keySet().equals(new TreeSet<String>(Arrays.asList("action","observation_id","package","role_id","reason"))),"exact search intent fields required");
        for(Object value:f.values())need(value instanceof String,"search intent values must be strings");
        need(ACTION.equals(f.get("action")),"only native.open_search belongs to this protocol");
        String observation=(String)f.get("observation_id"),pkg=(String)f.get("package"),role=(String)f.get("role_id"),reason=(String)f.get("reason");
        need(NativeAppEvidence.id(observation)&&NativeAppGoal.XIAOMI_PACKAGE.equals(pkg)&&NativeAppEvidence.sha(role),"search intent identity differs");
        need(!reason.isEmpty()&&reason.codePointCount(0,reason.length())<=96,"search reason bound");
        return new NativeSearchDecision(observation,pkg,role,reason);
    }
    Map<String,Object> evidence(){Map<String,Object> e=new LinkedHashMap<String,Object>();e.put("action",ACTION);e.put("observation_id",observationId);
        e.put("package",packageName);e.put("role_id",roleId);e.put("reason",reason);return Collections.unmodifiableMap(e);}
    private static void need(boolean value,String why)throws ActionDecision.InvalidActionException{if(!value)throw new ActionDecision.InvalidActionException(why);}
}
