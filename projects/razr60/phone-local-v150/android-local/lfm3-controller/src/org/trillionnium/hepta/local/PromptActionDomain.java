package org.trillionnium.hepta.local;

import java.util.Set;
import java.util.Map;

/** Admission protects every currently observed action target before optional text.
 * This adds no permission: repeat, signature, freshness and actual-action gates
 * still run, and a raw isScrollable flag never grants a direction.
 */
public final class PromptActionDomain {
    private PromptActionDomain() {}
    public static boolean eligible(String observedPackage,String nodePackage,boolean enabled,boolean password){
        if(observedPackage==null||nodePackage==null)throw new IllegalArgumentException("observed package facts required");
        return observedPackage.equals(nodePackage)&&enabled&&!password;
    }
    public static boolean requiresRetention(String observedPackage,String nodePackage,
            boolean enabled,boolean password,boolean clickable,boolean editable,ObservedScrollActions scrollActions){
        if(observedPackage==null||nodePackage==null||scrollActions==null)throw new IllegalArgumentException("observed capability facts required");
        return eligible(observedPackage,nodePackage,enabled,password)&&(clickable||editable||scrollActions.hasAny());
    }
    /** Describe the same post-policy sets supplied to DecisionGrammar, never raw widget flags. */
    public static String promptFlags(String nodeId,boolean focused,Set<String> clicks,Set<String> edits,
            Map<String,ObservedScrollActions> scrolls){
        if(nodeId==null||clicks==null||edits==null||scrolls==null)throw new IllegalArgumentException("actual action domain required");
        ObservedScrollActions directions=scrolls.get(nodeId);
        return (clicks.contains(nodeId)?"c":"")+(edits.contains(nodeId)?"t":"")
                +(directions!=null&&directions.hasAny()?"s":"")+(focused?"f":"");
    }
    public static void requireComplete(Set<String> required,Set<String> shown){
        if(required==null||shown==null||!shown.containsAll(required))
            throw new IllegalStateException("当前可操作节点未完整提供，未请求模型动作");
    }
}
