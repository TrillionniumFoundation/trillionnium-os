package org.trillionnium.hepta.local;

import java.util.Set;

/** Admission protects every currently observed action target before optional text.
 * This adds no permission: repeat, signature, freshness and actual-action gates
 * still run, and a raw isScrollable flag never grants a direction.
 */
public final class PromptActionDomain {
    private PromptActionDomain() {}
    public static boolean requiresRetention(String observedPackage,String nodePackage,
            boolean enabled,boolean password,boolean clickable,boolean editable,ObservedScrollActions scrollActions){
        if(observedPackage==null||nodePackage==null||scrollActions==null)throw new IllegalArgumentException("observed capability facts required");
        return observedPackage.equals(nodePackage)&&enabled&&!password&&(clickable||editable||scrollActions.hasAny());
    }
    public static void requireComplete(Set<String> required,Set<String> shown){
        if(required==null||shown==null||!shown.containsAll(required))
            throw new IllegalStateException("当前可操作节点未完整提供，未请求模型动作");
    }
}
