package org.trillionnium.hepta.local;

import java.util.Map;
import java.util.Set;

/** Type-only boundary for legacy non-Web gates.
 * The separate Web gate compiles the actual WebTaskDomain and receipt/geometry classes.
 * No instance or method here may be used to mint a Web capability.
 */
final class WebTaskDomain {
    final String taskId,ownerSha,authorizationSha,observationId,generation;
    final int displayId,windowId;
    final Set<String> clickIds;
    final Map<String,String> editValues;
    private WebTaskDomain(){throw unavailable();}
    private static AssertionError unavailable(){
        return new AssertionError("legacy non-Web fixture cannot execute WebTaskDomain");
    }
    boolean queryDispatched(){throw unavailable();}
    boolean resultReady(){throw unavailable();}
    Map<String,Object> resultRecord(){throw unavailable();}
    Map<String,Object> evidence(){throw unavailable();}
    Map<String,Object> promptEvidence(){throw unavailable();}
    Set<String> clicks(Set<String> original){throw unavailable();}
    Set<String> edits(Set<String> original){throw unavailable();}
    <T> Map<String,T> noNodeActions(Map<String,T> original){throw unavailable();}
    Set<String> openPackages(Set<String> original){throw unavailable();}
    Set<String> toolMask(Set<String> original){throw unavailable();}
}
