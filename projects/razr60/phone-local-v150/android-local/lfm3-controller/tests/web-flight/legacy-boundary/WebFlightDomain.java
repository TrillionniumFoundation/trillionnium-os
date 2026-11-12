package org.trillionnium.hepta.local;

import java.util.Map;
import java.util.Set;

/** Type-only boundary for legacy non-Web gates.
 * The separate Web gate compiles the actual WebFlightDomain and receipt/geometry classes.
 * No instance or method here may be used to mint a Web capability.
 */
final class WebFlightDomain {
    final String taskId,ownerSha,authorizationSha,observationId,generation;
    final int displayId,windowId;
    private WebFlightDomain(){throw unavailable();}
    private static AssertionError unavailable(){
        return new AssertionError("legacy non-Web fixture cannot execute WebFlightDomain");
    }
    Map<String,Object> evidence(){throw unavailable();}
    Set<String> clicks(Set<String> original){throw unavailable();}
    Set<String> edits(Set<String> original){throw unavailable();}
    <T> Map<String,T> noNodeActions(Map<String,T> original){throw unavailable();}
    Set<String> openPackages(Set<String> original){throw unavailable();}
    Set<String> toolMask(Set<String> original){throw unavailable();}
}
