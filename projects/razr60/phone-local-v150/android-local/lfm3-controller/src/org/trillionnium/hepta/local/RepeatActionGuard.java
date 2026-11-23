package org.trillionnium.hepta.local;

import java.util.HashSet;
import java.util.Set;

/** Existing same-effect dispatch guard, including known input-method changes. */
public final class RepeatActionGuard {
    private String previousActionKey;
    private ObservationState previousNoChangeState;
    private ActionDecision previousEffect;

    public boolean rejects(ActionDecision action,String currentTree) {
        return rejects(action,new ObservationState(currentTree,ImeVisibility.UNKNOWN));
    }
    public boolean rejects(ActionDecision action,ObservationState current) {
        return key(action).equals(previousActionKey)&&previousNoChangeState!=null
                &&!Boolean.TRUE.equals(current.changedFrom(previousNoChangeState));
    }

    /** Call only after the accepted action and its fresh after-observation. */
    public void observed(ActionDecision action,String beforeTree,String afterTree) {
        observed(action,new ObservationState(beforeTree,ImeVisibility.UNKNOWN),
                new ObservationState(afterTree,ImeVisibility.UNKNOWN));
    }
    public void observed(ActionDecision action,ObservationState before,ObservationState after) {
        // Preserve the code4 rule: catalogue reads retain the preceding effect;
        // wait clears it, while home/back replace it with their own action key.
        if(ActionPolicy.isReadOnlyDiscovery(action))return;
        boolean effect="open".equals(action.action)||"click".equals(action.action)
                ||"type".equals(action.action)||"scroll".equals(action.action)
                ||"back".equals(action.action)||"home".equals(action.action);
        previousActionKey=effect?key(action):null;
        // Unknown is not positive progress evidence. In particular it cannot
        // reset a rejected back by pretending an unobserved IME disappeared.
        previousNoChangeState=effect&&!Boolean.TRUE.equals(after.changedFrom(before))?after:null;
        previousEffect=effect?action:null;
    }

    /** Only expose an open that the unchanged dispatch predicate already rejects. */
    public String blockedOpenPackage(String currentTree) {
        return blockedOpenPackage(new ObservationState(currentTree,ImeVisibility.UNKNOWN));
    }
    public String blockedOpenPackage(ObservationState current) {
        return previousEffect!=null&&"open".equals(previousEffect.action)
                &&rejects(previousEffect,current)?previousEffect.packageName:null;
    }

    /** Keep the launch catalogue intact; use this same subset for grammar and policy. */
    public Set<String> allowedOpenPackages(Set<String> supplied,String currentTree) {
        return allowedOpenPackages(supplied,new ObservationState(currentTree,ImeVisibility.UNKNOWN));
    }
    public Set<String> allowedOpenPackages(Set<String> supplied,ObservationState current) {
        Set<String> allowed=new HashSet<String>(supplied);
        String blocked=blockedOpenPackage(current);
        if(blocked!=null)allowed.remove(blocked);
        return allowed;
    }

    /** Expose only the same node click that the existing dispatch predicate already rejects. */
    public String blockedClickNodeId(ObservationState current) {
        return previousEffect!=null&&"click".equals(previousEffect.action)&&previousEffect.nodeId!=null
                &&rejects(previousEffect,current)?previousEffect.nodeId:null;
    }

    /** Keep visible nodes intact; remove only an already-rejected click capability. */
    public Set<String> allowedClicks(Set<String> supplied,ObservationState current) {
        Set<String> allowed=new HashSet<String>(supplied);
        String blocked=blockedClickNodeId(current);
        if(blocked!=null)allowed.remove(blocked);
        return allowed;
    }

    // Exact code4 equality: observation id, reason, status and duration are not
    // part of the effect identity. Do not infer package families or app success.
    private static String key(ActionDecision a) {
        return a.action+"|"+a.packageName+"|"+a.nodeId+"|"+a.x+"|"+a.y+"|"+a.direction+"|"+a.text+"|"+a.query+"|"+a.offset;
    }
}
