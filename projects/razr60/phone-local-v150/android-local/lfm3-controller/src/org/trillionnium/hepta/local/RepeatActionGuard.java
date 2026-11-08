package org.trillionnium.hepta.local;

import java.util.HashSet;
import java.util.Set;

/** The controller's existing same-action/unchanged-tree dispatch guard. */
public final class RepeatActionGuard {
    private String previousActionKey;
    private String previousNoChangeTree;
    private ActionDecision previousEffect;

    public boolean rejects(ActionDecision action,String currentTree) {
        return key(action).equals(previousActionKey)&&currentTree.equals(previousNoChangeTree);
    }

    /** Call only after the accepted action and its fresh after-observation. */
    public void observed(ActionDecision action,String beforeTree,String afterTree) {
        // Preserve the code4 rule: catalogue reads retain the preceding effect;
        // wait clears it, while home/back replace it with their own action key.
        if(ActionPolicy.isReadOnlyDiscovery(action))return;
        boolean effect="open".equals(action.action)||"click".equals(action.action)
                ||"type".equals(action.action)||"scroll".equals(action.action)
                ||"back".equals(action.action)||"home".equals(action.action);
        previousActionKey=effect?key(action):null;
        previousNoChangeTree=effect&&beforeTree.equals(afterTree)?afterTree:null;
        previousEffect=effect?action:null;
    }

    /** Only expose an open that the unchanged dispatch predicate already rejects. */
    public String blockedOpenPackage(String currentTree) {
        return previousEffect!=null&&"open".equals(previousEffect.action)
                &&rejects(previousEffect,currentTree)?previousEffect.packageName:null;
    }

    /** Keep the launch catalogue intact; use this same subset for grammar and policy. */
    public Set<String> allowedOpenPackages(Set<String> supplied,String currentTree) {
        Set<String> allowed=new HashSet<String>(supplied);
        String blocked=blockedOpenPackage(currentTree);
        if(blocked!=null)allowed.remove(blocked);
        return allowed;
    }

    // Exact code4 equality: observation id, reason, status and duration are not
    // part of the effect identity. Do not infer package families or app success.
    private static String key(ActionDecision a) {
        return a.action+"|"+a.packageName+"|"+a.nodeId+"|"+a.x+"|"+a.y+"|"+a.direction+"|"+a.text+"|"+a.query+"|"+a.offset;
    }
}
