package org.trillionnium.hepta.local;

import java.util.Set;

/** Model-output checks before dispatch; the service separately rechecks live UI state. */
public final class ActionPolicy {
    private ActionPolicy() {}

    public static void validateAuthorizedDecision(ActionDecision action,String currentPackage,
            Set<String> shownApps,ObservedTargetLabels targets,ObservedAppLabels apps,
            TaskAuthorization.Gate owner,TaskAuthorization.Frame frame) throws ActionDecision.InvalidActionException {
        TaskAuthorization.require(owner!=null&&frame!=null&&owner.authorization==frame.authorization
                &&owner.taskId.equals(frame.taskId),"动作语法与当前任务授权不一致");
        owner.ready();frame.requireDecision(action);
        if("open".equals(action.action))
            TaskAuthorization.require(shownApps!=null&&shownApps.contains(action.packageName),"打开目标不在本轮授权工具域内");
        validateTextDecision(action,currentPackage,shownApps,targets,apps);
    }

    public static void validateTextDecision(ActionDecision action, String currentPackage,
            Set<String> shownApps, ObservedTargetLabels targets) throws ActionDecision.InvalidActionException {
        if (!ObservedTargetLabels.ACTION_SCHEMA.equals(action.actionSchema))
            throw new ActionDecision.InvalidActionException("v4 decisions require the observed app-pair policy");
        validateCommon(action,currentPackage,shownApps,targets);
    }

    public static void validateTextDecision(ActionDecision action, String currentPackage,
            Set<String> shownApps, ObservedTargetLabels targets, ObservedAppLabels apps)
            throws ActionDecision.InvalidActionException {
        if (!ObservedAppLabels.ACTION_SCHEMA.equals(action.actionSchema) || apps == null
                || !apps.observationId.equals(action.observationId) || !apps.currentPackage.equals(currentPackage)
                || shownApps == null || !apps.labels.keySet().equals(shownApps))
            throw new ActionDecision.InvalidActionException("app-label projection belongs to a different frame or schema");
        if ("open".equals(action.action) && !apps.matches(action.observationId,currentPackage,action.packageName,action.appLabel))
            throw new ActionDecision.InvalidActionException("app_label and package must be the exact supplied pair for this observation");
        validateCommon(action,currentPackage,shownApps,targets);
    }

    private static void validateCommon(ActionDecision action,String currentPackage,
            Set<String> shownApps,ObservedTargetLabels targets) throws ActionDecision.InvalidActionException {
        if (targets == null || !currentPackage.equals(targets.packageName))
            throw new ActionDecision.InvalidActionException("target-label projection belongs to a different package");
        if ("open".equals(action.action)) {
            if (!shownApps.contains(action.packageName))
                throw new ActionDecision.InvalidActionException("open package is not in the supplied launcher apps");
            if (currentPackage.equals(action.packageName))
                throw new ActionDecision.InvalidActionException("app is already foreground; inspect goal or use its nodes");
        } else if (!currentPackage.equals(action.packageName)) {
            throw new ActionDecision.InvalidActionException("package must exactly match screen.package");
        }
        // Discovery reads only the task's installed launcher snapshot. It does
        // not grant open permission: the next decision must still name a package
        // actually supplied in that next prompt's app projection.
        if (isReadOnlyDiscovery(action)) return;
        if (action.nodeId != null && !targets.matches(action.observationId, action.packageName, action.nodeId, action.nodeLabel))
            throw new ActionDecision.InvalidActionException("node_label and node_id must be the exact supplied pair for this observation");
        if ("click".equals(action.action) && action.nodeId == null)
            throw new ActionDecision.InvalidActionException("text-only controller must click an observed node_id, not coordinates");
    }

    /** Target-independent tools still require the observed live window identity.
     * A changing clock/readout does not change the meaning of opening an exact
     * installed package, going Home, waiting, or reading the app catalogue. */
    public static boolean requiresStableTree(ActionDecision action) {
        return !("open".equals(action.action)||"home".equals(action.action)
                ||"wait".equals(action.action)||isReadOnlyDiscovery(action));
    }

    public static boolean isReadOnlyDiscovery(ActionDecision action) {
        return "find_app".equals(action.action);
    }
}
