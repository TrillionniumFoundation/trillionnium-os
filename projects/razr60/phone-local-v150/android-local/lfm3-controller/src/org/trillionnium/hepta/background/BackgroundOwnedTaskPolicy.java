package org.trillionnium.hepta.background;

import java.util.Objects;

/**
 * A conditional outbound-Intent policy, not a task ownership or cleanup proof.
 * The broker must already have authenticated the request and verified its live owned display.
 * Android 16 Task.setIntent enables document auto-remove only for DOCUMENT_LAUNCH_NONE
 * (unless the manifest independently requests auto-remove). No task is removed here.
 */
public final class BackgroundOwnedTaskPolicy {
    public static final String SCHEMA = "hepta.background-task-launch-policy.v1";
    public static final int NEW_TASK = 0x10000000;
    public static final int MULTIPLE_TASK = 0x08000000;
    public static final int NEW_DOCUMENT = 0x00080000;
    public static final int RETAIN_IN_RECENTS = 0x00002000;
    private static final int REUSE_OR_CLEAR = 0x20000000 | 0x04000000 | 0x00020000 | 0x00008000;

    private BackgroundOwnedTaskPolicy() {}

    /** Values copied from one real PackageManager ActivityInfo; unknown is never replaced by zero. */
    public static final class Activity {
        public final String packageName, component, targetActivity, permission, sourceDir;
        public final int uid, launchMode, documentLaunchMode, manifestFlags;
        public final boolean enabled, applicationEnabled, exported;

        public Activity(String packageName, String component, int uid, int launchMode,
                        int documentLaunchMode, int manifestFlags, boolean enabled,
                        boolean applicationEnabled, boolean exported, String targetActivity,
                        String permission, String sourceDir) {
            if (!packageName(packageName) || component == null
                || !component.startsWith(packageName + "/")
                || component.length() <= packageName.length() + 1
                || component.indexOf('\0') >= 0 || uid < 0 || uid >= 100000
                || sourceDir == null || !sourceDir.startsWith("/") || sourceDir.indexOf('\0') >= 0)
                throw new IllegalArgumentException("ACTIVITY_IDENTITY_INVALID");
            this.packageName = packageName; this.component = component; this.uid = uid;
            this.launchMode = launchMode; this.documentLaunchMode = documentLaunchMode;
            this.manifestFlags = manifestFlags; this.enabled = enabled;
            this.applicationEnabled = applicationEnabled; this.exported = exported;
            this.targetActivity = targetActivity; this.permission = permission; this.sourceDir = sourceDir;
        }

        public boolean same(Activity other) {
            return other != null && packageName.equals(other.packageName)
                && component.equals(other.component) && uid == other.uid
                && launchMode == other.launchMode && documentLaunchMode == other.documentLaunchMode
                && manifestFlags == other.manifestFlags && enabled == other.enabled
                && applicationEnabled == other.applicationEnabled && exported == other.exported
                && Objects.equals(targetActivity, other.targetActivity)
                && Objects.equals(permission, other.permission) && sourceDir.equals(other.sourceDir);
        }
    }

    public static final class Plan {
        public final String generation, packageName, component, reason;
        public final int displayId, targetUid, originalFlags, outboundFlags;
        public final int launchMode, documentLaunchMode, manifestFlags;
        public final boolean eligible, newDocumentRequested;
        // Outbound flags cannot attest framework-adjusted flags, ownership or subsequent cleanup.
        public final boolean frameworkFlagsVerified = false;
        public final boolean taskOwnershipVerified = false;
        public final boolean recentsCleanupVerified = false;

        private Plan(String generation, int displayId, Activity activity, int flags,
                     boolean eligible, String reason) {
            this.generation = generation; this.displayId = displayId;
            packageName = activity.packageName; component = activity.component; targetUid = activity.uid;
            launchMode = activity.launchMode; documentLaunchMode = activity.documentLaunchMode;
            manifestFlags = activity.manifestFlags; originalFlags = flags; this.eligible = eligible;
            this.reason = reason;
            outboundFlags = eligible ? ((flags | NEW_DOCUMENT) & ~RETAIN_IN_RECENTS) : flags;
            newDocumentRequested = (outboundFlags & NEW_DOCUMENT) != 0;
        }
    }

    /** Preserve the original flags for unsupported manifest/task modes; never guess a mode. */
    public static Plan choose(String generation, int displayId, String scopedPackage,
                              Activity activity, int flags) {
        if (generation == null || !generation.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
            || displayId <= 0 || activity == null || !activity.packageName.equals(scopedPackage))
            throw new IllegalArgumentException("LEASE_ACTIVITY_BINDING_INVALID");
        if (!activity.enabled || !activity.applicationEnabled || !activity.exported)
            throw new IllegalArgumentException("ACTIVITY_NOT_ENABLED_EXPORTED");
        boolean freshTaskFlags = (flags & (NEW_TASK | MULTIPLE_TASK)) == (NEW_TASK | MULTIPLE_TASK)
            && (flags & REUSE_OR_CLEAR) == 0;
        boolean eligible = activity.launchMode == 0 && activity.documentLaunchMode == 0 && freshTaskFlags;
        String reason = activity.launchMode != 0 ? "unsupported_actual_launch_mode"
            : activity.documentLaunchMode != 0 ? "unsupported_actual_document_launch_mode"
            : !freshTaskFlags ? "intent_not_an_unambiguous_new_task_request"
            : "standard_document_none_new_task_request";
        return new Plan(generation, displayId, activity, flags, eligible, reason);
    }

    private static boolean packageName(String value) {
        return value != null && value.length() <= 255
            && value.matches("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+");
    }
}
