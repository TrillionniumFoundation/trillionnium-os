/* SPDX-License-Identifier: Apache-2.0 */
package org.trillionnium.agentaccessibility;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ResolveInfo;
import android.view.accessibility.AccessibilityManager;

import java.util.List;

/** Re-checks Android's per-user explicit Accessibility grant before exposing the Agent socket. */
final class AccessibilityUserAuthorizationGate {
    private AccessibilityUserAuthorizationGate() {}

    static boolean isExplicitlyEnabled(Context context, ComponentName expectedComponent) {
        if (context == null || expectedComponent == null) return false;
        AccessibilityManager manager = context.getSystemService(AccessibilityManager.class);
        if (manager == null || !manager.isEnabled()) return false;
        List<AccessibilityServiceInfo> enabled = manager.getEnabledAccessibilityServiceList(
                AccessibilityServiceInfo.FEEDBACK_ALL_MASK);
        if (enabled == null) return false;
        for (AccessibilityServiceInfo item : enabled) {
            ResolveInfo resolve = item == null ? null : item.getResolveInfo();
            if (resolve == null || resolve.serviceInfo == null) continue;
            ComponentName observed = new ComponentName(
                    resolve.serviceInfo.packageName, resolve.serviceInfo.name);
            if (expectedComponent.equals(observed)) return true;
        }
        return false;
    }
}
