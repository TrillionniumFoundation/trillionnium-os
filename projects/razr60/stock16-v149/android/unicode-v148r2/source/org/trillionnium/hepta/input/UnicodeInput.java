package org.trillionnium.hepta.input;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.app.UiAutomation;
import android.graphics.Rect;
import android.os.Bundle;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Process;
import android.os.SystemClock;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityWindowInfo;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;
import org.json.JSONObject;

/** One narrowly targeted ACTION_SET_TEXT, run as existing Android Shell UID2000.
 * This is not an IME, persistent service, permission grant or general shell API.
 */
public final class UnicodeInput {
    private static final String SCHEMA = "hepta.focused-unicode-input.v1";
    private static final int CONNECT_TIMEOUT_MS = 5000;
    private static final int READBACK_TIMEOUT_MS = 2000;
    private static final int MAX_VIEW_MATCHES = 32;

    private static final class Rejected extends Exception {
        Rejected(String reason) { super(reason); }
    }

    private static final class Candidate implements AutoCloseable {
        final AccessibilityNodeInfo root;
        final AccessibilityNodeInfo node;
        final AccessibilityWindowInfo window;
        final Rect bounds;
        final String text;
        Candidate(AccessibilityNodeInfo root, AccessibilityNodeInfo node,
                  AccessibilityWindowInfo window, Rect bounds, String text) {
            this.root = root; this.node = node; this.window = window;
            this.bounds = bounds; this.text = text;
        }
        boolean sameNode(Candidate other) {
            return window.getId() == other.window.getId() && node.equals(other.node);
        }
        public void close() {
            if (node != root) node.recycle();
            root.recycle(); window.recycle();
        }
    }

    private static String chars(CharSequence text) { return text == null ? "" : text.toString(); }
    private static String effectiveText(AccessibilityNodeInfo node) {
        // Showing a hint is an empty draft, not permission to replace a draft
        // containing the hint string itself.
        return node.isShowingHintText() ? "" : chars(node.getText());
    }

    private static Candidate observe(UiAutomation automation, InputContract c) throws Exception {
        automation.clearCache();
        AccessibilityNodeInfo root = automation.getRootInActiveWindow();
        if (root == null) throw new Rejected("no_active_root");
        AccessibilityNodeInfo selected = null;
        AccessibilityWindowInfo window = null;
        try {
            if (!c.packageName.equals(chars(root.getPackageName()))) throw new Rejected("foreground_package_differs");
            List<AccessibilityNodeInfo> matches = root.findAccessibilityNodeInfosByViewId(c.viewId);
            if (matches == null || matches.size() > MAX_VIEW_MATCHES) throw new Rejected("target_count_invalid");
            int selectedCount = 0;
            for (AccessibilityNodeInfo node : matches) {
                boolean eligible = c.packageName.equals(chars(node.getPackageName()))
                        && c.viewId.equals(node.getViewIdResourceName())
                        && node.isVisibleToUser() && node.isEnabled() && node.isEditable()
                        && node.isFocused() && !node.isPassword();
                if (eligible) { selectedCount++; if (selected == null) selected = node; else node.recycle(); }
                else node.recycle();
            }
            if (selectedCount != 1 || selected == null) throw new Rejected("focused_editable_target_not_unique");
            if (selected.getWindowId() != root.getWindowId()) throw new Rejected("target_window_differs");
            window = selected.getWindow();
            if (window == null || window.getDisplayId() != c.display || !window.isActive()
                    || !window.isFocused() || window.getType() != AccessibilityWindowInfo.TYPE_APPLICATION)
                throw new Rejected("active_window_or_display_differs");
            boolean supportsSetText = false;
            for (AccessibilityNodeInfo.AccessibilityAction action : selected.getActionList())
                if (action.getId() == AccessibilityNodeInfo.ACTION_SET_TEXT) supportsSetText = true;
            if (!supportsSetText) throw new Rejected("set_text_action_not_supported");
            Rect bounds = new Rect(), windowBounds = new Rect();
            selected.getBoundsInScreen(bounds); window.getBoundsInScreen(windowBounds);
            if (bounds.isEmpty() || !Rect.intersects(bounds, windowBounds)) throw new Rejected("target_not_in_window_bounds");
            Candidate answer = new Candidate(root, selected, window, bounds, effectiveText(selected));
            root = null; selected = null; window = null;
            return answer;
        } finally {
            if (selected != null) selected.recycle();
            if (root != null) root.recycle();
            if (window != null) window.recycle();
        }
    }

    private static Throwable unwrap(Throwable error) {
        while (error instanceof InvocationTargetException && error.getCause() != null) error = error.getCause();
        return error;
    }

    public static void main(String[] argv) {
        JSONObject result = new JSONObject();
        InputContract contract = null;
        HandlerThread callbacks = null;
        UiAutomation automation = null;
        Object connection = null;
        Candidate before = null;
        String phase = "arguments";
        boolean actionAttempted = false;
        boolean connected = false;
        boolean disconnected = false;
        int exitCode = 20;
        try {
            result.put("schema", SCHEMA).put("status", "rejected").put("effect_state", "not_started");
            if (Process.myUid() != 2000) throw new Rejected("requires_existing_shell_uid2000");
            contract = InputContract.parse(argv);
            result.put("operation_id", contract.operationId).put("display_id", contract.display)
                    .put("package", contract.packageName).put("view_id", contract.viewId)
                    .put("requested_utf8_sha256", InputContract.sha(contract.replacement));
            phase = "prepare_main_looper";
            if (Looper.getMainLooper() == null) Looper.prepareMainLooper();
            phase = "construct_shell_automation";
            callbacks = new HandlerThread("hepta-text-observer"); callbacks.start();
            Class<?> iface = Class.forName("android.app.IUiAutomationConnection");
            Class<?> implementation = Class.forName("android.app.UiAutomationConnection");
            Constructor<?> connectionConstructor = implementation.getDeclaredConstructor();
            connectionConstructor.setAccessible(true); connection = connectionConstructor.newInstance();
            Constructor<UiAutomation> constructor = UiAutomation.class.getDeclaredConstructor(Looper.class, iface);
            constructor.setAccessible(true); automation = constructor.newInstance(callbacks.getLooper(), connection);
            phase = "connect_bounded";
            Method connect = UiAutomation.class.getDeclaredMethod("connectWithTimeout", int.class, long.class);
            connect.setAccessible(true);
            connect.invoke(automation, UiAutomation.FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES, (long) CONNECT_TIMEOUT_MS);
            connected = true;
            phase = "own_service_observation_flags";
            AccessibilityServiceInfo info = automation.getServiceInfo();
            if (info == null) throw new Rejected("own_test_service_info_missing");
            info.flags |= AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS
                    | AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS;
            automation.setServiceInfo(info);
            phase = "observe_expected_focused_target";
            before = observe(automation, contract);
            if (!before.text.equals(contract.expected)) throw new Rejected("existing_text_differs_preserved");
            result.put("window_id", before.window.getId()).put("bounds", before.bounds.toShortString())
                    .put("before_utf8_sha256", InputContract.sha(before.text));
            // Repeat only the read observation immediately before one effect.
            try (Candidate current = observe(automation, contract)) {
                if (!before.sameNode(current) || !current.text.equals(contract.expected))
                    throw new Rejected("target_changed_before_action");
            }
            if (contract.replacement.equals(before.text)) {
                result.put("status", "already_exact").put("effect_state", "not_started")
                        .put("readback_text_b64", InputContract.encodeText(before.text))
                        .put("after_utf8_sha256", InputContract.sha(before.text));
                exitCode = 0;
            } else {
                phase = "one_set_text_action";
                Bundle arguments = new Bundle();
                arguments.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, contract.replacement);
                actionAttempted = true;
                result.put("effect_state", "attempted_once_outcome_unknown");
                boolean accepted = before.node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, arguments);
                result.put("action_accepted", accepted);
                phase = "readback_only_no_action_retry";
                long deadline = SystemClock.uptimeMillis() + READBACK_TIMEOUT_MS;
                boolean verified = false;
                while (SystemClock.uptimeMillis() <= deadline) {
                    try (Candidate after = observe(automation, contract)) {
                        if (!before.sameNode(after)) throw new Rejected("target_changed_after_action");
                        result.put("after_utf8_sha256", InputContract.sha(after.text));
                        if (after.text.equals(contract.replacement)) {
                            // Only the exact owner-requested replacement is exposed.
                            result.put("readback_text_b64", InputContract.encodeText(after.text));
                            verified = true; break;
                        }
                    }
                    SystemClock.sleep(50);
                }
                if (verified) {
                    result.put("status", "set_verified").put("effect_state", "observed_exact_requested_text");
                    exitCode = 0;
                } else {
                    result.put("status", "readback_not_verified"); exitCode = 22;
                }
            }
        } catch (Throwable error) {
            Throwable cause = unwrap(error);
            try {
                result.put("status", actionAttempted ? "outcome_unknown" : "rejected")
                        .put("effect_state", actionAttempted ? "attempted_once_outcome_unknown" : "not_started")
                        .put("failure_phase", phase).put("error_type", cause.getClass().getName());
                if (cause instanceof Rejected) result.put("reason", cause.getMessage());
            } catch (Throwable ignored) { }
            exitCode = actionAttempted ? 22 : 20;
        } finally {
            if (before != null) before.close();
            if (automation != null) {
                try {
                    Method disconnect = UiAutomation.class.getDeclaredMethod("disconnect");
                    disconnect.setAccessible(true); disconnect.invoke(automation); disconnected = true;
                } catch (Throwable error) {
                    try { result.put("disconnect_error_type", unwrap(error).getClass().getName()); }
                    catch (Throwable ignored) { }
                }
            }
            // This is this process's connection object, not an Android daemon.
            // It also unregisters a test service if connect timed out mid-callback.
            if (connection != null) {
                try {
                    Method shutdown = connection.getClass().getDeclaredMethod("shutdown");
                    shutdown.setAccessible(true); shutdown.invoke(connection);
                    disconnected = true;
                } catch (Throwable error) {
                    if (connected && !disconnected) {
                        try { result.put("shutdown_error_type", unwrap(error).getClass().getName()); }
                        catch (Throwable ignored) { }
                    }
                }
            }
            if (callbacks != null) {
                callbacks.quitSafely();
                try { callbacks.join(1000); } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
            }
            try { result.put("action_attempted", actionAttempted).put("own_automation_disconnected", disconnected); }
            catch (Throwable ignored) { }
            if (connected && !disconnected) exitCode = 25;
        }
        System.out.println(result.toString());
        System.exit(exitCode);
    }
}
