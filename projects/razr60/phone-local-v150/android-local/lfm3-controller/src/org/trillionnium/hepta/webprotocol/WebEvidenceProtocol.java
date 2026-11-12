package org.trillionnium.hepta.webprotocol;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

/** Byte-identical shared client/helper contract. No page-controlled route or JS. */
public final class WebEvidenceProtocol {
    private WebEvidenceProtocol() { }
    public static final String CONTROLLER_PACKAGE="org.trillionnium.hepta.local";
    public static final String HELPER_PACKAGE="org.trillionnium.hepta.webhelper";
    public static final String SERVICE_CLASS=HELPER_PACKAGE+".EvidenceService";
    public static final String ACTIVITY_CLASS=HELPER_PACKAGE+".PageActivity";
    public static final String PERMISSION=HELPER_PACKAGE+".permission.BIND_EVIDENCE";
    public static final String DESCRIPTOR=HELPER_PACKAGE+".IWebEvidence.v2";
    public static final String CALLBACK_DESCRIPTOR=HELPER_PACKAGE+".IWebEvidenceCallback.v2";
    public static final String CALLBACK_SCHEMA="hepta.web-helper.callback.v2";
    public static final String RAW_SCHEMA="hepta.web-helper.raw-evidence.v2";
    public static final String BINDING_SCHEMA="hepta.web-helper.binding.v2";
    public static final String JOURNAL_SCHEMA="hepta.web-helper.lease-journal.v2";
    public static final String RECOVERY_SCHEMA="hepta.web-helper.recovered-retirement.v1";
    public static final String UNSTARTED_SCHEMA="hepta.web-helper.unstarted-retirement.v1";
    public static final String UNSTARTED_CONFIRMATION_SCHEMA="hepta.web-helper.unstarted-retirement-confirmation.v1";
    public static final String UNSTARTED_FENCE_SCHEMA="hepta.web-helper.unstarted-resource-fence.v1";
    public static final int MAX_UNSTARTED_RECORD_BYTES=65536;
    public static final int HELPER_VERSION_CODE=3;
    public static final String HELPER_VERSION_NAME="0.3.0-web-evidence-v2";
    public static final String SIGNER_SHA256="202d00f853589c753069189086e0c76cb308d11745c33e70200985e4de3129d5";
    public static final String INITIAL_URL="https://m.csair.com/";
    public static final int ATTACH=1,CAPTURE=2,CLOSE=3,CALLBACK_RESULT=1;
    public static final int MAX_REQUEST_BYTES=16384,MAX_CALLBACK_BYTES=16384,MAX_EVIDENCE_BYTES=2*1024*1024;
    public static final int MAX_DOM_BYTES=1024*1024,MAX_REQUESTS_PER_SESSION=128,MAX_DIAGNOSTICS=64;
    public static final int MAX_CLOSE_REQUESTS_IN_WINDOW=32;
    public static final long CAPTURE_MS=3000,MAX_RPC_FUTURE_MS=10000,MAX_LEASE_MS=540000,MAX_FILES_BYTES=64L*1024*1024;
    public static final Set<String> COMMON_REQUEST=keys("schema","request_nonce","task_id","controller_session_nonce","deadline_elapsed_ms");
    public static final Set<String> ATTACH_EXTRA=keys("owner","owner_sha256","contract_sha256","authorization","background","controller_identity","helper_identity");
    public static final Set<String> CAPTURE_EXTRA=keys("expected_webview_instance","expected_navigation_epoch");
    public static final Set<String> CLOSE_EXTRA=keys("reason");
    public static final Set<String> BACKGROUND_KEYS=keys("generation","display_id","display_name","boot_count","created_elapsed_ms","expires_elapsed_ms","selected_packages");
    public static final Set<String> IDENTITY_KEYS=keys("package","uid","version_code","apk_hashes","apk_set_sha256","signer_sha256");
    public static final Set<String> AUTHORIZATION_KEYS=keys("schema","parser","instruction_sha256","authorization_sha256","allowed_tools","require_find_app_before_open","find_query","recognized_rules","arbitrary_semantic_constraints_verified");
    public static final Set<String> CALLBACK_KEYS=keys("schema","method","request_nonce","task_id","controller_session_nonce","status","reason","actual_helper_uid","actual_display_id","actual_window_id","webview_instance","navigation_epoch","binding_sha256","raw_length","raw_sha256","retired","cleanup","recovery");
    public static final Set<String> CLEANUP_KEYS=keys("captures_retired","stop_loading_called","webview_destroyed","active_view_absent","storage_clear_completed");
    public static final Set<String> READ_ONLY_TOOLS=keys("back","click","done","open","scroll","submit","type","wait");
    public static String method(int code) {
        if(code==ATTACH)return "attachLease";
        if(code==CAPTURE)return "captureEvidence";
        if(code==CLOSE)return "closeLease";
        throw new IllegalArgumentException("unknown evidence method");
    }
    public static String requestSchema(int code) {
        if(code==ATTACH)return "hepta.web-helper.attach.v2";
        if(code==CAPTURE)return "hepta.web-helper.capture.v2";
        if(code==CLOSE)return "hepta.web-helper.close.v2";
        throw new IllegalArgumentException("unknown evidence method");
    }
    public static Set<String> requestKeys(int code) {
        TreeSet<String> set=new TreeSet<String>(COMMON_REQUEST);
        set.addAll(code==ATTACH?ATTACH_EXTRA:code==CAPTURE?CAPTURE_EXTRA:code==CLOSE?CLOSE_EXTRA:Collections.<String>emptySet());
        method(code);return Collections.unmodifiableSet(set);
    }
    public static boolean hex32(String s){return s!=null&&s.matches("[0-9a-f]{32}");}
    public static boolean hex64(String s){return s!=null&&s.matches("[0-9a-f]{64}");}
    public static boolean uuid(String s){return s!=null&&s.matches("[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}");}
    private static Set<String> keys(String... names){return Collections.unmodifiableSet(new TreeSet<String>(Arrays.asList(names)));}
}
