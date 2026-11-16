package org.trillionnium.hepta.local;

import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebEvidenceBinding;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import org.trillionnium.hepta.webprotocol.WebRecoveryPolicy;
import org.trillionnium.hepta.webprotocol.WebStorageEvidence;
import org.trillionnium.hepta.webprotocol.WebTaskPurpose;
import org.trillionnium.hepta.webprotocol.WebSitePolicy;
import org.trillionnium.hepta.webprotocol.WebDomCanonical;
import org.trillionnium.hepta.webprotocol.WebDomStability;
import org.trillionnium.hepta.webprotocol.WebObservedNavigation;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Pure replay of the authenticated helper reply. No reply is a business success. */
final class WebEvidenceReceipt {
    static final String OBSERVER_SHA="05bb7c1e4e1929b961c42af1e5c0e01918bf6ff64f153132ca11c7d85873e705";
    final String status,bindingSha,instance,url,domSha;
    final long epoch,started,ended;
    final int displayId,windowId;
    final boolean cleanupKnown,recovered,unstarted;
    private final String replyRaw,evidenceRaw,captureRaw,domRaw,armRaw;
    private final WebDomStability.Result checkedStability;
    private WebEvidenceReceipt(JSONObject callback,String raw,String capture,String dom,boolean closed,boolean recovered)throws Exception{
        this(callback,raw,capture,dom,closed,recovered,null,null);
    }
    private WebEvidenceReceipt(JSONObject callback,String raw,String capture,String dom,boolean closed,boolean recovered,
                               WebDomStability.Result stability,JSONObject arm)throws Exception{
        checkedStability=stability;armRaw=arm==null?null:WebDomCanonical.canonical(arm);
        status=WebEvidenceJson.text(callback,"status");bindingSha=nullableText(callback,"binding_sha256");
        instance=nullableText(callback,"webview_instance");epoch=callback.isNull("navigation_epoch")?-1:WebEvidenceJson.number(callback,"navigation_epoch");
        displayId=WebEvidenceJson.integer(callback,"actual_display_id");windowId=WebEvidenceJson.integer(callback,"actual_window_id");
        replyRaw=callback.toString();evidenceRaw=raw;captureRaw=capture;domRaw=dom;cleanupKnown=closed;this.recovered=recovered;
        unstarted=closed&&"unstarted_retired".equals(status);
        JSONObject c=capture==null?null:WebEvidenceJson.parseCaptureEvidence(capture,WebEvidenceProtocol.MAX_EVIDENCE_BYTES);
        url=c==null?null:WebEvidenceJson.text(c,"current_native_url");
        domSha=c==null?null:WebEvidenceJson.text(c,"dom_sha256");
        started=c==null?-1:WebEvidenceJson.number(c,"started_elapsed_ms");ended=c==null?-1:WebEvidenceJson.number(c,"ended_elapsed_ms");
    }
    JSONObject callback()throws Exception{return WebEvidenceJson.parse(replyRaw,WebEvidenceProtocol.MAX_CALLBACK_BYTES);}
    JSONObject capture()throws Exception{return captureRaw==null?null:WebEvidenceJson.parseCaptureEvidence(captureRaw,WebEvidenceProtocol.MAX_EVIDENCE_BYTES);}
    JSONObject dom()throws Exception{return domRaw==null?null:WebEvidenceJson.parseDom(domRaw);}
    String evidenceRaw(){return evidenceRaw;}
    String domRaw(){return domRaw;}
    String beforeDomRaw()throws Exception{return captureRaw==null?null:text(capture(),"before_dom_raw_utf8");}
    WebDomStability.Result stability(){return checkedStability;}
    JSONObject arm()throws Exception{return armRaw==null?null:WebEvidenceJson.parseEvidence(armRaw,WebEvidenceProtocol.MAX_EVIDENCE_BYTES);}

    static WebEvidenceReceipt verify(int code,String requestRaw,JSONObject binding,String callbackRaw,byte[] raw,
                                      int authenticatedHelperUid,long sentElapsed,long receivedElapsed)throws Exception{
        return verify(code,requestRaw,binding,callbackRaw,raw,authenticatedHelperUid,sentElapsed,receivedElapsed,null);
    }
    static WebEvidenceReceipt verify(int code,String requestRaw,JSONObject binding,String callbackRaw,byte[] raw,
                                      int authenticatedHelperUid,long sentElapsed,long receivedElapsed,JSONObject sourceCapture)throws Exception{
        need((code==WebEvidenceProtocol.ARM_OBSERVED_LINK)==(sourceCapture!=null),
                "ARM alone requires the client's exact private successful source capture");
        WebTaskPurpose purpose=WebTaskPurpose.requireBinding(binding);
        JSONObject request=WebEvidenceJson.parse(requestRaw,WebEvidenceProtocol.MAX_REQUEST_BYTES);
        WebEvidenceJson.keys(request,WebEvidenceProtocol.requestKeys(code));
        need(WebEvidenceProtocol.requestSchema(code).equals(text(request,"schema")),"request schema differs");
        need(WebEvidenceProtocol.hex32(text(request,"task_id"))&&WebEvidenceProtocol.hex64(text(request,"controller_session_nonce"))
                &&WebEvidenceProtocol.hex64(text(request,"request_nonce")),"request identity shape differs");
        long deadline=number(request,"deadline_elapsed_ms");
        need(sentElapsed>=0&&receivedElapsed>=sentElapsed&&receivedElapsed<=deadline
                &&deadline>sentElapsed&&deadline-sentElapsed<=WebEvidenceProtocol.MAX_RPC_FUTURE_MS,"reply outside original RPC budget");
        need(text(binding,"task_id").equals(text(request,"task_id"))&&text(binding,"controller_session_nonce").equals(text(request,"controller_session_nonce"))
                &&WebEvidenceProtocol.BINDING_SCHEMA.equals(text(binding,"schema")),"immutable request binding differs");
        need(number(binding.getJSONObject("helper_identity"),"version_code")==WebEvidenceProtocol.HELPER_VERSION_CODE,
                "exact formal helper code is required; observer is not a task peer");
        JSONObject callback=WebEvidenceJson.parse(callbackRaw,WebEvidenceProtocol.MAX_CALLBACK_BYTES);
        WebEvidenceJson.keys(callback,WebEvidenceProtocol.CALLBACK_KEYS);
        need(WebEvidenceProtocol.CALLBACK_SCHEMA.equals(text(callback,"schema"))&&WebEvidenceProtocol.method(code).equals(text(callback,"method"))
                &&text(request,"request_nonce").equals(text(callback,"request_nonce"))
                &&text(request,"task_id").equals(text(callback,"task_id"))
                &&text(request,"controller_session_nonce").equals(text(callback,"controller_session_nonce")),"reply request identity differs");
        need(authenticatedHelperUid>=10000&&authenticatedHelperUid==WebEvidenceJson.integer(callback,"actual_helper_uid")
                &&authenticatedHelperUid==WebEvidenceJson.integer(binding.getJSONObject("helper_identity"),"uid"),"reply actual helper UID differs");
        Object reason=callback.get("reason");need(reason==JSONObject.NULL||reason instanceof String&&((String)reason).length()<=512,"reply reason shape");
        long length=number(callback,"raw_length");need(length>=0&&length<=WebEvidenceProtocol.MAX_EVIDENCE_BYTES,"raw evidence size");
        if(raw==null)need(length==0&&callback.get("raw_sha256")==JSONObject.NULL,"unexpected raw reference without FD");
        else need(length==raw.length&&length>0&&WebEvidenceProtocol.hex64(text(callback,"raw_sha256"))
                &&WebEvidenceJson.sha(raw).equals(text(callback,"raw_sha256")),"exact raw FD bytes/hash differ");
        String status=text(callback,"status"),bindingSha=WebEvidenceBinding.sha256(binding);
        boolean reject="rejected".equals(status);
        if(reject){
            need(raw==null&&callback.get("recovery")==JSONObject.NULL,"rejected reply contains evidence");
            throw new IllegalStateException("网页证据暂不可用："+(reason==JSONObject.NULL?status:reason));
        }
        need(bindingSha.equals(text(callback,"binding_sha256")),"reply binding SHA differs");
        if("unavailable".equals(status)){
            need(code==WebEvidenceProtocol.CAPTURE&&raw==null&&Boolean.FALSE.equals(callback.get("retired"))
                    &&callback.get("cleanup")==JSONObject.NULL&&callback.get("recovery")==JSONObject.NULL,
                    "only a live capture may report metadata-only unavailable");
            domain(callback,binding);
            Object expected=request.get("expected_webview_instance"),expectedEpoch=request.get("expected_navigation_epoch");
            need(expected==JSONObject.NULL&&expectedEpoch==JSONObject.NULL
                    ||expected instanceof String&&expected.equals(callback.get("webview_instance"))
                    &&(expectedEpoch instanceof Integer||expectedEpoch instanceof Long)
                    &&((Number)expectedEpoch).longValue()==number(callback,"navigation_epoch"),
                    "unavailable capture changed its exact expected page");
            return new WebEvidenceReceipt(callback,null,null,null,false,false);
        }
        if(code==WebEvidenceProtocol.ACK_CAPTURE){
            org.trillionnium.hepta.webprotocol.WebCaptureAcknowledgement.requireRequest(request,binding);
            need(org.trillionnium.hepta.webprotocol.WebCaptureAcknowledgement.STATUS.equals(status)&&raw==null
                    &&Boolean.FALSE.equals(callback.get("retired"))&&callback.get("cleanup")==JSONObject.NULL
                    &&callback.get("recovery")==JSONObject.NULL
                    &&org.trillionnium.hepta.webprotocol.WebCaptureAcknowledgement.reason(request).equals(reason),
                    "capture acknowledgement must bind exact durable transfer without page/cleanup authority");
            domain(callback,binding);return new WebEvidenceReceipt(callback,null,null,null,false,false);
        }
        if(code==WebEvidenceProtocol.CLOSE){
            need(Boolean.TRUE.equals(callback.get("retired")),"closed reply is not retired");
            if("closed".equals(status)){
                need(raw==null&&callback.get("recovery")==JSONObject.NULL,"ordinary close must not contain recovered proof");
                JSONObject cleanup=callback.getJSONObject("cleanup");WebEvidenceJson.keys(cleanup,WebEvidenceProtocol.CLEANUP_KEYS);
                for(String key:WebEvidenceProtocol.CLEANUP_KEYS)need(Boolean.TRUE.equals(cleanup.get(key)),"actual helper cleanup incomplete: "+key);
                domain(callback,binding);return new WebEvidenceReceipt(callback,null,null,null,true,false);
            }
            need(("recovered_retired".equals(status)||"unstarted_retired".equals(status))&&raw!=null,"unknown close evidence type");
            need(WebEvidenceJson.integer(callback,"actual_display_id")==-1&&WebEvidenceJson.integer(callback,"actual_window_id")==-1
                    &&callback.get("webview_instance")==JSONObject.NULL&&callback.get("navigation_epoch")==JSONObject.NULL,
                    "recovery must not represent an old view as live");
            String original=decode(raw);JSONObject evidence=WebEvidenceJson.parseEvidence(original,WebEvidenceProtocol.MAX_EVIDENCE_BYTES);
            if("unstarted_retired".equals(status)){
                JSONObject initial;String schema=text(evidence,"schema");
                if(WebEvidenceProtocol.UNSTARTED_SCHEMA.equals(schema)){
                    need(raw.length<=WebEvidenceProtocol.MAX_UNSTARTED_RECORD_BYTES,"initial unstarted FD budget");
                    requireRequestAndBinding(evidence,requestRaw,binding);initial=evidence;
                }else{
                    need(WebEvidenceProtocol.UNSTARTED_CONFIRMATION_SCHEMA.equals(schema),"exact unstarted retirement type");
                    requireOriginalRequest(evidence,requestRaw);
                    need(bindingSha.equals(text(evidence,"binding_sha256")),"confirmation binding hash differs");
                    initial=WebEvidenceJson.parseEvidence(text(evidence,"initial_record_utf8"),WebEvidenceProtocol.MAX_UNSTARTED_RECORD_BYTES);
                    need(WebEvidenceProtocol.UNSTARTED_SCHEMA.equals(text(initial,"schema")),"confirmation must preserve an initial proof");
                    requireRequestAndBinding(initial,text(initial,"request_json_utf8"),binding);
                }
                // Independently reject duplicate keys/types inside every preserved raw JSON.
                WebEvidenceJson.parse(text(initial,"request_json_utf8"),WebEvidenceProtocol.MAX_REQUEST_BYTES);
                WebEvidenceJson.parse(text(initial,"attach_request_json_utf8"),WebEvidenceProtocol.MAX_REQUEST_BYTES);
                WebEvidenceJson.parseEvidence(text(initial,"prior_journal_utf8"),65536);
                JSONObject verdict=WebRecoveryPolicy.evaluateUnstartedRecord(evidence);
                need(Boolean.TRUE.equals(verdict.get("retirement_verified"))
                        &&Boolean.TRUE.equals(verdict.get("owned_resources_never_started"))
                        &&Boolean.FALSE.equals(verdict.get("old_cleanup_methods_verified"))
                        &&Boolean.FALSE.equals(verdict.get("storage_cleanup_called"))
                        &&text(request,"request_nonce").equals(text(verdict,"request_nonce"))
                        &&same(verdict,callback.getJSONObject("recovery"))
                        &&same(initial.get("original_cleanup"),callback.get("cleanup")),
                        "unstarted retirement replay failed or changed old facts");
                return new WebEvidenceReceipt(callback,original,null,null,true,false);
            }
            requireRequestAndBinding(evidence,requestRaw,binding);
            // Parse embedded records strictly before the shared semantic replay, which uses org.json.
            WebEvidenceJson.parseEvidence(text(evidence,"prior_journal_utf8"),65536);
            WebEvidenceJson.parse(text(evidence,"request_json_utf8"),WebEvidenceProtocol.MAX_REQUEST_BYTES);
            JSONObject verdict=WebRecoveryPolicy.evaluateRecord(evidence);
            need(Boolean.TRUE.equals(verdict.get("retirement_verified"))
                    &&Boolean.TRUE.equals(verdict.get("recorded_profile_retirement_verified"))
                    &&Boolean.FALSE.equals(verdict.get("old_cleanup_methods_verified"))
                    &&same(verdict,callback.getJSONObject("recovery"))
                    &&same(evidence.get("original_cleanup"),callback.get("cleanup")),"recovered retirement replay failed or changed old facts");
            return new WebEvidenceReceipt(callback,original,null,null,true,true);
        }
        need(Boolean.FALSE.equals(callback.get("retired"))&&callback.get("cleanup")==JSONObject.NULL
                &&callback.get("recovery")==JSONObject.NULL,"active reply overclaims cleanup");
        domain(callback,binding);
        if(code==WebEvidenceProtocol.ATTACH){
            need("attached".equals(status)&&raw==null,"attach response differs");
            return new WebEvidenceReceipt(callback,null,null,null,false,false);
        }
        if(code==WebEvidenceProtocol.ARM_OBSERVED_LINK){
            need("armed".equals(status)&&raw!=null,"observed link ARM requires its exact read-only FD");
            String original=decode(raw);JSONObject evidence=WebEvidenceJson.parseEvidence(original,WebEvidenceProtocol.MAX_EVIDENCE_BYTES);
            exact(evidence,"schema","request_json_utf8","request_sha256","binding","binding_sha256","controller_identity","helper_identity",
                    "actual_window_id","arm","storage_isolation","actor","diagnostic_unbound","business_verified");
            need(WebEvidenceProtocol.RAW_SCHEMA.equals(text(evidence,"schema"))
                    &&"controller_observed_link_arm".equals(text(evidence,"actor"))
                    &&Boolean.FALSE.equals(evidence.get("diagnostic_unbound"))&&Boolean.FALSE.equals(evidence.get("business_verified")),
                    "formal observed-link ARM provenance required");
            requireRequestAndBinding(evidence,requestRaw,binding);
            need(same(evidence.getJSONObject("controller_identity"),binding.getJSONObject("controller_identity"))
                    &&same(evidence.getJSONObject("helper_identity"),binding.getJSONObject("helper_identity"))
                    &&number(evidence,"actual_window_id")==number(callback,"actual_window_id"),
                    "ARM installed/window identity differs");
            JSONObject arm=WebObservedNavigation.verifyArm(request,binding,sourceCapture,evidence.getJSONObject("arm"));
            long armed=number(arm,"armed_elapsed_ms"),expires=number(arm,"expires_elapsed_ms");
            need(sentElapsed<=armed&&armed<=receivedElapsed&&receivedElapsed<=expires
                    &&number(sourceCapture,"ended_elapsed_ms")<=sentElapsed
                    &&text(arm,"webview_instance").equals(text(callback,"webview_instance"))
                    &&number(arm,"navigation_epoch")==number(callback,"navigation_epoch")
                    &&number(arm,"actual_window_id")==number(callback,"actual_window_id")
                    &&number(arm,"display_id")==number(callback,"actual_display_id"),
                    "ARM reply is stale or belongs to another actual source window");
            WebStorageEvidence.requireCapture(binding,evidence.getJSONObject("storage_isolation"),armed,armed);
            return new WebEvidenceReceipt(callback,original,null,null,false,false,null,arm);
        }
        need(code==WebEvidenceProtocol.CAPTURE,"unknown method");
        if("state_changed".equals(status)){
            need(raw==null,"state change is metadata only");
            Object expectedInstance=request.get("expected_webview_instance"),expectedEpoch=request.get("expected_navigation_epoch");
            need(expectedInstance==JSONObject.NULL&&expectedEpoch==JSONObject.NULL
                    ||expectedInstance instanceof String&&expectedInstance.equals(callback.get("webview_instance"))
                    &&expectedEpoch instanceof Number&&number(callback,"navigation_epoch")>((Number)expectedEpoch).longValue(),
                    "state change must advance the same expected instance");
            return new WebEvidenceReceipt(callback,null,null,null,false,false);
        }
        need("captured".equals(status)&&raw!=null,"capture response differs");
        String original=decode(raw);JSONObject evidence=WebEvidenceJson.parseCaptureEvidence(original,WebEvidenceProtocol.MAX_EVIDENCE_BYTES);
        exact(evidence,"schema","request_json_utf8","request_sha256","binding","binding_sha256","controller_identity","helper_identity",
                "actual_window_id","capture","storage_isolation","actor","diagnostic_unbound","business_verified");
        need(WebEvidenceProtocol.RAW_SCHEMA.equals(text(evidence,"schema"))&&"controller_evidence_capture".equals(text(evidence,"actor"))
                &&Boolean.FALSE.equals(evidence.get("diagnostic_unbound"))&&Boolean.FALSE.equals(evidence.get("business_verified")),
                "bound controller capture required; diagnostics are not task evidence");
        requireRequestAndBinding(evidence,requestRaw,binding);
        need(same(evidence.getJSONObject("controller_identity"),binding.getJSONObject("controller_identity"))
                &&same(evidence.getJSONObject("helper_identity"),binding.getJSONObject("helper_identity"))
                &&number(evidence,"actual_window_id")==number(callback,"actual_window_id"),"raw installed/window identity differs");
        JSONObject capture=evidence.getJSONObject("capture");
        exact(capture,"schema","challenge","binding","helper_package","helper_uid","helper_pid","display_id","webview_instance",
                "actual_window_id","webview_bounds_screen_pixels","navigation_epoch","committed_main_frame_url","commit_elapsed_ms",
                "current_native_url","native_url_source","commit_source","visual_request_id","dom_raw_utf8","dom_sha256",
                "observer_script_sha256","started_elapsed_ms","ended_elapsed_ms","business_verified","pixel_equality_claimed",
                "all_visible_semantics_verified","truncated","capture_geometry","before_dom_raw_utf8","before_dom_sha256",
                "dom_stability","dom_stability_sha256","raw_dom_equal","comparison_scope","observed_link_navigation");
        need(WebObservedNavigation.CAPTURE_SCHEMA.equals(text(capture,"schema"))
                &&text(request,"request_nonce").equals(text(capture,"challenge"))&&same(binding,capture.getJSONObject("binding"))
                &&WebEvidenceProtocol.HELPER_PACKAGE.equals(text(capture,"helper_package"))
                &&number(capture,"helper_uid")==authenticatedHelperUid&&number(capture,"helper_pid")>0
                &&number(capture,"display_id")==number(callback,"actual_display_id")
                &&number(capture,"actual_window_id")==number(callback,"actual_window_id")
                &&text(capture,"webview_instance").equals(text(callback,"webview_instance"))
                &&number(capture,"navigation_epoch")==number(callback,"navigation_epoch"),"native capture identity differs");
        Object expected=request.get("expected_webview_instance"),epoch=request.get("expected_navigation_epoch");
        need((expected==JSONObject.NULL)==(epoch==JSONObject.NULL),"capture expectation pair");
        if(expected!=JSONObject.NULL)need(expected.equals(capture.get("webview_instance"))
                &&epoch instanceof Number&&((Number)epoch).longValue()==number(capture,"navigation_epoch"),"capture ignored exact instance/epoch");
        long started=number(capture,"started_elapsed_ms"),ended=number(capture,"ended_elapsed_ms"),committed=number(capture,"commit_elapsed_ms");
        JSONObject bg=binding.getJSONObject("background");
        need(number(bg,"created_elapsed_ms")<=committed&&committed<=started&&sentElapsed<=started
                &&started<=ended&&ended<=receivedElapsed&&ended-started<=WebEvidenceProtocol.CAPTURE_MS
                &&receivedElapsed<number(bg,"expires_elapsed_ms"),"capture/commit/RPC/lease time bracket differs");
        need("android.webkit.WebView.getUrl".equals(text(capture,"native_url_source"))
                &&"android.webkit.WebViewClient.onPageCommitVisible".equals(text(capture,"commit_source"))
                &&OBSERVER_SHA.equals(text(capture,"observer_script_sha256")),"native URL/fixed observer provenance differs");
        String url=text(capture,"current_native_url");String origin=purposeOrigin(purpose,url);
        need(origin.equals(purposeOrigin(purpose,text(capture,"committed_main_frame_url"))),"current and committed per-lease origins differ");
        for(String key:Arrays.asList("business_verified","pixel_equality_claimed","all_visible_semantics_verified","truncated"))
            need(Boolean.FALSE.equals(capture.get(key)),"capture scope/truncation differs: "+key);
        JSONArray box=capture.getJSONArray("webview_bounds_screen_pixels");
        need(box.length()==4,"native WebView bounds shape");
        long[] r=new long[4];for(int i=0;i<4;i++){Object v=box.get(i);need(v instanceof Integer||v instanceof Long,"integer native bounds");r[i]=((Number)v).longValue();}
        need(0<=r[0]&&0<=r[1]&&r[0]<r[2]&&r[1]<r[3]&&r[2]<=32768&&r[3]<=32768,"native WebView bounds invalid");
        String beforeRaw=text(capture,"before_dom_raw_utf8"),domRaw=text(capture,"dom_raw_utf8");
        need(WebEvidenceJson.sha(beforeRaw).equals(text(capture,"before_dom_sha256"))
                &&WebEvidenceJson.sha(domRaw).equals(text(capture,"dom_sha256")),"both exact DOM byte hashes required");
        JSONObject beforeDom=WebEvidenceJson.parseDom(beforeRaw),dom=WebEvidenceJson.parseDom(domRaw);
        for(JSONObject observed:Arrays.asList(beforeDom,dom)){
            need(WebDomStability.DOM_SCHEMA.equals(text(observed,"schema"))&&url.equals(text(observed,"href"))
                    &&origin.equals(text(observed,"origin"))&&"complete".equals(text(observed,"ready_state"))
                    &&Boolean.FALSE.equals(observed.get("truncated")),"DOM/current native origin/ready/truncation differs");
            need(observed.getJSONArray("nodes").length()<=1536&&number(observed,"visited")==observed.getJSONArray("nodes").length(),
                    "complete wire-v4 DOM node budget");
        }
        WebDomStability.Result stability=WebDomStability.verify(beforeRaw,domRaw,purpose.sitePolicyId,capture.getJSONObject("dom_stability"));
        need(stability.beforeRawSha256.equals(text(capture,"before_dom_sha256"))
                &&stability.afterRawSha256.equals(text(capture,"dom_sha256"))
                &&WebDomCanonical.sha256(stability.evidence()).equals(text(capture,"dom_stability_sha256"))
                &&Boolean.valueOf(stability.rawEqual).equals(capture.get("raw_dom_equal"))
                &&stability.comparisonScope.equals(text(capture,"comparison_scope")),
                "complete independent raw-pair/scope replay differs");
        if(purpose.flight!=null)need(stability.rawEqual&&WebDomStability.FULL_SCOPE.equals(stability.comparisonScope),
                "flight still requires the complete original raw equality predicate");
        Object navigation=capture.get("observed_link_navigation");
        if(navigation!=JSONObject.NULL){
            need(purpose.shopping!=null&&navigation instanceof JSONObject,"only a typed product-link navigation record is supported");
            JSONObject observed=(JSONObject)navigation;
            WebObservedNavigation.requireNavigationRecordShape(observed);
            JSONObject arm=observed.getJSONObject("arm");
            need(WebEvidenceBinding.sha256(binding).equals(text(arm,"binding_sha256"))
                    &&text(binding,"task_id").equals(text(arm,"task_id"))
                    &&text(binding,"controller_session_nonce").equals(text(arm,"controller_session_nonce"))
                    &&text(binding,"storage_profile_name").equals(text(arm,"storage_profile_name"))
                    &&text(capture,"webview_instance").equals(text(arm,"webview_instance"))
                    &&number(capture,"actual_window_id")==number(arm,"actual_window_id")
                    &&number(capture,"display_id")==number(arm,"display_id")
                    &&number(arm,"navigation_epoch")<=number(capture,"navigation_epoch")
                    &&number(arm,"armed_elapsed_ms")<=started,
                    "observed navigation record belongs to another lease/window/instance or future ARM");
            // This preserves partial/cancelled producer facts. It grants no
            // navigation success: the private expected ARM and original native
            // ActionOutcome/time bracket are replayed separately by the domain.
        }
        need(WebNativeGeometry.read(capture,dom,WebEvidenceJson.integer(callback,"actual_display_id"),
                WebEvidenceJson.integer(callback,"actual_window_id"),stability)!=null,"formal capture requires actual native geometry");
        WebStorageEvidence.requireCapture(binding,evidence.getJSONObject("storage_isolation"),started,ended);
        return new WebEvidenceReceipt(callback,original,capture.toString(),domRaw,false,false,stability,null);
    }

    private static String purposeOrigin(WebTaskPurpose purpose,String value)throws Exception{
        need(purpose!=null,"original recognized page purpose required");
        if(purpose.flight!=null)return officialOrigin(value);
        WebSitePolicy policy=WebSitePolicy.forShopping(purpose.shopping);
        need(policy.sha256.equals(purpose.sitePolicySha256)&&policy.allowsMainFrame(value),
                "URL is outside this lease's compiled public-product route");
        return policy.origin;
    }
    static String officialOrigin(String value)throws Exception{
        need(value!=null&&value.length()<=4096,"URL budget");URI uri=new URI(value);
        need("https".equals(uri.getScheme())&&"m.csair.com".equals(uri.getHost())&&uri.getRawUserInfo()==null
                &&(uri.getPort()==-1||uri.getPort()==443)&&!uri.isOpaque(),"only the fixed official HTTPS origin is covered");
        return "https://m.csair.com";
    }
    private static void domain(JSONObject callback,JSONObject binding)throws Exception{
        need(number(callback,"actual_display_id")==number(binding.getJSONObject("background"),"display_id")
                &&number(callback,"actual_display_id")>0&&number(callback,"actual_window_id")>=0
                &&WebEvidenceProtocol.uuid(text(callback,"webview_instance"))&&number(callback,"navigation_epoch")>=0,"actual bound view identity required");
    }
    private static void requireOriginalRequest(JSONObject evidence,String raw)throws Exception{
        need(raw.equals(text(evidence,"request_json_utf8"))&&WebEvidenceJson.sha(raw).equals(text(evidence,"request_sha256")),
                "raw original request differs");
    }
    private static void requireRequestAndBinding(JSONObject evidence,String raw,JSONObject binding)throws Exception{
        need(raw.equals(text(evidence,"request_json_utf8"))&&WebEvidenceJson.sha(raw).equals(text(evidence,"request_sha256"))
                &&same(binding,evidence.getJSONObject("binding"))&&WebEvidenceBinding.sha256(binding).equals(text(evidence,"binding_sha256")),
                "raw request/immutable binding differs");
    }
    static boolean same(Object a,Object b)throws Exception{return WebEvidenceBinding.canonical(a).equals(WebEvidenceBinding.canonical(b));}
    static String decode(byte[] bytes)throws Exception{return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();}
    static void exact(JSONObject o,String...keys)throws Exception{WebEvidenceJson.keys(o,new HashSet<String>(Arrays.asList(keys)));}
    static String text(JSONObject o,String k)throws Exception{return WebEvidenceJson.text(o,k);}
    static long number(JSONObject o,String k)throws Exception{return WebEvidenceJson.number(o,k);}
    static String nullableText(JSONObject o,String k)throws Exception{return o.get(k)==JSONObject.NULL?null:text(o,k);}
    static void need(boolean ok,String why){WebEvidenceJson.need(ok,why);}
}
