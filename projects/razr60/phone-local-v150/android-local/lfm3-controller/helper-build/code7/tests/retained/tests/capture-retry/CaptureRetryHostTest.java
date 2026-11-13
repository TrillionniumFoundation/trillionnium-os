package org.trillionnium.hepta.webhelper;

import android.os.SystemClock;
import android.webkit.ValueCallback;
import android.webkit.WebView;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import org.json.JSONArray;
import org.json.JSONObject;

/** Actual capture classes with deterministic Android callback doubles. No phone, JS engine or Mi result. */
public final class CaptureRetryHostTest {
    interface Checked {void run()throws Exception;}
    static int cases,assertions;
    static final ArrayList<String> names=new ArrayList<String>();
    static File asset;
    static void need(boolean ok,String reason){assertions++;if(!ok)throw new AssertionError(reason);}
    static void run(String name,Checked test)throws Exception{test.run();cases++;names.add(name);}
    static void rejects(Checked action)throws Exception{boolean rejected=false;try{action.run();}catch(Exception expected){rejected=true;}need(rejected,"expected rejection");}
    static String dom(String text)throws Exception{
        JSONObject node=WebScopedNavigationHostTest.node("0","html","",new JSONArray(new int[]{0,0,100,100}));
        return new JSONObject().put("schema","hepta.fixed-top-document-dom.v4")
            .put("href","https://www.mi.com/shop/search?keyword=AX3000T").put("origin","https://www.mi.com")
            .put("ready_state","complete").put("truncated",false).put("truncation_reasons",new JSONArray())
            .put("visited",1).put("nodes",new JSONArray().put(node)).put("synthetic_text",text).toString();}
    static final class Lease implements OfficialPageCapture.LeaseGuard {
        JSONObject value;boolean active=true;
        Lease(boolean manual)throws Exception{
            value=new JSONObject().put("schema",manual?"hepta.web-helper.unbound-diagnostic.v2":"hepta.web-helper.binding.v4")
                    .put("task_id",manual?JSONObject.NULL:"synthetic-task").put("display_id",0)
                    .put("actor","manual_native_open").put("grants_task_authority",false)
                    .put("site_policy_id","synthetic-fixed-mi");
        }
        public void requireActive(){if(!active)throw new IllegalStateException("synthetic lease changed");}
        public int expectedDisplayId(){return 0;}
        public JSONObject binding(){return value;}
    }
    static final class Sink implements OfficialPageCapture.Callback {
        int success,failed,pairs;JSONObject result;String reason;DomInstabilityEvidence.Pair pair;boolean throwOnMismatch;
        public void captured(JSONObject actual){success++;result=actual;}
        public void failed(String why){failed++;reason=why;}
        public void unstable(DomInstabilityEvidence.Pair actual)throws Exception{pairs++;pair=actual;if(throwOnMismatch)throw new Exception("synthetic diagnostic exception");}
    }
    static final class Fixture {
        final WebView view;final Lease lease;final PageSitePolicy capturePolicy=new PageSitePolicy();final OfficialPageCapture capture;final Sink sink=new Sink();
        Fixture(boolean manual)throws Exception{
            SystemClock.now=1000;android.os.Looper.current=android.os.Looper.getMainLooper();
            view=new WebView(asset);lease=new Lease(manual);
            capture=new OfficialPageCapture(view,lease,"12345678-1234-1234-1234-123456789abc",capturePolicy);
            view.client.onPageCommitVisible(view,view.url);
        }
        void start(){capture.capture(repeat('a',64),10000,sink);}
        void js(String raw){need(!view.javascript.isEmpty(),"one actual pending JavaScript callback");view.javascript.remove().onReceiveValue(JSONObject.quote(raw));}
        void visual(){need(!view.visuals.isEmpty(),"one actual visual callback");WebView.Visual v=view.visuals.remove();v.callback.onComplete(v.id);}
        void pair(String before,String after){js(before);visual();js(after);}
        void failedOnce(){need(sink.failed==1&&sink.success==0&&capture.pendingCaptureCount()==0,"one terminal failure, no success");}
    }
    static String repeat(char c,int n){char[] a=new char[n];java.util.Arrays.fill(a,c);return new String(a);}
    static JSONObject context()throws Exception{
        return new JSONObject().put("binding",new Lease(true).value).put("display_id",0).put("attempt_index",1)
                .put("started_elapsed_ms",1000).put("mismatch_elapsed_ms",1050).put("deadline_elapsed_ms",4000)
                .put("current_native_url","https://www.mi.com/shop/search?keyword=AX3000T")
                .put("geometry_samples",new JSONArray().put(new JSONObject()).put(new JSONObject()).put(new JSONObject()).put(new JSONObject()));
    }
    public static void main(String[] args)throws Exception{
        need(args.length==2,"asset/result args");asset=new File(args[0]);final String A=dom("A"),B=dom("B"),C=dom("C");
        run("unchanged_complete_dom_explicit_wire4_success_shape",()->{
            Fixture f=new Fixture(true);f.start();f.pair(A,A);
            need(f.sink.success==1&&f.sink.failed==0&&f.sink.pairs==0,"first pair succeeds");
            JSONObject r=f.sink.result;need("hepta.owned-webview-origin-dom.v2".equals(r.getString("schema")),"explicit wire4 schema");
            need(r.getString("dom_raw_utf8").equals(A)&&!r.getBoolean("business_verified"),"raw whole DOM no business");
            need(r.getJSONObject("capture_geometry").getJSONArray("samples").length()==4,"exact four samples");
            need(r.getJSONObject("capture_geometry").getBoolean("dom_equal_across_visual_callback"),"full equality required");
        });
        run("mismatch_then_stable_same_absolute_deadline",()->{
            Fixture f=new Fixture(true);f.start();f.pair(A,B);
            need(f.sink.success==0&&f.sink.failed==0&&f.sink.pairs==1,"mismatch does not succeed");
            f.view.advance(1100);f.pair(C,C);
            need(f.sink.success==1&&f.sink.failed==0&&f.sink.pairs==1,"second complete pair succeeds");
            need(f.sink.result.getLong("started_elapsed_ms")==1000&&f.sink.result.getLong("visual_request_id")==1100,"start not reset, actual final visual id");
            need(new JSONObject(f.sink.pair.contextRaw).getLong("deadline_elapsed_ms")==4000,"original three-second deadline");
        });
        run("late_old_javascript_callback_cannot_touch_new_attempt",()->{
            Fixture f=new Fixture(true);f.start();f.js(A);f.visual();
            ValueCallback<String> old=f.view.javascript.remove();old.onReceiveValue(JSONObject.quote(B));
            f.view.advance(1100);old.onReceiveValue("not JSON");
            need(f.sink.failed==0&&f.view.javascript.size()==1,"stale malformed callback ignored");
            f.pair(C,C);need(f.sink.success==1,"current attempt succeeds");
        });
        run("late_old_visual_callback_cannot_touch_new_attempt",()->{
            Fixture f=new Fixture(true);f.start();f.js(A);WebView.Visual old=f.view.visuals.remove();old.callback.onComplete(old.id);f.js(B);
            f.view.advance(1100);old.callback.onComplete(old.id+999);
            need(f.sink.failed==0&&f.view.javascript.size()==1,"stale wrong visual id ignored");
            f.pair(C,C);need(f.sink.success==1,"current pair still succeeds");
        });
        run("three_mismatches_are_bounded_no_fourth_read",()->{
            Fixture f=new Fixture(true);f.start();f.pair(A,B);f.view.advance(1100);f.pair(B,C);f.view.advance(1200);f.pair(C,A);
            f.failedOnce();need(f.view.scripts.size()==6&&f.sink.pairs==1,"three pairs and one first mismatch");
            f.view.advance(4000);need(f.sink.failed==1&&f.view.scripts.size()==6,"deadline cannot duplicate failure");
        });
        run("original_deadline_not_reset_by_retry",()->{
            Fixture f=new Fixture(true);f.start();f.pair(A,B);f.view.advance(1100);f.js(A);
            f.view.advance(4000);f.failedOnce();f.visual();
            need(f.view.javascript.isEmpty()&&f.sink.success==0,"late visual cannot reopen deadline");
        });
        run("caller_shorter_deadline_is_preserved",()->{
            Fixture f=new Fixture(true);f.capture.capture(repeat('a',64),1150,f.sink);f.pair(A,B);f.view.advance(1100);f.js(A);
            f.view.advance(1150);f.failedOnce();f.visual();need(f.sink.success==0,"caller deadline remains exact");
        });
        run("no_retry_when_delay_would_reach_deadline",()->{
            Fixture f=new Fixture(true);f.capture.capture(repeat('a',64),1100,f.sink);f.pair(A,B);f.failedOnce();
            need(f.view.scripts.size()==2,"insufficient remaining interval denies retry");
        });
        run("navigation_change_during_read_denies_without_retry",()->{
            Fixture f=new Fixture(true);f.start();f.js(A);f.view.client.onPageStarted(f.view,f.view.url,null);f.failedOnce();f.visual();
            need(f.view.scripts.size()==1,"no JS2 after navigation");
        });
        run("geometry_change_before_retry_denies_without_new_read",()->{
            Fixture f=new Fixture(true);f.start();f.pair(A,B);f.view.scrollY=1;f.view.advance(1100);f.failedOnce();
            need(f.view.scripts.size()==2,"original geometry preserved across attempts");
        });
        run("window_change_denies",()->{Fixture f=new Fixture(true);f.start();f.view.window++;f.js(A);f.failedOnce();need(f.view.visuals.isEmpty(),"no visual after window changed");});
        run("display_change_denies",()->{Fixture f=new Fixture(true);f.start();f.view.display.id=7;f.js(A);f.failedOnce();});
        run("lease_binding_change_denies",()->{Fixture f=new Fixture(true);f.start();f.lease.value.put("different",1);f.js(A);f.failedOnce();});
        run("lease_inactive_denies",()->{Fixture f=new Fixture(true);f.start();f.lease.active=false;f.js(A);f.failedOnce();});
        run("current_url_change_denies",()->{Fixture f=new Fixture(true);f.start();f.view.url="https://www.mi.com/shop/search?keyword=OTHER";f.js(A);f.failedOnce();});
        run("scale_callback_aborts_old_attempt",()->{Fixture f=new Fixture(true);f.start();f.view.client.onScaleChanged(f.view,1,2);f.failedOnce();f.js(A);need(f.view.visuals.isEmpty(),"late JS inert");});
        run("wrong_current_visual_id_denies",()->{Fixture f=new Fixture(true);f.start();f.js(A);WebView.Visual v=f.view.visuals.remove();v.callback.onComplete(v.id+1);f.failedOnce();need(f.view.scripts.size()==1,"wrong id not retry");});
        run("malformed_dom_is_not_retried",()->{Fixture f=new Fixture(true);f.start();f.js("{");f.failedOnce();need(f.view.scripts.size()==1,"malformed DOM no retry");});
        run("loading_dom_is_not_retried",()->{Fixture f=new Fixture(true);f.start();f.js(new JSONObject(A).put("ready_state","loading").toString());f.failedOnce();});
        run("wrong_dom_url_is_not_retried",()->{Fixture f=new Fixture(true);f.start();f.js(new JSONObject(A).put("href","https://www.mi.com/other").toString());f.failedOnce();});
        run("oversized_dom_is_not_retried",()->{Fixture f=new Fixture(true);f.start();f.js(repeat('x',1024*1024+1));f.failedOnce();});
        run("formal_mismatch_never_emits_manual_pair",()->{
            Fixture f=new Fixture(false);f.start();f.pair(A,B);need(f.sink.pairs==0,"formal FD has no manual diagnostic callback");
            f.view.advance(1100);f.pair(C,C);need(f.sink.success==1&&f.sink.pairs==0,"formal success still stable whole DOM");
        });
        run("diagnostic_exception_fails_no_retry",()->{
            Fixture f=new Fixture(true);f.sink.throwOnMismatch=true;f.start();f.pair(A,B);f.failedOnce();
            need(f.view.scripts.size()==2,"diagnostic exception cannot succeed");
        });
        run("retry_schedule_rejection_fails",()->{
            Fixture f=new Fixture(true);f.start();f.js(A);f.visual();f.view.acceptPost=false;f.js(B);f.failedOnce();
        });
        run("abort_while_waiting_retry_retires_ticket",()->{
            Fixture f=new Fixture(true);f.start();f.pair(A,B);f.capture.retire();f.failedOnce();f.view.advance(1100);
            need(f.view.scripts.size()==2,"retired queued retry cannot read");
        });
        run("old_ticket_timeout_cannot_abort_next_capture",()->{
            Fixture f=new Fixture(true);f.start();f.pair(A,A);f.view.advance(1100);
            Sink next=new Sink();f.capture.capture(repeat('b',64),10000,next);f.view.advance(4000);
            need(next.failed==0&&f.capture.pendingCaptureCount()==1,"old timeout inert for new ticket");
            f.pair(C,C);need(next.success==1&&next.failed==0,"new ticket still within own deadline");
        });
        run("budget_identity_deadline_and_terminal",()->{
            CaptureReadBudget b=new CaptureReadBudget(10,1000),other=new CaptureReadBudget(10,1000);
            CaptureReadBudget.Attempt a=b.begin(10),foreign=other.begin(10);
            need(!b.owns(foreign),"foreign token rejected");rejects(()->b.requireActive(foreign,10));
            need(b.retryAfterDomMismatch(a,20),"one retry permitted");need(!b.owns(a),"old token retired");
            rejects(()->b.begin(119));CaptureReadBudget.Attempt next=b.begin(120);b.complete(next,120);
            need(!b.owns(next),"successful token retired");rejects(()->b.begin(121));
        });
        run("budget_reversed_clock_overflow_and_expiry",()->{
            rejects(()->new CaptureReadBudget(Long.MAX_VALUE-1,Long.MAX_VALUE));rejects(()->new CaptureReadBudget(10,10));
            CaptureReadBudget b=new CaptureReadBudget(100,500);CaptureReadBudget.Attempt a=b.begin(100);
            rejects(()->b.requireActive(a,99));rejects(()->b.requireActive(a,500));b.cancel();need(!b.owns(a),"cancel token retired");
        });
        run("manual_pair_exact_raw_hash_and_false_authority",()->{
            DomInstabilityEvidence.Pair pair=new DomInstabilityEvidence.Pair(context(),A,B);
            JSONObject[] r=pair.records(repeat('d',64),"synthetic host test",new JSONObject().put("synthetic_profile","not-device").toString());
            need(r.length==2&&r[0].getString("dom_raw_utf8").equals(A)&&r[1].getString("dom_raw_utf8").equals(B),"both exact raw strings");
            for(JSONObject q:r){need("hepta.web-helper.manual-dom-instability.v2".equals(q.getString("schema")),"diagnostic schema");
                for(String key:new String[]{"capture_succeeded","dom_equal_across_visual_callback","grants_task_authority","grants_action_authority","formal_fd_evidence","business_verified","pixel_equality_claimed","all_visible_semantics_verified"})
                    need(Boolean.FALSE.equals(q.get(key)),"false diagnostic field "+key);
                need(q.has("task_id")&&q.isNull("task_id")&&q.getBoolean("diagnostic_unbound"),"no task/lease authority");
            }
            need(r[0].getString("before_dom_sha256").equals(r[1].getString("before_dom_sha256"))
                    &&!r[0].getString("before_dom_sha256").equals(r[0].getString("after_dom_sha256")),"distinct exact pair hashes");
        });
        run("pair_rejects_formal_binding_and_fake_authority",()->{
            JSONObject c=context();c.put("binding",new Lease(false).value);rejects(()->new DomInstabilityEvidence.Pair(c,A,B));
            JSONObject d=context();d.getJSONObject("binding").put("grants_task_authority",true);rejects(()->new DomInstabilityEvidence.Pair(d,A,B));
        });
        run("pair_rejects_wrong_type_bounds_and_expired_time",()->{
            JSONObject c=context().put("display_id","0");rejects(()->new DomInstabilityEvidence.Pair(c,A,B));
            JSONObject d=context().put("attempt_index",4);rejects(()->new DomInstabilityEvidence.Pair(d,A,B));
            JSONObject e=context().put("mismatch_elapsed_ms",4000);rejects(()->new DomInstabilityEvidence.Pair(e,A,B));
            JSONObject f=context().put("geometry_samples",new JSONArray());rejects(()->new DomInstabilityEvidence.Pair(f,A,B));
        });
        run("pair_rejects_equal_oversized_and_changed_url",()->{
            rejects(()->new DomInstabilityEvidence.Pair(context(),A,A));
            rejects(()->new DomInstabilityEvidence.Pair(context(),A,repeat('x',1024*1024+1)));
            rejects(()->new DomInstabilityEvidence.Pair(context(),A,new JSONObject(B).put("href","https://else.invalid/").toString()));
        });
        run("pair_record_overflow_and_metadata_error_cannot_promote",()->{
            String raw=dom(repeat('"',510000));DomInstabilityEvidence.Pair big=new DomInstabilityEvidence.Pair(context(),raw,B);
            rejects(()->big.records(repeat('d',64),"synthetic",new JSONObject().put("padding",repeat('s',65000)).toString()));
            DomInstabilityEvidence.Pair pair=new DomInstabilityEvidence.Pair(context(),A,B);
            rejects(()->pair.records("bad","synthetic","{}"));rejects(()->pair.records(repeat('d',64),"synthetic","not JSON"));
        });
        run("wire4_scope_capture_retains_both_raw_and_complete_diff",()->{
            Fixture f=new Fixture(true);f.capturePolicy.id=org.trillionnium.hepta.webprotocol.WebMiActionRegion.POLICY;
            JSONObject before=WebScopedNavigationHostTest.dom(),after=WebScopedNavigationHostTest.changedOutside(before);
            f.start();f.pair(before.toString(),after.toString());
            need(f.sink.success==1&&f.sink.failed==0&&f.sink.pairs==0,"valid scoped pair succeeds without mismatch retry");
            JSONObject result=f.sink.result;
            need(!result.getBoolean("raw_dom_equal")&&result.getString("comparison_scope").equals(
                    org.trillionnium.hepta.webprotocol.WebDomStability.REGION_SCOPE),"scope explicitly differs from raw equality");
            need(result.getString("before_dom_raw_utf8").equals(before.toString())
                    &&result.getString("dom_raw_utf8").equals(after.toString()),"both complete raw DOMs retained");
            need(result.getJSONObject("dom_stability").getJSONArray("all_json_differences").length()==2,"all exact differences retained");
            need(!result.getJSONObject("capture_geometry").getBoolean("dom_equal_across_visual_callback"),"geometry does not claim raw equality");
            f.capture.requireArmSource(result);
        });
        run("wire4_arm_source_native_geometry_and_freshness_rechecked",()->{
            Fixture f=new Fixture(true);f.start();f.pair(A,A);JSONObject actual=f.sink.result;
            f.capture.requireArmSource(actual);f.view.scrollY=1;rejects(()->f.capture.requireArmSource(actual));
            f.view.scrollY=0;f.view.advance(3501);rejects(()->f.capture.requireArmSource(actual));
        });
        run("wire4_navigation_gate_applies_to_request_history_and_commit",()->{
            Fixture f=new Fixture(true);
            f.capture.setNavigationGate(new OfficialPageCapture.NavigationGate(){
                public boolean allowMainFrameRequest(String url,String method){return false;}
                public boolean allowMainFrameStarted(String url){return false;}
                public boolean allowHistoryOrCommitUrl(String url){return false;}
            });
            android.webkit.WebResourceRequest request=new android.webkit.WebResourceRequest(){
                public boolean isForMainFrame(){return true;}
                public android.net.Uri getUrl(){return new android.net.Uri("https://www.mi.com/shop/buy?product_id=1&cfrom=search");}
                public String getMethod(){return "GET";}
            };
            need(f.view.client.shouldOverrideUrlLoading(f.view,request),"unarmed main-frame request blocked");
            f.view.client.onPageStarted(f.view,f.view.url,null);f.view.client.onPageCommitVisible(f.view,f.view.url);
            f.start();f.failedOnce();need(f.view.scripts.isEmpty(),"invalid commit does not capture");
        });
        JSONObject out=new JSONObject().put("schema","hepta.capture-retry-host-result.v1").put("all_pass",true)
                .put("cases",cases).put("assertions",assertions).put("case_names",new JSONArray(names))
                .put("actual_production_capture_classes",true).put("android_callbacks","deterministic host doubles")
                .put("javascript_executed",false).put("phone_tested",false).put("actual_mi_dom_seen",false)
                .put("business_verified",false);
        Files.write(Paths.get(args[1]),(out.toString()+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println(out.toString());
    }
}
