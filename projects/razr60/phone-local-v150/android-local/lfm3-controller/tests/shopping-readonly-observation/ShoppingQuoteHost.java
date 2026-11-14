package org.trillionnium.hepta.local;

import android.graphics.Rect;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.json.*;
import org.trillionnium.hepta.webprotocol.*;

/** Actual immutable DOM content, explicitly synthetic native/IPC service boundaries.
 * No historical retained AX is promoted to a complete native graph or real IPC proof. */
public final class ShoppingQuoteHost {
    interface Checked { void run() throws Exception; }
    static int cases,assertions;static final JSONArray names=new JSONArray();
    static JSONObject firstRaw,lastRaw,callbackTemplate,binding,selection;
    static WebTaskPurpose purpose;static TaskAuthorization authorization;
    static String task,owner,generation;
    static final String TARGET="0/0/0/0",REC="0/0/1";
    static final long BASE=892250000L;
    static void check(boolean ok,String reason){assertions++;if(!ok)throw new AssertionError(reason);}
    static void test(String name,Checked x)throws Exception{x.run();cases++;names.put(name);}
    static void rejects(Checked x)throws Exception{
        boolean bad=false;try{x.run();}catch(IllegalArgumentException|IllegalStateException|JSONException|java.io.IOException expected){bad=true;}
        check(bad,"expected production rejection");
    }
    static JSONObject obj(JSONObject x){return new JSONObject(x.toString());}
    static JSONArray arr(JSONArray x){return new JSONArray(x.toString());}
    static String id(long n){return String.format(java.util.Locale.ROOT,"%032x",n);}
    static String nonce(long n){return String.format(java.util.Locale.ROOT,"%064x",n);}
    static JSONObject read(Path p)throws Exception{return new JSONObject(new String(Files.readAllBytes(p),StandardCharsets.UTF_8));}
    static JSONObject nativeRow(String path,String cls,String parent,int children,int[] box,String text,String desc,String view,boolean click){
        return ShoppingReadonlyObservationHost.n(path,cls,parent,children,box,text,desc,view,click);
    }
    static JSONArray graph(boolean after)throws Exception{
        int[] web=WebNativeGeometry.read(firstRaw.getJSONObject("capture"),
                WebEvidenceJson.parseDom(firstRaw.getJSONObject("capture").getString("dom_raw_utf8")),36,3679).bounds;
        return new JSONArray()
            .put(nativeRow("0","android.widget.FrameLayout","",1,new int[]{0,0,720,1280},"","","",false))
            .put(nativeRow("0/0","android.webkit.WebView","android.widget.FrameLayout",2,web,"","","",false))
            .put(nativeRow("0/0/0","android.view.View","android.webkit.WebView",1,new int[]{0,280,720,600},"","","",false))
            .put(nativeRow(TARGET,"android.view.View","android.view.View",3,new int[]{0,296,171,546},"","Xiaomi路由器AX3000T 白色 159元 199元","",true))
            .put(nativeRow(TARGET+"/0","android.widget.Image","android.view.View",0,new int[]{0,296,171,430},"","","",false))
            .put(nativeRow(TARGET+"/1","android.widget.TextView","android.view.View",0,new int[]{8,440,162,460},"Xiaomi路由器AX3000T 白色","","",true))
            .put(nativeRow(TARGET+"/2","android.view.View","android.view.View",2,new int[]{20,480,150,520},"","","",false))
            .put(nativeRow(TARGET+"/2/0","android.widget.TextView","android.view.View",0,new int[]{20,480,70,520},"159元","","",false))
            .put(nativeRow(TARGET+"/2/1","android.view.View","android.view.View",0,new int[]{80,480,150,520}," 199元","","",false))
            .put(nativeRow(REC,"android.view.View","android.webkit.WebView",1,new int[]{0,650,711,827},"","","J_recommend_search",false))
            .put(nativeRow(REC+"/0","android.widget.TextView","android.view.View",0,new int[]{100,660,200,800},
                    after?"明确的测试推荐B":"明确的测试推荐A","","",false));
    }
    static PhoneObservation frame(long time,JSONArray rows)throws Exception{
        List<PhoneObservation.Node> nodes=new ArrayList<PhoneObservation.Node>();int chars=0;
        for(int i=0;i<rows.length();i++){
            JSONObject n=rows.getJSONObject(i);JSONArray box=n.getJSONArray("bounds");
            String text=n.getString("text"),desc=n.getString("description");chars+=text.length()+desc.length();
            nodes.add(new PhoneObservation.Node("n"+i,n.getString("package"),n.getString("class"),n.getString("view_id"),text,desc,
                new Rect(box.getInt(0),box.getInt(1),box.getInt(2),box.getInt(3)),n.getBoolean("clickable"),
                n.getBoolean("editable"),n.getBoolean("scrollable"),n.getBoolean("enabled"),n.getBoolean("focused"),n.getBoolean("password"),
                ObservedChildText.notApplicable(),ObservedScrollActions.observed(Collections.<String>emptyList()),ObservedImeEnter.UNKNOWN,null,false,
                WebDomCanonical.sha256(n),n.getString("path"),n.getString("parent_class")));
        }
        String tree=WebDomCanonical.sha256(rows);ObservationState state=new ObservationState(tree,ImeVisibility.HIDDEN);
        return new PhoneObservation(id(time),WebEvidenceProtocol.HELPER_PACKAGE,time,720,1280,0,3679,new Rect(0,0,720,1280),null,
            WebEvidenceJson.sha("explicit synthetic screen"),WebEvidenceJson.sha(state.fingerprintInput()),state,
            ObservedWindowMetadata.observed(new int[]{0,0,720,1280},"android.widget.FrameLayout",1,36,new int[]{0,0,720,1280},""),
            false,nodes,generation,WebEvidenceProtocol.HELPER_PACKAGE,Collections.singletonList(WebEvidenceProtocol.HELPER_PACKAGE),
            new PhoneObservation.CollectionStats(1024,512,6144,rows.length(),rows.length(),chars,0,0,0,0,10),selection,purpose.ownerSha256);
    }
    static WebEvidenceReceipt receipt(JSONObject original,long at)throws Exception{
        JSONObject raw=obj(original),cap=raw.getJSONObject("capture"),request=new JSONObject(raw.getString("request_json_utf8"));
        JSONObject bind=obj(binding);String bindingSha=WebEvidenceBinding.sha256(bind),challenge=nonce(at);
        request.put("request_nonce",challenge).put("deadline_elapsed_ms",at+2500)
            .put("expected_webview_instance",cap.get("webview_instance")).put("expected_navigation_epoch",cap.get("navigation_epoch"));
        String requestRaw=request.toString();
        cap.put("binding",bind).put("challenge",challenge).put("started_elapsed_ms",at).put("ended_elapsed_ms",at+100);
        JSONArray samples=cap.getJSONObject("capture_geometry").getJSONArray("samples");
        for(int i=0;i<samples.length();i++)samples.getJSONObject(i).getJSONObject("native").put("sampled_elapsed_ms",at+i*25);
        raw.put("binding",bind).put("binding_sha256",bindingSha).put("controller_identity",bind.get("controller_identity"))
            .put("helper_identity",bind.get("helper_identity")).put("request_json_utf8",requestRaw).put("request_sha256",WebEvidenceJson.sha(requestRaw));
        byte[] bytes=raw.toString().getBytes(StandardCharsets.UTF_8);
        JSONObject cb=obj(callbackTemplate).put("request_nonce",challenge).put("binding_sha256",bindingSha)
            .put("raw_length",bytes.length).put("raw_sha256",WebEvidenceJson.sha(bytes));
        return WebEvidenceReceipt.verify(WebEvidenceProtocol.CAPTURE,requestRaw,bind,cb.toString(),bytes,10484,at-10,at+150);
    }
    static JSONObject windows(){
        JSONObject w=new JSONObject().put("window_id",3679).put("display_id",36).put("layer",0).put("type",1)
            .put("bounds",new JSONArray(new int[]{0,0,720,1280}));
        return new JSONObject().put("source","getWindowsOnAllDisplays_selected_display_metadata").put("display_id",36)
            .put("target_window_id",3679).put("target_layer",0).put("target_bounds",new JSONArray(new int[]{0,0,720,1280}))
            .put("windows",new JSONArray().put(w)).put("observed_upper_or_same_layer_overlap",false)
            .put("ime_window_observed",false).put("unreported_window_claimed",false);
    }
    static final class Sample {
        final PhoneObservation frame;final JSONArray rows;final WebEvidenceReceipt receipt;final JSONObject proof;
        final WebTaskDomain raw,domain;
        Sample(long at,boolean after,String change)throws Exception{
            rows=graph(after);
            if("ancestor".equals(change))ShoppingReadonlyObservationHost.nativeNode(rows,"0/0/0").put("description","synthetic ancestor change");
            if("target".equals(change))ShoppingReadonlyObservationHost.nativeNode(rows,TARGET).getJSONArray("bounds").put(0,1);
            frame=frame(at-50,rows);JSONObject actual=after?lastRaw:firstRaw;
            receipt=receipt(actual,at);
            WebEvidenceReceipt previous=receipt(actual,at-2000);
            PhoneObservation before=frame(at-2050,rows);
            proof=WebShoppingObservationStability.compareObservationBracket(task,before.toJson(),rows,frame.toJson(),rows,
                    previous.capture(),receipt.capture(),TARGET);
            proof.put("source","private_service_snapshot_and_live_complete_native_traversal")
                .put("original_target_obtained_before_graph_recycling",true).put("original_node_ref_identity_preserved",true)
                .put("actual_ancestor_chain_refreshed",true).put("two_interactive_window_reads_equal",true)
                .put("native_invocation_entered",false).put("first_ax_captured_elapsed_ms",before.capturedElapsedMillis)
                .put("last_ax_captured_elapsed_ms",frame.capturedElapsedMillis).put("source_retained_elapsed_ms",at-2060)
                .put("started_elapsed_ms",at+160).put("checked_elapsed_ms",at+170)
                .put("live_native_recheck",WebShoppingObservationStability.compareNative(rows,rows,TARGET))
                .put("interactive_windows_before",windows()).put("interactive_windows_after",windows());
            raw=WebTaskDomain.observed(task,purpose,authorization.bind(task),frame,receipt,binding);
            domain=raw.withShoppingReadQuote(purpose.shopping,frame,receipt,proof);
            check(domain.shopping.searchQuote!=null,"synthetic complete source produces a current quote");
        }
    }
    static NotesCompletionEvidence.Frame completion(PhoneObservation o){
        if(o==null)return null;
        java.util.List<NotesCompletionEvidence.Node> nodes=new java.util.ArrayList<NotesCompletionEvidence.Node>();
        for(PhoneObservation.Node n:o.nodes){
            String label=n.label();
            if(n.text.trim().isEmpty()&&n.description.trim().isEmpty()&&(n.childText.truncated||!"derived".equals(n.childText.status)))label="";
            nodes.add(new NotesCompletionEvidence.Node(n.id,n.packageName,n.text,label,n.viewId,n.inputTextSha256,
                    new int[]{n.bounds.left,n.bounds.top,n.bounds.right,n.bounds.bottom},n.editable,n.clickable,n.scrollable,n.enabled,n.password,n.childText,n.observedAppTreeSignature));
        }
        return new NotesCompletionEvidence.Frame(o.id,o.packageName,o.windowId,o.windowMetadata.displayId==null?-1:o.windowMetadata.displayId,
                o.backgroundGeneration,o.windowMetadata.type==null?-1:o.windowMetadata.type,"observed".equals(o.windowMetadata.status),o.nodesTruncated,nodes);
    }
    static ActionDecision done(Sample a)throws Exception{return ActionDecision.parse(new JSONObject().put("action","done")
        .put("observation_id",a.frame.id).put("package",WebEvidenceProtocol.HELPER_PACKAGE).put("status","success")
        .put("summary","explicit synthetic model outcome for production composition test").toString());}
    static TaskCompletionGate gate(Sample a){
        TaskCompletionGate g=new TaskCompletionGate(task,owner,authorization);g.observed(completion(a.frame));g.bindWebDomain(a.domain);return g;
    }
    static final class Flow {
        final Sample before,after;final TaskCompletionGate gate;final ActionDecision action;
        final String run=id(22);final WebShoppingQuote.Pending pending;
        Flow(Sample a,Sample b)throws Exception{
            before=a;after=b;gate=gate(a);action=done(a);
            pending=WebShoppingQuote.Pending.fromOutcome(gate,a.domain,action,run,true,false,false,a.receipt.ended+100,a.receipt.ended+101);
            check(pending!=null,"actual modeled accepted no-effect outcome is necessary");
            gate.action(1,run,action,true,false,false,completion(a.frame),completion(b.frame),null);
            gate.bindWebDomain(b.domain);
        }
        WebShoppingQuote.Completion proof()throws Exception{
            return pending.complete(gate,after.domain,action,run,before.frame,after.frame);
        }
        TaskCompletionGate.Check claim()throws Exception{
            return gate.successClaim(1,run,completion(after.frame),before.frame.treeSha256.equals(after.frame.treeSha256),proof());
        }
    }
    static final class Closed {
        final Flow flow;final Object lease=new Object();final TaskCompletionGate.WebCloseAttempt close;
        Closed(Sample a,Sample b,boolean known)throws Exception{
            flow=new Flow(a,b);check(flow.claim().verified,"typed quote passes only preclose gate");
            close=flow.gate.beginWebClose(lease,b.domain,task,b.domain.shopping.bindingSha,"normal");
            check(close!=null,"single bound ordinary close candidate");
            flow.gate.clearWebDomain();
            if(known)check(flow.gate.webCloseKnown(close,lease,task,b.domain.shopping.bindingSha,"closed",b.domain.instance,b.domain.epoch,
                b.domain.displayId,b.domain.windowId,WebEvidenceJson.sha("synthetic authenticated CLOSE")),"typed close match");
        }
        TaskCompletionGate.Check terminal(int change)throws Exception{
            return flow.gate.terminalWebCheck(lease,completion(flow.after.frame),authorization.bind(task).frame(),1,
                change==6?id(23):flow.run,true,change!=1,true,true,true,change==2,true,change!=3,
                Integer.valueOf(change==4?143:0),change!=5,task,id(30),WebEvidenceJson.sha("synthetic native worker receipt"));
        }
    }
    public static void main(String[] args)throws Exception{
        Path fixture=Paths.get(args[0]);firstRaw=read(fixture.resolve("raw-first.json"));lastRaw=read(fixture.resolve("raw-last.json"));
        callbackTemplate=new JSONObject(read(fixture.resolve("reply-first.json")).getString("callback_json_utf8"));
        binding=obj(firstRaw.getJSONObject("binding"));
        // The pinned original DOMs remain untouched. This peer/version boundary is
        // explicitly synthetic and follows the compiled protocol in this host run.
        binding.getJSONObject("helper_identity").put("version_code",WebEvidenceProtocol.HELPER_VERSION_CODE);
        firstRaw.getJSONObject("capture").put("binding",binding);
        task=binding.getString("task_id");owner=binding.getString("owner");purpose=WebTaskPurpose.requireBinding(binding);
        authorization=purpose.authorization;generation=binding.getJSONObject("background").getString("generation");
        JSONObject background=read(fixture.resolve("ax-first.json")).getJSONObject("observation").getJSONObject("background_session");
        selection=obj(background);selection.remove("generation");selection.remove("display_id");
        Sample a=new Sample(BASE,false,null),b=new Sample(BASE+6000,true,null);
        test("actual_DOM_card_values_project_to_explicit_current_quote",()->{
            Map<String,Object> r=b.domain.resultRecord();
            check("Xiaomi路由器AX3000T 白色".equals(r.get("model_raw"))&&"159".equals(r.get("amount_decimal")),"actual same-card model and current amount");
            check("CNY".equals(r.get("currency"))&&"元".equals(r.get("currency_raw")),"observed CNY suffix");
            check("199".equals(r.get("comparison_amount_decimal"))&&Boolean.FALSE.equals(r.get("detail_price_verified"))
                &&Boolean.FALSE.equals(r.get("lowest_price_verified"))&&Boolean.FALSE.equals(r.get("order_completed")),"scope remains displayed card only");
            check("https://www.mi.com/shop/buy?product_id=1230803766&cfrom=search".equals(r.get("official_product_link")),"actual observed official link");
            check(b.domain.promptEvidence().containsKey("current_search_card_quote")&&b.domain.resultReady(),"current result and model projection wired");
            b.domain.requireCurrent(done(b));
        });
        test("ordinary_search_without_private_read_proof_stays_incomplete",()->{
            check(!a.raw.resultReady(),"mere card capture is not private native quote proof");
            rejects(()->a.raw.requireCurrent(done(a)));rejects(()->a.raw.withShoppingReadQuote(purpose.shopping,a.frame,a.receipt,null));
        });
        test("serialized_quote_record_cannot_replace_private_read_proof",()->rejects(()->a.raw.withShoppingReadQuote(purpose.shopping,a.frame,a.receipt,new JSONObject(a.domain.resultRecord()))));
        test("source_frame_and_capture_identity_are_not_interchangeable",()->{
            rejects(()->a.raw.withShoppingReadQuote(purpose.shopping,b.frame,a.receipt,a.proof));
            JSONObject p=obj(a.proof).put("last_capture_challenge",nonce(9));rejects(()->a.raw.withShoppingReadQuote(purpose.shopping,a.frame,a.receipt,p));
        });
        test("missing_live_target_or_ancestor_refresh_rejects_quote",()->{
            JSONObject p=obj(a.proof).put("actual_ancestor_chain_refreshed",false);rejects(()->a.raw.withShoppingReadQuote(purpose.shopping,a.frame,a.receipt,p));
            JSONObject q=obj(a.proof).put("original_node_ref_identity_preserved",false);rejects(()->a.raw.withShoppingReadQuote(purpose.shopping,a.frame,a.receipt,q));
        });
        test("live_native_target_change_and_window_overlap_reject_quote",()->{
            JSONObject p=obj(a.proof);ShoppingReadonlyObservationHost.nativeNode(p.getJSONObject("live_native_recheck").getJSONArray("after"),TARGET).getJSONArray("bounds").put(0,1);
            rejects(()->a.raw.withShoppingReadQuote(purpose.shopping,a.frame,a.receipt,p));
            JSONObject q=obj(a.proof);q.getJSONObject("interactive_windows_after").put("observed_upper_or_same_layer_overlap",true);
            rejects(()->a.raw.withShoppingReadQuote(purpose.shopping,a.frame,a.receipt,q));
        });
        test("fresh_capture_rechecks_same_native_quote_without_action_authority",()->{
            WebEvidenceReceipt fresh=receipt(firstRaw,BASE+1000);
            WebTaskDomain raw=WebTaskDomain.observed(task,purpose,authorization.bind(task),a.frame,fresh,binding);
            WebTaskDomain rechecked=raw.withRecheckedShoppingQuote(a.domain.shopping.searchQuote,a.frame,fresh);
            check(rechecked.resultReady()&&rechecked.pageKey.equals(a.domain.pageKey),"fresh same-frame semantics preserved");
            check(rechecked.clickIds.equals(a.raw.clickIds)&&rechecked.editValues.equals(a.raw.editValues),"read proof creates no extra action");
            check(Boolean.TRUE.equals(rechecked.resultRecord().get("fresh_capture_rechecked_against_same_native_frame")),"fresh boundary reported");
        });
        test("fresh_capture_cannot_rebind_quote_to_another_native_frame",()->rejects(()->b.raw.withRecheckedShoppingQuote(a.domain.shopping.searchQuote,b.frame,b.receipt)));
        test("rejected_dispatched_stale_or_absent_done_cannot_create_pending",()->{
            TaskCompletionGate g=gate(a);ActionDecision action=done(a);
            check(WebShoppingQuote.Pending.fromOutcome(g,a.domain,action,id(22),false,false,false,BASE+200,BASE+201)==null,"rejected");
            check(WebShoppingQuote.Pending.fromOutcome(g,a.domain,action,id(22),true,true,false,BASE+200,BASE+201)==null,"dispatched");
            check(WebShoppingQuote.Pending.fromOutcome(g,a.domain,action,id(22),true,false,true,BASE+200,BASE+201)==null,"stale");
            check(WebShoppingQuote.Pending.fromOutcome(g,a.domain,null,id(22),true,false,false,BASE+200,BASE+201)==null,"absent");
        });
        test("done_requires_exact_model_run_observation_and_capture_order",()->{
            rejects(()->WebShoppingQuote.Pending.fromOutcome(gate(a),a.domain,done(b),id(22),true,false,false,BASE+200,BASE+201));
            rejects(()->WebShoppingQuote.Pending.fromOutcome(gate(a),a.domain,done(a),"bad-run",true,false,false,BASE+200,BASE+201));
            rejects(()->WebShoppingQuote.Pending.fromOutcome(gate(a),a.domain,done(a),id(22),true,false,false,BASE-1,BASE));
        });
        test("final_read_compares_two_complete_frames_and_preserves_whole_tree_false",()->{
            Flow f=new Flow(a,b);WebShoppingQuote.Completion proof=f.proof();JSONObject e=proof.evidence();
            check(!a.frame.treeSha256.equals(b.frame.treeSha256),"synthetic outside recommendation really changes whole tree");
            check(e.getBoolean("complete_before_and_after_frames_included")&&e.getBoolean("all_non_recommendation_native_records_equal")
                    &&!e.getBoolean("whole_tree_equality_claimed")&&!e.getBoolean("business_verified"),"typed scope evidence is precise");
            TaskCompletionGate.Check claim=f.gate.successClaim(1,f.run,completion(b.frame),false,proof);
            check(claim.verified&&Boolean.FALSE.equals(claim.evidence.get("final_observation_stable"))
                &&Boolean.TRUE.equals(claim.evidence.get("search_quote_scope_verified")),"separate scoped completion does not rewrite old stable fact");
        });
        test("whole_tree_boolean_alone_cannot_complete_search_quote",()->{
            check(!gate(b).successClaim(1,id(22),completion(b.frame),true).verified,"even true requires typed quote final read");
            check(!gate(b).successClaim(1,id(22),completion(b.frame),false).verified,"false also requires proof");
        });
        test("changed_final_nonrecommendation_ancestor_is_rejected",()->{
            Sample changed=new Sample(BASE+7000,true,"ancestor");Flow f=new Flow(a,changed);rejects(()->f.proof());
        });
        test("changed_final_target_bounds_is_rejected",()->{
            Sample changed=new Sample(BASE+8000,true,"target");Flow f=new Flow(a,changed);rejects(()->f.proof());
        });
        test("pending_requires_same_action_object_run_and_gate",()->{
            Flow f=new Flow(a,b);rejects(()->f.pending.complete(f.gate,b.domain,done(a),f.run,a.frame,b.frame));
            Flow g=new Flow(a,b);rejects(()->g.pending.complete(g.gate,b.domain,g.action,id(23),a.frame,b.frame));
            Flow h=new Flow(a,b);rejects(()->h.pending.complete(gate(a),b.domain,h.action,h.run,a.frame,b.frame));
        });
        test("pending_is_consumed_even_when_final_validation_fails",()->{
            Flow f=new Flow(a,b);rejects(()->f.pending.complete(f.gate,b.domain,f.action,f.run,a.frame,a.frame));rejects(()->f.proof());
        });
        test("completion_is_one_shot_even_with_identical_serialized_evidence",()->{
            Flow f=new Flow(a,b);WebShoppingQuote.Completion p=f.proof();
            check(f.gate.successClaim(1,f.run,completion(b.frame),false,p).verified,"first use");
            check(!f.gate.successClaim(1,f.run,completion(b.frame),true,p).verified,"second use refused");
            rejects(()->f.proof());
        });
        test("completion_requires_current_domain_object_and_final_frame",()->{
            Flow f=new Flow(a,b);WebShoppingQuote.Completion p=f.proof();f.gate.bindWebDomain(a.domain);
            check(!f.gate.successClaim(1,f.run,completion(a.frame),false,p).verified,"old publication cannot consume new completion");
            Flow g=new Flow(a,b);check(!g.gate.successClaim(1,g.run,completion(a.frame),false,g.proof()).verified,"wrong frame");
        });
        test("waiting_or_retirement_clears_completion_authority",()->{
            Flow f=new Flow(a,b);WebShoppingQuote.Completion p=f.proof();f.gate.clearWebDomain();
            check(!f.gate.successClaim(1,f.run,completion(b.frame),false,p).verified,"no live domain");
        });
        test("ordinary_typed_close_and_native_cleanup_still_required",()->{
            Closed c=new Closed(a,b,true);TaskCompletionGate.Check result=c.terminal(0);
            check(result.verified,"synthetic complete original terminal chain");
            check(!c.terminal(0).verified,"terminal consumed once");
        });
        test("missing_unknown_or_wrong_typed_close_cannot_complete",()->{
            Closed c=new Closed(a,b,false);check(!c.terminal(0).verified,"unknown close");
            Closed d=new Closed(a,b,false);
            check(!d.flow.gate.webCloseKnown(d.close,d.lease,task,b.domain.shopping.bindingSha,"closed",b.domain.instance,b.domain.epoch+1,
                b.domain.displayId,b.domain.windowId,WebEvidenceJson.sha("synthetic close")),"wrong epoch");
            check(!d.terminal(0).verified,"bad close remains refused");
        });
        test("cleanup_cancel_exit_receipt_and_model_run_fail_closed",()->{
            for(int i=1;i<=6;i++)check(!new Closed(a,b,true).terminal(i).verified,"original terminal boundary "+i);
        });

        test("actual_Session_outcome_and_final_hook_produce_single_typed_proof",()->{
            TaskCompletionGate g=gate(a);WebShoppingSessionProjection s=new WebShoppingSessionProjection();s.initialize(a,g);
            s.outcome(a,true,false,false);check(s.hasPending(),"exact outcome method retains accepted done after its record");
            s.publish(b);WebShoppingQuote.Completion proof=s.finish(a,b.frame,BASE+20000);
            check(!s.hasPending()&&g.successClaim(1,s.modelRun,completion(b.frame),false,proof).verified,"exact final hook wires typed proof");
        });
        test("actual_Session_failed_outcome_record_cannot_publish_pending",()->{
            WebShoppingSessionProjection s=new WebShoppingSessionProjection();s.initialize(a,gate(a));s.writerFails();
            rejects(()->s.outcome(a,true,false,false));check(!s.hasPending(),"failed durable outcome record grants no pending continuation");
        });
        test("actual_Session_rejected_or_stale_done_has_no_continuation",()->{
            for(int i=0;i<2;i++){
                WebShoppingSessionProjection s=new WebShoppingSessionProjection();s.initialize(a,gate(a));
                s.outcome(a,i!=0,false,i==1);check(!s.hasPending(),"failed outcome cannot retain quote continuation");
                s.publish(b);check(s.finish(a,b.frame,BASE+20000)==null,"no continuation is created by final observation");
            }
        });
        test("actual_Session_cancel_before_or_after_persist_and_deadline_fail_closed",()->{
            for(int i=0;i<3;i++){
                WebShoppingSessionProjection s=new WebShoppingSessionProjection();s.initialize(a,gate(a));
                s.outcome(a,true,false,false);s.publish(b);
                if(i==0)s.cancel();else s.afterPersist(i==1,i==2?BASE+20000:0);
                rejects(()->s.finish(a,b.frame,BASE+20000));check(!s.hasPending(),"cancelled or expired continuation consumed");
            }
        });
        test("actual_Session_final_current_frame_mismatch_is_consumed",()->{
            WebShoppingSessionProjection s=new WebShoppingSessionProjection();s.initialize(a,gate(a));
            s.outcome(a,true,false,false);s.publish(b);rejects(()->s.finish(a,a.frame,BASE+20000));
            check(!s.hasPending()&&s.finish(a,b.frame,BASE+20000)==null,"mismatched final frame cannot retry a consumed done");
        });
        test("actual_Session_final_record_failure_cannot_return_typed_completion",()->{
            TaskCompletionGate g=gate(a);WebShoppingSessionProjection s=new WebShoppingSessionProjection();s.initialize(a,g);
            s.outcome(a,true,false,false);s.publish(b);s.writerFails();rejects(()->s.finish(a,b.frame,BASE+20000));
            check(!s.hasPending()&&!g.successClaim(1,s.modelRun,completion(b.frame),true).verified,"full-tree flag cannot rescue failed final record");
        });
        JSONObject result=new JSONObject().put("schema","hepta.shopping-quote-host.v1").put("all_pass",true)
            .put("cases",cases).put("assertions",assertions).put("passed",names)
            .put("actual_DOM_card_parsed",true).put("complete_native_and_IPC_boundaries","explicitly_synthetic")
            .put("phone_actions",0).put("actual_native_snapshot_or_ipc_verified",false).put("business_verified",false);
        System.out.println(result.toString());
    }
}
