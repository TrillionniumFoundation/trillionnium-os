package org.trillionnium.hepta.local;

import android.graphics.Rect;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebEvidenceBinding;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import org.trillionnium.hepta.webprotocol.WebTaskPurpose;
import org.trillionnium.hepta.webprotocol.WebObservedNavigation;

/**
 * Explicit synthetic v4 successor fixtures against the real receipt, provider, authority and
 * completion classes. URLs/SKUs/amounts below are TEST DATA, never observed Mi
 * pages, phone actions, Binder authentication, model runs or business results.
 */
public final class WebTaskCompositionHostTest {
    private static final String TASK=repeat("1",32),SESSION=repeat("3",64),RUN=repeat("9",32);
    private static final String PACKAGE=WebEvidenceProtocol.HELPER_PACKAGE;
    private static final String GENERATION="22345678-1234-1234-1234-123456789012";
    private static final String OWNER="查一下小米AX3000T的官网售价";
    private static final String FLIGHT="查一下2026年11月17日北京到上海的单程机票，1名成人";
    private static final String DETAIL=WebWire4SyntheticFactory.URL;
    private static final String MODEL="Xiaomi路由器AX3000T 白色",CARD_LABEL=MODEL+" 159元 199元";
    private static final List<String> cases=new ArrayList<String>();
    private static int assertions;
    private interface Work { void run()throws Exception; }
    private static void test(String name,Work body)throws Exception{body.run();cases.add(name);}
    private static void check(boolean ok,String message){assertions++;if(!ok)throw new AssertionError(message);}
    private static void rejects(Work body)throws Exception{
        boolean rejected=false;
        try{body.run();}catch(IllegalArgumentException|IllegalStateException|org.json.JSONException expected){rejected=true;}
        check(rejected,"expected exact production boundary rejection");
    }
    private static String repeat(String s,int n){StringBuilder b=new StringBuilder();while(n-->0)b.append(s);return b.toString();}
    private static JSONObject copy(JSONObject o)throws Exception{return new JSONObject(o.toString());}
    private static JSONObject oldFixture(String method)throws Exception{
        Method m=WebFlightEvidenceHostTest.class.getDeclaredMethod(method);m.setAccessible(true);
        try{return (JSONObject)m.invoke(null);}
        catch(InvocationTargetException e){if(e.getCause() instanceof Exception)throw (Exception)e.getCause();throw e;}
    }
    private static JSONObject binding(String owner)throws Exception{
        WebTaskPurpose p=WebTaskPurpose.fromOwner(owner);
        JSONObject original=oldFixture("binding");
        return WebEvidenceBinding.fromAttach(new JSONObject().put("task_id",TASK).put("controller_session_nonce",SESSION)
                .put("owner",owner).put("owner_sha256",p.ownerSha256).put("contract_sha256",p.contractSha256)
                .put("authorization",new JSONObject(p.authorization.evidence())).put("background",original.getJSONObject("background"))
                .put("controller_identity",original.getJSONObject("controller_identity"))
                .put("helper_identity",original.getJSONObject("helper_identity")));
    }
    private static JSONObject node(String path,String tag,String id,String text)throws Exception{
        JSONObject n=new JSONObject().put("path",path).put("parent_path","0".equals(path)?JSONObject.NULL:path.substring(0,path.lastIndexOf('/')))
                .put("tag",tag).put("id",id).put("text",text);
        for(String k:Arrays.asList("role","aria_label","item_type","item_prop","aria_hidden","aria_modal","aria_selected","aria_checked","aria_pressed"))
            n.put(k,"");
        for(String k:Arrays.asList("disabled","item_scope","hidden_attr","inert_attr"))n.put(k,false);
        n.put("visible_in_viewport",true);
        for(String k:Arrays.asList("href_raw","href_resolved","link_target"))n.put(k,JSONObject.NULL);
        return n;
    }
    private static JSONObject page(String url,JSONArray nodes)throws Exception{
        return oldFixture("dom").put("href",url).put("origin","https://www.mi.com").put("ready_state","complete")
                .put("truncated",false).put("truncation_reasons",new JSONArray()).put("nodes",nodes).put("visited",nodes.length());
    }
    private static JSONObject searchDom()throws Exception{
        // Retain explicit synthetic viewport facts required by the native geometry
        // parser, and use the complete scoped-card factory rather than a DOM ID.
        JSONObject d=oldFixture("dom"),card=WebWire4SyntheticFactory.dom();
        java.util.Iterator<String> keys=card.keys();while(keys.hasNext()){
            String key=keys.next();d.put(key,card.get(key));
        }
        return d;
    }
    private static JSONObject detailDom()throws Exception{
        JSONArray n=new JSONArray().put(node("0","html","","")).put(node("0/0","main","",""))
                .put(node("0/0/0","section","","").put("item_scope",true).put("item_type","https://schema.org/Product"))
                .put(node("0/0/0/0","h1","","AX3000T").put("item_prop","name"))
                .put(node("0/0/0/1","div","","").put("item_scope",true).put("item_type","https://schema.org/Offer").put("item_prop","offers"))
                .put(node("0/0/0/1/0","span","","199.00").put("item_prop","price"))
                .put(node("0/0/0/1/1","span","","CNY").put("item_prop","priceCurrency"));
        return page(DETAIL,n);
    }
    private static PhoneObservation.Node ax(String id,String view,String label,int y,boolean clickable,boolean enabled)throws Exception{
        return new PhoneObservation.Node(id,PACKAGE,"android.view.View",view,label,"",new Rect(200,y,550,y+60),
                clickable,false,false,enabled,false,false,ObservedChildText.notApplicable(),
                ObservedScrollActions.observed(Collections.<String>emptyList()),ObservedImeEnter.UNKNOWN,null,false,
                WebEvidenceJson.sha("synthetic AX "+id+" "+view+" "+label+" "+y));
    }
    private static PhoneObservation frame(String id,long clock,int window,List<PhoneObservation.Node> nodes)throws Exception{
        JSONObject selection=new JSONObject().put("mode","background").put("allowed_packages",new JSONArray().put(PACKAGE))
                .put("bootstrap_package",PACKAGE).put("bootstrap_source","owner_selected_initial_app")
                .put("bootstrap_model_issued",false).put("home_allowed",false).put("main_display_fallback",false);
        PhoneObservation.CollectionStats counters=new PhoneObservation.CollectionStats(
                1536,512,6144,nodes.size(),nodes.size(),syntheticRetainedText(nodes),0,0,0,0,1);
        return new PhoneObservation(id,PACKAGE,clock,1200,2800,0,window,new Rect(0,0,1200,2800),null,
                WebEvidenceJson.sha("synthetic app tree "+id),WebEvidenceJson.sha("synthetic screen "+id),
                new ObservationState(WebEvidenceJson.sha("synthetic state "+id),ImeVisibility.HIDDEN),
                ObservedWindowMetadata.observed(new int[]{0,0,1200,2800},"android.widget.FrameLayout",1,7,
                        new int[]{0,0,1200,2800},"owned helper"),false,nodes,GENERATION,PACKAGE,Collections.singletonList(PACKAGE),
                counters,selection,WebEvidenceJson.sha(OWNER));
    }
    private static int syntheticRetainedText(List<PhoneObservation.Node> nodes){
        int count=0;for(PhoneObservation.Node node:nodes)count+=node.text.length()+node.description.length();return count;
    }
    private static PhoneObservation searchFrame()throws Exception{
        return frame(repeat("2",32),1005,19,searchNodes());
    }
    private static PhoneObservation.Node nativeNode(String id,String path,String parent,String cls,String text,String description,
            Rect bounds,boolean clickable,boolean enabled)throws Exception{
        return new PhoneObservation.Node(id,PACKAGE,cls,"",text,description,bounds,clickable,false,false,enabled,false,false,
                ObservedChildText.notApplicable(),ObservedScrollActions.observed(Collections.<String>emptyList()),
                ObservedImeEnter.UNKNOWN,null,false,WebEvidenceJson.sha("synthetic native "+id+" "+path+" "+text+" "+description),
                path,parent);
    }
    private static List<PhoneObservation.Node> searchNodes()throws Exception{
        // These eight native nodes, coordinates and IDs are synthetic. Their
        // roles use the actual reviewed AX relationship; there is no CSS mapping.
        String view="android.view.View",text="android.widget.TextView",anchor="0/0/0/0";
        return new ArrayList<PhoneObservation.Node>(Arrays.asList(
                nativeNode("n10","0/0",view,"android.webkit.WebView","","",new Rect(0,400,1200,2800),false,true),
                nativeNode("n11","0/0/0","android.webkit.WebView",view,"","",new Rect(200,600,550,960),false,true),
                nativeNode("n1",anchor,view,view,"",CARD_LABEL,new Rect(200,600,550,960),true,true),
                nativeNode("n12",anchor+"/0",view,"android.widget.ImageView","","",new Rect(220,620,530,820),false,true),
                nativeNode("n2",anchor+"/1",view,text,MODEL,"",new Rect(220,830,530,855),true,true),
                nativeNode("n5",anchor+"/2",view,view,"","",new Rect(220,860,440,900),false,true),
                nativeNode("n3",anchor+"/2/0",view,text,"159元","",new Rect(220,860,300,890),false,true),
                nativeNode("n4",anchor+"/2/1",view,view," 199元","",new Rect(300,860,400,890),false,true)));
    }
    private static PhoneObservation searchFrameWithAnchor(Rect bounds,String description,boolean enabled,boolean duplicate)throws Exception{
        List<PhoneObservation.Node> nodes=searchNodes();
        nodes.set(2,nativeNode("n1","0/0/0/0","android.view.View","android.view.View","",description,bounds,true,enabled));
        if(duplicate)nodes.add(nativeNode("n9","0/0/1","android.view.View","android.view.View","",CARD_LABEL,
                new Rect(600,600,950,960),true,false));
        return frame(repeat("2",32),1005,19,nodes);
    }
    private static JSONObject ambiguousSearchDom()throws Exception{
        JSONObject d=searchDom();JSONArray nodes=d.getJSONArray("nodes");int count=nodes.length();
        for(int i=0;i<count;i++){
            JSONObject original=nodes.getJSONObject(i);String path=original.getString("path");
            if(path.equals(WebWire4SyntheticFactory.ROOT)||path.startsWith(WebWire4SyntheticFactory.ROOT+"/")){
                JSONObject other=copy(original);
                String next="0/0/0/1"+path.substring(WebWire4SyntheticFactory.ROOT.length());
                other.put("path",next).put("parent_path",next.substring(0,next.lastIndexOf('/')));
                nodes.put(other);
            }
        }
        d.put("visited",nodes.length());
        d.getJSONObject("action_region_observations").put("candidate_count",2).put("status","ambiguous");
        return d;
    }
    private static PhoneObservation detailFrame()throws Exception{
        return frame(repeat("5",32),1205,19,Arrays.asList(ax("n2","","AX3000T",600,false,true),
                ax("n3","","199.00",700,false,true),ax("n4","","CNY",800,false,true)));
    }
    private static JSONObject request(long epoch)throws Exception{
        return oldFixture("request").put("expected_navigation_epoch",epoch)
                .put("request_nonce",repeat(epoch==7?"4":"6",64));
    }
    private static JSONObject rawCaptureBase(JSONObject b,JSONObject dom,long epoch,long start)throws Exception{
        JSONObject raw=oldFixture("captured"),req=request(epoch),c=raw.getJSONObject("capture");
        String requestRaw=req.toString(),domRaw=dom.toString();long delta=start-1000;
        raw.put("request_json_utf8",requestRaw).put("request_sha256",WebEvidenceJson.sha(requestRaw))
                .put("binding",copy(b)).put("binding_sha256",WebEvidenceBinding.sha256(b))
                .put("controller_identity",copy(b.getJSONObject("controller_identity")))
                .put("helper_identity",copy(b.getJSONObject("helper_identity")));
        raw.getJSONObject("storage_isolation").put("first_url",b.get("initial_url"));
        c.put("binding",copy(b)).put("challenge",req.get("request_nonce")).put("navigation_epoch",epoch)
                .put("committed_main_frame_url",dom.get("href")).put("current_native_url",dom.get("href"))
                .put("commit_elapsed_ms",start-50).put("started_elapsed_ms",start).put("ended_elapsed_ms",start+10)
                .put("dom_raw_utf8",domRaw).put("dom_sha256",WebEvidenceJson.sha(domRaw));
        JSONArray samples=c.getJSONObject("capture_geometry").getJSONArray("samples");
        for(int i=0;i<samples.length();i++){
            JSONObject n=samples.getJSONObject(i).getJSONObject("native");
            n.put("sampled_elapsed_ms",n.getLong("sampled_elapsed_ms")+delta)
                    .put("scale_changed_elapsed_ms",n.getLong("scale_changed_elapsed_ms")+delta);
        }
        WebV4RegressionFixtures.capture(c,dom,b);
        return raw;
    }
    private static JSONObject armFor(JSONObject b,JSONObject source)throws Exception{
        JSONObject q=new JSONObject().put("schema",WebEvidenceProtocol.requestSchema(WebEvidenceProtocol.ARM_OBSERVED_LINK))
                .put("task_id",TASK).put("controller_session_nonce",SESSION).put("request_nonce",repeat("a",64))
                .put("deadline_elapsed_ms",2000L).put("expected_webview_instance",source.get("webview_instance"))
                .put("expected_navigation_epoch",source.get("navigation_epoch"))
                .put("source_capture_challenge",source.get("challenge")).put("source_dom_sha256",source.get("dom_sha256"))
                .put("source_stability_sha256",source.get("dom_stability_sha256"))
                .put("anchor_dom_path",WebWire4SyntheticFactory.ANCHOR).put("model_run_id",RUN);
        JSONObject arm=WebObservedNavigation.arm(q,b,source,1050);
        return WebObservedNavigation.verifyArm(q,b,source,arm);
    }
    private static JSONObject syntheticNavigation(JSONObject arm)throws Exception{
        JSONObject profile=new JSONObject().put("profile_assignment_api","WebViewCompat.setProfile")
                .put("profile_assigned_before_other_interactions",true)
                .put("actual_profile_name",arm.get("storage_profile_name")).put("profile_assigned_elapsed_ms",1101L)
                .put("reused_same_lease_profile",true).put("network_loads_blocked",true)
                .put("javascript_enabled",false).put("visible_in_layout",false);
        // Explicit unit event values exercise the real typed verifier. They do
        // not represent a WebView callback, native click, model run or phone fact.
        return new JSONObject().put("schema",WebObservedNavigation.NAV_SCHEMA).put("arm",copy(arm))
                .put("popup_callback_observed",true).put("popup_callback_elapsed_ms",1100L)
                .put("popup_is_dialog",false).put("popup_is_user_gesture",true)
                .put("popup_url_observed",true).put("popup_url_observed_elapsed_ms",1102L)
                .put("popup_observed_url",DETAIL).put("popup_observed_method","GET").put("popup_observed_main_frame",true)
                .put("popup_initiating_frame_verified",false).put("auxiliary_network_loads_blocked",true)
                .put("auxiliary_view_created",true).put("auxiliary_view_destroyed",true).put("same_profile_assignment",profile)
                .put("auxiliary_destroyed_elapsed_ms",1103L).put("same_lease_main_load_invoked",true)
                .put("same_lease_main_load_returned",true).put("main_load_begin_elapsed_ms",1104L)
                .put("main_load_returned_elapsed_ms",1105L).put("new_visible_window_created",false)
                .put("external_app_launched",false).put("transaction_authority",false).put("business_verified",false)
                .put("cancelled",false).put("cancelled_elapsed_ms",JSONObject.NULL).put("cancellation_reason",JSONObject.NULL);
    }
    private static JSONObject rawCapture(JSONObject b,JSONObject dom,long epoch,long start)throws Exception{
        JSONObject raw=rawCaptureBase(b,dom,epoch,start);
        WebTaskPurpose p=WebTaskPurpose.requireBinding(b);
        if(p.shopping!=null&&!p.initialUrl.equals(dom.getString("href"))){
            JSONObject source=rawCaptureBase(b,searchDom(),7,1000).getJSONObject("capture");
            raw.getJSONObject("capture").put("observed_link_navigation",syntheticNavigation(armFor(b,source)));
        }
        return raw;
    }
    private static WebEvidenceReceipt receipt(JSONObject b,JSONObject raw)throws Exception{
        JSONObject req=new JSONObject(raw.getString("request_json_utf8")),c=raw.getJSONObject("capture");
        byte[] bytes=(raw.toString()+"\n").getBytes(StandardCharsets.UTF_8);
        JSONObject cb=callback(b,req).put("status","captured").put("navigation_epoch",c.get("navigation_epoch"))
                .put("raw_length",bytes.length).put("raw_sha256",WebEvidenceJson.sha(bytes));
        return WebEvidenceReceipt.verify(WebEvidenceProtocol.CAPTURE,req.toString(),b,cb.toString(),bytes,10484,1000,1500);
    }
    private static JSONObject callback(JSONObject b,JSONObject req)throws Exception{
        return new JSONObject().put("schema",WebEvidenceProtocol.CALLBACK_SCHEMA).put("method","captureEvidence")
                .put("request_nonce",req.get("request_nonce")).put("task_id",TASK).put("controller_session_nonce",SESSION)
                .put("status","unavailable").put("reason","synthetic_unit_fixture").put("actual_helper_uid",10484)
                .put("actual_display_id",7).put("actual_window_id",19).put("webview_instance",req.get("expected_webview_instance"))
                .put("navigation_epoch",req.get("expected_navigation_epoch")).put("binding_sha256",WebEvidenceBinding.sha256(b))
                .put("raw_length",0).put("raw_sha256",JSONObject.NULL).put("retired",false)
                .put("cleanup",JSONObject.NULL).put("recovery",JSONObject.NULL);
    }
    private static WebTaskDomain observed(JSONObject b,JSONObject dom,long epoch,long time,PhoneObservation frame)throws Exception{
        WebTaskPurpose p=WebTaskPurpose.requireBinding(b);JSONObject raw=rawCapture(b,dom,epoch,time);
        WebTaskDomain result=WebTaskDomain.observed(TASK,p,p.authorization.bind(TASK),frame,receipt(b,raw),b);
        if(result.shopping!=null&&!result.clickIds.isEmpty())
            result=result.withObservedLinkArm(armFor(b,raw.getJSONObject("capture")));
        return result;
    }
    private static WebTaskDomain waiting(JSONObject b)throws Exception{
        WebTaskPurpose p=WebTaskPurpose.requireBinding(b);JSONObject req=request(7),cb=callback(b,req);
        WebEvidenceReceipt r=WebEvidenceReceipt.verify(WebEvidenceProtocol.CAPTURE,req.toString(),b,cb.toString(),null,10484,1000,1500);
        return WebTaskDomain.waiting(TASK,p,p.authorization.bind(TASK),searchFrame(),r,b);
    }
    private static ActionDecision action(String observation,String kind,String node,String status)throws Exception{
        JSONObject raw=new JSONObject().put("action",kind).put("observation_id",observation).put("package",PACKAGE);
        if("click".equals(kind))raw.put("node_id",node).put("node_label",CARD_LABEL);
        if("wait".equals(kind))raw.put("duration_ms",100);
        if("done".equals(kind))raw.put("status",status).put("summary","synthetic fixture only");
        return ActionDecision.parse(raw.toString());
    }
    private static NotesCompletionEvidence.Frame completionFrame(String observation,int window){
        return new NotesCompletionEvidence.Frame(observation,PACKAGE,window,7,GENERATION,1,true,false,
                Collections.<NotesCompletionEvidence.Node>emptyList());
    }
    private static WebShoppingDomain.Navigation navigate(WebTaskDomain before,WebTaskDomain after,boolean accepted,
            boolean dispatched,boolean stale,long start,long end)throws Exception{
        return WebShoppingDomain.Navigation.confirm(before.shopping,after.shopping,action(before.observationId,"click","n1",null),
                RUN,accepted,dispatched,stale,start,end);
    }
    private static Set<String> tools(){return new HashSet<String>(Arrays.asList("open","click","type","submit","back","scroll","wait","done"));}

    // These lifecycle inputs are explicit host doubles. The provider/domain,
    // TCG, immutable snapshot, identity checks and one-shot transitions are real.
    // This is not an authenticated Binder CLOSE or a native-worker execution.
    private static NotesCompletionEvidence.Frame terminalFrame()throws Exception{
        PhoneObservation f=detailFrame();List<NotesCompletionEvidence.Node> nodes=new ArrayList<NotesCompletionEvidence.Node>();
        for(PhoneObservation.Node n:f.nodes){
            String label=n.label();
            if(n.text.trim().isEmpty()&&n.description.trim().isEmpty()&&(n.childText.truncated||!"derived".equals(n.childText.status)))label="";
            nodes.add(new NotesCompletionEvidence.Node(n.id,n.packageName,n.text,label,n.viewId,n.inputTextSha256,
                    new int[]{n.bounds.left,n.bounds.top,n.bounds.right,n.bounds.bottom},n.editable,n.clickable,n.scrollable,
                    n.enabled,n.password,n.childText,n.observedAppTreeSignature));
        }
        return new NotesCompletionEvidence.Frame(f.id,f.packageName,f.windowId,7,f.backgroundGeneration,1,true,false,nodes);
    }
    private static final class TerminalFixture {
        final TaskAuthorization authorization=TaskAuthorization.parse(OWNER);
        final TaskCompletionGate gate=new TaskCompletionGate(TASK,OWNER,authorization);
        final Object lease=new Object();final WebTaskDomain domain;final NotesCompletionEvidence.Frame frame;
        final String binding;TaskCompletionGate.WebCloseAttempt close;boolean claimVerified;
        TerminalFixture(WebTaskDomain domain,boolean claim,boolean stable)throws Exception{
            this.domain=domain;frame=terminalFrame();binding=(String)domain.evidence().get("binding_sha256");
            gate.observed(frame);gate.bindWebDomain(domain);
            if(claim)claimVerified=gate.successClaim(1,RUN,frame,stable).verified;
        }
        void retire(){close=gate.beginWebClose(lease,domain,TASK,binding,"normal");gate.clearWebDomain();}
        boolean known(String bad){
            return gate.webCloseKnown(close,lease,"task".equals(bad)?repeat("e",32):TASK,
                    "binding".equals(bad)?repeat("e",64):binding,"status".equals(bad)?"recovered_retired":"closed",
                    "instance".equals(bad)?"different-instance":domain.instance,domain.epoch+("epoch".equals(bad)?1:0),
                    domain.displayId+("display".equals(bad)?1:0),domain.windowId+("window".equals(bad)?1:0),
                    "callback_sha".equals(bad)?"unverified":repeat("a",64));
        }
        TaskCompletionGate.Check finish(String bad,NotesCompletionEvidence.Frame current){
            TaskAuthorization.Frame owner=authorization.bind("owner_task".equals(bad)?repeat("e",32):TASK).frame();
            if("owner".equals(bad))owner=TaskAuthorization.parse(OWNER).bind(TASK).frame();
            if("no_owner".equals(bad))owner=null;
            return gate.terminalWebCheck("lease".equals(bad)?new Object():lease,current,owner,
                    "step".equals(bad)?2:1,"model_run".equals(bad)?repeat("e",32):RUN,
                    !"model_success".equals(bad),!"cleanup".equals(bad),!"helper".equals(bad),!"background".equals(bad),
                    !"scope".equals(bad),"cancelled".equals(bad),!"not_started".equals(bad),!"not_exited".equals(bad),
                    "exit".equals(bad)?1:0,!"receipt".equals(bad),"worker_task".equals(bad)?repeat("e",32):TASK,
                    "worker_generation".equals(bad)?"missing":repeat("b",32),"worker_sha".equals(bad)?"missing":repeat("c",64));
        }
    }
    private static TerminalFixture closedFixture(WebTaskDomain linked)throws Exception{
        TerminalFixture f=new TerminalFixture(linked,true,true);
        if(!f.claimVerified)throw new IllegalStateException("synthetic real-provider prerequisite");
        f.retire();if(!f.known(""))throw new IllegalStateException("synthetic ordinary-close prerequisite");return f;
    }
    private static NotesCompletionEvidence.Frame changedFrame(NotesCompletionEvidence.Frame f,String field,List<NotesCompletionEvidence.Node> nodes){
        return new NotesCompletionEvidence.Frame("observation".equals(field)?repeat("e",32):f.observationId,
                "package".equals(field)?"org.synthetic.other":f.packageName,f.windowId+("window".equals(field)?1:0),
                f.displayId+("display".equals(field)?1:0),"generation".equals(field)?"32345678-1234-1234-1234-123456789012":f.backgroundGeneration,
                "type".equals(field)?2:f.windowType,!"metadata".equals(field)&&f.metadataObserved,
                "truncated".equals(field)||f.nodesTruncated,nodes);
    }
    private static NotesCompletionEvidence.Node changedNode(NotesCompletionEvidence.Node n,String field){
        ObservedChildText.Result child=n.childText;
        if("child".equals(field))child=new ObservedChildText.Result("changed child","derived",false,1,Collections.<ObservedChildText.Source>emptyList());
        if("visited".equals(field))child=new ObservedChildText.Result(child.text,child.status,child.truncated,child.visited+1,child.sources);
        return new NotesCompletionEvidence.Node("id".equals(field)?"n999":n.id,
                "package".equals(field)?"org.synthetic.other":n.packageName,"text".equals(field)?n.text+" changed":n.text,
                "label".equals(field)?n.label+" changed":n.label,"view".equals(field)?n.viewId+" changed":n.viewId,
                "input".equals(field)?repeat("e",64):n.inputTextSha256,
                new int[]{n.left+("left".equals(field)?1:0),n.top+("top".equals(field)?1:0),
                        n.right+("right".equals(field)?1:0),n.bottom+("bottom".equals(field)?1:0)},
                "editable".equals(field)?!n.editable:n.editable,"clickable".equals(field)?!n.clickable:n.clickable,
                "scrollable".equals(field)?!n.scrollable:n.scrollable,"enabled".equals(field)?!n.enabled:n.enabled,
                "password".equals(field)?!n.password:n.password,child,
                "signature".equals(field)?repeat("e",64):n.observedAppTreeSignature);
    }
    @SuppressWarnings("unchecked")
    private static void terminalLifecycleCases(WebTaskDomain linked,WebTaskDomain unverified)throws Exception{
        test("terminal_verified_snapshot_survives_only_normal_known_close",()->{
            TerminalFixture f=closedFixture(linked);
            check(!f.gate.verified(f.frame),"ordinary clear still removes live completion/action eligibility");
            rejects(()->f.gate.webDomainFor(f.frame));
            TaskCompletionGate.Check end=f.finish("",f.frame);
            check(end.verified&&!end.retryAllowed,"real TCG result snapshot plus explicit synthetic terminal facts");
            Map<String,Object> result=(Map<String,Object>)end.evidence.get("public_web_result");
            Map<String,Object> terminal=(Map<String,Object>)end.evidence.get("terminal_web_completion");
            check("199.00".equals(result.get("amount_decimal"))&&"CNY".equals(result.get("currency"))
                    &&Boolean.TRUE.equals(result.get("action_domain_retired")),"actual fixture result is retained read-only");
            check(Boolean.FALSE.equals(result.get("business_verified"))&&Boolean.FALSE.equals(terminal.get("grants_tool_authority")),
                    "completion snapshot grants no transaction or action capability");
            boolean immutable=false;try{result.put("amount_decimal","0");}catch(UnsupportedOperationException expected){immutable=true;}
            check(immutable,"nested result evidence is immutable");
            Map<String,Object> page=(Map<String,Object>)end.evidence.get("official_page");
            Map<String,Object> frozenGeometry=(Map<String,Object>)page.get("native_geometry");
            Map<String,Object> actualGeometry=(Map<String,Object>)linked.evidence().get("native_geometry");
            check(frozenGeometry.equals(actualGeometry)&&frozenGeometry!=actualGeometry
                    &&frozenGeometry.get("native_bounds_screen_pixels") instanceof List,
                    "actual provider geometry is a typed structural map with detached arrays");
            List<Object> frozenBounds=(List<Object>)frozenGeometry.get("native_bounds_screen_pixels");
            boolean nestedImmutable=false;
            try{frozenBounds.set(0,Integer.valueOf(-1));}catch(UnsupportedOperationException expected){nestedImmutable=true;}
            check(nestedImmutable,"native geometry array is deeply immutable");
            Object originalGeometrySha=actualGeometry.get("native_geometry_sha256");
            try{
                actualGeometry.put("native_geometry_sha256",repeat("e",64));
                check(originalGeometrySha.equals(frozenGeometry.get("native_geometry_sha256")),
                        "mutating the retired provider map cannot change its terminal snapshot");
            }finally{actualGeometry.put("native_geometry_sha256",originalGeometrySha);}
            TerminalFixture changedBeforeClose=new TerminalFixture(linked,true,true);
            try{
                actualGeometry.put("native_geometry_sha256",repeat("e",64));
                changedBeforeClose.retire();
                check(changedBeforeClose.close==null&&!changedBeforeClose.known("")
                        &&!changedBeforeClose.finish("",changedBeforeClose.frame).verified,
                        "provider geometry mutation after claim and before close rejects completion");
            }finally{actualGeometry.put("native_geometry_sha256",originalGeometrySha);}
        });
        test("terminal_unclaimed_unstable_or_unverified_result_never_freezes",()->{
            for(int mode=0;mode<3;mode++){
                TerminalFixture f=new TerminalFixture(mode==2?unverified:linked,mode!=0,mode!=1);
                f.retire();check(f.close==null&&!f.known("")&&!f.finish("",f.frame).verified,"no snapshot from model intent or absent provider result");
            }
        });
        test("terminal_final_frame_identity_changes_are_rejected",()->{
            for(String field:Arrays.asList("observation","package","window","display","generation","type","metadata","truncated")){
                TerminalFixture f=closedFixture(linked);
                check(!f.finish("",changedFrame(f.frame,field,f.frame.nodes)).verified,"changed final frame: "+field);
            }
            TerminalFixture absent=closedFixture(linked);check(!absent.finish("",null).verified,"missing final frame");
        });
        test("terminal_final_native_node_changes_are_rejected",()->{
            for(String field:Arrays.asList("id","package","text","label","view","input","left","top","right","bottom",
                    "editable","clickable","scrollable","enabled","password","signature","child","visited")){
                TerminalFixture f=closedFixture(linked);List<NotesCompletionEvidence.Node> nodes=new ArrayList<NotesCompletionEvidence.Node>(f.frame.nodes);
                nodes.set(0,changedNode(nodes.get(0),field));
                check(!f.finish("",changedFrame(f.frame,"",nodes)).verified,"changed final node: "+field);
            }
            TerminalFixture order=closedFixture(linked);List<NotesCompletionEvidence.Node> reversed=new ArrayList<NotesCompletionEvidence.Node>(order.frame.nodes);
            Collections.reverse(reversed);check(!order.finish("",changedFrame(order.frame,"",reversed)).verified,"native node order bound");
            TerminalFixture count=closedFixture(linked);List<NotesCompletionEvidence.Node> shorter=new ArrayList<NotesCompletionEvidence.Node>(count.frame.nodes);
            shorter.remove(shorter.size()-1);check(!count.finish("",changedFrame(count.frame,"",shorter)).verified,"native node count bound");
        });
        test("terminal_closed_callback_identity_is_exact",()->{
            for(String fault:Arrays.asList("task","binding","status","instance","epoch","display","window","callback_sha")){
                TerminalFixture f=new TerminalFixture(linked,true,true);f.retire();
                check(!f.known(fault)&&!f.finish("",f.frame).verified,"ordinary CLOSE mismatch: "+fault);
            }
            TerminalFixture nonnormal=new TerminalFixture(linked,true,true);
            nonnormal.close=nonnormal.gate.beginWebClose(nonnormal.lease,linked,TASK,nonnormal.binding,"error");
            nonnormal.gate.clearWebDomain();check(nonnormal.close==null&&!nonnormal.known("")&&!nonnormal.finish("",nonnormal.frame).verified,"error close is not a normal terminal");
        });
        test("terminal_unknown_abort_and_late_close_never_recover_success",()->{
            TerminalFixture failed=new TerminalFixture(linked,true,true);failed.retire();failed.gate.abortWebClose(failed.close);
            check(!failed.known("")&&!failed.finish("",failed.frame).verified,"a late positive callback cannot undo unknown close");
            TerminalFixture noAttach=new TerminalFixture(linked,true,true);noAttach.retire();noAttach.gate.abortWebClose(noAttach.close);
            check(!noAttach.finish("",noAttach.frame).verified,"no-attach retirement is not an observed result close");
            TerminalFixture duplicate=new TerminalFixture(linked,true,true);duplicate.retire();
            check(duplicate.gate.beginWebClose(duplicate.lease,linked,TASK,duplicate.binding,"normal")==null
                    &&!duplicate.known("")&&!duplicate.finish("",duplicate.frame).verified,"one close attempt per gate");
        });
        test("terminal_clear_rebind_and_late_observation_invalidate_proof",()->{
            TerminalFixture cleared=new TerminalFixture(linked,true,true);cleared.gate.clearWebDomain();cleared.retire();
            check(cleared.close==null&&!cleared.finish("",cleared.frame).verified,"clear without prepared close cannot restore a candidate");
            TerminalFixture rebound=new TerminalFixture(linked,true,true);rebound.gate.bindWebDomain(linked);rebound.retire();
            check(rebound.close==null&&!rebound.finish("",rebound.frame).verified,"even equal domain rebinding consumes the old claim");
            TerminalFixture observed=new TerminalFixture(linked,true,true);
            observed.gate.observed(changedFrame(observed.frame,"observation",observed.frame.nodes));observed.gate.observed(observed.frame);observed.retire();
            check(observed.close==null&&!observed.finish("",observed.frame).verified,"return to the old frame cannot revive a changed observation");
            TerminalFixture twice=new TerminalFixture(linked,true,true);twice.retire();twice.gate.clearWebDomain();
            check(!twice.known("")&&!twice.finish("",twice.frame).verified,"exactly the prepared clear is allowed");
            TerminalFixture late=closedFixture(linked);late.gate.observed(late.frame);
            check(!late.finish("",late.frame).verified,"late observations after retirement do not mint a proof");
            TerminalFixture bindAfter=closedFixture(linked);rejects(()->bindAfter.gate.bindWebDomain(linked));
            check(!bindAfter.finish("",bindAfter.frame).verified,"retired action domain cannot be rebound");
        });
        test("terminal_requires_actual_owner_scope_cleanup_and_native_parent_facts",()->{
            for(String fault:Arrays.asList("lease","owner","owner_task","no_owner","step","model_run","model_success","cleanup",
                    "helper","background","scope","cancelled","not_started","not_exited","exit","receipt","worker_task","worker_generation","worker_sha")){
                TerminalFixture f=closedFixture(linked);
                check(!f.finish(fault,f.frame).verified,"missing actual terminal fact: "+fault);
            }
            TerminalFixture invalid=closedFixture(linked);invalid.gate.invalidateInstalled("synthetic post-close identity invalidation");
            check(!invalid.finish("",invalid.frame).verified,"identity invalidation after a known close still wins");
        });
        test("terminal_tokens_are_gate_local_and_consumed_once",()->{
            TerminalFixture first=new TerminalFixture(linked,true,true),other=new TerminalFixture(linked,true,true);first.retire();other.retire();
            check(!other.gate.webCloseKnown(first.close,first.lease,TASK,first.binding,"closed",linked.instance,linked.epoch,7,19,repeat("a",64)),
                    "a private token cannot cross even otherwise identical gates");
            check(!other.finish("",other.frame).verified&&!first.known(""),"foreign/replayed token cannot produce either success");
            TerminalFixture consumed=closedFixture(linked);
            check(consumed.finish("",consumed.frame).verified&&!consumed.finish("",consumed.frame).verified,"one terminal consumption");
        });
        test("terminal_flight_without_results_provider_stays_unverified",()->{
            TaskAuthorization a=TaskAuthorization.parse(FLIGHT);TaskCompletionGate gate=new TaskCompletionGate(TASK,FLIGHT,a);
            WebTaskDomain pending=waiting(binding(FLIGHT));NotesCompletionEvidence.Frame f=completionFrame(pending.observationId,pending.windowId);
            gate.observed(f);gate.bindWebDomain(pending);check(!gate.successClaim(1,RUN,f,true).verified,"no Flight provider manufactured");
            Object lease=new Object();TaskCompletionGate.WebCloseAttempt close=gate.beginWebClose(lease,pending,TASK,(String)pending.evidence().get("binding_sha256"),"normal");
            gate.clearWebDomain();check(close==null,"no immutable result for the actual form/query-only provider");
            check(!gate.terminalWebCheck(lease,f,a.bind(TASK).frame(),1,RUN,true,true,true,true,true,false,true,true,0,true,TASK,repeat("b",32),repeat("c",64)).verified,
                    "synthetic positive cleanup cannot turn absent Flight data into completion");
        });
    }

    public static void main(String[] argv)throws Exception{
        check(argv.length==1,"one create-only report path");
        final JSONObject b=binding(OWNER);
        final WebTaskDomain before=observed(b,searchDom(),7,1000,searchFrame());
        final WebTaskDomain after=observed(b,detailDom(),8,1200,detailFrame());
        final WebShoppingDomain.Navigation actualFixtureNavigation=navigate(before,after,true,true,false,1100,1101);
        final WebTaskDomain linked=after.withNavigation(actualFixtureNavigation);
        test("v4_receipt_and_real_composition",()->{
            check(WebEvidenceProtocol.HELPER_VERSION_CODE==6&&before.shopping!=null&&before.flight==null,"explicit current peer/provider");
            check(before.clickIds.equals(Collections.singleton("n1")),"only actual synthetic same-frame AX id");
            check(!before.resultReady()&&!after.resultReady(),"no result before accepted navigation");
            check(linked.resultReady(),"valid typed fixture connects both real providers");
            check(Boolean.FALSE.equals(linked.resultRecord().get("business_verified"))&&
                    Boolean.FALSE.equals(linked.resultRecord().get("final_native_and_cleanup_gates_verified")),"unit/provider proof is not overall completion");
        });
        test("price_not_filled_from_goal",()->check("199.00".equals(linked.resultRecord().get("amount_decimal"))&&
                "CNY".equals(linked.resultRecord().get("currency")),"actual synthetic data, not goal default"));
        test("result_record_requires_navigation",()->rejects(()->after.resultRecord()));
        test("current_tcg_real_provider_path",()->{
            TaskCompletionGate gate=new TaskCompletionGate(TASK,OWNER,TaskAuthorization.parse(OWNER));
            NotesCompletionEvidence.Frame f=completionFrame(linked.observationId,19);gate.observed(f);gate.bindWebDomain(linked);
            check(gate.verified(f),"real Web TCG does not use Notes installed field");
            check(!gate.successClaim(1,RUN,f,false).verified,"unstable final observation rejected");
            check(gate.successClaim(2,RUN,f,true).verified,"pure fixture completes only component gates");
            gate.clearWebDomain();check(!gate.verified(f),"clearing domain clears eligibility");
        });
        test("tcg_no_navigation_cannot_complete",()->{
            TaskCompletionGate gate=new TaskCompletionGate(TASK,OWNER,TaskAuthorization.parse(OWNER));
            NotesCompletionEvidence.Frame f=completionFrame(after.observationId,19);gate.observed(f);gate.bindWebDomain(after);
            check(!gate.successClaim(1,RUN,f).verified,"model success cannot replace navigation");
        });
        test("tcg_rejects_stale_observation",()->{
            TaskCompletionGate gate=new TaskCompletionGate(TASK,OWNER,TaskAuthorization.parse(OWNER));
            NotesCompletionEvidence.Frame f=completionFrame(linked.observationId,19);gate.observed(f);gate.bindWebDomain(linked);
            check(!gate.verified(completionFrame(repeat("7",32),19)),"old DOM cannot certify new frame");
            check(!gate.verified(completionFrame(linked.observationId,20)),"window identity retained");
            gate.invalidateInstalled("unit_current_identity_changed");check(!gate.verified(f),"current identity invalidation still blocks");
        });
        test("tcg_rejects_other_owner",()->{
            TaskCompletionGate gate=new TaskCompletionGate(TASK,FLIGHT,TaskAuthorization.parse(FLIGHT));rejects(()->gate.bindWebDomain(linked));
        });
        test("wait_has_no_action_capability",()->{
            WebTaskDomain pending=waiting(b);check(pending.clickIds.isEmpty()&&pending.toolMask(tools()).equals(new HashSet<String>(Arrays.asList("wait","done"))),"wait-only");
            check(!pending.resultReady(),"no price or navigation");pending.requireCurrent(action(pending.observationId,"wait",null,null));
            pending.requireCurrent(action(pending.observationId,"done",null,"partial"));
            rejects(()->pending.requireCurrent(action(pending.observationId,"done",null,"success")));
            rejects(()->pending.requireCurrent(action(pending.observationId,"click","n1",null)));
        });
        test("flight_wait_uses_original_natural_owner",()->{
            WebTaskDomain pending=waiting(binding(FLIGHT));
            check(pending.flight!=null&&pending.shopping==null&&!pending.resultReady(),"independent flight provider; no result provider fabricated");
        });
        test("original_tool_mask_is_intersection",()->{
            check(before.toolMask(Collections.singleton("wait")).equals(Collections.singleton("wait")),"no click if original authority lacks it");
            check(before.edits(Collections.singleton("n1")).isEmpty()&&before.openPackages(Collections.singleton(PACKAGE)).isEmpty(),"no type/open expansion");
            rejects(()->before.requireCurrent(ActionDecision.parse(new JSONObject().put("action","click").put("observation_id",before.observationId)
                    .put("package",PACKAGE).put("x",100).put("y",100).toString())));
        });
        test("missing_accepted_outcome_rejected",()->rejects(()->navigate(before,after,false,true,false,1100,1101)));
        test("missing_dispatch_outcome_rejected",()->rejects(()->navigate(before,after,true,false,false,1100,1101)));
        test("stale_native_outcome_rejected",()->rejects(()->navigate(before,after,true,true,true,1100,1101)));
        for(final long[] pair:new long[][]{{1009,1101},{1102,1101},{1100,1201}}){
            test("dispatch_time_order_"+pair[0]+"_"+pair[1],()->rejects(()->navigate(before,after,true,true,false,pair[0],pair[1])));
        }
        test("operator_without_native_run_rejected",()->rejects(()->WebShoppingDomain.Navigation.confirm(before.shopping,after.shopping,
                action(before.observationId,"click","n1",null),null,true,true,false,1100,1101)));
        test("old_source_observation_rejected",()->rejects(()->WebShoppingDomain.Navigation.confirm(before.shopping,after.shopping,
                action(repeat("7",32),"click","n1",null),RUN,true,true,false,1100,1101)));
        test("new_epoch_required",()->{
            WebTaskDomain same=observed(b,detailDom(),7,1200,detailFrame());rejects(()->navigate(before,same,true,true,false,1100,1101));
        });
        test("source_link_target_must_match",()->{
            JSONObject dom=detailDom().put("href",DETAIL.replace("1230803766","1230803767"));WebTaskDomain other=observed(b,dom,8,1200,detailFrame());
            rejects(()->navigate(before,other,true,true,false,1100,1101));
        });
        test("navigation_cannot_cross_lease",()->{
            JSONObject other=copy(b).put("controller_session_nonce",repeat("8",64)).put("storage_profile_name","hepta_v2_"+repeat("8",64));
            WebTaskPurpose p=WebTaskPurpose.requireBinding(other);check(!p.ownerSha256.isEmpty(),"same owner can have distinct lease");
            rejects(()->WebTaskDomain.observed(TASK,p,p.authorization.bind(TASK),detailFrame(),receipt(b,rawCapture(b,detailDom(),8,1200)),other));
        });
        test("code3_binding_rejected",()->{
            JSONObject bad=copy(b);bad.getJSONObject("helper_identity").put("version_code",3);rejects(()->waiting(bad));
        });
        test("old_v2_binding_rejected",()->rejects(()->waiting(copy(b).put("schema","hepta.web-helper.binding.v2"))));
        test("foreign_site_policy_rejected",()->rejects(()->waiting(copy(b).put("site_policy_id","csair_public_flight_v1"))));
        test("foreign_compiled_initial_url_rejected",()->rejects(()->waiting(copy(b).put("initial_url","https://m.csair.com/"))));
        test("mutated_authority_evidence_rejected",()->{
            JSONObject bad=copy(b);bad.getJSONObject("authorization").put("authorization_sha256",repeat("0",64));rejects(()->waiting(bad));
        });
        test("extra_selected_app_rejected",()->{
            JSONObject bad=copy(b);bad.getJSONObject("background").getJSONArray("selected_packages").put("com.android.settings");rejects(()->waiting(bad));
        });
        test("wrong_authenticated_uid_rejected",()->{
            JSONObject bad=copy(b);bad.getJSONObject("helper_identity").put("uid",10485);rejects(()->waiting(bad));
        });
        test("raw_controller_identity_mismatch_rejected",()->{
            JSONObject raw=rawCapture(b,searchDom(),7,1000);raw.getJSONObject("controller_identity").put("uid",10482);rejects(()->receipt(b,raw));
        });
        test("callback_metadata_lost_binding_rejected",()->{
            JSONObject req=request(7),cb=callback(b,req).put("binding_sha256",JSONObject.NULL);
            rejects(()->WebEvidenceReceipt.verify(WebEvidenceProtocol.CAPTURE,req.toString(),b,cb.toString(),null,10484,1000,1500));
        });
        test("bound_dom_wrong_origin_rejected",()->{
            JSONObject dom=searchDom().put("origin","https://m.mi.com");rejects(()->observed(b,dom,7,1000,searchFrame()));
        });
        test("manual_diagnostic_not_task_evidence",()->{
            JSONObject raw=rawCapture(b,searchDom(),7,1000).put("diagnostic_unbound",true);rejects(()->receipt(b,raw));
        });
        test("duplicate_native_card_description_blocks_even_disabled",()->{
            PhoneObservation f=searchFrameWithAnchor(new Rect(200,600,550,960),CARD_LABEL,true,true);
            check(observed(b,searchDom(),7,1000,f).clickIds.isEmpty(),"all duplicates counted before state filtering");
        });
        test("out_of_screen_native_node_has_no_css_fallback",()->{
            PhoneObservation f=searchFrameWithAnchor(new Rect(200,50,550,390),CARD_LABEL,true,false);
            check(observed(b,searchDom(),7,1000,f).clickIds.isEmpty(),"native rectangle outside actual WebView");
        });
        test("different_native_label_blocks_product_link",()->{
            PhoneObservation f=searchFrameWithAnchor(new Rect(200,600,550,960),"Xiaomi路由器AX3000 白色 159元 199元",true,false);
            check(observed(b,searchDom(),7,1000,f).clickIds.isEmpty(),"same native id is insufficient");
        });
        test("ambiguous_observed_region_blocks_product_link",()->{
            JSONObject dom=ambiguousSearchDom();
            check(observed(b,dom,7,1000,searchFrame()).clickIds.isEmpty(),"multiple complete synthetic cards cannot mint a unique region");
        });
        test("transaction_anchor_mints_no_capability",()->{
            JSONObject dom=searchDom();WebWire4SyntheticFactory.find(dom,WebWire4SyntheticFactory.ANCHOR).put("text","购买");
            check(observed(b,dom,7,1000,searchFrame()).clickIds.isEmpty(),"no purchase path");
        });
        test("modal_blocks_all_capabilities",()->{
            JSONObject dom=searchDom();dom.getJSONArray("nodes").put(node("0/0/1","div","","同意").put("role","dialog"));
            dom.put("visited",dom.getJSONArray("nodes").length());
            check(observed(b,dom,7,1000,searchFrame()).clickIds.isEmpty(),"consent not silently dismissed");
        });
        test("conditional_price_cannot_complete",()->{
            JSONObject dom=detailDom();dom.getJSONArray("nodes").put(node("0/0/0/2","span","","限时优惠"));dom.put("visited",8);
            WebTaskDomain conditional=observed(b,dom,8,1200,detailFrame());
            check(!conditional.withNavigation(navigate(before,conditional,true,true,false,1100,1101)).resultReady(),"conditional is not exact public price");
        });
        test("starting_price_cannot_complete",()->{
            JSONObject dom=detailDom();dom.getJSONArray("nodes").put(node("0/0/0/2","span","","起"));dom.put("visited",8);
            WebTaskDomain starting=observed(b,dom,8,1200,detailFrame());
            check(!starting.withNavigation(navigate(before,starting,true,true,false,1100,1101)).resultReady(),"starting price rejected");
        });
        test("currency_requires_actual_native_label",()->{
            PhoneObservation f=frame(repeat("5",32),1205,19,Arrays.asList(ax("n2","","AX3000T",600,false,true),ax("n3","","199.00",700,false,true)));
            WebTaskDomain missing=observed(b,detailDom(),8,1200,f);
            check(!missing.withNavigation(navigate(before,missing,true,true,false,1100,1101)).resultReady(),"DOM currency cannot replace native readback");
        });
        test("native_duplicate_amount_blocks_result",()->{
            PhoneObservation f=frame(repeat("5",32),1205,19,Arrays.asList(ax("n2","","AX3000T",600,false,true),
                    ax("n3","","199.00",700,false,true),ax("n4","","CNY",800,false,true),ax("n8","","199.00",900,false,false)));
            WebTaskDomain ambiguous=observed(b,detailDom(),8,1200,f);
            check(!ambiguous.withNavigation(navigate(before,ambiguous,true,true,false,1100,1101)).resultReady(),"disabled duplicate still ambiguous");
        });
        test("wrong_dom_currency_cannot_complete",()->{
            JSONObject dom=detailDom();dom.getJSONArray("nodes").getJSONObject(6).put("text","USD");
            WebTaskDomain wrong=observed(b,dom,8,1200,detailFrame());
            check(!wrong.withNavigation(navigate(before,wrong,true,true,false,1100,1101)).resultReady(),"CNY is observed, never inferred from goal");
        });
        terminalLifecycleCases(linked,after);
        WebFlightNativeStabilityHostCases.run((name,count)->{cases.add(name);assertions+=count;});
        WebFlightObservationSettleHostCases.run((name,count)->{cases.add(name);assertions+=count;});
        JSONObject report=new JSONObject().put("schema","hepta.v55-web-task-composition-host.v1").put("all_pass",true)
                .put("cases",cases.size()).put("assertions",assertions).put("case_names",new JSONArray(cases))
                .put("fixture_kind","explicit synthetic v4 DOM/native roles/ARM/NAV/clock/PM/outcome values against actual production code")
                .put("prior_case_count",43).put("legacy_dom_id_bridge_assertions_replaced",2)
                .put("terminal_lifecycle_cases_added",10).put("terminal_lifecycle_close_and_worker_inputs_synthetic",true)
                .put("flight_native_stability_replay",WebFlightNativeStabilityHostCases.provenance())
                .put("flight_readonly_observation_settle",WebFlightObservationSettleHostCases.provenance())
                .put("full_native_action_service_or_binder_executed",false).put("synthetic_profile_assignment_not_actual_webview",true)
                .put("actual_mi_dom_seen",false).put("actual_model_run_executed",false).put("binder_authenticated",false)
                .put("phone_commands_executed",0).put("actual_shopping_or_flight_result_verified",false)
                .put("business_verified",false).put("final_native_and_cleanup_gates_verified",false);
        Files.write(Paths.get(argv[0]),(report.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println("WEB_TASK_COMPOSITION_CASES="+cases.size());
        System.out.println("WEB_TASK_COMPOSITION_ASSERTIONS="+assertions);
    }
}
