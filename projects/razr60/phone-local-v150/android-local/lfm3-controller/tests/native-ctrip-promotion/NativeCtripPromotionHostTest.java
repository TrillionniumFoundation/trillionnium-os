package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import org.json.*;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.WindowOwnership;
import org.trillionnium.hepta.local.NativeCtripDateReservationHostTest.Harness;

final class NativeCtripPromotionHostTest {
    static final String OWNER="在携程查询2026年11月24日北京到上海的单程机票，1名成人，读取航班列表中可见的航班时间、航司和价格。只查询，不预订、不支付。";
    static final String SHA="dcb1cdd9fc05c98a339f652f0fa2a866c4feef740786bf4a3cb7453757783578";
    static final String CLOSE=NativeCtripFlightPage.CLOSE_PROMOTION;
    static final String PKG=NativeCtripFlightPage.PACKAGE;
    static final Set<String> CLOSE_TOOLS=new TreeSet<String>(Arrays.asList("click","done"));
    static JSONObject original;
    static ObservationCaptureEvidence sealed;
    static int assertions;
    static void check(boolean yes,String why){assertions++;if(!yes)throw new AssertionError(why);}
    interface Operation{void run()throws Exception;}
    static void reject(Operation op,String why)throws Exception{
        try{op.run();}catch(IllegalArgumentException|IllegalStateException|ActionDecision.InvalidActionException expected){assertions++;return;}
        throw new AssertionError(why);
    }

    // The eight actually visited nodes include four retained controls. Preserve all
    // of their public semantic fields. The DateReservation harness below supplies
    // synthetic model decisions, stable task ownership and clock for transition tests.
    static JSONObject projected() {
        JSONObject census=original.getJSONObject("first"),binding=original.getJSONObject("binding");
        JSONArray out=new JSONArray(), nodes=census.getJSONArray("nodes");
        for(int i=0;i<nodes.length();i++){
            JSONObject n=nodes.getJSONObject(i);
            if(n.isNull("label"))continue;
            JSONObject row=new JSONObject().put("id","n"+out.length()).put("package",n.getString("package"))
                    .put("class_name",n.getString("class")).put("node_app_tree_sha256",n.getString("ref_signature_sha256"))
                    .put("native_tree_position",new JSONObject().put("path",n.getString("path")).put("parent_class",n.getString("parent_class")))
                    .put("native_selection_state",new JSONObject().put("observed",true).put("selected",n.getBoolean("selected"))
                            .put("checkable",n.getBoolean("checkable")).put("checked",n.getBoolean("checked")));
            for(String key:Arrays.asList("bounds","view_id","text","description","enabled","password","clickable","editable","scrollable"))
                row.put(key,n.get(key));
            if(!"hepta.observed-scroll-actions.v1|observed".equals(n.getString("scroll_actions")))
                throw new AssertionError("unexpected action in recorded scroll census");
            out.put(row);
        }
        return new JSONObject().put("package",PKG).put("screen_width",binding.getInt("width")).put("screen_height",binding.getInt("height"))
                .put("rotation",binding.getInt("rotation")).put("window_id",binding.getInt("window_id"))
                .put("window",new JSONObject().put("type",1).put("bounds",new JSONArray(Arrays.asList(binding.getInt("left"),
                        binding.getInt("top"),binding.getInt("right"),binding.getInt("bottom")))))
                .put("app_tree_sha256",binding.getString("app_tree_sha256")).put("observation_state_sha256",binding.getString("observation_state_sha256"))
                .put("collection",new JSONObject().put("visited_nodes",census.getInt("visited")).put("retained_nodes",census.getInt("retained"))
                        .put("pending_nodes_at_stop",census.getInt("pending"))).put("nodes",out);
    }
    static void originalAx(Harness h)throws Exception{
        JSONObject b=original.getJSONObject("binding"),w=b.getJSONObject("profile_window");
        ProfileTarget p=h.profile;
        WindowOwnership ownership=new WindowOwnership(p,b.getString("background_generation"),b.getInt("display_id"),b.getInt("window_id"),
                w.getInt("task_id"),w.getInt("parent_task_id"),w.getString("task_token_id"),w.getString("proof_id"),
                w.getInt("user_id"),w.getLong("user_serial"),w.getInt("full_uid"),w.getLong("observed_elapsed_ms"),w.getLong("expires_elapsed_ms"));
        NativeAppEvidence.Frame shape=NativeCtripLoginLoadingHostTest.frame(h.parser,projected());
        NativeAppEvidence.Frame frame=new NativeAppEvidence.Frame(b.getString("task_id"),b.getString("owner_sha256"),
                b.getString("execution_target_sha256"),b.getString("task_authorization_sha256"),b.getString("actual_selection_sha256"),
                b.getString("observation_id"),PKG,b.getString("background_generation"),b.getString("app_tree_sha256"),
                b.getString("observation_state_sha256"),null,SHA,shape.completionFrameSha,b.getInt("display_id"),b.getInt("window_id"),
                shape.rotation,shape.width,shape.height,shape.left,shape.top,shape.right,shape.bottom,b.getLong("captured_elapsed_ms"),
                shape.nodesTruncated,shape.collectionComplete,shape.nodes,shape.windowType,shape.metadataObserved,ownership,sealed);
        NativeAppGoal goal=NativeAppGoal.parse(OWNER,PKG);
        check(goal!=null&&goal.ownerSha256.equals(frame.ownerSha),"exact original owner");
        sealed.requireBinding(Collections.<String,Object>singletonMap("native_goal_sha256",goal.contractSha256));
        check(frame.capture.nativeText()&&!frame.capture.formHistory()&&frame.screenshotSha==null,"retained original native AX evidence");
        check(NativeCtripFlightPage.PROMOTION.equals(NativeCtripFlightPage.inspect(goal,frame).phase),"original managed native AX promotion");
        check(NativeCtripFlightPage.resourcePromotionCloseClick(frame,"n1"),"actual close");
    }
    static JSONObject withClock(JSONObject r,Harness h,long at){
        r.put("captured_elapsed_ms",at).put("observation_id",NativeCtripDateReservationHostTest.id(h.name+":"+ ++h.cloneId));
        if(r.isNull("screen_sha256"))r.put("screen_sha256",NativeAppEvidence.hash("synthetic test image"));
        return r;
    }
    static void observe(Harness h,JSONObject r)throws Exception{h.observe(withClock(r,h,h.time+100));}
    static Harness fresh(String label)throws Exception{
        Harness h=new Harness(label);h.time=5000;observe(h,projected());return h;
    }
    static void propose(Harness h)throws Exception{h.begin(CLOSE,h.time+1,NativeCtripDateReservationHostTest.id(h.name+":model"));}
    static ActionDecision action(Harness h,String tool,String node,String status)throws Exception{
        JSONObject j=new JSONObject().put("action",tool).put("package",PKG).put("observation_id",h.frame.observationId);
        if(node!=null)j.put("node_id",node).put("node_label",h.frame.byId.get(node).label);
        if("wait".equals(tool))j.put("milliseconds",250);
        if(status!=null)j.put("status",status).put("summary","bounded host case");
        return ActionDecision.parse(j.toString(),ActionDecision.IME_ACTION_SCHEMA);
    }
    static JSONObject node(JSONObject r,String id){return NativeCtripLoginLoadingHostTest.node(r,id);}
    static void denied(Harness h,JSONObject changed)throws Exception{
        observe(h,changed);NativeAppDomain d=h.session.domain();
        check(d.clickIds.isEmpty()&&d.resourceClickIds.isEmpty()&&!d.backAllowed&&!d.resultReady,"mutated surface cannot grant clicks");
    }
    static void incomplete(Harness h,JSONObject changed)throws Exception{
        NativeAppEvidence.Frame f=NativeCtripLoginLoadingHostTest.frame(h.parser,changed);
        check(NativeCtripFlightPage.promotionClose(f)==null&&NativeCtripFlightPage.UNAVAILABLE.equals(
                NativeCtripFlightPage.inspect(NativeAppProviderHostTest.goal(),f).phase),"incomplete or foreign window admission refused");
    }
    static NativeAppEvidence.Frame successor(Harness h,NativeAppEvidence.Frame shape,boolean otherLeaf,long time){
        WindowOwnership src=h.frame.profileWindow;
        WindowOwnership w=new WindowOwnership(h.profile,src.generation,src.displayId,src.windowId,
                otherLeaf?src.taskId+1:src.taskId,src.parentTaskId,src.taskTokenId,src.proofId,src.userId,src.userSerial,src.fullUid,time-1,time+1000);
        return new NativeAppEvidence.Frame(h.frame.taskId,h.frame.ownerSha,h.frame.targetSha,h.frame.authorizationSha,h.frame.selectionSha,
                NativeCtripDateReservationHostTest.id(h.name+":new:"+ ++h.cloneId),PKG,src.generation,shape.treeSha,shape.stateSha,
                shape.screenshotSha,shape.sourceRecordSha,shape.completionFrameSha,src.displayId,src.windowId,shape.rotation,shape.width,shape.height,
                shape.left,shape.top,shape.right,shape.bottom,time,false,true,shape.nodes,1,true,w);
    }
    static void verify()throws Exception{
        Harness h=fresh("surface");originalAx(h);
        NativeAppDomain d=h.session.domain();
        check(d.clickIds.equals(Collections.singleton("n1"))&&d.resourceClickIds.equals(d.clickIds),"unique, unlabeled resource");
        check(d.toolMask(null).equals(CLOSE_TOOLS)&&!d.resultReady&&!d.backAllowed&&d.editValues.isEmpty(),"model may close or finish incomplete");
        d.requireCurrent(h.action(CLOSE));
        for(String id:Arrays.asList("n0","n2","n3"))reject(()->d.requireCurrent(action(h,"click",id,null)),"no ad or reward action");
        for(String tool:Arrays.asList("back","wait"))reject(()->d.requireCurrent(action(h,tool,null,null)),"no fallback or wait loop");
        reject(()->d.requireCurrent(action(h,"done",null,"success")),"no success");
        d.requireCurrent(action(h,"done",null,"failure"));
        check(!h.progress().getBoolean("flight_promotion_close_attempted"),"recognition never dispatches");
        ActionDecision old=h.action(CLOSE);observe(h,projected());reject(()->h.session.domain().requireCurrent(old),"prior observation rejected");
        h.installedCurrent=false;reject(()->propose(h),"installed verifier runs");h.installedCurrent=true;
        propose(h);reject(()->h.session.beforeModelAction(4,h.proposed,NativeCtripDateReservationHostTest.id("other model"),h.time+1),"inflight never reused");h.outcome(true,true,false,null,h.time+1);
        observe(h,projected());check(!h.progress().isNull("pending")&&h.session.domain().clickIds.isEmpty(),"same overlay is not dismissal");
        observe(h,NativeCtripDateReservationHostTest.raw(NativeCtripDateReservationHostTest.RESULT));
        check(!h.progress().isNull("pending")&&!h.session.domain().resultReady,"cached flight results cannot complete close");
        JSONObject destination=NativeCtripDateReservationHostTest.raw(NativeCtripDateReservationHostTest.FORM);
        observe(h,destination);
        JSONObject proof=h.progress().getJSONArray("transitions").getJSONObject(0);
        check(h.progress().isNull("pending")&&proof.getBoolean("navigation_only")&&!proof.getBoolean("query_or_result_proof_created")
                &&!proof.getBoolean("business_transition_verified")&&!h.session.domain().resultReady,"fresh verified form, navigation only");
        check(h.session.domain().purposes.containsValue("inspect_departure_year")&&h.progress().isNull("last_query_date"),"normal flight tools can continue");
        observe(h,projected());check(h.session.domain().clickIds.isEmpty(),"one-use even if promotion returns");
        Harness home=fresh("home");propose(home);home.outcome(true,true,false,null,home.time+1);
        NativeAppEvidence.Frame homeShape=home.parser.frame("home.xml");
        home.session.observed(successor(home,homeShape,false,home.time));
        check(!home.progress().isNull("pending"),"identical wall clock cannot establish a new destination");
        home.session.observed(successor(home,homeShape,true,home.time+1));
        check(!home.progress().isNull("pending")&&home.session.domain().clickIds.isEmpty(),"different leaf under the same profile cannot close navigation");
        home.session.observed(successor(home,homeShape,false,home.time+2));
        check(home.progress().isNull("pending")&&home.session.domain().purposes.containsValue("open_flight_form")
                &&!home.session.domain().resultReady,"fresh same-owner home allows only normal subsequent navigation");
        Harness stale=fresh("stale");propose(stale);stale.outcome(false,false,true,null,stale.time+1);observe(stale,projected());
        check(stale.session.domain().clickIds.isEmpty(),"stale proposal remains consumed");
        Harness timeout=fresh("timeout");propose(timeout);timeout.outcome(true,true,false,null,timeout.time+1);timeout.time+=15001;
        observe(timeout,NativeCtripDateReservationHostTest.raw(NativeCtripDateReservationHostTest.FORM));
        reject(()->timeout.session.domain(),"original deadline is binding");
        Harness before=fresh("post-query");before.prime();observe(before,projected());check(before.session.domain().clickIds.isEmpty(),"not granted post-query");
        NativeAppProviderHostTest.Harness user0=NativeCtripLoginLoadingHostTest.harness("unbound");
        NativeCtripLoginLoadingHostTest.observe(user0,projected());check(user0.session.domain().clickIds.isEmpty(),"no user0 grant");
        NativeCtripLoginExitHostTest.ProfileHarness signer=new NativeCtripLoginExitHostTest.ProfileHarness("wrong-signer");
        NativeAppEvidence.Frame f=NativeCtripLoginLoadingHostTest.frame(signer.raw,projected());signer.accept(f,signer.window(f.capturedElapsedMs));
        check(signer.session.domain().clickIds.isEmpty(),"different managed installation signer");
        Harness negative=fresh("shape");
        for(String id:Arrays.asList("n0","n1","n2","n3")){
            JSONObject r=projected();NativeCtripLoginLoadingHostTest.remove(r,id);denied(negative,r);
        }
        for(String key:Arrays.asList("view_id","description","text","class_name","package")){
            JSONObject r=projected();node(r,"n1").put(key,"other");denied(negative,r);
        }
        for(String key:Arrays.asList("selected","checkable","checked")){
            JSONObject r=projected();node(r,"n1").getJSONObject("native_selection_state").put(key,true);denied(negative,r);
        }
        for(String key:Arrays.asList("enabled","clickable","editable","password","scrollable")){
            JSONObject r=projected();node(r,"n1").put(key,!key.equals("enabled")&&!key.equals("clickable"));denied(negative,r);
        }
        for(String id:Arrays.asList("n2","n3")){
            JSONObject r=projected();node(r,id).put("clickable",true);denied(negative,r);
            r=projected();node(r,id).getJSONObject("native_tree_position").put("path","0/0/9");denied(negative,r);
        }
        JSONObject r=projected();node(r,"n1").put("bounds",node(r,"n3").getJSONArray("bounds"));denied(negative,r);
        r=projected();JSONObject duplicate=new JSONObject(node(r,"n1").toString()).put("id","n4");
        duplicate.getJSONObject("native_tree_position").put("path","0/0/9");r.getJSONArray("nodes").put(duplicate);
        r.getJSONObject("collection").put("retained_nodes",5);denied(negative,r);
        r=projected();r.put("nodes_truncated",true);incomplete(negative,r);
        r=projected();r.getJSONObject("collection").put("pending_nodes_at_stop",1);denied(negative,r);
        r=projected();r.getJSONObject("window").put("type",2);incomplete(negative,r);
    }
    public static void main(String[] args)throws Exception{
        Path fixtures=Paths.get(args[0]);NativeAppProviderHostTest.fixtures=fixtures;
        NativeCtripLoginLoadingHostTest.fixtures=fixtures;NativeCtripDateReservationHostTest.fixtures=fixtures;
        byte[] bytes=Files.readAllBytes(fixtures.resolve("ctrip-startup-promotion-native-ax.json"));
        original=new JSONObject(new String(bytes,StandardCharsets.UTF_8));
        sealed=ObservationCaptureEvidence.fromSealedNativeAx(original.toMap(),bytes,SHA);
        check(original.getJSONObject("first").getInt("visited")==8&&original.getJSONObject("first").getInt("retained")==4,"full actual census");
        verify();
        System.out.println("Ctrip startup promotion passed; host assertions="+assertions+"; model and Android dispatch simulated");
    }
}
