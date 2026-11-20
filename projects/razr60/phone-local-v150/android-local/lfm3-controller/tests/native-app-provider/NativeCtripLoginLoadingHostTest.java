package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;

/** Actual R18 AX semantics, with the account field explicitly redacted.
 * Task/lease/NodeRef/installed identity, model and dispatch remain host doubles.
 * No Android IPC, phone, login, consent or model inference is executed. */
final class NativeCtripLoginLoadingHostTest {
    static Path fixtures;static int checks;static final List<String> names=new ArrayList<String>();
    interface Test {void run()throws Exception;}
    static void check(boolean yes,String why){checks++;if(!yes)throw new AssertionError(why);}
    static void reject(Test t,String why)throws Exception{checks++;try{t.run();}catch(IllegalArgumentException|IllegalStateException|ActionDecision.InvalidActionException expected){return;}throw new AssertionError(why);}
    static void one(String name,Test t)throws Exception{t.run();names.add(name);}
    static String hash(String text){return NativeAppEvidence.hash(text);}
    static JSONObject raw(String name)throws Exception{return new JSONObject(new String(Files.readAllBytes(fixtures.resolve(name)),StandardCharsets.UTF_8));}
    static JSONObject login()throws Exception{return raw("ctrip-login-r18-redacted.json");}
    static JSONObject loading()throws Exception{return raw("ctrip-loading-r18.json");}
    /** Synthetic identity/NodeRef/clock values around the observed public SMS
     * resources and relative layout. No captured account or phone record is
     * embedded, and the empty field is never entered or submitted. */
    static JSONObject sms(){
        JSONObject r=new JSONObject().put("package",NativeAppGoal.CTRIP_PACKAGE).put("screen_width",1224).put("screen_height",2992).put("rotation",0)
                .put("window",new JSONObject().put("type",1).put("bounds",new JSONArray(Arrays.asList(0,0,1224,2992))))
                .put("collection",new JSONObject().put("visited_nodes",22).put("retained_nodes",19).put("pending_nodes_at_stop",0)
                        .put("child_slots_omitted_by_traversal_limit",0).put("nodes_omitted_by_node_limit",0).put("nodes_omitted_by_text_limit",0));
        JSONArray ns=new JSONArray();r.put("nodes",ns);
        smsNode(ns,0,"ivTitleBarLeftBtn","ImageView","","",36,160,108,232,true);
        smsNode(ns,1,"tvTitleBarRightBtn","TextView","注册","",1098,163,1188,228,true);
        smsNode(ns,2,"tvLoginTitle","TextView","手机验证码登录","",72,405,660,526,false);
        smsNode(ns,3,"tvLoginSubTitle","TextView","未注册手机验证后即可完成注册","",72,574,618,630,false);
        smsNode(ns,4,"llCountryCode","LinearLayout","","国家码，区号86",72,853,217,906,true);
        smsNode(ns,5,"","EditText","请输入手机号","",289,832,1152,906,true).put("editable",true);
        smsNode(ns,6,"tvDoLogin","TextView","获取验证码","获取验证码按钮不可用，请先输入手机号",72,1020,1152,1152,true).put("enabled",false);
        smsNode(ns,7,"tvLeftBtn","TextView","账号密码登录","",72,1206,306,1262,true);
        smsNode(ns,8,"tvRightBtn","TextView","境外手机密码登录","",840,1206,1152,1262,true);
        smsNode(ns,9,"ivLoginWechat","ImageView","","",72,2590,216,2734,true);
        smsNode(ns,10,"ivLoginQQ","ImageView","","",288,2590,432,2734,true);
        smsNode(ns,11,"ivLoginMore","ImageView","","",504,2590,648,2734,true);
        smsNode(ns,12,"rlSelectIcon","RelativeLayout","","",72,2782,132,2842,true);
        smsNode(ns,13,"tvServiceProtocolRemark","TextView","阅读并同意携程的","",132,2788,396,2836,false);
        smsNode(ns,14,"tvServiceProtocol","TextView","《服务协议》","",396,2789,606,2836,true);
        smsNode(ns,15,"","TextView","和","",606,2788,639,2836,false);
        smsNode(ns,16,"tvServicePolicy","TextView","《个人信息保护指引》","",639,2789,975,2836,true);
        smsNode(ns,17,"tvCountryCode","TextView","+ 86","",72,853,151,906,false)
                .getJSONObject("native_tree_position").put("path","0/0/0/4/0");
        smsNode(ns,18,"ivSelectIcon","ImageView","","勾选服务协议和个人信息保护指引",81,2791,123,2833,false)
                .getJSONObject("native_tree_position").put("path","0/0/0/12/0").put("parent_class","android.widget.RelativeLayout");
        return r;
    }
    static JSONObject smsNode(JSONArray ns,int number,String id,String cls,String text,String desc,int l,int t,int r,int b,boolean click){
        JSONObject n=new JSONObject().put("id","n"+number).put("package",NativeAppGoal.CTRIP_PACKAGE).put("class_name","android.widget."+cls)
                .put("view_id",id.isEmpty()?"":"ctrip.android.view:id/"+id).put("text",text).put("description",desc).put("clickable",click)
                .put("bounds",new JSONArray(Arrays.asList(l,t,r,b))).put("node_app_tree_sha256",hash("synthetic-sms-node:"+number))
                .put("native_tree_position",new JSONObject().put("path","0/0/0/"+number).put("parent_class","android.widget.LinearLayout"))
                .put("native_selection_state",new JSONObject().put("observed",true).put("selected",false).put("checkable",false).put("checked",false));
        ns.put(n);return n;
    }
    static JSONObject node(JSONObject r,String id){JSONArray ns=r.getJSONArray("nodes");for(int i=0;i<ns.length();i++)if(id.equals(ns.getJSONObject(i).getString("id")))return ns.getJSONObject(i);throw new AssertionError(id);}
    static void remove(JSONObject r,String id){JSONArray ns=r.getJSONArray("nodes");for(int i=0;i<ns.length();i++)if(id.equals(ns.getJSONObject(i).getString("id"))){ns.remove(i);r.getJSONObject("collection").put("retained_nodes",ns.length());return;}throw new AssertionError(id);}
    static NativeAppProviderHostTest.Harness harness(String name)throws Exception{return new NativeAppProviderHostTest.Harness("login-loading:"+name);}
    static NativeAppEvidence.Frame frame(NativeAppProviderHostTest.Harness h,JSONObject r)throws Exception{
        List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>();List<NotesCompletionEvidence.Node> retained=new ArrayList<NotesCompletionEvidence.Node>();
        JSONArray rows=r.getJSONArray("nodes");
        for(int i=0;i<rows.length();i++){
            JSONObject n=rows.getJSONObject(i),pos=n.getJSONObject("native_tree_position"),sel=n.getJSONObject("native_selection_state");
            JSONArray b=n.getJSONArray("bounds");String text=n.optString("text",""),desc=n.optString("description","");
            String label=ObservedTargetLabels.project(text.isEmpty()?desc:text);
            Set<String> dirs=new TreeSet<String>();JSONArray ds=n.optJSONArray("scroll_directions");if(ds!=null)for(int k=0;k<ds.length();k++)dirs.add(ds.getString(k));
            Boolean selected=sel.optBoolean("observed")?Boolean.valueOf(sel.getBoolean("selected")):null;
            NativeAppEvidence.Node x=new NativeAppEvidence.Node(n.getString("id"),n.getString("package"),n.getString("class_name"),n.optString("view_id",""),
                    text,desc,pos.getString("path"),pos.getString("parent_class"),n.getString("node_app_tree_sha256"),label,
                    b.getInt(0),b.getInt(1),b.getInt(2),b.getInt(3),n.optBoolean("enabled",true),n.optBoolean("password"),
                    n.optBoolean("clickable"),n.optBoolean("editable"),n.optBoolean("scrollable"),selected,
                    selected==null?null:Boolean.valueOf(sel.getBoolean("checkable")),selected==null?null:Boolean.valueOf(sel.getBoolean("checked")),dirs);
            nodes.add(x);retained.add(new NotesCompletionEvidence.Node(x.id,x.packageName,x.text,x.label,x.viewId,null,new int[]{x.left,x.top,x.right,x.bottom},
                    x.editable,x.clickable,x.scrollable,x.enabled,x.password,ObservedChildText.notApplicable(),x.signature));
        }
        h.observation++;h.time+=10;String obs=hash(h.task+":redacted-AX-host:"+h.observation).substring(0,32);JSONObject w=r.getJSONObject("window");
        int width=r.getInt("screen_width"),height=r.getInt("screen_height"),type=w.getInt("type"),window=r.optInt("host_window_id",70);JSONArray bounds=w.getJSONArray("bounds");
        boolean truncated=r.optBoolean("nodes_truncated"),metadata=!r.optBoolean("host_metadata_missing");
        JSONObject counts=r.getJSONObject("collection");boolean complete=counts.getInt("retained_nodes")==nodes.size()&&counts.optInt("pending_nodes_at_stop")==0
                &&counts.optInt("child_slots_omitted_by_traversal_limit")==0&&counts.optInt("nodes_omitted_by_node_limit")==0&&counts.optInt("nodes_omitted_by_text_limit")==0;
        h.completion=new NotesCompletionEvidence.Frame(obs,r.getString("package"),window,7,NativeAppProviderHostTest.GENERATION,type,metadata,truncated,retained);
        String completionSha=TaskCompletionGate.webFrameSha(h.completion);
        if(completionSha==null)completionSha=hash("synthetic-incomplete-completion:"+obs); // unavailable metadata has no TCG completion hash
        return new NativeAppEvidence.Frame(h.task,NativeAppProviderHostTest.goal().ownerSha256,h.selected.target.targetSha256,h.auth.sha256,
                hash("synthetic-selection-wire:"+h.selected.target.targetSha256),obs,r.getString("package"),NativeAppProviderHostTest.GENERATION,
                hash("synthetic-AX-tree:"+r.toString()),hash("synthetic-AX-state:"+r.toString()),hash("synthetic-image-not-opened"),
                hash("synthetic-redacted-AX-record:"+obs+":"+r.toString()),completionSha,7,window,r.getInt("rotation"),
                width,height,bounds.getInt(0),bounds.getInt(1),bounds.getInt(2),bounds.getInt(3),h.time,truncated,complete,nodes,type,metadata);
    }
    static void observe(NativeAppProviderHostTest.Harness h,JSONObject r)throws Exception{h.frame=frame(h,r);h.session.observed(h.frame);h.gate.observed(h.completion);}
    static NativeCtripFlightPage.Page inspect(JSONObject r)throws Exception{return NativeCtripFlightPage.inspect(NativeAppProviderHostTest.goal(),frame(harness("inspect"),r));}
    static void unavailable(JSONObject r)throws Exception{NativeCtripFlightPage.Page p=inspect(r);check(NativeCtripFlightPage.UNAVAILABLE.equals(p.phase),"unsupported shape stays unavailable");check(p.form==null&&p.homeFlight==null&&p.quotes.isEmpty(),"no business fields or actions");}
    static void noEffects(NativeAppDomain d){check(d.clickIds.isEmpty()&&d.resourceClickIds.isEmpty()&&d.editValues.isEmpty()&&!d.backAllowed&&!d.resultReady,"no effect or successful result permission");}
    static void boundedReturnOnly(NativeAppDomain d){
        check(d.clickIds.equals(Collections.singleton("n0"))&&d.resourceClickIds.isEmpty()&&d.editValues.isEmpty()&&!d.backAllowed&&!d.resultReady,"only explicit return; no account, system Back or result authority");
        check(d.purposes.size()==1&&NativeCtripFlightPage.LOGIN_EXIT.equals(d.purposes.get("n0")),"Ctrip query-bound return purpose");
    }
    static ActionDecision action(NativeAppProviderHostTest.Harness h,String kind,String status,String id)throws Exception{
        JSONObject j=new JSONObject().put("action",kind).put("package",h.frame.packageName).put("observation_id",h.frame.observationId);
        if(status!=null)j.put("status",status).put("summary","synthetic host result");
        if("wait".equals(kind))j.put("milliseconds",500);
        if(id!=null)j.put("node_id",id).put("node_label",h.frame.byId.get(id).label);
        return ActionDecision.parse(j.toString(),ActionDecision.IME_ACTION_SCHEMA);
    }
    static DecisionGrammar grammar(NativeAppProviderHostTest.Harness h){
        Map<String,String> pairs=new TreeMap<String,String>();for(NativeAppEvidence.Node n:h.frame.nodes)pairs.put(n.id,n.label);
        NativeAppDomain d=h.session.domain();
        return DecisionGrammar.createImeAuthorized(h.frame.observationId,h.frame.packageName,Collections.<String>emptySet(),d.clickIds,d.editValues.keySet(),
                Collections.<String,ObservedScrollActions>emptyMap(),Collections.<String,ObservedImeEnter>emptyMap(),
                ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,h.frame.observationId,h.frame.packageName,pairs),
                ObservedAppLabels.create(ObservedAppLabels.SCHEMA,h.frame.observationId,h.frame.packageName,Collections.<String,String>emptyMap()),
                h.owner.frame(),true,d.toolMask(new HashSet<String>(Arrays.asList("click","type","back","open","scroll","submit","wait","done"))),d.resultReady);
    }
    static void query17(NativeAppProviderHostTest.Harness h)throws Exception{
        h.observe("form17.xml");h.perform("inspect_departure_year","calendar14.xml");h.perform("return_from_calendar","form17.xml");
        h.issue(h.action("query_observed_form"),true,true,false);
    }
    static void addRole(JSONObject r,String role){JSONObject x=new JSONObject(node(r,"n2").toString());x.put("id","n99").put("view_id",role).put("description",role).put("text","");
        x.getJSONObject("native_tree_position").put("path","0/9");r.getJSONArray("nodes").put(x);r.getJSONObject("collection").put("retained_nodes",r.getJSONArray("nodes").length());}
    static void denyInstalled(long version,String apk)throws Exception{
        NativeAppProviderHostTest.Harness h=harness("installed");
        reject(()->new NativeAppSession(h.task,h.owner,h.selected,new NativeAppEvidence.Installed(NativeAppGoal.CTRIP_PACKAGE,10367,version,Collections.singletonMap("base",apk)),
                hash("synthetic-selection-wire:"+h.selected.target.targetSha256),NativeAppProviderHostTest.GENERATION,7,
                new NativeAppSession.InstalledVerifier(){public void verify(){}},new NativeAppSession.Journal(){public void write(String leaf,Map<String,Object> value){}}),"exact installed identity required");
    }
    static NativeAppProviderHostTest.Harness queriedSms(String name)throws Exception{
        NativeAppProviderHostTest.Harness h=harness("sms:"+name);h.year();h.perform("query_observed_form","result14.xml");observe(h,sms());return h;
    }
    static void onlySmsReturn(NativeAppProviderHostTest.Harness h){
        NativeAppDomain d=h.session.domain();
        check(NativeCtripFlightPage.LOGIN_REQUIRED.equals(d.phase)&&d.clickIds.equals(Collections.singleton("n0"))
                &&d.resourceClickIds.equals(Collections.singleton("n0"))&&d.editValues.isEmpty()&&!d.backAllowed&&!d.resultReady,
                "only current version-bound SMS return, no account/system Back/result authority");
        check(d.purposes.size()==1&&NativeCtripFlightPage.LOGIN_EXIT.equals(d.purposes.get("n0")),"original one-return purpose");
    }
    static void smsCases()throws Exception{
        one("sms_public_structure_is_recognized_without_prior_query_or_account_action",()->{
            NativeAppProviderHostTest.Harness h=harness("sms-recognized");observe(h,sms());NativeAppDomain d=h.session.domain();
            check(NativeCtripFlightPage.LOGIN_REQUIRED.equals(d.phase)&&d.missing.contains("native_ctrip_login_requires_user_handling"),"truthful login obstruction, not unavailable");
            noEffects(d);JSONObject p=new JSONObject(d.promptEvidence()).getJSONObject("provider");
            check(p.getBoolean("requires_user_handling")&&!p.getBoolean("credentials_or_agreement_actions_available")
                    &&!p.getBoolean("public_browsing_requires_login_verified"),"no unsupported mandatory-login claim");
            check(new TreeSet<String>(grammar(h).actions).equals(new TreeSet<String>(Arrays.asList("wait","done")))&&!grammar(h).successAllowed,"unchanged incomplete-only grammar");
        });
        one("sms_disabled_code_button_is_an_observed_fact_never_an_action",()->{
            NativeAppProviderHostTest.Harness h=queriedSms("disabled");NativeAppEvidence.Node n=h.frame.byId.get("n6");
            check(h.frame.usable(n)&&!n.enabled&&n.clickable,"usable denotes provenance/bounds, not enabled capability");onlySmsReturn(h);
            reject(()->h.session.domain().requireCurrent(action(h,"click",null,"n6")),"disabled OTP request never granted");
            JSONObject r=sms();node(r,"n6").put("enabled",true);unavailable(r);
        });
        one("sms_required_ids_and_empty_field_types_are_exact",()->{
            for(String id:new String[]{"n2","n3","n4","n5","n6","n7","n8","n12","n13","n14","n16","n17","n18"}){JSONObject r=sms();remove(r,id);unavailable(r);}
            for(String key:new String[]{"view_id","class_name","text","description"}){JSONObject r=sms();node(r,"n6").put(key,"unrecognized");unavailable(r);}
            JSONObject r=sms();node(r,"n5").put("text","ARTIFICIAL_PRIVATE_ACCOUNT");unavailable(r);
            r=sms();node(r,"n5").put("editable",false);unavailable(r);
        });
        one("sms_duplicate_foreign_and_unusable_anchors_are_not_filtered_away",()->{
            for(String pkg:new String[]{NativeAppGoal.CTRIP_PACKAGE,"foreign.app"})for(String id:new String[]{"n2","n5","n6","n13"}){
                JSONObject r=sms(),copy=new JSONObject(node(r,id).toString()).put("id","n99").put("package",pkg);
                copy.getJSONObject("native_tree_position").put("path","0/0/99");r.getJSONArray("nodes").put(copy);r.getJSONObject("collection").put("retained_nodes",20);unavailable(r);
            }
            JSONObject r=sms(),copy=new JSONObject(node(r,"n6").toString()).put("id","n99");copy.getJSONObject("native_tree_position").put("path","0/0/99");
            copy.put("bounds",new JSONArray(Arrays.asList(-100,0,-1,100)));r.getJSONArray("nodes").put(copy);r.getJSONObject("collection").put("retained_nodes",20);unavailable(r);
            r=sms();node(r,"n9").put("package","foreign.app");unavailable(r);
        });
        one("sms_container_geometry_selection_and_mixed_layouts_are_rejected",()->{
            for(String id:new String[]{"n2","n6","n17","n18"}){JSONObject r=sms();node(r,id).getJSONObject("native_tree_position").put("path","0/8/2");unavailable(r);}
            JSONObject r=sms();node(r,"n6").put("bounds",node(r,"n5").getJSONArray("bounds"));unavailable(r);
            r=sms();node(r,"n6").getJSONObject("native_selection_state").put("checked",true);unavailable(r);
            r=sms();node(r,"n18").getJSONObject("native_selection_state").put("observed",false);unavailable(r);
            for(String id:new String[]{"bLoginBtn","tvPersonalizedSubtitle","tvLoginMiddle","tvCarrierServicePolicy","bt_submit_inquire","home_grid_flight_widget","calendar_month_title_left_tv"}){
                r=sms();addRole(r,"ctrip.android.view:id/"+id);unavailable(r);
            }
            for(String role:new String[]{"单程列表页","列表页头部重新搜索","单程TripSwitcherCity","单程TripSwitcherDate"}){r=sms();addRole(r,role);unavailable(r);}
        });
        one("sms_complete_owned_application_observation_remains_required",()->{
            JSONObject r=sms();r.getJSONObject("window").put("type",2);unavailable(r);
            r=sms();r.put("host_metadata_missing",true);unavailable(r);
            r=sms();r.getJSONObject("collection").put("pending_nodes_at_stop",1);unavailable(r);
            r=sms();r.put("nodes_truncated",true);unavailable(r);
            r=sms();r.put("package","foreign.app");unavailable(r);
        });
        one("sms_query_result_chain_grants_only_exact_empty_label_return_resource",()->{
            NativeAppProviderHostTest.Harness h=queriedSms("resource");onlySmsReturn(h);NativeAppDomain d=h.session.domain();
            check(h.frame.byId.get("n0").label.isEmpty()&&d.permitsResourceClick("n0"),"no inferred label");
            check(new TreeSet<String>(grammar(h).actions).equals(new TreeSet<String>(Arrays.asList("click","wait","done")))&&!grammar(h).successAllowed,"same existing grammar path");
            JSONObject resource=new JSONObject(d.promptEvidence()).getJSONObject("resource_clicks").getJSONObject("n0");
            check(resource.getString("node_label").isEmpty()&&!resource.getBoolean("visible_label_inferred")
                    &&resource.getLong("provider_version_code")==1779&&NativeCtripFlightPage.BASE_APK_SHA256.equals(resource.getString("provider_base_apk_sha256")),"actual resource provenance, no invented AX label");
            for(NativeAppEvidence.Node n:h.frame.nodes)check(NativeCtripFlightPage.resourceLoginReturnClick(h.frame,n.id)=="n0".equals(n.id),"only the unique return resource");
            d.requireCurrent(action(h,"click",null,"n0"));
        });
        one("sms_calendar_cache_pending_and_stale_query_cannot_grant_return",()->{
            for(int kind=0;kind<5;kind++){
                NativeAppProviderHostTest.Harness h=harness("sms-no-chain:"+kind);
                if(kind==1)h.year();if(kind==2)h.observe("result14.xml");
                if(kind>=3){h.year();h.issue(h.action("query_observed_form"),kind==3,kind==3,kind==4);if(kind==4)h.observe("result14.xml");}
                observe(h,sms());noEffects(h.session.domain());check(!h.gate.verified(h.completion),"no query/result proof from login");
            }
        });
        one("sms_missing_ambiguous_or_changed_return_has_no_back_fallback",()->{
            for(String key:new String[]{"text","description","class_name","view_id"}){JSONObject r=sms();node(r,"n0").put(key,"changed");NativeAppProviderHostTest.Harness h=queriedSms("return-"+key);observe(h,r);noEffects(h.session.domain());}
            JSONObject r=sms();remove(r,"n0");NativeAppProviderHostTest.Harness h=queriedSms("missing-return");observe(h,r);noEffects(h.session.domain());
            r=sms();node(r,"n0").getJSONObject("native_tree_position").put("path","0/0/1/0");h=queriedSms("moved-return");observe(h,r);noEffects(h.session.domain());
            r=sms();node(r,"n0").put("enabled",false);h=queriedSms("disabled-return");observe(h,r);noEffects(h.session.domain());
            r=sms();node(r,"n0").put("bounds",new JSONArray(Arrays.asList(800,160,872,232)));h=queriedSms("wrong-geometry");observe(h,r);noEffects(h.session.domain());
            r=sms();JSONObject copy=new JSONObject(node(r,"n0").toString()).put("id","n99");copy.getJSONObject("native_tree_position").put("path","0/0/99");r.getJSONArray("nodes").put(copy);r.getJSONObject("collection").put("retained_nodes",20);
            h=queriedSms("duplicate-return");observe(h,r);noEffects(h.session.domain());
        });
        one("sms_resource_whitelist_requires_original_phase_and_purpose",()->{
            NativeAppProviderHostTest.Harness h=queriedSms("domain");
            for(String phase:new String[]{NativeCtripFlightPage.HOME,NativeCtripFlightPage.UNAVAILABLE})reject(()->new NativeAppDomain(h.frame,phase,Collections.singleton("n0"),Collections.<String,String>emptyMap(),
                    Collections.singletonMap("n0",NativeCtripFlightPage.LOGIN_EXIT),false,NativeAppEvidence.map(),null,Collections.<String>emptyList()),"no generic unlabelled click");
            reject(()->new NativeAppDomain(h.frame,NativeCtripFlightPage.LOGIN_REQUIRED,Collections.singleton("n0"),Collections.<String,String>emptyMap(),
                    Collections.singletonMap("n0","open_flight_form"),false,NativeAppEvidence.map(),null,Collections.<String>emptyList()),"exact return purpose required");
        });
        one("sms_new_same_app_window_rebuilds_domain_without_reusing_old_node",()->{
            NativeAppProviderHostTest.Harness h=queriedSms("new-window");String old=h.frame.observationId;JSONObject r=sms().put("host_window_id",71);observe(h,r);onlySmsReturn(h);
            check(h.frame.windowId==71&&!old.equals(h.frame.observationId),"fresh same-App window actually consumed");
            ActionDecision stale=ActionDecision.parse(new JSONObject().put("action","click").put("package",h.frame.packageName).put("observation_id",old).put("node_id","n0").put("node_label","").toString(),ActionDecision.IME_ACTION_SCHEMA);
            reject(()->h.session.domain().requireCurrent(stale),"old window observation cannot act");
            ActionDecision guessed=ActionDecision.parse(new JSONObject().put("action","click").put("package",h.frame.packageName).put("observation_id",h.frame.observationId).put("node_id","n0").put("node_label","返回").toString(),ActionDecision.IME_ACTION_SCHEMA);
            reject(()->h.session.domain().requireCurrent(guessed),"empty label must not be invented");
        });
        one("sms_login_account_consent_registration_and_success_remain_unavailable",()->{
            NativeAppProviderHostTest.Harness h=queriedSms("no-account");
            for(int id=1;id<19;id++){final String name="n"+id;reject(()->h.session.domain().requireCurrent(action(h,"click",null,name)),"no non-return click");}
            ActionDecision input=ActionDecision.parse(new JSONObject().put("action","type").put("package",h.frame.packageName).put("observation_id",h.frame.observationId)
                    .put("node_id","n5").put("node_label",h.frame.byId.get("n5").label).put("text","HOST_TEST_VALUE").toString(),ActionDecision.IME_ACTION_SCHEMA);
            reject(()->h.session.domain().requireCurrent(input),"no phone/account input");
            reject(()->h.session.domain().requireCurrent(action(h,"back",null,null)),"no generic system Back");
            reject(()->h.session.domain().requireCurrent(action(h,"done","success",null)),"login/return is not completed query");
        });
        one("sms_stale_return_spends_same_once_budget_across_login_variants",()->{
            NativeAppProviderHostTest.Harness h=queriedSms("stale-return");h.issue(h.action(NativeCtripFlightPage.LOGIN_EXIT),false,false,true);observe(h,sms());noEffects(h.session.domain());
            observe(h,login());noEffects(h.session.domain());check(new JSONObject(h.session.evidence()).getJSONObject("progress").getBoolean("flight_login_exit_attempted"),"no variant-based budget reset");
            h=harness("old-spends");h.year();h.perform("query_observed_form","result14.xml");observe(h,login());h.issue(h.action(NativeCtripFlightPage.LOGIN_EXIT),false,false,true);observe(h,sms());noEffects(h.session.domain());
        });
        one("sms_return_needs_new_same_query_results_and_original_deadline",()->{
            NativeAppProviderHostTest.Harness h=queriedSms("navigation");h.issue(h.action(NativeCtripFlightPage.LOGIN_EXIT),true,true,false);h.observe("result14.xml");
            JSONObject p=new JSONObject(h.session.evidence()).getJSONObject("progress");check(p.isNull("pending")&&"2026-11-14".equals(p.getString("last_query_date"))&&!h.gate.verified(h.completion),"return navigation does not create desired-date query");
            observe(h,sms());noEffects(h.session.domain());
            NativeAppProviderHostTest.Harness timed=queriedSms("deadline");timed.issue(timed.action(NativeCtripFlightPage.LOGIN_EXIT),true,true,false);timed.time+=15001;timed.observe("result14.xml");reject(()->timed.session.domain(),"original transition deadline unchanged");
            NativeAppProviderHostTest.Harness target=harness("sms-target");query17(target);target.observe("result17.xml");observe(target,sms());onlySmsReturn(target);
            target.issue(target.action(NativeCtripFlightPage.LOGIN_EXIT),true,true,false);target.observe("result17.xml");check(target.gate.verified(target.completion),"only original actual target-query+fresh complete-card proof may complete");
            target.claim();check(NativeAppProviderHostTest.passed(target.normal()),"original terminal cleanup/normal0 proof still required");
        });
        one("sms_installed_identity_and_retired_session_checks_still_run",()->{
            NativeAppProviderHostTest.Harness h=queriedSms("installed");h.installedCurrent=false;reject(()->h.issue(h.action(NativeCtripFlightPage.LOGIN_EXIT),true,true,false),"installed bytes rechecked at action");
            NativeAppProviderHostTest.Harness retired=queriedSms("retired");ActionDecision a=retired.action(NativeCtripFlightPage.LOGIN_EXIT);retired.session.retire();reject(()->retired.issue(a,true,true,false),"retired task cannot act");
        });
        one("sms_profile_full_uid_and_current_owned_window_remain_required",()->{
            NativeCtripLoginExitHostTest.ProfileHarness h=new NativeCtripLoginExitHostTest.ProfileHarness("sms-valid");h.queried();NativeAppEvidence.Frame f=frame(h.raw,sms());h.accept(f,h.window(f.capturedElapsedMs));
            check(h.frame.profileWindow.fullUid==1010367&&h.session.domain().resourceClickIds.equals(Collections.singleton("n0")),"same profile/current window bound resource");
            h.issue(NativeCtripFlightPage.LOGIN_EXIT);h.xml("result14.xml");check(!h.gate.verified(h.raw.completion),"profile return never makes wrong-date query succeed");
            NativeCtripLoginExitHostTest.ProfileHarness absent=new NativeCtripLoginExitHostTest.ProfileHarness("sms-no-window");absent.queried();NativeAppEvidence.Frame missing=frame(absent.raw,sms());
            reject(()->absent.accept(missing,null),"no profile window proof");
            NativeCtripLoginExitHostTest.ProfileHarness other=new NativeCtripLoginExitHostTest.ProfileHarness("sms-foreign-profile");other.queried();NativeAppEvidence.Frame bad=frame(other.raw,sms());
            org.trillionnium.hepta.background.WindowOwnership w=other.window(NativeCtripLoginExitHostTest.profile(11,11),500,400,"12345678-1234-4234-8234-123456789aaa",bad.capturedElapsedMs);
            reject(()->other.accept(bad,w),"foreign profile/full UID cannot authorize return");
        });
    }
    public static void main(String[] args)throws Exception{
        fixtures=Paths.get(args[0]);NativeAppProviderHostTest.fixtures=fixtures;Path output=Paths.get(args[1]);
        one("actual_redacted_login_ax_recognized_without_any_effect_or_result",()->{
            NativeAppProviderHostTest.Harness h=harness("actual");observe(h,login());check(NativeCtripFlightPage.LOGIN_REQUIRED.equals(h.session.domain().phase),"observed login phase");
            noEffects(h.session.domain());check(h.session.domain().missing.contains("native_ctrip_login_requires_user_handling"),"truthful blocker");
            check(!h.gate.verified(h.completion),"not a flight result");
            JSONObject view=new JSONObject(h.session.domain().promptEvidence()).getJSONObject("provider");
            check(view.getBoolean("requires_user_handling")&&!view.getBoolean("credentials_or_agreement_actions_available"),"public obstruction without account actions");
        });
        one("account_value_does_not_participate_in_recognition_or_public_projection",()->{
            JSONObject r=login();node(r,"n1").put("text","[SECOND ARTIFICIAL ACCOUNT]").put("description","[SECOND ARTIFICIAL ACCOUNT]");
            NativeAppProviderHostTest.Harness h=harness("redaction");observe(h,r);check(NativeCtripFlightPage.LOGIN_REQUIRED.equals(h.session.domain().phase),"account independent");
            check(!new JSONObject(h.session.domain().promptEvidence()).toString().contains("SECOND ARTIFICIAL ACCOUNT"),"no account field projected");
        });
        one("login_exact_authorized_grammar_only_wait_and_incomplete_done",()->{
            NativeAppProviderHostTest.Harness h=harness("grammar");observe(h,login());DecisionGrammar g=grammar(h);
            check(g.actions.size()==2&&new TreeSet<String>(g.actions).equals(new TreeSet<String>(Arrays.asList("wait","done")))&&!g.successAllowed,"no effect grammar or success");
            h.session.domain().requireCurrent(action(h,"done","partial",null));h.session.domain().requireCurrent(action(h,"done","failure",null));
        });
        one("login_button_agreement_return_and_done_success_are_refused",()->{
            NativeAppProviderHostTest.Harness h=harness("reject-actions");observe(h,login());
            for(String id:new String[]{"n0","n3","n4","n5","n7","n9","n11"})reject(()->h.session.domain().requireCurrent(action(h,"click",null,id)),"no login or agreement or return click");
            reject(()->h.session.domain().requireCurrent(action(h,"back",null,null)),"no back");
            reject(()->h.session.domain().requireCurrent(action(h,"done","success",null)),"no success");
        });
        one("login_foreign_package_is_not_recognized",()->{JSONObject r=login();r.put("package","foreign.app");unavailable(r);});
        one("login_foreign_owner_is_not_recognized",()->{NativeAppProviderHostTest.Harness h=harness("owner");NativeAppEvidence.Frame f=frame(h,login());check(NativeCtripFlightPage.UNAVAILABLE.equals(NativeCtripFlightPage.inspect(NativeAppProviderHostTest.goal(),NativeAppProviderHostTest.altered(f,hash("foreign"),f.targetSha,f.generation,true,false)).phase),"owner required");});
        one("login_wrong_installed_version_is_refused",()->denyInstalled(1778,NativeCtripFlightPage.BASE_APK_SHA256));
        one("login_wrong_installed_apk_is_refused",()->denyInstalled(1779,hash("different-apk")));
        one("login_installed_identity_rechecked_before_observation",()->{NativeAppProviderHostTest.Harness h=harness("installed-recheck");h.installedCurrent=false;reject(()->observe(h,login()),"installed reread");});
        one("login_nonapplication_window_is_unavailable",()->{JSONObject r=login();r.getJSONObject("window").put("type",2);unavailable(r);});
        one("login_unknown_window_metadata_is_unavailable",()->{JSONObject r=login();r.put("host_metadata_missing",true);unavailable(r);});
        one("login_incomplete_collection_is_unavailable",()->{JSONObject r=login();r.getJSONObject("collection").put("pending_nodes_at_stop",1);unavailable(r);});
        one("login_truncated_collection_is_unavailable",()->{JSONObject r=login();r.put("nodes_truncated",true);unavailable(r);});
        one("each_required_login_anchor_is_required",()->{for(String id:new String[]{"n2","n3","n4","n5","n6","n7","n9","n11","n13"}){JSONObject r=login();remove(r,id);unavailable(r);}});
        one("login_wrong_resource_text_or_class_is_unavailable",()->{for(String key:new String[]{"view_id","text","class_name"}){JSONObject r=login();node(r,"n3").put(key,"unrecognized");unavailable(r);}});
        one("duplicate_and_foreign_duplicate_login_anchors_are_not_silently_ignored",()->{for(String pkg:new String[]{NativeAppGoal.CTRIP_PACKAGE,"foreign.app"}){JSONObject r=login();JSONObject n=new JSONObject(node(r,"n3").toString()).put("id","n99").put("package",pkg);n.getJSONObject("native_tree_position").put("path","0/0/99");r.getJSONArray("nodes").put(n);r.getJSONObject("collection").put("retained_nodes",15);unavailable(r);}});
        one("offscreen_login_anchor_is_unavailable",()->{JSONObject r=login();node(r,"n3").getJSONArray("bounds").put(0,-1);unavailable(r);});
        one("disabled_password_editable_scrollable_and_selection_changes_are_unavailable",()->{
            for(String key:new String[]{"enabled","password","editable","scrollable","clickable"}){JSONObject r=login();node(r,"n3").put(key,!"enabled".equals(key)&&!"clickable".equals(key));unavailable(r);}
            for(String key:new String[]{"selected","checkable","checked"}){JSONObject r=login();node(r,"n13").getJSONObject("native_selection_state").put(key,true);unavailable(r);}
        });
        one("missing_selection_tuple_cannot_recognize_login",()->{JSONObject r=login();node(r,"n13").getJSONObject("native_selection_state").put("observed",false);unavailable(r);});
        one("login_anchors_require_same_observed_scroll_container",()->{JSONObject r=login();node(r,"n4").getJSONObject("native_tree_position").put("path","0/1/6");unavailable(r);});
        one("login_agreement_indicator_requires_same_parent_and_bounds",()->{JSONObject r=login();node(r,"n13").getJSONObject("native_tree_position").put("path","0/0/15/0");unavailable(r);});
        one("overlapping_login_controls_are_unavailable",()->{JSONObject r=login();node(r,"n4").put("bounds",node(r,"n3").getJSONArray("bounds"));unavailable(r);});
        one("login_mixed_with_flight_form_result_home_or_calendar_is_unavailable",()->{
            for(String role:new String[]{"ctrip.android.view:id/bt_submit_inquire","单程列表页","ctrip.android.view:id/home_grid_flight_widget","ctrip.android.view:id/calendar_month_title_left_tv"}){JSONObject r=login();addRole(r,role);unavailable(r);}
        });
        one("unknown_page_does_not_gain_login_or_flight_capability",()->{JSONObject r=login();JSONArray rows=new JSONArray().put(node(r,"n0"));r.put("nodes",rows);r.getJSONObject("collection").put("retained_nodes",1);unavailable(r);});
        one("pending_query_login_reports_blocker_without_creating_query_or_result",()->{
            NativeAppProviderHostTest.Harness h=harness("pending-login");query17(h);observe(h,login());
            check(NativeCtripFlightPage.LOGIN_REQUIRED.equals(h.session.domain().phase),"login overrides pending projection");noEffects(h.session.domain());check(!h.gate.verified(h.completion),"login is not query result");
        });
        one("pending_login_done_and_final_observation_keep_query_unproved",()->{
            for(String status:new String[]{"partial","failure"}){
                NativeAppProviderHostTest.Harness h=harness("pending-done:"+status);query17(h);observe(h,login());
                h.issue(action(h,"done",status,null),true,false,false);observe(h,login());
                check(NativeCtripFlightPage.LOGIN_REQUIRED.equals(h.session.domain().phase),"final current login still reported");noEffects(h.session.domain());
                JSONObject progress=new JSONObject(h.session.evidence()).getJSONObject("progress");
                check(progress.isNull("last_query_date")&&!progress.isNull("pending"),"login and incomplete done never close the query transition");
                check(!h.gate.verified(h.completion)&&!NativeAppProviderHostTest.passed(h.normal()),"normal cleanup cannot make blocked query a completed flight search");
            }
        });
        one("pending_login_preserves_original_transition_deadline",()->{
            NativeAppProviderHostTest.Harness h=harness("pending-login-deadline");query17(h);observe(h,login());h.time+=15001;observe(h,login());
            reject(()->h.session.domain(),"expired original query transition remains invalid");
            JSONObject evidence=new JSONObject(h.session.evidence());
            check(evidence.getBoolean("invalid")&&"actual_native_transition_observation_deadline".equals(evidence.getString("invalid_reason")),"original deadline not extended by login recognition");
            check(evidence.getJSONObject("progress").isNull("last_query_date")&&!h.gate.verified(h.completion),"no query proof or result after deadline");
        });
        one("actual_query_loading_page_has_date_strip_but_no_complete_card",()->{NativeCtripFlightPage.Page p=inspect(loading());check(NativeCtripFlightPage.RESULTS.equals(p.phase)&&p.quotes.isEmpty(),"actual loading results retained");check(java.time.LocalDate.of(2026,11,17).equals(p.displayedMonthDay(java.time.LocalDate.of(2026,11,17))),"actual date rail retained");});
        one("same_target_query_proof_with_empty_cards_waits_without_requery_back",()->{
            NativeAppProviderHostTest.Harness h=harness("loading");query17(h);observe(h,loading());NativeAppDomain d=h.session.domain();noEffects(d);
            check(d.missing.contains("native_target_query_waiting_for_complete_cards")&&!d.missing.contains("target_date_form_and_explicit_query_required"),"missing cards not missing query");
            JSONObject v=new JSONObject(d.promptEvidence()).getJSONObject("provider");check("2026-11-17".equals(v.getString("last_explicit_query_date")),"query proof preserved");
            check(grammar(h).actions.size()==2&&new TreeSet<String>(grammar(h).actions).equals(new TreeSet<String>(Arrays.asList("wait","done")))&&!grammar(h).successAllowed,"only incomplete continuation");
        });
        one("complete_cards_after_loading_can_complete_without_a_second_query",()->{
            NativeAppProviderHostTest.Harness h=harness("loading-complete");query17(h);observe(h,loading());h.observe("result17.xml");
            check(h.session.domain().resultReady&&h.gate.verified(h.completion),"same original target query plus complete cards");check(h.target("query_observed_form")==null,"no duplicate query grant");
        });
        one("loading_without_same_task_query_proof_keeps_original_back_requirement",()->{
            NativeAppProviderHostTest.Harness h=harness("no-proof");observe(h,loading());check(h.session.domain().backAllowed&&h.session.domain().missing.contains("same_task_explicit_query_missing"),"no proof still requires form");check(!h.session.domain().resultReady,"no unproved result");
        });
        one("non_target_query_then_target_result_date_still_requires_target_form_query",()->{
            NativeAppProviderHostTest.Harness h=harness("wrong-query-date");h.year();h.perform("query_observed_form","result14.xml");observe(h,loading());
            check(h.session.domain().backAllowed&&h.session.domain().missing.contains("target_date_form_and_explicit_query_required"),"non-target proof cannot be upgraded");check(!h.session.domain().resultReady,"no result");
        });
        one("target_query_with_wrong_current_result_date_keeps_date_navigation",()->{
            NativeAppProviderHostTest.Harness h=harness("wrong-shown");query17(h);h.observe("result17.xml");h.observe("result14.xml");
            check(!h.session.domain().resultReady&&!h.session.domain().missing.contains("native_target_query_waiting_for_complete_cards"),"wrong current date not treated as target loading");
            boolean nav=false;for(String p:h.session.domain().purposes.values())if(p.startsWith("navigate_departure_date:"))nav=true;check(nav,"original bounded date navigation retained");
        });
        one("stale_undispatched_query_never_becomes_target_loading_proof",()->{
            NativeAppProviderHostTest.Harness h=harness("stale-query");h.observe("form17.xml");h.perform("inspect_departure_year","calendar14.xml");h.perform("return_from_calendar","form17.xml");
            h.issue(h.action("query_observed_form"),false,false,true);observe(h,loading());
            check(!h.session.domain().resultReady&&h.session.domain().missing.contains("same_task_explicit_query_missing"),"stale proposal creates no query proof");
        });
        one("complete_cards_without_query_proof_remain_unverified",()->{NativeAppProviderHostTest.Harness h=harness("cached-cards");h.observe("result17.xml");check(!h.session.domain().resultReady&&h.session.domain().backAllowed,"complete cached quotes are not task completion");});
        one("loading_then_login_has_only_bounded_return_without_result",()->{NativeAppProviderHostTest.Harness h=harness("loading-login");query17(h);observe(h,loading());observe(h,login());check(NativeCtripFlightPage.LOGIN_REQUIRED.equals(h.session.domain().phase),"real observed next phase");boundedReturnOnly(h.session.domain());});
        one("login_revokes_previously_ready_flight_cards",()->{NativeAppProviderHostTest.Harness h=harness("ready-login");h.ready();observe(h,login());boundedReturnOnly(h.session.domain());check(!h.gate.verified(h.completion),"login cannot reuse prior result");});
        one("incomplete_loading_observation_never_receives_result_or_navigation",()->{NativeAppProviderHostTest.Harness h=harness("incomplete-loading");query17(h);JSONObject r=loading();r.put("nodes_truncated",true);observe(h,r);noEffects(h.session.domain());check(!h.gate.verified(h.completion),"incomplete post-query frame no result");});
        smsCases();
        Map<String,Object> out=NativeAppEvidence.map();out.put("schema","hepta.native-ctrip-login-loading-host.v1");out.put("all_pass",true);
        out.put("case_names",names);out.put("cases",names.size());out.put("assertions",checks);out.put("phone_operations",0);out.put("android_runtime",false);
        out.put("model_executed",false);out.put("business_verified",false);out.put("account_field_artificially_redacted",true);
        Files.write(output,(new JSONObject(out).toString(2)+"\n").getBytes(StandardCharsets.UTF_8));System.out.println("ctrip login/loading "+names.size()+" cases / "+checks+" assertions");
    }
}
