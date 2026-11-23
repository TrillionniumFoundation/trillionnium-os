package org.trillionnium.hepta.local;

import android.net.LocalSocket;
import android.os.SystemClock;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.JSONObject;
import org.trillionnium.hepta.background.WindowOwnership;

/** Actual price XML and production goal/permission/domain/terminal. Profile
 * transport, timestamps, model decisions and outcome callbacks are host fixtures. */
public final class NativeXiaomiBudgetPreviewHostTest {
    static final String AUDIT="在小米商城买1台小米路由器AX3000T，预算不超过200元，核对商品、数量和总额后停在订单确认页，不提交，不支付";
    static final String NATURAL="在小米商城给 AX3000T（白色）1件，核价，预算200元，若金额在预算内就准备到确认页停下，不提交订单、不支付。";
    static final String MI=NativeAppGoal.XIAOMI_PACKAGE;
    static final List<Map<String,Object>> results=new ArrayList<Map<String,Object>>();static int assertions;
    static Path fixtures;
    interface Work{void run()throws Exception;}
    static void check(boolean ok,String reason){assertions++;if(!ok)throw new AssertionError(reason);}
    static void one(String name,Work work){int start=assertions;SystemClock.now=1000000;LocalSocket.reset();Map<String,Object> r=new LinkedHashMap<String,Object>();
        try{work.run();r.put("passed",true);}catch(Throwable e){e.printStackTrace();r.put("passed",false);r.put("error",e.toString());}
        r.put("name",name);r.put("assertions",assertions-start);results.add(r);}
    static String id(){return UUID.randomUUID().toString().replace("-","");}
    static String sha(String s){return NativeAppEvidence.hash(s);}
    static final class Harness implements AutoCloseable{
        final NativeProfileIdentityHostTest.Env env;final NativeAppSession task;final TaskAuthorization.Gate auth;
        final TaskCompletionGate completion;final String selection,token=UUID.randomUUID().toString();
        NativeAppEvidence.Frame frame;NotesCompletionEvidence.Frame retained;int step;
        Harness(String owner)throws Exception{
            env=new NativeProfileIdentityHostTest.Env(NativeProfileIdentityHostTest.xiaomi(),owner);env.active();
            TaskAuthorization bound=TaskAuthorization.parse(owner).forExecutionSelection(env.session.selection);auth=bound.bind(NativeProfileIdentityHostTest.TASK);
            selection=NativeAppObservation.selectionSha(env.session.selection);
            task=new NativeAppSession(NativeProfileIdentityHostTest.TASK,auth,env.session.selection,new NativeAppEvidence.Installed(env.target),
                    selection,env.session.generation,env.session.displayId(),()->{},(leaf,record)->{});
            completion=new TaskCompletionGate(task.taskId,owner,bound,env.session.selection);completion.bindNativeSession(task);
        }
        WindowOwnership window()throws Exception{
            LocalSocket.responder=raw->{JSONObject request=ProfileClientPort.decode(raw),reply=env.reply(raw,env.target,true);
                if("window".equals(request.getString("op"))){WindowOwnership w=new WindowOwnership(env.target,env.session.generation,env.session.displayId(),
                    request.getInt("window_id"),request.getInt("task_id"),1200,token,UUID.randomUUID().toString(),env.target.profile.userId,
                    env.target.profile.serial,env.target.fullUid,SystemClock.now,SystemClock.now+1000);reply.put("window_ownership_wire",w.wire());}
                return ProfileClientPort.frame(reply.toString().getBytes(StandardCharsets.UTF_8));};
            return env.session.verifyProfileWindow(96,1234,()->false,SystemClock.now+4000);
        }
        void observe(String name)throws Exception{
            NativeXmlFixture.Snapshot raw=NativeXmlFixture.read(fixtures.resolve(name+".xml"));
            observeNodes(raw.nodes,raw.rootBounds,raw.sourceSha256,1224,2992);
        }
        void observeLogin()throws Exception{
            NativeAppEvidence.Frame login=SyntheticXiaomiNativeLoginFixture.frame();
            observeNodes(login.nodes,new int[]{login.left,login.top,login.right,login.bottom},login.sourceRecordSha,login.width,login.height);
        }
        void observeNodes(List<NativeAppEvidence.Node> nodes,int[] b,String sourceSha,int width,int height)throws Exception{
            SystemClock.now+=100;
            String obs=id();List<NotesCompletionEvidence.Node> rows=new ArrayList<NotesCompletionEvidence.Node>();
            for(NativeAppEvidence.Node n:nodes)rows.add(new NotesCompletionEvidence.Node(n.id,n.packageName,n.text,n.label,n.viewId,null,
                    new int[]{n.left,n.top,n.right,n.bottom},n.editable,n.clickable,n.scrollable,n.enabled,n.password,ObservedChildText.notApplicable(),n.signature));
            retained=new NotesCompletionEvidence.Frame(obs,MI,96,env.session.displayId(),env.session.generation,1,true,false,rows);
            frame=new NativeAppEvidence.Frame(task.taskId,task.goal.ownerSha256,task.target.targetSha256,auth.authorization.sha256,
                    selection,obs,MI,env.session.generation,sha("host AX "+sourceSha),sha("host state "+obs),sha("unopened render"),sourceSha,
                    TaskCompletionGate.webFrameSha(retained),env.session.displayId(),96,0,width,height,b[0],b[1],b[2],b[3],SystemClock.now,false,true,nodes,1,true,window());
            SystemClock.now+=150;task.observed(frame);completion.observed(retained);
        }
        ActionDecision proposed(String action,String status,String node)throws Exception{
            JSONObject j=new JSONObject().put("action",action).put("package",MI).put("observation_id",frame.observationId);
            if(node!=null)j.put("node_id",node).put("node_label",frame.byId.get(node).label);
            if("done".equals(action))j.put("status",status).put("summary","fixture");
            if("wait".equals(action))j.put("duration_ms",100);
            return ActionDecision.parse(j.toString(),ActionDecision.IME_ACTION_SCHEMA);
        }
        void issue(String purpose)throws Exception{
            String node=null;for(Map.Entry<String,String> x:task.domain().purposes.entrySet())if(purpose.equals(x.getValue())){check(node==null,"unique permitted proposal");node=x.getKey();}
            check(node!=null,"current page must expose "+purpose+"; "+task.domain().purposes);
            ActionDecision a=proposed("click",null,node);task.domain().requireCurrent(a);String run=id();auth.check(a,run);
            task.beforeModelAction(++step,a,run,++SystemClock.now);task.modelActionOutcome(a,run,true,true,false,sha("explicit host accepted "+run),++SystemClock.now);
        }
        void detail()throws Exception{observe("suggestions");issue("submit_exact_suggestion");observe("results");issue("open_exact_product");observe("detail");}
        Map<String,Object> terminalEvidence()throws Exception{
            task.retire();TaskCompletionGate.Check t=completion.terminalNativeCheck(task,retained,auth.frame(),step,null,false,true,true,true,true,false,true,true,
                    Integer.valueOf(0),true,task.taskId,id(),sha("synthetic worker exit"));
            check(!t.verified,"order preparation goal never verified by a display price");
            return new LinkedHashMap<String,Object>(t.evidence);
        }
        Map<String,Object> explain(Map<String,Object> facts){
            return LocalTaskController.OutcomeExplanation.create(task.taskId,task.goal.ownerSha256,"partial",true,false,retained,facts,null);
        }
        Map<String,Object> end()throws Exception{
            return explain(terminalEvidence());
        }
        public void close()throws IOException{env.close();}
    }
    @SuppressWarnings("unchecked")
    static Map<String,Object> editableChild(Map<String,Object> record,String key){
        Map<String,Object> value=new LinkedHashMap<String,Object>((Map<String,Object>)record.get(key));
        record.put(key,value);return value;
    }
    public static void main(String[] args)throws Exception{
        fixtures=Paths.get(args[0]);NativeProfileIdentityHostTest.workspace=Paths.get(args[1]);Files.createDirectories(NativeProfileIdentityHostTest.workspace);
        one("complete_owner_scope_and_negative_transactions",()->{
            for(String owner:new String[]{AUDIT,NATURAL}){NativeAppGoal g=NativeAppGoal.parse(owner,MI);
                check(g!=null&&NativeAppGoal.PRODUCT_ORDER_PREVIEW.equals(g.kind)&&g.readsXiaomiProduct(),"budgeted owner parsed");
                check(g.orderPreview.quantity==1&&"200".equals(g.orderPreview.capYuan)&&"AX3000T".equals(owner.substring(g.modelStartUtf16,g.modelEndUtf16)),"bound model, quantity, cap");
                check("200".equals(owner.substring(g.orderPreview.capStartUtf16,g.orderPreview.capEndUtf16))&&!g.toolCeiling.contains("submit"),"literal cap and no general submit");}
            check("白色".equals(NativeAppGoal.parse(NATURAL,MI).orderPreview.requestedVariant)&&NativeAppGoal.parse(AUDIT,MI).orderPreview.requestedVariant==null,"only stated SKU variant retained");
            for(String owner:new String[]{AUDIT+"，提交订单",AUDIT.replace("不支付","支付"),AUDIT.replace("不提交，",""),AUDIT.replace("1台","2台"),AUDIT.replace("200元","200美元"),
                    AUDIT.replace("200元","0元"),AUDIT.replace("AX3000T","AX3000"),AUDIT.replace("核对商品、数量和总额后停在订单确认页","直接下单"),NATURAL.replace("白色","任选款式"),"帮我下单购物"})
                check(NativeAppGoal.parse(owner,MI)==null,"unsupported or added effect "+owner);
            check(NativeAppGoal.parse(AUDIT,NativeAppGoal.CTRIP_PACKAGE)==null,"no substitute package");
            check(NativeAppGoal.PRODUCT_PRICE.equals(NativeAppGoal.parse("在小米商城查询AX3000T价格",MI).kind),"legacy price goal unchanged");
        });
        for(String cap:new String[]{"200","159","100"}){final String amount=cap;
            one("real_detail_unit_price_compared_to_"+cap,()->{try(Harness h=new Harness(AUDIT.replace("200元",amount+"元"))){
                h.detail();NativeAppDomain d=h.task.domain();check(d.incompleteOrderPreview&&!d.resultReady&&d.resultRecord()==null,"detail price cannot promote order confirmation");
                check(d.clickIds.isEmpty()&&d.editValues.isEmpty()&&!d.backAllowed&&d.toolMask(null).equals(Collections.singleton("done")),"no purchase/loading/price input");
                for(ActionDecision a:new ActionDecision[]{h.proposed("done","success",null),h.proposed("wait",null,null),h.proposed("back",null,null)}){
                    boolean refused=false;try{d.requireCurrent(a);}catch(ActionDecision.InvalidActionException expected){refused=true;}check(refused,"only partial or failure can end");
                }
                d.requireCurrent(h.proposed("done","partial",null));Map<String,Object> answer=h.end();String msg=(String)answer.get("message");
                String direction=amount.equals("200")?"低于":amount.equals("159")?"等于":"高于";
                check("native_xiaomi_order_preview_price_only".equals(answer.get("code"))&&msg.contains("159 元")&&msg.contains(direction+"预算"),"original sale price and literal comparison");
                check(msg.contains("尚未核实所选款式、数量及结算总额")&&Boolean.FALSE.equals(answer.get("business_verified")),"no assumed SKU, quantity, total or order");
            }});}
        one("direct_detail_cannot_create_review_without_current_query_and_card",()->{try(Harness h=new Harness(AUDIT)){
            h.observe("detail");check(!h.task.domain().incompleteOrderPreview&&!h.task.domain().resultReady,"old or directly opened detail cannot qualify");
            check(h.end().isEmpty(),"no owner quote without original query and model navigation");
        }});
        for(String owner:new String[]{AUDIT,"在小米商城查询AX3000T价格"}){
            final boolean preview=owner.equals(AUDIT);
            one(preview?"managed_login_shows_budget_blocker":"managed_login_shows_price_blocker",()->{
                try(Harness h=new Harness(owner)){
                    h.observeLogin();
                    check(NativeXiaomiProductPage.LOGIN.equals(h.task.domain().phase),"the current observed page must be the account form");
                    Map<String,Object> reason=h.end();String shown=String.valueOf(reason.get("message"));
                    check("native_xiaomi_login_page".equals(reason.get("code"))&&shown.contains("小米商城显示了账号登录页"),"explain the actual current page");
                    check(shown.contains("工作资料中的小米商城")&&shown.contains("商品售价"),"identify the bound profile and missing displayed price");
                    check(preview==shown.contains("无法核对预算")&&preview==shown.contains("结算总额"),"only an order-preview goal mentions budget and checkout");
                    check(Boolean.FALSE.equals(reason.get("business_verified"))&&Boolean.FALSE.equals(reason.get("grants_tool_authority")),"no login or checkout authority");
                }
            });
        }
        one("login_then_home_explanation_requires_original_navigation",()->{
            try(Harness h=new Harness(AUDIT)){
                h.observeLogin();
                Map<String,Object> before=h.frame.evidence(),page=NativeXiaomiProductPage.inspect(h.task.goal,h.frame).evidence();
                h.issue(NativeXiaomiProductPage.LOGIN_EXIT);h.observe("home");
                String destination=h.task.domain().phase;
                check("home_search".equals(destination),"the original model-issued return led to the recognized home search page");
                Map<String,Object> after=h.frame.evidence(),facts=h.terminalEvidence();
                Map<String,Object> session=editableChild(facts,"native_app_session"),domain=editableChild(session,"current_domain");
                Map<String,Object> provider=editableChild(domain,"provider"),progress=editableChild(session,"progress");
                // Supply the typed-navigation publication from the parallel provider change. The actual
                // native session above supplied the login-exit attempt, its return transition, and the final frame.
                Map<String,Object> login=new LinkedHashMap<String,Object>();
                login.put("schema","hepta.native-search-login-observed.v1");login.put("phase",NativeXiaomiProductPage.LOGIN);
                login.put("task_id",h.task.taskId);login.put("owner_sha256",h.task.goal.ownerSha256);
                login.put("execution_target_sha256",before.get("execution_target_sha256"));login.put("authorization_sha256",before.get("task_authorization_sha256"));
                login.put("fresh_frame",before);login.put("provider",page);login.put("query_or_price_verified",false);login.put("fresh_search_contract_observed",false);
                List<Object> transitions=new ArrayList<Object>();transitions.add(login);
                for(Object entry:(List<?>)progress.get("transitions")){
                    Map<?,?> original=(Map<?,?>)entry;
                    Map<Object,Object> row=new LinkedHashMap<Object,Object>(original);
                    if(after.equals(row.get("after"))&&Boolean.TRUE.equals(row.get("navigation_only")))
                        row.put("actual_return_destination",destination);
                    transitions.add(row);
                }
                progress.put("transitions",transitions);progress.put("typed_search_login_observed",login);
                domain.put("phase",NativeXiaomiProductPage.LOGIN_BLOCKED);domain.put("missing",Collections.singletonList("native_login_returned_to_home_after_wide_search"));
                provider.put("returned_to_home_after_wide_search",true);provider.put("actual_return_destination","home_search");
                provider.put("observed_login_page",false);provider.put("credentials_or_agreement_actions_available",false);
                Map<String,Object> answer=h.explain(facts);
                check("native_xiaomi_search_returned_home_after_login".equals(answer.get("code"))
                        &&String.valueOf(answer.get("message")).contains("返回后显示商城首页"),"show the historical login and actual home separately");
                check(after.get("observation_id").equals(answer.get("observation_id")),"final observation is the home page");
                login.put("task_id",id());check(h.explain(facts).isEmpty(),"reject an earlier login from another task");login.put("task_id",h.task.taskId);
                progress.put("transitions",Collections.singletonList(login));check(h.explain(facts).isEmpty(),"a login page alone cannot prove the return home");
            }
        });
        boolean pass=true;for(Map<String,Object> r:results)pass&=Boolean.TRUE.equals(r.get("passed"));
        Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("all_pass",pass);out.put("cases",results.size());out.put("assertions",assertions);out.put("results",results);
        Files.write(Paths.get(args[2]),(new JSONObject(out).toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        if(!pass)System.exit(1);
    }
}
