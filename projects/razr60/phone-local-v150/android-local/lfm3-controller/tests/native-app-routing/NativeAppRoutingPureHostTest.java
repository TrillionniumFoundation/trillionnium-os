package org.trillionnium.hepta.local;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebEvidenceBinding;
import org.trillionnium.hepta.webprotocol.WebTaskPurpose;

/** Actual immutable targets, Selection, OWNER authority, and extracted Web constructor admission.
 * No package manager, Binder, display, model, native provider or app effect is simulated as success. */
public final class NativeAppRoutingPureHostTest {
    static final String CTRIP="ctrip.android.view",MI="com.xiaomi.shop",CSA="com.csair.mbp";
    static final String HELPER=BackgroundTaskTarget.HELPER,NOTES=org.trillionnium.hepta.background.FixedIntentTools.forAction("notes.create").packageName;
    static final String FLIGHT="查一下2099年11月17日北京到上海的单程机票，1名成人";
    static final String PRODUCT="在小米商城App中查询AX3000T的价格";
    static final String WEB_PRODUCT="查一下小米AX3000T的官网价格";
    static final String TASK="11111111111111111111111111111111";
    static final List<String> names=new ArrayList<String>();static int assertions;static Path scratch;
    interface Body{void run()throws Exception;}
    static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    static void test(String name,Body run)throws Exception{run.run();names.add(name);}
    static void rejects(Body run)throws Exception{
        boolean rejected=false;try{run.run();}catch(IllegalArgumentException|IllegalStateException e){rejected=true;}
        check(rejected,"expected actual admission refusal");
    }
    static Set<String> packages(String... values){return new TreeSet<String>(Arrays.asList(values));}
    static BackgroundSession.Selection selection(String owner,String initial,String... allowed){
        return new BackgroundSession.Selection(BackgroundTaskTarget.resolveExplicitSelection(owner,initial,packages(allowed)));
    }
    static TaskAuthorization bound(String owner,BackgroundSession.Selection s){return TaskAuthorization.parse(owner).forExecutionSelection(s);}
    static String canonical(Map<String,Object> value)throws Exception{return WebEvidenceBinding.canonical(new JSONObject(value));}
    static BackgroundSession background(String owner,BackgroundSession.Selection s)throws Exception{
        Path files=Files.createTempDirectory(scratch,"private-files-");
        Files.write(files.resolve("fake.apk"),"synthetic host APK boundary".getBytes(StandardCharsets.UTF_8));
        android.content.Context context=new android.content.Context(files.toFile());
        return new BackgroundSession(context,TASK,owner,s,new QualificationScopeConfig.FilesRoot(context));
    }
    static void helperAdmission(String owner,BackgroundSession.Selection s,TaskAuthorization a)throws Exception{
        RouteWebAdmissionProjection.admit(TASK,owner,a.bind(TASK),background(owner,s),new TaskCompletionGate(TASK,owner,TaskAuthorization.parse(owner)));
    }
    public static void main(String[] args)throws Exception{
        scratch=Paths.get(args[1]);Files.createDirectories(scratch);
        test("natural_flight_preserves_explicit_ctrip_while_legacy_resolver_selected_helper",()->{
            Set<String> apps=packages(CTRIP,HELPER);
            check(HELPER.equals(BackgroundTaskTarget.resolve(FLIGHT,CTRIP,apps).packageName),"old failure shape must be exercised");
            BackgroundTaskTarget t=BackgroundTaskTarget.resolveExplicitSelection(FLIGHT,CTRIP,apps);
            check(CTRIP.equals(t.packageName)&&!t.webHelper()&&t.nativeGoal!=null,"native selection survives old Web-shaped OWNER");
            check(t.effectivePackages.equals(Collections.singleton(CTRIP)),"original multi-app scope narrowed");
        });
        test("same_flight_owner_csair_has_distinct_native_package_and_goal_contract",()->{
            BackgroundTaskTarget a=selection(FLIGHT,CTRIP,CTRIP,CSA).taskTarget,b=selection(FLIGHT,CSA,CTRIP,CSA).taskTarget;
            check(CSA.equals(b.packageName)&&!a.targetSha256.equals(b.targetSha256),"explicit App binds target identity");
            check(!a.nativeGoal.contractSha256.equals(b.nativeGoal.contractSha256),"goal remains selected provider specific");
        });
        test("xiaomi_native_price_preserves_owner_and_explicit_package",()->{
            BackgroundSession.Selection s=selection(PRODUCT,MI,MI,HELPER);TaskAuthorization a=bound(PRODUCT,s);
            s.requireTaskTarget(PRODUCT,a);
            check(s.taskTarget.nativeGoal!=null&&MI.equals(s.initialPackage),"supported native price facts only");
            check(a.allowedTools.equals(s.taskTarget.nativeGoal.toolCeiling),"native query ceiling is actual intersection");
            check(a.immutableOwner().equals(PRODUCT)&&s.taskTarget.nativeGoal.immutableOwner.equals(PRODUCT),"no owner rewrite");
        });
        test("old_website_owner_with_native_selection_stays_native_without_provider",()->{
            BackgroundSession.Selection s=selection(WEB_PRODUCT,MI,MI,HELPER);TaskAuthorization a=bound(WEB_PRODUCT,s);
            check(s.taskTarget.nativeGoal==null&&!s.taskTarget.webHelper(),"unsupported native wording cannot change selected App");
            check(!a.allowedTools.contains("web.search")&&!a.allowedTools.contains("type"),"old OWNER narrowing is not widened");
            RouteWebAdmissionProjection.validateSelection(WEB_PRODUCT,s);
        });
        test("native_unrecognized_owner_and_tool_clauses_keep_original_restrictions",()->{
            String owner=FLIGHT+"。不要点击。不要输入";
            BackgroundSession.Selection s=selection(owner,CTRIP,CTRIP,HELPER);
            TaskAuthorization original=TaskAuthorization.parse(owner),a=bound(owner,s);
            Set<String> expected=new TreeSet<String>(original.allowedTools);expected.remove("web.search");
            check(s.taskTarget.nativeGoal==null&&a.allowedTools.equals(expected),"full OWNER parse retained with null goal");
            check(!a.allowedTools.contains("click")&&!a.allowedTools.contains("type"),"restrictions cannot be erased");
            check(!a.bind(TASK).frame().allows("web.search"),"native browser tool not admitted");
        });
        test("unknown_native_app_is_singleton_not_a_generic_success_capability",()->{
            String owner="查看当前页面";BackgroundSession.Selection s=selection(owner,"com.example.hostfixture","com.example.hostfixture",HELPER);
            TaskAuthorization a=bound(owner,s);
            check(s.taskTarget.nativeGoal==null&&!s.taskTarget.webHelper(),"unknown native goal");
            check(s.allowedPackages.equals(Collections.singletonList("com.example.hostfixture")),"no scope widening");
            check(Boolean.FALSE.equals(s.taskTarget.evidence().get("business_verified"))
                    &&Boolean.FALSE.equals(s.taskTarget.evidence().get("grants_tool_authority")),"target evidence grants no result");
            check(!a.allowedTools.contains("web.search"),"null goal also removes Web fixed intent");
        });
        test("explicit_notes_keeps_notes_create_without_switching_to_helper",()->{
            String owner="记一下，NativeRoute65原文。";BackgroundSession.Selection s=selection(owner,NOTES,NOTES,HELPER);
            TaskAuthorization a=bound(owner,s);
            check(NOTES.equals(s.initialPackage)&&a.allowedTools.contains("notes.create"),"Notes remains its selected native App");
            check(!a.allowedTools.contains("web.search"),"Notes does not gain browser shortcut");
        });
        test("flight_owner_in_explicit_notes_does_not_switch_package",()->{
            BackgroundSession.Selection s=selection(FLIGHT,NOTES,NOTES,HELPER);
            check(NOTES.equals(s.initialPackage)&&s.taskTarget.nativeGoal==null,"wrong selected App cannot become a provider");
            RouteWebAdmissionProjection.validateSelection(FLIGHT,s);
        });
        test("explicit_helper_flight_keeps_entire_original_public_authorization",()->{
            BackgroundSession.Selection s=selection(FLIGHT,HELPER,CTRIP,HELPER);TaskAuthorization original=TaskAuthorization.parse(FLIGHT),a=bound(FLIGHT,s);
            check(a.sha256.equals(original.sha256)&&canonical(a.evidence()).equals(canonical(original.evidence())),"exact old helper public protocol");
            check(!a.evidence().containsKey("execution_target")&&!s.json().has("execution_target")&&s.json().has("owner_task_selection"),"original public authorization and Selection projection preserved");
            helperAdmission(FLIGHT,s,a);
        });
        test("explicit_helper_shopping_keeps_original_public_authorization",()->{
            BackgroundSession.Selection s=selection(WEB_PRODUCT,HELPER,MI,HELPER);TaskAuthorization original=TaskAuthorization.parse(WEB_PRODUCT),a=bound(WEB_PRODUCT,s);
            check(a.sha256.equals(original.sha256)&&canonical(a.evidence()).equals(canonical(original.evidence())),"shopping original public protocol");
            helperAdmission(WEB_PRODUCT,s,a);
        });
        test("explicit_helper_does_not_accept_unknown_or_notes_goal",()->{
            rejects(()->selection("查看当前页面",HELPER,HELPER));
            rejects(()->selection("记一下，保持原文",HELPER,NOTES,HELPER));
        });
        test("original_ui_selection_is_frozen_and_effective_scope_is_singleton",()->{
            Set<String> original=packages(CTRIP,MI,HELPER);
            BackgroundTaskTarget target=BackgroundTaskTarget.resolveExplicitSelection(FLIGHT,CTRIP,original);
            original.clear();original.add(CSA);
            check(target.originalPackages.equals(new ArrayList<String>(packages(CTRIP,MI,HELPER))),"copy preserves original UI evidence");
            check(target.effectivePackages.equals(Collections.singleton(CTRIP)),"effective App unchanged");
            BackgroundSession.Selection s=new BackgroundSession.Selection(target);
            boolean immutable=false;try{s.allowedPackages.add(HELPER);}catch(UnsupportedOperationException expected){immutable=true;}
            check(immutable,"Selection list must be immutable");
        });
        test("same_actual_selection_and_target_objects_survive_repeated_admission",()->{
            BackgroundSession.Selection s=selection(FLIGHT,CTRIP,CTRIP,HELPER);TaskAuthorization a=bound(FLIGHT,s);
            for(int i=0;i<3;i++){s.requireTaskTarget(FLIGHT,a);a.requireExecutionSelection(s);}
            check(s.executionTarget()==s.taskTarget&&a.immutableOwner().equals(FLIGHT),"same refs and owner");
        });
        test("replacement_selection_with_same_target_is_rejected",()->{
            BackgroundSession.Selection s=selection(FLIGHT,CTRIP,CTRIP),clone=new BackgroundSession.Selection(s.taskTarget);TaskAuthorization a=bound(FLIGHT,s);
            rejects(()->clone.requireTaskTarget(FLIGHT,a));rejects(()->a.requireExecutionSelection(clone));
        });
        test("equal_looking_recreated_target_and_selection_are_rejected",()->{
            BackgroundSession.Selection s=selection(FLIGHT,CTRIP,CTRIP),clone=selection(FLIGHT,CTRIP,CTRIP);TaskAuthorization a=bound(FLIGHT,s);
            check(s.taskTarget.targetSha256.equals(clone.taskTarget.targetSha256),"same values are intentionally exercised");
            rejects(()->clone.requireTaskTarget(FLIGHT,a));
        });
        test("owner_rewrite_or_other_original_owner_is_rejected",()->{
            BackgroundSession.Selection s=selection(FLIGHT,CTRIP,CTRIP);TaskAuthorization a=bound(FLIGHT,s);
            rejects(()->s.requireTaskTarget(FLIGHT+" ",a));
            rejects(()->TaskAuthorization.parse("查看当前页面").forExecutionSelection(s));
        });
        test("native_authorization_hash_binds_selected_app_and_original_scope",()->{
            BackgroundSession.Selection a=selection(FLIGHT,CTRIP,CTRIP),b=selection(FLIGHT,CSA,CSA),c=selection(FLIGHT,CTRIP,CTRIP,HELPER);
            check(!bound(FLIGHT,a).sha256.equals(bound(FLIGHT,b).sha256),"different explicit packages");
            check(!bound(FLIGHT,a).sha256.equals(bound(FLIGHT,c).sha256),"different original selection scope");
        });
        test("helper_same_public_hash_still_requires_original_private_selection",()->{
            BackgroundSession.Selection a=selection(FLIGHT,HELPER,HELPER),b=selection(FLIGHT,HELPER,HELPER);TaskAuthorization x=bound(FLIGHT,a),y=bound(FLIGHT,b);
            check(x.sha256.equals(y.sha256),"legacy public auth identical");
            rejects(()->b.requireTaskTarget(FLIGHT,x));rejects(()->helperAdmission(FLIGHT,b,x));
        });
        test("bound_authorization_cannot_be_rebound",()->{
            BackgroundSession.Selection s=selection(PRODUCT,MI,MI);TaskAuthorization a=bound(PRODUCT,s);
            rejects(()->a.forExecutionSelection(s));
        });
        test("legacy_selection_cannot_enter_new_explicit_admission",()->{
            BackgroundSession.Selection legacy=new BackgroundSession.Selection(CTRIP,Collections.singleton(CTRIP));
            rejects(()->legacy.requireImmutableTarget(FLIGHT));
            rejects(()->TaskAuthorization.parse(FLIGHT).forExecutionSelection(legacy));
        });
        test("mutable_binding_is_rejected_if_target_changes_during_binding",()->{
            BackgroundTaskTarget a=selection(FLIGHT,CTRIP,CTRIP).taskTarget,b=selection(FLIGHT,CSA,CSA).taskTarget;
            BackgroundTaskTarget.SelectionBinding moving=new BackgroundTaskTarget.SelectionBinding(){
                int reads;public BackgroundTaskTarget executionTarget(){return reads++==0?a:b;}
            };
            rejects(()->TaskAuthorization.parse(FLIGHT).forExecutionSelection(moving));
        });
        test("selected_package_must_be_valid_and_in_original_scope",()->{
            rejects(()->BackgroundTaskTarget.resolveExplicitSelection(FLIGHT,CTRIP,packages(CSA)));
            rejects(()->BackgroundTaskTarget.resolveExplicitSelection(FLIGHT,"com.bad/Injected",packages("com.bad/Injected")));
            rejects(()->BackgroundTaskTarget.resolveExplicitSelection(FLIGHT,null,packages(CTRIP)));
        });
        test("native_route_validation_does_not_grant_web_constructor_admission",()->{
            BackgroundSession.Selection s=selection(FLIGHT,CTRIP,CTRIP,HELPER);TaskAuthorization a=bound(FLIGHT,s);
            RouteWebAdmissionProjection.validateSelection(FLIGHT,s);
            rejects(()->RouteWebAdmissionProjection.requireWebSelection(FLIGHT,s));
            rejects(()->helperAdmission(FLIGHT,s,a));
        });
        test("helper_constructor_rejects_wrong_task_retired_authority_and_null_completion",()->{
            BackgroundSession.Selection s=selection(FLIGHT,HELPER,HELPER);TaskAuthorization a=bound(FLIGHT,s);
            TaskAuthorization.Gate g=a.bind(TASK);g.retire();
            rejects(()->RouteWebAdmissionProjection.admit(TASK,FLIGHT,g,background(FLIGHT,s),new TaskCompletionGate(TASK,FLIGHT,TaskAuthorization.parse(FLIGHT))));
            rejects(()->RouteWebAdmissionProjection.admit("22222222222222222222222222222222",FLIGHT,a.bind(TASK),background(FLIGHT,s),new TaskCompletionGate(TASK,FLIGHT,TaskAuthorization.parse(FLIGHT))));
            rejects(()->RouteWebAdmissionProjection.admit(TASK,FLIGHT,a.bind(TASK),background(FLIGHT,s),null));
        });
        test("helper_constructor_preserves_complete_original_public_auth_comparison",()->{
            BackgroundSession.Selection h=selection(FLIGHT,HELPER,HELPER),n=selection(FLIGHT,CTRIP,CTRIP);
            rejects(()->helperAdmission(FLIGHT,h,bound(FLIGHT,n)));
            BackgroundSession.Selection legacy=new BackgroundSession.Selection(HELPER,Collections.singleton(HELPER));
            helperAdmission(FLIGHT,legacy,TaskAuthorization.parse(FLIGHT));
            check(WebTaskPurpose.fromOwner(FLIGHT).ownerSha256.equals(h.taskTarget.ownerSha256),"legacy contract remains exact OWNER");
        });
        test("foreground_or_absent_selection_cannot_auto_create_web_session",()->{
            rejects(()->RouteWebAdmissionProjection.requireWebSelection(FLIGHT,null));
            rejects(()->RouteWebAdmissionProjection.validateSelection(FLIGHT,null));
        });
        test("find_before_open_and_original_no_open_clauses_remain_effective",()->{
            String owner="先查找已安装的携程应用，再打开；只允许查找应用和打开和等待和结束";
            BackgroundSession.Selection s=selection(owner,CTRIP,CTRIP);TaskAuthorization a=bound(owner,s);
            check(a.requireFindAppBeforeOpen&&!a.allowedTools.contains("click"),"original sequencing and restrictions retained");
            check(!a.bind(TASK).frame().successAllowed(),"no fabricated actual app lookup");
            String noOpen="查看当前页面。只允许等待和结束任务";
            TaskAuthorization b=bound(noOpen,selection(noOpen,CTRIP,CTRIP));
            check(!b.allowedTools.contains("open")&&b.allowedTools.contains("wait"),"binding cannot add bootstrap permission");
        });
        test("completion_entry_cannot_omit_or_replace_bound_selection",()->{
            BackgroundSession.Selection s=selection(FLIGHT,CTRIP,CTRIP),copy=new BackgroundSession.Selection(s.taskTarget);
            TaskAuthorization a=bound(FLIGHT,s);a.requireCompletionSelection(s);
            rejects(()->a.requireCompletionSelection(null));rejects(()->a.requireCompletionSelection(copy));
        });
        test("legacy_completion_entry_remains_unbound_only",()->{
            TaskAuthorization a=TaskAuthorization.parse(FLIGHT);a.requireCompletionSelection(null);
            BackgroundSession.Selection s=selection(FLIGHT,CTRIP,CTRIP);
            rejects(()->a.requireCompletionSelection(s));
        });
        test("actual_background_session_evidence_retains_target_outside_unchanged_selection_wire",()->{
            BackgroundSession.Selection s=selection(PRODUCT,MI,MI,HELPER);
            BackgroundSession bg=background(PRODUCT,s);JSONObject audit=bg.evidence();
            JSONObject target=audit.getJSONObject("execution_target");
            check(target.getString("target_sha256").equals(s.taskTarget.targetSha256)
                    &&target.getString("owner_sha256").equals(s.taskTarget.ownerSha256),"real session carries exact target audit");
            check(target.getString("effective_initial_package").equals(MI)
                    &&target.getString("route").equals(BackgroundTaskTarget.NATIVE_APP),"same selected App and route recorded");
            check(!audit.getBoolean("spawn_attempted")&&!audit.getBoolean("bootstrap_dispatched"),"audit cannot invent broker/app effects");
            check(!s.json().has("execution_target")
                    &&s.json().getString("bootstrap_source").equals("owner_intent_within_explicit_ui_selection"),"strict old observation projection remains intact");
        });
        JSONObject result=new JSONObject().put("schema","hepta.native-app-routing-pure-host.v1")
                .put("all_pass",true).put("cases",names.size()).put("assertions",assertions).put("case_names",names)
                .put("android_runtime",false).put("phone_operations",0).put("provider_or_business_verified",false);
        Files.write(Paths.get(args[0]),(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println(result.toString());
    }
}
