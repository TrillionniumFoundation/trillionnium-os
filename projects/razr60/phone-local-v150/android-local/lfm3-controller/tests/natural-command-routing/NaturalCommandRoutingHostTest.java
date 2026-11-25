package org.trillionnium.hepta.local;

import java.io.File;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.ProfileIdentity;
import org.trillionnium.hepta.background.ProfileTarget;

/** Real resolver/authorization/completion/grammar and extracted ordinary UI.
 * Installed identities, Android IO, model assets and scheduling are host ports.
 * These synthetic inputs confer no device, model or business qualification.
 */
public final class NaturalCommandRoutingHostTest {
    private static final String HASH=String.join("",Collections.nCopies(64,"a"));
    private static final String NONCE=String.join("",Collections.nCopies(32,"b"));
    private static final String TASK=String.join("",Collections.nCopies(32,"c"));
    private static final String NATURAL="请在携程查明天上海到北京的机票";
    private static final String FLIGHT="请在携程查询2099年11月17日北京到上海的单程机票，1名成人";
    private static final String PRODUCT="在小米商城App中查询AX3000T的价格";
    private static final String PREVIEW="在小米商城买1台小米路由器AX3000T，预算不超过200元，核对商品、数量和总额后停在订单确认页，不提交，不支付";
    private static final String NOTE="请新建并保存一条笔记，正文为“在携程查机票，不要打开小米商城”，然后从笔记列表重新打开核对正文。";
    private static int assertions;
    private static Path root;
    private static final List<JSONObject> results=new ArrayList<JSONObject>();
    private interface Work {void run()throws Exception;}
    private static void check(boolean value,String reason){assertions++;if(!value)throw new AssertionError(reason);}
    private static void rejects(Work work)throws Exception {
        boolean refused=false;try{work.run();}catch(IllegalArgumentException|IllegalStateException expected){refused=true;}
        check(refused,"actual production refusal required");
    }
    private static void test(String name,Work work){
        int before=assertions;JSONObject row=new JSONObject().put("name",name);results.add(row);
        try{work.run();row.put("passed",true);}catch(Throwable failure){
            row.put("passed",false).put("error",failure.toString());failure.printStackTrace();
        }
        row.put("assertions",assertions-before);
    }
    private static BackgroundAutoTargetPreferences.Entry target(int user,String pkg){
        ProfileTarget p=new ProfileTarget(new ProfileIdentity(user,1000+user,0,ProfileIdentity.MANAGED),
                user*100000+10367,pkg,pkg+"/SyntheticActivity",7,Collections.singletonMap("base",HASH),Collections.singleton(HASH));
        return BackgroundAutoTargetPreferences.captureProfile(p);
    }
    private static BackgroundAutoTargetPreferences.Snapshot list(BackgroundAutoTargetPreferences.Entry... entries){
        return new BackgroundAutoTargetPreferences.Snapshot(true,Arrays.asList(entries));
    }
    private static BackgroundAutoTargetResolver.Resolution resolve(String owner,BackgroundAutoTargetPreferences.Snapshot saved){
        return BackgroundAutoTargetResolver.resolve(owner,saved,TaskAuthorization.parse(owner));
    }
    private static void noRoute(String owner,BackgroundAutoTargetPreferences.Snapshot saved)throws Exception{
        rejects(()->resolve(owner,saved).choose(null));
    }
    private static BackgroundAutoTargetResolver.StartSelection confirm(BackgroundAutoTargetResolver.Resolution r,
            BackgroundAutoTargetPreferences.Entry item){
        return r.confirm(item,NONCE,TASK,HASH);
    }
    private static final class Env implements AutoCloseable {
        final LocalProbeApplication app;final MainActivity ui;final File directory;
        final BackgroundAutoTargetPreferences.Entry notes,flight,product;
        Env(String name,String owner,boolean visualPreference)throws Exception{
            directory=root.resolve(name).toFile();check(directory.mkdir(),"new fixture directory");
            android.system.Os.chmod(directory.getPath(),0700);
            File model=new File(directory,"model");check(model.mkdir(),"new model fixture");
            android.system.Os.chmod(model.getPath(),0700);
            MobiMindPrivateFiles.writeNew(new File(model,"runtime-config.json"),RuntimeConfigTransaction.selected(ModelProfile.LFM3.id,"npu"));
            Files.write(new File(model,ModelProfile.LFM3.fileName).toPath(),new byte[]{1});
            File image=new File(directory,ModelProfile.GUI_OWL_4B.visualDirectory());check(image.mkdir(),"visual asset IO port");
            Files.write(new File(image,ModelProfile.GUI_OWL_4B.fileName).toPath(),new byte[]{1});
            Files.write(new File(image,VlmResultContract.named(ModelProfile.GUI_OWL_4B.id).projectorFilename).toPath(),new byte[]{1});
            app=new LocalProbeApplication(directory);
            app.getPackageManager().install(BackgroundAutoTargetPreferences.NOTES,10490,"synthetic Notes signer".getBytes(StandardCharsets.UTF_8));
            notes=BackgroundAutoTargetPreferences.captureNotes(app);
            BackgroundAutoTargetPreferences.Entry current=target(10,ProfileTarget.CTRIP);
            flight=visualPreference?current:current.withModel(ModelProfile.LFM3);
            product=target(10,ProfileTarget.XIAOMI);
            ProfileCatalogueClient.actual=flight.choice.profileTarget;
            ui=new MainActivity(app,list(notes,flight,product),owner);
        }
        void hold(){app.model.verificationEntered=new CountDownLatch(1);app.model.verificationRelease=new CountDownLatch(1);}
        void startPending()throws Exception{
            check(ui.start(),"visible ordinary Start accepted");
            long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);
            while(app.model.verificationEntered.getCount()!=0&&System.nanoTime()<end)android.os.Handler.pump();
            check(app.model.verificationEntered.getCount()==0&&ui.pending()&&app.modelSettings.isBusy(),
                    "actual settings reached declared model-asset port before scheduling");
            check(app.tasks.schedules==0,"no task before model generation qualification");
        }
        void drain()throws Exception{
            if(app.model.verificationRelease!=null)app.model.verificationRelease.countDown();
            long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);
            while((app.modelSettings.isBusy()||android.os.Handler.size()!=0)&&System.nanoTime()<end)android.os.Handler.pump();
            check(!app.modelSettings.isBusy()&&android.os.Handler.size()==0,"settings worker and main callbacks drained");
        }
        String preview()throws Exception{
            Method method=MainActivity.class.getDeclaredMethod("refreshAutomaticTargetPreview");
            method.setAccessible(true);method.invoke(ui);return ui.backgroundChoiceState.getText();
        }
        public void close(){
            if(app.model.verificationRelease!=null)app.model.verificationRelease.countDown();
            app.modelSettings.close();app.model.close();
        }
    }

    public static void main(String[] args)throws Exception{
        root=Paths.get(args[0]);Files.createDirectory(root);android.os.Looper.getMainLooper();
        final BackgroundAutoTargetPreferences.Entry flight=target(10,ProfileTarget.CTRIP).withModel(ModelProfile.LFM3);
        final BackgroundAutoTargetPreferences.Entry shop=target(10,ProfileTarget.XIAOMI);
        final BackgroundAutoTargetPreferences.Snapshot saved=list(flight,shop);
        test("natural_explicit_target_real_unknown_contract_and_partial_only",()->{
            BackgroundAutoTargetResolver.Resolution r=resolve(NATURAL,saved);
            check(r.choose(null)==flight&&!r.hasCompletionContract(flight),"explicit Ctrip target without business claim");
            BackgroundAutoTargetResolver.StartSelection start=confirm(r,flight);
            check(start.nativeGoal==null&&OwnerExplicitAppRoute.RECOGNITION.equals(start.recognition),"no synthetic NativeAppGoal");
            check(start.owner.equals(NATURAL)&&start.ownerSha256.equals(TaskAuthorization.parse(NATURAL).instructionSha256),"whole owner retained");
            BackgroundTaskTarget target=BackgroundTaskTarget.resolveAutomaticSelection(NATURAL,start);
            BackgroundSession.Selection selection=new BackgroundSession.Selection(target,true,false);
            TaskAuthorization original=TaskAuthorization.parse(NATURAL),bound=original.forExecutionSelection(selection);
            selection.requireTaskTarget(NATURAL,bound);
            check(original.allowedTools.containsAll(bound.allowedTools)&&!bound.allowedTools.contains("web.search"),"same explicit native narrowing");
            check(target.effectivePackages.equals(Collections.singleton(ProfileTarget.CTRIP))&&target.profileTarget==flight.choice.profileTarget,"one original saved instance");
            TaskCompletionGate completion=new TaskCompletionGate(TASK,NATURAL,bound,selection);
            check(TaskCompletionGate.UNKNOWN.equals(completion.contract.kind)&&!completion.verified(null),"actual UNKNOWN cannot verify completion");
            Set<String> statuses=DecisionGrammar.completionStatuses(null,completion.verified(null),null);
            check(statuses.equals(new java.util.TreeSet<String>(Arrays.asList("partial","failure"))),"actual grammar retains partial/failure and refuses success");
            check(Boolean.FALSE.equals(start.evidence().get("grants_dispatch_authority")),"route evidence does not grant dispatch");
        });
        test("known_native_contract_and_readonly_preview_keep_priority",()->{
            for(String owner:Arrays.asList(FLIGHT,PRODUCT,PREVIEW)){
                BackgroundAutoTargetResolver.Resolution r=resolve(owner,saved);
                BackgroundAutoTargetPreferences.Entry item=r.choose(null);
                BackgroundAutoTargetResolver.StartSelection start=confirm(r,item);
                check(r.hasCompletionContract(item)&&start.nativeGoal!=null,"full original business contract retained");
                start.nativeGoal.requireBinding(owner,item.packageName());
                BackgroundTaskTarget target=BackgroundTaskTarget.resolveAutomaticSelection(owner,start);
                BackgroundSession.Selection selection=new BackgroundSession.Selection(target,true,false);
                TaskAuthorization bound=TaskAuthorization.parse(owner).forExecutionSelection(selection);
                check(start.nativeGoal.toolCeiling.containsAll(bound.allowedTools),"original business ceiling cannot widen");
            }
        });
        test("known_notes_contract_treats_app_names_and_negative_body_as_data",()->{
            try(Env e=new Env("notes-data",NOTE,false)){
                BackgroundAutoTargetResolver.Resolution r=resolve(NOTE,e.ui.automaticTargets);
                check(r.matches.size()==1&&r.choose(null)==e.notes&&r.hasCompletionContract(e.notes),"full Notes wins quoted Ctrip/Xiaomi content");
                check(confirm(r,e.notes).nativeGoal==null&&TaskCompletionGate.NOTES.equals(TaskCompletionGate.Contract.parse(NOTE,TaskAuthorization.parse(NOTE)).kind),"true Notes contract without a fabricated native goal");
            }
        });
        test("literal_app_aliases_and_direct_open",()->{
            for(String owner:Arrays.asList("在携程旅行里看看明天的航班","请用携程App搜索明天机票","打开携程","请帮我在携程查天气"))
                check(resolve(owner,saved).choose(null)==flight,"unambiguous literal Ctrip designation");
            check(resolve("请在小米商城查看手机价格",saved).choose(null)==shop,"generic Xiaomi query");
        });
        test("quoted_search_data_does_not_select_another_app",()->{
            check(resolve("在携程搜索“小米商城附近的酒店”",saved).choose(null)==flight,"quoted app names remain query data");
        });
        test("other_tool_negatives_are_preserved_not_target_negation",()->{
            for(String owner:Arrays.asList("在携程查机票，不要切到主屏","在携程查机票，不要点击","在携程查机票，不要返回桌面")){
                BackgroundAutoTargetResolver.Resolution r=resolve(owner,saved);
                BackgroundAutoTargetResolver.StartSelection start=confirm(r,r.choose(null));
                BackgroundTaskTarget t=BackgroundTaskTarget.resolveAutomaticSelection(owner,start);
                BackgroundSession.Selection selection=new BackgroundSession.Selection(t,true,false);
                TaskAuthorization original=TaskAuthorization.parse(owner),bound=original.forExecutionSelection(selection);
                check(start.owner.equals(owner)&&original.allowedTools.containsAll(bound.allowedTools),"entire original owner and parsed ceiling retained");
                if(owner.endsWith("不要点击"))check(!bound.allowedTools.contains("click"),"actual click deny survives");
                if(owner.endsWith("不要返回桌面"))check(!bound.allowedTools.contains("home"),"actual home deny survives");
            }
        });
        test("unquoted_business_condition_without_target_condition_keeps_owner",()->{
            String owner="在携程查机票，如果看到优惠先告诉我";
            BackgroundAutoTargetResolver.StartSelection start=confirm(resolve(owner,saved),flight);
            check(start.owner.equals(owner)&&start.nativeGoal==null,"business clause not removed or converted to a verification claim");
        });
        test("target_negation_declines_without_semantic_guess",()->{
            for(String owner:Arrays.asList("不要打开携程","请不要在携程查机票","不用携程查机票",
                    "在携程查机票，不要再打开携程","在携程查机票，不是携程","别用携程查机票"))
                noRoute(owner,saved);
        });
        test("target_conditions_and_alternatives_require_manual_choice",()->{
            for(String owner:Arrays.asList("如果有优惠就用携程查机票","是否用携程查机票",
                    "在携程查机票，如果便宜才用携程","在携程查机票，若用携程请先问我",
                    "在携程或者小米商城查看价格","也许打开携程"))
                noRoute(owner,saved);
        });
        test("multiple_app_references_cannot_collapse_to_single_target",()->{
            for(String owner:Arrays.asList("在携程查机票，然后打开小米商城","在小米商城查看携程优惠",
                    "打开携程和小米商城","在携程查机票，不要用小米商城"))
                noRoute(owner,saved);
        });
        test("quoted_only_malformed_and_escaped_targets_decline",()->{
            for(String owner:Arrays.asList("“在携程查机票”","请在“携程”查机票","记录‘打开携程’",
                    "在携程搜索“未闭合","在携程搜索“嵌套‘小米商城’”","在携程搜索\\\"字面文本\\\""))
                noRoute(owner,saved);
        });
        test("partial_alias_and_company_reference_do_not_name_app",()->{
            noRoute("在携程旅行社查询地址",saved);
            noRoute("在携程工作多年的人有什么看法",saved);
            noRoute("小米商城今天怎么样",saved);
        });
        test("known_contract_with_extra_action_or_condition_cannot_downgrade",()->{
            for(String owner:Arrays.asList(PREVIEW+"，然后支付",PREVIEW+"然后支付",
                    PREVIEW+" 然后打开其他页面",PRODUCT+" 然后付款",PRODUCT+"之后付款",
                    " "+PRODUCT+" 随后打开其他页面",PRODUCT+"，然后打开商品详情",
                    FLIGHT+"，不要切到主屏",FLIGHT+"，如果有票就预订"))
                noRoute(owner,saved);
        });
        test("existing_owner_byte_bound_also_bounds_prefix_detection",()->{
            String head="在携程查询";
            int remaining=1600-head.getBytes(StandardCharsets.UTF_8).length;
            String exact=head+String.join("",Collections.nCopies(remaining,"x"));
            check(exact.getBytes(StandardCharsets.UTF_8).length==1600,"original maximum byte length");
            check(resolve(exact,saved).choose(null)==flight,"bounded unknown route at the existing maximum");
            rejects(()->resolve(exact+"x",saved));
            check(OwnerExplicitAppRoute.packageName(exact+"x")==null,"standalone target recognizer also refuses oversize input");
        });
        test("sole_saved_target_is_not_implicit_task_intent",()->{
            for(String owner:Arrays.asList("看看明天的安排","查一下机票","随便看看携程"))
                noRoute(owner,list(flight));
        });
        test("explicit_unsaved_app_never_replaced_with_only_saved_app",()->{
            noRoute(NATURAL,list(shop));
            noRoute("在小米商城查看手机价格",list(flight));
        });
        test("empty_missing_owner_and_authorization_mismatch_refuse",()->{
            rejects(()->BackgroundAutoTargetResolver.resolve(NATURAL,saved,null));
            rejects(()->BackgroundAutoTargetResolver.resolve(NATURAL,null,TaskAuthorization.parse(NATURAL)));
            rejects(()->resolve("",saved));
            rejects(()->BackgroundAutoTargetResolver.resolve(NATURAL,saved,TaskAuthorization.parse(PRODUCT)));
        });
        test("disabled_empty_and_duplicate_saved_identity_refuse",()->{
            rejects(()->resolve(NATURAL,saved.withAutomatic(false)));
            rejects(()->new BackgroundAutoTargetPreferences.Snapshot(true,Collections.<BackgroundAutoTargetPreferences.Entry>emptyList()));
            rejects(()->list(flight,flight));
        });
        test("same_package_multiple_profiles_require_exact_visible_choice",()->{
            BackgroundAutoTargetPreferences.Entry second=target(11,ProfileTarget.CTRIP).withModel(ModelProfile.LFM3);
            BackgroundAutoTargetResolver.Resolution r=resolve(NATURAL,list(flight,second,shop));
            check(r.matches.size()==2,"distinct profile instances remain distinct");
            rejects(()->r.choose(null));
            check(r.choose(second.instanceKey)==second,"explicit existing instance selection only");
            rejects(()->r.choose(shop.instanceKey));
            check(confirm(r,second).entry==second,"confirmed original snapshot entry");
        });
        test("equal_looking_replacement_entry_and_invalid_nonce_refuse",()->{
            BackgroundAutoTargetResolver.Resolution r=resolve(NATURAL,saved);
            BackgroundAutoTargetPreferences.Entry replacement=target(10,ProfileTarget.CTRIP).withModel(ModelProfile.LFM3);
            check(replacement.identitySha256.equals(flight.identitySha256),"same bytes alone do not confer membership");
            rejects(()->confirm(r,replacement));
            rejects(()->r.confirm(flight,"bad",TASK,HASH));
        });
        test("owner_and_snapshot_changes_cannot_reuse_resolution",()->{
            BackgroundAutoTargetResolver.Resolution r=resolve(NATURAL,saved);
            check(r.same(NATURAL,saved),"same immutable route input");
            check(!r.same(NATURAL+" ",saved)&&!r.same(NATURAL,list(shop))&&!r.same(NATURAL,saved.withAutomatic(false)),"owner/list/mode changes invalidate");
            BackgroundAutoTargetResolver.StartSelection start=confirm(r,flight);
            rejects(()->start.requireOwner(NATURAL+" "));
            rejects(()->BackgroundTaskTarget.resolveAutomaticSelection(PRODUCT,start));
        });
        test("actual_preview_separates_routability_and_verification",()->{
            try(Env e=new Env("generic-preview",NATURAL,false)){
                String preview=e.preview();
                check(preview.contains("携程")&&preview.contains("通用本地操作")&&preview.contains("暂不支持独立完成验证"),"actual UI warns only about missing verification");
            }
            try(Env e=new Env("known-preview",FLIGHT,false)){
                check(e.preview().contains("支持独立完成核对"),"actual known-contract preview");
            }
        });
        test("actual_ordinary_start_passes_unknown_to_existing_singleton_path_once",()->{
            try(Env e=new Env("generic-start",NATURAL,false)){
                check(e.ui.start(),"actual ordinary start");
                check(e.app.tasks.schedules==1&&!e.ui.pending()&&e.app.model.verificationCalls==0,"one schedule on already-qualified generation");
                BackgroundTaskTarget t=e.app.tasks.selection.taskTarget;
                check(t.nativeGoal==null&&t.automaticStart!=null&&t.profileTarget==e.flight.choice.profileTarget,"generic same-profile route");
                check(e.app.tasks.owner.equals(NATURAL)&&e.app.tasks.selection.independentProfileDisplay,"owner and background mode preserved");
                e.ui.onLocalModelSettingsChanged();check(e.app.tasks.schedules==1,"late event does not replay start");
            }
        });
        for(String change:Arrays.asList("owner","snapshot")){
            test("actual_pending_"+change+"_change_prevents_schedule",()->{
                try(Env e=new Env("pending-"+change,NATURAL,true)){
                    e.hold();e.startPending();
                    if("owner".equals(change))e.ui.edit("在小米商城查看手机价格");
                    else BackgroundAutoTargetPreferences.save(e.app,e.ui.automaticTargets.withAutomatic(false));
                    e.drain();
                    check(e.app.tasks.schedules==0&&!e.ui.pending(),"stale original start cannot schedule");
                    e.ui.onLocalModelSettingsChanged();check(e.app.tasks.schedules==0,"later callback remains inert");
                }
            });
        }
        test("actual_stale_installation_scope_and_nonbutton_admission_preserved",()->{
            try(Env e=new Env("stale-notes","在备忘录里查看笔记列表",false)){
                e.app.getPackageManager().install(BackgroundAutoTargetPreferences.NOTES,10491,new byte[]{9});
                check(!e.ui.start()&&e.app.tasks.schedules==0,"fresh installed identity still required");
            }
            try(Env e=new Env("scoped",NATURAL,false)){
                Files.write(new File(e.directory,QualificationScope.FILE_NAME).toPath(),new byte[]{1});
                check(!e.ui.start()&&e.app.tasks.schedules==0&&e.app.model.verificationCalls==0,"qualification scope cannot be bypassed");
            }
            try(Env e=new Env("nonbutton",NATURAL,false)){
                check(!e.ui.startForeign()&&e.app.tasks.schedules==0,"actual visible user-button origin still required");
            }
        });
        boolean pass=true;for(JSONObject row:results)pass&=row.getBoolean("passed");
        JSONObject report=new JSONObject().put("schema","hepta.natural-command-routing-cases.v1")
                .put("all_pass",pass).put("cases",results.size()).put("assertions",assertions).put("case_results",new JSONArray(results))
                .put("phone_operations",0).put("android_runtime",false).put("model_inference",false).put("business_verified",false)
                .put("actual_resolver_authorization_completion_grammar_and_ui",true)
                .put("synthetic_android_identity_assets_and_schedule_ports",true).put("private_phone_history_used",false);
        Files.write(root.resolve("RESULT.json"),report.toString(2).getBytes(StandardCharsets.UTF_8));
        System.out.println(report.toString());System.exit(pass?0:1);
    }
}
