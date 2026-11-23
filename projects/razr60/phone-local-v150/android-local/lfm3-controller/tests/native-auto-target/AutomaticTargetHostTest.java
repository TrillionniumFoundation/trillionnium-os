package org.trillionnium.hepta.local;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.ProfileIdentity;
import org.trillionnium.hepta.background.ProfileTarget;

/** Actual values/recognizers/Start/settings transaction; Android/asset/process IO
 * and schedule acceptance are declared ports. No App launch/input/model occurs. */
public final class AutomaticTargetHostTest {
    private static final String NOTES=BackgroundAutoTargetPreferences.NOTES;
    private static final String FLIGHT="查一下2099年11月17日北京到上海的单程机票，1名成人";
    private static final String PRODUCT="在小米商城App中查询AX3000T的价格";
    private static final String NOTE="新建一条备忘录，正文为：“携程和小米商城只是正文”，保存这条新笔记，然后回到笔记列表，重新打开它并停留在正文完整可见的页面。";
    private static final String HASH=String.join("",Collections.nCopies(64,"a"));
    private static int assertions;
    private static Path root;
    private static final List<JSONObject> results=new ArrayList<JSONObject>();
    private interface Work {void run()throws Exception;}
    private static void check(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    private static void rejects(Work work)throws Exception {boolean refused=false;try{work.run();}catch(IllegalArgumentException|IllegalStateException expected){refused=true;}check(refused,"actual production refusal required");}
    private static void test(String name,Work work)throws Exception {
        int before=assertions;JSONObject r=new JSONObject().put("name",name);results.add(r);
        try{work.run();r.put("passed",true);}catch(Throwable failure){r.put("passed",false).put("error",failure.toString());failure.printStackTrace();}
        r.put("assertions",assertions-before);
    }
    private static ProfileTarget profile(int user,String pkg){
        return new ProfileTarget(new ProfileIdentity(user,1000+user,0,ProfileIdentity.MANAGED),user*100000+10367,pkg,pkg+"/SyntheticActivity",7,
                Collections.singletonMap("base",HASH),Collections.singleton(HASH));
    }
    private static BackgroundAutoTargetPreferences.Entry target(int user,String pkg){return BackgroundAutoTargetPreferences.captureProfile(profile(user,pkg));}
    private static BackgroundAutoTargetResolver.Resolution resolve(String owner,BackgroundAutoTargetPreferences.Snapshot list){return BackgroundAutoTargetResolver.resolve(owner,list,TaskAuthorization.parse(owner));}
    private static final class Env implements AutoCloseable {
        final LocalProbeApplication app;final MainActivity ui;final File directory;
        final BackgroundAutoTargetPreferences.Entry notes,flight,product;
        final byte[] originalConfig;
        Env(String name,String owner,boolean visual)throws Exception {
            directory=root.resolve(name).toFile();check(directory.mkdir(),"fresh case directory");android.system.Os.chmod(directory.getPath(),0700);
            File model=new File(directory,"model");check(model.mkdir(),"fresh model dir");android.system.Os.chmod(model.getPath(),0700);
            originalConfig=visual?RuntimeConfigTransaction.selectedVisualTools("npu"):RuntimeConfigTransaction.selected(ModelProfile.LFM3.id,"npu");
            MobiMindPrivateFiles.writeNew(new File(model,"runtime-config.json"),originalConfig);
            // One-byte ports satisfy only the existing UI isFile check. The
            // actual LocalModelSettings asset endpoint is explicitly a port.
            Files.write(new File(model,ModelProfile.LFM3.fileName).toPath(),new byte[]{1});
            File image=new File(directory,ModelProfile.GUI_OWL_4B.visualDirectory());check(image.mkdir(),"visual port dir");
            Files.write(new File(image,ModelProfile.GUI_OWL_4B.fileName).toPath(),new byte[]{1});
            Files.write(new File(image,VlmResultContract.named(ModelProfile.GUI_OWL_4B.id).projectorFilename).toPath(),new byte[]{1});
            app=new LocalProbeApplication(directory);app.getPackageManager().install(NOTES,10490,"synthetic Notes signer".getBytes(StandardCharsets.UTF_8));
            notes=BackgroundAutoTargetPreferences.captureNotes(app);flight=target(10,ProfileTarget.CTRIP);product=target(10,ProfileTarget.XIAOMI);
            ui=new MainActivity(app,new BackgroundAutoTargetPreferences.Snapshot(true,Arrays.asList(notes,flight,product)),owner);
        }
        void hold(){app.model.verificationEntered=new CountDownLatch(1);app.model.verificationRelease=new CountDownLatch(1);}
        void startedSettings()throws Exception {
            check(ui.start(),"visible Start accepted preparation");long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);
            while(app.model.verificationEntered.getCount()!=0&&System.nanoTime()<deadline)android.os.Handler.pump();
            check(app.model.verificationEntered.getCount()==0&&ui.pending()&&app.modelSettings.isBusy(),"real settings worker reached asset boundary before Start");
            check(app.tasks.schedules==0,"no task before real settings completion");
        }
        void finish()throws Exception {
            if(app.model.verificationRelease!=null)app.model.verificationRelease.countDown();
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);
            while((app.modelSettings.isBusy()||android.os.Handler.size()!=0)&&System.nanoTime()<deadline)android.os.Handler.pump();
            check(!app.modelSettings.isBusy()&&android.os.Handler.size()==0,"settings callback and queued main work drained");
        }
        void noTask(){check(app.tasks.schedules==0&&!ui.pending(),"invalidated Start consumed without scheduling");ui.onLocalModelSettingsChanged();check(app.tasks.schedules==0,"later callback cannot resurrect Start");}
        public void close(){if(app.model.verificationRelease!=null)app.model.verificationRelease.countDown();app.modelSettings.close();app.model.close();}
    }
    public static void main(String[] args)throws Exception {
        root=Paths.get(args[0]);Files.createDirectories(root);android.os.Looper.getMainLooper();
        test("saved_instance_list_roundtrip_digest_and_manual_preferences_untouched",()->{
            try(Env e=new Env("roundtrip",NOTE,false)){
                BackgroundUiPreferences.save(e.app,e.notes.choice);Map<String,?> before=e.app.getSharedPreferences("background-ui-choice-v1",0).getAll();
                String encoded=BackgroundAutoTargetPreferences.encode(e.ui.automaticTargets);
                BackgroundAutoTargetPreferences.Snapshot again=BackgroundAutoTargetPreferences.decode(encoded);
                check(again.sha256.equals(e.ui.automaticTargets.sha256)&&again.targets.size()==3,"full identity/model list roundtrip");
                BackgroundAutoTargetPreferences.save(e.app,again);check(before.equals(e.app.getSharedPreferences("background-ui-choice-v1",0).getAll()),"independent preference file");
                check(again.entry(e.flight.instanceKey).modelProfile.equals(ModelProfile.GUI_OWL_4B.id),"visible Ctrip GUI preference");
            }
        });
        test("notes_body_app_names_never_route_and_old_long_contract_kept",()->{
            try(Env e=new Env("notes-routing",NOTE,false)){
                BackgroundAutoTargetResolver.Resolution r=resolve(NOTE,e.ui.automaticTargets);check(r.matches.size()==1&&r.choose(null)==e.notes,"full Notes body remains data");
                check(TaskCompletionGate.NOTES.equals(TaskCompletionGate.Contract.parse(NOTE,TaskAuthorization.parse(NOTE)).kind),"old complete Notes contract actually parsed");
                check(resolve(PRODUCT,e.ui.automaticTargets).choose(null)==e.product,"actual native shopping parser");
                check(resolve(FLIGHT,e.ui.automaticTargets).choose(null)==e.flight,"actual native flight parser");
            }
        });
        test("same_package_different_profile_ambiguous_requires_exact_instance",()->{
            try(Env e=new Env("ambiguity",FLIGHT,false)){
                BackgroundAutoTargetPreferences.Entry another=target(11,ProfileTarget.CTRIP);
                BackgroundAutoTargetPreferences.Snapshot list=new BackgroundAutoTargetPreferences.Snapshot(true,Arrays.asList(e.flight,another,e.notes));
                BackgroundAutoTargetResolver.Resolution r=resolve(FLIGHT,list);check(r.matches.size()==2,"no package deduplication");rejects(()->r.choose(null));
                check(r.choose(another.instanceKey)==another,"visible exact instance selection");rejects(()->r.choose(e.product.instanceKey));
            }
        });
        test("unknown_zero_saved_match_and_wrong_original_owner_refuse",()->{
            try(Env e=new Env("unknown",NOTE,false)){
                rejects(()->resolve("随便看看携程和小米",e.ui.automaticTargets).choose(null));
                rejects(()->resolve(FLIGHT,new BackgroundAutoTargetPreferences.Snapshot(true,Collections.singletonList(e.notes))).choose(null));
                rejects(()->BackgroundAutoTargetResolver.resolve(FLIGHT,e.ui.automaticTargets,TaskAuthorization.parse(NOTE)));
            }
        });
        test("six_limit_duplicate_profile_user_serial_conflict_and_empty_automatic",()->{
            List<BackgroundAutoTargetPreferences.Entry> items=new ArrayList<BackgroundAutoTargetPreferences.Entry>();for(int i=10;i<16;i++)items.add(target(i,ProfileTarget.CTRIP));
            check(new BackgroundAutoTargetPreferences.Snapshot(true,items).targets.size()==6,"exact six entries allowed");items.add(target(16,ProfileTarget.CTRIP));rejects(()->new BackgroundAutoTargetPreferences.Snapshot(true,items));
            rejects(()->new BackgroundAutoTargetPreferences.Snapshot(true,Collections.<BackgroundAutoTargetPreferences.Entry>emptyList()));
            rejects(()->new BackgroundAutoTargetPreferences.Snapshot(true,Arrays.asList(items.get(0),items.get(0))));
            ProfileTarget changed=new ProfileTarget(new ProfileIdentity(10,9999,0,ProfileIdentity.MANAGED),1010367,ProfileTarget.XIAOMI,ProfileTarget.XIAOMI+"/Synthetic",1,Collections.singletonMap("base",HASH),Collections.singleton(HASH));
            rejects(()->new BackgroundAutoTargetPreferences.Snapshot(true,Arrays.asList(items.get(0),BackgroundAutoTargetPreferences.captureProfile(changed))));
        });
        test("strict_preference_schema_model_identity_hash_and_trailing_data",()->{
            try(Env e=new Env("json",NOTE,false)){
                String raw=BackgroundAutoTargetPreferences.encode(e.ui.automaticTargets);
                rejects(()->BackgroundAutoTargetPreferences.decode(raw+" {}"));
                rejects(()->BackgroundAutoTargetPreferences.decode(new JSONObject(raw).put("unknown",1).toString()));
                JSONObject bad=new JSONObject(raw);bad.getJSONArray("targets").getJSONObject(0).put("compute","gpu");rejects(()->BackgroundAutoTargetPreferences.decode(bad.toString()));
                rejects(()->BackgroundAutoTargetPreferences.decode(new JSONObject(raw).put("sha256",HASH).toString()));
                e.app.getSharedPreferences("background-auto-targets-v1",0).fail=true;boolean failed=false;try{BackgroundAutoTargetPreferences.save(e.app,e.ui.automaticTargets);}catch(IllegalStateException expected){failed=true;}check(failed,"commit failure is visible");
            }
        });
        test("start_selection_provenance_original_owner_singleton_and_distinct_binding",()->{
            try(Env e=new Env("binding",FLIGHT,false)){
                BackgroundAutoTargetResolver.Resolution r=resolve(FLIGHT,e.ui.automaticTargets);String nonce=String.join("",Collections.nCopies(32,"b"));
                BackgroundAutoTargetResolver.StartSelection s=r.confirm(e.flight,nonce,e.app.model.runtimeGeneration().id,e.app.model.runtimeGeneration().source.sha());
                BackgroundTaskTarget target=BackgroundTaskTarget.resolveAutomaticSelection(FLIGHT,s);BackgroundSession.Selection selection=new BackgroundSession.Selection(target,true,false);
                TaskAuthorization a=TaskAuthorization.parse(FLIGHT).forExecutionSelection(selection);selection.requireTaskTarget(FLIGHT,a);
                check(target.profileTarget==e.flight.choice.profileTarget&&target.effectivePackages.equals(Collections.singleton(ProfileTarget.CTRIP)),"actual same ProfileTarget singleton");
                check(Boolean.FALSE.equals(s.evidence().get("grants_dispatch_authority"))&&s.evidence().get("saved_target_list_sha256").equals(e.ui.automaticTargets.sha256),"origin evidence has no dispatch authority");
                check(!target.targetSha256.equals(BackgroundTaskTarget.resolveExplicitSelection(FLIGHT,ProfileTarget.CTRIP,Collections.singleton(ProfileTarget.CTRIP),e.flight.choice.profileTarget).targetSha256),"auto origin changes binding");
                rejects(()->BackgroundTaskTarget.resolveAutomaticSelection(PRODUCT,s));rejects(()->r.confirm(target(10,ProfileTarget.CTRIP),nonce,e.app.model.runtimeGeneration().id,HASH));
            }
        });
        test("current_matching_model_no_settings_write_single_start",()->{
            try(Env e=new Env("same",NOTE,false)){
                LocalModelEngine.RuntimeGeneration before=e.app.model.runtimeGeneration();byte[] config=Files.readAllBytes(new File(e.directory,"model/runtime-config.json").toPath());
                check(e.ui.start(),"actual visible Start");check(e.app.tasks.schedules==1&&!e.ui.pending(),"one original schedule");
                check(e.app.model.verificationCalls==0&&e.app.model.runtimeGeneration()==before,"no settings transaction for same profile");
                check(Arrays.equals(config,Files.readAllBytes(before.source.path.toPath()))&&!new File(e.directory,"runtime-settings").exists(),"runtime config untouched");
                check(e.app.tasks.selection.taskTarget.automaticStart!=null&&e.app.tasks.selection.independentPersonalDisplay,"actual target selection plus original display mode");
                e.ui.onLocalModelSettingsChanged();e.ui.onLocalModelSettingsChanged();check(e.app.tasks.schedules==1,"second callback cannot schedule");
            }
        });
        test("gui_preference_real_settings_transaction_new_generation_then_original_start",()->{
            try(Env e=new Env("switch-gui",FLIGHT,false)){
                e.hold();LocalModelEngine.RuntimeGeneration before=e.app.model.runtimeGeneration();e.startedSettings();e.finish();
                check(e.app.tasks.schedules==1&&!e.ui.pending(),"only after real transaction callback");
                check(e.app.model.runtimeGeneration()!=before&&e.app.model.configuration().profile==ModelProfile.GUI_OWL_4B,"actual new generation/config");
                check(e.app.model.verificationCalls==1&&RuntimeConfigTransaction.restoreAvailable(e.directory),"original transaction committed exact restore pointer");
                check(e.app.tasks.selection.profileTarget==e.flight.choice.profileTarget&&e.app.tasks.selection.independentProfileDisplay,"same managed instance");
                check(!RuntimeConfigTransaction.pending(e.directory),"durable pending marker retired");
                e.ui.onLocalModelSettingsChanged();check(e.app.tasks.schedules==1,"no callback replay");
            }
        });
        test("notes_preference_returns_to_npu_with_same_transaction",()->{
            try(Env e=new Env("switch-notes",NOTE,true)){
                e.hold();e.startedSettings();e.finish();check(e.app.tasks.schedules==1&&e.app.model.configuration().profile==ModelProfile.LFM3,"per target switch before task");
                check(e.app.model.verificationCalls==1&&e.app.tasks.selection.taskTarget.packageName.equals(NOTES),"one settings and one singleton task");
            }
        });
        for(String variant:new String[]{"text","choice","mode","background_mode","saved_list","focus","stop_resume","cancel","second_start"}){
            test("pending_invalidation_"+variant,()->{
                try(Env e=new Env("invalidate-"+variant,FLIGHT,false)){
                    e.hold();e.startedSettings();
                    if("text".equals(variant))e.ui.edit(PRODUCT);
                    else if("choice".equals(variant))e.ui.choose(e.product.instanceKey);
                    else if("mode".equals(variant))e.ui.mode(false);
                    else if("background_mode".equals(variant))e.ui.backgroundMode.setChecked(false);
                    else if("saved_list".equals(variant))BackgroundAutoTargetPreferences.save(e.app,e.ui.automaticTargets.withAutomatic(false));
                    else if("focus".equals(variant))e.ui.onWindowFocusChanged(false);
                    else if("stop_resume".equals(variant))e.ui.stopActivity();
                    else if("cancel".equals(variant))e.ui.cancel();
                    else check(!e.ui.start(),"second Start while settings busy refused");
                    e.finish();if("stop_resume".equals(variant))e.ui.resumeActivity();e.noTask();
                }
            });
        }
        test("settings_failure_actual_rollback_wrong_profile_never_resumes",()->{
            try(Env e=new Env("asset-fail",FLIGHT,false)){
                e.hold();e.app.model.failVerification=true;e.startedSettings();e.finish();e.noTask();
                check(e.app.model.configuration().profile==ModelProfile.LFM3&&Arrays.equals(e.originalConfig,Files.readAllBytes(new File(e.directory,"model/runtime-config.json").toPath())),"actual original config restored");
            }
        });
        test("current_generation_invalid_readiness_prevents_settings_and_schedule",()->{
            try(Env e=new Env("invalid-runtime",FLIGHT,false)){
                e.app.model.hostError();check(!e.ui.start(),"invalid actual configuration refused");e.noTask();check(e.app.model.verificationCalls==0,"no new settings admission");
            }
        });
        test("same_profile_actual_source_changed_refuses_without_schedule",()->{
            try(Env e=new Env("changed-source",NOTE,false)){
                Files.write(new File(e.directory,"model/runtime-config.json").toPath(),RuntimeConfigTransaction.selected(ModelProfile.LFM3.id,"gpu"));
                check(!e.ui.start(),"same object profile is insufficient when actual source changed");e.noTask();check(e.app.model.verificationCalls==0,"no settings fallback");
            }
        });
        test("actual_generation_replaced_during_final_ui_binding_refuses",()->{
            try(Env e=new Env("generation-change",NOTE,false)){
                final LocalModelEngine.RuntimeGeneration old=e.app.model.runtimeGeneration();
                e.app.getSharedPreferences("background-auto-targets-v1",0).beforeRead=()->{
                    e.app.getSharedPreferences("background-auto-targets-v1",0).beforeRead=()->{
                        try{e.app.model.hostGeneration(LocalModelEngine.generation(old.source,new ModelFileVerifier()));}
                        catch(Exception failure){throw new IllegalStateException(failure);}
                    };
                };
                // The second read occurs with the original pending already captured.
                // A new actual generation has identical bytes but a distinct identity.
                check(!e.ui.start(),"runtime/profile mismatch cannot be accepted as current readiness");e.noTask();
            }
        });
        test("ordinary_start_failure_clears_pending_and_no_late_callback_retry",()->{
            try(Env e=new Env("schedule-fail",NOTE,false)){
                e.app.tasks.failSchedule=true;check(!e.ui.start(),"original task slot admission failure");
                check(e.app.tasks.schedules==1&&!e.ui.pending(),"attempt consumed, no pending retained");e.ui.onLocalModelSettingsChanged();check(e.app.tasks.schedules==1,"no retry after failed schedule");
            }
        });
        test("scope_nonbutton_absent_visibility_and_stale_install_all_refuse",()->{
            try(Env e=new Env("nonbutton",NOTE,false)){check(!e.ui.startForeign(),"nonbutton source");e.noTask();}
            try(Env e=new Env("visibility",NOTE,false)){e.ui.focused=false;check(!e.ui.start(),"no actual focus");e.noTask();}
            try(Env e=new Env("scope",FLIGHT,false)){Files.write(new File(e.directory,QualificationScope.FILE_NAME).toPath(),new byte[]{1});check(!e.ui.start(),"scope before settings");e.noTask();check(e.app.model.verificationCalls==0,"no settings before scope rejection");}
            try(Env e=new Env("stale-install",NOTE,false)){e.app.getPackageManager().install(NOTES,10491,new byte[]{9});check(!e.ui.start(),"actual PackageManager differs");e.noTask();}
        });
        test("manual_explicit_initial_not_overridden_by_owner_or_saved_auto_list",()->{
            try(Env e=new Env("manual",FLIGHT,false)){
                e.ui.mode(false);e.ui.manual=e.notes.choice;e.ui.manualPersonal=true;e.ui.backgroundPackages.add(NOTES);
                check(e.ui.start(),"ordinary manual Start remains allowed");check(e.app.tasks.selection.taskTarget.packageName.equals(NOTES)&&e.app.tasks.selection.taskTarget.nativeGoal==null,"explicit Notes wins flight owner as before");
                check(e.app.tasks.selection.taskTarget.automaticStart==null&&e.app.model.verificationCalls==0,"no auto provenance or model switch in manual mode");
            }
        });
        boolean pass=true;for(JSONObject row:results)pass&=row.getBoolean("passed");
        JSONObject report=new JSONObject().put("schema","hepta.automatic-target-cases.v1").put("all_pass",pass).put("cases",results.size()).put("assertions",assertions)
                .put("case_results",new JSONArray(results)).put("phone_operations",0).put("model_inference",false).put("android_runtime",false).put("business_verified",false)
                .put("actual_transaction_and_ui_methods",true).put("android_asset_process_and_schedule_ports",true);
        Files.write(root.resolve("RESULT.json"),report.toString(2).getBytes(StandardCharsets.UTF_8));System.out.println(report.toString());System.exit(pass?0:1);
    }
}
