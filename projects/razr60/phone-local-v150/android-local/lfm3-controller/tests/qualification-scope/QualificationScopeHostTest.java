package org.trillionnium.hepta.local;

import android.content.*;
import android.content.pm.*;
import android.os.*;
import org.json.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

/** Production gates and dispatch calls; all package/UI/model evidence is synthetic. */
public final class QualificationScopeHostTest {
    static final String SETTINGS="com.android.settings",SEARCH="com.android.settings.intelligence",CALC="com.motorola.cn.calculator",HOME="com.motorola.launcher3";
    static final String[] FOREIGN={"com.google.android.apps.messaging","com.android.dialer","com.android.contacts","com.motorola.cn.searchintelligence"};
    static final String H="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static final List<String> passed=new ArrayList<String>();static Path output;
    interface Case{void run()throws Exception;}
    static void test(String name,Case body)throws Exception{body.run();passed.add(name);System.out.println("PASS "+name);}
    static void check(boolean value,String reason){if(!value)throw new AssertionError(reason);}
    static void rejects(Case body)throws Exception{try{body.run();}catch(QualificationScope.Violation expected){return;}throw new AssertionError("expected refusal");}
    static byte[] bytes(String value){return value.getBytes(StandardCharsets.UTF_8);}
    static void write(Path path,byte[] bytes,int mode)throws Exception{Files.createDirectories(path.getParent());Files.write(path,bytes);android.system.Os.chmod(path.toString(),mode);}
    static final class Env implements AutoCloseable {
        final Path dir;final PackageManager pm=new PackageManager();final HeptaAccessibilityService service;
        final LocalRuntimeConfig runtime=new LocalRuntimeConfig(ModelProfile.ORVENA4B,"npu",8192,4);
        final Map<String,Object> fields=new LinkedHashMap<String,Object>();final String task="11111111111111111111111111111111";
        byte[] config;String scopeSha;QualificationScopeConfig.Bound bound;LocalTaskController controller;boolean cleanupUnknown,invalidRuntime;Case closeMutation;
        Env(boolean scoped)throws Exception{this(scoped,false);}
        Env(boolean scoped,boolean frameworkAlias)throws Exception{
            Path parent=Files.createTempDirectory(output,"scope-");File frameworkFiles;
            if(frameworkAlias){
                dir=Files.createDirectory(parent.resolve("files"));
                Path alias=parent.resolveSibling(parent.getFileName().toString()+"-framework-alias");
                Files.createSymbolicLink(alias,parent);frameworkFiles=alias.resolve("files").toFile();
                check(!frameworkFiles.getAbsoluteFile().equals(frameworkFiles.getCanonicalFile()),"fixture must expose a real ancestor alias");
            }else{dir=parent;frameworkFiles=dir.toFile();}
            String[] packages={"org.trillionnium.hepta.local",SETTINGS,SEARCH,CALC,HOME};
            for(int i=0;i<packages.length;i++){
                PackageInfo info=new PackageInfo();info.packageName=packages[i];info.version=i==0?30:100+i;
                info.applicationInfo=new ApplicationInfo();info.applicationInfo.packageName=packages[i];info.applicationInfo.uid=i==0?android.os.Process.myUid():10000+i;
                Path apk=dir.resolve("installed/"+i+".apk");write(apk,bytes("synthetic-apk-"+packages[i]),0644);info.applicationInfo.sourceDir=apk.toString();pm.packages.put(packages[i],info);
            }
            service=new HeptaAccessibilityService(frameworkFiles,pm);service.prepare(SETTINGS);
            service.launchable.put(SETTINGS,"设置");service.launchable.put(CALC,"计算器");service.launchable.put(HOME,"桌面");
            for(String p:FOREIGN)service.launchable.put(p,"synthetic-foreign");
            byte[] asset=bytes("{\"schema\":\"hepta.actual-build-inputs.v1\",\"version_code\":30,\"source_inputs\":[{\"path\":\"synthetic-fixture-only\",\"sha256\":\""+H+"\"}]}");
            write(dir.resolve("assets/"+QualificationScope.BUILD_ASSET),asset,0644);
            byte[] runtimeBytes=bytes("{\"schema\":\"hepta.local-runtime.v2\",\"model_profile\":\"orvena-4b-q4_k_m\",\"compute\":\"npu\",\"context_tokens\":8192,\"threads\":4}");
            write(dir.resolve("model/runtime-config.json"),runtimeBytes,0600);
            fields.put("schema","hepta.qualification-scope.v1");fields.put("enabled",true);fields.put("qualification_id","synthetic-host-only");
            fields.put("build_identity_sha256",QualificationScope.hash(asset));fields.put("runtime_config_sha256",QualificationScope.hash(runtimeBytes));fields.put("hepta_version_code",30);
            fields.put("hepta_apk_sha256",QualificationScope.hash(Files.readAllBytes(Paths.get(pm.packages.get(packages[0]).applicationInfo.sourceDir))));
            fields.put("launcher_component",HOME+"/"+HOME+".Launcher");
            java.util.List<String> roles=QualificationScope.ROLES;
            for(int i=0;i<roles.size();i++){
                String role=roles.get(i),p=packages[i+1];PackageInfo info=pm.packages.get(p);
                String sha=QualificationScope.hash(Files.readAllBytes(Paths.get(info.applicationInfo.sourceDir)));
                fields.put(role+"_package",p);fields.put(role+"_uid",info.applicationInfo.uid);fields.put(role+"_version_code",info.version);
                fields.put(role+"_apk_set_sha256",QualificationScope.hash(bytes("base\t"+sha+"\n")));
                fields.put(role+"_observation_sha256",QualificationScope.hash(bytes("synthetic independent observed UI:"+p)));
            }
            updateConfig();if(scoped)writeConfig();
        }
        void updateConfig(){config=bytes(new JSONObject(fields).toString());scopeSha=QualificationScope.hash(config);}
        void writeConfig()throws Exception{write(dir.resolve(QualificationScope.FILE_NAME),config,0600);}
        void bind(String expected)throws Exception{bindOwner(expected,"执行合成测试任务。");}
        OwnerActionPolicy bindOwner(String expected,String owner)throws Exception{
            check(service.acquireTask(task,()->{}),"lease acquisition");bound=QualificationScopeConfig.capture(service,task,expected,runtime);service.bindQualificationScope(task,bound);
            OwnerActionPolicy policy=OwnerActionPolicy.compile(task,owner);service.bindOwnerActionPolicy(task,policy);
            return policy;
        }
        ActionDecision action(String kind,String target)throws Exception{return ActionDecision.parse(actionText(kind,target),DecisionGrammar.SCHEMA);}
        String actionText(String kind,String target)throws Exception{
            JSONObject row=new JSONObject().put("reason","核对当前测试画面后执行一步").put("action",kind).put("observation_id",service.current.id).put("package",target);
            if("click".equals(kind)||"type".equals(kind)||"scroll".equals(kind))row.put("node_label","测试").put("node_id","n0");
            if("type".equals(kind))row.put("text","42");if("scroll".equals(kind))row.put("direction","forward");if("wait".equals(kind))row.put("duration_ms",100);
            if("done".equals(kind))row.put("status","success").put("summary","synthetic only");if("find_app".equals(kind))row.put("query","计算器").put("offset",0);
            return row.toString();
        }
        HeptaAccessibilityService.ActionOutcome run(String kind,String target)throws Exception{return service.execute(action(kind,target));}
        void zeroDenied(HeptaAccessibilityService.ActionOutcome result){check(result!=null&&!result.accepted&&!result.dispatched&&!result.stale&&service.effects()==0,"scope denial must be terminal and dispatch nothing");check(result.qualificationScope!=null,"scope receipt missing");}
        LocalTaskController.TaskResult controller(String firstAction,String target,Runnable atModel)throws Exception{
            CountingModel model=new CountingModel(this,firstAction,target,atModel);service.testInference=model;
            controller=new LocalTaskController(service,model);final LocalTaskController.TaskResult[] result=new LocalTaskController.TaskResult[1];CountDownLatch latch=new CountDownLatch(1);
            check(controller.start("打开设置并完成本地测试",scopeSha,new LocalTaskController.Listener(){public void onState(String s){}public void onFinished(LocalTaskController.TaskResult r){result[0]=r;latch.countDown();}}),"controller starts");
            check(latch.await(10,TimeUnit.SECONDS),"controller terminal timeout");
            write(dir.resolve("host-native-call-count.txt"),bytes(Integer.toString(model.calls)),0600);return result[0];
        }
        public void close(){if(controller!=null)controller.close();if(service.ownedController!=null)service.ownedController.close();service.releaseTask(task);Handler.queued.clear();Handler.hold=false;Handler.holdPosts=false;}
    }
    static final class CountingModel implements LocalInference {
        final Env env;final String action,target;final Runnable mutate;int calls;
        CountingModel(Env e,String a,String t,Runnable m){env=e;action=a;target=t;mutate=m;}
        public LocalRuntimeConfig configuration(){if(env.invalidRuntime)throw new IllegalStateException("synthetic invalid runtime");return env.runtime;}
        public TaskCleanup endTask(){if(env.closeMutation!=null)try{env.closeMutation.run();}catch(Exception e){throw new IllegalStateException(e);}return env.cleanupUnknown?new TaskCleanup(false,true,false,null,null,env.task,false,null):TaskCleanup.noWorker();}
        public Handle generate(String prompt,String system,File image,DecisionGrammar grammar,int n,long timeout,Callback callback){
            calls++;try{
                String text=env.actionText(action,target);
                // In the independent label-first integration, obtain the required
                // open label from the actual supplied grammar, never a guessed label.
                if("open".equals(action))try{
                    Object appLabels=grammar.getClass().getField("appLabels").get(grammar);
                    if(appLabels!=null){Object map=appLabels.getClass().getField("labels").get(appLabels);
                        Object label=((Map<?,?>)map).get(target);check(label instanceof String,"test target was not supplied in actual app grammar");
                        JSONObject old=new JSONObject(text);text=new JSONObject().put("reason",old.get("reason")).put("action",old.get("action"))
                            .put("observation_id",old.get("observation_id")).put("app_label",label).put("package",old.get("package")).toString();}
                }catch(NoSuchFieldException legacyV3){/* exact ec9 legacy grammar has no appLabels field */}
                if(mutate!=null)mutate.run();callback.onSuccess(text,String.format(Locale.ROOT,"%032x",calls));}
            catch(Exception failure){throw new IllegalStateException(failure);}return ()->{};
        }
    }
    static void productionControllerCases()throws Exception{
        test("controller_foreign_open_terminal_failed_one_model_zero_dispatch",()->{try(Env e=new Env(true)){
            LocalTaskController.TaskResult r=e.controller("open",FOREIGN[2],null);check("failed".equals(r.status)&&!r.modelReportedSuccess&&r.cleanupKnown,"controller result must fail with known cleanup");check(e.service.effects()==0,"no foreign open");
            JSONObject result=new JSONObject(new String(Files.readAllBytes(r.evidenceDirectory.toPath().resolve("result.json")),StandardCharsets.UTF_8));check(e.scopeSha.equals(result.getString("expected_scope_sha256"))&&e.scopeSha.equals(result.getString("actual_scope_sha256")),"result scope bound");
            JSONObject action=new JSONObject(new String(Files.readAllBytes(r.evidenceDirectory.toPath().resolve("step-01-action.json")),StandardCharsets.UTF_8));check(!action.getBoolean("dispatched")&&!action.getBoolean("accepted"),"actual action receipt denial");check("1".equals(new String(Files.readAllBytes(e.dir.resolve("host-native-call-count.txt")),StandardCharsets.UTF_8)),"no second model");
        }});
        test("controller_foreground_changes_after_model_before_action_zero_dispatch",()->{try(Env e=new Env(true)){
            LocalTaskController.TaskResult r=e.controller("click",SETTINGS,()->e.service.root.pkg=FOREIGN[0]);check("failed".equals(r.status)&&!r.modelReportedSuccess&&e.service.effects()==0,"late foreign foreground must fail");
        }});
        test("controller_node_package_changes_before_dispatch_zero_effects",()->{try(Env e=new Env(true)){
            LocalTaskController.TaskResult r=e.controller("type",SETTINGS,()->e.service.node.pkg=FOREIGN[1]);check("failed".equals(r.status)&&!r.modelReportedSuccess&&e.service.effects()==0,"foreign refreshed node must fail");
        }});
        test("allowed_click_navigates_foreign_then_terminal_no_second_model",()->{try(Env e=new Env(true)){
            e.service.effectHook=()->e.service.root.pkg=FOREIGN[2];LocalTaskController.TaskResult r=e.controller("click",SETTINGS,null);
            check("failed".equals(r.status)&&!r.modelReportedSuccess&&e.service.effects()==1,"one scoped click, no foreign follow-up");
            check("1".equals(new String(Files.readAllBytes(e.dir.resolve("host-native-call-count.txt")),StandardCharsets.UTF_8)),"no second model after outside observation");
        }});
        test("controller_runtime_failure_still_records_owner_expectation_null_actual",()->{try(Env e=new Env(true)){
            e.invalidRuntime=true;LocalTaskController.TaskResult r=e.controller("done",SETTINGS,null);
            check("failed".equals(r.status)&&r.steps==0&&r.actualScopeSha256==null,"invalid runtime fails before inference");
            JSONObject owner=new JSONObject(new String(Files.readAllBytes(r.evidenceDirectory.toPath().resolve("owner.json")),StandardCharsets.UTF_8));
            check(e.scopeSha.equals(owner.getString("expected_scope_sha256"))&&owner.isNull("actual_scope_sha256")&&owner.isNull("qualification_scope"),"owner explicit unknown scope");
        }});
        test("controller_expected_scope_missing_records_null_actual_zero_model",()->{try(Env e=new Env(true)){
            Files.delete(e.dir.resolve(QualificationScope.FILE_NAME));LocalTaskController.TaskResult r=e.controller("done",SETTINGS,null);
            check("failed".equals(r.status)&&r.steps==0&&!r.modelReportedSuccess&&r.actualScopeSha256==null,"missing expected scope cannot become unrestricted");
            JSONObject owner=new JSONObject(new String(Files.readAllBytes(r.evidenceDirectory.toPath().resolve("owner.json")),StandardCharsets.UTF_8));check(owner.isNull("actual_scope_sha256")&&e.scopeSha.equals(owner.getString("expected_scope_sha256")),"null actual explicitly recorded");
        }});
        test("scope_failure_cannot_hide_unknown_native_cleanup_or_release_lease",()->{try(Env e=new Env(true)){
            e.cleanupUnknown=true;LocalTaskController.TaskResult r=e.controller("open",FOREIGN[2],null);
            check("blocked".equals(r.status)&&!r.cleanupKnown&&!r.modelReportedSuccess&&e.service.effects()==0,"cleanup unknown dominates scope failure");
            check(!e.service.acquireTask("22222222222222222222222222222222",()->{}),"unknown cleanup keeps lease blocked");
        }});
        for(String changed:new String[]{QualificationScope.FILE_NAME,"model/runtime-config.json"})test("controller_rechecks_"+changed+"_after_blocking_close",()->{try(Env e=new Env(true)){
            e.closeMutation=()->write(e.dir.resolve(changed),bytes("{}"),0600);LocalTaskController.TaskResult r=e.controller("done",SETTINGS,null);
            check("failed".equals(r.status)&&!r.modelReportedSuccess&&r.cleanupKnown&&r.steps==1,"post-close mutation must downgrade done");
            JSONObject value=new JSONObject(new String(Files.readAllBytes(r.evidenceDirectory.toPath().resolve("result.json")),StandardCharsets.UTF_8));
            check(value.getJSONObject("qualification_scope").getBoolean("scope_refused"),"post-close refusal recorded");
        }});
        test("controller_valid_done_retains_expected_actual_and_scope_receipt",()->{try(Env e=new Env(true)){
            LocalTaskController.TaskResult r=e.controller("done",SETTINGS,null);check("model_reported_done".equals(r.status)&&r.modelReportedSuccess&&r.cleanupKnown&&e.service.effects()==0,"valid done control");check(e.scopeSha.equals(r.expectedScopeSha256)&&e.scopeSha.equals(r.actualScopeSha256),"result object identity");
        }});
    }
    static void apkSplitCases()throws Exception{
        for(int combination=0;combination<4;combination++){
            final int shape=combination;
            test("installed_base_only_null_empty_shape_"+shape,()->{try(Env e=new Env(true)){
                for(PackageInfo info:e.pm.packages.values()){
                    info.splitNames=(shape&1)==0?null:new String[0];
                    info.applicationInfo.splitSourceDirs=(shape&2)==0?null:new String[0];
                }
                QualificationScopeConfig.Bound bound=QualificationScopeConfig.capture(e.service,e.task,e.scopeSha,e.runtime);
                bound.requireReady();bound.verifyUnchanged();
                check(e.scopeSha.equals(bound.actualSha256),"base-only scope identity retained");
                // Equivalent zero representations do not change the installed APK set.
                for(PackageInfo info:e.pm.packages.values()){
                    info.splitNames=info.splitNames==null?new String[0]:null;
                    info.applicationInfo.splitSourceDirs=info.applicationInfo.splitSourceDirs==null?new String[0]:null;
                }
                bound.verifyUnchanged();
                LocalTaskController.TaskResult result=e.controller("done",SETTINGS,null);
                check("model_reported_done".equals(result.status)&&result.steps==1&&result.cleanupKnown,"base-only controller must reach one synthetic model step: "+result.summary);
            }});
        }
        test("installed_nonempty_split_pairs_hash_and_revalidation",()->{try(Env e=new Env(true)){
            PackageInfo info=e.pm.packages.get(CALC);Path first=e.dir.resolve("installed/config.en.apk"),second=e.dir.resolve("installed/config.arm64_v8a.apk");
            byte[] firstBytes=bytes("synthetic English split"),secondBytes=bytes("synthetic arm64 split");
            write(first,firstBytes,0644);write(second,secondBytes,0644);
            info.splitNames=new String[]{"config.en","config.arm64_v8a"};
            info.applicationInfo.splitSourceDirs=new String[]{first.toString(),second.toString()};
            String rows="base\t"+QualificationScope.hash(Files.readAllBytes(Paths.get(info.applicationInfo.sourceDir)))+"\n"
                    +"split:config.arm64_v8a\t"+QualificationScope.hash(secondBytes)+"\n"
                    +"split:config.en\t"+QualificationScope.hash(firstBytes)+"\n";
            e.fields.put("calculator_apk_set_sha256",QualificationScope.hash(bytes(rows)));e.updateConfig();e.writeConfig();
            e.bind(e.scopeSha);e.bound.requireReady();e.bound.verifyUnchanged();
            info.applicationInfo.splitSourceDirs[1]=first.toString();
            rejects(()->e.bound.verifyUnchanged());
        }});
        for(int variant=0;variant<8;variant++){
            final int shape=variant;
            test("installed_malformed_splits_still_refused_"+shape,()->{try(Env e=new Env(true)){
                PackageInfo info=e.pm.packages.get(CALC);String apk=info.applicationInfo.sourceDir;
                switch(shape){
                    case 0:info.splitNames=new String[]{"config.en"};info.applicationInfo.splitSourceDirs=null;break;
                    case 1:info.splitNames=null;info.applicationInfo.splitSourceDirs=new String[]{apk};break;
                    case 2:info.splitNames=new String[]{"config.en"};info.applicationInfo.splitSourceDirs=new String[0];break;
                    case 3:info.splitNames=new String[0];info.applicationInfo.splitSourceDirs=new String[]{apk};break;
                    case 4:info.splitNames=new String[]{"config.en"};info.applicationInfo.splitSourceDirs=new String[]{apk,apk};break;
                    case 5:info.splitNames=new String[]{null};info.applicationInfo.splitSourceDirs=new String[]{apk};break;
                    case 6:info.splitNames=new String[]{"config.en"};info.applicationInfo.splitSourceDirs=new String[]{null};break;
                    default:info.splitNames=new String[]{"config.en","config.en"};info.applicationInfo.splitSourceDirs=new String[]{apk,apk};break;
                }
                e.bind(e.scopeSha);rejects(()->e.bound.requireReady());check(e.bound.restricted(),"malformed split metadata must not downgrade to unrestricted");
                if(shape<5){String refusal=e.bound.evidence().getString("refusal");
                    check(refusal.contains(CALC)&&refusal.contains("splitNames=")&&refusal.contains("splitSourceDirs=")&&!refusal.contains(e.dir.toString()),"count failure must identify package/shape without private paths");}
            }});
        }
    }
    static void privatePathCases()throws Exception{
        test("framework_root_alias_scope_runtime_controller_evidence_and_revalidation",()->{try(Env e=new Env(true,true)){
            QualificationScopeConfig.Bound bound=QualificationScopeConfig.capture(e.service,e.task,e.scopeSha,e.runtime);
            bound.requireReady();bound.verifyUnchanged();
            check(bound.scopePath.equals(e.dir.resolve(QualificationScope.FILE_NAME).toFile()),"scope must retain canonical root plus unchanged child");
            check(bound.runtimeFile.path.equals(e.dir.resolve("model/runtime-config.json").toFile()),"runtime must share captured canonical root");
            LocalTaskController.TaskResult r=e.controller("done",SETTINGS,null);
            check("model_reported_done".equals(r.status)&&r.modelReportedSuccess&&r.cleanupKnown&&r.steps==1,"scoped controller must reach one synthetic model step: "+r.summary);
            check(e.scopeSha.equals(r.expectedScopeSha256)&&e.scopeSha.equals(r.actualScopeSha256)&&e.service.effects()==0,"scope identity and zero UI effects");
            Path evidence=r.evidenceDirectory.toPath();
            check(Arrays.equals(e.config,Files.readAllBytes(evidence.resolve("qualification-scope.json"))),"scope evidence exact bytes");
            check(Arrays.equals(bound.buildBytes,Files.readAllBytes(evidence.resolve("build-identity.json"))),"build evidence exact bytes");
            check(Arrays.equals(bound.runtimeFile.bytes,Files.readAllBytes(evidence.resolve("scope-runtime-config.json"))),"runtime evidence exact bytes");
            bound.verifyUnchanged();
        }});
        test("framework_root_alias_does_not_accept_scope_leaf_symlink",()->{try(Env e=new Env(true,true)){
            Path scope=e.dir.resolve(QualificationScope.FILE_NAME),target=e.dir.resolve("same-scope-bytes.json");
            Files.move(scope,target);Files.createSymbolicLink(scope,target);
            QualificationScopeConfig.Bound bound=QualificationScopeConfig.capture(e.service,e.task,e.scopeSha,e.runtime);
            rejects(()->bound.requireReady());check(bound.restricted()&&bound.raw==null,"leaf symlink must be refused before scope bytes load");
        }});
        test("framework_root_alias_does_not_accept_model_directory_symlink",()->{try(Env e=new Env(true,true)){
            Path model=e.dir.resolve("model"),target=e.dir.resolve("same-model-directory");
            Files.move(model,target);Files.createSymbolicLink(model,target);
            QualificationScopeConfig.Bound bound=QualificationScopeConfig.capture(e.service,e.task,e.scopeSha,e.runtime);
            rejects(()->bound.requireReady());check(bound.restricted()&&e.scopeSha.equals(bound.actualSha256)&&bound.runtimeFile==null,"intermediate child symlink must be refused before runtime read");
        }});
    }
    public static void main(String[] args)throws Exception{
        check(args.length==1||(args.length==2&&"--apk-splits-only".equals(args[1])),"unexpected host test mode");
        output=Paths.get(args[0]);Files.createDirectories(output);apkSplitCases();
        if(args.length==2){writeResult();return;}
        privatePathCases();
        test("closed_config_exact_roles_and_proof_identity",()->{try(Env e=new Env(true)){QualificationScope.Config c=QualificationScope.Config.parse(e.config);check(c.allows(SETTINGS)&&c.allows(SEARCH)&&c.allows(CALC)&&c.allows(HOME),"all roles");for(String p:FOREIGN)check(!c.allows(p),"foreign excluded");}});
        test("closed_config_missing_unknown_duplicate_and_type_rejected",()->{try(Env e=new Env(true)){
            final Map<String,Object> missing=new LinkedHashMap<String,Object>(e.fields);missing.remove("search_observation_sha256");rejects(()->QualificationScope.Config.parse(bytes(new JSONObject(missing).toString())));
            Map<String,Object> m=new LinkedHashMap<String,Object>(e.fields);m.put("allow_all",true);final byte[] unknown=bytes(new JSONObject(m).toString());rejects(()->QualificationScope.Config.parse(unknown));
            rejects(()->QualificationScope.Config.parse(bytes(new String(e.config,StandardCharsets.UTF_8).replaceFirst("\\{","{\"enabled\":true,"))));
            rejects(()->QualificationScope.Config.parse(bytes(new String(e.config,StandardCharsets.UTF_8).replace("\"enabled\":true","\"enabled\":\"true\""))));
        }});
        test("config_cannot_guess_search_alias_or_allow_contacts_role",()->{try(Env e=new Env(true)){e.fields.put("search_package",FOREIGN[3]);e.updateConfig();rejects(()->QualificationScope.Config.parse(e.config));e.fields.put("search_package",SEARCH);e.fields.put("calculator_package",FOREIGN[2]);e.updateConfig();rejects(()->QualificationScope.Config.parse(e.config));}});
        test("config_invalid_utf8_unpaired_unicode_and_oversize_rejected",()->{rejects(()->QualificationScope.Config.parse(new byte[]{(byte)0xff}));rejects(()->QualificationScope.Config.parse(bytes("{\"x\":\"\\ud800\"}")));rejects(()->QualificationScope.Config.parse(new byte[16385]));});
        test("capture_exact_installed_assets_runtime_home_verified",()->{try(Env e=new Env(true)){e.bind(e.scopeSha);e.bound.requireReady();check(e.bound.restricted()&&e.scopeSha.equals(e.bound.actualSha256),"capture identity");e.bound.verifyUnchanged();}});
        test("capture_expectation_mismatch_stays_restricted",()->{try(Env e=new Env(true)){e.bind(H);rejects(()->e.bound.requireReady());check(e.bound.restricted()&&e.scopeSha.equals(e.bound.actualSha256),"actual bytes recorded on mismatch");}});
        test("capture_invalid_scope_present_never_falls_back",()->{try(Env e=new Env(true)){write(e.dir.resolve(QualificationScope.FILE_NAME),bytes("{}"),0600);e.bind(null);rejects(()->e.bound.requireReady());check(e.bound.restricted(),"present malformed restricted");}});
        test("capture_source_asset_mismatch_denied",()->{try(Env e=new Env(true)){write(e.dir.resolve("assets/"+QualificationScope.BUILD_ASSET),bytes("{}"),0644);e.bind(e.scopeSha);rejects(()->e.bound.requireReady());}});
        test("capture_loaded_engine_runtime_mismatch_denied",()->{try(Env e=new Env(true)){
            QualificationScopeConfig.Bound b=QualificationScopeConfig.capture(e.service,e.task,e.scopeSha,new LocalRuntimeConfig(ModelProfile.ORVENA4B,"gpu",8192,4));rejects(()->b.requireReady());}});
        for(String foreign:FOREIGN)test("dispatch_foreign_open_"+foreign,()->{try(Env e=new Env(true)){e.bind(e.scopeSha);e.zeroDenied(e.run("open",foreign));}});
        for(String action:new String[]{"click","type","scroll","back","home","done","wait","find_app"})test("dispatch_foreign_foreground_blocks_"+action,()->{try(Env e=new Env(true)){e.bind(e.scopeSha);e.service.root.pkg=FOREIGN[0];e.zeroDenied(e.run(action,SETTINGS));}});
        for(String action:new String[]{"click","type","scroll"})test("dispatch_actual_node_package_blocks_"+action,()->{try(Env e=new Env(true)){e.bind(e.scopeSha);e.service.node.pkg=FOREIGN[2];e.zeroDenied(e.run(action,SETTINGS));}});
        test("dispatch_missing_root_blocks_navigation",()->{try(Env e=new Env(true)){e.bind(e.scopeSha);e.service.root=null;e.zeroDenied(e.run("home",SETTINGS));}});
        test("dispatch_unknown_node_package_blocks_type",()->{try(Env e=new Env(true)){e.bind(e.scopeSha);e.service.node.pkg=null;e.zeroDenied(e.run("type",SETTINGS));}});
        test("dispatch_node_window_mismatch_blocks_click",()->{try(Env e=new Env(true)){e.bind(e.scopeSha);e.service.node.windowId=8;e.zeroDenied(e.run("click",SETTINGS));}});
        test("dispatch_failed_node_refresh_blocks_click",()->{try(Env e=new Env(true)){e.bind(e.scopeSha);e.service.node.refreshResult=false;e.zeroDenied(e.run("click",SETTINGS));}});
        test("dispatch_inactive_or_overlay_or_wrong_display_window_denied",()->{
            for(int variant=0;variant<3;variant++)try(Env e=new Env(true)){e.bind(e.scopeSha);if(variant==0)e.service.root.window.active=false;if(variant==1)e.service.root.window.type=3;if(variant==2)e.service.root.window.display=1;e.zeroDenied(e.run("back",SETTINGS));}});
        test("dispatch_late_foreground_race_before_open_denied",()->{try(Env e=new Env(true)){e.bind(e.scopeSha);e.service.mutateOnRoot=2;e.service.mutateRootPackage=FOREIGN[1];e.zeroDenied(e.run("open",CALC));}});
        test("dispatch_late_node_refresh_change_denied",()->{try(Env e=new Env(true)){e.bind(e.scopeSha);e.service.node.onRefresh=()->{if(e.service.node.refreshes==3)e.service.node.pkg=FOREIGN[0];};e.zeroDenied(e.run("click",SETTINGS));}});
        test("dispatch_resolved_open_component_mismatch_denied",()->{try(Env e=new Env(true)){e.bind(e.scopeSha);e.pm.resolvedOverride=FOREIGN[1];e.zeroDenied(e.run("open",CALC));}});
        test("scope_deleted_after_binding_fails_closed",()->{try(Env e=new Env(true)){e.bind(e.scopeSha);Files.delete(e.dir.resolve(QualificationScope.FILE_NAME));e.zeroDenied(e.run("click",SETTINGS));}});
        test("scope_replaced_identical_bytes_fails_closed",()->{try(Env e=new Env(true)){e.bind(e.scopeSha);Path replacement=e.dir.resolve("replacement.json");write(replacement,e.config,0600);Files.move(replacement,e.dir.resolve(QualificationScope.FILE_NAME),StandardCopyOption.REPLACE_EXISTING);e.zeroDenied(e.run("home",SETTINGS));}});
        test("runtime_changed_after_binding_fails_closed",()->{try(Env e=new Env(true)){e.bind(e.scopeSha);write(e.dir.resolve("model/runtime-config.json"),bytes("{}"),0600);e.zeroDenied(e.run("open",CALC));}});
        test("installed_uid_or_default_home_change_denied",()->{for(int v=0;v<2;v++)try(Env e=new Env(true)){e.bind(e.scopeSha);if(v==0)e.pm.packages.get(CALC).applicationInfo.uid++;else e.pm.homePackage=FOREIGN[1];e.zeroDenied(e.run("open",CALC));}});
        test("sticky_refusal_no_done_home_back_rescue",()->{try(Env e=new Env(true)){e.bind(e.scopeSha);e.zeroDenied(e.run("open",FOREIGN[1]));for(String a:new String[]{"home","back","done"})e.zeroDenied(e.run(a,SETTINGS));}});
        test("scope_bound_once_lease_cannot_downgrade",()->{try(Env e=new Env(true)){e.bind(e.scopeSha);rejects(()->e.service.bindQualificationScope(e.task,e.bound));}});
        for(String action:new String[]{"click","type","scroll","back","home","open"})test("allowed_actual_dispatch_"+action,()->{try(Env e=new Env(true)){e.bind(e.scopeSha);HeptaAccessibilityService.ActionOutcome r=e.run(action,"open".equals(action)?CALC:SETTINGS);check(r.accepted&&r.dispatched&&e.service.effects()==1,"allowed one actual fake effect");}});
        test("unrestricted_absent_scope_preserves_foreign_open",()->{try(Env e=new Env(false)){e.bind(null);e.bound.requireReady();HeptaAccessibilityService.ActionOutcome r=e.run("open",FOREIGN[2]);check(r.dispatched&&e.service.opens==1&&!e.bound.restricted(),"daily behavior preserved");}});
        test("scope_added_during_unrestricted_task_ends_old_mode",()->{try(Env e=new Env(false)){e.bind(null);e.writeConfig();e.zeroDenied(e.run("open",FOREIGN[2]));}});
        test("launch_owner_edit_reuse_and_restoration_do_not_weaken",()->{
            QualificationScope.Launch original=QualificationScope.Launch.prefill("原任务",H);check(H.equals(original.claim("原任务")),"bound owner");rejects(()->original.claim("已修改"));QualificationScope.Launch consumed=original.accepted();rejects(()->consumed.claim("原任务"));
            QualificationScope.Launch restored=QualificationScope.Launch.restore(consumed.expectedSha256,consumed.ownerSha256,consumed.consumed);rejects(()->restored.claim("原任务"));check(H.equals(original.claim("原任务")),"immutable prior task claim");check(QualificationScope.Launch.normal().claim("新任务")==null,"new normal UI");});
        lifecycleCases();uiCases();productionControllerCases();
        writeResult();
    }
    private static void writeResult()throws Exception{
        JSONObject result=new JSONObject().put("schema","hepta.scope-host-tests.v1").put("passed",passed.size()).put("failed",0).put("cases",new JSONArray(passed)).put("phone_operations",false).put("native_inference",false).put("android_runtime",false);
        Files.write(output.resolve("RESULT.json"),bytes(result.toString(2)+"\n"));System.out.println(result.toString());
    }
    static void lifecycleCases()throws Exception{
        for(String kind:new String[]{"wait","click","type","scroll","home","open"})test("late_"+kind+"_callback_keeps_old_scope_after_release_rebind",()->{try(Env e=new Env(true)){
            e.bind(e.scopeSha);String oldSha=e.scopeSha;final HeptaAccessibilityService.ActionOutcome[] reply=new HeptaAccessibilityService.ActionOutcome[1];
            android.view.accessibility.AccessibilityNodeInfo oldNode=e.service.node;Handler.hold=true;
            e.service.enqueue(e.action(kind,"open".equals(kind)?CALC:SETTINGS),()->false,value->reply[0]=value);
            check(reply[0]==null,"real production delayed callback was queued");int oldActions=oldNode.actions,refreshes=oldNode.refreshes,opens=e.service.opens,nav=e.service.navigations;
            check(("wait".equals(kind)?0:1)==oldActions+opens+nav,"effect dispatched before delay");
            e.service.releaseTask(e.task);e.fields.put("qualification_id","synthetic-new-lease");e.updateConfig();e.writeConfig();
            // Reusing even the same synthetic ID must not borrow a different Bound.
            String next="type".equals(kind)?e.task:"22222222222222222222222222222222";
            check(e.service.acquireTask(next,()->{}),"new lease");QualificationScopeConfig.Bound nextScope=QualificationScopeConfig.capture(e.service,next,e.scopeSha,e.runtime);nextScope.requireReady();e.service.bindQualificationScope(next,nextScope);e.service.bindOwnerActionPolicy(next,OwnerActionPolicy.compile(next,"执行合成测试任务。"));
            e.service.prepare(CALC);oldNode.onRefresh=()->{throw new IllegalStateException("retired node must not be read");};
            Handler.drain();check(reply[0]!=null&&!reply[0].accepted&&!reply[0].stale&&reply[0].dispatched!= "wait".equals(kind),"late receipt rejected while actual dispatch preserved");
            JSONObject proof=reply[0].qualificationScope;check(oldSha.equals(proof.getString("actual_scope_sha256"))&&e.task.equals(proof.getString("task_id"))&&!proof.getBoolean("callback_lease_current"),"callback uses captured old identity");
            check(oldNode.refreshes==refreshes&&oldNode.actions==oldActions&&e.service.opens==opens&&e.service.navigations==nav&&e.service.node.actions==0,"no retired read or late effect");
            check(!nextScope.evidence().getBoolean("scope_refused"),"old callback did not poison new scope");
            HeptaAccessibilityService.ActionOutcome fresh=e.run("open",SETTINGS);check(fresh.accepted&&fresh.dispatched&&e.scopeSha.equals(fresh.qualificationScope.getString("actual_scope_sha256")),"new task still uses own scope");
        }});
        test("queued_perform_retired_before_main_dispatch_has_no_effect",()->{try(Env e=new Env(true)){
            e.bind(e.scopeSha);String oldSha=e.scopeSha;HeptaAccessibilityService.ActionOutcome[] reply=new HeptaAccessibilityService.ActionOutcome[1];Handler.holdPosts=true;
            e.service.enqueue(e.action("open",CALC),()->false,value->reply[0]=value);check(reply[0]==null,"main entry queued");e.service.releaseTask(e.task);
            e.fields.put("qualification_id","replacement-task");e.updateConfig();e.writeConfig();check(e.service.acquireTask(e.task,()->{}),"new same-ID lease");QualificationScopeConfig.Bound replacement=QualificationScopeConfig.capture(e.service,e.task,e.scopeSha,e.runtime);replacement.requireReady();e.service.bindQualificationScope(e.task,replacement);e.service.bindOwnerActionPolicy(e.task,OwnerActionPolicy.compile(e.task,"执行合成测试任务。"));
            Handler.drain();check(reply[0]!=null&&!reply[0].accepted&&!reply[0].dispatched&&e.service.effects()==0,"retired queued work did not dispatch");check(oldSha.equals(reply[0].qualificationScope.getString("actual_scope_sha256")),"no replacement scope borrowed");
        }});
        test("cancelled_delayed_type_skips_retired_node_and_preserves_effect",()->{try(Env e=new Env(true)){
            e.bind(e.scopeSha);java.util.concurrent.atomic.AtomicBoolean cancel=new java.util.concurrent.atomic.AtomicBoolean();HeptaAccessibilityService.ActionOutcome[] reply=new HeptaAccessibilityService.ActionOutcome[1];Handler.hold=true;
            e.service.enqueue(e.action("type",SETTINGS),cancel::get,value->reply[0]=value);int reads=e.service.node.refreshes;cancel.set(true);e.service.node.onRefresh=()->{throw new IllegalStateException("cancelled node read");};Handler.drain();
            check(reply[0]!=null&&!reply[0].accepted&&reply[0].dispatched&&reply[0].qualificationScope.getBoolean("callback_cancelled")&&e.service.node.actions==1&&e.service.node.refreshes==reads,"cancelled type safely finishes");
        }});
        test("owned_type_readback_exception_is_recorded_without_late_effect",()->{try(Env e=new Env(true)){
            e.bind(e.scopeSha);HeptaAccessibilityService.ActionOutcome[] reply=new HeptaAccessibilityService.ActionOutcome[1];Handler.hold=true;
            e.service.enqueue(e.action("type",SETTINGS),()->false,value->reply[0]=value);e.service.node.onRefresh=()->{throw new IllegalStateException("node disappeared after accepted write");};Handler.drain();
            check(reply[0]!=null&&!reply[0].accepted&&reply[0].dispatched&&reply[0].qualificationScope.getBoolean("callback_lease_current")&&e.service.node.actions==1,"readback failure retained one known dispatch");
        }});
        test("disconnected_service_late_callback_does_not_throw_or_borrow",()->{try(Env e=new Env(true)){
            e.bind(e.scopeSha);HeptaAccessibilityService.ActionOutcome[] reply=new HeptaAccessibilityService.ActionOutcome[1];Handler.hold=true;e.service.enqueue(e.action("wait",SETTINGS),()->false,value->reply[0]=value);
            HeptaAccessibilityService.live=null;Handler.drain();check(reply[0]!=null&&!reply[0].accepted&&!reply[0].dispatched&&!reply[0].qualificationScope.getBoolean("callback_lease_current"),"disconnected callback safely rejected");
        }});
    }
    static void uiCases()throws Exception{
        test("actual_ui_reused_intent_and_rotation_keep_pending_restriction",()->{try(Env e=new Env(true)){
            LocalModelEngine engine=new LocalModelEngine(Paths.get(e.pm.packages.get("org.trillionnium.hepta.local").applicationInfo.sourceDir).toFile(),e.runtime);LocalTaskSession tasks=new LocalTaskSession(e.service,engine);ScopeUiFixture ui=new ScopeUiFixture(tasks,engine);
            Intent intent=new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER).putExtra("task","打开设置").putExtra(QualificationScope.EXPECTED_EXTRA,e.scopeSha);
            ui.intent(intent);check(!intent.hasExtra("task")&&!intent.hasExtra(QualificationScope.EXPECTED_EXTRA),"consume extras");ui.intent(intent);check(e.scopeSha.equals(ui.scopeLaunch.claim("打开设置")),"reused cleared intent cannot downgrade");
            Bundle state=new Bundle();ui.save(state);ScopeUiFixture restored=new ScopeUiFixture(tasks,engine);restored.restore(state);check(e.scopeSha.equals(restored.scopeLaunch.claim("打开设置")),"recreated Activity claim");
            restored.intent(new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER));check(restored.scopeLaunch.claim("正常新任务")==null,"explicit normal new launcher session clears UI binding");
        }});
        test("actual_ui_start_session_pending_capture_immutable_across_new_intent",()->{try(Env e=new Env(true)){
            CountingModel model=new CountingModel(e,"done",SETTINGS,null);e.service.testInference=model;
            LocalModelEngine engine=new LocalModelEngine(Paths.get(e.pm.packages.get("org.trillionnium.hepta.local").applicationInfo.sourceDir).toFile(),e.runtime);LocalTaskSession tasks=new LocalTaskSession(e.service,engine);ScopeUiFixture ui=new ScopeUiFixture(tasks,engine);
            ui.intent(new Intent().putExtra("task","打开设置").putExtra(QualificationScope.EXPECTED_EXTRA,e.scopeSha));Handler.hold=true;check(ui.start(),"ordinary button schedules");
            check("user_button".equals(tasks.origin)&&e.scopeSha.equals(tasks.expectedScopeSha),"source and expectation bound in pending session");
            ui.intent(new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER).putExtra("task","new ordinary task"));check(e.scopeSha.equals(tasks.expectedScopeSha),"running pending session immutable");
            Handler.drain();long end=System.currentTimeMillis()+10000;JSONObject session=null;
            // The host Handler executes worker callbacks directly; wait for the actual
            // terminal session write, rather than racing controller.running=false.
            while(System.currentTimeMillis()<end){
                try{JSONObject candidate=new JSONObject(new String(Files.readAllBytes(e.dir.resolve("control-session.json")),StandardCharsets.UTF_8));
                    if(tasks.lastResult!=null&&"model_reported_done".equals(candidate.getString("status"))){session=candidate;break;}}
                catch(Exception transientWrite){/* host AtomicFile fixture can expose an in-progress write */}
                Thread.sleep(1);
            }
            check(tasks.lastResult!=null&&e.scopeSha.equals(tasks.lastResult.expectedScopeSha256)&&session!=null,"controller receives original expectation");check(e.scopeSha.equals(session.getString("expected_scope_sha256"))&&e.scopeSha.equals(session.getString("actual_scope_sha256")),"session terminal binds both hashes");
            rejects(()->ui.scopeLaunch.claim("打开设置"));
        }});
        test("actual_ui_bad_or_edited_expected_prefill_cannot_start",()->{try(Env e=new Env(true)){
            LocalModelEngine engine=new LocalModelEngine(Paths.get(e.pm.packages.get("org.trillionnium.hepta.local").applicationInfo.sourceDir).toFile(),e.runtime);LocalTaskSession tasks=new LocalTaskSession(e.service,engine);ScopeUiFixture ui=new ScopeUiFixture(tasks,engine);
            ui.intent(new Intent().putExtra("task","打开设置").putExtra(QualificationScope.EXPECTED_EXTRA,e.scopeSha));ui.taskInput.text="修改任务";check(!ui.start()&&!tasks.isRunning(),"edited owner denied");
            ui.intent(new Intent().putExtra("task","打开设置").putExtra(QualificationScope.EXPECTED_EXTRA,"bad"));check(!ui.start(),"malformed expectation denied");
            ui.endUi();check(ui.scopeLaunch.claim("普通任务")==null,"explicit stop clears only UI claim");
        }});
        test("actual_private_debug_start_passes_same_expected_scope",()->{try(Env e=new Env(true)){
            e.service.testInference=new CountingModel(e,"done",SETTINGS,null);LocalModelEngine engine=new LocalModelEngine(Paths.get(e.pm.packages.get("org.trillionnium.hepta.local").applicationInfo.sourceDir).toFile(),e.runtime);LocalTaskSession tasks=new LocalTaskSession(e.service,engine);ScopeUiFixture ui=new ScopeUiFixture(tasks,engine);
            Handler.hold=true;ui.intent(new Intent().putExtra("auto_task",true).putExtra("test_nonce","synthetic-nonce").putExtra(QualificationScope.EXPECTED_EXTRA,e.scopeSha));
            check(tasks.pending&&e.scopeSha.equals(tasks.expectedScopeSha)&&"private_debug_nonce".equals(tasks.origin),"core private trigger expectation");ui.endUi();check(!tasks.isRunning(),"pending cancelled");
        }});
    }
}
