package org.trillionnium.hepta.local;

import android.app.ActivityManager;
import android.os.Handler;
import android.os.Looper;
import android.system.Os;
import java.io.File;
import java.io.RandomAccessFile;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;
import org.json.JSONObject;

/** Complete settings/engine/transaction/router with explicitly declared host boundaries. */
public final class VisualSettingsHostTest {
    private static Path output;
    private static int cases,assertions,ids;
    private static final JSONArray rows=new JSONArray();
    private static final List<Env> environments=new ArrayList<Env>();
    private static final List<LocalModelEngine> realEngines=new ArrayList<LocalModelEngine>();
    private static final byte[] ORIGINAL=("{\n \"threads\":4, \"context_tokens\":8192,\n \"compute\":\"npu\", \"schema\":\"hepta.local-runtime.v1\"\n}\n").getBytes(StandardCharsets.UTF_8);
    private interface Work {void run()throws Exception;}
    private static void check(boolean value,String text){assertions++;if(!value)throw new AssertionError(text);}
    private static void reject(Work work)throws Exception{
        boolean rejected=false;try{work.run();}catch(Exception expected){rejected=true;}
        check(rejected,"actual operation must reject");
    }
    private static String id(){return String.format(Locale.ROOT,"%032x",++ids);}
    private static Path fresh(String name)throws Exception{
        Path files=output.resolve(String.format(Locale.ROOT,"%03d-",cases)+name);
        Files.createDirectory(files);Files.setPosixFilePermissions(files,PosixFilePermissions.fromString("rwx------"));
        Files.createDirectory(files.resolve("model"));Files.setPosixFilePermissions(files.resolve("model"),PosixFilePermissions.fromString("rwx------"));
        write(files.resolve("model/runtime-config.json"),ORIGINAL);return files;
    }
    private static void write(Path path,byte[] bytes)throws Exception{
        Files.write(path,bytes,StandardOpenOption.CREATE,StandardOpenOption.TRUNCATE_EXISTING);
        Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rw-------"));
    }
    private static Object field(Object object,String name)throws Exception{
        Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(object);
    }
    private static void runtime(LocalModelEngine engine,LocalModelEngine.RuntimeGeneration value)throws Exception{
        Field f=LocalModelEngine.class.getDeclaredField("runtime");f.setAccessible(true);f.set(engine,value);
    }
    private static Object delegate(LocalInference router)throws Exception{return field(field(router,"binding"),"delegate");}
    private static ThreadPoolExecutor executor(LocalModelEngine engine)throws Exception{
        Field f=LocalModelEngine.class.getDeclaredField("executor");f.setAccessible(true);return(ThreadPoolExecutor)f.get(engine);
    }
    private static final class Env {
        final Path files;
        final LocalProbeApplication app;
        final PositiveAssetBoundaryEngine engine;
        final HeptaAccessibilityService service;
        final OwnerButtons ui;
        final LocalTaskController controller;
        Env(String name)throws Exception{
            files=fresh(name);app=new LocalProbeApplication(files.toFile());engine=new PositiveAssetBoundaryEngine(app);
            app.model=engine;service=new HeptaAccessibilityService(app);app.modelSettings=new LocalModelSettings(app,engine);
            ui=new OwnerButtons(app);controller=service.taskController(engine);environments.add(this);
        }
        byte[] config()throws Exception{return Files.readAllBytes(files.resolve("model/runtime-config.json"));}
        void awaitSettings()throws Exception{
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);
            while(app.modelSettings.isBusy()){
                Handler.drain();
                if(System.nanoTime()>deadline)throw new AssertionError("actual settings callback deadline");
                Thread.sleep(1);
            }
            Handler.drain();
        }
        void choose(int choice)throws Exception{
            AlertDialog.last=null;ui.choose();check(AlertDialog.last!=null,"actual ordinary selection button opened");
            check(AlertDialog.last.labels.length==6,"four original text choices, original GUI tools and one restricted LFM3 observation choice");
            AlertDialog.last.choose(choice);AlertDialog.last.confirm();awaitSettings();
        }
        void restored()throws Exception{
            AlertDialog.last=null;ui.restore();check(AlertDialog.last!=null,"actual ordinary restore button opened");
            AlertDialog.last.confirm();awaitSettings();
        }
        void close()throws Exception{
            app.modelSettings.close();engine.close();
            if(!executor(engine).awaitTermination(3,TimeUnit.SECONDS))throw new IllegalStateException("actual engine executor did not terminate");
        }
    }
    private static void run(String name,Work test)throws Exception{
        Os.reset();Looper.resetMain();Handler.reset();LocalProbeApplication.permissionBlocked=false;
        ActivityManager.low=false;ActivityManager.available=12L<<30;VlmInferenceAdapter.throwAfterBegin=false;
        int before=assertions;JSONObject row=new JSONObject().put("name",name);rows.put(row);
        try{test.run();row.put("passed",true);cases++;}
        catch(Throwable failure){row.put("passed",false).put("error",failure.toString());throw failure;}
        finally{row.put("assertions",assertions-before);Os.reset();}
    }
    private static void settings()throws Exception{
        run("explicit-visual-tools-v3-and-unchanged-default",()->{
            byte[] raw=RuntimeConfigTransaction.selectedVisualTools("npu");
            JSONObject object=new JSONObject(new String(raw,StandardCharsets.UTF_8));
            check(object.length()==6&&object.getString("schema").equals("hepta.local-runtime.v3"),"exact v3 fields");
            check(object.getString("visual_mode").equals("tools")&&object.getString("compute").equals("npu"),"explicit tools and HTP0 request");
            check(object.getString("model_profile").equals(ModelProfile.GUI_OWL_4B.id),"exact pinned GUI-Owl profile");
            check(object.getInt("context_tokens")==8192&&object.getInt("threads")==4,"fixed bounded visual configuration");
            check(ModelProfile.GUI_OWL_4B.minimumAvailableBytes==6L<<30,"six GiB admission is unchanged");
            check(LocalRuntimeConfig.defaults().profile==ModelProfile.LFM3,"default model does not silently change");
            reject(()->RuntimeConfigTransaction.selected(ModelProfile.GUI_OWL_4B.id,"npu"));
            for(String compute:new String[]{"gpu","cpu","auto","NPU",""})reject(()->RuntimeConfigTransaction.selectedVisualTools(compute));
        });
        run("visual-observe-extra-fields-and-wrong-shape-reject",()->{
            for(String mode:new String[]{"observe","unknown"}){
                Path files=fresh("reject-"+mode);
                JSONObject object=new JSONObject(new String(RuntimeConfigTransaction.selectedVisualTools("npu"),StandardCharsets.UTF_8));
                object.put("visual_mode",mode);
                reject(()->RuntimeConfigTransaction.prepare(files.toFile(),object.toString().getBytes(StandardCharsets.UTF_8),true));
                check(Arrays.equals(ORIGINAL,Files.readAllBytes(files.resolve("model/runtime-config.json"))),"rejected mode preserves config");
                check(!RuntimeConfigTransaction.pending(files.toFile()),"rejected mode publishes no pointer");
            }
            Path files=fresh("extra");JSONObject object=new JSONObject(new String(RuntimeConfigTransaction.selectedVisualTools("npu"),StandardCharsets.UTF_8));
            object.put("external_model",true);
            reject(()->RuntimeConfigTransaction.prepare(files.toFile(),object.toString().getBytes(StandardCharsets.UTF_8),true));
            object.remove("external_model");object.put("schema","hepta.local-runtime.v2");
            reject(()->RuntimeConfigTransaction.prepare(files.toFile(),object.toString().getBytes(StandardCharsets.UTF_8),true));
        });
        run("ordinary-save-same-service-text-visual-text-next-task",()->{
            Env e=new Env("roundtrip");
            check(e.controller==e.service.taskController(e.engine),"one cached controller before any save");
            LocalModelEngine.RuntimeGeneration original=e.engine.runtimeGeneration();
            String text=id();e.controller.begin(text);
            check(delegate(e.controller.inference) instanceof EngineInferenceAdapter,"first task uses actual text adapter");
            check(!e.controller.inference.acceptsObservedImage(),"first task is text");
            check(e.controller.finish().cleanupKnown&&!e.engine.isBusy(),"first actual warm reservation released");

            e.choose(4);LocalModelEngine.RuntimeGeneration visual=e.engine.runtimeGeneration();
            check(visual!=original&&visual.config.profile==ModelProfile.GUI_OWL_4B,"same engine published a fresh visual generation");
            check(e.engine.selected==visual.config||e.engine.selected.profile==visual.config.profile,"positive admission boundary received selected visual profile");
            check(e.app.modelSettings.state().contains("语言 Hexagon NPU + 图像 Adreno GPU"),"ordinary status identifies both devices");
            check(e.app.modelSettings.state().contains("本次没有运行推理"),"save does not claim inference qualification");
            check(e.controller==e.service.taskController(e.engine),"same service retains the exact controller after visual save");
            String image=id();e.controller.begin(image);Object visualDelegate=delegate(e.controller.inference);
            check(visualDelegate instanceof VlmInferenceAdapter,"next task uses selected visual adapter");
            check(field(field(e.controller.inference,"binding"),"runtime")==visual,"task binds actual runtime generation object");
            check(image.equals(field(field(e.controller.inference,"binding"),"taskId")),"task binds exact identity");
            check(e.controller.inference.acceptsObservedImage()&&e.controller.inference.modelOutputDispatchAllowed(),"visual tools mode is exposed to controller");
            check(e.controller.inference.requestCompletionGraceMillis()==VlmPins.COMPLETION_GRACE_MILLIS,"visual completion grace follows selected delegate");
            check(e.controller.finish().cleanupKnown&&!e.engine.isBusy(),"actual visual task lease released after known terminal");

            e.choose(1);LocalModelEngine.RuntimeGeneration back=e.engine.runtimeGeneration();
            check(back!=visual&&back.config.profile==ModelProfile.LFM3&&back.config.compute.equals("gpu"),"same engine published selected text GPU generation");
            check(e.controller==e.service.taskController(e.engine),"same controller survives visual to text");
            e.controller.begin(id());
            check(delegate(e.controller.inference) instanceof EngineInferenceAdapter,"following task returns to actual text adapter");
            check(delegate(e.controller.inference)!=visualDelegate&&!e.controller.inference.acceptsObservedImage(),"visual adapter is not reused across tasks");
            check(e.controller.inference.requestCompletionGraceMillis()==17000L,"text grace restored");
            check(e.controller.finish().cleanupKnown&&!e.engine.isBusy(),"following text task cleaned");
            check(e.app.tasks.journalChecks>=6,"actual settings worker ran journal guards around commit");
        });
        run("ordinary-four-existing-text-choices-remain-exact",()->{
            Env e=new Env("text-choices");
            for(int choice=0;choice<4;choice++){
                e.choose(choice);LocalRuntimeConfig config=e.engine.configuration();
                check(config.profile==(choice<2?ModelProfile.LFM3:ModelProfile.LFM25_8B_A1B),"existing profile mapping unchanged");
                check(config.compute.equals(choice%2==0?"npu":"gpu"),"existing device mapping unchanged");
                check(new JSONObject(new String(e.config(),StandardCharsets.UTF_8)).length()==5,"existing text schema stays v2 only");
            }
        });
        run("ordinary-restore-text-and-visual-exact-original-bytes",()->{
            Env e=new Env("restore");e.choose(4);byte[] visual=e.config();
            check(new JSONObject(new String(visual,StandardCharsets.UTF_8)).getString("visual_mode").equals("tools"),"stored visual mode exact");
            e.restored();check(Arrays.equals(ORIGINAL,e.config()),"restore preserves original whitespace and key order");
            check(e.engine.configuration().profile==ModelProfile.LFM3,"same engine reflects exact restored text");
            e.restored();check(Arrays.equals(visual,e.config()),"restore can return to exact previous visual bytes");
            check(e.engine.configuration().profile==ModelProfile.GUI_OWL_4B,"same engine reflects exact restored visual");
            AlertDialog.last=null;e.ui.choose();check(AlertDialog.last.checked==4,"ordinary menu marks visual selection");
        });
        run("ordinary-recovery-of-pending-visual-publication",()->{
            Path files=fresh("pending-visual");
            RuntimeConfigTransaction tx=RuntimeConfigTransaction.prepare(files.toFile(),RuntimeConfigTransaction.selectedVisualTools("npu"),true);
            tx.apply();
            LocalProbeApplication app=new LocalProbeApplication(files.toFile());PositiveAssetBoundaryEngine engine=new PositiveAssetBoundaryEngine(app);
            app.model=engine;new HeptaAccessibilityService(app);app.modelSettings=new LocalModelSettings(app,engine);
            OwnerButtons ui=new OwnerButtons(app);
            check(engine.settingsBlocked()&&!app.canChangeLocalModelSettings(false),"pending visual commit blocks new settings/tasks");
            check(app.canChangeLocalModelSettings(true),"ordinary restore is admitted only through restoration gate");
            AlertDialog.last=null;ui.restore();check(AlertDialog.last!=null,"ordinary restore opened for pending visual");
            AlertDialog.last.confirm();
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);
            while(app.modelSettings.isBusy()){Handler.drain();if(System.nanoTime()>deadline)throw new AssertionError("pending recovery timeout");Thread.sleep(1);}
            Handler.drain();check(Arrays.equals(ORIGINAL,Files.readAllBytes(files.resolve("model/runtime-config.json"))),"pending recovery restores original text bytes");
            check(!engine.settingsBlocked()&&!RuntimeConfigTransaction.pending(files.toFile()),"actual recovery clears only known own transaction");
            app.modelSettings.close();engine.close();check(executor(engine).awaitTermination(3,TimeUnit.SECONDS),"recovery engine stopped");
        });
        run("ordinary-asset-refusal-rolls-back-without-route-change",()->{
            Env e=new Env("asset-refusal");LocalModelEngine.RuntimeGeneration before=e.engine.runtimeGeneration();
            e.engine.reject=true;e.choose(4);
            check(Arrays.equals(ORIGINAL,e.config()),"failed visual asset gate restores exact text bytes");
            check(e.engine.configuration().profile==ModelProfile.LFM3&&!e.engine.settingsBlocked(),"same engine remains usable with original text config");
            check(e.app.modelSettings.state().contains("模型设置未完成"),"ordinary status reports failure");
            check(e.engine.runtimeGeneration()!=before,"rollback installs an explicit new generation");
            e.controller.begin(id());check(delegate(e.controller.inference) instanceof EngineInferenceAdapter,"no visual task after failed save");
            check(e.controller.finish().cleanupKnown,"failed-save text reservation cleaned");
        });
        run("ordinary-active-task-and-late-confirmation-cannot-switch",()->{
            Env e=new Env("active");AlertDialog.last=null;e.ui.choose();AlertDialog.Builder stale=AlertDialog.last;
            check(stale!=null,"ordinary dialog opened while idle");
            byte[] before=e.config();e.controller.begin(id());Object delegate=delegate(e.controller.inference);
            check(!e.app.canChangeLocalModelSettings(false),"active controller blocks actual application idle gate");
            stale.choose(4);stale.confirm();Handler.drain();
            check(!e.app.modelSettings.isBusy()&&Arrays.equals(before,e.config()),"late confirm starts no settings mutation");
            reject(()->e.app.modelSettings.start(ModelProfile.GUI_OWL_4B.id,"npu",false));
            reject(()->e.engine.reserveSettings(false));
            check(delegate(e.controller.inference)==delegate,"active text delegate remains exact");
            check(e.controller.finish().cleanupKnown,"active original task cleaned");
        });
    }
    private static void routing()throws Exception{
        run("unknown-visual-cleanup-retains-delegate-and-shared-slot",()->{
            Env e=new Env("unknown");e.choose(4);String task=id();e.controller.begin(task);
            VlmInferenceAdapter visual=(VlmInferenceAdapter)delegate(e.controller.inference);visual.known=false;
            LocalInference.TaskCleanup proof=e.controller.finish();
            check(!proof.cleanupKnown&&task.equals(proof.taskId),"unknown original task proof is preserved");
            check(delegate(e.controller.inference)==visual&&e.engine.isBusy(),"unknown cleanup retains actual visual lease and delegate");
            e.controller.running=false; // Isolate the engine fence even if the controller terminal is idle.
            check(!e.app.canChangeLocalModelSettings(false),"actual engine reservation independently denies settings");
            reject(()->e.app.modelSettings.start(ModelProfile.LFM3.id,"npu",false));
            reject(()->e.controller.inference.beginTask(id()));
            check(delegate(e.controller.inference)==visual,"failed later admissions cannot replace unknown delegate");
            visual.known=true;check(e.controller.finish().cleanupKnown&&!e.engine.isBusy(),"only original known terminal releases lease");
            e.choose(0);e.controller.begin(id());check(delegate(e.controller.inference) instanceof EngineInferenceAdapter,"text allowed only after original cleanup");
            check(e.controller.finish().cleanupKnown,"new text task cleaned");
        });
        run("foreign-cleanup-proof-cannot-retire-or-relabel-task",()->{
            Env e=new Env("foreign-proof");e.choose(4);String task=id();e.controller.begin(task);
            VlmInferenceAdapter visual=(VlmInferenceAdapter)delegate(e.controller.inference);
            reject(()->e.controller.inference.endTask(id()));check(delegate(e.controller.inference)==visual,"foreign requested task leaves binding");
            visual.foreignProof=true;reject(()->e.controller.finish());
            check(delegate(e.controller.inference)==visual&&e.engine.isBusy(),"foreign returned proof cannot release or replace binding");
            reject(()->e.controller.inference.beginTask(id()));
            visual.foreignProof=false;check(e.controller.finish().cleanupKnown,"exact original task cleanup accepted");
        });
        run("partial-begin-failure-retains-original-adapter-for-cleanup",()->{
            Env e=new Env("partial-begin");e.choose(4);String task=id();VlmInferenceAdapter.throwAfterBegin=true;
            reject(()->e.controller.begin(task));VlmInferenceAdapter visual=(VlmInferenceAdapter)delegate(e.controller.inference);
            check(visual.lease!=null&&visual.lease.current()&&e.engine.isBusy(),"failure happened after real visual lease reservation");
            check(task.equals(field(field(e.controller.inference,"binding"),"taskId")),"failed begin retains correct task identity");
            reject(()->e.controller.inference.beginTask(id()));
            e.controller.inference.cancelTask();check(visual.cancelled,"cancellation targets retained adapter");
            VlmInferenceAdapter.throwAfterBegin=false;
            check(e.controller.finish().cleanupKnown&&!e.engine.isBusy(),"original adapter proves partial-start cleanup");
        });
        run("runtime-generation-cannot-change-between-selection-and-reservation",()->{
            Env e=new Env("generation-race");LocalModelEngine.RuntimeGeneration before=e.engine.runtimeGeneration();
            RuntimeInferenceAdapter router=new RuntimeInferenceAdapter(e.engine,config->{
                try{runtime(e.engine,LocalModelEngine.generation(before.source,new ModelFileVerifier()));}
                catch(Exception error){throw new IllegalStateException(error);}
                return new EngineInferenceAdapter(e.engine);
            });
            String task=id();reject(()->router.beginTask(task));
            check(!e.engine.isBusy(),"mismatched generation acquired no native/task lease");
            check(router.endTask(task).cleanupKnown,"no-start cleanup remains task-neutral");
            runtime(e.engine,before);
        });
        run("active-runtime-generation-is-frozen-and-drift-fails-closed",()->{
            Env e=new Env("generation-drift");String task=id();e.controller.begin(task);
            LocalModelEngine.RuntimeGeneration before=e.engine.runtimeGeneration();Object selected=delegate(e.controller.inference);
            runtime(e.engine,LocalModelEngine.generation(before.source,new ModelFileVerifier()));
            check(e.controller.inference.configuration()==before.config,"in-flight config stays original object");
            reject(()->e.controller.inference.generateObserved("x","s",null,null,1,1000,null));
            check(delegate(e.controller.inference)==selected,"generation drift never swaps delegates");
            runtime(e.engine,before);check(e.controller.finish().cleanupKnown,"exact original generation can be finalized");
        });
        run("visual-frame-task-identity-and-original-frame-are-preserved",()->{
            Env e=new Env("frame");e.choose(4);String task=id();e.controller.begin(task);
            VlmInferenceAdapter visual=(VlmInferenceAdapter)delegate(e.controller.inference);
            LocalInference.CurrentFrame foreign=frame(e.files,id()),original=frame(e.files,task);
            reject(()->e.controller.inference.generateObserved("p","s",foreign,null,1,1000,null));
            check(visual.observed==null,"foreign frame rejected before delegate");
            LocalInference.Handle handle=e.controller.inference.generateObserved("p","s",original,null,1,1000,null);
            check(visual.observed==original,"exact current frame, not an unbound copied image, is forwarded");
            handle.cancel();check(visual.cancelled,"request cancellation belongs to selected delegate");
            check(e.controller.finish().cleanupKnown,"frame test real visual reservation cleaned");
        });
    }
    private static LocalInference.CurrentFrame frame(Path files,String task){
        return new LocalInference.CurrentFrame(files.resolve("host-frame.png").toFile(),task,
                repeat('a'),"host-observation","host-background","com.example.host",repeat('b'),10,10,222,7,0,1,
                "{}".getBytes(StandardCharsets.UTF_8),()->{});
    }
    private static String repeat(char value){char[] chars=new char[64];Arrays.fill(chars,value);return new String(chars);}
    private static LocalModelEngine real(Path files){
        LocalModelEngine engine=new LocalModelEngine(new LocalProbeApplication(files.toFile()));realEngines.add(engine);return engine;
    }
    private static void sparse(Path file,long bytes)throws Exception{
        try(RandomAccessFile out=new RandomAccessFile(file.toFile(),"rw")){out.setLength(bytes);}
        Files.setPosixFilePermissions(file,PosixFilePermissions.fromString("rw-------"));
    }
    private static LocalRuntimeConfig visual(){return new LocalRuntimeConfig(ModelProfile.GUI_OWL_4B,"npu",8192,4);}
    private static void assets()throws Exception{
        run("actual-visual-memory-threshold-and-low-memory-refuse-before-assets",()->{
            Path files=fresh("budget");LocalModelEngine engine=real(files);LocalModelEngine.SettingsReservation lease=engine.reserveSettings(false);
            ActivityManager.available=(6L<<30)-1;ActivityManager.low=false;
            reject(()->engine.verifySettingsModel(lease,visual()));
            check(!Files.exists(files.resolve("gui-owl-model")),"insufficient budget never creates a model directory");
            ActivityManager.available=12L<<30;ActivityManager.low=true;
            reject(()->engine.verifySettingsModel(lease,visual()));
            ActivityManager.low=false;ActivityManager.available=6L<<30;
            reject(()->engine.verifySettingsModel(lease,visual()));
            lease.requireOwned();engine.finishSettings(lease,true);check(!engine.isBusy(),"negative preflight releases only its own settings reservation");
        });
        for(String kind:new String[]{"missing","short","symlink","hardlink","owner"}){
            final String variant=kind;
            run("actual-projector-"+kind+"-refuses-before-primary-hash",()->{
                Path files=fresh("projector-"+variant),dir=files.resolve("gui-owl-model");
                Files.createDirectory(dir);Files.setPosixFilePermissions(dir,PosixFilePermissions.fromString("rwx------"));
                Path model=dir.resolve(ModelProfile.GUI_OWL_4B.fileName),projector=dir.resolve(VlmPins.PROJECTOR),other=files.resolve("host-projector-other");
                sparse(model,ModelProfile.GUI_OWL_4B.bytes);
                LocalModelEngine engine=real(files);LocalModelEngine.SettingsReservation lease=engine.reserveSettings(false);
                try{
                    if(variant.equals("short"))write(projector,new byte[]{1,2,3});
                    if(variant.equals("symlink")){sparse(other,VlmPins.PROJECTOR_BYTES);Files.createSymbolicLink(projector,other);}
                    if(variant.equals("hardlink")){sparse(projector,VlmPins.PROJECTOR_BYTES);Files.createLink(other,projector);}
                    if(variant.equals("owner")){sparse(projector,VlmPins.PROJECTOR_BYTES);Os.uidOverridePath=projector.toString();}
                    reject(()->engine.verifySettingsModel(lease,visual()));
                    check(!RuntimeConfigTransaction.pending(files.toFile()),"asset refusal cannot publish settings");
                    check(Arrays.equals(ORIGINAL,Files.readAllBytes(files.resolve("model/runtime-config.json"))),"asset refusal preserves original config");
                    lease.requireOwned();engine.finishSettings(lease,true);
                }finally{
                    Os.reset();Files.deleteIfExists(projector);Files.deleteIfExists(other);Files.deleteIfExists(model);
                }
            });
        }
        run("actual-complete-primary-content-hash-refuses-sparse-impostor",()->{
            Path files=fresh("full-hash"),dir=files.resolve("gui-owl-model");Files.createDirectory(dir);
            Files.setPosixFilePermissions(dir,PosixFilePermissions.fromString("rwx------"));
            Path model=dir.resolve(ModelProfile.GUI_OWL_4B.fileName),projector=dir.resolve(VlmPins.PROJECTOR);
            sparse(model,ModelProfile.GUI_OWL_4B.bytes);sparse(projector,VlmPins.PROJECTOR_BYTES);
            LocalModelEngine engine=real(files);LocalModelEngine.SettingsReservation lease=engine.reserveSettings(false);
            try{
                reject(()->engine.verifySettingsModel(lease,visual()));
                check(!engine.settingsBlocked(),"content rejection is not silently qualified");
                lease.requireOwned();engine.finishSettings(lease,true);
            }finally{Files.deleteIfExists(projector);Files.deleteIfExists(model);}
        });
        run("projector-hash-helper-validates-full-content-and-independent-pin",()->{
            Path files=fresh("hash-helper"),asset=files.resolve(VlmPins.PROJECTOR);
            byte[] raw=new byte[2*1024*1024+17];for(int i=0;i<raw.length;i++)raw[i]=(byte)(i%251);
            write(asset,raw);String hash=MobiMindContract.sha(raw);ModelFileVerifier verifier=new ModelFileVerifier();
            verifier.verifyPinned(asset.toFile(),"host-projector",VlmPins.PROJECTOR,raw.length,hash,()->false);
            check(field(verifier,"verifiedPath").equals(asset.toString()),"real full hash establishes only the supplied host fixture pin");
            reject(()->verifier.verifyPinned(asset.toFile(),"host-projector",VlmPins.PROJECTOR,raw.length,repeat('0'),()->false));
            reject(()->new ModelFileVerifier().verifyPinned(asset.toFile(),"host-projector",VlmPins.PROJECTOR,raw.length,hash,()->true));
            raw[raw.length-1]^=1;write(asset,raw);
            reject(()->new ModelFileVerifier().verifyPinned(asset.toFile(),"host-projector",VlmPins.PROJECTOR,raw.length,hash,()->false));
            check(ModelProfile.GUI_OWL_4B.bytes==2375774624L&&VlmPins.PROJECTOR_BYTES==836180288L,"actual independent file sizes stay pinned");
            check(ModelProfile.GUI_OWL_4B.sha256.equals("c71f372d2e2b71f173622f1966ac6a1bc60da1c2dbdd6d92534ab6f83724b8df"),"actual primary hash unchanged");
            check(VlmPins.PROJECTOR_SHA.equals("eabdc0291d460f2e68874f51044030a7da8fe956c2a6b86abd69fd701227c105"),"actual projector hash unchanged");
        });
    }
    private static String failure(Work operation)throws Exception{
        try{operation.run();throw new AssertionError("expected actual operation refusal");}
        catch(Exception expected){return expected.getMessage();}
    }
    private static LocalRuntimeConfig lfmObserve(){return new LocalRuntimeConfig(ModelProfile.LFM3_VL_2B,"npu",8192,4,true);}
    private static void lfmObserveSettings()throws Exception{
        run("lfm3-observe-v3-is-explicit-and-tools-rejected",()->{
            byte[] raw=RuntimeConfigTransaction.selectedVisualObservation("npu");
            JSONObject value=new JSONObject(new String(raw,StandardCharsets.UTF_8));
            check(value.length()==6&&value.getString("schema").equals("hepta.local-runtime.v3"),"closed v3 fields");
            check(value.getString("model_profile").equals(ModelProfile.LFM3_VL_2B.id)
                    &&value.getString("visual_mode").equals("observe")&&value.getString("compute").equals("npu"),"LFM3-VL observation only");
            check(LocalRuntimeConfig.defaults().profile==ModelProfile.LFM3,"ordinary default remains text LFM3");
            reject(()->RuntimeConfigTransaction.selected(ModelProfile.LFM3_VL_2B.id,"npu"));
            for(String compute:new String[]{"gpu","cpu","auto","NPU",""})reject(()->RuntimeConfigTransaction.selectedVisualObservation(compute));
            Path files=fresh("lfm-forbidden-tools");value.put("visual_mode","tools");
            reject(()->RuntimeConfigTransaction.prepare(files.toFile(),value.toString().getBytes(StandardCharsets.UTF_8),true));
            check(Arrays.equals(ORIGINAL,Files.readAllBytes(files.resolve("model/runtime-config.json"))),"forbidden tools preserves bytes");
            check(!RuntimeConfigTransaction.pending(files.toFile()),"forbidden tools creates no transaction");
        });
        run("ordinary-text-lfm3-observe-gui-tools-text-router",()->{
            Env e=new Env("lfm-roundtrip");e.choose(5);
            check(e.engine.configuration().profile==ModelProfile.LFM3_VL_2B&&e.engine.configuration().visualObservationOnly,"ordinary selection is exact observation profile");
            check(e.app.modelSettings.state().contains("仅观察"),"owner status explains no model tool dispatch");
            AlertDialog.last=null;e.ui.choose();check(AlertDialog.last.checked==5,"ordinary menu selects LFM3-VL");
            String task=id();e.controller.begin(task);VlmInferenceAdapter visual=(VlmInferenceAdapter)delegate(e.controller.inference);
            check(e.controller==e.service.taskController(e.engine)&&e.controller.inference.acceptsObservedImage()
                    &&!e.controller.inference.modelOutputDispatchAllowed(),"cached controller uses new observation delegate without tool authority");
            LocalInference.CurrentFrame original=frame(e.files,task);
            e.controller.inference.generateObserved("p","s",original,null,1,1000,null);
            check(visual.observed==original,"LFM3-VL receives exact current-frame identity");
            check(e.controller.finish().cleanupKnown&&!e.engine.isBusy(),"observation task lease cleaned");
            e.choose(4);e.controller.begin(id());
            check(e.engine.configuration().profile==ModelProfile.GUI_OWL_4B&&e.controller.inference.modelOutputDispatchAllowed(),"following explicit GUI tools selection retains original boundary");
            check(e.controller.finish().cleanupKnown,"GUI task cleaned");
            e.choose(1);e.controller.begin(id());
            check(delegate(e.controller.inference) instanceof EngineInferenceAdapter&&e.engine.configuration().compute.equals("gpu"),"following text GPU task uses text adapter");
            check(e.controller.finish().cleanupKnown,"following text task cleaned");
        });
        run("ordinary-lfm3-observe-restore-keeps-exact-bytes",()->{
            Env e=new Env("lfm-restore");e.choose(5);byte[] observed=e.config();
            check(new JSONObject(new String(observed,StandardCharsets.UTF_8)).getString("visual_mode").equals("observe"),"stored observation mode exact");
            e.restored();check(Arrays.equals(ORIGINAL,e.config()),"restore keeps original text whitespace and key order");
            e.restored();check(Arrays.equals(observed,e.config())&&e.engine.configuration().profile==ModelProfile.LFM3_VL_2B
                    &&e.engine.configuration().visualObservationOnly,"restored observation bytes and authority exact");
        });
        run("lfm3-unknown-cleanup-retains-observe-authority",()->{
            Env e=new Env("lfm-unknown");e.choose(5);e.controller.begin(id());
            VlmInferenceAdapter visual=(VlmInferenceAdapter)delegate(e.controller.inference);visual.known=false;
            check(!e.controller.finish().cleanupKnown&&e.engine.isBusy(),"unknown LFM3 cleanup retains real lease");
            reject(()->e.app.modelSettings.start(ModelProfile.GUI_OWL_4B.id,"npu",false));
            check(e.engine.configuration().profile==ModelProfile.LFM3_VL_2B&&!e.controller.inference.modelOutputDispatchAllowed(),"failed switch cannot gain tools authority");
            visual.known=true;check(e.controller.finish().cleanupKnown&&!e.engine.isBusy(),"only original known cleanup releases observation lease");
            e.choose(4);check(e.engine.configuration().profile==ModelProfile.GUI_OWL_4B&&!e.engine.configuration().visualObservationOnly,"GUI selection requires completed original cleanup");
        });
        run("lfm3-actual-missing-and-foreign-assets-refuse-before-hash",()->{
            for(String variant:new String[]{"missing","q8","gui","text-language"}){
                Path files=fresh("lfm-assets-"+variant),dir=files.resolve("lfm3-vl-model");
                Files.createDirectory(dir);Files.setPosixFilePermissions(dir,PosixFilePermissions.fromString("rwx------"));
                Path model=dir.resolve("LFM3-VL-2B-QAD-Q4_0.gguf"),projector=dir.resolve("mmproj-LFM3-VL-2B-F16.gguf");
                sparse(model,variant.equals("text-language")?1049615680L:1049615648L);
                if(variant.equals("q8"))sparse(projector,203031872L);
                if(variant.equals("gui"))sparse(projector,836180288L);
                LocalModelEngine engine=real(files);LocalModelEngine.SettingsReservation lease=engine.reserveSettings(false);
                try{
                    reject(()->engine.verifySettingsModel(lease,lfmObserve()));
                    check(!RuntimeConfigTransaction.pending(files.toFile()),"foreign visual artifact cannot publish");
                    check(Arrays.equals(ORIGINAL,Files.readAllBytes(files.resolve("model/runtime-config.json"))),"foreign visual artifact preserves exact text config");
                    lease.requireOwned();engine.finishSettings(lease,true);check(!engine.isBusy(),"refused asset lease is released explicitly");
                }finally{Files.deleteIfExists(projector);Files.deleteIfExists(model);}
            }
        });
        run("lfm3-actual-complete-primary-hash-rejects-sparse-impostor",()->{
            Path files=fresh("lfm-full-hash"),dir=files.resolve("lfm3-vl-model");Files.createDirectory(dir);
            Files.setPosixFilePermissions(dir,PosixFilePermissions.fromString("rwx------"));
            Path model=dir.resolve("LFM3-VL-2B-QAD-Q4_0.gguf"),projector=dir.resolve("mmproj-LFM3-VL-2B-F16.gguf");
            sparse(model,1049615648L);sparse(projector,378996032L);
            LocalModelEngine engine=real(files);LocalModelEngine.SettingsReservation lease=engine.reserveSettings(false);
            try{
                String reason=failure(()->engine.verifySettingsModel(lease,lfmObserve()));
                check(reason!=null&&reason.contains("SHA-256"),"correct LFM3 directory/F16 sizes reached full primary hash: "+reason);
                check(!engine.settingsBlocked(),"unqualified sparse model was not published");
                lease.requireOwned();engine.finishSettings(lease,true);check(!engine.isBusy(),"failed content verification lease released");
            }finally{Files.deleteIfExists(projector);Files.deleteIfExists(model);}
        });
        run("lfm3-ordinary-asset-refusal-rolls-back-to-text",()->{
            Env e=new Env("lfm-rollback");e.engine.reject=true;e.choose(5);
            check(Arrays.equals(ORIGINAL,e.config()),"failed observation save restores exact text bytes");
            check(e.engine.configuration().profile==ModelProfile.LFM3&&!e.engine.settingsBlocked(),"failed observation save leaves usable text generation");
            e.controller.begin(id());check(delegate(e.controller.inference) instanceof EngineInferenceAdapter,"rollback does not leave a cached visual delegate");
            check(e.controller.finish().cleanupKnown,"rollback text reservation cleaned");
        });
        run("lfm3-four-gib-memory-contract-and-actual-low-memory-refusal",()->{
            Path files=fresh("lfm-memory");LocalModelEngine engine=real(files);LocalModelEngine.SettingsReservation lease=engine.reserveSettings(false);
            MemoryAvailability below=MemoryAvailability.fromText(0,12L<<30,false,"MemTotal: 12582912 kB\nMemAvailable: 4194303 kB\n");
            check(!below.admits(ModelProfile.LFM3_VL_2B.minimumAvailableBytes),"actual parser rejects below four GiB");
            MemoryAvailability exact=MemoryAvailability.fromText(0,12L<<30,false,"MemTotal: 12582912 kB\nMemAvailable: 4194304 kB\n");
            check(exact.admits(ModelProfile.LFM3_VL_2B.minimumAvailableBytes)&&!exact.admits(ModelProfile.GUI_OWL_4B.minimumAvailableBytes),
                    "actual four GiB contract is separate from GUI six GiB; host /proc memory is not replaced");
            ActivityManager.available=12L<<30;ActivityManager.low=true;
            check(failure(()->engine.verifySettingsModel(lease,lfmObserve())).contains("available memory"),"lowMemory remains authoritative");
            check(!RuntimeConfigTransaction.pending(files.toFile()),"memory failure writes no config");
            ActivityManager.low=false;lease.requireOwned();engine.finishSettings(lease,true);check(!engine.isBusy(),"memory test releases owned reservation");
        });
    }
    public static void main(String[] args)throws Exception{
        output=Paths.get(args[0]);Files.createDirectory(output);boolean passed=false;Throwable error=null;
        try{settings();routing();assets();lfmObserveSettings();passed=true;}
        catch(Throwable failure){error=failure;failure.printStackTrace();}
        finally{
            for(Env e:environments)try{e.close();}catch(Exception failure){passed=false;if(error==null)error=failure;failure.printStackTrace();}
            for(LocalModelEngine engine:realEngines)try{engine.close();if(!executor(engine).awaitTermination(3,TimeUnit.SECONDS))throw new IllegalStateException("real engine did not exit");}
                catch(Exception failure){passed=false;if(error==null)error=failure;failure.printStackTrace();}
        }
        JSONObject report=new JSONObject().put("schema","hepta.local-model-settings-visual-cases.v1").put("passed",passed)
                .put("cases",cases).put("assertions",assertions).put("case_results",rows)
                .put("actual_owner_button_methods",true).put("actual_application_idle_methods",true)
                .put("actual_service_controller_factory",true).put("actual_settings_transaction_and_engine",true)
                .put("actual_runtime_generation_binding",true).put("same_service_and_controller_roundtrip",true)
                .put("positive_weight_verification_is_host_boundary",true).put("vlm_model_loading_is_host_boundary",true)
                .put("actual_negative_asset_and_hash_checks",true).put("android_view_and_inventory_are_host_boundaries",true)
                .put("phone_operations",0).put("native_model_executed",false).put("positive_backend_qualified",false)
                .put("error",error==null?JSONObject.NULL:error.toString());
        Files.write(output.resolve("RESULT.json"),(report.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println(report.toString());if(!passed)System.exit(1);
    }
}
