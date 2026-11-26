package org.trillionnium.hepta.local;

import android.app.ActivityManager;
import android.os.Looper;
import android.system.Os;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;

/** Real transaction/Engine code and real host files; Android memory/UID/FD are explicit ports. */
public final class SettingsMemoryAdmissionHostTest {
    private static Path output;private static int assertions;
    private static final JSONArray rows=new JSONArray();
    private interface Work {void run()throws Exception;}
    private static void check(boolean yes,String why){assertions++;if(!yes)throw new AssertionError(why);}
    private static void reject(Work work)throws Exception{
        boolean refused=false;try{work.run();}catch(Exception expected){refused=true;}
        check(refused,"invalid diagnostic write must reject");
    }
    private static void write(Path path,byte[] raw)throws Exception{
        Files.write(path,raw);Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rw-------"));
    }
    private static Path fresh(String name)throws Exception{
        Path files=output.resolve(name);Files.createDirectory(files);Files.setPosixFilePermissions(files,PosixFilePermissions.fromString("rwx------"));
        Files.createDirectory(files.resolve("model"));Files.setPosixFilePermissions(files.resolve("model"),PosixFilePermissions.fromString("rwx------"));
        write(files.resolve("model/runtime-config.json"),RuntimeConfigTransaction.selectedVisualTools("npu"));return files;
    }
    private static RuntimeConfigTransaction prepare(Path files)throws Exception{
        return RuntimeConfigTransaction.prepare(files.toFile(),RuntimeConfigTransaction.selected(ModelProfile.LFM25_8B_A1B.id,"npu"),true);
    }
    private static LocalRuntimeConfig target(){return new LocalRuntimeConfig(ModelProfile.LFM25_8B_A1B,"npu",8192,4);}
    private static List<Path> records(RuntimeConfigTransaction tx)throws Exception{
        List<Path> result=new ArrayList<Path>();
        try(java.nio.file.DirectoryStream<Path> stream=Files.newDirectoryStream(tx.directory.toPath(),"memory-admission-*.json")){
            for(Path p:stream)result.add(p);
        }return result;
    }
    private static JSONObject only(RuntimeConfigTransaction tx)throws Exception{
        List<Path> all=records(tx);check(all.size()==1,"one immutable diagnostic file");
        JSONObject v=new JSONObject(new String(Files.readAllBytes(all.get(0)),StandardCharsets.UTF_8));
        check(all.get(0).getFileName().toString().equals("memory-admission-"+v.getString("admission_id")+".json"),"filename binds admission ID");
        check(v.getString("id").equals(tx.id)&&v.getInt("app_uid")==android.os.Process.myUid(),"transaction and UID bind receipt");
        check(v.getString("schema").equals("hepta.local-model-settings-memory-admission.v1"),"typed memory receipt");
        check(v.getString("configuration_sha256").equals(tx.target().sha())&&v.getBoolean("configuration_present"),"exact target bytes bind receipt");
        check(v.getString("model_profile").equals(ModelProfile.LFM25_8B_A1B.id)&&v.getLong("minimum_available_memory_bytes")==7L<<30,"pinned model threshold");
        check(!v.getBoolean("grants_admission")&&!v.getBoolean("inference_executed")&&!v.getBoolean("model_asset_verified_by_this_record"),"diagnostic does not claim model validation or execution");
        return v;
    }
    private static void finish(RuntimeConfigTransaction tx)throws Exception{tx.rollbackFiles();tx.finishRollback();}
    private static void sample(String name,MemoryAvailability memory,boolean admitted)throws Exception{
        Path f=fresh(name);byte[] before=Files.readAllBytes(f.resolve("model/runtime-config.json"));RuntimeConfigTransaction tx=prepare(f);
        tx.recordMemoryAdmission(target(),memory,1234L);JSONObject v=only(tx);
        check(v.getLong("available_memory_bytes")==memory.availableBytes&&v.getString("available_memory_source").equals(memory.source),"same supplied sample is serialized");
        check(v.getBoolean("admitted")==admitted&&v.getBoolean("admitted")==memory.admits(7L<<30),"original admission predicate retained");
        check(v.getBoolean("memory_measurement_valid")==memory.measurementValid&&v.getBoolean("android_low_memory")==memory.lowMemory,"invalid and lowMemory retained separately");
        check(v.getLong("activity_manager_available_bytes")==memory.activityManagerAvailable&&v.getLong("observed_elapsed_ms")==1234L,"AM value and original observation time retained");
        check(Arrays.equals(before,Files.readAllBytes(f.resolve("model/runtime-config.json")))&&RuntimeConfigTransaction.pending(f.toFile()),"diagnostic neither applies configuration nor clears pending");
        byte[] evidence=Files.readAllBytes(records(tx).get(0));finish(tx);
        check(Arrays.equals(evidence,Files.readAllBytes(records(tx).get(0)))&&!RuntimeConfigTransaction.pending(f.toFile()),"rollback preserves exact memory evidence");
    }
    private static MemoryAvailability kernel(long available,boolean low){
        return MemoryAvailability.fromText(111L,16L<<30,low,"MemTotal: 16777216 kB\nMemAvailable: "+available+" kB\n");
    }
    private static void run(String name,Work work)throws Exception{
        Os.reset();Looper.resetMain();int before=assertions;JSONObject row=new JSONObject().put("name",name);rows.put(row);
        try{work.run();row.put("passed",true);}catch(Throwable error){row.put("passed",false).put("error",error.toString());throw error;}
        finally{row.put("assertions",assertions-before);Os.reset();}
    }
    public static void main(String[] args)throws Exception{
        output=Paths.get(args[0]);Files.createDirectory(output);boolean passed=false;Throwable error=null;
        try{
            run("kernel_above_threshold",()->sample("above",kernel(8L<<20,false),true));
            run("kernel_below_threshold",()->sample("below",kernel(6L<<20,false),false));
            run("valid_kernel_low_memory_flag",()->sample("low",kernel(8L<<20,true),false));
            run("invalid_kernel_units",()->sample("invalid",MemoryAvailability.fromText(12L<<30,16L<<30,false,"MemTotal: 16777216 kB\nMemAvailable: 8000 MB\n"),false));
            run("duplicate_kernel_fields",()->sample("duplicate",MemoryAvailability.fromText(12L<<30,16L<<30,false,"MemTotal: 16777216 kB\nMemAvailable: 8000 kB\nMemAvailable: 8000 kB\n"),false));
            run("explicit_activity_manager_fallback",()->sample("fallback",MemoryAvailability.fromText(8L<<30,16L<<30,false,null),true));
            run("target_binding_refuses_other_profile",()->{
                Path f=fresh("wrong-profile");RuntimeConfigTransaction tx=prepare(f);
                reject(()->tx.recordMemoryAdmission(new LocalRuntimeConfig(ModelProfile.LFM3,"npu",8192,4),kernel(8L<<20,false),1));
                check(records(tx).isEmpty(),"no evidence written for foreign target");finish(tx);
            });
            run("pending_owner_refuses_other_transaction",()->{
                Path f=fresh("wrong-owner");RuntimeConfigTransaction tx=prepare(f);Path p=f.resolve("runtime-settings/pending.json");byte[] old=Files.readAllBytes(p);
                write(p,new JSONObject().put("schema","hepta.local-model-settings-pointer.v1").put("id","ffffffffffffffffffffffffffffffff").toString().getBytes(StandardCharsets.UTF_8));
                reject(()->tx.recordMemoryAdmission(target(),kernel(8L<<20,false),1));check(records(tx).isEmpty(),"foreign pending cannot receive evidence");
                write(p,old);finish(tx);
            });
            run("foreign_configuration_refuses_diagnostic_write",()->{
                Path f=fresh("foreign-config");RuntimeConfigTransaction tx=prepare(f);Path p=f.resolve("model/runtime-config.json");byte[] old=Files.readAllBytes(p);
                write(p,RuntimeConfigTransaction.selected(ModelProfile.LFM3.id,"gpu"));
                reject(()->tx.recordMemoryAdmission(target(),kernel(8L<<20,false),1));check(records(tx).isEmpty(),"foreign configuration not attributed to original transaction");
                write(p,old);finish(tx);
            });
            run("multiple_observations_never_overwrite",()->{
                Path f=fresh("append");RuntimeConfigTransaction tx=prepare(f);
                tx.recordMemoryAdmission(target(),kernel(6L<<20,false),1);Path first=records(tx).get(0);byte[] old=Files.readAllBytes(first);
                tx.recordMemoryAdmission(target(),kernel(8L<<20,false),2);
                check(records(tx).size()==2&&Arrays.equals(old,Files.readAllBytes(first)),"a later sample cannot replace failed memory evidence");finish(tx);
            });
            run("engine_retains_actual_rejected_sample",()->{
                Path f=fresh("actual-engine");LocalModelEngine engine=new LocalModelEngine(new android.content.Context(f.toFile()));
                LocalModelEngine.SettingsReservation lease=engine.reserveSettings(false);RuntimeConfigTransaction tx=prepare(f);
                try{
                    ActivityManager.low=true;ActivityManager.available=0;
                    reject(()->engine.verifySettingsModel(lease,target()));
                    LocalModelEngine.SettingsMemoryCheck check=engine.settingsMemoryCheck(lease);
                    check(check!=null&&check.memory.lowMemory&&!check.memory.admits(7L<<30),"actual verifier retains the sample that rejected admission");
                    ActivityManager.low=false;ActivityManager.available=12L<<30;
                    tx.recordMemoryAdmission(check.configuration,check.memory,check.elapsedMs);JSONObject v=only(tx);
                    check(v.getBoolean("android_low_memory")&&v.getLong("activity_manager_available_bytes")==0L,"later AM change does not replace the verifier sample");
                    check(v.getLong("available_memory_bytes")==check.memory.availableBytes,"actual captured kernel value retained verbatim");
                    finish(tx);engine.finishSettings(lease,true);
                }finally{engine.close();ActivityManager.low=true;ActivityManager.available=0;}
            });
            passed=true;
        }catch(Throwable failure){error=failure;failure.printStackTrace();}
        JSONObject report=new JSONObject().put("schema","hepta.settings-memory-diagnostics-host.v1").put("passed",passed)
                .put("cases",rows.length()).put("assertions",assertions).put("case_results",rows)
                .put("phone_operations",0).put("native_model_executed",false).put("android_platform_is_host_boundary",true)
                .put("error",error==null?JSONObject.NULL:error.toString());
        Files.write(output.resolve("RESULT.json"),report.toString(2).getBytes(StandardCharsets.UTF_8));
        if(!passed)System.exit(1);
    }
}
