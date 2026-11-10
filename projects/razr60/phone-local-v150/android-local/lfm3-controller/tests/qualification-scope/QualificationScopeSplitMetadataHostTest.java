package org.trillionnium.hepta.local;

import android.content.pm.PackageInfo;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import static org.trillionnium.hepta.local.QualificationScopeHostTest.*;

/** Actual production capture/verify/controller; real synthetic APK files, no device inference. */
public final class QualificationScopeSplitMetadataHostTest {
    private QualificationScopeSplitMetadataHostTest(){}
    private static String selection;
    private static void testSplit(String name,Case body)throws Exception{if(selection==null||selection.equals(name))test(name,body);}
    private static QualificationScopeConfig.Bound capture(Env e){return QualificationScopeConfig.capture(e.service,e.task,e.scopeSha,e.runtime);}
    private static void ready(QualificationScopeConfig.Bound b){b.requireReady();b.verifyUnchanged();}
    private static void emptyMetadata(Env e,boolean namesNull,boolean filesNull){
        for(PackageInfo info:e.pm.packages.values()){
            info.splitNames=namesNull?null:new String[0];info.applicationInfo.splitSourceDirs=filesNull?null:new String[0];
        }
    }
    private static Path[] splitFiles(Env e)throws Exception{
        Path zh=e.dir.resolve("installed/calculator-config-zh.apk"),arm=e.dir.resolve("installed/calculator-config-arm.apk");
        write(zh,bytes("synthetic split zh exact bytes"),0644);write(arm,bytes("synthetic split arm exact bytes"),0644);return new Path[]{zh,arm};
    }
    private static Path[] validSplits(Env e,boolean bindExpected)throws Exception{
        Path[] p=splitFiles(e);PackageInfo info=e.pm.packages.get(CALC);
        info.splitNames=new String[]{"config.zh","config.arm64_v8a"};info.applicationInfo.splitSourceDirs=new String[]{p[0].toString(),p[1].toString()};
        if(bindExpected){
            // Independent expected rows in the documented sorted APK-set wire format.
            String rows="base\t"+QualificationScope.hash(Files.readAllBytes(Paths.get(info.applicationInfo.sourceDir)))+"\n"
                    +"split:config.arm64_v8a\t"+QualificationScope.hash(Files.readAllBytes(p[1]))+"\n"
                    +"split:config.zh\t"+QualificationScope.hash(Files.readAllBytes(p[0]))+"\n";
            e.fields.put("calculator_apk_set_sha256",QualificationScope.hash(bytes(rows)));e.updateConfig();e.writeConfig();
        }
        return p;
    }
    private static void verifyRefusal(QualificationScopeConfig.Bound b,String prefix,String packageName)throws Exception{
        rejects(()->b.requireReady());String reason=b.evidence().getString("refusal");
        check(reason.startsWith("qualification_scope: "+prefix)&&reason.contains("package="+packageName)&&reason.contains("splitNames_length=")&&reason.contains("splitSourceDirs_length="),"refusal retains package and original array lengths: "+reason);
    }
    private static void allCases()throws Exception{
        for(boolean namesNull:new boolean[]{true,false})for(boolean filesNull:new boolean[]{true,false}){
            String name="empty_split_names_"+(namesNull?"null":"zero")+"_paths_"+(filesNull?"null":"zero");
            testSplit(name,()->{try(Env e=new Env(true,true)){
                emptyMetadata(e,namesNull,filesNull);QualificationScopeConfig.Bound b=capture(e);ready(b);
                check(e.scopeSha.equals(b.actualSha256),"scope remains exactly bound");
                LocalTaskController.TaskResult r=e.controller("done",SETTINGS,null);
                check("model_reported_done".equals(r.status)&&r.steps==1&&r.cleanupKnown&&r.modelReportedSuccess&&e.service.effects()==0,"empty representation reaches one synthetic model step: "+r.summary);
                check(e.scopeSha.equals(r.expectedScopeSha256)&&e.scopeSha.equals(r.actualScopeSha256),"controller keeps full expected/actual scope identity");
            }});
        }
        testSplit("empty_representation_changes_preserve_captured_apk_identity",()->{try(Env e=new Env(true,true)){
            QualificationScopeConfig.Bound b=capture(e);ready(b);
            for(boolean n:new boolean[]{true,false})for(boolean f:new boolean[]{true,false}){emptyMetadata(e,n,f);b.verifyUnchanged();}
        }});
        testSplit("valid_multiple_splits_full_hash_and_reordered_pairs",()->{try(Env e=new Env(true,true)){
            Path[] p=validSplits(e,true);QualificationScopeConfig.Bound b=capture(e);ready(b);
            PackageInfo info=e.pm.packages.get(CALC);info.splitNames=new String[]{"config.arm64_v8a","config.zh"};info.applicationInfo.splitSourceDirs=new String[]{p[1].toString(),p[0].toString()};
            b.verifyUnchanged();check(e.scopeSha.equals(b.actualSha256),"pair order does not change the captured map or expected APK-set hash");
        }});
        testSplit("valid_multiple_splits_actual_controller",()->{try(Env e=new Env(true,true)){
            validSplits(e,true);LocalTaskController.TaskResult r=e.controller("done",SETTINGS,null);
            check("model_reported_done".equals(r.status)&&r.modelReportedSuccess&&r.cleanupKnown&&r.steps==1&&e.service.effects()==0,"actual nonempty split set remains usable");
        }});
        testSplit("nonempty_splits_cannot_be_silently_reduced_to_base_hash",()->{try(Env e=new Env(true,true)){
            validSplits(e,false);QualificationScopeConfig.Bound b=capture(e);rejects(()->b.requireReady());
            check(b.evidence().getString("refusal").contains("installed role identity mismatch: calculator"),"full nonempty APK-set hash must be checked");
        }});
        testSplit("empty_metadata_still_checks_actual_hepta_apk_hash",()->{try(Env e=new Env(true,true)){
            emptyMetadata(e,true,false);e.fields.put("hepta_apk_sha256",H);e.updateConfig();e.writeConfig();QualificationScopeConfig.Bound b=capture(e);rejects(()->b.requireReady());
            check(b.evidence().getString("refusal").contains("installed Hepta identity mismatch"),"base APK full hash is not bypassed");
        }});
        String[] invalid={"names_null_one_path","names_zero_one_path","one_name_paths_null","one_name_paths_zero","two_names_one_path","one_name_two_paths","null_name","empty_name","duplicate_name","invalid_name","null_path","empty_path"};
        for(String kind:invalid)testSplit("invalid_split_"+kind,()->{try(Env e=new Env(true,true)){
            Path[] p=splitFiles(e);PackageInfo info=e.pm.packages.get(CALC);String z=p[0].toString(),a=p[1].toString();
            switch(kind){
                case "names_null_one_path":info.splitNames=null;info.applicationInfo.splitSourceDirs=new String[]{z};break;
                case "names_zero_one_path":info.splitNames=new String[0];info.applicationInfo.splitSourceDirs=new String[]{z};break;
                case "one_name_paths_null":info.splitNames=new String[]{"config.zh"};info.applicationInfo.splitSourceDirs=null;break;
                case "one_name_paths_zero":info.splitNames=new String[]{"config.zh"};info.applicationInfo.splitSourceDirs=new String[0];break;
                case "two_names_one_path":info.splitNames=new String[]{"config.zh","config.arm"};info.applicationInfo.splitSourceDirs=new String[]{z};break;
                case "one_name_two_paths":info.splitNames=new String[]{"config.zh"};info.applicationInfo.splitSourceDirs=new String[]{z,a};break;
                case "null_name":info.splitNames=new String[]{null};info.applicationInfo.splitSourceDirs=new String[]{z};break;
                case "empty_name":info.splitNames=new String[]{""};info.applicationInfo.splitSourceDirs=new String[]{z};break;
                case "duplicate_name":info.splitNames=new String[]{"config.zh","config.zh"};info.applicationInfo.splitSourceDirs=new String[]{z,a};break;
                case "invalid_name":info.splitNames=new String[]{"../config"};info.applicationInfo.splitSourceDirs=new String[]{z};break;
                case "null_path":info.splitNames=new String[]{"config.zh"};info.applicationInfo.splitSourceDirs=new String[]{null};break;
                case "empty_path":info.splitNames=new String[]{"config.zh"};info.applicationInfo.splitSourceDirs=new String[]{""};break;
                default:throw new AssertionError(kind);
            }
            QualificationScopeConfig.Bound b=capture(e);String prefix=(kind.endsWith("one_path")||kind.endsWith("two_paths")||kind.endsWith("paths_null")||kind.endsWith("paths_zero"))?"APK splits unknown:":"APK split name invalid:";
            verifyRefusal(b,prefix,CALC);check(e.scopeSha.equals(b.actualSha256)&&e.service.effects()==0,"metadata denial occurs after exact scope capture, before any UI effect");
        }});
        testSplit("captured_nonempty_split_file_mutation_refused",()->{try(Env e=new Env(true,true)){
            Path[] p=validSplits(e,true);QualificationScopeConfig.Bound b=capture(e);ready(b);write(p[0],bytes("changed installed split APK bytes"),0644);rejects(()->b.verifyUnchanged());
        }});
        testSplit("captured_nonempty_split_path_change_refused",()->{try(Env e=new Env(true,true)){
            Path[] p=validSplits(e,true);QualificationScopeConfig.Bound b=capture(e);ready(b);Path other=e.dir.resolve("installed/identical-zh-new-path.apk");write(other,Files.readAllBytes(p[0]),0644);
            e.pm.packages.get(CALC).applicationInfo.splitSourceDirs[0]=other.toString();rejects(()->b.verifyUnchanged());
            check(b.evidence().getString("refusal").contains("APK path changed"),"same bytes at another path do not preserve identity");
        }});
        testSplit("captured_nonempty_split_set_removed_refused",()->{try(Env e=new Env(true,true)){
            validSplits(e,true);QualificationScopeConfig.Bound b=capture(e);ready(b);PackageInfo info=e.pm.packages.get(CALC);info.splitNames=null;info.applicationInfo.splitSourceDirs=new String[0];rejects(()->b.verifyUnchanged());
            check(b.evidence().getString("refusal").contains("installed identity changed"),"empty normalization cannot remove an existing captured split set");
        }});
        testSplit("captured_nonempty_split_metadata_mismatch_has_diagnostics",()->{try(Env e=new Env(true,true)){
            validSplits(e,true);QualificationScopeConfig.Bound b=capture(e);ready(b);e.pm.packages.get(CALC).splitNames=null;rejects(()->b.verifyUnchanged());verifyRefusal(b,"APK splits unknown:",CALC);
            check(b.evidence().getString("refusal").contains("splitNames_length=null")&&b.evidence().getString("refusal").contains("splitSourceDirs_length=2"),"null and actual nonempty length remain distinguishable");
        }});
        testSplit("invalid_split_controller_zero_model_and_diagnostic_result",()->{try(Env e=new Env(true,true)){
            Path[] p=splitFiles(e);PackageInfo info=e.pm.packages.get(CALC);info.splitNames=null;info.applicationInfo.splitSourceDirs=new String[]{p[0].toString()};
            LocalTaskController.TaskResult r=e.controller("done",SETTINGS,null);
            check("failed".equals(r.status)&&r.steps==0&&!r.modelReportedSuccess&&r.cleanupKnown&&e.service.effects()==0,"bad nonempty metadata stops before planning");
            check("0".equals(new String(Files.readAllBytes(e.dir.resolve("host-native-call-count.txt")),StandardCharsets.UTF_8)),"no model call on bad metadata");
            JSONObject result=new JSONObject(new String(Files.readAllBytes(r.evidenceDirectory.toPath().resolve("result.json")),StandardCharsets.UTF_8));
            String reason=result.getJSONObject("qualification_scope").getString("refusal");
            check(reason.contains("package="+CALC)&&reason.contains("splitNames_length=null")&&reason.contains("splitSourceDirs_length=1"),"actual production terminal evidence carries diagnostic shape");
            check(e.scopeSha.equals(r.expectedScopeSha256)&&e.scopeSha.equals(r.actualScopeSha256),"scope identity remains exact even on metadata refusal");
        }});
    }
    public static void main(String[] args)throws Exception{
        output=Paths.get(args[0]);Files.createDirectories(output);selection=args.length>1?args[1]:null;allCases();check(!passed.isEmpty(),"selected split case exists");
        JSONObject result=new JSONObject().put("schema","hepta.split-metadata-host-tests.v1").put("passed",passed.size()).put("tests",new JSONArray(passed))
                .put("phone_operations",false).put("native_inference",false).put("android_runtime",false)
                .put("boundary","Actual production scope capture/verify/controller and real synthetic APK files; Android PackageManager/IO/model endpoints are explicit host substitutes");
        Files.write(output.resolve("RESULT.json"),result.toString(2).getBytes(StandardCharsets.UTF_8));System.out.println("PASS split-metadata cases="+passed.size());
    }
}
