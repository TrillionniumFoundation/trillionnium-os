package org.trillionnium.hepta.local;

import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import static org.trillionnium.hepta.local.QualificationScopeHostTest.*;

/** Real host ancestor aliases; actual loader/controller, synthetic Android and model endpoints. */
public final class QualificationScopePrivateRootHostTest {
    private QualificationScopePrivateRootHostTest(){}
    private static String selection;
    private static void testPath(String name,Case body)throws Exception{
        if(selection==null||selection.equals(name))test(name,body);
    }
    private static QualificationScopeConfig.Bound capture(Env e){
        return QualificationScopeConfig.capture(e.service,e.task,e.scopeSha,e.runtime);
    }
    private static void ready(QualificationScopeConfig.Bound bound){bound.requireReady();bound.verifyUnchanged();}
    private static void refused(QualificationScopeConfig.Bound bound)throws Exception{
        rejects(()->bound.requireReady());check(bound.restricted(),"failure must never become unrestricted");
    }
    private static void noModelOrEffects(Env e,LocalTaskController.TaskResult result)throws Exception{
        check("failed".equals(result.status)&&result.steps==0&&!result.modelReportedSuccess&&result.cleanupKnown,"path refusal must be terminal before planning");
        check("0".equals(new String(Files.readAllBytes(e.dir.resolve("host-native-call-count.txt")),StandardCharsets.UTF_8))&&e.service.effects()==0,"path refusal must call neither model nor UI");
    }
    private static void symbolic(Path path,Path target)throws Exception{Files.move(path,target);Files.createSymbolicLink(path,target);}
    private static void allCases()throws Exception{
        testPath("framework_ancestor_alias_actual_scope_capture",()->{try(Env e=new Env(true,true)){
            QualificationScopeConfig.Bound b=capture(e);ready(b);
            check(b.scopePath.equals(e.dir.resolve(QualificationScope.FILE_NAME).toFile()),"scope uses canonical ancestor and unchanged leaf");
            check(b.runtimeFile.path.equals(e.dir.resolve("model/runtime-config.json").toFile()),"runtime shares canonical ancestor");
            check(e.scopeSha.equals(b.actualSha256)&&Arrays.equals(e.config,b.raw),"exact scope bytes and binding");
        }});
        testPath("framework_ancestor_alias_actual_controller_three_evidence_files",()->{try(Env e=new Env(true,true)){
            QualificationScopeConfig.Bound b=capture(e);ready(b);
            LocalTaskController.TaskResult r=e.controller("done",SETTINGS,null);
            check("model_reported_done".equals(r.status)&&r.modelReportedSuccess&&r.cleanupKnown&&r.steps==1,"controller must reach one synthetic model step: "+r.summary);
            check("1".equals(new String(Files.readAllBytes(e.dir.resolve("host-native-call-count.txt")),StandardCharsets.UTF_8))&&e.service.effects()==0,"exactly one fake model call; no UI dispatch");
            check(r.evidenceDirectory.getAbsoluteFile().equals(r.evidenceDirectory.getCanonicalFile()),"evidence directory must itself remain canonical");
            check(e.scopeSha.equals(r.expectedScopeSha256)&&e.scopeSha.equals(r.actualScopeSha256),"task binds expected and actual scope");
            Path evidence=r.evidenceDirectory.toPath();
            check(Arrays.equals(e.config,Files.readAllBytes(evidence.resolve("qualification-scope.json"))),"scope evidence bytes");
            check(Arrays.equals(b.buildBytes,Files.readAllBytes(evidence.resolve("build-identity.json"))),"build evidence bytes");
            check(Arrays.equals(b.runtimeFile.bytes,Files.readAllBytes(evidence.resolve("scope-runtime-config.json"))),"runtime evidence bytes");
            b.verifyUnchanged();
        }});
        testPath("normal_journal_and_child_directory_growth_retains_root_identity",()->{try(Env e=new Env(true,true)){
            android.system.Os.chmod(e.dir.toString(),0755);QualificationScopeConfig.Bound b=capture(e);ready(b);
            android.system.StructStat before=android.system.Os.lstat(e.dir.toString());
            write(e.dir.resolve("task-session.json"),bytes("{\"state\":\"synthetic-running\"}"),0600);
            Files.createDirectory(e.dir.resolve("new-run-directory"));
            write(e.dir.resolve("new-run-directory/receipt.json"),bytes("{\"synthetic\":true}"),0600);
            android.system.Os.chmod(e.dir.toString(),0700);
            android.system.StructStat after=android.system.Os.lstat(e.dir.toString());
            check(before.st_dev==after.st_dev&&before.st_ino==after.st_ino&&before.st_nlink!=after.st_nlink,"real child creation changes directory link count without changing identity");
            b.verifyUnchanged();
            LocalTaskController.TaskResult r=e.controller("done",SETTINGS,null);
            check("model_reported_done".equals(r.status)&&r.cleanupKnown,"normal new task remains valid");b.verifyUnchanged();
        }});
        testPath("private_diagnostics_capture_app_namespace_before_leaf_guard",()->{try(Env e=new Env(true,true)){
            Path scope=e.dir.resolve(QualificationScope.FILE_NAME);symbolic(scope,e.dir.resolve("same-scope-bytes.json"));
            QualificationScopeConfig.Bound b=capture(e);refused(b);
            JSONObject d=b.evidence().getJSONObject("private_path_diagnostics");
            check(d.getBoolean("metadata_only")&&"hepta.private-path-diagnostics.v1".equals(d.getString("schema")),"metadata contract");
            check(d.getString("framework_files_absolute").equals(e.service.getFilesDir().getAbsolutePath()),"actual framework absolute path retained");
            check(d.getString("framework_files_canonical").equals(e.dir.toFile().getCanonicalPath()),"app-process canonical path retained");
            check(d.getString("framework_scope_canonical").equals(e.dir.resolve("same-scope-bytes.json").toString())&&b.raw==null,"diagnostic canonicalization never becomes an accepted read path");
        }});
        testPath("scope_leaf_alias_inside_files_is_refused",()->{try(Env e=new Env(true,true)){
            symbolic(e.dir.resolve(QualificationScope.FILE_NAME),e.dir.resolve("scope-real.json"));QualificationScopeConfig.Bound b=capture(e);refused(b);check(b.raw==null&&b.actualSha256==null,"no scope bytes read through a leaf alias");
        }});
        testPath("scope_leaf_alias_outside_files_is_refused",()->{try(Env e=new Env(true,true)){
            symbolic(e.dir.resolve(QualificationScope.FILE_NAME),e.dir.getParent().resolve("scope-real.json"));QualificationScopeConfig.Bound b=capture(e);refused(b);check(b.raw==null,"no out-of-root scope read");
        }});
        testPath("model_directory_alias_is_refused",()->{try(Env e=new Env(true,true)){
            symbolic(e.dir.resolve("model"),e.dir.resolve("model-real"));QualificationScopeConfig.Bound b=capture(e);refused(b);check(e.scopeSha.equals(b.actualSha256)&&b.runtimeFile==null,"intermediate model alias refused before runtime read");
        }});
        testPath("runtime_leaf_alias_is_refused",()->{try(Env e=new Env(true,true)){
            symbolic(e.dir.resolve("model/runtime-config.json"),e.dir.resolve("model/runtime-real.json"));QualificationScopeConfig.Bound b=capture(e);refused(b);check(b.runtimeFile==null,"runtime leaf alias refused");
        }});
        testPath("framework_files_directory_itself_cannot_be_alias",()->{try(Env e=new Env(true,true)){
            symbolic(e.dir,e.dir.resolveSibling("files-real"));QualificationScopeConfig.Bound b=capture(e);refused(b);check(b.raw==null,"only framework ancestor can be normalized");
        }});
        testPath("controller_control_tasks_alias_refuses_before_model_or_write",()->{try(Env e=new Env(true,true)){
            Path target=Files.createDirectory(e.dir.resolve("evidence-outside-control"));Files.createSymbolicLink(e.dir.resolve("control-tasks"),target);
            noModelOrEffects(e,e.controller("done",SETTINGS,null));
            try(java.util.stream.Stream<Path> children=Files.list(target)){check(children.count()==0,"aliased task directory receives no evidence write");}
        }});
        testPath("files_root_refusal_keeps_controller_terminal_cleanup_and_lease_release",()->{try(Env e=new Env(true,true)){
            symbolic(e.dir,e.dir.resolveSibling("files-real"));LocalTaskController.TaskResult r=e.controller("done",SETTINGS,null);noModelOrEffects(e,r);
            check(r.evidenceDirectory==null&&!e.controller.isRunning(),"early root failure must not invent an evidence directory or leave a running controller");
            check(e.service.acquireTask(e.task,()->{}),"failed task releases the accessibility lease");e.service.releaseTask(e.task);
        }});
        testPath("fresh_task_directory_alias_and_collision_remain_refused",()->{try(Env e=new Env(true,true)){
            Path root=e.dir.resolve("control-tasks");MobiMindPrivateFiles.directory(root.toFile(),false);
            Path target=Files.createDirectory(e.dir.resolve("external-task")),child=root.resolve("fixed-test-task");Files.createSymbolicLink(child,target);
            boolean denied=false;try{MobiMindPrivateFiles.directory(child.toFile(),true);}catch(Exception expected){denied=true;}check(denied,"new task alias must fail");
            Files.delete(child);Files.createDirectory(child);denied=false;try{MobiMindPrivateFiles.directory(child.toFile(),true);}catch(Exception expected){denied=true;}check(denied,"new task collision must fail");
        }});
        testPath("framework_ancestor_retarget_after_capture_is_refused",()->{try(Env e=new Env(true,true)){
            QualificationScopeConfig.Bound b=capture(e);ready(b);
            Path other=Files.createTempDirectory(output,"other-framework-parent-");Files.createDirectory(other.resolve("files"));Files.delete(e.frameworkAlias);Files.createSymbolicLink(e.frameworkAlias,other);
            rejects(()->b.verifyUnchanged());check(b.evidence().getString("refusal").contains("root changed"),"retarget refusal identifies root binding");
        }});
        testPath("files_directory_inode_replacement_is_refused",()->{try(Env e=new Env(true,true)){
            QualificationScopeConfig.Bound b=capture(e);ready(b);Files.move(e.dir,e.dir.resolveSibling("original-files"));Files.createDirectory(e.dir);
            rejects(()->b.verifyUnchanged());check(b.evidence().getString("refusal").contains("identity changed"),"stable path cannot substitute a new directory inode");
        }});
        testPath("files_directory_alias_after_capture_is_refused",()->{try(Env e=new Env(true,true)){
            QualificationScopeConfig.Bound b=capture(e);ready(b);symbolic(e.dir,e.dir.resolveSibling("original-files"));rejects(()->b.verifyUnchanged());
        }});
        testPath("files_permissions_widening_is_refused",()->{try(Env e=new Env(true,true)){
            android.system.Os.chmod(e.dir.toString(),0700);QualificationScopeConfig.Bound b=capture(e);ready(b);android.system.Os.chmod(e.dir.toString(),0755);
            rejects(()->b.verifyUnchanged());check(b.evidence().getString("refusal").contains("permissions widened"),"permission boundary");
        }});
        testPath("observed_permission_tightening_cannot_be_reversed",()->{try(Env e=new Env(true,true)){
            android.system.Os.chmod(e.dir.toString(),0755);QualificationScopeConfig.Bound b=capture(e);ready(b);android.system.Os.chmod(e.dir.toString(),0700);b.verifyUnchanged();
            android.system.Os.chmod(e.dir.toString(),0755);rejects(()->b.verifyUnchanged());
        }});
        testPath("scope_hardlink_is_refused_with_framework_alias",()->{try(Env e=new Env(true,true)){
            Files.createLink(e.dir.resolve("scope-hardlink.json"),e.dir.resolve(QualificationScope.FILE_NAME));QualificationScopeConfig.Bound b=capture(e);refused(b);check(b.raw==null,"single-link scope constraint");
        }});
        testPath("runtime_hardlink_is_refused_with_framework_alias",()->{try(Env e=new Env(true,true)){
            Files.createLink(e.dir.resolve("runtime-hardlink.json"),e.dir.resolve("model/runtime-config.json"));QualificationScopeConfig.Bound b=capture(e);refused(b);check(b.runtimeFile==null,"single-link runtime constraint");
        }});
        for(String file:new String[]{QualificationScope.FILE_NAME,"model/runtime-config.json"}){
            testPath("private_mode_refused_"+file,()->{try(Env e=new Env(true,true)){
                android.system.Os.chmod(e.dir.resolve(file).toString(),0640);refused(capture(e));
            }});
            testPath("private_content_mutation_refused_"+file,()->{try(Env e=new Env(true,true)){
                QualificationScopeConfig.Bound b=capture(e);ready(b);write(e.dir.resolve(file),bytes("{}"),0600);rejects(()->b.verifyUnchanged());
            }});
        }
        testPath("unrestricted_alias_task_remains_unrestricted_until_scope_appears",()->{try(Env e=new Env(false,true)){
            QualificationScopeConfig.Bound b=QualificationScopeConfig.capture(e.service,e.task,null,e.runtime);ready(b);check(!b.restricted(),"optional scope remains optional");
            write(e.dir.resolve("ordinary-journal.json"),bytes("{}"),0600);Files.createDirectory(e.dir.resolve("ordinary-run"));b.verifyUnchanged();e.writeConfig();rejects(()->b.verifyUnchanged());
        }});
        for(boolean alias:new boolean[]{false,true})testPath("unrestricted_actual_controller_still_operates_alias_"+alias,()->{try(Env e=new Env(false,alias)){
            LocalTaskController.TaskResult r=e.controller("done",SETTINGS,null,null);
            check("model_reported_done".equals(r.status)&&r.modelReportedSuccess&&r.cleanupKnown&&r.steps==1&&e.service.effects()==0,"ordinary no-scope production controller remains usable");
            check(r.expectedScopeSha256==null&&r.actualScopeSha256==null,"no invented qualification binding");
        }});
        testPath("expected_scope_missing_never_falls_back_with_alias",()->{try(Env e=new Env(false,true)){
            QualificationScopeConfig.Bound b=capture(e);refused(b);check(b.raw==null,"expected missing scope never weakens the task");
        }});
        testPath("model_directory_alias_after_capture_is_refused",()->{try(Env e=new Env(true,true)){
            QualificationScopeConfig.Bound b=capture(e);ready(b);symbolic(e.dir.resolve("model"),e.dir.resolve("old-model"));rejects(()->b.verifyUnchanged());
        }});
    }
    public static void main(String[] args)throws Exception{
        output=Paths.get(args[0]);Files.createDirectories(output);selection=args.length>1?args[1]:null;allCases();
        check(!passed.isEmpty(),"selected private-root case must exist");
        JSONObject result=new JSONObject().put("schema","hepta.private-root-host-tests.v1").put("passed",passed.size()).put("tests",new JSONArray(passed))
                .put("phone_operations",false).put("native_inference",false).put("android_runtime",false)
                .put("boundary","Real host paths, symlinks and actual production capture/controller; Android IO and model endpoints are surrogates");
        Files.write(output.resolve("RESULT.json"),result.toString(2).getBytes(StandardCharsets.UTF_8));
        System.out.println("PASS private-root cases="+passed.size());
    }
}
