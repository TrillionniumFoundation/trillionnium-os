package org.trillionnium.hepta.local;

import android.content.Context;
import android.system.Os;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import org.json.JSONArray;
import org.json.JSONObject;

/** Real ancestor/leaf symlinks and directory replacement; Android Context/UID are host ports. */
public final class RuntimeContextFilesHostTest {
    private static int cases,assertions;
    private static Path output;
    private static final JSONArray rows=new JSONArray();
    private static final byte[] ORIGINAL=("{\n \"schema\":\"hepta.local-runtime.v1\",\"compute\":\"npu\","
            +"\"context_tokens\":8192,\"threads\":4\n}\n").getBytes(StandardCharsets.UTF_8);
    private interface Work {void run()throws Exception;}
    private static void check(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    private static void reject(Work body)throws Exception{
        boolean refused=false;try{body.run();}catch(Exception expected){refused=true;}
        check(refused,"unsafe path must be refused");
    }
    private static void directory(Path path)throws Exception{
        Files.createDirectory(path);Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rwx------"));
    }
    private static void write(Path path,byte[] bytes)throws Exception{
        Files.write(path,bytes,StandardOpenOption.CREATE_NEW);
        Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rw-------"));
    }
    private static final class Tree {
        final Path base,real,alias,files,fromContext;
        final Context context;
        Tree(String name)throws Exception{
            base=output.resolve(name);directory(base);
            real=base.resolve("data");directory(real);
            Path user=base.resolve("user");directory(user);
            alias=user.resolve("0");Files.createSymbolicLink(alias,real);
            Path app=real.resolve("org.trillionnium.hepta.local");directory(app);
            files=app.resolve("files");directory(files);directory(files.resolve("model"));
            write(files.resolve("model/runtime-config.json"),ORIGINAL);
            fromContext=alias.resolve("org.trillionnium.hepta.local/files");
            context=new Context(fromContext.toFile());
        }
        File canonical()throws Exception{return RuntimeConfigTransaction.contextFiles(context);}
        byte[] config()throws Exception{return Files.readAllBytes(files.resolve("model/runtime-config.json"));}
        Path pending(){return files.resolve("runtime-settings/pending.json");}
    }
    private static void run(String name,Work body)throws Exception{
        Os.reset();int before=assertions;JSONObject row=new JSONObject().put("name",name);rows.put(row);
        try{body.run();row.put("passed",true);cases++;}
        catch(Throwable error){row.put("passed",false).put("error",error.toString());throw error;}
        finally{row.put("assertions",assertions-before);Os.reset();}
    }
    private static void tests()throws Exception{
        run("context-ancestor-alias-engine-commit-and-exact-restore",()->{
            Tree tree=new Tree("ancestor");
            check(!tree.fromContext.toFile().equals(tree.fromContext.toFile().getCanonicalFile()),"real ancestor alias exists");
            File canonical=tree.canonical();check(canonical.equals(tree.files.toFile()),"trusted Context root resolves to the same directory");
            reject(()->RuntimeConfigTransaction.current(tree.fromContext.toFile()));
            reject(()->RuntimeConfigTransaction.pending(tree.fromContext.toFile()));
            reject(()->RuntimeConfigTransaction.prepare(tree.fromContext.toFile(),RuntimeConfigTransaction.selected(ModelProfile.LFM3.id,"gpu"),true));
            LocalModelEngine original=new LocalModelEngine(tree.context);
            try{
                check(original.configuration().profile==ModelProfile.LFM3&&"npu".equals(original.configuration().compute),"actual Engine loads the original Context config");
                check(!original.settingsBlocked(),"legal platform alias does not create an unknown pending state");
                check(original.modelDirectory().equals(tree.files.resolve("model").toFile())
                        &&original.modelFile().equals(original.modelFile().getCanonicalFile()),"model verification receives canonical paths from the same trusted root");
            }finally{original.close();}
            byte[] gpu=RuntimeConfigTransaction.selected(ModelProfile.LFM3.id,"gpu");
            RuntimeConfigTransaction tx=RuntimeConfigTransaction.prepare(tree.canonical(),gpu,true);
            check(RuntimeConfigTransaction.pending(tree.canonical()),"pending visible through Context normalization");
            tx.apply();tx.commit();check(Arrays.equals(gpu,tree.config()),"committed bytes exact");
            LocalModelEngine selected=new LocalModelEngine(tree.context);
            try{check("gpu".equals(selected.configuration().compute)&&!selected.settingsBlocked(),"new Engine observes committed GPU config without inference");}
            finally{selected.close();}
            check(RuntimeConfigTransaction.restoreAvailable(tree.canonical()),"ordinary restore is available");
            RuntimeConfigTransaction restore=RuntimeConfigTransaction.restore(tree.canonical());
            restore.apply();restore.commit();
            check(Arrays.equals(ORIGINAL,tree.config()),"original whitespace and exact bytes restored");
            check(!RuntimeConfigTransaction.pending(tree.canonical()),"own pending marker cleared");
        });
        run("context-files-leaf-symlink-rejected",()->{
            Tree tree=new Tree("leaf");Path saved=tree.files.resolveSibling("files-saved");
            Files.move(tree.files,saved);Files.createSymbolicLink(tree.files,saved);
            reject(()->tree.canonical());
            LocalModelEngine engine=new LocalModelEngine(tree.context);
            try{reject(()->engine.configuration());check(engine.settingsBlocked(),"unsafe Context root blocks actual Engine startup");}
            finally{engine.close();}
            check(!Files.exists(saved.resolve("runtime-settings")),"leaf rejection writes no settings records");
        });
        run("context-files-replaced-during-resolution-rejected",()->{
            Tree tree=new Tree("replacement");Path saved=tree.files.resolveSibling("files-original");boolean[] replaced={false};
            Os.hookEvent="BEFORE_LSTAT";Os.hookNeedle=tree.files.toString();
            Os.hook=()->{try{Files.move(tree.files,saved);directory(tree.files);replaced[0]=true;}
                catch(Exception error){throw new IllegalStateException(error);}};
            reject(()->tree.canonical());check(replaced[0],"real original directory was replaced after its first lstat");
            check(Arrays.equals(ORIGINAL,Files.readAllBytes(saved.resolve("model/runtime-config.json"))),"original config bytes preserved");
            check(!Files.exists(tree.files.resolve("runtime-settings")),"replacement is not used for settings");
        });
        run("context-files-owner-mismatch-rejected",()->{
            Tree tree=new Tree("owner");Os.uidOverridePath=tree.fromContext.toString();
            reject(()->tree.canonical());check(!Files.exists(tree.pending()),"wrong-owner root publishes no transaction");
        });
        for(String node:new String[]{"model","config","settings"}){
            final String kind=node;run("context-internal-"+kind+"-symlink-rejected",()->{
                Tree tree=new Tree(kind);File canonical=tree.canonical();
                Path path=kind.equals("model")?tree.files.resolve("model"):
                        kind.equals("config")?tree.files.resolve("model/runtime-config.json"):tree.files.resolve("runtime-settings");
                if(kind.equals("settings"))directory(path);
                Path saved=path.resolveSibling(path.getFileName()+"-original");Files.move(path,saved);Files.createSymbolicLink(path,saved);
                reject(()->RuntimeConfigTransaction.prepare(canonical,RuntimeConfigTransaction.selected(ModelProfile.LFM3.id,"gpu"),true));
                check(Arrays.equals(ORIGINAL,tree.config()),"internal alias rejection preserves configuration");
                check(!Files.exists(tree.pending()),"internal alias never publishes a pending marker");
            });
        }
        run("context-transaction-directory-symlink-rejected",()->{
            Tree tree=new Tree("transaction");RuntimeConfigTransaction tx=RuntimeConfigTransaction.prepare(tree.canonical(),RuntimeConfigTransaction.selected(ModelProfile.LFM3.id,"gpu"),true);
            byte[] pending=Files.readAllBytes(tree.pending());Path path=tx.directory.toPath(),saved=path.resolveSibling("saved-transaction");
            Files.move(path,saved);Files.createSymbolicLink(path,saved);
            reject(()->RuntimeConfigTransaction.restore(tree.canonical()));
            check(Arrays.equals(pending,Files.readAllBytes(tree.pending())),"aliased transaction leaves original marker intact");
            check(Arrays.equals(ORIGINAL,tree.config()),"aliased transaction changes no config bytes");
        });
    }
    public static void main(String[] args)throws Exception{
        output=Paths.get(args[0]);directory(output);boolean pass=false;Throwable failure=null;
        try{tests();pass=true;}catch(Throwable error){failure=error;error.printStackTrace();}
        JSONObject report=new JSONObject().put("schema","hepta.local-model-settings-context-files-host.v1")
                .put("passed",pass).put("cases",cases).put("assertions",assertions).put("case_results",rows)
                .put("real_ancestor_and_leaf_symlinks",true).put("real_directory_replacement",true)
                .put("full_production_engine_and_transaction",true).put("android_context_uid_fd_directory_fsync_surrogates",true)
                .put("phone_operations",0).put("native_model_executed",false).put("error",failure==null?JSONObject.NULL:failure.toString());
        Files.write(output.resolve("RESULT.json"),(report.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println(report.toString());if(!pass)System.exit(1);
    }
}
