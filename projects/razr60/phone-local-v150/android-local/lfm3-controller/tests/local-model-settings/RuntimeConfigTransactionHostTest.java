package org.trillionnium.hepta.local;
import android.system.Os;
import java.io.*;import java.nio.charset.StandardCharsets;import java.nio.file.*;import java.nio.file.attribute.PosixFilePermissions;import java.util.*;import java.util.concurrent.TimeUnit;
import org.json.*;
/** Executes the frozen production transaction against real host files, a pinned real org.json,
 * and explicit Android UID/FD/directory-fsync boundary adapters. Never a phone or power-loss test. */
public final class RuntimeConfigTransactionHostTest {
 private static int assertions,cases;private static Path output;private static final JSONArray rows=new JSONArray();
 private interface Work{void run()throws Exception;}
 private static final byte[] ORIGINAL=("{\n  \"threads\": 4, \"context_tokens\":8192,\n \"compute\":\"npu\", \"schema\":\"hepta.local-runtime.v1\"\n}\n").getBytes(StandardCharsets.UTF_8);
 private static final byte[] GPU=selected(ModelProfile.LFM3.id,"gpu");
 private static byte[] selected(String model,String compute){try{return RuntimeConfigTransaction.selected(model,compute);}catch(Exception e){throw new ExceptionInInitializerError(e);}}
 private static void check(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
 private static void equal(byte[] a,byte[] b,String message){check(Arrays.equals(a,b),message);}
 private static void reject(Work work)throws Exception{boolean denied=false;try{work.run();}catch(Exception expected){denied=true;}check(denied,"operation must reject");}
 private static Path fresh(String name)throws Exception{Path p=output.resolve(String.format(Locale.ROOT,"%03d-",cases)+name);Files.createDirectory(p);Files.setPosixFilePermissions(p,PosixFilePermissions.fromString("rwx------"));Path model=p.resolve("model");Files.createDirectory(model);Files.setPosixFilePermissions(model,PosixFilePermissions.fromString("rwx------"));return p;}
 private static void write(Path p,byte[] raw)throws Exception{Files.write(p,raw,StandardOpenOption.CREATE,StandardOpenOption.TRUNCATE_EXISTING);Files.setPosixFilePermissions(p,PosixFilePermissions.fromString("rw-------"));}
 private static Path config(Path files){return files.resolve("model/runtime-config.json");}
 private static Path pending(Path files){return files.resolve("runtime-settings/pending.json");}
 private static Path last(Path files){return files.resolve("runtime-settings/last.json");}
 private static long inode(Path p)throws Exception{return ((Number)Files.getAttribute(p,"unix:ino",LinkOption.NOFOLLOW_LINKS)).longValue();}
 private static byte[] pointer(String id)throws Exception{return new JSONObject().put("schema","hepta.local-model-settings-pointer.v1").put("id",id).toString().getBytes(StandardCharsets.UTF_8);}
 private static void restored(Path files,boolean exists)throws Exception{
  RuntimeConfigTransaction tx=RuntimeConfigTransaction.restore(files.toFile());
  check(tx.recoveringPending,"pending recovery path selected");
  RuntimeConfigTransaction.Snapshot s=tx.rollbackFiles();check(s.exists==exists,"restored existence exact");
  if(exists)equal(ORIGINAL,Files.readAllBytes(config(files)),"original whitespace and key order exactly restored");else check(!Files.exists(config(files)),"original absence restored");
  tx.finishRollback();check(!RuntimeConfigTransaction.pending(files.toFile()),"own pending marker cleared");
 }
 private static void run(String name,Work test)throws Exception{
  Os.reset();int before=assertions;JSONObject row=new JSONObject().put("name",name);rows.put(row);
  try{test.run();row.put("passed",true);cases++;}
  catch(Throwable failure){row.put("passed",false).put("error",failure.toString());throw failure;}
  finally{row.put("assertions",assertions-before);Os.reset();}
 }
 private static void normal()throws Exception{
  for(String model:new String[]{ModelProfile.LFM3.id,ModelProfile.LFM25_8B_A1B.id})for(String compute:new String[]{"npu","gpu"}){
   final String id=model,device=compute;
   run("selection-"+id+"-"+device,()->{byte[] raw=RuntimeConfigTransaction.selected(id,device);JSONObject j=new JSONObject(new String(raw,StandardCharsets.UTF_8));check(j.length()==5,"only fixed selection fields");
    Path f=fresh("selected");write(config(f),raw);LocalRuntimeConfig c=RuntimeConfigTransaction.decode(RuntimeConfigTransaction.current(f.toFile()));
    check(c.profile==ModelProfile.named(id)&&c.compute.equals(device)&&c.contextTokens==8192&&c.threads==4,"fixed selected runtime");
    check(c.profile.minimumAvailableBytes==(c.profile==ModelProfile.LFM3?3L:7L)<<30,"profile admission threshold preserved");});
  }
  run("allowlist-rejects-other-models-and-devices",()->{
   for(String id:new String[]{ModelProfile.MINICPM5.id,ModelProfile.GUI_OWL_4B.id,"unknown","../escape"})reject(()->RuntimeConfigTransaction.selected(id,"npu"));
   for(String device:new String[]{"cpu","auto","NPU","","https://external"})reject(()->RuntimeConfigTransaction.selected(ModelProfile.LFM3.id,device));
  });
  run("config-types-and-extra-fields-reject",()->{
   Path f=fresh("types");for(String value:new String[]{
    "{\"schema\":\"hepta.local-runtime.v2\",\"model_profile\":\"lfm3-1.7b-qad-q4_0\",\"compute\":\"npu\",\"context_tokens\":8192.0,\"threads\":4}",
    "{\"schema\":\"hepta.local-runtime.v2\",\"model_profile\":\"lfm3-1.7b-qad-q4_0\",\"compute\":\"npu\",\"context_tokens\":8192,\"threads\":\"4\"}",
    "{\"schema\":\"hepta.local-runtime.v2\",\"model_profile\":\"lfm3-1.7b-qad-q4_0\",\"compute\":\"npu\",\"context_tokens\":8192,\"threads\":4,\"external\":true}"}){
    write(config(f),value.getBytes(StandardCharsets.UTF_8));reject(()->RuntimeConfigTransaction.decode(RuntimeConfigTransaction.current(f.toFile())));
   }
  });
  run("commit-and-explicit-exact-raw-restore",()->{
   Path f=fresh("commit");write(config(f),ORIGINAL);RuntimeConfigTransaction tx=RuntimeConfigTransaction.prepare(f.toFile(),GPU,true);
   check(RuntimeConfigTransaction.pending(f.toFile()),"pending is durable before apply");equal(ORIGINAL,Files.readAllBytes(config(f)),"prepare does not change configuration");
   equal(ORIGINAL,Files.readAllBytes(tx.directory.toPath().resolve("previous.raw")),"exact raw backup");
   tx.apply();equal(GPU,Files.readAllBytes(config(f)),"apply exact selected bytes");tx.commit();
   check(!RuntimeConfigTransaction.pending(f.toFile())&&RuntimeConfigTransaction.restoreAvailable(f.toFile()),"commit clears own pending and keeps explicit restore");
   JSONObject receipt=new JSONObject(new String(Files.readAllBytes(tx.directory.toPath().resolve("committed.json")),StandardCharsets.UTF_8));
   check(!receipt.getBoolean("inference_executed")&&!receipt.getBoolean("backend_qualified"),"saving never claims inference");
   RuntimeConfigTransaction back=RuntimeConfigTransaction.restore(f.toFile());check(!back.recoveringPending,"completed restore creates a new transaction");
   back.apply();back.commit();equal(ORIGINAL,Files.readAllBytes(config(f)),"restored original raw exactly");
  });
  run("original-absence-restored",()->{
   Path f=fresh("absent");RuntimeConfigTransaction tx=RuntimeConfigTransaction.prepare(f.toFile(),GPU,true);tx.apply();tx.commit();
   RuntimeConfigTransaction back=RuntimeConfigTransaction.restore(f.toFile());check(!back.target().exists,"target preserves original absence");back.apply();back.commit();check(!Files.exists(config(f)),"absent configuration removed legitimately");
  });
  run("pending-apply-crash-restores-original",()->{
   Path f=fresh("pending");write(config(f),ORIGINAL);RuntimeConfigTransaction tx=RuntimeConfigTransaction.prepare(f.toFile(),GPU,true);tx.apply();restored(f,true);
  });
  run("pending-before-apply-restores-without-config-replacement",()->{
   Path f=fresh("prepared");write(config(f),ORIGINAL);long prior=inode(config(f));RuntimeConfigTransaction.prepare(f.toFile(),GPU,true);restored(f,true);check(inode(config(f))==prior,"unchanged original inode when no config write was necessary");
  });
  run("retained-after-commit-pending-can-rollback-own-index",()->{
   Path f=fresh("own-index");write(config(f),ORIGINAL);RuntimeConfigTransaction tx=RuntimeConfigTransaction.prepare(f.toFile(),GPU,true);tx.apply();tx.commit();tx.retainPending();restored(f,true);check(!Files.exists(last(f)),"own half-commit index restored to previous absence");
  });
  run("prior-last-bytes-restored-across-second-transaction",()->{
   Path f=fresh("old-index");write(config(f),ORIGINAL);RuntimeConfigTransaction first=RuntimeConfigTransaction.prepare(f.toFile(),GPU,true);first.apply();first.commit();
   byte[] oldIndex=Files.readAllBytes(last(f));byte[] selected=selected(ModelProfile.LFM25_8B_A1B.id,"npu");
   RuntimeConfigTransaction second=RuntimeConfigTransaction.prepare(f.toFile(),selected,true);second.apply();second.commit();second.retainPending();
   RuntimeConfigTransaction recover=RuntimeConfigTransaction.restore(f.toFile());recover.rollbackFiles();recover.finishRollback();
   equal(GPU,Files.readAllBytes(config(f)),"prior committed config restored");equal(oldIndex,Files.readAllBytes(last(f)),"prior last pointer exact bytes restored");
  });
  for(String kind:new String[]{"foreign","bad-json","read-io"}){
   final String variant=kind;run("foreign-last-before-any-config-write-"+kind,()->{
    Path f=fresh(variant);write(config(f),ORIGINAL);RuntimeConfigTransaction tx=RuntimeConfigTransaction.prepare(f.toFile(),GPU,true);tx.apply();
    if(variant.equals("foreign"))write(last(f),pointer("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));else if(variant.equals("bad-json"))write(last(f),"{".getBytes(StandardCharsets.UTF_8));
    else {write(last(f),pointer(tx.id));Os.fail("BEFORE_OPEN","last.json",1,false);}
    byte[] raw=Files.readAllBytes(config(f));long originalInode=inode(config(f));reject(()->tx.rollbackFiles());
    equal(raw,Files.readAllBytes(config(f)),"foreign index rejection changes no configuration byte");check(inode(config(f))==originalInode,"foreign index rejection changes no config inode");
    check(Files.exists(pending(f)),"uncertain transaction remains pending");if(variant.equals("read-io"))check(Os.triggered,"actual IO failure was injected");
   });
  }
  run("foreign-config-not-overwritten",()->{
   Path f=fresh("foreign-config");write(config(f),ORIGINAL);RuntimeConfigTransaction tx=RuntimeConfigTransaction.prepare(f.toFile(),GPU,true);tx.apply();
   byte[] foreign=selected(ModelProfile.LFM25_8B_A1B.id,"gpu");write(config(f),foreign);long before=inode(config(f));
   reject(()->tx.rollbackFiles());equal(foreign,Files.readAllBytes(config(f)),"foreign config raw preserved");check(inode(config(f))==before,"foreign config inode preserved");
  });
  run("foreign-pending-not-overwritten",()->{
   Path f=fresh("foreign-pending");write(config(f),ORIGINAL);RuntimeConfigTransaction tx=RuntimeConfigTransaction.prepare(f.toFile(),GPU,true);
   byte[] foreign=pointer("cccccccccccccccccccccccccccccccc");write(pending(f),foreign);
   reject(()->tx.retainPending());reject(()->tx.apply());equal(foreign,Files.readAllBytes(pending(f)),"foreign pending raw preserved");equal(ORIGINAL,Files.readAllBytes(config(f)),"no configuration modification");
  });
  run("pending-race-before-atomic-publication-rejects",()->{
   final Path f=fresh("publication-race");write(config(f),ORIGINAL);final byte[] foreign=pointer("dddddddddddddddddddddddddddddddd");
   Os.hookEvent="AFTER_FSYNC";Os.hookNeedle="pending-";Os.hook=()->{try{write(pending(f),foreign);}catch(Exception e){throw new RuntimeException(e);}};
   reject(()->RuntimeConfigTransaction.prepare(f.toFile(),GPU,true));
   equal(foreign,Files.readAllBytes(pending(f)),"appeared foreign marker never replaced");equal(ORIGINAL,Files.readAllBytes(config(f)),"no config write after marker race");
  });
  run("corrupt-original-backup-rejects-recovery",()->{
   Path f=fresh("corrupt-backup");write(config(f),ORIGINAL);RuntimeConfigTransaction tx=RuntimeConfigTransaction.prepare(f.toFile(),GPU,true);tx.apply();
   write(tx.directory.toPath().resolve("previous.raw"),"changed".getBytes(StandardCharsets.UTF_8));
   reject(()->RuntimeConfigTransaction.restore(f.toFile()));equal(GPU,Files.readAllBytes(config(f)),"corrupt backup never applied");check(Files.exists(pending(f)),"marker retained");
  });
  for(String type:new String[]{"symlink","hardlink","mode","owner"}){
   final String kind=type;run("private-config-"+type+"-rejected",()->{
    Path f=fresh(kind);write(config(f),ORIGINAL);
    if(kind.equals("symlink")){Path original=f.resolve("owned-original");Files.move(config(f),original);Files.createSymbolicLink(config(f),original);}
    if(kind.equals("hardlink"))Files.createLink(f.resolve("second-link"),config(f));
    if(kind.equals("mode"))Os.chmod(config(f).toString(),0644);
    if(kind.equals("owner"))Os.uidOverridePath=config(f).toString();
    reject(()->RuntimeConfigTransaction.prepare(f.toFile(),GPU,true));check(!Files.exists(pending(f)),"invalid private input never publishes pending");
   });
  }
  run("duplicate-selection-rejected-without-marker",()->{Path f=fresh("duplicate");write(config(f),GPU);reject(()->RuntimeConfigTransaction.prepare(f.toFile(),GPU,true));check(!Files.exists(pending(f)),"duplicate has no transaction marker");});
  run("delete-false-does-not-claim-absence",()->{
   Path f=fresh("delete-false");RuntimeConfigTransaction tx=RuntimeConfigTransaction.prepare(f.toFile(),GPU,true);tx.apply();
   Os.chmod(f.resolve("model").toString(),0500);try{reject(()->tx.rollbackFiles());equal(GPU,Files.readAllBytes(config(f)),"failed delete preserves selected file");check(Files.exists(pending(f)),"failed delete remains pending");}
   finally{Os.chmod(f.resolve("model").toString(),0700);}restored(f,false);
  });
 }
 private static void injectedApply()throws Exception{
  for(String event:new String[]{"AFTER_CREATE","PARTIAL_WRITE","BEFORE_FSYNC","AFTER_FSYNC","BEFORE_RENAME","AFTER_RENAME","AFTER_READ"}){
   final String operation=event;run("apply-io-failure-"+event,()->{
    Path f=fresh("apply-"+operation);write(config(f),ORIGINAL);RuntimeConfigTransaction tx=RuntimeConfigTransaction.prepare(f.toFile(),GPU,true);
    String needle=operation.contains("RENAME")||operation.equals("AFTER_READ")?"runtime-config.json":"-apply.new";
    Os.fail(operation,needle,1,false);reject(()->tx.apply());check(Os.triggered,"actual apply IO stage hit");Os.reset();restored(f,true);
   });
  }
  for(String event:new String[]{"PARTIAL_WRITE","BEFORE_FSYNC","AFTER_FSYNC"}){
   final String operation=event;run("commit-record-io-failure-"+event,()->{
    Path f=fresh("commit-"+operation);write(config(f),ORIGINAL);RuntimeConfigTransaction tx=RuntimeConfigTransaction.prepare(f.toFile(),GPU,true);tx.apply();
    Os.fail(operation,"committed.json",1,false);reject(()->tx.commit());check(Os.triggered,"actual commit IO stage hit");Os.reset();restored(f,true);
   });
  }
  run("index-rename-failure-after-publication-rolls-back",()->{
   Path f=fresh("index-rename");write(config(f),ORIGINAL);RuntimeConfigTransaction tx=RuntimeConfigTransaction.prepare(f.toFile(),GPU,true);tx.apply();
   Os.fail("AFTER_RENAME","last.json",1,false);reject(()->tx.commit());check(Os.triggered,"index was published then injected failure");Os.reset();restored(f,true);check(!Files.exists(last(f)),"own new index removed");
  });
  run("retained-pointer-partial-write-never-publishes",()->{
   Path f=fresh("retain");write(config(f),ORIGINAL);RuntimeConfigTransaction tx=RuntimeConfigTransaction.prepare(f.toFile(),GPU,true);tx.apply();tx.commit();
   Os.fail("PARTIAL_WRITE","pending-",1,false);reject(()->tx.retainPending());check(Os.triggered,"retain temp write actually interrupted");check(!Files.exists(pending(f)),"partial retain temp is never startup marker");Os.reset();
   tx.retainPending();restored(f,true);
  });
 }
 private static void crashMatrix()throws Exception{
  for(String event:new String[]{"AFTER_CREATE","PARTIAL_WRITE","BEFORE_FSYNC","AFTER_FSYNC","BEFORE_RENAME","AFTER_RENAME"}){
   final String operation=event;run("actual-child-halt-pending-"+event,()->{
    Path f=fresh("crash-"+operation);write(config(f),ORIGINAL);
    List<String> argv=Arrays.asList(System.getProperty("java.home")+"/bin/java","-Dhepta.fixture.host_uid="+System.getProperty("hepta.fixture.host_uid"),"-cp",System.getProperty("java.class.path"),RuntimeConfigTransactionHostTest.class.getName(),"crash",f.toString(),operation);
    Path log=f.resolve("child.stdout"),err=f.resolve("child.stderr");Process p=new ProcessBuilder(argv).redirectOutput(log.toFile()).redirectError(err.toFile()).start();
    check(p.waitFor(15,TimeUnit.SECONDS),"host crash child terminated");check(p.exitValue()==86,"child reached the exact Runtime.halt fault boundary");
    equal(ORIGINAL,Files.readAllBytes(config(f)),"prepare crash never changed original config");
    boolean published=Files.exists(pending(f));check(published==operation.equals("AFTER_RENAME"),"only complete atomic publication exposes marker");
    if(published){JSONObject pointer=new JSONObject(new String(Files.readAllBytes(pending(f)),StandardCharsets.UTF_8));check(pointer.length()==2&&pointer.getString("id").matches("[0-9a-f]{32}"),"published marker remains complete typed JSON");restored(f,true);}
   });
  }
 }
 public static void main(String[] args)throws Exception{
  if(args.length==3&&args[0].equals("crash")){
   Path files=Paths.get(args[1]);String event=args[2];Os.fail(event,event.contains("RENAME")?"pending.json":"pending-",1,true);RuntimeConfigTransaction.prepare(files.toFile(),GPU,true);throw new AssertionError("fault not reached");
  }
  output=Paths.get(args[0]);Files.createDirectory(output);boolean pass=false;Throwable error=null;
  try{normal();injectedApply();crashMatrix();pass=true;}
  catch(Throwable failure){error=failure;failure.printStackTrace();}
  JSONObject report=new JSONObject().put("schema","hepta.local-model-settings-transaction-host.v1").put("passed",pass).put("cases",cases).put("assertions",assertions).put("case_results",rows)
    .put("actual_production_transaction",true).put("actual_production_private_file_io",true).put("real_temp_files",true).put("real_file_fsync_and_atomic_rename",true)
    .put("directory_fsync_surrogate",true).put("android_uid_and_fd_metadata_surrogates",true).put("real_host_process_halt",true).put("android_power_loss_durability_verified",false)
    .put("phone_operations",0).put("native_model_executed",false).put("error",error==null?JSONObject.NULL:error.toString());
  Files.write(output.resolve("RESULT.json"),(report.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
  System.out.println(report.toString());if(!pass)System.exit(1);
 }
}
