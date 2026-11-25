package org.trillionnium.hepta.local;

import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.system.Os;
import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.BooleanSupplier;
import org.json.*;

public final class OfflineModelImportHostTest {
    private static int cases,assertions;private static Path output;
    private static final JSONArray rows=new JSONArray();
    private static final byte[] DATA=new byte[197321];
    private static final byte[] OLD="existing-good-model-must-remain-readable".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    private static final ModelImportStream.Cancellation LIVE=()->false;
    private interface Work {void run()throws Exception;}
    private static void check(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    private static void reject(Work work)throws Exception{
        boolean refused=false;try{work.run();}catch(Exception expected){refused=true;}
        check(refused,"operation should refuse");
    }
    private static String sha(byte[] value)throws Exception{
        StringBuilder text=new StringBuilder();for(byte b:MessageDigest.getInstance("SHA-256").digest(value))text.append(String.format(Locale.ROOT,"%02x",b&255));return text.toString();
    }
    private static Path fresh(String name)throws Exception{
        Path files=output.resolve(String.format(Locale.ROOT,"%03d-",cases)+name);Files.createDirectory(files);
        Files.setPosixFilePermissions(files,PosixFilePermissions.fromString("rwx------"));
        Path model=Files.createDirectory(files.resolve("model"));Files.setPosixFilePermissions(model,PosixFilePermissions.fromString("rwx------"));
        write(model.resolve("old-good.gguf"),OLD);return files;
    }
    private static void write(Path path,byte[] value)throws Exception{
        Files.write(path,value,StandardOpenOption.CREATE_NEW);Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rw-------"));
    }
    private static long inode(Path path)throws Exception{return ((Number)Files.getAttribute(path,"unix:ino",LinkOption.NOFOLLOW_LINKS)).longValue();}
    private static LocalModelImportFile.Pin pin()throws Exception{return new LocalModelImportFile.Pin("fixture/model","model","fixture.gguf",DATA.length,sha(DATA));}
    private static void unchangedOld(Path files)throws Exception{check(Arrays.equals(OLD,Files.readAllBytes(files.resolve("model/old-good.gguf"))),"existing good model remains readable and unchanged");}
    private static void clean(Path files)throws Exception{
        check(!LocalModelImportFile.pending(files.toFile()),"pending marker absent");
        try(java.util.stream.Stream<Path> paths=Files.list(files.resolve("model"))){
            check(paths.noneMatch(x->x.getFileName().toString().startsWith(".hepta-import-")),"no partial remains");
        }
        unchangedOld(files);
    }
    private static LocalModelImportFile.Stage copied(Path files)throws Exception{
        LocalModelImportFile.Stage stage=LocalModelImportFile.begin(files.toFile(),pin());
        stage.copy(new ByteArrayInputStream(DATA),LIVE,null);return stage;
    }
    private static void run(String name,Work body)throws Exception{
        Os.reset();Handler.reset();Looper.resetMain();LocalProbeApplication.permissionBlocked=false;HeptaAccessibilityService.current=null;
        int prior=assertions;JSONObject row=new JSONObject().put("name",name);rows.put(row);
        try{body.run();cases++;row.put("passed",true);}catch(Throwable failure){row.put("passed",false).put("error",failure.toString());throw failure;}
        finally{row.put("assertions",assertions-prior);Os.reset();}
    }
    private static void pump(BooleanSupplier done)throws Exception{
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(8);
        while(!done.getAsBoolean()){
            Handler.drain();if(System.nanoTime()>deadline)throw new AssertionError("host worker did not reach expected state");Thread.sleep(2);
        }Handler.drain();
    }
    private static void pauses()throws Exception{
        long until=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(60);
        while(System.nanoTime()<until){Handler.drain();Thread.sleep(2);}
    }
    private static void await(CountDownLatch value)throws IOException{
        try{if(!value.await(8,TimeUnit.SECONDS))throw new IOException("host fixture release timed out");}
        catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new IOException(interrupted);}
    }
    private static void busyRejects(LocalModelEngine engine)throws Exception{
        check(engine.isBusy(),"real shared Engine process slot is occupied");
        reject(()->engine.start(new LocalModelEngine.Request("42",null,null,8,1000),r->{}));
        reject(()->engine.beginWarmTask("11111111111111111111111111111111"));
        reject(()->engine.reserveExternal("22222222222222222222222222222222"));
        reject(()->engine.reserveSettings(false));
    }
    private static final class Session implements AutoCloseable {
        final LocalProbeApplication app;final LocalModelEngine engine;final LocalModelImport importer;
        Session(Path files,LocalModelImport.InputSource input){
            app=new LocalProbeApplication(files.toFile());engine=new LocalModelEngine(app);
            importer=new LocalModelImport(app,engine,input,Executors.newSingleThreadExecutor());
        }
        void start()throws Exception{importer.start(ModelProfile.LFM3.id+"/model",Uri.parse("content://fixture/local-model"));}
        public void close(){importer.close();engine.close();}
    }
    private static void streamCases()throws Exception{
        run("bounded-stream-exact-bytes-and-sha",()->{
            AtomicInteger maximum=new AtomicInteger();ByteArrayOutputStream out=new ByteArrayOutputStream();
            InputStream input=new ByteArrayInputStream(DATA){@Override public synchronized int read(byte[] b,int off,int len){maximum.set(Math.max(maximum.get(),len));return super.read(b,off,len);}};
            ModelImportStream.copy(input,out,DATA.length,sha(DATA),LIVE,null);
            check(Arrays.equals(DATA,out.toByteArray()),"copied bytes exact");check(maximum.get()<=65536,"buffer bounded at 64 KiB");
        });
        run("truncated-stream-refused",()->reject(()->ModelImportStream.copy(new ByteArrayInputStream(Arrays.copyOf(DATA,DATA.length-1)),new ByteArrayOutputStream(),DATA.length,sha(DATA),LIVE,null)));
        run("extra-byte-refused-without-writing-it",()->{
            ByteArrayOutputStream out=new ByteArrayOutputStream();
            reject(()->ModelImportStream.copy(new ByteArrayInputStream(Arrays.copyOf(DATA,DATA.length+1)),out,DATA.length,sha(DATA),LIVE,null));
            check(out.size()==DATA.length,"overlength byte never written");
        });
        run("wrong-sha-refused",()->reject(()->ModelImportStream.copy(new ByteArrayInputStream(DATA),new ByteArrayOutputStream(),DATA.length,sha(OLD),LIVE,null)));
        run("zero-read-provider-refused",()->reject(()->ModelImportStream.copy(new InputStream(){public int read(){return 0;}public int read(byte[] b,int off,int len){return 0;}},new ByteArrayOutputStream(),DATA.length,sha(DATA),LIVE,null)));
        run("length-over-int-keeps-small-read",()->{
            AtomicInteger wanted=new AtomicInteger();
            reject(()->ModelImportStream.copy(new InputStream(){public int read(){return -1;}public int read(byte[] b,int off,int len){wanted.set(len);return -1;}},new ByteArrayOutputStream(),((long)Integer.MAX_VALUE)+100,sha(DATA),LIVE,null));
            check(wanted.get()==65536,"large length never becomes a giant allocation or overflow");
        });
        run("cancel-before-source-read",()->{
            AtomicInteger reads=new AtomicInteger();
            reject(()->ModelImportStream.copy(new InputStream(){public int read(){reads.incrementAndGet();return 0;}},new ByteArrayOutputStream(),1,sha(new byte[1]),()->true,null));
            check(reads.get()==0,"cancelled stream not touched");
        });
        run("cancel-after-read-before-write",()->{
            AtomicBoolean cancelled=new AtomicBoolean();ByteArrayOutputStream out=new ByteArrayOutputStream();
            InputStream input=new ByteArrayInputStream(DATA){@Override public synchronized int read(byte[] b,int off,int len){int n=super.read(b,off,len);cancelled.set(true);return n;}};
            reject(()->ModelImportStream.copy(input,out,DATA.length,sha(DATA),cancelled::get,null));
            check(out.size()==0,"cancel observed before output write");
        });
        run("source-read-error-propagates",()->reject(()->ModelImportStream.copy(new InputStream(){public int read()throws IOException{throw new IOException("source failed");}},new ByteArrayOutputStream(),1,sha(new byte[1]),LIVE,null)));
        run("destination-write-error-propagates",()->reject(()->ModelImportStream.copy(new ByteArrayInputStream(DATA),new OutputStream(){public void write(int value)throws IOException{throw new IOException("disk full");}},DATA.length,sha(DATA),LIVE,null)));
    }
    private static void fileCases()throws Exception{
        run("private-atomic-publication-and-existing-ready",()->{
            Path f=fresh("publish");LocalModelImportFile.Stage stage=copied(f);stage.publish(LIVE);Path target=f.resolve("model/fixture.gguf");
            check(Arrays.equals(DATA,Files.readAllBytes(target)),"published complete bytes");
            check(((Number)Files.getAttribute(target,"unix:nlink")).longValue()==1,"single final link");
            check(Files.getPosixFilePermissions(target).equals(PosixFilePermissions.fromString("rw-------")),"private mode 0600");
            check(LocalModelImportFile.ready(f.toFile(),pin(),LIVE),"complete existing file is verified");
            long old=inode(target);reject(()->LocalModelImportFile.begin(f.toFile(),pin()));check(inode(target)==old,"existing model inode preserved");clean(f);
        });
        run("bad-existing-model-never-replaced",()->{
            Path f=fresh("bad-existing"),target=f.resolve("model/fixture.gguf");write(target,OLD);long old=inode(target);
            reject(()->LocalModelImportFile.ready(f.toFile(),pin(),LIVE));reject(()->LocalModelImportFile.begin(f.toFile(),pin()));
            check(inode(target)==old&&Arrays.equals(OLD,Files.readAllBytes(target)),"existing bytes and inode retained");clean(f);
        });
        run("late-good-destination-arrival-never-overwritten",()->{
            Path f=fresh("arrival");LocalModelImportFile.Stage stage=copied(f);Path target=f.resolve("model/fixture.gguf");
            write(target,DATA);long old=inode(target);reject(()->stage.publish(LIVE));stage.abort();
            check(inode(target)==old&&Arrays.equals(DATA,Files.readAllBytes(target)),"newly arrived good destination preserved");clean(f);
        });
        run("private-fsync-failure-cleans-only-temporary",()->{
            Path f=fresh("fsync");LocalModelImportFile.Stage stage=LocalModelImportFile.begin(f.toFile(),pin());Os.fail("BEFORE_FSYNC",".partial",1,false);
            reject(()->stage.copy(new ByteArrayInputStream(DATA),LIVE,null));check(Os.triggered,"actual fsync fault reached");stage.abort();
            check(!Files.exists(f.resolve("model/fixture.gguf")),"unverified data never published");clean(f);
        });
        run("publish-failure-keeps-old-model-readable",()->{
            Path f=fresh("link");LocalModelImportFile.Stage stage=copied(f);Os.fail("BEFORE_LINK","fixture.gguf",1,false);
            reject(()->stage.publish(LIVE));check(Os.triggered,"publication syscall fault reached");stage.abort();
            check(!Files.exists(f.resolve("model/fixture.gguf")),"failed link leaves destination absent");clean(f);
        });
        run("post-publication-cleanup-failure-preserves-good-file",()->{
            Path f=fresh("after-link");LocalModelImportFile.Stage stage=copied(f);Os.fail("BEFORE_UNLINK",".partial",1,false);
            reject(()->stage.publish(LIVE));check(Os.triggered,"temporary unlink fault reached");stage.abort();
            check(Arrays.equals(DATA,Files.readAllBytes(f.resolve("model/fixture.gguf"))),"verified published file retained after failure");
            check(((Number)Files.getAttribute(f.resolve("model/fixture.gguf"),"unix:nlink")).longValue()==1,"later exact cleanup removes only second link");clean(f);
        });
        for(String kind:new String[]{"short","long","hash","cancel"}){
            final String variant=kind;run("failed-copy-cleans-temporary-"+kind,()->{
                Path f=fresh(variant);LocalModelImportFile.Pin selected=variant.equals("hash")?new LocalModelImportFile.Pin("fixture/model","model","fixture.gguf",DATA.length,sha(OLD)):pin();
                LocalModelImportFile.Stage stage=LocalModelImportFile.begin(f.toFile(),selected);
                byte[] bytes=variant.equals("short")?Arrays.copyOf(DATA,DATA.length-1):variant.equals("long")?Arrays.copyOf(DATA,DATA.length+1):DATA;
                AtomicBoolean cancelled=new AtomicBoolean();
                reject(()->stage.copy(new ByteArrayInputStream(bytes),cancelled::get,(copied,total)->{if(variant.equals("cancel"))cancelled.set(true);}));
                stage.abort();check(!Files.exists(f.resolve("model/fixture.gguf")),"failed copy not published");clean(f);
            });
        }
        run("interrupted-copy-marker-cleanup",()->{
            Path f=fresh("recover-copy");copied(f);LocalModelImportFile.recover(f.toFile(),id->{try{return pin();}catch(Exception e){throw new IllegalStateException(e);}});
            check(!Files.exists(f.resolve("model/fixture.gguf")),"recovery never publishes interrupted copy");clean(f);
        });
        run("interrupted-publication-keeps-good-target",()->{
            Path f=fresh("recover-link");LocalModelImportFile.Stage stage=copied(f);Path target=f.resolve("model/fixture.gguf");Files.createLink(target,stage.temporary.toPath());long old=inode(target);
            LocalModelImportFile.recover(f.toFile(),id->{try{return pin();}catch(Exception e){throw new IllegalStateException(e);}});
            check(inode(target)==old&&Arrays.equals(DATA,Files.readAllBytes(target)),"recovery retains verified target inode and data");
            check(((Number)Files.getAttribute(target,"unix:nlink")).longValue()==1,"recovery removes only exact temporary link");clean(f);
        });
        run("symlink-destination-refused",()->{
            Path f=fresh("symlink");Files.createSymbolicLink(f.resolve("model/fixture.gguf"),f.resolve("model/old-good.gguf"));
            reject(()->LocalModelImportFile.ready(f.toFile(),pin(),LIVE));reject(()->LocalModelImportFile.begin(f.toFile(),pin()));unchangedOld(f);
        });
        run("fixed-registry-matches-real-model-and-projector-pins",()->{
            check(LocalModelImportAsset.all().size()==9,"seven pinned models plus two existing projectors only");
            for(ModelProfile model:new ModelProfile[]{ModelProfile.LFM3,ModelProfile.LFM25_8B_A1B,ModelProfile.GUI_OWL_4B,ModelProfile.LFM3_VL_2B,ModelProfile.QWEN35_4B,ModelProfile.GEMMA4_E2B,ModelProfile.GEMMA4_E4B}){
                LocalModelImportFile.Pin modelPin=LocalModelImportAsset.named(model.id+"/model").pin;
                check(modelPin.filename.equals(model.fileName)&&modelPin.bytes==model.bytes&&modelPin.sha256.equals(model.sha256),"model pin from existing allowlist");
                if(model.visual()){VlmResultContract.Profile visual=VlmResultContract.named(model.id);LocalModelImportFile.Pin projector=LocalModelImportAsset.named(model.id+"/projector").pin;
                    check(projector.filename.equals(visual.projectorFilename)&&projector.bytes==visual.projectorBytes&&projector.sha256.equals(visual.projectorSha256),"projector from existing exact profile");}
            }
            reject(()->LocalModelImportAsset.named(ModelProfile.GEMMA4_E2B.id+"/projector"));
            reject(()->LocalModelImportAsset.named(ModelProfile.GEMMA4_E4B.id+"/projector"));
            reject(()->LocalModelImportAsset.named("gemma4-e2b-qat-q4_1/model"));
            reject(()->LocalModelImportAsset.named("external/model"));reject(()->new LocalModelImportFile.Pin("escape","../","bad.gguf",1,sha(OLD)));
        });
    }
    private static void sessionCases()throws Exception{
        run("absent-runtime-config-defaults-allow-owned-publication",()->{
            Path f=fresh("default-source");LocalProbeApplication app=new LocalProbeApplication(f.toFile());LocalModelEngine engine=new LocalModelEngine(app);
            try{
                check(!Files.exists(f.resolve("model/runtime-config.json")),"no configuration file was preinstalled");
                LocalRuntimeConfig config=engine.configuration();
                check(config.profile==ModelProfile.LFM3&&"npu".equals(config.compute)&&config.contextTokens==8192&&config.threads==4,"factory defaults select existing LFM3 NPU profile");
                LocalModelEngine.SettingsReservation lease=engine.reserveSettings(false);
                check(lease.previous.source!=null&&!lease.previous.source.exists,"default runtime retains an absence Snapshot, not null");
                lease.previous.source.unchanged();LocalModelImportFile.Stage stage=copied(f);stage.publish(LIVE);
                lease.previous.source.unchanged();engine.finishSettings(lease,true);
                check(LocalModelImportFile.ready(f.toFile(),pin(),LIVE)&&!engine.isBusy(),"verified file publishes under the real default runtime reservation");
                check(!Files.exists(f.resolve("model/runtime-config.json")),"import does not synthesize or change a configuration");clean(f);
            }finally{engine.close();}
        });
        for(String boundary:new String[]{"open","read","close"}){
            final String phase=boundary;run("cancel-blocked-provider-"+boundary+"-retains-real-engine-slot",()->{
                Path f=fresh("blocked-"+phase);CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
                try(Session s=new Session(f,uri->{
                    if(phase.equals("open")){entered.countDown();await(release);return new ByteArrayInputStream(DATA);}
                    return new InputStream(){
                        public int read()throws IOException{if(phase.equals("read")){entered.countDown();await(release);return 1;}return -1;}
                        @Override public int read(byte[] b,int off,int len)throws IOException{return read();}
                        @Override public void close()throws IOException{if(phase.equals("close")){entered.countDown();await(release);}}
                    };
                })){
                    s.start();pump(()->entered.getCount()==0);busyRejects(s.engine);
                    s.importer.cancel();pauses();check(s.importer.isBusy(),"cancel did not release blocked provider");busyRejects(s.engine);
                    release.countDown();pump(()->!s.importer.isBusy());check(!s.engine.isBusy(),"completed I/O and cleanup releases slot");clean(f);
                }finally{release.countDown();}
            });
        }
        run("unfinished-task-and-background-admission-refused",()->{
            Path f=fresh("busy-owner");AtomicInteger opened=new AtomicInteger();
            try(Session s=new Session(f,uri->{opened.incrementAndGet();return new ByteArrayInputStream(DATA);})){
                s.app.taskRunning=true;reject(s::start);s.app.taskRunning=false;
                s.app.taskBlocked=true;reject(s::start);s.app.taskBlocked=false;
                s.app.backgroundLease=true;reject(s::start);s.app.backgroundLease=false;
                s.app.tasks.journalBlocked=true;s.start();pump(()->!s.importer.isBusy());
                check(opened.get()==0&&!s.engine.isBusy(),"busy or unfinished task never opens provider");clean(f);
            }
        });
        run("non-content-uri-and-unknown-asset-refused",()->{
            Path f=fresh("uri");AtomicInteger opened=new AtomicInteger();
            try(Session s=new Session(f,uri->{opened.incrementAndGet();return new ByteArrayInputStream(DATA);})){
                reject(()->s.importer.start(ModelProfile.LFM3.id+"/model",Uri.parse("file:///external/model")));
                reject(()->s.importer.start(ModelProfile.LFM3.id+"/model",Uri.parse("https://external/model")));
                reject(()->s.importer.start("caller-supplied-model",Uri.parse("content://fixture/input")));
                check(opened.get()==0&&!s.engine.isBusy(),"invalid selection obtains no process slot or file");clean(f);
            }
        });
        run("cleanup-failure-retains-real-slot-and-old-model",()->{
            Path f=fresh("cleanup-unknown");CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
            try(Session s=new Session(f,uri->new InputStream(){
                public int read()throws IOException{entered.countDown();await(release);return -1;}
                public int read(byte[] b,int off,int len)throws IOException{return read();}
            })){
                s.start();pump(()->entered.getCount()==0);Os.fail("BEFORE_UNLINK",".partial",1,false);release.countDown();
                pump(()->s.importer.state().contains("清理尚未确认"));check(Os.triggered,"actual cleanup fault occurred");
                check(s.importer.isBusy()&&LocalModelImportFile.pending(f.toFile()),"unknown cleanup retains session and durable marker");
                busyRejects(s.engine);unchangedOld(f);
            }finally{release.countDown();}
        });
    }
    public static void main(String[] args)throws Exception{
        output=Paths.get(args[0]);Files.createDirectory(output);new Random(41023).nextBytes(DATA);
        boolean passed=false;Throwable failure=null;
        try{streamCases();fileCases();sessionCases();passed=true;}catch(Throwable problem){failure=problem;}
        JSONObject result=new JSONObject().put("schema","hepta.offline-model-import-host.v1").put("passed",passed)
                .put("cases",cases).put("assertions",assertions).put("case_results",rows)
                .put("phone_operations",0).put("native_model_executed",false).put("external_model_used",false)
                .put("real_engine_slot_exercised",true).put("android_runtime",false).put("directory_fsync_is_surrogate",true);
        if(failure!=null)result.put("error",failure.toString());
        Files.write(output.resolve("RESULT.json"),result.toString(2).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        System.out.println(result.toString());if(failure!=null)failure.printStackTrace();
        System.exit(passed?0:1);
    }
}

