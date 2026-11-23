package org.trillionnium.hepta.local;

import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;
import java.util.concurrent.atomic.AtomicBoolean;

/** Application-owned offline import; a document picker never supplies a model identity or destination. */
final class LocalModelImport implements AutoCloseable {
    interface Listener {void onLocalModelImportChanged();}
    interface InputSource {InputStream open(Uri uri)throws Exception;}
    private final LocalProbeApplication app;
    private final LocalModelEngine engine;
    private final Handler main=new Handler(Looper.getMainLooper());
    private final ExecutorService worker;
    private final InputSource source;
    private WeakReference<Listener> listener=new WeakReference<Listener>(null);
    private volatile Request active;
    private volatile boolean closed;
    private volatile String state="选择手机中的模型文件，导入后离线使用。";
    private static final class Request {
        final LocalModelImportAsset asset;final Uri uri;
        final LocalModelEngine.SettingsReservation lease;
        final HeptaAccessibilityService service;
        final AtomicBoolean cancelled=new AtomicBoolean();
        Request(LocalModelImportAsset asset,Uri uri,LocalModelEngine.SettingsReservation lease,HeptaAccessibilityService service){
            this.asset=asset;this.uri=uri;this.lease=lease;this.service=service;
        }
    }
    LocalModelImport(LocalProbeApplication app,LocalModelEngine engine){
        this(app,engine,uri->app.getContentResolver().openInputStream(uri),Executors.newSingleThreadExecutor());
    }
    /** Test seam controls only the read-only document source and serial executor. */
    LocalModelImport(LocalProbeApplication app,LocalModelEngine engine,InputSource source,ExecutorService worker){
        this.app=app;this.engine=engine;this.source=source;this.worker=worker;
        try{if(LocalModelImportFile.pending(RuntimeConfigTransaction.contextFiles(app)))
            state="上次导入未完成。重新选择文件后会先清理本次导入的临时文件，已有模型会保留。";}
        catch(Exception unknown){state="上次导入记录需要核验；选择文件后会先检查，已有模型会保留。";}
    }
    void bind(Listener value){listener=new WeakReference<Listener>(value);publish();}
    void unbind(Listener value){if(listener.get()==value)listener.clear();}
    boolean isBusy(){return active!=null;}
    String state(){return state;}
    private void mainOnly(){if(Looper.myLooper()!=Looper.getMainLooper())throw new IllegalStateException("模型导入须由手机界面发起");}
    private void publish(){Listener value=listener.get();if(value!=null)try{value.onLocalModelImportChanged();}catch(RuntimeException ignored){/* UI owns no file or reservation. */}}
    void start(String assetId,Uri uri)throws Exception{
        mainOnly();
        if(closed||active!=null)throw new IllegalStateException("已有模型文件正在导入");
        if(uri==null||!"content".equals(uri.getScheme()))throw new IllegalArgumentException("请选择手机文件管理器中的文件");
        LocalModelImportAsset asset=LocalModelImportAsset.named(assetId);
        HeptaAccessibilityService service=HeptaAccessibilityService.connected();
        app.requireModelImportIdle(service);
        LocalModelEngine.SettingsReservation lease=engine.reserveSettings(false);
        if(lease.previous.source==null){engine.finishSettings(lease,true);throw new IllegalStateException("请先修复本地模型配置，再导入文件");}
        Request request=new Request(asset,uri,lease,service);active=request;
        state="正在读取并核验 "+asset.label+"…";publish();
        try{worker.execute(()->perform(request));}
        catch(RuntimeException rejected){
            engine.finishSettings(lease,true);active=null;state="导入未开始，请重新选择文件。";publish();throw rejected;
        }
    }
    void cancel(){
        mainOnly();Request request=active;if(request==null)return;
        request.cancelled.set(true);
        // A provider's open/read/close can block. Cancellation never releases the slot,
        // deletes a file being written, or pretends that interrupted I/O has stopped.
        state="正在取消导入，等待文件读取结束并清理临时文件…";publish();
    }
    private <T>T onMain(Callable<T> work)throws Exception{
        FutureTask<T> callback=new FutureTask<T>(work);
        if(!main.post(callback))throw new IOException("导入完成回调未送达");
        boolean interrupted=false;
        try{for(;;)try{return callback.get();}catch(InterruptedException retry){interrupted=true;}}
        finally{if(interrupted)Thread.currentThread().interrupt();}
    }
    private void requireOwner(Request request)throws Exception{
        ModelImportStream.check(()->closed||request.cancelled.get());
        request.lease.requireOwned();
        onMain(()->{
            if(closed||active!=request)throw new IOException("本次导入已结束");
            app.requireModelImportIdle(request.service);request.lease.requireOwned();return null;
        });
    }
    private void quiet(List<RecoveryQuiescence.Sample> samples)throws Exception{
        app.taskSession().requireModelSettingsJournalIdle();
        if(samples.isEmpty())samples.addAll(RecoveryProcessInventory.awaitInitial(app));
        else{samples.add(RecoveryProcessInventory.capture(app));RecoveryQuiescence.confirm(samples,android.os.Process.myUid(),android.os.Process.myPid());}
        app.taskSession().requireModelSettingsJournalIdle();
    }
    private void perform(Request request){
        LocalModelImportFile.Stage stage=null;boolean storageKnown=false;String message;
        List<RecoveryQuiescence.Sample> samples=new ArrayList<RecoveryQuiescence.Sample>();
        try{
            requireOwner(request);quiet(samples);
            File files=RuntimeConfigTransaction.contextFiles(app);
            LocalModelImportFile.recover(files,id->LocalModelImportAsset.named(id).pin);
            requireOwner(request);
            ModelImportStream.Cancellation cancelled=()->closed||request.cancelled.get();
            if(LocalModelImportFile.ready(files,request.asset.pin,cancelled)){
                message=request.asset.label+" 已就绪，保留已有文件。";
            }else{
                stage=LocalModelImportFile.begin(files,request.asset.pin);
                final long[] lastUpdate={0};
                // Keep the same request/lease even if the provider never returns.
                try(InputStream input=source.open(request.uri)){
                    if(input==null)throw new IOException("无法读取所选文件");
                    ModelImportStream.check(cancelled);
                    stage.copy(input,cancelled,(copied,total)->{
                        long now=SystemClock.elapsedRealtime();
                        if(now-lastUpdate[0]<500&&copied!=total)return;
                        lastUpdate[0]=now;
                        final long percent=copied*100/total;
                        main.post(()->{if(active==request&&!request.cancelled.get()){
                            state="正在导入 "+request.asset.label+" · "+percent+"%";publish();
                        }});
                    });
                }
                // Input is closed and the fixed-size hash has passed before any publication.
                requireOwner(request);quiet(samples);request.lease.previous.source.unchanged();
                stage.publish(cancelled);
                message=request.asset.label+" 已就绪。可在“本地模型设置”中选择使用。";
            }
            request.lease.previous.source.unchanged();storageKnown=true;
        }catch(Exception failure){
            message=failure instanceof ModelImportStream.Cancelled?"已取消导入，已有模型保持可用。"
                    :"导入未完成："+HeptaAccessibilityService.message(failure);
            try{
                if(stage!=null)stage.abort();
                File files=RuntimeConfigTransaction.contextFiles(app);
                if(LocalModelImportFile.pending(files))throw new IOException("导入临时文件或记录尚未清理");
                request.lease.previous.source.unchanged();storageKnown=true;
            }catch(Exception cleanup){message+="；临时文件清理尚未确认，任务继续暂停。";}
        }
        final boolean known=storageKnown;final String result=message;
        if(!known){state=result;main.post(this::publish);return;}
        try{onMain(()->{
            if(active!=request)throw new IOException("导入会话身份已变化");
            engine.finishSettings(request.lease,true);active=null;state=result;publish();return null;
        });}catch(Exception unknown){state=result+" 完成回调尚未确认，任务继续暂停。";main.post(this::publish);}
    }
    @Override public void close(){closed=true;Request request=active;if(request!=null)request.cancelled.set(true);worker.shutdown();}
}

