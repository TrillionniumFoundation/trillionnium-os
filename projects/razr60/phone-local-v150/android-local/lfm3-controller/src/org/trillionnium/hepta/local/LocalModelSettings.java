package org.trillionnium.hepta.local;

import android.os.Handler;
import android.os.Looper;
import java.io.File;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;

/** Ordinary owner settings only: no inference, navigation, task recovery or external runtime. */
final class LocalModelSettings implements AutoCloseable {
    interface Listener {void onLocalModelSettingsChanged();}
    private final LocalProbeApplication app;
    private final LocalModelEngine engine;
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private final Handler main=new Handler(Looper.getMainLooper());
    private WeakReference<Listener> listener=new WeakReference<Listener>(null);
    private volatile boolean active,closed,restoreAvailable;
    private volatile String state="LFM3：QAD Q4_0，启动门槛 3 GiB 可用内存。8B MoE：Q4_0，启动门槛 7 GiB（实验）。均为 8192 上下文、4 线程；门槛不是实测峰值。";
    LocalModelSettings(LocalProbeApplication app,LocalModelEngine engine){
        this.app=app;this.engine=engine;refreshRestore();
        if(engine.settingsBlocked())state="上次模型设置未完成。新推理已暂停；空闲后可恢复上次配置。";
    }
    void bind(Listener value){listener=new WeakReference<Listener>(value);publish();}
    void unbind(Listener value){if(listener.get()==value)listener.clear();}
    boolean isBusy(){return active;}
    boolean restoreAvailable(){return restoreAvailable;}
    String state(){return state;}
    private void refreshRestore(){
        try{restoreAvailable=RuntimeConfigTransaction.restoreAvailable(app.getFilesDir());}
        catch(Exception unknown){restoreAvailable=true;}
    }
    private void publish(){
        Listener value=listener.get();
        if(value!=null)try{value.onLocalModelSettingsChanged();}catch(RuntimeException ignored){/* UI cannot release the slot. */}
    }
    private void mainOnly(){
        if(Looper.myLooper()!=Looper.getMainLooper())throw new IllegalStateException("model settings require ordinary main-thread UI");
    }
    void start(String profile,String compute,boolean restore)throws Exception{
        mainOnly();
        if(closed||active)throw new IllegalStateException("已有模型设置正在处理");
        final byte[] selected=restore?null:RuntimeConfigTransaction.selected(profile,compute);
        final HeptaAccessibilityService service=HeptaAccessibilityService.connected();
        app.requireModelSettingsIdle(service);
        final LocalModelEngine.SettingsReservation lease=engine.reserveSettings(restore);
        active=true;state=restore?"正在核验空闲状态并恢复上次模型配置……":"正在核验空闲状态、可用内存与完整模型文件……";publish();
        try{worker.execute(()->perform(lease,service,selected,restore));}
        catch(RuntimeException rejected){
            active=false;engine.finishSettings(lease,!engine.settingsBlocked());
            state="模型设置未开始："+HeptaAccessibilityService.message(rejected);publish();throw rejected;
        }
    }
    private <T>T onMain(Callable<T> work)throws Exception{
        FutureTask<T> task=new FutureTask<T>(work);
        if(!main.post(task))throw new IOException("main-thread settings callback was not accepted");
        // Losing the actual callback never releases the reservation or assumes it executed.
        boolean interrupted=false;
        try{
            for(;;)try{return task.get();}catch(InterruptedException wait){interrupted=true;}
        }finally{if(interrupted)Thread.currentThread().interrupt();}
    }
    private void requireOwner(LocalModelEngine.SettingsReservation lease,HeptaAccessibilityService service)throws Exception{
        lease.requireOwned();
        onMain(()->{if(closed)throw new IOException("settings owner closed");app.requireModelSettingsIdle(service);lease.requireOwned();return null;});
    }
    private void requireJournals()throws Exception{app.taskSession().requireModelSettingsJournalIdle();}
    private void quiet(List<RecoveryQuiescence.Sample> samples)throws Exception{
        requireJournals();
        if(samples.isEmpty())samples.addAll(RecoveryProcessInventory.awaitInitial(app));
        else{
            samples.add(RecoveryProcessInventory.capture(app));
            RecoveryQuiescence.confirm(samples,android.os.Process.myUid(),android.os.Process.myPid());
        }
        requireJournals();
    }
    private void perform(LocalModelEngine.SettingsReservation lease,HeptaAccessibilityService service,byte[] selected,boolean restore){
        RuntimeConfigTransaction transaction=null;boolean committed=false;
        List<RecoveryQuiescence.Sample> samples=new ArrayList<RecoveryQuiescence.Sample>();
        String message;
        try{
            requireOwner(lease,service);quiet(samples);
            transaction=restore?RuntimeConfigTransaction.restore(app.getFilesDir()):
                    RuntimeConfigTransaction.prepare(app.getFilesDir(),selected,true);
            LocalRuntimeConfig target=RuntimeConfigTransaction.decode(transaction.target());
            ModelFileVerifier verifier=engine.verifySettingsModel(lease,target);
            requireOwner(lease,service);quiet(samples);
            RuntimeConfigTransaction.Snapshot applied=transaction.recoveringPending?transaction.rollbackFiles():transaction.apply();
            LocalModelEngine.RuntimeGeneration next=LocalModelEngine.generation(applied,verifier);
            requireOwner(lease,service);quiet(samples);applied.unchanged();
            onMain(()->{app.requireModelSettingsIdle(service);engine.publishSettings(lease,next);return null;});
            if(transaction.recoveringPending)transaction.finishRollback();else transaction.commit();
            committed=true;
            message=(restore?"已恢复上次配置。":"已保存本地模型配置。")+"下一次请求使用 "+target.profile.displayName
                    +" / "+("npu".equals(target.compute)?"Hexagon NPU":"Adreno GPU")
                    +"。本次没有运行推理；速度和应用操作仍需实际验证。";
            final String success=message;
            onMain(()->{engine.finishSettings(lease,true);active=false;refreshRestore();state=success;publish();return null;});
            return;
        }catch(Exception failure){
            message="模型设置未完成："+HeptaAccessibilityService.message(failure);
            if(committed){
                // Re-establish the durable pending marker before any attempted exact rollback.
                try{final RuntimeConfigTransaction tx=transaction;tx.retainPending();}
                catch(Exception retention){message+="；设置记录仍需人工核验。";}
            }
            boolean restored=false;
            try{
                if(transaction!=null){
                    transaction.retainPending();requireOwner(lease,service);
                    List<RecoveryQuiescence.Sample> rollbackSamples=new ArrayList<RecoveryQuiescence.Sample>();quiet(rollbackSamples);
                    RuntimeConfigTransaction.Snapshot original=transaction.rollbackFiles();
                    LocalModelEngine.RuntimeGeneration prior=LocalModelEngine.generation(original,new ModelFileVerifier());
                    original.unchanged();
                    onMain(()->{app.requireModelSettingsIdle(service);engine.publishSettings(lease,prior);return null;});
                    transaction.finishRollback();restored=true;
                }else if(lease.previous.source!=null&&!RuntimeConfigTransaction.pending(app.getFilesDir())){
                    lease.previous.source.unchanged();restored=true;
                }
            }catch(Exception rollback){message+="；原配置恢复尚未确认："+HeptaAccessibilityService.message(rollback);}
            final boolean exact=restored;
            final String result=message+(exact?"。已保留或恢复原始配置，未启动任何推理。":"。新推理继续暂停；原始配置与待恢复记录保留。");
            try{onMain(()->{engine.finishSettings(lease,exact);active=false;refreshRestore();state=result;publish();return null;});}
            catch(Exception unknown){
                // The shared slot remains occupied when ownership or callback completion cannot be established.
                state=result+" 设置完成回调未确认。";
            }
        }
    }
    @Override public void close(){closed=true;worker.shutdown();}
}
