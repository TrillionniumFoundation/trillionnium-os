package org.trillionnium.hepta.local;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Binder;
import android.os.IBinder;
import android.os.Looper;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebEvidenceBinding;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Explicit signature Binder client. This class has no URL loading, UI action or model execution. */
final class WebEvidenceClient implements AutoCloseable {
    interface Guard { void requireCurrent(boolean cleanup)throws Exception; boolean cancelled(); }
    interface Journal {
        void request(int method,String nonce,String raw)throws Exception;
        void response(int method,String nonce,String callback,byte[] raw,boolean verified)throws Exception;
        void failure(int method,String nonce,String reason)throws Exception;
    }
    private final Context context;
    private final WebHelperIdentity controller,helper;
    private final String bindingRaw,bindingSha;
    private final Guard guard;
    private final Journal journal;
    private final ExecutorService fdReader=Executors.newSingleThreadExecutor();
    private final CountDownLatch connected=new CountDownLatch(1);
    private final Set<String> consumed=new HashSet<String>();
    private volatile IBinder peer;
    private volatile boolean bound,stopped,connectionLost;
    private volatile Rpc pending;
    // The attach callback is the helper's lifetime binder and must stay live after its one reply.
    private volatile Rpc lifetime;
    private boolean firstCapture=true;
    private String instance;
    private long epoch=-1;
    private int used;
    private final ServiceConnection connection=new ServiceConnection(){
        @Override public void onServiceConnected(ComponentName name,IBinder binder){
            try{
                if(!new ComponentName(WebEvidenceProtocol.HELPER_PACKAGE,WebEvidenceProtocol.SERVICE_CLASS).equals(name)
                        ||stopped||binder==null||!WebEvidenceProtocol.DESCRIPTOR.equals(binder.getInterfaceDescriptor()))
                    throw new IOException("unexpected evidence service binding");
                WebHelperIdentity.requirePeer(context,controller,helper);
                peer=binder;
                binder.linkToDeath(()->disconnected(),0);
            }catch(Exception refused){connectionLost=true;}
            finally{connected.countDown();}
        }
        @Override public void onServiceDisconnected(ComponentName name){disconnected();}
        @Override public void onBindingDied(ComponentName name){disconnected();}
        @Override public void onNullBinding(ComponentName name){disconnected();}
    };
    private void disconnected(){connectionLost=true;peer=null;connected.countDown();Rpc active=pending;if(active!=null)active.fail(new IOException("evidence service disconnected"));}

    WebEvidenceClient(Context context,WebHelperIdentity controller,WebHelperIdentity helper,JSONObject binding,Guard guard,Journal journal)throws Exception{
        this.context=context.getApplicationContext();this.controller=controller;this.helper=helper;this.guard=guard;this.journal=journal;
        need(guard!=null&&journal!=null,"actual guard/journal required");
        bindingRaw=WebEvidenceBinding.canonical(binding);bindingSha=WebEvidenceBinding.sha256(binding);
        controller.requireRequest(binding.getJSONObject("controller_identity"));helper.requireRequest(binding.getJSONObject("helper_identity"));
        WebHelperIdentity.requirePeer(this.context,controller,helper);
    }
    void connect(long deadline)throws Exception{
        workerOnly();need(!bound&&!stopped,"client already bound or retired");guard.requireCurrent(true);
        WebHelperIdentity.requirePeer(context,controller,helper);
        Intent intent=new Intent().setComponent(new ComponentName(WebEvidenceProtocol.HELPER_PACKAGE,WebEvidenceProtocol.SERVICE_CLASS));
        bound=context.bindService(intent,connection,Context.BIND_AUTO_CREATE);
        need(bound,"signature evidence service unavailable");
        long remain=deadline-SystemClock.elapsedRealtime();need(remain>0&&connected.await(remain,TimeUnit.MILLISECONDS),"evidence service connect deadline");
        need(!connectionLost&&peer!=null&&!stopped,"evidence service connection failed");
        WebHelperIdentity.requirePeer(context,controller,helper);
    }
    synchronized WebEvidenceReceipt attach(JSONObject originalAttach)throws Exception{
        need(lifetime==null,"attach is single use");
        JSONObject binding=WebEvidenceBinding.fromAttach(originalAttach);need(bindingSha.equals(WebEvidenceBinding.sha256(binding)),"attach binding differs");
        WebEvidenceReceipt result=call(WebEvidenceProtocol.ATTACH,originalAttach);
        need("attached".equals(result.status),"helper not attached");
        instance=result.instance;epoch=result.epoch;return result;
    }
    synchronized WebEvidenceReceipt capture(long callerDeadline)throws Exception{
        guard.requireCurrent(false);
        JSONObject request=common(WebEvidenceProtocol.CAPTURE,Math.min(callerDeadline,expiry()));
        request.put("expected_webview_instance",firstCapture?JSONObject.NULL:instance)
                .put("expected_navigation_epoch",firstCapture?JSONObject.NULL:epoch);
        // A dispatched failed read is never retried under the same nonce or null-first-capture capability.
        firstCapture=false;
        WebEvidenceReceipt result=call(WebEvidenceProtocol.CAPTURE,request);
        need(instance!=null&&instance.equals(result.instance),"helper WebView instance changed");
        need(result.epoch>=epoch,"navigation epoch went backwards");
        epoch=result.epoch;return result;
    }
    synchronized WebEvidenceReceipt closeLease(String reason,long callerDeadline)throws Exception{
        JSONObject request=common(WebEvidenceProtocol.CLOSE,callerDeadline);
        request.put("reason",reason);
        return call(WebEvidenceProtocol.CLOSE,request);
    }
    JSONObject newAttach(long callerDeadline)throws Exception{
        JSONObject binding=WebEvidenceJson.parseEvidence(bindingRaw,WebEvidenceProtocol.MAX_REQUEST_BYTES);
        JSONObject request=common(WebEvidenceProtocol.ATTACH,Math.min(callerDeadline,expiry()));
        for(String key:WebEvidenceProtocol.ATTACH_EXTRA)request.put(key,binding.get(key));
        return request;
    }
    String bindingSha(){return bindingSha;}
    String currentInstance(){return instance;}
    long currentEpoch(){return epoch;}
    private long expiry()throws Exception{return WebEvidenceJson.number(WebEvidenceJson.parseEvidence(bindingRaw,WebEvidenceProtocol.MAX_REQUEST_BYTES).getJSONObject("background"),"expires_elapsed_ms");}
    private JSONObject common(int code,long deadline)throws Exception{
        JSONObject binding=WebEvidenceJson.parseEvidence(bindingRaw,WebEvidenceProtocol.MAX_REQUEST_BYTES);
        long now=SystemClock.elapsedRealtime(),limit=Math.min(deadline,now+WebEvidenceProtocol.MAX_RPC_FUTURE_MS);
        need(limit>now,"RPC deadline exhausted");
        String nonce=UUID.randomUUID().toString().replace("-","")+UUID.randomUUID().toString().replace("-","");
        return new JSONObject().put("schema",WebEvidenceProtocol.requestSchema(code)).put("request_nonce",nonce)
                .put("task_id",binding.getString("task_id")).put("controller_session_nonce",binding.getString("controller_session_nonce"))
                .put("deadline_elapsed_ms",limit);
    }
    private WebEvidenceReceipt call(int code,JSONObject request)throws Exception{
        workerOnly();need(!stopped&&peer!=null&&!connectionLost&&pending==null,"evidence client unavailable");
        boolean cleanup=code==WebEvidenceProtocol.CLOSE;
        guard.requireCurrent(cleanup);if(!cleanup)need(!guard.cancelled(),"task cancelled");
        WebHelperIdentity.requirePeer(context,controller,helper);
        WebEvidenceJson.keys(request,WebEvidenceProtocol.requestKeys(code));
        String raw=request.toString(),nonce=WebEvidenceJson.text(request,"request_nonce");
        need(raw.getBytes(StandardCharsets.UTF_8).length<=WebEvidenceProtocol.MAX_REQUEST_BYTES&&consumed.add(nonce),"bounded unique request required");
        if(!cleanup)need(used++<WebEvidenceProtocol.MAX_REQUESTS_PER_SESSION,"task evidence request budget exhausted");
        else need(consumed.size()<=WebEvidenceProtocol.MAX_REQUESTS_PER_SESSION+WebEvidenceProtocol.MAX_CLOSE_REQUESTS_IN_WINDOW,"cleanup request budget exhausted");
        long sent=SystemClock.elapsedRealtime(),deadline=WebEvidenceJson.number(request,"deadline_elapsed_ms");
        need(deadline>sent&&deadline-sent<=WebEvidenceProtocol.MAX_RPC_FUTURE_MS,"invalid RPC deadline");
        Rpc rpc=new Rpc(code,nonce,raw,sent,deadline);pending=rpc;
        // This durable exact nonce/request precedes every possible remote method effect.
        Parcel data=Parcel.obtain();
        try{
            journal.request(code,nonce,raw);
            if(code==WebEvidenceProtocol.ATTACH)lifetime=rpc;
            guard.requireCurrent(cleanup);WebHelperIdentity.requirePeer(context,controller,helper);
            data.writeInterfaceToken(WebEvidenceProtocol.DESCRIPTOR);data.writeString(raw);data.writeStrongBinder(rpc);
            need(peer.transact(code,data,null,IBinder.FLAG_ONEWAY),"evidence transaction rejected");
            while(!rpc.done.await(Math.max(1,Math.min(100,deadline-SystemClock.elapsedRealtime())),TimeUnit.MILLISECONDS)){
                if(SystemClock.elapsedRealtime()>=deadline)throw new IOException("evidence RPC deadline exceeded");
                if(!cleanup&&guard.cancelled())throw new IOException("task cancelled during evidence capture");
                guard.requireCurrent(cleanup);
            }
            if(rpc.callbackRaw!=null)journal.response(code,nonce,rpc.callbackRaw,rpc.raw,rpc.failure==null&&rpc.result!=null);
            if(rpc.failure!=null)throw rpc.failure;
            need(rpc.result!=null,"evidence reply missing");
            guard.requireCurrent(cleanup);WebHelperIdentity.requirePeer(context,controller,helper);
            need(SystemClock.elapsedRealtime()<=deadline,"evidence reply completed too late");
            return rpc.result;
        }catch(Exception failure){
            try{journal.failure(code,nonce,HeptaAccessibilityService.message(failure));}catch(Exception durability){failure.addSuppressed(durability);}
            throw failure;
        }finally{
            rpc.retired.set(true);pending=null;data.recycle();
        }
    }
    private final class Rpc extends Binder {
        final int code;final String nonce,request;final long sent,deadline;
        final CountDownLatch done=new CountDownLatch(1);final AtomicBoolean received=new AtomicBoolean(),retired=new AtomicBoolean();
        volatile Exception failure;volatile WebEvidenceReceipt result;volatile String callbackRaw;volatile byte[] raw;
        Rpc(int code,String nonce,String request,long sent,long deadline){this.code=code;this.nonce=nonce;this.request=request;this.sent=sent;this.deadline=deadline;}
        void fail(Exception cause){failure=cause;retired.set(true);done.countDown();}
        @Override protected boolean onTransact(int operation,Parcel data,Parcel reply,int flags)throws android.os.RemoteException{
            ParcelFileDescriptor fd=null;
            try{
                // Preserve actual Binder caller identity before leaving its thread.
                need(Binder.getCallingUid()==helper.uid,"reply caller UID differs");
                if(operation==IBinder.INTERFACE_TRANSACTION){if(reply!=null)reply.writeString(WebEvidenceProtocol.CALLBACK_DESCRIPTOR);return true;}
                need(operation==WebEvidenceProtocol.CALLBACK_RESULT&&(flags&IBinder.FLAG_ONEWAY)!=0,"one-way callback method required");
                data.enforceInterface(WebEvidenceProtocol.CALLBACK_DESCRIPTOR);
                String json=data.readString();int present=data.readInt();need(present==0||present==1,"FD presence flag differs");
                if(present==1)fd=ParcelFileDescriptor.CREATOR.createFromParcel(data);
                need(data.dataAvail()==0,"trailing callback Parcel fields");
                need(!retired.get()&&!stopped&&pending==this&&SystemClock.elapsedRealtime()<=deadline&&received.compareAndSet(false,true),"late or duplicate callback");
                final ParcelFileDescriptor incoming=fd;fd=null;final long arrived=SystemClock.elapsedRealtime();
                try{fdReader.execute(()->{
                    try{
                        need(!retired.get()&&!stopped&&pending==this,"retired evidence read");
                        WebHelperIdentity.requirePeer(context,controller,helper);
                        JSONObject cb=WebEvidenceJson.parse(json,WebEvidenceProtocol.MAX_CALLBACK_BYTES);
                        callbackRaw=json; // Preserve bounded authenticated rejection receipts too; this is not a success claim.
                        byte[] bytes=incoming==null?null:readFd(incoming,WebEvidenceJson.number(cb,"raw_length"),helper.uid);
                        need(!retired.get()&&!stopped&&pending==this&&SystemClock.elapsedRealtime()<=deadline,"evidence read exceeded original request");
                        JSONObject binding=WebEvidenceJson.parseEvidence(bindingRaw,WebEvidenceProtocol.MAX_REQUEST_BYTES);
                        raw=bytes;
                        WebEvidenceReceipt verified=WebEvidenceReceipt.verify(code,request,binding,json,bytes,helper.uid,sent,arrived);
                        WebHelperIdentity.requirePeer(context,controller,helper);
                        result=verified;
                    }catch(Exception error){failure=error;}
                    finally{if(incoming!=null)try{incoming.close();}catch(Exception ignored){}done.countDown();}
                });}catch(RuntimeException enqueueFailure){if(incoming!=null)try{incoming.close();}catch(Exception ignored){}throw enqueueFailure;}
                return true;
            }catch(Exception refused){
                if(fd!=null)try{fd.close();}catch(Exception ignored){}
                // Reject malformed or late callbacks; no such callback supplies evidence.
                if(Binder.getCallingUid()==helper.uid&&!retired.get()&&pending==this)fail(new IOException("evidence callback refused",refused));
                return false;
            }
        }
    }
    private static byte[] readFd(ParcelFileDescriptor pfd,long expected,int uid)throws Exception{
        need(expected>0&&expected<=WebEvidenceProtocol.MAX_EVIDENCE_BYTES,"evidence FD budget");
        java.io.FileDescriptor fd=pfd.getFileDescriptor();StructStat before=Os.fstat(fd);
        need(OsConstants.S_ISREG(before.st_mode)&&before.st_uid==uid&&before.st_nlink==1&&before.st_size==expected,
                "helper-owned regular evidence FD required");
        need((Os.fcntlInt(fd,OsConstants.F_GETFL,0)&OsConstants.O_ACCMODE)==OsConstants.O_RDONLY,"read-only evidence FD required");
        need(Os.lseek(fd,0,OsConstants.SEEK_CUR)==0,"evidence FD offset must start at zero");
        ByteArrayOutputStream out=new ByteArrayOutputStream((int)expected);byte[] buffer=new byte[16384];
        // Read through the borrowed FD directly; only the ParcelFileDescriptor owns its closure.
        int count;
        while((count=Os.read(fd,buffer,0,buffer.length))>0){need(out.size()+count<=expected,"evidence FD grew");out.write(buffer,0,count);}
        need(count==0,"unexpected evidence FD read result");
        StructStat after=Os.fstat(fd);
        need(out.size()==expected&&same(before,after),"evidence FD changed during read");return out.toByteArray();
    }
    private static boolean same(StructStat a,StructStat b){return a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_uid==b.st_uid
            &&a.st_size==b.st_size&&a.st_mode==b.st_mode&&a.st_nlink==b.st_nlink&&a.st_mtime==b.st_mtime&&a.st_ctime==b.st_ctime;}
    @Override public void close(){
        stopped=true;Rpc rpc=pending;if(rpc!=null)rpc.fail(new IOException("client retired"));
        if(bound){try{context.unbindService(connection);}catch(Exception ignored){}bound=false;}
        peer=null;fdReader.shutdown();
    }
    private static void workerOnly(){need(Looper.myLooper()!=Looper.getMainLooper(),"evidence IPC may not block the UI thread");}
    private static void need(boolean condition,String message){WebEvidenceJson.need(condition,message);}
}
