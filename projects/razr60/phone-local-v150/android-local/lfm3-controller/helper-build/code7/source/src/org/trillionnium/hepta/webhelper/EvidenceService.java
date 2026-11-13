package org.trillionnium.hepta.webhelper;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/** Signature service. Hashing stays off both WebView and accessibility UI threads. */
public final class EvidenceService extends Service {
    private final ExecutorService verifier=Executors.newSingleThreadExecutor();
    private final AtomicInteger queued=new AtomicInteger();
    private final Binder endpoint=new Binder(){
        @Override protected boolean onTransact(int code,Parcel data,Parcel reply,int flags)throws RemoteException{
            if(code==IBinder.INTERFACE_TRANSACTION){if(reply!=null)reply.writeString(WebEvidenceProtocol.DESCRIPTOR);return true;}
            if(code<WebEvidenceProtocol.ATTACH||code>WebEvidenceProtocol.ACK_CAPTURE)return super.onTransact(code,data,reply,flags);
            data.enforceInterface(WebEvidenceProtocol.DESCRIPTOR);
            if((flags&IBinder.FLAG_ONEWAY)==0||data.dataSize()>2*WebEvidenceProtocol.MAX_REQUEST_BYTES+8192)throw new SecurityException("bounded asynchronous evidence request required");
            final int caller=Binder.getCallingUid();final String raw=data.readString();final IBinder callback=data.readStrongBinder();
            if(data.dataAvail()!=0||callback==null)throw new SecurityException("exact evidence parcel required");
            final JSONObject request;
            try{InstalledIdentity.requireControllerCaller(EvidenceService.this,caller);request=Jsons.parse(raw,WebEvidenceProtocol.MAX_REQUEST_BYTES);TaskBinding.validateCommon(request,code);}
            catch(Exception rejected){throw new SecurityException(rejected.getMessage());}
            if(queued.incrementAndGet()>4){queued.decrementAndGet();throw new SecurityException("evidence verification queue full");}
            final int method=code;
            verifier.execute(()->{
                try{
                    InstalledIdentity.requireControllerCaller(EvidenceService.this,caller);
                    InstalledIdentity controller=InstalledIdentity.read(EvidenceService.this,WebEvidenceProtocol.CONTROLLER_PACKAGE);
                    InstalledIdentity helper=InstalledIdentity.read(EvidenceService.this,WebEvidenceProtocol.HELPER_PACKAGE);
                    Jsons.need(controller.uid==caller,"controller changed during verification");TaskBinding.validateCommon(request,method);
                    RemoteReply response=new RemoteReply(callback,request,raw,method,caller,controller,helper);
                    EvidenceSession.get(EvidenceService.this).dispatch(response);
                }catch(Exception rejected){
                    // No authority or side effect is inferred from a missing callback.
                    // The client retains its durable unknown lease until a real close.
                }finally{queued.decrementAndGet();}
            });return true;
        }
    };
    @Override public IBinder onBind(Intent intent){return endpoint;}
    @Override public void onDestroy(){
        verifier.shutdown();try{EvidenceSession.get(this).serviceStopped();}catch(Exception ignored){}
        super.onDestroy();
    }
}
