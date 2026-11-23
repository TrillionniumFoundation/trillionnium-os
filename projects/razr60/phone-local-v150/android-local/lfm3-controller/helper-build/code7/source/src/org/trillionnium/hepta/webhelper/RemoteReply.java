package org.trillionnium.hepta.webhelper;

import android.os.IBinder;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;

/** A single authenticated-controller callback; never repeats a dispatched reply. */
final class RemoteReply {
    final IBinder binder;
    final JSONObject request;
    final String rawRequest;
    final int method,callerUid;
    final InstalledIdentity controller,helper;
    private final AtomicBoolean replied=new AtomicBoolean();
    RemoteReply(IBinder binder,JSONObject request,String raw,int method,int callerUid,
            InstalledIdentity controller,InstalledIdentity helper){
        this.binder=binder;this.request=request;rawRequest=raw;this.method=method;this.callerUid=callerUid;this.controller=controller;this.helper=helper;
    }
    void send(JSONObject receipt,EvidenceFiles.Record record)throws Exception{
        Jsons.keys(receipt,WebEvidenceProtocol.CALLBACK_KEYS);
        byte[] metadata=receipt.toString().getBytes(StandardCharsets.UTF_8);Jsons.need(metadata.length<=WebEvidenceProtocol.MAX_CALLBACK_BYTES,"callback metadata budget");
        Jsons.need(replied.compareAndSet(false,true),"callback already retired");
        Parcel p=Parcel.obtain();ParcelFileDescriptor fd=null;
        try{
            requireEvidenceDisposition(receipt,record);
            if(record!=null)fd=record.openReadOnly();
            p.writeInterfaceToken(WebEvidenceProtocol.CALLBACK_DESCRIPTOR);p.writeString(receipt.toString());p.writeInt(fd==null?0:1);
            if(fd!=null)fd.writeToParcel(p,0);
            Jsons.need(binder.transact(WebEvidenceProtocol.CALLBACK_RESULT,p,null,IBinder.FLAG_ONEWAY),"callback transaction refused");
        }finally{if(fd!=null)fd.close();p.recycle();}
    }
    private void requireEvidenceDisposition(JSONObject receipt,EvidenceFiles.Record record)throws Exception{
        Jsons.need(WebEvidenceProtocol.CALLBACK_SCHEMA.equals(Jsons.text(receipt,"schema"))
                &&WebEvidenceProtocol.method(method).equals(Jsons.text(receipt,"method"))
                &&Jsons.text(request,"request_nonce").equals(Jsons.text(receipt,"request_nonce"))
                &&Jsons.text(request,"task_id").equals(Jsons.text(receipt,"task_id"))
                &&Jsons.text(request,"controller_session_nonce").equals(Jsons.text(receipt,"controller_session_nonce")),
                "callback method and original request tuple differ");
        String status=Jsons.text(receipt,"status"),nonce=Jsons.text(request,"request_nonce");
        boolean capture=method==WebEvidenceProtocol.CAPTURE&&"captured".equals(status);
        boolean armed=method==WebEvidenceProtocol.ARM_OBSERVED_LINK&&"armed".equals(status);
        boolean recovered=method==WebEvidenceProtocol.CLOSE&&"recovered_retired".equals(status);
        boolean unstarted=method==WebEvidenceProtocol.CLOSE&&"unstarted_retired".equals(status);
        boolean typed=capture||armed||recovered||unstarted;
        Jsons.need((record!=null)==typed,"FD presence must match one exact typed evidence reply");
        if(record==null){
            Jsons.need(Jsons.number(receipt,"raw_length")==0&&receipt.get("raw_sha256")==JSONObject.NULL,
                    "callback without FD must not describe raw bytes");
            return;
        }
        Jsons.need(record.length>0&&record.length<=WebEvidenceProtocol.MAX_EVIDENCE_BYTES
                &&Jsons.number(receipt,"raw_length")==record.length
                &&WebEvidenceProtocol.hex64(record.sha)&&record.sha.equals(Jsons.text(receipt,"raw_sha256")),
                "typed FD original length/SHA differ");
        String name=record.path.getName();
        Jsons.need(WebEvidenceProtocol.hex64(nonce)
                &&(capture?name.equals("capture-"+nonce+".json"):
                   armed?name.equals("link-arm-"+nonce+".json"):
                   recovered?name.equals("recovered-"+nonce+".json"):
                   name.equals("unstarted-"+nonce+".json")||name.equals("unstarted-confirm-"+nonce+".json")),
                "typed FD original record kind/nonce differ");
        if(capture||armed){
            Jsons.need(Boolean.FALSE.equals(receipt.get("retired"))&&receipt.get("recovery")==JSONObject.NULL,
                    "live capture/ARM cannot carry retirement authority");
        }else{
            JSONObject verdict=receipt.getJSONObject("recovery");
            String expected=recovered?"hepta.web-helper.retirement-record-verdict.v1":
                    "hepta.web-helper.unstarted-retirement-verdict.v1";
            Jsons.need(Boolean.TRUE.equals(receipt.get("retired"))&&expected.equals(Jsons.text(verdict,"schema"))
                    &&Boolean.TRUE.equals(verdict.get("retirement_verified"))
                    &&Boolean.FALSE.equals(verdict.get("old_cleanup_methods_verified"))
                    &&Boolean.FALSE.equals(verdict.get("business_verified"))
                    &&WebEvidenceProtocol.hex64(Jsons.text(receipt,"binding_sha256"))
                    &&Jsons.text(receipt,"binding_sha256").equals(Jsons.text(verdict,"binding_sha256")),
                    "typed retirement verdict and binding required; original cleanup flags stay unchanged");
        }
    }
    boolean alreadyReplied(){return replied.get();}
}
