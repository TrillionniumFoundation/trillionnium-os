package org.trillionnium.hepta.webhelper;

import android.os.IBinder;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import org.json.JSONObject;
import org.json.JSONArray;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import java.io.File;

/**
 * Executes the complete production RemoteReply.send with explicit Binder/Parcel/
 * Record test doubles. No Android runtime, real FD, SDK, lease retirement or
 * business success is asserted. The doubles observe the actual single-use,
 * disposition, transaction and finally paths; they do not implement policy.
 */
public final class RemoteReplyHostTest {
    private static final String NONCE=repeat('a',64),TASK=repeat('b',32),SESSION=repeat('c',64),HASH=repeat('d',64),BINDING=repeat('e',64);
    private static int cases,assertions;
    private static final JSONArray names=new JSONArray();
    private interface Check { void run()throws Exception; }
    private static final class Receiver implements IBinder {
        int calls; boolean result=true,throwOnCall; int code,flags; String descriptor,metadata; int fdPresence,fdWrites;
        public boolean transact(int c,Parcel p,Parcel reply,int f)throws Exception {
            calls++;code=c;flags=f;descriptor=p.token;metadata=p.text;fdPresence=p.marker;fdWrites=p.fdWrites;
            if(throwOnCall)throw new Exception("synthetic binder failure");
            return result;
        }
    }
    private static void ok(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    private static void test(String name,Check c)throws Exception {
        Parcel.reset();ParcelFileDescriptor.reset();c.run();cases++;names.put(name);
    }
    private static void reject(Check c)throws Exception {boolean rejected=false;try{c.run();}catch(Exception expected){rejected=true;}ok(rejected,"expected refusal");}
    private static String repeat(char c,int n){StringBuilder b=new StringBuilder();while(n-->0)b.append(c);return b.toString();}
    private static JSONObject request()throws Exception{return new JSONObject().put("request_nonce",NONCE).put("task_id",TASK).put("controller_session_nonce",SESSION);}
    private static JSONObject verdict(boolean unstarted)throws Exception{return new JSONObject()
            .put("schema",unstarted?"hepta.web-helper.unstarted-retirement-verdict.v1":"hepta.web-helper.retirement-record-verdict.v1")
            .put("retirement_verified",true).put("old_cleanup_methods_verified",false)
            .put("business_verified",false).put("binding_sha256",BINDING);}
    private static JSONObject metadata(int method,String status)throws Exception {
        JSONObject r=new JSONObject();for(String key:WebEvidenceProtocol.CALLBACK_KEYS)r.put(key,JSONObject.NULL);
        return r.put("schema",WebEvidenceProtocol.CALLBACK_SCHEMA).put("method",WebEvidenceProtocol.method(method))
                .put("request_nonce",NONCE).put("task_id",TASK).put("controller_session_nonce",SESSION)
                .put("status",status).put("actual_helper_uid",10484).put("actual_display_id",-1)
                .put("actual_window_id",-1).put("raw_length",0).put("retired",false);
    }
    private static EvidenceFiles.Record record(String kind){return new EvidenceFiles.Record(new File("/synthetic-only/"+kind+"-"+NONCE+".json"),17,HASH);}
    private static JSONObject withRecord(JSONObject r,EvidenceFiles.Record f)throws Exception{return r.put("raw_length",f.length).put("raw_sha256",f.sha);}
    private static RemoteReply response(Receiver b,int method)throws Exception{return new RemoteReply(b,request(),request().toString(),method,10481,null,null);}
    private static void transport(Receiver b,RemoteReply reply,boolean fd)throws Exception {
        ok(reply.alreadyReplied(),"single reply consumed");ok(b.calls==1,"one transaction");
        ok(b.code==WebEvidenceProtocol.CALLBACK_RESULT&&b.flags==IBinder.FLAG_ONEWAY,"exact one-way callback");
        ok(WebEvidenceProtocol.CALLBACK_DESCRIPTOR.equals(b.descriptor),"exact descriptor");
        ok(b.fdPresence==(fd?1:0)&&b.fdWrites==(fd?1:0),"FD marker and serialized FD agree");
        ok(Parcel.obtained==1&&Parcel.recycled==1,"parcel released");
        ok(ParcelFileDescriptor.opened==(fd?1:0)&&ParcelFileDescriptor.closed==(fd?1:0),"FD released exactly once");
    }
    private static void deniedBeforeOpen(Receiver b,RemoteReply reply,JSONObject m,EvidenceFiles.Record f)throws Exception {
        reject(()->reply.send(m,f));ok(b.calls==0,"no transaction on denial");
        ok(ParcelFileDescriptor.opened==0,"no FD open on metadata denial");
        ok(Parcel.obtained==1&&Parcel.recycled==1,"denied parcel released");
        ok(reply.alreadyReplied(),"invalid owned reply consumed");reject(()->reply.send(metadata(reply.method,"unavailable"),null));
        ok(b.calls==0&&ParcelFileDescriptor.opened==0,"no fallback resend");
    }
    public static void main(String[] args)throws Exception {
        test("capture-exact-typed-fd",()->{
            Receiver b=new Receiver();RemoteReply r=response(b,WebEvidenceProtocol.CAPTURE);EvidenceFiles.Record f=record("capture");
            r.send(withRecord(metadata(r.method,"captured"),f),f);transport(b,r,true);ok(f.opens==1,"original record opened");
        });
        test("arm-exact-typed-fd",()->{
            Receiver b=new Receiver();RemoteReply r=response(b,WebEvidenceProtocol.ARM_OBSERVED_LINK);EvidenceFiles.Record f=record("link-arm");
            r.send(withRecord(metadata(r.method,"armed"),f),f);transport(b,r,true);
        });
        test("recovered-close-original-false-cleanup-preserved",()->{
            Receiver b=new Receiver();RemoteReply r=response(b,WebEvidenceProtocol.CLOSE);EvidenceFiles.Record f=record("recovered");
            JSONObject cleanup=new JSONObject().put("captures_retired",false).put("stop_loading_called",false)
                    .put("webview_destroyed",false).put("active_view_absent",false).put("storage_clear_completed",false);
            JSONObject m=withRecord(metadata(r.method,"recovered_retired"),f).put("retired",true).put("binding_sha256",BINDING)
                    .put("recovery",verdict(false)).put("cleanup",cleanup);
            r.send(m,f);transport(b,r,true);
            ok(new JSONObject(b.metadata).getJSONObject("cleanup").toString().equals(cleanup.toString()),"original cleanup flags not promoted");
        });
        test("unstarted-close-and-confirmation-typed-fds",()->{
            for(String kind:new String[]{"unstarted","unstarted-confirm"}){
                Parcel.reset();ParcelFileDescriptor.reset();
                Receiver b=new Receiver();RemoteReply r=response(b,WebEvidenceProtocol.CLOSE);EvidenceFiles.Record f=record(kind);
                JSONObject m=withRecord(metadata(r.method,"unstarted_retired"),f).put("retired",true)
                        .put("binding_sha256",BINDING).put("recovery",verdict(true));
                r.send(m,f);transport(b,r,true);
            }
        });
        test("ordinary-closed-stays-metadata-only",()->{
            Receiver b=new Receiver();RemoteReply r=response(b,WebEvidenceProtocol.CLOSE);
            r.send(metadata(r.method,"closed").put("retired",true),null);transport(b,r,false);
        });
        test("attach-and-unavailable-stay-metadata-only",()->{
            for(int method:new int[]{WebEvidenceProtocol.ATTACH,WebEvidenceProtocol.ARM_OBSERVED_LINK}){
                Parcel.reset();ParcelFileDescriptor.reset();Receiver b=new Receiver();RemoteReply r=response(b,method);
                r.send(metadata(method,method==WebEvidenceProtocol.ATTACH?"attached":"unavailable"),null);transport(b,r,false);
            }
        });
        test("typed-status-cannot-drop-fd",()->{
            for(int method:new int[]{WebEvidenceProtocol.CAPTURE,WebEvidenceProtocol.ARM_OBSERVED_LINK,WebEvidenceProtocol.CLOSE}){
                Parcel.reset();ParcelFileDescriptor.reset();Receiver b=new Receiver();RemoteReply r=response(b,method);
                String status=method==WebEvidenceProtocol.CAPTURE?"captured":method==WebEvidenceProtocol.ARM_OBSERVED_LINK?"armed":"recovered_retired";
                deniedBeforeOpen(b,r,metadata(method,status),null);
            }
        });
        test("ordinary-closed-cannot-gain-fd",()->{
            Receiver b=new Receiver();RemoteReply r=response(b,WebEvidenceProtocol.CLOSE);EvidenceFiles.Record f=record("recovered");
            deniedBeforeOpen(b,r,withRecord(metadata(r.method,"closed").put("retired",true),f),f);
        });
        test("fd-cannot-cross-method-or-request",()->{
            for(String key:new String[]{"method","request_nonce","task_id","controller_session_nonce"}){
                Parcel.reset();ParcelFileDescriptor.reset();Receiver b=new Receiver();RemoteReply r=response(b,WebEvidenceProtocol.CAPTURE);EvidenceFiles.Record f=record("capture");
                JSONObject m=withRecord(metadata(r.method,"captured"),f).put(key,key.equals("method")?"armObservedLink":"wrong");
                deniedBeforeOpen(b,r,m,f);
            }
        });
        test("record-length-sha-kind-and-nonce-exact",()->{
            for(int which=0;which<4;which++){
                Parcel.reset();ParcelFileDescriptor.reset();Receiver b=new Receiver();RemoteReply r=response(b,WebEvidenceProtocol.ARM_OBSERVED_LINK);
                EvidenceFiles.Record f=which==2?record("capture"):which==3?new EvidenceFiles.Record(new File("/synthetic-only/link-arm-"+repeat('f',64)+".json"),17,HASH):record("link-arm");
                JSONObject m=withRecord(metadata(r.method,"armed"),f);
                if(which==0)m.put("raw_length",18);if(which==1)m.put("raw_sha256",repeat('f',64));
                deniedBeforeOpen(b,r,m,f);
            }
        });
        test("retirement-verdict-schema-binding-and-booleans-strict",()->{
            for(String field:new String[]{"schema","binding_sha256","retirement_verified","old_cleanup_methods_verified","business_verified"}){
                Parcel.reset();ParcelFileDescriptor.reset();Receiver b=new Receiver();RemoteReply r=response(b,WebEvidenceProtocol.CLOSE);EvidenceFiles.Record f=record("recovered");
                JSONObject v=verdict(false);
                if(field.equals("schema"))v.put(field,"wrong");
                else if(field.equals("binding_sha256"))v.put(field,repeat('f',64));
                else if(field.equals("retirement_verified"))v.put(field,"true");
                else v.put(field,true);
                JSONObject m=withRecord(metadata(r.method,"recovered_retired"),f).put("retired",true).put("binding_sha256",BINDING).put("recovery",v);
                deniedBeforeOpen(b,r,m,f);
            }
        });
        test("live-arm-cannot-claim-retirement",()->{
            for(int which=0;which<2;which++){
                Parcel.reset();ParcelFileDescriptor.reset();Receiver b=new Receiver();RemoteReply r=response(b,WebEvidenceProtocol.ARM_OBSERVED_LINK);EvidenceFiles.Record f=record("link-arm");
                JSONObject m=withRecord(metadata(r.method,"armed"),f);if(which==0)m.put("retired",true);else m.put("recovery",verdict(false));
                deniedBeforeOpen(b,r,m,f);
            }
        });
        test("no-fd-metadata-cannot-claim-raw-bytes",()->{
            for(int which=0;which<2;which++){
                Parcel.reset();ParcelFileDescriptor.reset();Receiver b=new Receiver();RemoteReply r=response(b,WebEvidenceProtocol.CLOSE);
                JSONObject m=metadata(r.method,"closed");if(which==0)m.put("raw_length",1);else m.put("raw_sha256",HASH);
                deniedBeforeOpen(b,r,m,null);
            }
        });
        test("successful-callback-cannot-be-repeated",()->{
            Receiver b=new Receiver();RemoteReply r=response(b,WebEvidenceProtocol.ARM_OBSERVED_LINK);EvidenceFiles.Record f=record("link-arm");
            JSONObject m=withRecord(metadata(r.method,"armed"),f);r.send(m,f);reject(()->r.send(m,f));
            transport(b,r,true);ok(f.opens==1,"no second FD open");
        });
        test("binder-false-keeps-unknown-and-closes-fd",()->{
            Receiver b=new Receiver();b.result=false;RemoteReply r=response(b,WebEvidenceProtocol.CAPTURE);EvidenceFiles.Record f=record("capture");
            JSONObject m=withRecord(metadata(r.method,"captured"),f);reject(()->r.send(m,f));transport(b,r,true);
            reject(()->r.send(m,f));ok(b.calls==1&&f.opens==1,"refused transaction never replayed");
        });
        test("binder-exception-keeps-unknown-and-closes-fd",()->{
            Receiver b=new Receiver();b.throwOnCall=true;RemoteReply r=response(b,WebEvidenceProtocol.CAPTURE);EvidenceFiles.Record f=record("capture");
            JSONObject m=withRecord(metadata(r.method,"captured"),f);reject(()->r.send(m,f));transport(b,r,true);
            reject(()->r.send(m,f));ok(b.calls==1&&f.opens==1,"unknown transaction never replayed");
        });
        test("record-open-failure-consumes-without-transaction",()->{
            Receiver b=new Receiver();RemoteReply r=response(b,WebEvidenceProtocol.CAPTURE);EvidenceFiles.Record f=record("capture");f.failOpen=true;
            JSONObject m=withRecord(metadata(r.method,"captured"),f);reject(()->r.send(m,f));ok(r.alreadyReplied(),"open failure consumes");
            ok(b.calls==0&&f.opens==1&&Parcel.recycled==1&&ParcelFileDescriptor.opened==0,"open failure releases parcel");
            reject(()->r.send(m,f));ok(f.opens==1,"no second open");
        });
        test("exact-metadata-keys-and-budget-precede-transport",()->{
            for(int which=0;which<3;which++){
                Parcel.reset();ParcelFileDescriptor.reset();Receiver b=new Receiver();RemoteReply r=response(b,WebEvidenceProtocol.CLOSE);JSONObject m=metadata(r.method,"closed");
                if(which==0)m.put("unexpected",true);else if(which==1)m.remove("reason");else m.put("reason",repeat('x',WebEvidenceProtocol.MAX_CALLBACK_BYTES+1));
                reject(()->r.send(m,null));ok(b.calls==0&&Parcel.obtained==0&&ParcelFileDescriptor.opened==0,"bad metadata never reaches transport");
            }
        });
        ok(cases==18,"fixed focused case count");
        System.out.println(new JSONObject().put("schema","hepta.helper6-typed-callback-focused.v1")
                .put("all_pass",true).put("case_count",cases).put("assertion_count",assertions).put("cases",names)
                .put("production_remote_reply_executed",true).put("binder_parcel_record_test_doubles",true)
                .put("android_binder_exercised",false).put("real_fd_exercised",false).put("actual_retirement_verified",false)
                .put("phone_tested",false).put("business_verified",false).toString());
    }
}
