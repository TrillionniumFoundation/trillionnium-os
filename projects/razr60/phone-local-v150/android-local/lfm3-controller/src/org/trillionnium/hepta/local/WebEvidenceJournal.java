package org.trillionnium.hepta.local;

import android.content.Context;
import android.os.Process;
import android.os.SystemClock;
import android.system.Os;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebEvidenceBinding;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.UUID;

/** App-private durable exact request/FD records. A pending helper lease never disappears on restart. */
final class WebEvidenceJournal implements WebEvidenceClient.Journal {
    static final String ACTIVE="web-helper.active.json",SCHEMA="hepta.web-controller-lease.v1";
    final String taskId,session,bindingSha;
    final File directory;
    private final Context context;
    private final QualificationScopeConfig.FilesRoot filesRoot;
    private final File active;
    private final String bindingRaw;
    private long storedBytes;
    private WebEvidenceJournal(Context context,QualificationScopeConfig.FilesRoot root,File directory,JSONObject binding)throws Exception{
        this.context=context.getApplicationContext();filesRoot=root;this.directory=directory;
        filesRoot.unchanged(context);active=new File(root.path,ACTIVE);
        taskId=binding.getString("task_id");session=binding.getString("controller_session_nonce");
        need(WebEvidenceProtocol.hex32(taskId)&&WebEvidenceProtocol.hex64(session),"journal task/session shape");
        bindingRaw=WebEvidenceBinding.canonical(binding);bindingSha=WebEvidenceBinding.sha256(binding);
    }
    static boolean hasUnreleased(Context context){
        try{return MobiMindPrivateFiles.exists(new File(new QualificationScopeConfig.FilesRoot(context).path,ACTIVE));}
        catch(Exception unknown){return true;}
    }
    static WebEvidenceJournal create(Context context,QualificationScopeConfig.FilesRoot root,File evidence,JSONObject binding)throws Exception{
        root.unchanged(context);
        String task=binding.getString("task_id");
        File expected=new File(new File(root.path,"control-tasks"),task).getCanonicalFile();
        need(evidence.getCanonicalFile().equals(expected)&&evidence.equals(evidence.getCanonicalFile()),"evidence directory does not belong to task");
        need(!hasUnreleased(context),"previous web helper lease requires explicit cleanup");
        File directory=MobiMindPrivateFiles.directory(new File(evidence,"web-helper"),true);
        WebEvidenceJournal journal=new WebEvidenceJournal(context,root,directory,binding);
        byte[] raw=journal.bindingRaw.getBytes(StandardCharsets.UTF_8);
        need(raw.length<=WebEvidenceProtocol.MAX_REQUEST_BYTES,"binding byte budget");
        MobiMindPrivateFiles.writeNew(new File(directory,"BINDING.json"),raw);
        JSONObject marker=new JSONObject().put("schema",SCHEMA).put("task_id",journal.taskId)
                .put("controller_session_nonce",journal.session).put("binding_sha256",journal.bindingSha)
                .put("binding_raw_sha256",WebEvidenceJson.sha(raw)).put("binding_bytes",raw.length)
                .put("relative_directory","control-tasks/"+journal.taskId+"/web-helper")
                .put("controller_uid",Process.myUid()).put("created_elapsed_ms",SystemClock.elapsedRealtime())
                .put("automatic_resume",false).put("business_verified",false);
        MobiMindPrivateFiles.writeNew(journal.active,marker.toString().getBytes(StandardCharsets.UTF_8));
        journal.storedBytes=raw.length;return journal;
    }
    static WebEvidenceJournal open(Context context)throws Exception{
        QualificationScopeConfig.FilesRoot root=new QualificationScopeConfig.FilesRoot(context);root.unchanged(context);
        MobiMindPrivateFiles.Read mark=MobiMindPrivateFiles.read(new File(root.path,ACTIVE),65536,true);
        JSONObject marker=WebEvidenceJson.parseEvidence(WebEvidenceReceipt.decode(mark.bytes),65536);
        WebEvidenceReceipt.exact(marker,"schema","task_id","controller_session_nonce","binding_sha256","binding_raw_sha256",
                "binding_bytes","relative_directory","controller_uid","created_elapsed_ms","automatic_resume","business_verified");
        String task=marker.getString("task_id");
        need(SCHEMA.equals(marker.getString("schema"))&&WebEvidenceProtocol.hex32(task)
                &&WebEvidenceProtocol.hex64(marker.getString("controller_session_nonce"))
                &&WebEvidenceJson.number(marker,"controller_uid")==Process.myUid()
                &&Boolean.FALSE.equals(marker.get("automatic_resume"))&&Boolean.FALSE.equals(marker.get("business_verified")),"unknown active web lease");
        String relative="control-tasks/"+task+"/web-helper";need(relative.equals(marker.getString("relative_directory")),"journal relative path differs");
        File directory=new File(root.path,relative);
        android.system.StructStat actual=Os.lstat(directory.getPath());
        need(directory.equals(directory.getCanonicalFile())&&android.system.OsConstants.S_ISDIR(actual.st_mode)
                &&actual.st_uid==Process.myUid(),"original private journal directory required; recovery never creates it");
        MobiMindPrivateFiles.Read original=MobiMindPrivateFiles.read(new File(directory,"BINDING.json"),WebEvidenceProtocol.MAX_REQUEST_BYTES,true);
        need(original.bytes.length==WebEvidenceJson.number(marker,"binding_bytes")&&WebEvidenceJson.sha(original.bytes).equals(marker.getString("binding_raw_sha256")),"original web binding changed");
        JSONObject binding=WebEvidenceJson.parseEvidence(WebEvidenceReceipt.decode(original.bytes),WebEvidenceProtocol.MAX_REQUEST_BYTES);
        WebEvidenceJournal journal=new WebEvidenceJournal(context,root,directory,binding);
        need(journal.taskId.equals(task)&&journal.session.equals(marker.getString("controller_session_nonce"))
                &&journal.bindingSha.equals(marker.getString("binding_sha256")),"journal binding/task differs");
        mark.unchangedPath();original.unchangedPath();journal.storedBytes=journal.actualStoredBytes();return journal;
    }
    JSONObject binding()throws Exception{return WebEvidenceJson.parseEvidence(bindingRaw,WebEvidenceProtocol.MAX_REQUEST_BYTES);}
    private void current()throws Exception{
        filesRoot.unchanged(context);
        MobiMindPrivateFiles.Read current=MobiMindPrivateFiles.read(active,65536,true);
        JSONObject value=WebEvidenceJson.parseEvidence(WebEvidenceReceipt.decode(current.bytes),65536);
        need(SCHEMA.equals(value.getString("schema"))&&taskId.equals(value.getString("task_id"))
                &&session.equals(value.getString("controller_session_nonce"))&&bindingSha.equals(value.getString("binding_sha256")),"active helper lease changed");
        current.unchangedPath();
    }
    @Override public synchronized void request(int code,String nonce,String raw)throws Exception{
        current();need(WebEvidenceProtocol.hex64(nonce),"nonce shape");
        JSONObject parsed=WebEvidenceJson.parse(raw,WebEvidenceProtocol.MAX_REQUEST_BYTES);
        WebEvidenceJson.keys(parsed,WebEvidenceProtocol.requestKeys(code));
        need(WebEvidenceProtocol.requestSchema(code).equals(parsed.getString("schema"))&&nonce.equals(parsed.getString("request_nonce"))
                &&taskId.equals(parsed.getString("task_id"))&&session.equals(parsed.getString("controller_session_nonce")),"request belongs to another lease");
        save("request-"+nonce+".json",new JSONObject().put("schema","hepta.web-controller-request.v1")
                .put("method",WebEvidenceProtocol.method(code)).put("request_json_utf8",raw).put("request_sha256",WebEvidenceJson.sha(raw))
                .put("binding_sha256",bindingSha).put("before_remote_submission",true)
                .put("recorded_elapsed_ms",SystemClock.elapsedRealtime()).toString().getBytes(StandardCharsets.UTF_8));
    }
    @Override public synchronized void response(int code,String nonce,String callback,byte[] raw,boolean verified)throws Exception{
        current();need(WebEvidenceProtocol.hex64(nonce),"nonce shape");
        byte[] original=MobiMindPrivateFiles.read(new File(directory,"request-"+nonce+".json"),65536,true).bytes;
        JSONObject cb=WebEvidenceJson.parse(callback,WebEvidenceProtocol.MAX_CALLBACK_BYTES);
        need(nonce.equals(cb.getString("request_nonce"))&&taskId.equals(cb.getString("task_id"))&&session.equals(cb.getString("controller_session_nonce")),"response belongs to another lease");
        String rawName=raw==null?null:"raw-"+nonce+".json";
        if(raw!=null){need(raw.length<=WebEvidenceProtocol.MAX_EVIDENCE_BYTES,"evidence byte budget");save(rawName,raw);}
        save("reply-"+nonce+".json",new JSONObject().put("schema","hepta.web-controller-reply.v1")
                .put("method",WebEvidenceProtocol.method(code)).put("original_request_record_sha256",WebEvidenceJson.sha(original))
                .put("callback_json_utf8",callback).put("callback_sha256",WebEvidenceJson.sha(callback)).put("callback_verification_passed",verified)
                .put("binding_sha256",bindingSha).put("raw_file",rawName==null?JSONObject.NULL:rawName)
                .put("raw_bytes",raw==null?0:raw.length).put("raw_sha256",raw==null?JSONObject.NULL:WebEvidenceJson.sha(raw))
                .put("recorded_elapsed_ms",SystemClock.elapsedRealtime()).put("business_verified",false).toString().getBytes(StandardCharsets.UTF_8));
    }
    @Override public synchronized JSONObject captureAcknowledgement(String nonce,WebEvidenceReceipt expected)throws Exception{
        current();need(WebEvidenceProtocol.hex64(nonce)&&expected!=null&&"captured".equals(expected.status)
                &&bindingSha.equals(expected.bindingSha)&&expected.evidenceRaw()!=null,
                "only an actual verified capture may prepare durable acknowledgement");
        MobiMindPrivateFiles.Read requestRead=MobiMindPrivateFiles.read(new File(directory,"request-"+nonce+".json"),65536,true);
        MobiMindPrivateFiles.Read replyRead=MobiMindPrivateFiles.read(new File(directory,"reply-"+nonce+".json"),65536,true);
        MobiMindPrivateFiles.Read rawRead=MobiMindPrivateFiles.read(new File(directory,"raw-"+nonce+".json"),WebEvidenceProtocol.MAX_EVIDENCE_BYTES,true);
        JSONObject original=WebEvidenceJson.parseEvidence(WebEvidenceReceipt.decode(requestRead.bytes),65536);
        WebEvidenceReceipt.exact(original,"schema","method","request_json_utf8","request_sha256","binding_sha256","before_remote_submission","recorded_elapsed_ms");
        String requestRaw=original.getString("request_json_utf8");
        JSONObject request=WebEvidenceJson.parse(requestRaw,WebEvidenceProtocol.MAX_REQUEST_BYTES);
        WebEvidenceJson.keys(request,WebEvidenceProtocol.requestKeys(WebEvidenceProtocol.CAPTURE));
        need("hepta.web-controller-request.v1".equals(original.getString("schema"))
                &&WebEvidenceProtocol.method(WebEvidenceProtocol.CAPTURE).equals(original.getString("method"))
                &&bindingSha.equals(original.getString("binding_sha256"))&&Boolean.TRUE.equals(original.get("before_remote_submission"))
                &&WebEvidenceJson.sha(requestRaw).equals(original.getString("request_sha256"))
                &&WebEvidenceProtocol.requestSchema(WebEvidenceProtocol.CAPTURE).equals(request.getString("schema"))
                &&nonce.equals(request.getString("request_nonce"))&&taskId.equals(request.getString("task_id"))
                &&session.equals(request.getString("controller_session_nonce")),"durable original capture request differs");
        JSONObject reply=WebEvidenceJson.parseEvidence(WebEvidenceReceipt.decode(replyRead.bytes),65536);
        WebEvidenceReceipt.exact(reply,"schema","method","original_request_record_sha256","callback_json_utf8","callback_sha256",
                "callback_verification_passed","binding_sha256","raw_file","raw_bytes","raw_sha256","recorded_elapsed_ms","business_verified");
        String callbackRaw=reply.getString("callback_json_utf8");
        JSONObject callback=WebEvidenceJson.parse(callbackRaw,WebEvidenceProtocol.MAX_CALLBACK_BYTES);
        need("hepta.web-controller-reply.v1".equals(reply.getString("schema"))
                &&WebEvidenceProtocol.method(WebEvidenceProtocol.CAPTURE).equals(reply.getString("method"))
                &&WebEvidenceJson.sha(requestRead.bytes).equals(reply.getString("original_request_record_sha256"))
                &&WebEvidenceJson.sha(callbackRaw).equals(reply.getString("callback_sha256"))
                &&Boolean.TRUE.equals(reply.get("callback_verification_passed"))&&Boolean.FALSE.equals(reply.get("business_verified"))
                &&bindingSha.equals(reply.getString("binding_sha256"))&&("raw-"+nonce+".json").equals(reply.getString("raw_file"))
                &&rawRead.bytes.length==WebEvidenceJson.number(reply,"raw_bytes")
                &&WebEvidenceJson.sha(rawRead.bytes).equals(reply.getString("raw_sha256"))
                &&WebEvidenceReceipt.same(callback,expected.callback())
                &&Arrays.equals(rawRead.bytes,expected.evidenceRaw().getBytes(StandardCharsets.UTF_8)),
                "durable request/raw/verified callback readback differs");
        JSONObject bound=binding();
        JSONObject proof=org.trillionnium.hepta.webprotocol.WebCaptureAcknowledgement.proof(bound,nonce,requestRaw,callbackRaw,
                rawRead.bytes,requestRead.bytes,replyRead.bytes);
        requestRead.unchangedPath();replyRead.unchangedPath();rawRead.unchangedPath();current();
        byte[] proofBytes=org.trillionnium.hepta.webprotocol.WebDomCanonical.canonical(proof).getBytes(StandardCharsets.UTF_8);
        String leaf="transfer-"+nonce+".json";save(leaf,proofBytes);
        MobiMindPrivateFiles.Read proofRead=MobiMindPrivateFiles.read(new File(directory,leaf),65536,true);
        need(Arrays.equals(proofBytes,proofRead.bytes),"durable transfer proof readback differs");
        requestRead.unchangedPath();replyRead.unchangedPath();rawRead.unchangedPath();proofRead.unchangedPath();current();
        return WebEvidenceJson.parseEvidence(WebEvidenceReceipt.decode(proofRead.bytes),65536);
    }
    @Override public synchronized void failure(int code,String nonce,String reason)throws Exception{
        current();need(WebEvidenceProtocol.hex64(nonce),"nonce shape");
        save("failure-"+nonce+"-"+UUID.randomUUID().toString()+".json",new JSONObject().put("schema","hepta.web-controller-rpc-failure.v1")
                .put("method",WebEvidenceProtocol.method(code)).put("request_nonce",nonce).put("binding_sha256",bindingSha)
                .put("reason",HeptaAccessibilityService.limited(reason,512)).put("outcome_known",false)
                .put("automatic_retry",false).put("recorded_elapsed_ms",SystemClock.elapsedRealtime()).toString().getBytes(StandardCharsets.UTF_8));
    }
    boolean attachWasPrepared()throws Exception{
        current();String[] names=directory.list();need(names!=null&&names.length<=1024,"bounded journal enumeration");
        for(String name:names)if(name.matches("request-[0-9a-f]{64}\\.json")){
            JSONObject record=WebEvidenceJson.parseEvidence(WebEvidenceReceipt.decode(MobiMindPrivateFiles.read(new File(directory,name),65536,true).bytes),65536);
            need(bindingSha.equals(record.getString("binding_sha256")),"request journal binding differs");
            String request=record.getString("request_json_utf8");need(WebEvidenceJson.sha(request).equals(record.getString("request_sha256")),"request journal hash differs");
            JSONObject parsed=WebEvidenceJson.parse(request,WebEvidenceProtocol.MAX_REQUEST_BYTES);
            need(taskId.equals(parsed.getString("task_id"))&&session.equals(parsed.getString("controller_session_nonce")),"request journal task differs");
            if(WebEvidenceProtocol.method(WebEvidenceProtocol.ATTACH).equals(record.getString("method")))return true;
        }
        return false;
    }
    synchronized void closeKnown(WebEvidenceReceipt proof)throws Exception{
        current();need(proof!=null&&proof.cleanupKnown&&bindingSha.equals(proof.bindingSha),"typed exact helper retirement proof required");
        JSONObject callback=proof.callback();String nonce=callback.getString("request_nonce");
        byte[] reply=MobiMindPrivateFiles.read(new File(directory,"reply-"+nonce+".json"),65536,true).bytes;
        JSONObject record=WebEvidenceJson.parseEvidence(WebEvidenceReceipt.decode(reply),65536);
        need(Boolean.TRUE.equals(record.get("callback_verification_passed"))&&WebEvidenceReceipt.same(callback,WebEvidenceJson.parse(record.getString("callback_json_utf8"),WebEvidenceProtocol.MAX_CALLBACK_BYTES)),"persisted verified close reply differs");
        finish(new JSONObject().put("schema","hepta.web-controller-cleanup.v1").put("task_id",taskId).put("binding_sha256",bindingSha)
                .put("request_nonce",nonce).put("reply_file","reply-"+nonce+".json").put("reply_sha256",WebEvidenceJson.sha(reply))
                .put("retirement_verified",true).put("recovered_retirement",proof.recovered)
                .put("unstarted_retirement",proof.unstarted)
                .put("old_cleanup_methods_upgraded",false).put("business_verified",false));
    }
    synchronized void closeNeverAttached()throws Exception{
        current();need(!attachWasPrepared(),"an attach may already have been submitted");
        finish(new JSONObject().put("schema","hepta.web-controller-cleanup.v1").put("task_id",taskId).put("binding_sha256",bindingSha)
                .put("no_attach_request_prepared",true).put("retirement_verified",true).put("helper_resources_created_by_this_client",false)
                .put("business_verified",false));
    }
    private void finish(JSONObject proof)throws Exception{
        // A crash between the immutable receipt and marker unlink remains visible to explicit cleanup.
        proof.put("completed_elapsed_ms",SystemClock.elapsedRealtime());
        save("cleanup-"+UUID.randomUUID().toString()+".json",proof.toString().getBytes(StandardCharsets.UTF_8));
        MobiMindPrivateFiles.Read before=MobiMindPrivateFiles.read(active,65536,true);current();before.unchangedPath();
        need(active.delete(),"verified private web lease unlink failed");MobiMindPrivateFiles.syncDirectory(filesRoot.path);
    }
    private void save(String name,byte[] bytes)throws Exception{
        need(name.matches("[A-Za-z0-9_.-]+")&&!name.equals(".")&&!name.equals(".."),"fixed journal filename required");
        need(storedBytes+bytes.length<=WebEvidenceProtocol.MAX_FILES_BYTES,"web evidence storage budget exhausted");
        MobiMindPrivateFiles.writeNew(new File(directory,name),bytes);storedBytes+=bytes.length;
    }
    private long actualStoredBytes()throws Exception{
        String[] names=directory.list();need(names!=null&&names.length<=1024,"bounded journal files required");Arrays.sort(names);long total=0;
        for(String name:names){need(name.matches("[A-Za-z0-9_.-]+"),"unexpected journal entry");
            MobiMindPrivateFiles.Read file=MobiMindPrivateFiles.read(new File(directory,name),WebEvidenceProtocol.MAX_EVIDENCE_BYTES,true);
            total+=file.bytes.length;need(total<=WebEvidenceProtocol.MAX_FILES_BYTES,"journal byte budget");}
        return total;
    }
    private static void need(boolean ok,String why){WebEvidenceJson.need(ok,why);}
}
