package org.trillionnium.hepta.local;

import android.content.Context;
import android.net.Credentials;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.Looper;
import android.os.SystemClock;
import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONObject;
import org.trillionnium.hepta.background.BrokerProtocol;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.PublicOwnGroupPolicy;
import org.trillionnium.hepta.background.PublicProfileBusinessAbsenceRecovery;

/** Ordinary recovery's cleanup-only client. It never promotes the broker reply
 * into a recovered lease; the independent current-absence checker still follows. */
final class RetainedProfileCleanupClient {
    static final String SCHEMA="hepta.retained-profile-cleanup-bootstrap.v1";
    private static final String KEYS="session-recovery/retained-cleanup-keys";
    private static final String CLAIMS="session-recovery/retained-cleanup-claims";
    private RetainedProfileCleanupClient(){}

    static final class Bootstrap {
        private final PublicOwnGroupPolicy.Scope scope;
        private final String nonce;
        final String tokenSha256,socketName,keyPath;
        private Bootstrap(PublicOwnGroupPolicy.Scope scope){
            if(scope==null||scope.targetUserId!=10)throw new IllegalArgumentException("独立清理仅适用于资料用户后台空间");
            this.scope=scope;byte[] random=new byte[32];new SecureRandom().nextBytes(random);
            StringBuilder text=new StringBuilder();for(byte value:random)text.append(String.format(java.util.Locale.ROOT,"%02x",value&255));
            Arrays.fill(random,(byte)0);nonce=text.toString();tokenSha256=sha(nonce.getBytes(StandardCharsets.UTF_8));
            socketName=BrokerProtocol.retainedCleanupSocket(scope.generation);keyPath=KEYS+"/"+scope.generation+".json";
        }
        void addJournalFields(JSONObject value)throws Exception{
            value.put("retained_cleanup_schema",SCHEMA).put("retained_cleanup_token_sha256",tokenSha256)
                    .put("retained_cleanup_socket",socketName).put("retained_cleanup_key_path",keyPath);
        }
        void persist(Context context,QualificationScopeConfig.FilesRoot root)throws Exception{
            root.unchanged(context);File recovery=MobiMindPrivateFiles.directory(new File(root.path,"session-recovery"),false);
            File keys=MobiMindPrivateFiles.directory(new File(recovery,"retained-cleanup-keys"),false);
            JSONObject key=new JSONObject().put("schema",SCHEMA).put("task_id",scope.taskId).put("generation",scope.generation)
                    .put("scope_sha256",scope.sha256).put("owner_sha256",scope.ownerSha256).put("owner_uid",scope.appUid)
                    .put("nonce",nonce).put("token_sha256",tokenSha256);
            File path=new File(keys,scope.generation+".json");byte[] bytes=key.toString().getBytes(StandardCharsets.UTF_8);
            MobiMindPrivateFiles.writeNew(path,bytes);MobiMindPrivateFiles.syncDirectory(keys);MobiMindPrivateFiles.syncDirectory(recovery);
            if(!Arrays.equals(bytes,MobiMindPrivateFiles.read(path,4096,true).bytes))throw new IOException("独立清理私有凭据读回不一致");
            root.unchanged(context);
        }
    }
    static Bootstrap create(PublicOwnGroupPolicy.Scope scope){return scope!=null&&scope.targetUserId==10?new Bootstrap(scope):null;}
    static boolean configured(JSONObject journal)throws Exception{
        String[] names={"retained_cleanup_schema","retained_cleanup_token_sha256","retained_cleanup_socket","retained_cleanup_key_path"};
        int count=0;for(String name:names)if(journal.has(name))count++;
        if(count==0)return false;
        String generation=string(journal,"generation");
        if(count!=names.length||!SCHEMA.equals(string(journal,names[0]))||!string(journal,names[1]).matches("[0-9a-f]{64}")
                ||!BrokerProtocol.retainedCleanupSocket(generation).equals(string(journal,names[2]))
                ||!(KEYS+"/"+generation+".json").equals(string(journal,names[3])))throw new IOException("独立清理凭据不完整或作用域不匹配");
        return true;
    }

    static void cleanupIfConfigured(Context context,MobiMindPrivateFiles.Read original,
            BackgroundSession.BusinessReconciliationCheck check,PublicProfileBusinessRecoveryClient.PreparedRetainedCleanup prepared)throws Exception{
        if(Looper.myLooper()==Looper.getMainLooper())throw new IOException("后台清理不得阻塞主线程");
        JSONObject journal=object(original.bytes);if(!configured(journal))return;
        if(check==null||prepared==null)throw new IOException("独立清理缺少原始模型退出与任务预约凭据");
        QualificationScopeConfig.FilesRoot root=new QualificationScopeConfig.FilesRoot(context);
        PublicProfileBusinessAbsenceRecovery.Request prior=prepared.request;
        if(!prior.retainedCurrentAbsenceRequired())return;
        String generation=string(journal,"generation"),task=string(journal,"task_id"),owner=string(journal,"owner_sha256");
        String commitment=string(journal,"retained_cleanup_token_sha256"),socketName=string(journal,"retained_cleanup_socket");
        PublicOwnGroupPolicy.Scope scope=PublicOwnGroupPolicy.Scope.fromWire(string(journal,"public_own_group_scope_wire"));
        ProfileTarget target=ProfileTarget.fromWire(string(journal,"profile_target_wire"));
        scope.requireConfig(android.os.Process.myUid(),generation,number(journal,"expires_elapsed_ms"),target);
        if(!prior.taskId.equals(task)||!prior.generation.equals(generation)||!prior.ownerSha256.equals(owner)
                ||!prior.journalSha256.equals(sha(original.bytes))||!prior.publicScope.sha256.equals(scope.sha256)
                ||prior.displayId!=number(journal,"display_id")||!prior.target.same(target))throw new IOException("独立清理原件与当前租约不一致");
        prepared.beforeEffect();check.checkBusiness(task,owner);root.unchanged(context);original.unchangedPath();
        File recovery=MobiMindPrivateFiles.directory(new File(root.path,"session-recovery"),false);
        File claims=MobiMindPrivateFiles.directory(new File(recovery,"retained-cleanup-claims"),false);
        File claimPath=new File(claims,generation+".json");
        if(MobiMindPrivateFiles.exists(claimPath)){
            // An interrupted or uncertain prior send is never replayed. The caller
            // may only proceed to its independent, read-only current-absence check.
            JSONObject claim=object(MobiMindPrivateFiles.read(claimPath,4096,true).bytes);
            if(!"hepta.retained-profile-cleanup-claim.v1".equals(string(claim,"schema"))||!task.equals(string(claim,"task_id"))
                    ||!generation.equals(string(claim,"generation"))||!scope.sha256.equals(string(claim,"scope_sha256"))
                    ||!commitment.equals(string(claim,"token_sha256"))||!prior.journalSha256.equals(string(claim,"journal_sha256")))
                throw new IOException("旧独立清理预约身份不一致，拒绝重放");
            prepared.afterEffect();return;
        }
        File keyFile=new File(root.path,string(journal,"retained_cleanup_key_path"));
        MobiMindPrivateFiles.Read keyRead=MobiMindPrivateFiles.read(keyFile,4096,true);JSONObject key=object(keyRead.bytes);
        String nonce=string(key,"nonce");
        if(key.length()!=8||!SCHEMA.equals(string(key,"schema"))||!task.equals(string(key,"task_id"))
                ||!generation.equals(string(key,"generation"))||!scope.sha256.equals(string(key,"scope_sha256"))
                ||!owner.equals(string(key,"owner_sha256"))||number(key,"owner_uid")!=android.os.Process.myUid()
                ||!nonce.matches("[0-9a-f]{64}")||!commitment.equals(string(key,"token_sha256"))
                ||!commitment.equals(sha(nonce.getBytes(StandardCharsets.UTF_8))))throw new IOException("独立清理私有凭据与原始后台实例不一致");
        long began=SystemClock.elapsedRealtime(),deadline=began+BrokerProtocol.RetainedCleanupRequest.LIMIT_MS;
        String requestId=UUID.randomUUID().toString();
        JSONObject wire=new JSONObject().put("version",1).put("op","cleanup_retained_profile").put("request_id",requestId)
                .put("generation",generation).put("task_id",task).put("display_scope_sha256",scope.sha256)
                .put("profile_target_sha256",target.sha256).put("nonce",nonce)
                .put("started_elapsed_ms",began).put("deadline_elapsed_ms",deadline);
        byte[] requestBytes=wire.toString().getBytes(StandardCharsets.UTF_8);
        // Parse the exact outbound bytes with the production strict vocabulary.
        BrokerProtocol.RetainedCleanupRequest request=BrokerProtocol.RetainedCleanupRequest.parse(requestBytes);
        File dir=MobiMindPrivateFiles.directory(new File(recovery,"retained-cleanup-"+requestId),true);
        byte[] archive=prepared.archiveBytes();byte[] manifest=PublicProfileBusinessAbsenceRecovery.canonical(prior.manifest.json()).getBytes(StandardCharsets.UTF_8);
        writeVerified(new File(dir,"originals.bin"),archive);writeVerified(new File(dir,"manifest.json"),manifest);
        JSONObject record=new JSONObject().put("schema","hepta.retained-profile-cleanup-request.v1").put("request",new JSONObject(request.evidence()))
                .put("request_bytes_sha256",sha(requestBytes)).put("token_sha256",commitment).put("journal_sha256",prior.journalSha256)
                .put("originals_sha256",sha(archive)).put("manifest_sha256",sha(manifest)).put("secret_archived",false)
                .put("business_resumed",false).put("original_result_rewritten",false);
        byte[] recordBytes=record.toString(2).getBytes(StandardCharsets.UTF_8);
        writeVerified(new File(dir,"request.json"),recordBytes);MobiMindPrivateFiles.syncDirectory(dir);
        MobiMindPrivateFiles.syncDirectory(recovery);
        boolean attempted=false;JSONObject reply=null;String failure=null;int peerPid=-1;
        final AtomicBoolean done=new AtomicBoolean();
        try(LocalSocket socket=new LocalSocket()){
            Thread closer=new Thread(()->{
                while(!done.get()&&SystemClock.elapsedRealtime()<deadline){
                    try{Thread.sleep(Math.min(50,Math.max(1,deadline-SystemClock.elapsedRealtime())));}catch(InterruptedException ignored){}
                }
                if(!done.get())closeSocket(socket);
            },"hepta-retained-cleanup-client-deadline");closer.setDaemon(true);closer.start();
            socket.connect(new LocalSocketAddress(socketName,LocalSocketAddress.Namespace.ABSTRACT));
            Credentials peer=socket.getPeerCredentials();
            if(peer==null||peer.getUid()!=0||peer.getPid()<=0)throw new IOException("独立清理服务不是真实 root 对端");peerPid=peer.getPid();
            timeout(socket,deadline);prepared.beforeEffect();keyRead.unchangedPath();original.unchangedPath();root.unchanged(context);
            check.checkBusiness(task,owner);
            JSONObject claim=new JSONObject().put("schema","hepta.retained-profile-cleanup-claim.v1").put("task_id",task)
                    .put("generation",generation).put("scope_sha256",scope.sha256).put("token_sha256",commitment)
                    .put("journal_sha256",prior.journalSha256).put("request_id",requestId).put("request_record_sha256",sha(recordBytes));
            writeVerified(claimPath,claim.toString().getBytes(StandardCharsets.UTF_8));MobiMindPrivateFiles.syncDirectory(claims);
            // The durable claim precedes the first possible byte. No catch path retries.
            timeout(socket,deadline);attempted=true;BrokerProtocol.writeFrame(socket.getOutputStream(),requestBytes);
            timeout(socket,deadline);DataInputStream input=new DataInputStream(socket.getInputStream());int size=input.readInt();
            if(size<=0||size>BrokerProtocol.MAX_RESPONSE)throw new IOException("独立清理回复长度无效");
            byte[] bytes=new byte[size];input.readFully(bytes);timeout(socket,deadline);reply=object(bytes);
            requireReply(reply,request,prior,deadline);
        }catch(Exception error){
            // This is only a cleanup attempt result. An unavailable old endpoint
            // or lost reply may still be followed by the independent read-only
            // checker; neither is interpreted as absence or permission to retry.
            failure=error.getMessage()==null?error.getClass().getSimpleName():error.getMessage();
        }
        finally{
            done.set(true);Arrays.fill(requestBytes,(byte)0);root.unchanged(context);
            JSONObject evidence=new JSONObject().put("schema","hepta.retained-profile-cleanup-client.v1")
                    .put("request_id",requestId).put("task_id",task).put("generation",generation).put("journal_sha256",prior.journalSha256)
                    .put("socket_peer_uid",peerPid>0?0:JSONObject.NULL).put("socket_peer_pid",peerPid>0?peerPid:JSONObject.NULL)
                    .put("request_bytes_attempted",attempted).put("request_replayed",false).put("finished_elapsed_ms",SystemClock.elapsedRealtime())
                    .put("response",reply==null?JSONObject.NULL:reply).put("failure",failure==null?JSONObject.NULL:failure)
                    .put("original_result_rewritten",false).put("independent_current_absence_still_required",true)
                    .put("lease_retired",false).put("control_session_acknowledged",false);
            writeVerified(new File(dir,"receipt.json"),evidence.toString(2).getBytes(StandardCharsets.UTF_8));
            MobiMindPrivateFiles.syncDirectory(dir);MobiMindPrivateFiles.syncDirectory(recovery);
        }
        prepared.afterEffect();
    }
    private static void requireReply(JSONObject value,BrokerProtocol.RetainedCleanupRequest expected,
            PublicProfileBusinessAbsenceRecovery.Request prior,long deadline)throws Exception{
        JSONObject request=value.getJSONObject("request"),interval=value.getJSONObject("interval");
        if(!"hepta.retained-profile-cleanup-attempt.v1".equals(string(value,"schema"))
                ||!PublicProfileBusinessAbsenceRecovery.canonical(request).equals(PublicProfileBusinessAbsenceRecovery.canonical(new JSONObject(expected.evidence())))
                ||!Boolean.TRUE.equals(value.get("claimed"))||!Boolean.TRUE.equals(value.get("entered"))||!Boolean.TRUE.equals(value.get("finished"))
                ||!Boolean.TRUE.equals(value.get("current_absence_verified"))||value.get("failure")!=JSONObject.NULL
                ||!Boolean.FALSE.equals(value.get("business_admission_restored"))||!Boolean.FALSE.equals(value.get("business_deadline_extended"))
                ||!Boolean.FALSE.equals(value.get("old_failure_rewritten"))||!Boolean.FALSE.equals(value.get("request_replayed"))
                ||number(value,"finished_elapsed_ms")<expected.started||number(value,"finished_elapsed_ms")>=deadline
                ||!"hepta.retained-profile-cleanup-interval.v1".equals(string(interval,"schema"))
                ||!prior.generation.equals(string(interval,"generation"))||!prior.target.sha256.equals(string(interval,"target_sha256"))
                ||prior.displayId!=number(interval,"display_id")||prior.ownedRootTaskId!=number(interval,"root_task_id")
                ||prior.ownedLeafTaskId!=number(interval,"leaf_task_id")||!Boolean.TRUE.equals(interval.get("current_tasks_absent"))
                ||!Boolean.TRUE.equals(interval.get("current_display_absent"))||!Boolean.TRUE.equals(interval.get("outside_live_tasks_unchanged"))
                ||!Boolean.FALSE.equals(interval.get("business_admission_restored"))||!Boolean.FALSE.equals(interval.get("old_failure_rewritten")))
            throw new IOException("独立清理回复未证明原始后台空间在新清理区间内释放");
    }
    private static void timeout(LocalSocket socket,long deadline)throws IOException{
        long remaining=deadline-SystemClock.elapsedRealtime();if(remaining<=0)throw new IOException("独立清理超过本次期限");
        socket.setSoTimeout((int)Math.min(Integer.MAX_VALUE,remaining));
    }
    private static void closeSocket(java.io.Closeable socket){try{socket.close();}catch(IOException ignored){}}
    private static void writeVerified(File path,byte[] bytes)throws Exception{
        MobiMindPrivateFiles.writeNew(path,bytes);
        if(!Arrays.equals(bytes,MobiMindPrivateFiles.read(path,bytes.length,true).bytes))throw new IOException("独立清理凭据持久读回不一致");
    }
    private static JSONObject object(byte[] bytes)throws Exception{return new JSONObject(new String(bytes,StandardCharsets.UTF_8));}
    private static String string(JSONObject value,String key)throws Exception{Object item=value.get(key);if(!(item instanceof String))throw new IOException("独立清理字段类型无效: "+key);return (String)item;}
    private static long number(JSONObject value,String key)throws Exception{Object item=value.get(key);if(!(item instanceof Integer)&&!(item instanceof Long))throw new IOException("独立清理整数类型无效: "+key);return ((Number)item).longValue();}
    private static String sha(byte[] bytes){return HeptaAccessibilityService.sha(bytes);}
}
