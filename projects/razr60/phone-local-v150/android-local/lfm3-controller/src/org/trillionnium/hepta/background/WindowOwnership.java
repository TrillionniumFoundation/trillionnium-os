package org.trillionnium.hepta.background;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** Bounded readback evidence. A serialized value is not a Binder token or an action permit. */
public final class WindowOwnership {
    public static final String SCHEMA="hepta.profile-window-ownership.v1";
    public static final String SOURCE="observed_accessibility_task_id_and_fresh_privileged_leaf";
    public final String generation,targetSha256,proofId,taskTokenId,sha256;
    public final int displayId,windowId,taskId,parentTaskId,userId,fullUid;
    public final long userSerial,observedElapsedMs,expiresElapsedMs;
    private final byte[] canonical;
    /** Producer supplies actual leaf user/UID/serial and its retained token identifier. */
    public WindowOwnership(ProfileTarget target,String generation,int displayId,int windowId,
            int taskId,int parentTaskId,String taskTokenId,String proofId,int actualUserId,
            long actualUserSerial,int actualFullUid,long observedElapsedMs,long expiresElapsedMs){
        ProfileIdentity.need(target!=null&&ProfileIdentity.uuid(generation)&&ProfileIdentity.uuid(taskTokenId)
                &&ProfileIdentity.uuid(proofId),"PROFILE_WINDOW_IDENTITY_INVALID");
        ProfileIdentity.need(displayId>0&&windowId>=0&&taskId>0&&parentTaskId>0&&parentTaskId!=taskId,"PROFILE_WINDOW_TASK_INVALID");
        ProfileIdentity.need(actualUserId==target.profile.userId&&actualUserSerial==target.profile.serial
                &&actualFullUid==target.fullUid,"PROFILE_WINDOW_USER_MISMATCH");
        ProfileIdentity.need(observedElapsedMs>=0&&expiresElapsedMs>observedElapsedMs
                &&expiresElapsedMs-observedElapsedMs<=10000,"PROFILE_WINDOW_LIFETIME_INVALID");
        this.generation=generation;targetSha256=target.sha256;this.displayId=displayId;this.windowId=windowId;
        this.taskId=taskId;this.parentTaskId=parentTaskId;this.taskTokenId=taskTokenId;this.proofId=proofId;
        userId=actualUserId;userSerial=actualUserSerial;fullUid=actualFullUid;
        this.observedElapsedMs=observedElapsedMs;this.expiresElapsedMs=expiresElapsedMs;
        canonical=encode();sha256=ProfileIdentity.sha(canonical);
    }
    private byte[] encode(){
        try{ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
            out.writeUTF(SCHEMA);out.writeUTF(generation);out.writeUTF(targetSha256);out.writeUTF(proofId);out.writeUTF(taskTokenId);
            out.writeInt(displayId);out.writeInt(windowId);out.writeInt(taskId);out.writeInt(parentTaskId);out.writeInt(userId);
            out.writeLong(userSerial);out.writeInt(fullUid);out.writeLong(observedElapsedMs);out.writeLong(expiresElapsedMs);
            out.flush();return bytes.toByteArray();
        }catch(java.io.IOException impossible){throw new IllegalStateException(impossible);}
    }
    public String wire(){return Base64.getUrlEncoder().withoutPadding().encodeToString(canonical);}
    public static WindowOwnership fromWire(String wire,ProfileTarget target){
        ProfileIdentity.need(target!=null&&wire!=null&&!wire.isEmpty()&&wire.length()<=4096
                &&wire.matches("[A-Za-z0-9_-]+"),"PROFILE_WINDOW_WIRE_INVALID");
        try{DataInputStream in=new DataInputStream(new ByteArrayInputStream(Base64.getUrlDecoder().decode(wire)));
            ProfileIdentity.need(SCHEMA.equals(in.readUTF()),"PROFILE_WINDOW_SCHEMA_INVALID");
            String generation=in.readUTF(),sha=in.readUTF(),proof=in.readUTF(),token=in.readUTF();
            ProfileIdentity.need(target.sha256.equals(sha),"PROFILE_WINDOW_TARGET_MISMATCH");
            int display=in.readInt(),window=in.readInt(),task=in.readInt(),parent=in.readInt(),user=in.readInt();
            long serial=in.readLong();int uid=in.readInt();long at=in.readLong(),expiry=in.readLong();
            ProfileIdentity.need(in.read()==-1,"PROFILE_WINDOW_TRAILING_DATA");
            WindowOwnership result=new WindowOwnership(target,generation,display,window,task,parent,token,proof,user,serial,uid,at,expiry);
            ProfileIdentity.need(result.wire().equals(wire),"PROFILE_WINDOW_WIRE_NONCANONICAL");return result;
        }catch(java.io.IOException invalid){throw new IllegalArgumentException("PROFILE_WINDOW_WIRE_TRUNCATED",invalid);}
    }
    public void requireMatches(ProfileTarget target,String generation,int display,int window,int observedTask,long now){
        ProfileIdentity.need(target!=null&&target.sha256.equals(targetSha256)&&target.profile.userId==userId
                &&target.profile.serial==userSerial&&target.fullUid==fullUid&&this.generation.equals(generation)
                &&displayId==display&&windowId==window&&taskId==observedTask&&now>=observedElapsedMs&&now<expiresElapsedMs,
                "PROFILE_WINDOW_PROOF_STALE_OR_DIFFERENT");
    }
    public Map<String,Object> evidence(){
        Map<String,Object> v=new LinkedHashMap<String,Object>();v.put("schema",SCHEMA);v.put("source",SOURCE);
        v.put("generation",generation);v.put("target_identity_sha256",targetSha256);v.put("proof_id",proofId);v.put("task_token_id",taskTokenId);
        v.put("display_id",displayId);v.put("window_id",windowId);v.put("task_id",taskId);v.put("parent_task_id",parentTaskId);
        v.put("user_id",userId);v.put("user_serial",userSerial);v.put("full_uid",fullUid);v.put("observed_elapsed_ms",observedElapsedMs);
        v.put("expires_elapsed_ms",expiresElapsedMs);v.put("proof_sha256",sha256);
        v.put("serialized_token_is_authority",false);v.put("grants_action_authority",false);return Collections.unmodifiableMap(v);
    }
}
