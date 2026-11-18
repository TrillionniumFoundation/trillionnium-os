package org.trillionnium.hepta.background;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/** Read-only RPC evidence. Decoding does not authorize a click: the client must
 * retain and check the actual object received through its live authenticated RPC.
 * This value can never be substituted for ordinary WindowOwnership. */
public final class PermissionWindowObservation {
    public static final String SCHEMA="hepta.profile-permission-window.v1";
    public final ProfileTarget target;
    public final String generation,targetSha256,proofId,leafTokenId,activityRecord,resultToActivityRecord;
    public final String systemApkSha256,systemSignerSha256,activitiesSha256,sha256;
    public final int displayId,windowId,rootTaskId,taskId,userId,fullUid,permissionUid;
    public final long userSerial,observedElapsedMs,expiresElapsedMs;
    public final Map<Integer,String> physicalIdentities;
    private final byte[] canonical;

    private PermissionWindowObservation(ProfileTarget target,String generation,String proofId,String leafTokenId,
            int display,int window,int root,int task,int permissionUid,String activity,String resultTo,
            String apk,String signer,String activities,long at,long expiry,Map<Integer,String> physical){
        ProfileIdentity.need(target!=null&&ProfileIdentity.uuid(generation)&&ProfileIdentity.uuid(proofId)
                &&ProfileIdentity.uuid(leafTokenId),"PERMISSION_READ_IDENTITY_INVALID");
        ProfileIdentity.need(display>1&&window>=0&&root>0&&task>0&&root!=task,"PERMISSION_READ_TASK_INVALID");
        ProfileIdentity.need(permissionUid/100000==target.profile.userId&&permissionUid!=target.fullUid
                &&permissionUid%100000>=1000,"PERMISSION_READ_SYSTEM_UID_INVALID");
        ProfileIdentity.need(label(activity)&&label(resultTo)&&!activity.equals(resultTo)
                &&ProfileIdentity.hash(apk)&&ProfileIdentity.hash(signer)&&ProfileIdentity.hash(activities),"PERMISSION_READ_SOURCE_INVALID");
        ProfileIdentity.need(at>=0&&expiry>at&&expiry-at<=ProfilePermissionTransient.MAX_AGE_MS,"PERMISSION_READ_LIFETIME_INVALID");
        ProfileIdentity.need(physical!=null&&physical.size()==2&&physical.containsKey(0)&&physical.containsKey(1)
                &&ProfileIdentity.hash(physical.get(0))&&ProfileIdentity.hash(physical.get(1)),"PERMISSION_READ_PHYSICAL_FENCE_INVALID");
        this.target=target;this.generation=generation;targetSha256=target.sha256;this.proofId=proofId;this.leafTokenId=leafTokenId;
        displayId=display;windowId=window;rootTaskId=root;taskId=task;this.permissionUid=permissionUid;
        activityRecord=activity;resultToActivityRecord=resultTo;systemApkSha256=apk;systemSignerSha256=signer;activitiesSha256=activities;
        userId=target.profile.userId;userSerial=target.profile.serial;fullUid=target.fullUid;observedElapsedMs=at;expiresElapsedMs=expiry;
        Map<Integer,String> copy=new LinkedHashMap<Integer,String>();copy.put(0,physical.get(0));copy.put(1,physical.get(1));
        physicalIdentities=Collections.unmodifiableMap(copy);canonical=encode();sha256=ProfileIdentity.sha(canonical);
    }
    static PermissionWindowObservation fromLive(ProfileOwnedTask.PermissionRead read,Map<Integer,String> physical,long now)throws Exception{
        read.requireFresh(now);Map<String,Object> source=read.evidence();
        return new PermissionWindowObservation(read.target,read.generation,UUID.randomUUID().toString(),read.leafTokenId,
                read.displayId,read.windowId,read.rootTaskId,read.taskId,read.permissionUid,read.activityRecord,read.resultToActivityRecord,
                (String)source.get("system_apk_sha256"),(String)source.get("system_signer_sha256"),(String)source.get("activities_sha256"),
                read.observedElapsedMs,read.expiresElapsedMs,physical);
    }
    private static boolean label(String s){return s!=null&&s.matches("[A-Za-z0-9_]{1,128}");}
    private byte[] encode(){
        try{ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
            for(String s:new String[]{SCHEMA,generation,targetSha256,proofId,leafTokenId,activityRecord,resultToActivityRecord,
                    systemApkSha256,systemSignerSha256,activitiesSha256})out.writeUTF(s);
            for(int i:new int[]{displayId,windowId,rootTaskId,taskId,userId,fullUid,permissionUid})out.writeInt(i);
            out.writeLong(userSerial);out.writeLong(observedElapsedMs);out.writeLong(expiresElapsedMs);
            out.writeUTF(physicalIdentities.get(0));out.writeUTF(physicalIdentities.get(1));out.flush();return bytes.toByteArray();
        }catch(java.io.IOException impossible){throw new IllegalStateException(impossible);}
    }
    public String wire(){return Base64.getUrlEncoder().withoutPadding().encodeToString(canonical);}
    public static PermissionWindowObservation fromWire(String wire,ProfileTarget target){
        ProfileIdentity.need(target!=null&&wire!=null&&!wire.isEmpty()&&wire.length()<=8192&&wire.matches("[A-Za-z0-9_-]+"),"PERMISSION_READ_WIRE_INVALID");
        try{DataInputStream in=new DataInputStream(new ByteArrayInputStream(Base64.getUrlDecoder().decode(wire)));
            ProfileIdentity.need(SCHEMA.equals(in.readUTF()),"PERMISSION_READ_SCHEMA_INVALID");
            String gen=in.readUTF(),targetSha=in.readUTF(),proof=in.readUTF(),token=in.readUTF(),activity=in.readUTF(),result=in.readUTF();
            String apk=in.readUTF(),signer=in.readUTF(),activities=in.readUTF();
            int display=in.readInt(),window=in.readInt(),root=in.readInt(),task=in.readInt(),user=in.readInt(),uid=in.readInt(),pcUid=in.readInt();
            long serial=in.readLong(),at=in.readLong(),expiry=in.readLong();
            Map<Integer,String> physical=new LinkedHashMap<Integer,String>();physical.put(0,in.readUTF());physical.put(1,in.readUTF());
            ProfileIdentity.need(in.read()==-1&&target.sha256.equals(targetSha)&&user==target.profile.userId&&uid==target.fullUid
                    &&serial==target.profile.serial,"PERMISSION_READ_WIRE_TARGET_MISMATCH");
            PermissionWindowObservation value=new PermissionWindowObservation(target,gen,proof,token,display,window,root,task,pcUid,
                    activity,result,apk,signer,activities,at,expiry,physical);
            ProfileIdentity.need(value.wire().equals(wire),"PERMISSION_READ_WIRE_NONCANONICAL");return value;
        }catch(java.io.IOException invalid){throw new IllegalArgumentException("PERMISSION_READ_WIRE_TRUNCATED",invalid);}
    }
    public void requireFresh(long now){ProfileIdentity.need(now>=observedElapsedMs&&now<expiresElapsedMs,"PROFILE_PERMISSION_READ_STALE");}
    public void requireMatches(ProfileTarget target,String generation,int display,int window,int task,long now){
        requireFresh(now);ProfileIdentity.need(this.target.same(target)&&this.generation.equals(generation)&&displayId==display
                &&windowId==window&&taskId==task,"PERMISSION_READ_SCOPE_CHANGED");
    }
    public boolean sameOwnedTask(PermissionWindowObservation other){return other!=null&&target.same(other.target)
            &&generation.equals(other.generation)&&displayId==other.displayId&&rootTaskId==other.rootTaskId&&taskId==other.taskId
            &&leafTokenId.equals(other.leafTokenId);}
    public boolean sameRequest(PermissionWindowObservation other){return sameOwnedTask(other)&&windowId==other.windowId
            &&permissionUid==other.permissionUid&&activityRecord.equals(other.activityRecord)&&resultToActivityRecord.equals(other.resultToActivityRecord)
            &&systemApkSha256.equals(other.systemApkSha256)&&systemSignerSha256.equals(other.systemSignerSha256);}
    public Map<String,Object> evidence(){
        Map<String,Object> e=new LinkedHashMap<String,Object>();e.put("schema",SCHEMA);e.put("generation",generation);e.put("target_sha256",targetSha256);
        e.put("proof_id",proofId);e.put("leaf_token_id",leafTokenId);e.put("display_id",displayId);e.put("window_id",windowId);
        e.put("root_task_id",rootTaskId);e.put("task_id",taskId);e.put("user_id",userId);e.put("user_serial",userSerial);
        e.put("requester_uid",fullUid);e.put("permission_uid",permissionUid);e.put("activity_record",activityRecord);e.put("result_to_activity_record",resultToActivityRecord);
        e.put("system_apk_sha256",systemApkSha256);e.put("system_signer_sha256",systemSignerSha256);e.put("activities_sha256",activitiesSha256);
        e.put("observed_elapsed_ms",observedElapsedMs);e.put("expires_elapsed_ms",expiresElapsedMs);e.put("physical_identities",physicalIdentities);
        e.put("sha256",sha256);e.put("business_observation_allowed",false);e.put("permission_input_allowed",false);
        e.put("serialized_evidence_is_authority",false);return Collections.unmodifiableMap(e);
    }
}
