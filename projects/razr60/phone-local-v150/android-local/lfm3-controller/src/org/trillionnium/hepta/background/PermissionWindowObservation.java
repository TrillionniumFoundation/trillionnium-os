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
    public static final String PUBLIC_SCHEMA="hepta.profile-permission-window.v2";
    /** Read-only topology, not a task/input capability. V1's complete physical
     * fingerprints remain unchanged and V2 carries those same audit fields.
     * Only V2 additionally compares this public lease's actual stable scope.
     * The private PermissionRead below supplies the root/leaf/permission binding. */
    public static final class PublicInitialization {
        public static final String SCHEMA="hepta.public-profile-initialization-ownership.v1";
        public final String sha256;
        private final PublicOwnGroupPolicy.Scope scope;
        private final ProfileTarget target;
        private final PublicOwnGroupPolicy.DisplayState display;
        private final Map<Integer,String> devices;
        private final byte[] canonical;
        private PublicInitialization(PublicOwnGroupPolicy.Scope scope,ProfileTarget target,
                PublicOwnGroupPolicy.DisplayState display,Map<Integer,String> devices){
            ProfileIdentity.need(scope!=null&&target!=null&&display!=null&&devices!=null
                    &&scope.targetUserId==target.profile.userId&&scope.targetSha256.equals(target.sha256)
                    &&scope.targetUserId>0&&display.displayId>1&&display.name.equals("hepta-bg-"+scope.generation)
                    &&devices.size()==2&&devices.containsKey(0)&&devices.containsKey(1)
                    &&ProfileIdentity.hash(devices.get(0))&&ProfileIdentity.hash(devices.get(1))
                    &&!devices.get(0).equals(devices.get(1)),"PERMISSION_PUBLIC_PROJECTION_INVALID");
            this.scope=scope;this.target=target;this.display=display;
            Map<Integer,String> copy=new LinkedHashMap<Integer,String>();for(int id:new int[]{0,1})copy.put(id,devices.get(id));
            this.devices=Collections.unmodifiableMap(copy);canonical=encode();sha256=ProfileIdentity.sha(canonical);
        }
        /** The caller must already own this actual broker/App RPC readback. This
         * value alone never establishes its provenance or authorizes an effect. */
        public static PublicInitialization fromReadback(PublicOwnGroupPolicy.Scope scope,ProfileTarget target,
                PublicOwnGroupPolicy.Readback actual,long now){
            ProfileIdentity.need(actual!=null,"PERMISSION_PUBLIC_READBACK_MISSING");actual.requireFresh(scope,now);
            return new PublicInitialization(scope,target,actual.display,actual.physicalDeviceIdentities);
        }
        private byte[] encode(){
            try{ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
                out.writeUTF(SCHEMA);out.writeUTF(scope.wire());out.writeUTF(target.sha256);out.writeInt(target.fullUid);
                out.writeInt(display.displayId);out.writeUTF(display.name);out.writeUTF(display.uniqueId);out.writeUTF(display.ownerPackage);
                for(int value:new int[]{display.ownerUid,display.flags,display.groupId,display.physical0GroupId,display.physical1GroupId,
                        display.removeMode,display.destroyConstant,display.imeActual,display.imeHide})out.writeInt(value);
                for(int id:new int[]{0,1})out.writeUTF(devices.get(id));out.flush();return bytes.toByteArray();
            }catch(java.io.IOException impossible){throw new IllegalStateException(impossible);}
        }
        public String wire(){return Base64.getUrlEncoder().withoutPadding().encodeToString(canonical);}
        private static PublicInitialization fromWire(String wire,ProfileTarget target){
            ProfileIdentity.need(wire!=null&&!wire.isEmpty()&&wire.length()<=8192&&wire.matches("[A-Za-z0-9_-]+"),"PERMISSION_PUBLIC_PROJECTION_WIRE_INVALID");
            try{DataInputStream in=new DataInputStream(new ByteArrayInputStream(Base64.getUrlDecoder().decode(wire)));
                ProfileIdentity.need(SCHEMA.equals(in.readUTF()),"PERMISSION_PUBLIC_PROJECTION_SCHEMA");
                PublicOwnGroupPolicy.Scope scope=PublicOwnGroupPolicy.Scope.fromWire(in.readUTF());
                ProfileIdentity.need(target!=null&&target.sha256.equals(in.readUTF())&&target.fullUid==in.readInt(),"PERMISSION_PUBLIC_PROJECTION_TARGET");
                int id=in.readInt();String name=in.readUTF(),unique=in.readUTF(),owner=in.readUTF();
                PublicOwnGroupPolicy.DisplayState display=new PublicOwnGroupPolicy.DisplayState(id,name,unique,in.readInt(),owner,
                        in.readInt(),in.readInt(),in.readInt(),in.readInt(),in.readInt(),in.readInt(),in.readInt(),in.readInt());
                Map<Integer,String> devices=new LinkedHashMap<Integer,String>();for(int physical:new int[]{0,1})devices.put(physical,in.readUTF());
                ProfileIdentity.need(in.read()==-1,"PERMISSION_PUBLIC_PROJECTION_TRAILING_DATA");
                PublicInitialization value=new PublicInitialization(scope,target,display,devices);
                ProfileIdentity.need(value.wire().equals(wire),"PERMISSION_PUBLIC_PROJECTION_NONCANONICAL");return value;
            }catch(java.io.IOException invalid){throw new IllegalArgumentException("PERMISSION_PUBLIC_PROJECTION_TRUNCATED",invalid);}
        }
        public boolean same(PublicInitialization other){return other!=null&&java.util.Arrays.equals(canonical,other.canonical);}
        private void requirePermission(ProfileTarget actual,String generation,int ownedDisplay){
            ProfileIdentity.need(target.same(actual)&&scope.generation.equals(generation)&&display.displayId==ownedDisplay,
                    "PERMISSION_PUBLIC_PROJECTION_SCOPE_CHANGED");
        }
        public void requireReadback(PublicOwnGroupPolicy.Scope expected,ProfileTarget actual,PublicOwnGroupPolicy.Readback readback,long now){
            ProfileIdentity.need(same(fromReadback(expected,actual,readback,now)),"PERMISSION_PUBLIC_PROJECTION_READBACK_CHANGED");
        }
        public Map<String,Object> evidence(){
            Map<String,Object> e=new LinkedHashMap<String,Object>();e.put("schema",SCHEMA);e.put("scope_sha256",scope.sha256);
            e.put("generation",scope.generation);e.put("target_sha256",target.sha256);e.put("user_id",target.profile.userId);e.put("full_uid",target.fullUid);
            e.put("display_id",display.displayId);e.put("display_name",display.name);e.put("display_unique_id",display.uniqueId);
            e.put("owner_uid",display.ownerUid);e.put("owner_package",display.ownerPackage);e.put("flags",display.flags);
            e.put("display_group_id",display.groupId);e.put("physical_0_group_id",display.physical0GroupId);e.put("physical_1_group_id",display.physical1GroupId);
            e.put("physical_device_identities",physicalEvidence(devices));e.put("sha256",sha256);e.put("serialized_evidence_is_authority",false);
            e.put("physical_user_activity_frozen",false);return Collections.unmodifiableMap(e);
        }
    }
    public final ProfileTarget target;
    public final String schema;
    public final String generation,targetSha256,proofId,leafTokenId,activityRecord,resultToActivityRecord;
    public final String systemApkSha256,systemSignerSha256,activitiesSha256,sha256;
    public final int displayId,windowId,rootTaskId,taskId,userId,fullUid,permissionUid;
    public final long userSerial,observedElapsedMs,expiresElapsedMs;
    public final Map<Integer,String> physicalIdentities;
    private final PublicInitialization publicInitialization;
    private final byte[] canonical;

    private PermissionWindowObservation(ProfileTarget target,String generation,String proofId,String leafTokenId,
            int display,int window,int root,int task,int permissionUid,String activity,String resultTo,
            String apk,String signer,String activities,long at,long expiry,Map<Integer,String> physical){
        this(target,generation,proofId,leafTokenId,display,window,root,task,permissionUid,activity,resultTo,apk,signer,activities,at,expiry,physical,null);
    }
    private PermissionWindowObservation(ProfileTarget target,String generation,String proofId,String leafTokenId,
            int display,int window,int root,int task,int permissionUid,String activity,String resultTo,
            String apk,String signer,String activities,long at,long expiry,Map<Integer,String> physical,PublicInitialization publicInitialization){
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
        this.publicInitialization=publicInitialization;schema=publicInitialization==null?SCHEMA:PUBLIC_SCHEMA;
        if(publicInitialization!=null)publicInitialization.requirePermission(target,generation,display);
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
    static PermissionWindowObservation fromLive(ProfileOwnedTask.PermissionRead read,Map<Integer,String> physical,
            PublicInitialization projection,long now)throws Exception{
        ProfileIdentity.need(projection!=null,"PERMISSION_PUBLIC_PROJECTION_MISSING");
        read.requireFresh(now);Map<String,Object> source=read.evidence();
        return new PermissionWindowObservation(read.target,read.generation,UUID.randomUUID().toString(),read.leafTokenId,
                read.displayId,read.windowId,read.rootTaskId,read.taskId,read.permissionUid,read.activityRecord,read.resultToActivityRecord,
                (String)source.get("system_apk_sha256"),(String)source.get("system_signer_sha256"),(String)source.get("activities_sha256"),
                read.observedElapsedMs,read.expiresElapsedMs,physical,projection);
    }
    private static boolean label(String s){return s!=null&&s.matches("[A-Za-z0-9_]{1,128}");}
    /** Android JSONObject(Map) casts every key to String, including wrapped
     * nested maps. This changes only the JSON boundary, never V1/V2 wire data. */
    private static Map<String,String> physicalEvidence(Map<Integer,String> source){
        Map<String,String> value=new LinkedHashMap<String,String>();for(int id:new int[]{0,1})value.put(Integer.toString(id),source.get(id));
        return Collections.unmodifiableMap(value);
    }
    private byte[] encode(){
        try{ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
            for(String s:new String[]{schema,generation,targetSha256,proofId,leafTokenId,activityRecord,resultToActivityRecord,
                    systemApkSha256,systemSignerSha256,activitiesSha256})out.writeUTF(s);
            for(int i:new int[]{displayId,windowId,rootTaskId,taskId,userId,fullUid,permissionUid})out.writeInt(i);
            out.writeLong(userSerial);out.writeLong(observedElapsedMs);out.writeLong(expiresElapsedMs);
            out.writeUTF(physicalIdentities.get(0));out.writeUTF(physicalIdentities.get(1));
            if(publicInitialization!=null)out.writeUTF(publicInitialization.wire());out.flush();return bytes.toByteArray();
        }catch(java.io.IOException impossible){throw new IllegalStateException(impossible);}
    }
    public String wire(){return Base64.getUrlEncoder().withoutPadding().encodeToString(canonical);}
    public static PermissionWindowObservation fromWire(String wire,ProfileTarget target){
        ProfileIdentity.need(target!=null&&wire!=null&&!wire.isEmpty()&&wire.length()<=8192&&wire.matches("[A-Za-z0-9_-]+"),"PERMISSION_READ_WIRE_INVALID");
        try{DataInputStream in=new DataInputStream(new ByteArrayInputStream(Base64.getUrlDecoder().decode(wire)));
            String schema=in.readUTF();ProfileIdentity.need(SCHEMA.equals(schema)||PUBLIC_SCHEMA.equals(schema),"PERMISSION_READ_SCHEMA_INVALID");
            String gen=in.readUTF(),targetSha=in.readUTF(),proof=in.readUTF(),token=in.readUTF(),activity=in.readUTF(),result=in.readUTF();
            String apk=in.readUTF(),signer=in.readUTF(),activities=in.readUTF();
            int display=in.readInt(),window=in.readInt(),root=in.readInt(),task=in.readInt(),user=in.readInt(),uid=in.readInt(),pcUid=in.readInt();
            long serial=in.readLong(),at=in.readLong(),expiry=in.readLong();
            Map<Integer,String> physical=new LinkedHashMap<Integer,String>();physical.put(0,in.readUTF());physical.put(1,in.readUTF());
            PublicInitialization projection=PUBLIC_SCHEMA.equals(schema)?PublicInitialization.fromWire(in.readUTF(),target):null;
            ProfileIdentity.need(in.read()==-1&&target.sha256.equals(targetSha)&&user==target.profile.userId&&uid==target.fullUid
                    &&serial==target.profile.serial,"PERMISSION_READ_WIRE_TARGET_MISMATCH");
            PermissionWindowObservation value=new PermissionWindowObservation(target,gen,proof,token,display,window,root,task,pcUid,
                    activity,result,apk,signer,activities,at,expiry,physical,projection);
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
    /** Equality of the admitted physical scope; complete physical audit bytes
     * remain bound to each individual wire but unrelated user-0 UI may evolve. */
    public boolean samePhysicalScope(PermissionWindowObservation other){return other!=null&&schema.equals(other.schema)
            &&(publicInitialization==null?physicalIdentities.equals(other.physicalIdentities):publicInitialization.same(other.publicInitialization));}
    public void requireMode(PublicOwnGroupPolicy.Scope scope,PublicOwnGroupPolicy.Readback readback,long now){
        if(scope==null)ProfileIdentity.need(SCHEMA.equals(schema)&&publicInitialization==null,"PERMISSION_LEGACY_PROJECTION_MODE");
        else{
            ProfileIdentity.need(PUBLIC_SCHEMA.equals(schema)&&publicInitialization!=null,"PERMISSION_PUBLIC_PROJECTION_REQUIRED");
            publicInitialization.requirePermission(target,generation,displayId);publicInitialization.requireReadback(scope,target,readback,now);
        }
    }
    public Map<String,Object> evidence(){
        Map<String,Object> e=new LinkedHashMap<String,Object>();e.put("schema",schema);e.put("generation",generation);e.put("target_sha256",targetSha256);
        e.put("proof_id",proofId);e.put("leaf_token_id",leafTokenId);e.put("display_id",displayId);e.put("window_id",windowId);
        e.put("root_task_id",rootTaskId);e.put("task_id",taskId);e.put("user_id",userId);e.put("user_serial",userSerial);
        e.put("requester_uid",fullUid);e.put("permission_uid",permissionUid);e.put("activity_record",activityRecord);e.put("result_to_activity_record",resultToActivityRecord);
        e.put("system_apk_sha256",systemApkSha256);e.put("system_signer_sha256",systemSignerSha256);e.put("activities_sha256",activitiesSha256);
        e.put("observed_elapsed_ms",observedElapsedMs);e.put("expires_elapsed_ms",expiresElapsedMs);e.put("physical_identities",physicalEvidence(physicalIdentities));
        if(publicInitialization!=null){e.put("public_initialization_projection",publicInitialization.evidence());e.put("physical_audit_controls_admission",false);}
        e.put("sha256",sha256);e.put("business_observation_allowed",false);e.put("permission_input_allowed",false);
        e.put("serialized_evidence_is_authority",false);return Collections.unmodifiableMap(e);
    }
}
