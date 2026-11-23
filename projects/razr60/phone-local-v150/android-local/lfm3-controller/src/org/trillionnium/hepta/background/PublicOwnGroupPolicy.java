package org.trillionnium.hepta.background;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** Explicit experimental public display scope. These wire values are evidence,
 * never authority: the app must register a readback from its own root-peer RPC
 * in the exact live lease and independently read the public Display object. */
public final class PublicOwnGroupPolicy {
    public static final int REQUESTED_FLAGS=89417, ACTUAL_FLAGS=7040, DESTROY_CONTENT=1;
    public static final long MAX_PROOF_AGE_MS=1500, REFRESH_AFTER_MS=500;
    public static final String SCOPE_SCHEMA="hepta.public-own-group.scope.v1";
    public static final String READBACK_SCHEMA="hepta.public-own-group.readback.v2";
    private PublicOwnGroupPolicy(){}
    private static void need(boolean value,String reason){if(!value)throw new IllegalArgumentException(reason);}
    private static boolean label(String value,int limit){return value!=null&&!value.isEmpty()&&value.length()<=limit
            &&value.indexOf('\0')<0&&value.indexOf('\n')<0&&value.indexOf('\r')<0;}
    private static DataInputStream decode(String wire)throws IOException{
        need(wire!=null&&!wire.isEmpty()&&wire.length()<=16384&&wire.matches("[A-Za-z0-9_-]+"),"PUBLIC_SCOPE_WIRE_INVALID");
        return new DataInputStream(new ByteArrayInputStream(Base64.getUrlDecoder().decode(wire)));
    }
    private static String wire(byte[] bytes){return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}

    public static final class Scope {
        public final String taskId,ownerSha256,generation,targetSha256,sha256;
        public final int appUid,targetUserId,bootCount;
        public final long createdElapsedMs,expiresElapsedMs;
        private final byte[] canonical;
        public Scope(String task,String owner,String generation,int appUid,ProfileTarget target,
                long created,long expires,int boot){
            this(task,owner,generation,appUid,target==null?"":target.sha256,target==null?0:target.profile.userId,created,expires,boot);
        }
        private Scope(String task,String owner,String generation,int appUid,String targetSha,int targetUser,
                long created,long expires,int boot){
            need(task!=null&&task.matches("[0-9a-f]{32}")&&ProfileIdentity.hash(owner)&&ProfileIdentity.uuid(generation),"PUBLIC_SCOPE_IDENTITY_INVALID");
            need(appUid>=10000&&appUid<90000&&targetUser>=0&&((targetUser==0&&"".equals(targetSha))
                    ||(targetUser>=10&&ProfileIdentity.hash(targetSha))),"PUBLIC_SCOPE_USER_INVALID");
            need(created>=0&&expires>created&&expires-created<=BrokerProtocol.MAX_TTL_MS&&boot>=0,"PUBLIC_SCOPE_LIFETIME_INVALID");
            taskId=task;ownerSha256=owner;this.generation=generation;this.appUid=appUid;targetSha256=targetSha;
            targetUserId=targetUser;createdElapsedMs=created;expiresElapsedMs=expires;bootCount=boot;
            canonical=encode();sha256=ProfileIdentity.sha(canonical);
        }
        private byte[] encode(){try{
            ByteArrayOutputStream b=new ByteArrayOutputStream();DataOutputStream o=new DataOutputStream(b);
            for(String s:new String[]{SCOPE_SCHEMA,taskId,ownerSha256,generation,targetSha256})o.writeUTF(s);
            o.writeInt(appUid);o.writeInt(targetUserId);o.writeInt(bootCount);o.writeLong(createdElapsedMs);o.writeLong(expiresElapsedMs);
            o.flush();return b.toByteArray();
        }catch(IOException impossible){throw new IllegalStateException(impossible);}}
        public String wire(){return PublicOwnGroupPolicy.wire(canonical);}
        public static Scope fromWire(String wire){try{
            DataInputStream in=decode(wire);need(SCOPE_SCHEMA.equals(in.readUTF()),"PUBLIC_SCOPE_SCHEMA_INVALID");
            String task=in.readUTF(),owner=in.readUTF(),generation=in.readUTF(),target=in.readUTF();
            int uid=in.readInt(),user=in.readInt(),boot=in.readInt();long created=in.readLong(),expires=in.readLong();
            need(in.read()==-1,"PUBLIC_SCOPE_TRAILING_DATA");Scope value=new Scope(task,owner,generation,uid,target,user,created,expires,boot);
            need(value.wire().equals(wire),"PUBLIC_SCOPE_NONCANONICAL");return value;
        }catch(IOException invalid){throw new IllegalArgumentException("PUBLIC_SCOPE_TRUNCATED",invalid);}}
        public void requireConfig(int uid,String generation,long expires,ProfileTarget target){
            need(appUid==uid&&this.generation.equals(generation)&&expiresElapsedMs==expires
                    &&targetUserId==(target==null?0:target.profile.userId)
                    &&targetSha256.equals(target==null?"":target.sha256),"PUBLIC_SCOPE_CONFIG_MISMATCH");
        }
    }

    /** Values come from the real root process and real checkSelfPermission calls. */
    public static final class Privileges {
        public final int processUid,addTrusted,addAlwaysUnlocked,internalSystemWindow;
        public Privileges(int uid,int trusted,int always,int internal){
            need(uid==0&&trusted==0&&always==0&&internal==0,"PUBLIC_SCOPE_ROOT_PRIVILEGES_REQUIRED");
            processUid=uid;addTrusted=trusted;addAlwaysUnlocked=always;internalSystemWindow=internal;
        }
    }
    /** Unknown/failed Binder reads cannot be represented as an accepted state. */
    public static final class UserState {
        public final int userId,deviceId;
        public final boolean keyguardSecure,deviceSecure,deviceLocked;
        public UserState(int user,int device,boolean keyguardSecure,boolean deviceSecure,boolean deviceLocked){
            need(user>=0&&device==0&&!keyguardSecure&&!deviceSecure&&!deviceLocked,"PUBLIC_SCOPE_CREDENTIALS_NOT_INSECURE");
            userId=user;deviceId=device;this.keyguardSecure=keyguardSecure;this.deviceSecure=deviceSecure;this.deviceLocked=deviceLocked;
        }
    }
    public static final class Credentials {
        public final int currentUserId;
        public final boolean keyguardShowing;
        public final UserState owner,target;
        public Credentials(int currentUser,boolean showing,UserState owner,UserState target){
            need(currentUser==0&&owner!=null&&owner.userId==0&&target!=null,"PUBLIC_SCOPE_CURRENT_USER_INVALID");
            currentUserId=currentUser;keyguardShowing=showing;this.owner=owner;this.target=target;
        }
    }
    public static final class DisplayState {
        public final int displayId,flags,groupId,physical0GroupId,physical1GroupId,ownerUid,removeMode,destroyConstant,imeActual,imeHide;
        public final String name,uniqueId,ownerPackage;
        public DisplayState(int id,String name,String unique,int ownerUid,String ownerPackage,int flags,int group,int physical0Group,
                int physical1Group,int remove,int destroy,int imeActual,int imeHide){
            need(id>1&&label(name,128)&&label(unique,512)&&ownerUid==0&&"com.android.shell".equals(ownerPackage),"PUBLIC_SCOPE_DISPLAY_IDENTITY_INVALID");
            need(flags==ACTUAL_FLAGS&&group>0&&physical0Group>=0&&physical1Group>=0&&group!=physical0Group&&group!=physical1Group,
                    "PUBLIC_SCOPE_DISPLAY_FLAGS_GROUP_INVALID");
            need(remove==DESTROY_CONTENT&&destroy==DESTROY_CONTENT&&imeActual>=0&&imeHide>=0&&imeActual==imeHide,"PUBLIC_SCOPE_REMOVAL_IME_INVALID");
            displayId=id;this.name=name;uniqueId=unique;this.ownerUid=ownerUid;this.ownerPackage=ownerPackage;this.flags=flags;
            groupId=group;physical0GroupId=physical0Group;physical1GroupId=physical1Group;removeMode=remove;destroyConstant=destroy;
            this.imeActual=imeActual;this.imeHide=imeHide;
        }
        private boolean same(DisplayState other){return other!=null&&displayId==other.displayId&&name.equals(other.name)
                &&uniqueId.equals(other.uniqueId)&&ownerUid==other.ownerUid&&ownerPackage.equals(other.ownerPackage)&&flags==other.flags
                &&groupId==other.groupId
                &&removeMode==other.removeMode&&destroyConstant==other.destroyConstant&&imeActual==other.imeActual&&imeHide==other.imeHide;}
    }
    /** Immutable physical device identity is distinct from user-controlled
     * power, rotation, geometry, focus or keyguard-showing observations. */
    public static final class PhysicalDisplays {
        public final Map<Integer,String> stableDeviceIdentities,observedFacts;
        public PhysicalDisplays(Map<Integer,String> stable,Map<Integer,String> observed){
            need(stable!=null&&stable.size()==2&&ProfileIdentity.hash(stable.get(0))&&ProfileIdentity.hash(stable.get(1))
                    &&observed!=null&&observed.size()==2&&label(observed.get(0),1024)&&label(observed.get(1),1024),
                    "PUBLIC_SCOPE_PHYSICAL_DEVICE_IDENTITY_INVALID");
            Map<Integer,String> identity=new LinkedHashMap<Integer,String>(),facts=new LinkedHashMap<Integer,String>();
            for(int id:new int[]{0,1}){identity.put(id,stable.get(id));facts.put(id,observed.get(id));}
            stableDeviceIdentities=Collections.unmodifiableMap(identity);observedFacts=Collections.unmodifiableMap(facts);
        }
    }
    public static final class Readback {
        public final String scopeSha256,requestId,sha256;
        public final long observedStartedElapsedMs,observedEndedElapsedMs;
        public final Privileges privileges;public final Credentials credentials;public final DisplayState display;
        /** Stable id/uniqueId/type only. Runtime facts do not authorize input,
         * prove task/recents absence, or freeze the user's physical screens. */
        public final PhysicalDisplays physical;
        public final Map<Integer,String> physicalDeviceIdentities,physicalObservedFacts;
        private final byte[] canonical;
        public Readback(Scope scope,String request,long begin,long end,Privileges privileges,Credentials credentials,
                DisplayState display,PhysicalDisplays physical){
            need(scope!=null&&ProfileIdentity.uuid(request)&&privileges!=null&&credentials!=null&&display!=null,"PUBLIC_SCOPE_READBACK_INVALID");
            need(begin>=scope.createdElapsedMs&&end>=begin&&end-begin<=MAX_PROOF_AGE_MS&&end<scope.expiresElapsedMs,"PUBLIC_SCOPE_READBACK_CLOCK_INVALID");
            need(credentials.target.userId==scope.targetUserId&&display.name.equals("hepta-bg-"+scope.generation),"PUBLIC_SCOPE_READBACK_BINDING_INVALID");
            need(physical!=null,"PUBLIC_SCOPE_PHYSICAL_DEVICE_IDENTITY_INVALID");
            scopeSha256=scope.sha256;requestId=request;observedStartedElapsedMs=begin;observedEndedElapsedMs=end;
            this.privileges=privileges;this.credentials=credentials;this.display=display;
            this.physical=physical;physicalDeviceIdentities=physical.stableDeviceIdentities;physicalObservedFacts=physical.observedFacts;
            canonical=encode();sha256=ProfileIdentity.sha(canonical);
        }
        private byte[] encode(){try{
            ByteArrayOutputStream b=new ByteArrayOutputStream();DataOutputStream o=new DataOutputStream(b);
            o.writeUTF(READBACK_SCHEMA);o.writeUTF(scopeSha256);o.writeUTF(requestId);o.writeLong(observedStartedElapsedMs);o.writeLong(observedEndedElapsedMs);
            for(int i:new int[]{privileges.processUid,privileges.addTrusted,privileges.addAlwaysUnlocked,privileges.internalSystemWindow,
                    credentials.currentUserId})o.writeInt(i);
            o.writeBoolean(credentials.keyguardShowing);
            for(UserState u:new UserState[]{credentials.owner,credentials.target}){o.writeInt(u.userId);o.writeInt(u.deviceId);
                o.writeBoolean(u.keyguardSecure);o.writeBoolean(u.deviceSecure);o.writeBoolean(u.deviceLocked);}
            o.writeInt(display.displayId);o.writeUTF(display.name);o.writeUTF(display.uniqueId);o.writeUTF(display.ownerPackage);
            for(int i:new int[]{display.ownerUid,display.flags,display.groupId,display.physical0GroupId,display.physical1GroupId,
                    display.removeMode,display.destroyConstant,display.imeActual,display.imeHide})o.writeInt(i);
            for(int id:new int[]{0,1}){o.writeUTF(physicalDeviceIdentities.get(id));o.writeUTF(physicalObservedFacts.get(id));}
            o.flush();return b.toByteArray();
        }catch(IOException impossible){throw new IllegalStateException(impossible);}}
        public String wire(){return PublicOwnGroupPolicy.wire(canonical);}
        public static Readback fromWire(String wire,Scope scope){try{
            DataInputStream in=decode(wire);need(READBACK_SCHEMA.equals(in.readUTF())&&scope.sha256.equals(in.readUTF()),"PUBLIC_SCOPE_READBACK_SCHEMA_SCOPE_INVALID");
            String request=in.readUTF();long begin=in.readLong(),end=in.readLong();
            Privileges privileges=new Privileges(in.readInt(),in.readInt(),in.readInt(),in.readInt());
            int current=in.readInt();boolean showing=in.readBoolean();
            UserState owner=new UserState(in.readInt(),in.readInt(),in.readBoolean(),in.readBoolean(),in.readBoolean());
            UserState target=new UserState(in.readInt(),in.readInt(),in.readBoolean(),in.readBoolean(),in.readBoolean());
            Credentials credentials=new Credentials(current,showing,owner,target);
            int id=in.readInt();String name=in.readUTF(),unique=in.readUTF(),pkg=in.readUTF();
            DisplayState display=new DisplayState(id,name,unique,in.readInt(),pkg,in.readInt(),in.readInt(),in.readInt(),in.readInt(),
                    in.readInt(),in.readInt(),in.readInt(),in.readInt());
            Map<Integer,String> physical=new LinkedHashMap<Integer,String>(),facts=new LinkedHashMap<Integer,String>();
            for(int physicalId:new int[]{0,1}){physical.put(physicalId,in.readUTF());facts.put(physicalId,in.readUTF());}
            need(in.read()==-1,"PUBLIC_SCOPE_READBACK_TRAILING_DATA");Readback value=new Readback(scope,request,begin,end,privileges,credentials,display,new PhysicalDisplays(physical,facts));
            need(value.wire().equals(wire),"PUBLIC_SCOPE_READBACK_NONCANONICAL");return value;
        }catch(IOException invalid){throw new IllegalArgumentException("PUBLIC_SCOPE_READBACK_TRUNCATED",invalid);}}
        public void requireFresh(Scope scope,long now){need(scope.sha256.equals(scopeSha256)&&now>=observedEndedElapsedMs
                &&now-observedStartedElapsedMs<=MAX_PROOF_AGE_MS&&now<scope.expiresElapsedMs,"PUBLIC_SCOPE_READBACK_STALE");}
        public boolean sameLifetimeIdentity(Readback other){return other!=null&&scopeSha256.equals(other.scopeSha256)
                &&display.same(other.display)&&physicalDeviceIdentities.equals(other.physicalDeviceIdentities)
                &&credentials.currentUserId==other.credentials.currentUserId
                &&credentials.target.userId==other.credentials.target.userId;}
    }
    public static final class AppDisplay {
        public final int id,flags;public final String name;public final long begin,end;
        public AppDisplay(int id,String name,int flags,boolean valid,long begin,long end){
            need(valid&&id>1&&label(name,128)&&flags==ACTUAL_FLAGS&&begin>=0&&end>=begin,"PUBLIC_SCOPE_APP_DISPLAY_INVALID");
            this.id=id;this.name=name;this.flags=flags;this.begin=begin;this.end=end;
        }
    }
    /** In-memory registration only. The owning session keeps ownerToken private.
     * Serialized state cannot restore, renew or reactivate this lease. */
    public static final class LiveLease {
        private final Object ownerToken;public final Scope scope;
        private Readback first,current;private boolean retired;
        private final java.util.Set<String> receivedRequestIds=new java.util.LinkedHashSet<String>();
        public LiveLease(Object ownerToken,Scope scope){need(ownerToken!=null&&scope!=null,"PUBLIC_SCOPE_LIVE_OWNER_MISSING");this.ownerToken=ownerToken;this.scope=scope;}
        private void owner(Object token,long now){need(token==ownerToken&&!retired&&now>=scope.createdElapsedMs&&now<scope.expiresElapsedMs,"PUBLIC_SCOPE_LEASE_RETIRED");}
        public synchronized void registerRootRpc(Object token,Readback readback,int kernelPeerUid,String requestId,long requestBegan,long now,AppDisplay app){
            try{owner(token,now);need(kernelPeerUid==0&&readback!=null&&readback.requestId.equals(requestId)
                    &&readback.observedStartedElapsedMs>=requestBegan,"PUBLIC_SCOPE_RPC_PROVENANCE_INVALID");
                readback.requireFresh(scope,now);cross(readback,app,now);
                need(first==null||first.sameLifetimeIdentity(readback),"PUBLIC_SCOPE_LIFETIME_IDENTITY_CHANGED");
                need(current==null||readback.observedStartedElapsedMs>=current.observedEndedElapsedMs,"PUBLIC_SCOPE_READBACK_TIME_REVERSED");
                need(receivedRequestIds.size()<BrokerProtocol.MAX_PROFILE_REQUEST_IDS&&!receivedRequestIds.contains(requestId),"PUBLIC_SCOPE_REQUEST_REPLAY_OR_LIMIT");
                receivedRequestIds.add(requestId);if(first==null)first=readback;current=readback;
            }catch(RuntimeException refused){if(token==ownerToken){retired=true;current=null;}throw refused;}
        }
        private static void cross(Readback readback,AppDisplay app,long now){need(app!=null&&app.id==readback.display.displayId
                &&app.flags==readback.display.flags&&app.name.equals(readback.display.name)
                &&app.begin>=readback.observedEndedElapsedMs&&app.end<=now,"PUBLIC_SCOPE_APP_CROSSCHECK_INVALID");}
        public synchronized Readback current(Object token,long now,AppDisplay app){owner(token,now);
            need(current!=null,"PUBLIC_SCOPE_NO_AUTHENTICATED_READBACK");current.requireFresh(scope,now);cross(current,app,now);return current;}
        /** Scheduling-only identity check; never use its result to enter an effect. */
        public synchronized void requireAdmission(Object token,long now){owner(token,now);need(first!=null,"PUBLIC_SCOPE_NOT_STARTED");}
        public synchronized boolean refreshRequired(Object token,long now){owner(token,now);return current==null
                ||now<current.observedEndedElapsedMs||now-current.observedStartedElapsedMs>=REFRESH_AFTER_MS;}
        public synchronized void retire(Object token){need(token==ownerToken,"PUBLIC_SCOPE_OWNER_MISMATCH");retired=true;current=null;}
    }
}
