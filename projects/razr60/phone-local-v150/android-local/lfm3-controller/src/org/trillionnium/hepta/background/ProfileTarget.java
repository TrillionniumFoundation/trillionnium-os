package org.trillionnium.hepta.background;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;

/** Target installation captured for an explicit profile; never a model-selected user. */
public final class ProfileTarget {
    public static final String SCHEMA="hepta.profile-target.v1",CTRIP="ctrip.android.view";
    public static final int MAX_WIRE=16384;
    public final ProfileIdentity profile;
    public final int fullUid;
    public final String packageName,component,sha256,apkSetSha256;
    public final long versionCode;
    public final SortedMap<String,String> apkHashes;
    public final SortedSet<String> signerSha256;
    private final byte[] canonical;
    public ProfileTarget(ProfileIdentity profile,int fullUid,String packageName,String component,
                         long versionCode,Map<String,String> apkHashes,Set<String> signerSha256) {
        ProfileIdentity.need(profile!=null&&fullUid>0&&fullUid/100000==profile.userId
                &&fullUid%100000>=10000&&fullUid%100000<90000,"PROFILE_TARGET_UID_INVALID");
        ProfileIdentity.need(CTRIP.equals(packageName)&&component!=null&&component.startsWith(packageName+"/")
                &&component.length()<=512&&component.substring(packageName.length()+1).matches("[A-Za-z_$][A-Za-z0-9_.$]*")
                &&versionCode>0,"PROFILE_TARGET_COMPONENT_INVALID");
        ProfileIdentity.need(apkHashes!=null&&!apkHashes.isEmpty()&&apkHashes.size()<=32&&apkHashes.containsKey("base"),"PROFILE_TARGET_APK_SET_INVALID");
        TreeMap<String,String> apks=new TreeMap<String,String>();
        for(Map.Entry<String,String> row:apkHashes.entrySet()) {
            String key=row.getKey();ProfileIdentity.need(key!=null&&("base".equals(key)||key.matches("split:[A-Za-z0-9_.-]{1,128}"))
                    &&ProfileIdentity.hash(row.getValue()),"PROFILE_TARGET_APK_IDENTITY_INVALID");apks.put(key,row.getValue());
        }
        ProfileIdentity.need(signerSha256!=null&&!signerSha256.isEmpty()&&signerSha256.size()<=4,"PROFILE_TARGET_SIGNERS_INVALID");
        TreeSet<String> signers=new TreeSet<String>();
        for(String signer:signerSha256){ProfileIdentity.need(ProfileIdentity.hash(signer),"PROFILE_TARGET_SIGNER_INVALID");signers.add(signer);}
        this.profile=profile;this.fullUid=fullUid;this.packageName=packageName;this.component=component;this.versionCode=versionCode;
        this.apkHashes=Collections.unmodifiableSortedMap(apks);this.signerSha256=Collections.unmodifiableSortedSet(signers);
        StringBuilder rows=new StringBuilder();for(Map.Entry<String,String> row:apks.entrySet())rows.append(row.getKey()).append('\t').append(row.getValue()).append('\n');
        apkSetSha256=ProfileIdentity.sha(rows.toString());canonical=encode();sha256=ProfileIdentity.sha(canonical);
    }
    private byte[] encode(){
        try{ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
            out.writeUTF(SCHEMA);out.writeInt(profile.userId);out.writeLong(profile.serial);out.writeInt(profile.parentUserId);
            out.writeUTF(profile.type);out.writeInt(fullUid);out.writeUTF(packageName);out.writeUTF(component);out.writeLong(versionCode);
            out.writeInt(apkHashes.size());for(Map.Entry<String,String> row:apkHashes.entrySet()){out.writeUTF(row.getKey());out.writeUTF(row.getValue());}
            out.writeInt(signerSha256.size());for(String signer:signerSha256)out.writeUTF(signer);out.flush();return bytes.toByteArray();
        }catch(java.io.IOException impossible){throw new IllegalStateException(impossible);}
    }
    public String wire(){return Base64.getUrlEncoder().withoutPadding().encodeToString(canonical);}
    public static ProfileTarget fromWire(String wire){
        ProfileIdentity.need(wire!=null&&!wire.isEmpty()&&wire.length()<=MAX_WIRE&&wire.matches("[A-Za-z0-9_-]+"),"PROFILE_TARGET_WIRE_INVALID");
        try{DataInputStream in=new DataInputStream(new ByteArrayInputStream(Base64.getUrlDecoder().decode(wire)));
            ProfileIdentity.need(SCHEMA.equals(in.readUTF()),"PROFILE_TARGET_SCHEMA_INVALID");
            ProfileIdentity p=new ProfileIdentity(in.readInt(),in.readLong(),in.readInt(),in.readUTF());
            int uid=in.readInt();String pkg=in.readUTF(),component=in.readUTF();long version=in.readLong();int count=in.readInt();
            ProfileIdentity.need(count>0&&count<=32,"PROFILE_TARGET_APK_SET_INVALID");Map<String,String> apks=new TreeMap<String,String>();
            for(int i=0;i<count;i++)ProfileIdentity.need(apks.put(in.readUTF(),in.readUTF())==null,"PROFILE_TARGET_APK_DUPLICATE");
            int n=in.readInt();ProfileIdentity.need(n>0&&n<=4,"PROFILE_TARGET_SIGNERS_INVALID");Set<String> signers=new TreeSet<String>();
            for(int i=0;i<n;i++)ProfileIdentity.need(signers.add(in.readUTF()),"PROFILE_TARGET_SIGNER_DUPLICATE");
            ProfileIdentity.need(in.read()==-1,"PROFILE_TARGET_TRAILING_DATA");ProfileTarget t=new ProfileTarget(p,uid,pkg,component,version,apks,signers);
            ProfileIdentity.need(t.wire().equals(wire),"PROFILE_TARGET_WIRE_NONCANONICAL");return t;
        }catch(java.io.IOException invalid){throw new IllegalArgumentException("PROFILE_TARGET_WIRE_TRUNCATED",invalid);}
    }
    public boolean same(ProfileTarget other){return other!=null&&sha256.equals(other.sha256)&&wire().equals(other.wire());}
    public Map<String,Object> evidence(){
        Map<String,Object> v=new LinkedHashMap<String,Object>();v.put("schema",SCHEMA);v.put("profile",profile.evidence());v.put("full_uid",fullUid);
        v.put("package",packageName);v.put("component",component);v.put("version_code",versionCode);v.put("apk_hashes",apkHashes);
        v.put("apk_set_sha256",apkSetSha256);v.put("signer_sha256",signerSha256);v.put("target_identity_sha256",sha256);
        v.put("grants_action_authority",false);return Collections.unmodifiableMap(v);
    }
}
