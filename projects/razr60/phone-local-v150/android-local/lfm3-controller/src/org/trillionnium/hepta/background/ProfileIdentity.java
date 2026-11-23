package org.trillionnium.hepta.background;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** An explicit profile choice. Immutable facts alone do not establish live authority. */
public final class ProfileIdentity {
    public static final String SCHEMA="hepta.managed-profile-identity.v1";
    public static final String MANAGED="android.os.usertype.profile.MANAGED";
    public final int userId,parentUserId;
    public final long serial;
    public final String type,sha256;
    public ProfileIdentity(int userId,long serial,int parentUserId,String type) {
        need(userId>0&&userId<=21473&&serial>0&&parentUserId==0&&MANAGED.equals(type),"PROFILE_IDENTITY_INVALID");
        this.userId=userId;this.serial=serial;this.parentUserId=parentUserId;this.type=type;
        try {
            ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
            out.writeUTF(SCHEMA);out.writeInt(userId);out.writeLong(serial);out.writeInt(parentUserId);out.writeUTF(type);
            out.flush();sha256=sha(bytes.toByteArray());
        } catch(java.io.IOException impossible) {throw new IllegalStateException(impossible);}
    }
    public boolean same(ProfileIdentity other) {
        return other!=null&&userId==other.userId&&serial==other.serial&&parentUserId==other.parentUserId&&type.equals(other.type);
    }
    public Map<String,Object> evidence() {
        Map<String,Object> value=new LinkedHashMap<String,Object>();value.put("schema",SCHEMA);
        value.put("user_id",userId);value.put("user_serial",serial);value.put("parent_user_id",parentUserId);
        value.put("user_type",type);value.put("profile_identity_sha256",sha256);value.put("grants_action_authority",false);
        return Collections.unmodifiableMap(value);
    }
    static void need(boolean value,String reason) {if(!value)throw new IllegalArgumentException(reason);}
    static boolean hash(String value) {return value!=null&&value.matches("[0-9a-f]{64}");}
    static boolean uuid(String value) {return value!=null&&value.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");}
    static String sha(byte[] bytes) {
        try {byte[] hash=MessageDigest.getInstance("SHA-256").digest(bytes);StringBuilder value=new StringBuilder(64);
            for(byte part:hash)value.append(String.format(java.util.Locale.ROOT,"%02x",part&255));return value.toString();
        }catch(java.security.NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
    }
    static String sha(String value){return sha(value.getBytes(StandardCharsets.UTF_8));}
}
