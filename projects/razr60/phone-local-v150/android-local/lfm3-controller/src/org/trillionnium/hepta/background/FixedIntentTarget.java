package org.trillionnium.hepta.background;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/** Installed facts supplied by trusted PackageManager inspection, never model fields. */
public final class FixedIntentTarget {
    public final String action, packageName, className, appLabel, permission;
    public final int uid;
    public FixedIntentTarget(String action,String label,int uid,String permission){
        FixedIntentTools.Profile profile=FixedIntentTools.forAction(action);
        if(profile==null||label==null||label.length()>512||label.indexOf('\0')>=0||uid<10000||uid>=90000)
            throw new IllegalArgumentException("fixed intent installed identity required");
        for(int i=0;i<label.length();i++){
            char c=label.charAt(i);
            if(Character.isHighSurrogate(c)){if(++i>=label.length()||!Character.isLowSurrogate(label.charAt(i)))throw new IllegalArgumentException("invalid app label");}
            else if(Character.isLowSurrogate(c))throw new IllegalArgumentException("invalid app label");
        }
        this.action=action;this.packageName=profile.packageName;this.className=profile.className;
        this.appLabel=label;this.uid=uid;this.permission=permission==null||permission.isEmpty()?null:permission;
    }
    public boolean sameIdentity(FixedIntentTarget other){
        return other!=null&&action.equals(other.action)&&uid==other.uid&&packageName.equals(other.packageName)
                &&className.equals(other.className)&&appLabel.equals(other.appLabel)&&Objects.equals(permission,other.permission);
    }
    private static final String LOWER_HEX="0123456789abcdef";
    public static String payloadSha256(String value){
        if(value==null)throw new IllegalArgumentException("payload required");
        try{
            byte[] digest=java.security.MessageDigest.getInstance("SHA-256").digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            char[] hex=new char[digest.length*2];
            for(int i=0;i<digest.length;i++){
                int unsigned=digest[i]&255;
                hex[2*i]=LOWER_HEX.charAt(unsigned>>>4);
                hex[2*i+1]=LOWER_HEX.charAt(unsigned&15);
            }
            return new String(hex);
        }
        catch(java.security.NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
    }
    public Map<String,Object> evidence(){
        Map<String,Object> out=new LinkedHashMap<String,Object>();
        out.put("source","installed_package_manager");out.put("action",action);out.put("package",packageName);
        out.put("component",packageName+"/"+className);out.put("target_uid",uid);out.put("app_label",appLabel);
        out.put("exported",true);out.put("activity_enabled",true);out.put("application_enabled",true);
        out.put("declared_intent_filter_matched",true);out.put("required_permission",permission);
        out.put("ordinary_caller_permission_checked",true);return out;
    }
}
