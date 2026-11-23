package org.trillionnium.hepta.local;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/** Exact current prompt app pairs, keyed by original package; never resolves a label. */
public final class ObservedAppLabels {
    public static final String SCHEMA="hepta.observed-app-labels.v1";
    public static final String ACTION_SCHEMA="hepta.observed-action-gbnf.v4-app-label-first";
    public static final String ENCODING="utf8-length-prefixed-be32-sorted-package.v1";
    public static final int PROJECTION_UTF16_LIMIT=48;
    public final String observationId,currentPackage,sha256;
    public final Map<String,String> labels;

    private ObservedAppLabels(String observationId,String currentPackage,Map<String,String> labels){
        this.observationId=observationId;this.currentPackage=currentPackage;
        this.labels=Collections.unmodifiableMap(new TreeMap<String,String>(labels));
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        field(bytes,SCHEMA);field(bytes,ENCODING);field(bytes,observationId);field(bytes,currentPackage);
        integer(bytes,this.labels.size());
        for(Map.Entry<String,String> pair:this.labels.entrySet()){field(bytes,pair.getKey());field(bytes,pair.getValue());}
        try{
            StringBuilder hex=new StringBuilder(64);
            for(byte value:MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray()))hex.append(String.format(Locale.ROOT,"%02x",value&255));
            sha256=hex.toString();
        }catch(java.security.NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
    }

    public static ObservedAppLabels create(String schema,String observationId,String currentPackage,Map<String,String> labels){
        if(!SCHEMA.equals(schema))throw new IllegalArgumentException("unknown observed-app label schema");
        if(observationId==null||!observationId.matches("[0-9a-f]{32}"))throw new IllegalArgumentException("invalid observed-app identity");
        checkPackage(currentPackage,true);
        if(labels==null||labels.size()>40)throw new IllegalArgumentException("invalid observed-app projection");
        for(Map.Entry<String,String> pair:labels.entrySet()){
            checkPackage(pair.getKey(),false);
            if(currentPackage.equals(pair.getKey()))throw new IllegalArgumentException("current package cannot be opened");
            requireProjectedLabel(pair.getValue());
        }
        return new ObservedAppLabels(observationId,currentPackage,labels);
    }

    /** Preserve the existing prompt's 48 UTF-16-unit projection and ellipsis. */
    public static String project(String raw){
        validUnicode(raw);
        if(raw.length()<=PROJECTION_UTF16_LIMIT)return raw;
        int end=PROJECTION_UTF16_LIMIT;
        if(Character.isHighSurrogate(raw.charAt(end-1)))end--;
        return raw.substring(0,end)+"…";
    }

    public static void requireProjectedLabel(String label){
        validUnicode(label);
        if(label.length()>PROJECTION_UTF16_LIMIT+1)throw new IllegalArgumentException("app_label exceeds supplied projection bound");
    }

    public boolean matches(String observation,String current,String targetPackage,String appLabel){
        return observationId.equals(observation)&&currentPackage.equals(current)&&targetPackage!=null&&appLabel!=null
                &&labels.containsKey(targetPackage)&&labels.get(targetPackage).equals(appLabel);
    }

    private static void checkPackage(String value,boolean allowSystem){
        if(value==null||value.length()>255||(!(allowSystem&&"android".equals(value))
                &&!value.matches("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+")))
            throw new IllegalArgumentException("invalid observed-app package");
    }
    private static void validUnicode(String value){
        if(value==null||value.indexOf('\0')>=0)throw new IllegalArgumentException("missing or NUL app label");
        for(int i=0;i<value.length();i++){
            char c=value.charAt(i);
            if(Character.isHighSurrogate(c)){
                if(i+1>=value.length()||!Character.isLowSurrogate(value.charAt(++i)))throw new IllegalArgumentException("invalid app-label surrogate");
            }else if(Character.isLowSurrogate(c))throw new IllegalArgumentException("invalid app-label surrogate");
        }
    }
    private static void integer(ByteArrayOutputStream out,int value){
        out.write((value>>>24)&255);out.write((value>>>16)&255);out.write((value>>>8)&255);out.write(value&255);
    }
    private static void field(ByteArrayOutputStream out,String value){
        byte[] bytes=value.getBytes(StandardCharsets.UTF_8);integer(out,bytes.length);out.write(bytes,0,bytes.length);
    }
}
