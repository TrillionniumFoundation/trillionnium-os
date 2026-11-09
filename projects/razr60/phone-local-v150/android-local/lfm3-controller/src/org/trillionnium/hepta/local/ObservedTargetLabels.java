package org.trillionnium.hepta.local;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/** Exact labels already supplied in one prompt; never resolves a label to a new ID. */
public final class ObservedTargetLabels {
    public static final String SCHEMA="hepta.observed-target-labels.v1";
    public static final String ACTION_SCHEMA="hepta.observed-action-gbnf.v3-label-first";
    public static final String ENCODING="utf8-length-prefixed-be32-sorted-node-id.v1";
    public static final int PROJECTION_UTF16_LIMIT=36;
    public final String observationId,packageName,sha256;
    public final Map<String,String> labels;

    private ObservedTargetLabels(String observationId,String packageName,Map<String,String> labels){
        this.observationId=observationId;this.packageName=packageName;
        this.labels=Collections.unmodifiableMap(new TreeMap<String,String>(labels));
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        field(bytes,SCHEMA);field(bytes,ENCODING);field(bytes,observationId);field(bytes,packageName);
        integer(bytes,this.labels.size());
        for(Map.Entry<String,String> pair:this.labels.entrySet()){field(bytes,pair.getKey());field(bytes,pair.getValue());}
        try{
            StringBuilder hex=new StringBuilder(64);
            for(byte value:MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray()))hex.append(String.format(Locale.ROOT,"%02x",value&255));
            sha256=hex.toString();
        }catch(java.security.NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
    }
    public static ObservedTargetLabels create(String schema,String observationId,String packageName,Map<String,String> labels){
        if(!SCHEMA.equals(schema))throw new IllegalArgumentException("unknown observed-target label schema");
        if(observationId==null||!observationId.matches("[0-9a-f]{32}"))throw new IllegalArgumentException("invalid observed-target identity");
        if(packageName==null||packageName.length()>255||(!"android".equals(packageName)&&!packageName.matches("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+")))
            throw new IllegalArgumentException("invalid observed-target package");
        if(labels==null||labels.size()>200)throw new IllegalArgumentException("invalid observed-target projection");
        for(Map.Entry<String,String> pair:labels.entrySet()){
            if(pair.getKey()==null||!pair.getKey().matches("n[0-9]{1,5}"))throw new IllegalArgumentException("invalid observed-target node ID");
            requireProjectedLabel(pair.getValue());
        }
        return new ObservedTargetLabels(observationId,packageName,labels);
    }
    /** Preserves the pre-existing 36 UTF-16-unit projection and its ellipsis. */
    public static String project(String raw){
        validUnicode(raw);
        if(raw.length()<=PROJECTION_UTF16_LIMIT)return raw;
        int end=PROJECTION_UTF16_LIMIT;
        if(Character.isHighSurrogate(raw.charAt(end-1)))end--;
        return raw.substring(0,end)+"…";
    }
    public static void requireProjectedLabel(String label){
        validUnicode(label);
        if(label.length()>PROJECTION_UTF16_LIMIT+1)throw new IllegalArgumentException("node_label exceeds supplied projection bound");
    }
    public boolean matches(String observation,String packageValue,String nodeId,String nodeLabel){
        return observationId.equals(observation)&&packageName.equals(packageValue)&&nodeId!=null
                &&nodeLabel!=null&&labels.containsKey(nodeId)&&labels.get(nodeId).equals(nodeLabel);
    }
    private static void validUnicode(String value){
        if(value==null)throw new IllegalArgumentException("missing node label");
        for(int i=0;i<value.length();i++){
            char c=value.charAt(i);
            if(Character.isHighSurrogate(c)){
                if(i+1>=value.length()||!Character.isLowSurrogate(value.charAt(++i)))throw new IllegalArgumentException("invalid node-label surrogate");
            }else if(Character.isLowSurrogate(c))throw new IllegalArgumentException("invalid node-label surrogate");
        }
    }
    private static void integer(ByteArrayOutputStream out,int value){
        out.write((value>>>24)&255);out.write((value>>>16)&255);out.write((value>>>8)&255);out.write(value&255);
    }
    private static void field(ByteArrayOutputStream out,String value){
        byte[] bytes=value.getBytes(StandardCharsets.UTF_8);integer(out,bytes.length);out.write(bytes,0,bytes.length);
    }
}
