package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/** Bounded facts about the active root and its own API window; no inferred page role. */
public final class ObservedWindowMetadata {
    public static final String SCHEMA="hepta.observed-window-metadata.v1";
    public static final String SCOPE="active_root_only";
    public static final int TITLE_LIMIT=96, CLASS_LIMIT=128;
    public static final int PROMPT_TITLE_LIMIT=16, PROMPT_CLASS_LIMIT=32;
    public final String status,rootClass,title;
    public final boolean rootClassTruncated,titleTruncated;
    public final Integer type,displayId;
    private final int[] rootBounds,windowBounds;
    private final String rootClassIdentity,titleIdentity;

    private ObservedWindowMetadata(int[] rootBounds,String rootClass,boolean observed,
            Integer type,Integer displayId,int[] windowBounds,String title){
        if(!validBounds(rootBounds))throw new IllegalArgumentException("observed root bounds required");
        this.rootBounds=rootBounds.clone();
        this.status=observed?"observed":"unknown";
        this.rootClass=bounded(rootClass,CLASS_LIMIT);
        this.rootClassTruncated=rootClass!=null&&rootClass.length()>CLASS_LIMIT;
        this.rootClassIdentity=identity(rootClass);
        this.type=observed?type:null;
        this.displayId=observed?displayId:null;
        this.windowBounds=observed&&validBounds(windowBounds)?windowBounds.clone():null;
        this.title=observed?bounded(title,TITLE_LIMIT):null;
        this.titleTruncated=observed&&title!=null&&title.length()>TITLE_LIMIT;
        this.titleIdentity=observed?identity(title):null;
    }

    public static ObservedWindowMetadata unknown(int[] rootBounds,String rootClass){
        return new ObservedWindowMetadata(rootBounds,rootClass,false,null,null,null,null);
    }

    /** Caller has matched getWindow().getId()/getDisplayId() to the selected root. */
    public static ObservedWindowMetadata observed(int[] rootBounds,String rootClass,
            int type,int displayId,int[] windowBounds,String title){
        return new ObservedWindowMetadata(rootBounds,rootClass,true,Integer.valueOf(type),
                Integer.valueOf(displayId),windowBounds,title);
    }

    public int[] rootBounds(){return rootBounds.clone();}
    public int[] windowBounds(){return windowBounds==null?null:windowBounds.clone();}
    public String promptTitle(){return bounded(title,PROMPT_TITLE_LIMIT);}
    public String promptRootClass(){return bounded(rootClass,PROMPT_CLASS_LIMIT);}
    public boolean promptTitleTruncated(){return titleTruncated||(title!=null&&title.length()>PROMPT_TITLE_LIMIT);}
    public boolean promptRootClassTruncated(){return rootClassTruncated||(rootClass!=null&&rootClass.length()>PROMPT_CLASS_LIMIT);}

    /** Exact freshness includes metadata, but unavailable/available metadata is not task progress. */
    public String bindFreshness(String stateFingerprint){
        if(stateFingerprint==null)throw new IllegalArgumentException("observed state required");
        return SCHEMA+atom(stateFingerprint)+atom(SCOPE)+atom(status)+atom(Arrays.toString(rootBounds))
                +atom(rootClassIdentity)+atom(type==null?null:type.toString())
                +atom(displayId==null?null:displayId.toString())
                +atom(windowBounds==null?null:Arrays.toString(windowBounds))+atom(titleIdentity);
    }

    private static boolean validBounds(int[] value){
        return value!=null&&value.length==4&&value[2]>value[0]&&value[3]>value[1];
    }
    private static String bounded(String value,int limit){
        if(value==null||value.length()<=limit)return value;
        int end=limit-1;
        if(end>0&&Character.isHighSurrogate(value.charAt(end-1)))end--;
        return value.substring(0,end)+"…";
    }
    private static String atom(String value){return value==null?"-1:":value.length()+":"+value;}
    private static String identity(String value){
        if(value==null)return null;
        try{
            byte[] digest=MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder result=new StringBuilder(64);
            for(byte b:digest){result.append(Character.forDigit((b>>>4)&15,16));result.append(Character.forDigit(b&15,16));}
            return result.toString();
        }catch(java.security.NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
    }
}
