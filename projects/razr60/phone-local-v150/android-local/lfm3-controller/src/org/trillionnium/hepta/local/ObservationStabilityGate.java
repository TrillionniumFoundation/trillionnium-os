package org.trillionnium.hepta.local;

import java.util.Objects;

/** Bounded stability of the complete observed graph; never authorizes an effect. */
public final class ObservationStabilityGate {
    public static final long SAMPLE_GAP_MS=200, SETTLE_LIMIT_MS=2000;
    public enum Result { WAIT, READY, EXPIRED, CANCELLED }

    /** Existing active-window identity/digest plus its observation truncation state. */
    public static final class FrameKey {
        public final String packageName,observedDigest;
        public final int windowId,rotation,left,top,right,bottom;
        public final boolean truncated;
        public FrameKey(String packageName,int windowId,int rotation,int left,int top,int right,int bottom,
                        String observedDigest,boolean truncated){
            if(packageName==null||packageName.isEmpty()||observedDigest==null||observedDigest.isEmpty())
                throw new IllegalArgumentException("observed window and digest required");
            this.packageName=packageName;this.windowId=windowId;this.rotation=rotation;
            this.left=left;this.top=top;this.right=right;this.bottom=bottom;
            this.observedDigest=observedDigest;this.truncated=truncated;
        }
        @Override public boolean equals(Object other){
            if(!(other instanceof FrameKey))return false;
            FrameKey value=(FrameKey)other;
            return windowId==value.windowId&&rotation==value.rotation&&left==value.left&&top==value.top
                    &&right==value.right&&bottom==value.bottom&&truncated==value.truncated
                    &&packageName.equals(value.packageName)&&observedDigest.equals(value.observedDigest);
        }
        @Override public int hashCode(){
            return Objects.hash(packageName,Integer.valueOf(windowId),Integer.valueOf(rotation),Integer.valueOf(left),
                    Integer.valueOf(top),Integer.valueOf(right),Integer.valueOf(bottom),observedDigest,Boolean.valueOf(truncated));
        }
    }

    private final long started,requestDeadline,settleDeadline;
    private long lastClock,previousAt;
    private FrameKey previous;
    private boolean retired;

    public ObservationStabilityGate(long started,long requestDeadline){
        if(started<0||requestDeadline<0)throw new IllegalArgumentException("elapsed deadlines required");
        this.started=started;this.lastClock=started;this.requestDeadline=requestDeadline;
        long end=started>Long.MAX_VALUE-SETTLE_LIMIT_MS?Long.MAX_VALUE:started+SETTLE_LIMIT_MS;
        this.settleDeadline=Math.min(end,requestDeadline);
    }
    /** A screenshot may finish after the settle phase, but never after the caller's deadline. */
    public boolean requestAlive(long now,boolean allowed){
        if(retired||!allowed||now<started||now<lastClock||now>=requestDeadline)return false;
        lastClock=now;return true;
    }
    /** Null means no active root this time. It is not an empty, stable observation. */
    public Result sample(long now,FrameKey frame,boolean allowed){
        if(retired||!allowed)return Result.CANCELLED;
        if(!requestAlive(now,true)||now>=settleDeadline)return Result.EXPIRED;
        if(frame==null){previous=null;previousAt=0;return Result.WAIT;}
        if(previous!=null&&previous.equals(frame)){
            return now-previousAt>=SAMPLE_GAP_MS?Result.READY:Result.WAIT;
        }
        previous=frame;previousAt=now;return Result.WAIT;
    }
    /** Drop evidence after a changed screenshot; the original deadlines do not move. */
    public void resetEvidence(){previous=null;previousAt=0;}
    public long nextSampleDelay(long now){return Math.max(0,Math.min(SAMPLE_GAP_MS,settleDeadline-now));}
    public void retire(){retired=true;previous=null;}
}
