package org.trillionnium.hepta.webhelper;

/**
 * UI-thread-owned read budget. Time is supplied by the actual monotonic clock.
 * Only a DOM mismatch can request another read; no page action is represented here.
 */
final class CaptureReadBudget {
    static final int MAX_ATTEMPTS=3;
    static final long MAX_CAPTURE_MS=3000,RETRY_DELAY_MS=100;
    static final class Attempt {
        final int index;
        final long visualRequestId;
        private Attempt(int index,long now){this.index=index;this.visualRequestId=now;}
    }
    final long started,deadline;
    private long lastObserved,notBefore;
    private int count;
    private Attempt active;
    private boolean closed;

    CaptureReadBudget(long now,long callerDeadline){
        need(now>=0&&now<=Long.MAX_VALUE-MAX_CAPTURE_MS&&callerDeadline>now,"capture deadline invalid");
        started=now;deadline=Math.min(now+MAX_CAPTURE_MS,callerDeadline);
        lastObserved=now;notBefore=now;
    }
    Attempt begin(long now){
        checkTime(now);
        need(!closed&&active==null&&count<MAX_ATTEMPTS&&now>=notBefore,"capture attempt unavailable");
        active=new Attempt(++count,now);return active;
    }
    boolean owns(Attempt token){return !closed&&token!=null&&active==token;}
    void requireActive(Attempt token,long now){
        need(owns(token),"capture attempt is stale");
        checkTime(now);
    }
    boolean retryAfterDomMismatch(Attempt token,long now){
        requireActive(token,now);
        active=null; // Late callbacks lose ownership before the next read is posted.
        if(count>=MAX_ATTEMPTS||deadline-now<=RETRY_DELAY_MS){closed=true;return false;}
        notBefore=now+RETRY_DELAY_MS;return true;
    }
    long nextDelay(long now){
        checkTime(now);
        need(!closed&&active==null&&count<MAX_ATTEMPTS,"capture retry unavailable");
        return Math.max(0,notBefore-now);
    }
    void complete(Attempt token,long now){requireActive(token,now);active=null;closed=true;}
    void cancel(){active=null;closed=true;}
    int attempts(){return count;}
    private void checkTime(long now){
        need(now>=lastObserved&&now<deadline,"capture absolute deadline expired or monotonic clock changed");
        lastObserved=now;
    }
    private static void need(boolean value,String reason){if(!value)throw new IllegalStateException(reason);}
}
