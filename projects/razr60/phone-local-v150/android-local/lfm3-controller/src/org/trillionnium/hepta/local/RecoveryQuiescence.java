package org.trillionnium.hepta.local;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Evidence of a bounded quiet interval; never a claim about an old worker's exit. */
public final class RecoveryQuiescence {
    public static final String SCHEMA="hepta.same-uid-recovery-quiescence.v1";
    public static final long MIN_SPAN_MS=1500;
    public static final int MIN_SAMPLES=3,MAX_SAMPLES=8;
    private RecoveryQuiescence(){}
    public static final class Sample {
        public final int uid,pid,otherSameUidProcesses;
        public final long startTicks,elapsedMs;
        public final boolean complete;
        public Sample(int uid,int pid,long startTicks,long elapsedMs,int others,boolean complete){
            this.uid=uid;this.pid=pid;this.startTicks=startTicks;this.elapsedMs=elapsedMs;
            this.otherSameUidProcesses=others;this.complete=complete;
        }
    }
    public static final class Permit {
        public final int uid,pid;
        public final long startTicks,firstElapsedMs,lastElapsedMs;
        public final List<Sample> samples;
        private Permit(List<Sample> input){
            samples=Collections.unmodifiableList(new ArrayList<Sample>(input));
            Sample first=samples.get(0),last=samples.get(samples.size()-1);
            uid=first.uid;pid=first.pid;startTicks=first.startTicks;
            firstElapsedMs=first.elapsedMs;lastElapsedMs=last.elapsedMs;
        }
        public Map<String,String> record(){
            Map<String,String> m=new LinkedHashMap<String,String>();
            m.put("schema",SCHEMA);m.put("uid",Integer.toString(uid));
            m.put("pid",Integer.toString(pid));m.put("start_ticks",Long.toString(startTicks));
            m.put("sample_count",Integer.toString(samples.size()));
            m.put("old_native_cleanup","unknown");
            for(int i=0;i<samples.size();i++){
                Sample s=samples.get(i);String p="sample."+i+".";
                m.put(p+"elapsed_ms",Long.toString(s.elapsedMs));
                m.put(p+"other_same_uid_processes",Integer.toString(s.otherSameUidProcesses));
                m.put(p+"complete",Boolean.toString(s.complete));
            }
            return Collections.unmodifiableMap(m);
        }
    }
    public static Permit confirm(List<Sample> samples,int expectedUid,int expectedPid){
        if(samples==null||samples.size()<MIN_SAMPLES||samples.size()>MAX_SAMPLES
                ||expectedUid<10000||expectedPid<=0)throw new IllegalStateException("incomplete quiet interval");
        Sample first=samples.get(0);long previous=-1;
        for(Sample s:samples){
            if(s==null||!s.complete||s.uid!=expectedUid||s.pid!=expectedPid||s.startTicks<=0
                    ||s.startTicks!=first.startTicks||s.otherSameUidProcesses!=0
                    ||s.elapsedMs<=previous)throw new IllegalStateException("worker identity or quiet interval changed");
            previous=s.elapsedMs;
        }
        if(previous-first.elapsedMs<MIN_SPAN_MS)throw new IllegalStateException("quiet interval too short");
        return new Permit(samples);
    }
    public static Permit readRecord(Map<String,String> m,int expectedUid){
        try{
            if(!SCHEMA.equals(m.get("schema"))||!"unknown".equals(m.get("old_native_cleanup")))
                throw new IllegalStateException("not a recovery absence record");
            int uid=Integer.parseInt(m.get("uid")),pid=Integer.parseInt(m.get("pid"));
            long ticks=Long.parseLong(m.get("start_ticks"));
            int n=Integer.parseInt(m.get("sample_count"));
            if(n<MIN_SAMPLES||n>MAX_SAMPLES)throw new IllegalStateException("invalid sample count");
            List<Sample> s=new ArrayList<Sample>();
            for(int i=0;i<n;i++){
                String p="sample."+i+".";
                String complete=m.get(p+"complete");
                if(!"true".equals(complete))throw new IllegalStateException("incomplete process visibility");
                s.add(new Sample(uid,pid,ticks,Long.parseLong(m.get(p+"elapsed_ms")),
                        Integer.parseInt(m.get(p+"other_same_uid_processes")),true));
            }
            if(m.size()!=6+3*n)throw new IllegalStateException("unexpected quiescence fields");
            return confirm(s,expectedUid,pid);
        }catch(NumberFormatException|NullPointerException e){throw new IllegalStateException("invalid quiescence record",e);}
    }
}
