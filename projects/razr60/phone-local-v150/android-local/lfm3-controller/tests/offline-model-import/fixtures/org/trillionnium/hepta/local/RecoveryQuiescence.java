package org.trillionnium.hepta.local;
final class RecoveryQuiescence {
    static final class Sample {}
    static void confirm(java.util.List<Sample> samples,int uid,int pid){
        if(samples.size()<2||uid!=android.os.Process.myUid()||pid!=android.os.Process.myPid())throw new IllegalStateException("fixture process snapshot identity");
    }
}

