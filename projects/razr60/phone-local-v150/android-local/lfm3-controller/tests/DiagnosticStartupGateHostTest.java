import org.trillionnium.hepta.local.DiagnosticStartupGate;

public final class DiagnosticStartupGateHostTest {
    static int assertions;
    static void yes(boolean v){assertions++;if(!v)throw new AssertionError();}
    public static void main(String[] args){
        for(int mask=0;mask<8;mask++){
            final int[] reservations={0};
            DiagnosticStartupGate g=new DiagnosticStartupGate((mask&1)!=0,(mask&2)!=0,(mask&4)!=0);
            g.apply(() -> reservations[0]++);
            yes(g.isBlocked()==(mask!=0));yes(reservations[0]==(mask==0?0:1));
            boolean refused=false;try{g.apply(() -> reservations[0]++);}catch(IllegalStateException expected){refused=true;}
            yes(refused);yes(reservations[0]==(mask==0?0:1));
        }
        DiagnosticStartupGate failed=new DiagnosticStartupGate(false,true,true);final int[] attempts={0};
        try{failed.apply(() -> {attempts[0]++;throw new IllegalStateException("slot already held");});throw new AssertionError();}
        catch(IllegalStateException expected){yes(failed.isBlocked());}
        try{failed.apply(() -> attempts[0]++);throw new AssertionError();}catch(IllegalStateException expected){yes(attempts[0]==1);}
        System.out.println("startup recovery matrix passed: "+assertions+"; at most one shared reservation for three dirty journals");
    }
}
