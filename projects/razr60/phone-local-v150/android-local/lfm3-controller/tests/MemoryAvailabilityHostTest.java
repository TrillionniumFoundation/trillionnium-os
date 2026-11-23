import org.trillionnium.hepta.local.MemoryAvailability;
public final class MemoryAvailabilityHostTest {
    private static final long G=1024L*1024*1024, MIN=3*G;
    private static int assertions;
    private static void check(boolean yes,String message){assertions++;if(!yes)throw new AssertionError(message);}
    private static MemoryAvailability memory(String text){return MemoryAvailability.fromText(2*G,12*G,false,text);}
    public static void main(String[] args){
        MemoryAvailability current=memory("MemTotal: 12582912 kB\nMemFree: 1974448 kB\nMemAvailable: 8612588 kB\nSwapFree: 99999999 kB\n");
        check(current.measurementValid&&current.admits(MIN),"reclaimable kernel headroom can admit when AM is low");
        check(current.availableBytes==8612588L*1024&&current.activityManagerAvailable==2*G,"record both without confusing bytes/kB");
        check("kernel_memavailable".equals(current.source),"source explicit");
        check(!MemoryAvailability.fromText(8*G,12*G,true,"MemTotal: 12582912 kB\nMemAvailable: 8612588 kB\n").admits(MIN),"AM lowMemory always blocks");
        check(!memory("MemTotal: 12582912 kB\nMemAvailable: 0 kB\n").admits(MIN),"zero available never falls back");
        check(memory("MemTotal: 12582912 kB\nMemAvailable: 3145728 kB\n").admits(MIN),"3 GiB exact boundary");
        check(!memory("MemTotal: 12582912 kB\nMemAvailable: 3145727 kB\n").admits(MIN),"below threshold rejects");
        MemoryAvailability missing=MemoryAvailability.fromText(4*G,12*G,false,"MemTotal: 12582912 kB\nMemFree: 8388608 kB\nSwapFree: 99999999 kB\n");
        check(missing.availableBytes==4*G&&missing.admits(MIN)&&"activity_manager_fallback".equals(missing.source),"only missing kernel fields use AM");
        check(!memory("MemTotal: 12582912 kB\nMemFree: 8388608 kB\nSwapFree: 99999999 kB\n").admits(MIN),"never use free/swap/total as available");
        for(String bad:new String[]{
            "MemTotal: 12582912 kB\nMemAvailable: 99999999 kB\n",
            "MemTotal: 12582912 kB\nMemAvailable: -1 kB\n",
            "MemTotal: 12582912 kB\nMemAvailable: 8 GB\n",
            "MemTotal: 12582912 kB\nMemAvailable: 8000000 KB\n",
            "MemTotal: 12582912 kB\nMemAvailable: 8000000\n",
            "MemTotal: 12582912 kB\nMemAvailable: 8000000 kB\nMemAvailable: 1 kB\n",
            "MemTotal: 12582912 kB\nMemTotal: 12582912 kB\nMemAvailable: 1 kB\n",
            "MemTotal: 12582912 kB\nMemAvailable: 9223372036854775807 kB\n",
            "MemTotal: 12582912 kB\nMemAvailable: 999999999999999999999999 kB\n",
            "MemTotal: 0 kB\nMemAvailable: 0 kB\n",
            "MemTotal: 1099511627776 kB\nMemAvailable: 1 kB\n"}){
            MemoryAvailability value=MemoryAvailability.fromText(8*G,12*G,false,bad);
            check(!value.measurementValid&&!value.admits(MIN)&&"invalid".equals(value.kernelStatus),"invalid kernel fields fail closed despite high AM");
        }
        check(!MemoryAvailability.fromText(20*G,12*G,false,null).admits(MIN),"invalid AM fallback cannot authorize");
        check(!MemoryAvailability.fromText(8*G,12*G,true,null).admits(MIN),"lowMemory also blocks fallback");
        System.out.println("PASS "+assertions+" memory admission assertions; threshold=3GiB; phone_tested=false");
    }
}
