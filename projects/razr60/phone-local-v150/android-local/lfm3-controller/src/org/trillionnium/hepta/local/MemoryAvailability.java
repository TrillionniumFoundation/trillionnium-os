package org.trillionnium.hepta.local;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Fresh physical-headroom measurement; never substitutes free/swap/total for available. */
public final class MemoryAvailability {
    private static final Pattern LINE=Pattern.compile("^(MemAvailable|MemTotal):[ \\t]+([0-9]+)[ \\t]+kB[ \\t]*$");
    private static final long MIN_TOTAL=128L*1024*1024, MAX_TOTAL=1024L*1024*1024*1024;
    public final long activityManagerAvailable,activityManagerTotal,availableBytes;
    public final Long kernelAvailable,kernelTotal;
    public final boolean lowMemory,measurementValid;
    public final String source,kernelStatus,detail;

    private MemoryAvailability(long amAvailable,long amTotal,boolean low,Long kernelAvailable,Long kernelTotal,String status,String detail){
        activityManagerAvailable=amAvailable;activityManagerTotal=amTotal;lowMemory=low;
        this.kernelAvailable=kernelAvailable;this.kernelTotal=kernelTotal;kernelStatus=status;this.detail=detail;
        if("valid".equals(status)){
            availableBytes=kernelAvailable.longValue();source="kernel_memavailable";measurementValid=true;
        }else if("missing".equals(status)){
            availableBytes=amAvailable;source="activity_manager_fallback";
            measurementValid=amTotal>0&&amAvailable>=0&&amAvailable<=amTotal;
        }else{
            availableBytes=-1;source="invalid_kernel_measurement";measurementValid=false;
        }
    }
    public boolean admits(long minimum){return measurementValid&&!lowMemory&&availableBytes>=minimum;}

    public static MemoryAvailability read(long amAvailable,long amTotal,boolean low){
        try(FileInputStream input=new FileInputStream("/proc/meminfo");ByteArrayOutputStream out=new ByteArrayOutputStream()){
            byte[] bytes=new byte[4096];int count;
            while((count=input.read(bytes))!=-1){if(out.size()+count>65536)return invalid(amAvailable,amTotal,low,"meminfo above bound");out.write(bytes,0,count);}
            return fromText(amAvailable,amTotal,low,new String(out.toByteArray(),StandardCharsets.US_ASCII));
        }catch(IOException|SecurityException unavailable){
            return new MemoryAvailability(amAvailable,amTotal,low,null,null,"missing","/proc/meminfo unavailable: "+unavailable.getClass().getSimpleName());
        }
    }

    public static MemoryAvailability fromText(long amAvailable,long amTotal,boolean low,String meminfo){
        if(meminfo==null)return new MemoryAvailability(amAvailable,amTotal,low,null,null,"missing","kernel fields unavailable");
        if(meminfo.length()>65536)return invalid(amAvailable,amTotal,low,"meminfo above bound");
        Long available=null,total=null;
        for(String line:meminfo.split("\\n",-1)){
            if(!line.startsWith("MemAvailable:")&&!line.startsWith("MemTotal:"))continue;
            Matcher match=LINE.matcher(line);
            if(!match.matches())return invalid(amAvailable,amTotal,low,"invalid kernel field format or unit");
            long value;
            try{value=Long.parseLong(match.group(2));if(value>Long.MAX_VALUE/1024)return invalid(amAvailable,amTotal,low,"kernel field overflow");value*=1024;}
            catch(NumberFormatException malformed){return invalid(amAvailable,amTotal,low,"invalid kernel field number");}
            if("MemAvailable".equals(match.group(1))){if(available!=null)return invalid(amAvailable,amTotal,low,"duplicate MemAvailable");available=value;}
            else{if(total!=null)return invalid(amAvailable,amTotal,low,"duplicate MemTotal");total=value;}
        }
        if(total!=null&&(total<MIN_TOTAL||total>MAX_TOTAL))return invalid(amAvailable,amTotal,low,"MemTotal outside physical range");
        if(available==null||total==null)return new MemoryAvailability(amAvailable,amTotal,low,available,total,"missing","required kernel field absent");
        if(available>total)return invalid(amAvailable,amTotal,low,"MemAvailable exceeds MemTotal");
        return new MemoryAvailability(amAvailable,amTotal,low,available,total,"valid",null);
    }
    private static MemoryAvailability invalid(long available,long total,boolean low,String detail){return new MemoryAvailability(available,total,low,null,null,"invalid",detail);}
}
