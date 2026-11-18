package org.trillionnium.hepta.background;

import android.hardware.display.DisplayManager;
import android.os.IBinder;
import android.os.IInterface;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.util.DisplayMetrics;
import android.view.Display;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;

/** Fixed, read-only framework reads, available solely inside the broker. No shell
 * command string, caller-supplied dump command, task mutation or permission grant. */
final class PublicOwnGroupPhysicalReader {
    private PublicOwnGroupPhysicalReader(){}
    static Map<Integer,String> read(Object windowManager,DisplayManager displays,int targetUser,LongSupplier deadline)throws Exception{
        if(android.os.Build.VERSION.SDK_INT!=36)throw new IOException("PUBLIC_AUDIT_PHYSICAL_PLATFORM_UNSUPPORTED");
        Map<Integer,PublicOwnGroupPhysicalFence.DisplayFacts> before=displayFacts(displays);
        Object am=Class.forName("android.app.ActivityManager").getMethod("getService").invoke(null);
        String activities=dump(am,new String[]{"-a","activities"},deadline);
        String windows=dump(windowManager,new String[]{"-a","displays"},deadline);
        String recents=dump(am,new String[]{"-a","recents"},deadline);
        Map<Integer,PublicOwnGroupPhysicalFence.DisplayFacts> after=displayFacts(displays);
        for(int id:new int[]{0,1})if(!before.get(id).data().equals(after.get(id).data()))throw new IOException("PUBLIC_AUDIT_PHYSICAL_STATE_CHANGED_DURING_READ");
        if(SystemClock.elapsedRealtime()>=deadline.getAsLong())throw new IOException("PUBLIC_AUDIT_PHYSICAL_READ_DEADLINE");
        return PublicOwnGroupPhysicalFence.capture(activities,windows,recents,after,targetUser);
    }
    private static Map<Integer,PublicOwnGroupPhysicalFence.DisplayFacts> displayFacts(DisplayManager manager)throws Exception{
        Display[] all=manager.getDisplays();if(all==null||all.length<2||all.length>32)throw new IOException("PUBLIC_AUDIT_PHYSICAL_CENSUS_UNAVAILABLE");
        Map<Integer,PublicOwnGroupPhysicalFence.DisplayFacts> result=new LinkedHashMap<Integer,PublicOwnGroupPhysicalFence.DisplayFacts>();
        for(Display display:all){
            if(display==null||!display.isValid())throw new IOException("PUBLIC_AUDIT_PHYSICAL_DISPLAY_UNAVAILABLE");
            int id=display.getDisplayId(),type=(Integer)Display.class.getMethod("getType").invoke(display);
            if(id!=0&&id!=1){if(type!=5)throw new IOException("PUBLIC_AUDIT_UNREVIEWED_PHYSICAL_DISPLAY");continue;}
            DisplayMetrics metrics=new DisplayMetrics();display.getRealMetrics(metrics);
            String unique=(String)Display.class.getMethod("getUniqueId").invoke(display);
            PublicOwnGroupPhysicalFence.DisplayFacts row=new PublicOwnGroupPhysicalFence.DisplayFacts(id,unique,type,display.getState(),display.getRotation(),metrics.widthPixels,metrics.heightPixels);
            if(result.put(id,row)!=null)throw new IOException("PUBLIC_AUDIT_PHYSICAL_DISPLAY_DUPLICATE");
        }
        if(result.size()!=2||!result.containsKey(0)||!result.containsKey(1))throw new IOException("PUBLIC_AUDIT_PHYSICAL_CENSUS_UNAVAILABLE");return result;
    }
    private static String dump(Object service,String[] arguments,LongSupplier deadline)throws Exception{
        if(SystemClock.elapsedRealtime()>=deadline.getAsLong()||!(service instanceof IInterface))throw new IOException("PUBLIC_AUDIT_PHYSICAL_DUMP_UNAVAILABLE");
        IBinder binder=((IInterface)service).asBinder();if(binder==null)throw new IOException("PUBLIC_AUDIT_PHYSICAL_DUMP_UNAVAILABLE");
        final ParcelFileDescriptor[] pipe=ParcelFileDescriptor.createPipe();final ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        final AtomicReference<Throwable> failure=new AtomicReference<Throwable>();
        Thread reader=new Thread(()->{
            try(ParcelFileDescriptor.AutoCloseInputStream input=new ParcelFileDescriptor.AutoCloseInputStream(pipe[0])){
                byte[] buffer=new byte[8192];int count;
                while((count=input.read(buffer))!=-1){if(bytes.size()+count>2*1024*1024)throw new IOException("PUBLIC_AUDIT_PHYSICAL_DUMP_SIZE");bytes.write(buffer,0,count);}
            }catch(Throwable error){failure.set(error);}
        },"HeptaPublicPhysicalAuditRead");reader.setDaemon(true);reader.start();
        try{binder.dump(pipe[1].getFileDescriptor(),arguments);}finally{pipe[1].close();}
        long remaining=deadline.getAsLong()-SystemClock.elapsedRealtime();if(remaining>0)reader.join(remaining);
        if(reader.isAlive()){pipe[0].close();throw new IOException("PUBLIC_AUDIT_PHYSICAL_DUMP_DEADLINE");}
        if(failure.get()!=null)throw new IOException("PUBLIC_AUDIT_PHYSICAL_DUMP_FAILED",failure.get());
        if(SystemClock.elapsedRealtime()>=deadline.getAsLong())throw new IOException("PUBLIC_AUDIT_PHYSICAL_DUMP_DEADLINE");
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes.toByteArray())).toString();
    }
}
