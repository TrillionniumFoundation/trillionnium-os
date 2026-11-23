package org.trillionnium.hepta.background;

import android.graphics.Matrix;
import android.graphics.Rect;
import android.graphics.Region;
import android.graphics.RegionIterator;
import android.os.IBinder;
import android.os.SystemClock;
import android.util.Pair;
import android.util.Size;
import android.view.InputWindowHandle;
import android.window.WindowInfosListener;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * One real boot-framework listener, owned by one broker read request.
 * The register() cache is diagnostic only. Qualification requires a new actual callback.
 * No input events, SurfaceControl transactions, shell commands, or permission changes occur here.
 */
final class WindowInfosCapture {
    private final Object lock=new Object();
    private final long deadline;
    private final Access access;
    private final Listener listener;
    private boolean registrationAttempted,registrationReturned,retired,unregisterClaimed,unregisterReturned;
    private boolean unregisterFailed;
    private int callbacksInFlight,cachedWindows=-1,cachedDisplays=-1;
    private long registerStarted=-1,registerEnded=-1,retiredAt=-1,unregisterStarted=-1,unregisterEnded=-1;
    private long callbackArrivals,callbackFinishes,ignoredAfterRetirement,supersededCallbacks;
    private long lastCallbackFinishedElapsedMs=-1;
    private String failure;
    private InputChannelIsolation.Census current;

    WindowInfosCapture(long deadline)throws InputChannelIsolation.Refusal{
        InputChannelIsolation.need(deadline>SystemClock.elapsedRealtime(),"INPUT_CAPTURE_DEADLINE");
        this.deadline=deadline;
        try{
            requireBootApi();access=new Access();listener=new Listener(this);
        }catch(InputChannelIsolation.Refusal e){throw e;}
        catch(Throwable e){throw new InputChannelIsolation.Refusal("INPUT_BOOT_API_UNAVAILABLE");}
    }

    private static void requireBootApi()throws Exception{
        InputChannelIsolation.need(android.os.Process.myUid()==0,"INPUT_CAPTURE_ROOT_REQUIRED");
        InputChannelIsolation.need(android.os.Build.VERSION.SDK_INT==36,"INPUT_CAPTURE_PLATFORM_UNSUPPORTED");
        ClassLoader boot=IBinder.class.getClassLoader();
        InputChannelIsolation.need(WindowInfosListener.class.getClassLoader()==boot
                &&InputWindowHandle.class.getClassLoader()==boot
                &&WindowInfosListener.DisplayInfo.class.getClassLoader()==boot
                &&WindowInfosCapture.class.getClassLoader()!=boot,"INPUT_CAPTURE_NOT_BOOT_FRAMEWORK");
        InputChannelIsolation.need(Class.forName("android.os.InputConfig").getClassLoader()==boot,
                "INPUT_CONFIG_NOT_BOOT_FRAMEWORK");
    }

    void register()throws InputChannelIsolation.Refusal{
        synchronized(lock){
            InputChannelIsolation.need(!registrationAttempted&&!retired&&SystemClock.elapsedRealtime()<deadline,
                    "INPUT_LISTENER_REGISTRATION_NOT_ALLOWED");
            registrationAttempted=true;registerStarted=SystemClock.elapsedRealtime();
        }
        try{
            Pair<InputWindowHandle[],WindowInfosListener.DisplayInfo[]> cache=listener.register();
            synchronized(lock){
                registrationReturned=true;registerEnded=SystemClock.elapsedRealtime();
                if(cache!=null){cachedWindows=cache.first==null?-1:cache.first.length;cachedDisplays=cache.second==null?-1:cache.second.length;}
                lock.notifyAll();
                InputChannelIsolation.need(!retired&&registerEnded<deadline,"INPUT_LISTENER_REGISTRATION_LATE");
            }
        }catch(InputChannelIsolation.Refusal e){fail(e.code);throw e;}
        catch(Throwable e){fail("INPUT_LISTENER_REGISTRATION_FAILED");throw new InputChannelIsolation.Refusal("INPUT_LISTENER_REGISTRATION_FAILED");}
    }

    InputChannelIsolation.Census awaitCallback()throws InputChannelIsolation.Refusal{
        synchronized(lock){
            while(true){
                requireOpenLocked();
                if(current!=null&&callbacksInFlight==0&&current.ordinal==callbackArrivals){
                    requireCurrentLocked(current);return current;
                }
                long now=SystemClock.elapsedRealtime();
                InputChannelIsolation.need(now<deadline,"INPUT_CALLBACK_DEADLINE");
                try{lock.wait(Math.max(1,Math.min(20,deadline-now)));}
                catch(InterruptedException e){Thread.currentThread().interrupt();throw new InputChannelIsolation.Refusal("INPUT_CALLBACK_WAIT_INTERRUPTED");}
            }
        }
    }

    void requireCurrent(InputChannelIsolation.Census expected)throws InputChannelIsolation.Refusal{
        synchronized(lock){requireOpenLocked();requireCurrentLocked(expected);}
    }
    private void requireOpenLocked()throws InputChannelIsolation.Refusal{
        InputChannelIsolation.need(registrationAttempted&&registrationReturned&&!retired&&!unregisterClaimed,
                "INPUT_LISTENER_NOT_LIVE");
        InputChannelIsolation.need(failure==null,failure==null?"INPUT_LISTENER_FAILED":failure);
    }
    private void requireCurrentLocked(InputChannelIsolation.Census expected)throws InputChannelIsolation.Refusal{
        long now=SystemClock.elapsedRealtime();
        InputChannelIsolation.need(expected!=null&&current==expected&&callbacksInFlight==0
                &&callbackArrivals==callbackFinishes&&expected.ordinal==callbackArrivals,
                "INPUT_CALLBACK_CHANGED_DURING_READ");
        InputChannelIsolation.need(now>=expected.completedElapsedMs&&now<deadline
                &&now-expected.receivedElapsedMs<=InputChannelIsolation.MAX_CALLBACK_AGE_MS,"INPUT_CENSUS_STALE");
    }

    /** Nonblocking admission retirement. A late native callback cannot republish any token. */
    void retire(){synchronized(lock){if(!retired){retired=true;retiredAt=SystemClock.elapsedRealtime();}current=null;lock.notifyAll();}}

    /**
     * The native unregister call is made exactly once, outside our callback lock.
     * Its return does not claim that SurfaceFlinger's asynchronous removal queue has drained.
     * Local retirement plus actual callback drain is recorded separately.
     */
    void unregisterAndDrain(long closeDeadline)throws InputChannelIsolation.Refusal{
        retire();boolean call=false;
        synchronized(lock){
            if(registrationAttempted&&!unregisterClaimed){unregisterClaimed=true;unregisterStarted=SystemClock.elapsedRealtime();call=true;}
        }
        if(call){
            try{listener.unregister();synchronized(lock){unregisterReturned=true;unregisterEnded=SystemClock.elapsedRealtime();lock.notifyAll();}}
            catch(Throwable e){synchronized(lock){unregisterFailed=true;unregisterEnded=SystemClock.elapsedRealtime();lock.notifyAll();}}
        }
        synchronized(lock){
            while(!locallyDrainedLocked()){
                if(unregisterFailed)throw new InputChannelIsolation.Refusal("INPUT_LISTENER_UNREGISTER_UNKNOWN");
                long now=SystemClock.elapsedRealtime();
                InputChannelIsolation.need(now<closeDeadline,"INPUT_LISTENER_DRAIN_DEADLINE");
                try{lock.wait(Math.max(1,Math.min(20,closeDeadline-now)));}
                catch(InterruptedException e){Thread.currentThread().interrupt();throw new InputChannelIsolation.Refusal("INPUT_LISTENER_DRAIN_INTERRUPTED");}
            }
        }
    }
    boolean locallyDrained(){synchronized(lock){return locallyDrainedLocked();}}
    private boolean locallyDrainedLocked(){return retired&&current==null&&callbacksInFlight==0
            &&callbackFinishes==callbackArrivals&&(!registrationAttempted||unregisterReturned)&&!unregisterFailed;}

    Map<String,Object> evidence(){
        synchronized(lock){
            Map<String,Object> v=new LinkedHashMap<String,Object>();
            v.put("schema","hepta.window-infos-listener-lifecycle.v1");
            v.put("actual_boot_framework_required",true);v.put("registration_attempted",registrationAttempted);
            v.put("registration_returned",registrationReturned);v.put("register_started_elapsed_ms",registerStarted);
            v.put("register_ended_elapsed_ms",registerEnded);v.put("original_deadline_elapsed_ms",deadline);
            v.put("register_cache_window_count",cachedWindows);v.put("register_cache_display_count",cachedDisplays);
            v.put("register_cache_grants_currentness",false);v.put("callback_arrivals",callbackArrivals);
            v.put("callback_finishes",callbackFinishes);v.put("callbacks_in_flight",callbacksInFlight);
            v.put("last_callback_finished_elapsed_ms",lastCallbackFinishedElapsedMs);
            v.put("superseded_callbacks",supersededCallbacks);v.put("late_callbacks_ignored",ignoredAfterRetirement);
            v.put("retired",retired);v.put("retired_elapsed_ms",retiredAt);v.put("retains_current_census",current!=null);
            v.put("unregister_attempted",unregisterClaimed);v.put("unregister_returned",unregisterReturned);
            v.put("unregister_failed",unregisterFailed);v.put("unregister_started_elapsed_ms",unregisterStarted);
            v.put("unregister_ended_elapsed_ms",unregisterEnded);v.put("local_callbacks_drained",locallyDrainedLocked());
            v.put("surfaceflinger_removal_queue_drain_observed",false);v.put("failure",failure);
            v.put("grants_dispatch",false);v.put("input_attempts",0);return Collections.unmodifiableMap(v);
        }
    }

    private void fail(String code){synchronized(lock){if(failure==null)failure=code;current=null;lock.notifyAll();}}
    private void callback(InputWindowHandle[] windows,WindowInfosListener.DisplayInfo[] displays){
        final long ordinal,received;
        synchronized(lock){
            if(retired){ignoredAfterRetirement++;return;}
            if(!registrationAttempted){failure="INPUT_CALLBACK_BEFORE_REGISTRATION";current=null;lock.notifyAll();return;}
            ordinal=++callbackArrivals;callbacksInFlight++;received=SystemClock.elapsedRealtime();
        }
        InputChannelIsolation.Census captured=null;String error=null;
        try{captured=access.copy(ordinal,received,windows,displays);}
        catch(InputChannelIsolation.Refusal e){error=e.code;}
        catch(Throwable e){error="INPUT_CALLBACK_READ_FAILED";}
        finally{
            synchronized(lock){
                callbacksInFlight--;callbackFinishes++;lastCallbackFinishedElapsedMs=SystemClock.elapsedRealtime();
                if(error!=null&&failure==null)failure=error;
                if(!retired&&failure==null&&ordinal==callbackArrivals)current=captured;
                else if(!retired&&failure==null)supersededCallbacks++;
                if(retired||failure!=null)current=null;
                lock.notifyAll();
            }
        }
    }

    private static final class Listener extends WindowInfosListener {
        private final WindowInfosCapture owner;
        Listener(WindowInfosCapture owner){super();this.owner=owner;}
        @Override public void onWindowInfosChanged(InputWindowHandle[] windows,WindowInfosListener.DisplayInfo[] displays){
            owner.callback(windows,displays);
        }
    }

    /** Raw public fields on the hidden boot class; never the lossy ForTest projection. */
    private static final class Access {
        private final Map<String,Field> windowFields=new LinkedHashMap<String,Field>();
        private final Map<String,Field> displayFields=new LinkedHashMap<String,Field>();
        private final Method getWindowToken;
        private final InputChannelIsolation.Flags flags;
        Access()throws Exception{
            for(String name:new String[]{"token","displayId","ownerUid","ownerPid","packageName","inputConfig",
                    "layoutParamsType","layoutParamsFlags","frame","touchableRegion","transform","alpha"})
                windowFields.put(name,InputWindowHandle.class.getField(name));
            for(String name:new String[]{"mDisplayId","mLogicalSize","mTransform"})
                displayFields.put(name,WindowInfosListener.DisplayInfo.class.getField(name));
            getWindowToken=InputWindowHandle.class.getMethod("getWindowToken");
            Map<String,Integer> constants=new TreeMap<String,Integer>();
            for(Field f:Class.forName("android.os.InputConfig").getFields())
                if(Modifier.isStatic(f.getModifiers())&&Modifier.isFinal(f.getModifiers())&&f.getType()==Integer.TYPE)
                    constants.put(f.getName(),f.getInt(null));
            flags=new InputChannelIsolation.Flags(constants);
        }
        InputChannelIsolation.Census copy(long ordinal,long received,InputWindowHandle[] rawWindows,
                WindowInfosListener.DisplayInfo[] rawDisplays)throws Exception{
            InputChannelIsolation.need(rawWindows!=null&&rawWindows.length>0&&rawWindows.length<=InputChannelIsolation.MAX_WINDOWS
                    &&rawDisplays!=null&&rawDisplays.length>0&&rawDisplays.length<=InputChannelIsolation.MAX_DISPLAYS,
                    "INPUT_CALLBACK_ARRAYS_INCOMPLETE");
            List<InputChannelIsolation.DisplayFacts> displays=new ArrayList<InputChannelIsolation.DisplayFacts>();
            for(Object d:rawDisplays){
                InputChannelIsolation.need(d!=null&&d.getClass()==WindowInfosListener.DisplayInfo.class,"INPUT_DISPLAY_RUNTIME_TYPE");
                Object size=displayFields.get("mLogicalSize").get(d),matrix=displayFields.get("mTransform").get(d);
                InputChannelIsolation.need(size instanceof Size&&matrix instanceof Matrix,"INPUT_DISPLAY_FACTS_INCOMPLETE");
                displays.add(new InputChannelIsolation.DisplayFacts(displayFields.get("mDisplayId").getInt(d),
                        ((Size)size).getWidth(),((Size)size).getHeight(),matrix((Matrix)matrix)));
            }
            List<InputChannelIsolation.WindowFacts> windows=new ArrayList<InputChannelIsolation.WindowFacts>();
            int rectangleCount=0;
            for(Object w:rawWindows){
                InputChannelIsolation.need(w!=null&&w.getClass()==InputWindowHandle.class,"INPUT_WINDOW_RUNTIME_TYPE");
                Object input=windowFields.get("token").get(w),window=getWindowToken.invoke(w);
                InputChannelIsolation.need((input==null||input instanceof IBinder)&&(window==null||window instanceof IBinder),
                        "INPUT_TOKEN_RUNTIME_TYPE");
                Object frame=windowFields.get("frame").get(w),region=windowFields.get("touchableRegion").get(w),
                        transform=windowFields.get("transform").get(w),pkg=windowFields.get("packageName").get(w);
                InputChannelIsolation.need(frame instanceof Rect&&region instanceof Region&&transform instanceof Matrix
                        &&pkg instanceof String,"INPUT_WINDOW_FACTS_INCOMPLETE");
                Rect r=new Rect((Rect)frame);Region frozenRegion=new Region((Region)region);
                RegionIterator iterator=new RegionIterator(frozenRegion);Rect part=new Rect();List<int[]> rects=new ArrayList<int[]>();
                while(iterator.next(part)){
                    rectangleCount++;InputChannelIsolation.need(rectangleCount<=InputChannelIsolation.MAX_REGION_RECTS,"INPUT_CENSUS_REGION_LIMIT");
                    rects.add(rect(part));
                }
                windows.add(new InputChannelIsolation.WindowFacts(input,window,
                        integer(w,"displayId"),integer(w,"ownerUid"),integer(w,"ownerPid"),(String)pkg,
                        integer(w,"inputConfig"),integer(w,"layoutParamsType"),integer(w,"layoutParamsFlags"),
                        rect(r),rects.toArray(new int[rects.size()][]),matrix((Matrix)transform),
                        windowFields.get("alpha").getFloat(w)));
            }
            return new InputChannelIsolation.Census(ordinal,received,SystemClock.elapsedRealtime(),windows,displays,flags);
        }
        private int integer(Object w,String name)throws IllegalAccessException{return windowFields.get(name).getInt(w);}
        private static int[] rect(Rect r){return new int[]{r.left,r.top,r.right,r.bottom};}
        private static float[] matrix(Matrix m){Matrix copy=new Matrix(m);float[] v=new float[9];copy.getValues(v);return v;}
    }
}
