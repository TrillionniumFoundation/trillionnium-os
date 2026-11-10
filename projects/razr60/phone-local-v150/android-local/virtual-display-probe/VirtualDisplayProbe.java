package org.trillionnium.hepta.displayprobe;

import android.app.UiAutomation;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.PixelFormat;
import android.hardware.display.DisplayManager;
import android.hardware.display.VirtualDisplay;
import android.media.Image;
import android.media.ImageReader;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.SystemClock;
import android.util.SparseArray;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityWindowInfo;
import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import org.json.JSONArray;
import org.json.JSONObject;

/** Bounded shell-owned feasibility probe; no network, arbitrary RPC or model control. */
public final class VirtualDisplayProbe {
    private static File root;
    private static VirtualDisplay display;
    private static ImageReader reader;
    private static UiAutomation observer;
    private static HandlerThread observerThread;
    private static String generation;
    private static int displayId = -1;
    private static long deadline;
    private static int frames;
    private static boolean closed;
    private static Handler handler;
    private static final int WIDTH = 720, HEIGHT = 1280;
    // SDK 36 hidden flag values; actual acceptance is checked in dumpsys.
    private static final int FLAGS = (1 << 0) | (1 << 3) | (1 << 6) | (1 << 8)
        | (1 << 10) | (1 << 14) | (1 << 16);

    private static void write(String name, JSONObject value) throws Exception {
        value.put("generation", generation).put("display_id", displayId)
             .put("uptime_ms", SystemClock.uptimeMillis());
        File target = new File(root, name);
        File tmp = new File(root, name + ".tmp");
        try (FileOutputStream out = new FileOutputStream(tmp)) {
            out.write((value.toString(2) + "\n").getBytes(StandardCharsets.UTF_8));
            out.getFD().sync();
        }
        if (!tmp.renameTo(target)) throw new IllegalStateException("receipt rename failed");
    }

    private static void close(String reason) {
        if (closed) return;
        closed = true;
        try { if (observer != null) UiAutomation.class.getMethod("disconnect").invoke(observer); } catch (Throwable ignored) {}
        try { if (display != null) display.release(); } catch (Throwable ignored) {}
        try { if (reader != null) reader.close(); } catch (Throwable ignored) {}
        try { if (observerThread != null) observerThread.quitSafely(); } catch (Throwable ignored) {}
        try { write("terminal.json", new JSONObject().put("status","released")
             .put("reason",reason).put("frames",frames)); } catch (Throwable error) { error.printStackTrace(); }
    }

    private static JSONObject node(AccessibilityNodeInfo n, int depth, int[] count) throws Exception {
        if (n == null || depth > 24 || ++count[0] > 2000) return null;
        android.graphics.Rect bounds = new android.graphics.Rect();
        n.getBoundsInScreen(bounds);
        JSONObject j = new JSONObject().put("window_id",n.getWindowId())
            .put("package",String.valueOf(n.getPackageName()))
            .put("class",String.valueOf(n.getClassName()))
            .put("id",n.getViewIdResourceName()).put("text",String.valueOf(n.getText()))
            .put("description",String.valueOf(n.getContentDescription()))
            .put("bounds",bounds.flattenToString()).put("clickable",n.isClickable())
            .put("editable",n.isEditable()).put("visible",n.isVisibleToUser());
        JSONArray children = new JSONArray();
        if (!n.isPassword()) for (int i=0; i<n.getChildCount(); ++i) {
            AccessibilityNodeInfo child=n.getChild(i);
            try { JSONObject value=node(child,depth+1,count); if(value!=null) children.put(value); }
            finally { if(child!=null) child.recycle(); }
        }
        if(n.isPassword()) j.put("text","REDACTED").put("description","REDACTED");
        return j.put("children",children);
    }

    private static void observe() throws Exception {
        if(observer==null) {
            observerThread=new HandlerThread("HeptaDisplayObserver");
            observerThread.start();
            Class<?> connectionClass=Class.forName("android.app.UiAutomationConnection");
            Object connection=connectionClass.getDeclaredConstructor().newInstance();
            Class<?> connectionInterface=Class.forName("android.app.IUiAutomationConnection");
            Constructor<UiAutomation> ctor=UiAutomation.class.getDeclaredConstructor(Looper.class,connectionInterface);
            ctor.setAccessible(true);
            observer=ctor.newInstance(observerThread.getLooper(),connection);
            UiAutomation.class.getMethod("connect",int.class).invoke(observer,UiAutomation.FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES);
            android.accessibilityservice.AccessibilityServiceInfo info=observer.getServiceInfo();
            info.flags |= android.accessibilityservice.AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
                       | android.accessibilityservice.AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS;
            observer.setServiceInfo(info);
        }
        SparseArray<List<AccessibilityWindowInfo>> all=observer.getWindowsOnAllDisplays();
        JSONArray windows=new JSONArray();
        List<AccessibilityWindowInfo> target=all.get(displayId);
        if(target!=null) for(AccessibilityWindowInfo w:target) {
            JSONObject item=new JSONObject().put("id",w.getId()).put("display_id",w.getDisplayId())
                .put("active",w.isActive()).put("focused",w.isFocused()).put("title",String.valueOf(w.getTitle()));
            AccessibilityNodeInfo n=w.getRoot();
            try { item.put("root",node(n,0,new int[1])); } finally {if(n!=null)n.recycle();}
            windows.put(item);
        }
        write("observation.json",new JSONObject().put("windows",windows)
            .put("non_suppressing",true).put("frames",frames));
    }

    public static void main(String[] args) throws Exception {
        if(args.length!=1 || !args[0].matches("/data/local/tmp/hepta-vdisplay-[a-zA-Z0-9-]+"))
            throw new IllegalArgumentException("unique private probe directory required");
        root=new File(args[0]);
        if(!root.isDirectory())throw new IllegalArgumentException("directory missing");
        generation=UUID.randomUUID().toString();
        Looper.prepareMainLooper();
        handler=new Handler(Looper.getMainLooper());
        Object thread=Class.forName("android.app.ActivityThread").getMethod("systemMain").invoke(null);
        Context system=(Context)thread.getClass().getMethod("getSystemContext").invoke(thread);
        Context shell=system.createPackageContext("com.android.shell",0);
        DisplayManager dm=(DisplayManager)shell.getSystemService(Context.DISPLAY_SERVICE);
        reader=ImageReader.newInstance(WIDTH,HEIGHT,PixelFormat.RGBA_8888,3);
        reader.setOnImageAvailableListener(r -> {
            try(Image image=r.acquireLatestImage()) {
                if(image==null)return;
                ++frames;
                File trigger=new File(root,"capture");
                if(!trigger.exists())return;
                Image.Plane plane=image.getPlanes()[0];
                int stride=plane.getRowStride()/plane.getPixelStride();
                Bitmap padded=Bitmap.createBitmap(stride,HEIGHT,Bitmap.Config.ARGB_8888);
                padded.copyPixelsFromBuffer(plane.getBuffer());
                Bitmap exact=Bitmap.createBitmap(padded,0,0,WIDTH,HEIGHT);
                try(FileOutputStream out=new FileOutputStream(new File(root,"frame.png"))) {
                    exact.compress(Bitmap.CompressFormat.PNG,100,out);
                }
                if(exact!=padded)exact.recycle();
                padded.recycle();
                trigger.delete();
                write("capture.json",new JSONObject().put("frames",frames).put("width",WIDTH).put("height",HEIGHT));
            } catch(Throwable error){error.printStackTrace();}
        },handler);
        display=dm.createVirtualDisplay("Hepta background probe",WIDTH,HEIGHT,240,reader.getSurface(),FLAGS);
        if(display==null)throw new IllegalStateException("virtual display unavailable");
        displayId=display.getDisplay().getDisplayId();
        Object wm=Class.forName("android.view.WindowManagerGlobal").getMethod("getWindowManagerService").invoke(null);
        Class.forName("android.view.IWindowManager").getMethod("setDisplayImePolicy",int.class,int.class).invoke(wm,displayId,2);
        deadline=SystemClock.elapsedRealtime()+300000L;
        write("created.json",new JSONObject().put("status","created").put("uid",android.os.Process.myUid())
            .put("pid",android.os.Process.myPid()).put("requested_flags",FLAGS)
            .put("display_flags",display.getDisplay().getFlags()).put("ime_policy","hide")
            .put("ttl_ms",300000).put("capture_secure",false).put("always_unlocked",false));
        Runtime.getRuntime().addShutdownHook(new Thread(() -> close("process_shutdown")));
        handler.post(new Runnable() { public void run() {
            try {
                if(new File(root,"stop").exists() || SystemClock.elapsedRealtime()>=deadline) {
                    close("stop_or_deadline"); System.exit(0); return;
                }
                File request=new File(root,"observe");
                if(request.exists()) {
                    request.delete();
                    try { observe(); } catch(Throwable error) {
                        write("observation-error.json",new JSONObject().put("error",error.toString()));
                    }
                }
            } catch(Throwable error){error.printStackTrace();}
            handler.postDelayed(this,250);
        }});
        Looper.loop();
    }
}
