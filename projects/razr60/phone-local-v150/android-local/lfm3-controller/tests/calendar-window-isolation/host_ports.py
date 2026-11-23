"""Explicit host Android/Binder/geometry IO ports, not a ROM implementation."""
BOOT = {
 'android/os/IBinder.java': '''package android.os; public interface IBinder {boolean isBinderAlive();}''',
 'android/os/Binder.java': '''package android.os; public final class Binder implements IBinder {public boolean alive=true;public boolean isBinderAlive(){return alive;}}''',
 'android/os/Process.java': '''package android.os; public final class Process {public static int uid=0;public static int myUid(){return uid;}}''',
 'android/os/Build.java': '''package android.os; public final class Build {public static final class VERSION {public static int SDK_INT=36;}}''',
 'android/os/SystemClock.java': '''package android.os; public final class SystemClock {public static volatile long now=1000;public static long elapsedRealtime(){return now;}}''',
 'android/os/InputConfig.java': '''package android.os; public final class InputConfig {public static final int DEFAULT=0,NO_INPUT_CHANNEL=1,NOT_VISIBLE=2,NOT_TOUCHABLE=4,SPY=8,CLONE=16,DUPLICATE_TOUCH_TO_WALLPAPER=32,IS_WALLPAPER=64,SLIPPERY=128,NOT_FOCUSABLE=256;}''',
 'android/util/Pair.java': '''package android.util; public final class Pair<A,B> {public final A first;public final B second;public Pair(A a,B b){first=a;second=b;}}''',
 'android/util/Size.java': '''package android.util; public final class Size {private final int w,h;public Size(int w,int h){this.w=w;this.h=h;}public int getWidth(){return w;}public int getHeight(){return h;}}''',
 'android/graphics/Rect.java': '''package android.graphics; public final class Rect {public int left,top,right,bottom;public Rect(){}public Rect(int l,int t,int r,int b){left=l;top=t;right=r;bottom=b;}public Rect(Rect r){this(r.left,r.top,r.right,r.bottom);}}''',
 'android/graphics/Matrix.java': '''package android.graphics; public final class Matrix {private float[] v={1,0,0,0,1,0,0,0,1};public Matrix(){}public Matrix(Matrix x){v=x.v.clone();}public void setValues(float[] x){v=x.clone();}public void getValues(float[] x){System.arraycopy(v,0,x,0,9);}}''',
 'android/graphics/Region.java': '''package android.graphics; import java.util.*; public final class Region {public final List<Rect> rects=new ArrayList<Rect>();public Region(){}public Region(Rect r){rects.add(new Rect(r));}public Region(Region r){for(Rect x:r.rects)rects.add(new Rect(x));}}''',
 'android/graphics/RegionIterator.java': '''package android.graphics; public final class RegionIterator {private final Region r;private int i;public RegionIterator(Region r){this.r=r;}public boolean next(Rect out){if(i==r.rects.size())return false;Rect x=r.rects.get(i++);out.left=x.left;out.top=x.top;out.right=x.right;out.bottom=x.bottom;return true;}}''',
 'android/view/InputWindowHandle.java': '''package android.view;
 public final class InputWindowHandle {
  public android.os.IBinder token,windowToken;public int displayId,ownerUid,ownerPid,inputConfig,layoutParamsType,layoutParamsFlags;
  public String packageName;public android.graphics.Rect frame;public android.graphics.Region touchableRegion;
  public android.graphics.Matrix transform;public float alpha;public Runnable beforeToken;
  public android.os.IBinder getWindowToken(){if(beforeToken!=null)beforeToken.run();return windowToken;}
 }''',
 'android/window/WindowInfosListener.java': '''package android.window;
 import android.view.InputWindowHandle;import android.util.*;import android.graphics.Matrix;
 public abstract class WindowInfosListener {
  public static WindowInfosListener last;public static Runnable onRegister,onUnregister;
  public static boolean registerFails,unregisterFails;public static int registrations,unregistrations;
  public static Pair<InputWindowHandle[],DisplayInfo[]> cache;
  public WindowInfosListener(){}
  public abstract void onWindowInfosChanged(InputWindowHandle[] w,DisplayInfo[] d);
  public Pair<InputWindowHandle[],DisplayInfo[]> register(){last=this;registrations++;if(registerFails)throw new IllegalStateException("register IO");if(onRegister!=null)onRegister.run();return cache;}
  public void unregister(){unregistrations++;if(onUnregister!=null)onUnregister.run();if(unregisterFails)throw new IllegalStateException("unregister IO");}
  public static void reset(){last=null;onRegister=null;onUnregister=null;registerFails=false;unregisterFails=false;registrations=0;unregistrations=0;cache=null;}
  public static final class DisplayInfo {public int mDisplayId;public Size mLogicalSize;public Matrix mTransform;public DisplayInfo(int id,int w,int h){mDisplayId=id;mLogicalSize=new Size(w,h);mTransform=new Matrix();}}
 }''',
 'android/app/ActivityManager.java': '''package android.app; public final class ActivityManager {public static int currentUser=0;public static int getCurrentUser(){return currentUser;}}''',
 'android/os/ServiceManager.java': '''package android.os; public final class ServiceManager {public static IBinder accessibility;public static IBinder getService(String s){if(!"accessibility".equals(s))throw new AssertionError("unexpected service");return accessibility;}}''',
 'android/view/accessibility/IAccessibilityManager.java': '''package android.view.accessibility;import android.os.IBinder;
 public interface IAccessibilityManager {IBinder getWindowToken(int w,int user);
  public static final class Stub {public static IAccessibilityManager service;public static IAccessibilityManager asInterface(IBinder b){return service;}}
 }'''
}
APP = {
 'org/trillionnium/hepta/background/ProfilePackages.java': '''package org.trillionnium.hepta.background;
 /** Only the Android UserManager/PackageManager read port is replaced in this fixture. */
 public final class ProfilePackages {public interface Identity {ProfileIdentity read(int user);}
  public Identity source;public ProfilePackages(Identity s){source=s;}public ProfileIdentity identity(int user){return source.read(user);}}
'''
}
LOADER = '''import java.net.*;import java.nio.file.*;
public final class CalendarHostLoader {
 public static void main(String[] a)throws Exception{
  URLClassLoader boot=new URLClassLoader(new URL[]{Paths.get(a[0]).toUri().toURL()},null);
  URLClassLoader app=new URLClassLoader(new URL[]{Paths.get(a[1]).toUri().toURL(),Paths.get(a[2]).toUri().toURL()},boot);
  try{Class.forName("org.trillionnium.hepta.background.CalendarWindowHostTest",true,app)
    .getMethod("main",String[].class).invoke(null,(Object)new String[]{a[3]});}
  catch(java.lang.reflect.InvocationTargetException e){Throwable x=e.getCause();if(x instanceof Exception)throw(Exception)x;if(x instanceof Error)throw(Error)x;throw new RuntimeException(x);}
  finally{app.close();boot.close();}
 }
}'''
