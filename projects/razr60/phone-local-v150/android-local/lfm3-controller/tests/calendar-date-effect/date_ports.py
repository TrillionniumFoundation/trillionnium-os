"""Explicit host platform ports for the exact calendar-date broker methods, not Android qualification."""
import importlib.util
from pathlib import Path
P=Path(__file__).resolve().parents[1]/'calendar-window-isolation'/'host_ports.py'
spec=importlib.util.spec_from_file_location('date_base_android_ports',P)
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
BOOT=dict(base.BOOT);APP=dict(base.APP)
BOOT['android/os/SystemClock.java']='''package android.os;public final class SystemClock {public static volatile long now=1000,uptime=71;public static long elapsedRealtime(){return now;}public static long uptimeMillis(){return uptime;}}'''
BOOT['android/view/InputEvent.java']='''package android.view;public abstract class InputEvent {public abstract int getDisplayId();public abstract int getDeviceId();}'''
BOOT['android/view/InputDevice.java']='''package android.view;public final class InputDevice {public static final int SOURCE_TOUCHSCREEN=4098,SOURCE_KEYBOARD=257;}'''
BOOT['android/view/KeyCharacterMap.java']='''package android.view;public final class KeyCharacterMap {public static final int VIRTUAL_KEYBOARD=-1;}'''
BOOT['android/view/MotionEvent.java']='''package android.view;
public final class MotionEvent extends InputEvent {
 public static final int ACTION_DOWN=0,ACTION_UP=1,ACTION_CANCEL=3,TOOL_TYPE_FINGER=1,FLAG_NO_FOCUS_CHANGE=1073741824;
 public static Runnable afterSetDisplay;public static int created,recycled;
 public static final class PointerProperties {public int id,toolType;}
 public static final class PointerCoords {public float x,y,pressure,size;}
 private long downTime,eventTime;private int action,display,device,source,flags,pointerId,toolType;private float x,y,pressure;private boolean closed;
 public static MotionEvent obtain(long down,long when,int action,int count,PointerProperties[] p,PointerCoords[] c,int meta,int buttons,float xp,float yp,int device,int edge,int source,int flags){
  if(count!=1||p.length!=1||c.length!=1||meta!=0||buttons!=0||edge!=0||xp!=1f||yp!=1f)throw new AssertionError("unexpected motion construction");
  MotionEvent m=new MotionEvent();m.downTime=down;m.eventTime=when;m.action=action;m.device=device;m.source=source;m.flags=flags;m.pointerId=p[0].id;m.toolType=p[0].toolType;m.x=c[0].x;m.y=c[0].y;m.pressure=c[0].pressure;created++;return m;
 }
 public void setDisplayId(int id){display=id;if(afterSetDisplay!=null)afterSetDisplay.run();}
 public int getDisplayId(){return display;}public int getDeviceId(){return device;}public int getPointerCount(){return 1;}
 public int getPointerId(int i){if(i!=0)throw new AssertionError();return pointerId;}public int getToolType(int i){if(i!=0)throw new AssertionError();return toolType;}
 public int getActionMasked(){return action;}public int getSource(){return source;}public int getFlags(){return flags;}
 public long getDownTime(){return downTime;}public long getEventTime(){return eventTime;}public float getX(){return x;}public float getY(){return y;}public float getPressure(){return pressure;}
 public void recycle(){if(closed)throw new AssertionError("recycled twice");closed=true;recycled++;}
 public static void reset(){afterSetDisplay=null;created=0;recycled=0;android.os.SystemClock.uptime=71;}
}'''
BOOT['android/hardware/input/InputManager.java']='''package android.hardware.input;
import android.view.*;import java.util.*;
public final class InputManager {
 public static final int INJECT_INPUT_EVENT_MODE_WAIT_FOR_RESULT=1;
 public final List<Map<String,Object>> calls=new ArrayList<Map<String,Object>>();
 public boolean downResult=true,upResult=true;public RuntimeException downError,upError;public Runnable beforeDownReturn,beforeUpReturn;
 public boolean injectInputEvent(InputEvent value,int mode,int targetUid){
  if(!(value instanceof MotionEvent))throw new AssertionError("not motion");MotionEvent e=(MotionEvent)value;
  Map<String,Object> r=new LinkedHashMap<String,Object>();r.put("action",e.getActionMasked());r.put("mode",mode);r.put("uid",targetUid);r.put("display",e.getDisplayId());r.put("device",e.getDeviceId());r.put("source",e.getSource());r.put("flags",e.getFlags());r.put("pointer",e.getPointerId(0));r.put("tool",e.getToolType(0));r.put("down",e.getDownTime());r.put("time",e.getEventTime());r.put("x",e.getX());r.put("y",e.getY());r.put("pressure",e.getPressure());calls.add(r);
  if(e.getActionMasked()==MotionEvent.ACTION_DOWN){if(beforeDownReturn!=null)beforeDownReturn.run();if(downError!=null)throw downError;return downResult;}
  if(e.getActionMasked()==MotionEvent.ACTION_UP){if(beforeUpReturn!=null)beforeUpReturn.run();if(upError!=null)throw upError;return upResult;}
  throw new AssertionError("CANCEL or other input");
 }
}'''
APP['org/trillionnium/hepta/background/ProfilePackages.java']='''package org.trillionnium.hepta.background;
/** Only UserManager/PackageManager live read IO is replaced. Actual guard and same-target comparison execute. */
public final class ProfilePackages {
 public interface Identity {ProfileIdentity read(int user);}
 public Identity source;public ProfileTarget installedTarget;public Runnable beforePackageRead;public int packageReads;
 public ProfilePackages(Identity s){source=s;}public ProfileIdentity identity(int user){return source.read(user);}
 public Readback read(int user,String pkg,boolean ready,long deadline)throws Exception{packageReads++;if(beforePackageRead!=null)beforePackageRead.run();if(android.os.SystemClock.elapsedRealtime()>=deadline)throw new BrokerProtocol.Refusal("PROFILE_READ_DEADLINE");if(user!=10||!ProfileTarget.CTRIP.equals(pkg)||!ready)throw new AssertionError("unexpected profile read");return new Readback(installedTarget);}
 public static final class Readback {public final ProfileTarget target;Readback(ProfileTarget t){target=t;}}
}'''
LOADER=base.LOADER.replace('CalendarWindowHostTest','CalendarDateEntryHostTest')
