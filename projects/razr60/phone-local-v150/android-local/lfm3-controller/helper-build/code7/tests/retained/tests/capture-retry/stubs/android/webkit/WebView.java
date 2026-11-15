package android.webkit;
import java.util.*;
public final class WebView {
 public abstract static class VisualStateCallback {public abstract void onComplete(long id);}
 public static final class Visual {public final long id;public final VisualStateCallback callback;Visual(long i,VisualStateCallback c){id=i;callback=c;}}
 public static final class Posted {public final long at;public final Runnable runnable;Posted(long t,Runnable r){at=t;runnable=r;}}
 public final ArrayDeque<ValueCallback<String>> javascript=new ArrayDeque<ValueCallback<String>>();
 public final ArrayDeque<Visual> visuals=new ArrayDeque<Visual>();
 public final ArrayList<Posted> posted=new ArrayList<Posted>();
 public final ArrayList<String> scripts=new ArrayList<String>();
 public final android.content.Context context;
 public final android.view.Display display=new android.view.Display(0);
 public final WebSettings settings=new WebSettings();
 public WebViewClient client;
 public String url="https://www.mi.com/shop/search?keyword=AX3000T";
 public boolean attached=true,shown=true,acceptPost=true;
 public int window=33,left=0,top=400,width=1224,height=2500,scrollX,scrollY,padding;
 public float scale=1,transform=1,rotation,translation;
 public WebView(java.io.File asset){context=new android.content.Context(asset);}
 public int stopLoadingCalls;
 public void stopLoading(){stopLoadingCalls++;}
 public void setWebViewClient(WebViewClient c){client=c;}
 public android.content.Context getContext(){return context;}
 public String getUrl(){return url;}
 public android.view.Display getDisplay(){return display;}
 public boolean isAttachedToWindow(){return attached;}
 public boolean isShown(){return shown;}
 public android.view.accessibility.AccessibilityNodeInfo createAccessibilityNodeInfo(){return new android.view.accessibility.AccessibilityNodeInfo(window);}
 public void getLocationOnScreen(int[] out){out[0]=left;out[1]=top;}
 public int getWidth(){return width;} public int getHeight(){return height;}
 public float getScale(){return scale;}
 public boolean getGlobalVisibleRect(android.graphics.Rect r){r.left=left;r.top=top;r.right=left+width;r.bottom=top+height;return true;}
 public int getScrollX(){return scrollX;} public int getScrollY(){return scrollY;}
 public int getPaddingLeft(){return padding;} public int getPaddingTop(){return padding;}
 public int getPaddingRight(){return padding;} public int getPaddingBottom(){return padding;}
 public float getScaleX(){return transform;} public float getScaleY(){return transform;}
 public float getRotation(){return rotation;} public float getTranslationX(){return translation;} public float getTranslationY(){return translation;}
 public WebSettings getSettings(){return settings;}
 public void evaluateJavascript(String script,ValueCallback<String> callback){scripts.add(script);javascript.add(callback);}
 public void postVisualStateCallback(long id,VisualStateCallback callback){visuals.add(new Visual(id,callback));}
 public boolean postDelayed(Runnable runnable,long delay){if(!acceptPost)return false;posted.add(new Posted(android.os.SystemClock.now+delay,runnable));return true;}
 public void advance(long time){
   if(time<android.os.SystemClock.now)throw new IllegalStateException("test time reversed");
   android.os.SystemClock.now=time;
   for(;;){Posted next=null;for(Posted p:posted)if(p.at<=time&&(next==null||p.at<next.at))next=p;
     if(next==null)break;posted.remove(next);next.runnable.run();}
 }
}
