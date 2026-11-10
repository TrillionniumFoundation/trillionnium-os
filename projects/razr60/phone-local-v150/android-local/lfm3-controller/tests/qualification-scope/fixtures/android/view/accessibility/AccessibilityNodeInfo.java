package android.view.accessibility;
import android.graphics.Rect;import android.os.Bundle;import java.util.*;
public class AccessibilityNodeInfo {
 public static final int ACTION_CLICK=16,ACTION_LONG_CLICK=32,ACTION_SET_TEXT=2097152,ACTION_SCROLL_FORWARD=4096,ACTION_SCROLL_BACKWARD=8192;
 public static final String ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE="text";
 public String pkg,text="",description="",className="TextView",viewId="synthetic:id/entry";public int windowId,actions,refreshes;
 public boolean visible=true,enabled=true,password=false,editable=false,scrollable=false,clickable=true,refreshResult=true;public Runnable onRefresh,onAction;public AccessibilityWindowInfo window=new AccessibilityWindowInfo();public Rect bounds=new Rect(10,10,500,150);
 public AccessibilityNodeInfo(String p,int w){pkg=p;windowId=w;window.id=w;}
 public static AccessibilityNodeInfo obtain(AccessibilityNodeInfo n){return n;}
 public boolean refresh(){refreshes++;if(onRefresh!=null)onRefresh.run();return refreshResult;}public void recycle(){}
 public CharSequence getPackageName(){return pkg;}public int getWindowId(){return windowId;}public AccessibilityWindowInfo getWindow(){return window;}public void getBoundsInScreen(Rect r){r.left=bounds.left;r.top=bounds.top;r.right=bounds.right;r.bottom=bounds.bottom;}
 public CharSequence getText(){return text;}public CharSequence getContentDescription(){return description;}public CharSequence getClassName(){return className;}public String getViewIdResourceName(){return viewId;}
 public boolean isVisibleToUser(){return visible;}public boolean isEnabled(){return enabled;}public boolean isPassword(){return password;}public boolean isEditable(){return editable;}public boolean isScrollable(){return scrollable;}public boolean isClickable(){return clickable;}public boolean isFocused(){return true;}public boolean isLongClickable(){return false;}public boolean isCheckable(){return false;}public int getInputType(){return editable?1:0;}
 public int getChildCount(){return 0;}public AccessibilityNodeInfo getChild(int i){return null;}
 public List<AccessibilityAction> getActionList(){return Arrays.asList(new AccessibilityAction(ACTION_CLICK),new AccessibilityAction(ACTION_SET_TEXT),AccessibilityAction.ACTION_SCROLL_FORWARD,AccessibilityAction.ACTION_SCROLL_BACKWARD);}
 public boolean performAction(int a){return performAction(a,null);}public boolean performAction(int a,Bundle b){actions++;if(a==ACTION_SET_TEXT&&b!=null)text=b.getCharSequence(ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE).toString();if(onAction!=null)onAction.run();return true;}
 public static final class AccessibilityAction {private final int id;public AccessibilityAction(int id){this.id=id;}public int getId(){return id;}public static final AccessibilityAction ACTION_SCROLL_FORWARD=new AccessibilityAction(4096),ACTION_SCROLL_BACKWARD=new AccessibilityAction(8192),ACTION_SCROLL_UP=new AccessibilityAction(16908344),ACTION_SCROLL_DOWN=new AccessibilityAction(16908346),ACTION_SCROLL_LEFT=new AccessibilityAction(16908345),ACTION_SCROLL_RIGHT=new AccessibilityAction(16908347);}
}
