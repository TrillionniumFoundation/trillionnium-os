package android.view.accessibility;
import android.graphics.Rect;
public final class AccessibilityWindowInfo {
 public static final int TYPE_APPLICATION=1,TYPE_INPUT_METHOD=2;
 public int id=7,type=1,display=0,layer=1,recycles;public boolean active=true,focused=true;
 public AccessibilityNodeInfo root;public String title="Synthetic window";public Rect bounds=new Rect(0,0,1080,2400);
 public int getId(){return id;}public int getType(){return type;}public int getDisplayId(){return display;}public boolean isActive(){return active;}
 public boolean isFocused(){return focused;}public int getLayer(){return layer;}public AccessibilityNodeInfo getRoot(){return root;}
 public CharSequence getTitle(){return title;}public void getBoundsInScreen(Rect r){r.left=bounds.left;r.top=bounds.top;r.right=bounds.right;r.bottom=bounds.bottom;}
 public void recycle(){recycles++;}
}
