package android.view.accessibility;
import android.os.Parcel;import android.graphics.Rect;import android.graphics.Region;
/** Controlled serializer boundary, not Android's real Parcelable implementation. */
public final class AccessibilityWindowInfo {
 public static final int TYPE_APPLICATION=1;public static boolean mutateRoundTrip,throwCreator;public static int copied,recycled;
 public int display=15,type=1,layer=4,flags=3,id=96,parent=-1,task=500,wireId=-2,wireDisplay=-2,wireFlags=-2;
 public boolean trailing;public String title="untrusted title";public Rect bounds=new Rect(0,0,1224,2992),wireBounds;private boolean copy;
 public int getId(){return id;}public int getDisplayId(){return display;}public int getType(){return type;}public int getLayer(){return layer;}
 public boolean isActive(){return (flags&1)!=0;}public boolean isFocused(){return (flags&2)!=0;}public boolean isAccessibilityFocused(){return (flags&4)!=0;}public boolean isInPictureInPictureMode(){return (flags&8)!=0;}
 public void getBoundsInScreen(Rect r){r.left=bounds.left;r.top=bounds.top;r.right=bounds.right;r.bottom=bounds.bottom;}
 public void getRegionInScreen(Region r){r.set(bounds);}
 public void writeToParcel(Parcel p,int ignored){p.writeInt(wireDisplay==-2?display:wireDisplay);p.writeInt(type);p.writeInt(layer);p.writeInt(wireFlags==-2?flags:wireFlags);p.writeInt(wireId==-2?id:wireId);p.writeInt(parent);p.writeInt(task);Region region=new Region();region.set(wireBounds==null?bounds:wireBounds);region.writeToParcel(p,0);p.writeString(title);if(trailing)p.writeInt(17);}
 public static final class Creator {public AccessibilityWindowInfo createFromParcel(Parcel p){
  if(throwCreator)throw new IllegalStateException("controlled creator failure");
  AccessibilityWindowInfo w=new AccessibilityWindowInfo();w.display=p.readInt();w.type=p.readInt();w.layer=p.readInt();w.flags=p.readInt();w.id=p.readInt();w.parent=p.readInt();w.task=p.readInt();w.bounds=Region.CREATOR.createFromParcel(p).getBounds();w.title=p.readString();w.copy=true;copied++;if(mutateRoundTrip)w.wireId=w.id+1;return w;}}
 public static final Creator CREATOR=new Creator();
 public void recycle(){if(!copy)throw new AssertionError("reader must not recycle caller's window");recycled++;}
 public String toString(){throw new AssertionError("no toString parsing");}
}