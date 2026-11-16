package android.graphics;import android.os.Parcel;
public final class Region {private Rect r=new Rect();public void set(Rect x){r=new Rect(x.left,x.top,x.right,x.bottom);}public Rect getBounds(){return new Rect(r.left,r.top,r.right,r.bottom);}
 public void writeToParcel(Parcel p,int flags){p.writeInt(r.left);p.writeInt(r.top);p.writeInt(r.right);p.writeInt(r.bottom);}
 public static final class Creator {public Region createFromParcel(Parcel p){Region r=new Region();r.set(new Rect(p.readInt(),p.readInt(),p.readInt(),p.readInt()));return r;}}
 public static final Creator CREATOR=new Creator();public boolean equals(Object o){return o instanceof Region&&r.equals(((Region)o).r);}public int hashCode(){return r.hashCode();}}