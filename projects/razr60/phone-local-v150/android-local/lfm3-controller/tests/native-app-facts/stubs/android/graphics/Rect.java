package android.graphics;
/** Host data-only double. No Android platform execution is claimed. */
public final class Rect {
    public int left,top,right,bottom;
    public Rect(int l,int t,int r,int b){left=l;top=t;right=r;bottom=b;}
    public Rect(Rect value){this(value.left,value.top,value.right,value.bottom);}
}
