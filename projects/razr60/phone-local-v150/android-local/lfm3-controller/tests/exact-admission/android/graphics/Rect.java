package android.graphics;
/** Host IO fixture; production phone geometry is Android Rect. */
public final class Rect {
    public final int left,top,right,bottom;
    public Rect(int left,int top,int right,int bottom){this.left=left;this.top=top;this.right=right;this.bottom=bottom;}
    public Rect(Rect other){this(other.left,other.top,other.right,other.bottom);}
}
