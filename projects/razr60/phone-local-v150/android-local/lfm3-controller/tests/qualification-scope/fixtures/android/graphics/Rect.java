package android.graphics;
public final class Rect {
 public int left,top,right,bottom;
 public Rect(){}public Rect(int a,int b,int c,int d){left=a;top=b;right=c;bottom=d;}public Rect(Rect r){this(r.left,r.top,r.right,r.bottom);}
 public boolean isEmpty(){return right<=left||bottom<=top;}public boolean contains(int x,int y){return x>=left&&x<right&&y>=top&&y<bottom;}
 public static boolean intersects(Rect a,Rect b){return a.left<b.right&&b.left<a.right&&a.top<b.bottom&&b.top<a.bottom;}
 @Override public boolean equals(Object o){if(!(o instanceof Rect))return false;Rect r=(Rect)o;return left==r.left&&top==r.top&&right==r.right&&bottom==r.bottom;}
 @Override public int hashCode(){return left+top+right+bottom;}@Override public String toString(){return left+","+top+","+right+","+bottom;}
}
