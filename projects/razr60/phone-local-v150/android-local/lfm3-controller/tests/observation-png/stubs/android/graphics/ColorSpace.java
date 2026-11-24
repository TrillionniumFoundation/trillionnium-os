package android.graphics;
public final class ColorSpace {
    public enum Named {SRGB}
    public static final ColorSpace SRGB=new ColorSpace(),WIDE=new ColorSpace();
    private ColorSpace(){}
    public static ColorSpace get(Named ignored){return SRGB;}
}
