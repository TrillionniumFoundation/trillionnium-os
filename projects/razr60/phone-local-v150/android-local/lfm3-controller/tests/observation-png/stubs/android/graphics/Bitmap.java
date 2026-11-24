package android.graphics;
import java.io.*;
public final class Bitmap {
    public enum Config {ARGB_8888,RGB_565}
    public enum CompressFormat {PNG}
    public static final byte[] ORIGINAL={80,78,71,1};
    public int width,height,generation=1,pixelReads,compressCalls;public int[] pixels;
    public boolean mutable,gainmap,compressResult=true;
    public Config config=Config.ARGB_8888;public ColorSpace color=ColorSpace.SRGB;
    public Runnable afterPixels,afterCompress;
    public Bitmap(int w,int h,int[] p){width=w;height=h;pixels=p;}
    public ColorSpace getColorSpace(){return color;}public Config getConfig(){return config;}
    public int getWidth(){return width;}public int getHeight(){return height;}
    public boolean isMutable(){return mutable;}public boolean hasGainmap(){return gainmap;}
    public int getGenerationId(){return generation;}
    public void getPixels(int[] p,int offset,int stride,int x,int y,int w,int h){
        if(offset!=0||stride!=width||x!=0||y!=0||w!=width||h!=height)throw new AssertionError("complete exact original pixels required");
        pixelReads++;System.arraycopy(pixels,0,p,0,pixels.length);if(afterPixels!=null)afterPixels.run();
    }
    public boolean compress(CompressFormat f,int quality,OutputStream output)throws IOException{
        if(f!=CompressFormat.PNG||quality!=100)throw new AssertionError("original PNG call changed");
        compressCalls++;output.write(ORIGINAL);if(afterCompress!=null)afterCompress.run();return compressResult;
    }
}
