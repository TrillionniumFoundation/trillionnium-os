package org.trillionnium.hepta.local;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.CRC32;
import java.util.zip.Deflater;

/**
 * A bounded lossless encoding of already-copied opaque sRGB pixels.
 * No Android read, deadline, file, observation or publication authority lives here.
 */
final class ObservationPngEncoder {
    static final int MAX_PIXELS=4*1024*1024, MAX_BYTES=8*1024*1024;
    private static final int BUFFER_BYTES=32768;
    private static final byte[] SIGNATURE={(byte)137,80,78,71,13,10,26,10};
    private static final byte[] IHDR={73,72,68,82}, SRGB={115,82,71,66},
            IDAT={73,68,65,84}, IEND={73,69,78,68};
    private ObservationPngEncoder() { }

    static boolean supportedSize(int width,int height) {
        return width>0&&height>0&&width<=8192&&height<=8192
                &&(long)width*height<=MAX_PIXELS;
    }

    /**
     * Null means the original encoder must handle a non-opaque or oversized result.
     * Deadline/cancellation and all other failures propagate; they never select fallback.
     * The returned PNG has exactly the supplied dimensions and opaque RGB samples.
     */
    static byte[] encode(int[] argb,int width,int height,Runnable check) throws IOException {
        if(check==null)throw new IllegalArgumentException("original work check required");
        check.run();
        if(!supportedSize(width,height)||argb==null||argb.length!=(long)width*height)
            throw new IllegalArgumentException("complete bounded pixel array required");
        for(int i=0;i<argb.length;i++) {
            if((i&4095)==0)check.run();
            if((argb[i]>>>24)!=255)return null;
        }
        check.run();
        LimitedBytes output=new LimitedBytes();
        Deflater deflater=new Deflater(Deflater.BEST_SPEED);
        try {
            output.write(SIGNATURE,0,SIGNATURE.length);
            byte[] header=new byte[13];number(header,0,width);number(header,4,height);
            header[8]=8;header[9]=2; // 8-bit truecolor, implicit alpha 255.
            chunk(output,IHDR,header,header.length);
            chunk(output,SRGB,new byte[]{0},1); // Original pixels are exactly sRGB.
            byte[] row=new byte[1+width*3],compressed=new byte[BUFFER_BYTES];
            row[0]=1; // PNG Sub: invertible byte differences, no pixel quantization.
            int pixel=0;
            for(int y=0;y<height;y++) {
                check.run();
                int previousRed=0,previousGreen=0,previousBlue=0,at=1;
                for(int x=0;x<width;x++) {
                    int color=argb[pixel++];
                    int red=(color>>>16)&255,green=(color>>>8)&255,blue=color&255;
                    row[at++]=(byte)(red-previousRed);
                    row[at++]=(byte)(green-previousGreen);
                    row[at++]=(byte)(blue-previousBlue);
                    previousRed=red;previousGreen=green;previousBlue=blue;
                }
                deflater.setInput(row);
                while(!deflater.needsInput()) {
                    check.run();
                    int count=deflater.deflate(compressed);
                    if(count>0)chunk(output,IDAT,compressed,count);
                    else if(!deflater.needsInput())throw new IOException("PNG compressor made no progress");
                }
            }
            check.run();deflater.finish();
            while(!deflater.finished()) {
                check.run();
                int count=deflater.deflate(compressed);
                if(count<=0&&!deflater.finished())throw new IOException("PNG compressor did not finish");
                if(count>0)chunk(output,IDAT,compressed,count);
            }
            check.run();chunk(output,IEND,new byte[0],0);
            byte[] png=output.toByteArray();check.run();return png;
        } catch(TooLarge originalEncoderRequired) {
            check.run();return null;
        } finally {
            deflater.end();
        }
    }

    private static void number(byte[] target,int offset,int value) {
        target[offset]=(byte)(value>>>24);target[offset+1]=(byte)(value>>>16);
        target[offset+2]=(byte)(value>>>8);target[offset+3]=(byte)value;
    }
    private static void integer(LimitedBytes output,int value) throws TooLarge {
        byte[] bytes=new byte[4];number(bytes,0,value);output.write(bytes,0,4);
    }
    private static void chunk(LimitedBytes output,byte[] type,byte[] data,int length) throws TooLarge {
        integer(output,length);output.write(type,0,4);output.write(data,0,length);
        CRC32 crc=new CRC32();crc.update(type,0,4);crc.update(data,0,length);
        integer(output,(int)crc.getValue());
    }
    private static final class TooLarge extends IOException {
        private static final long serialVersionUID=1L;
        TooLarge(){super("bounded PNG requires the original encoder");}
    }
    private static final class LimitedBytes {
        private final ByteArrayOutputStream bytes=new ByteArrayOutputStream(65536);
        void write(byte[] value,int offset,int count) throws TooLarge {
            if(count<0||count>MAX_BYTES-bytes.size())throw new TooLarge();
            bytes.write(value,offset,count);
        }
        byte[] toByteArray(){return bytes.toByteArray();}
    }
}
