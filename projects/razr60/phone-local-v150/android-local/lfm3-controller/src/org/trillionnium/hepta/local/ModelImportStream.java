package org.trillionnium.hepta.local;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Copies one owner-selected local file without allocating memory proportional to its size. */
final class ModelImportStream {
    static final int BUFFER_BYTES=64*1024;
    interface Cancellation {boolean cancelled();}
    interface Progress {void copied(long bytes,long expected);}
    static final class Cancelled extends IOException {
        private static final long serialVersionUID=1L;
        Cancelled(){super("导入已取消");}
    }
    private ModelImportStream(){}
    static void check(Cancellation cancellation)throws Cancelled{
        if(cancellation==null||cancellation.cancelled()||Thread.currentThread().isInterrupted())throw new Cancelled();
    }
    static void copy(InputStream input,OutputStream output,long expected,String digest,
                     Cancellation cancellation,Progress progress)throws IOException{
        if(input==null||output==null||expected<=0||digest==null||!digest.matches("[0-9a-f]{64}"))
            throw new IOException("模型文件校验参数无效");
        final MessageDigest hash;
        try{hash=MessageDigest.getInstance("SHA-256");}
        catch(NoSuchAlgorithmException unavailable){throw new IOException("文件校验不可用",unavailable);}
        byte[] buffer=new byte[BUFFER_BYTES];long copied=0;
        check(cancellation);
        while(copied<expected){
            int wanted=(int)Math.min((long)buffer.length,expected-copied);
            int count=input.read(buffer,0,wanted);
            check(cancellation);
            if(count<0)throw new IOException("文件不完整，请选择下载完成的模型文件");
            if(count==0||count>wanted)throw new IOException("文件读取未取得有效数据");
            output.write(buffer,0,count);hash.update(buffer,0,count);copied+=count;
            check(cancellation);
            if(progress!=null)progress.copied(copied,expected);
        }
        check(cancellation);
        int extra=input.read();
        check(cancellation);
        if(extra!=-1)throw new IOException("文件大小与所选模型不符");
        byte[] actual=hash.digest();StringBuilder hex=new StringBuilder(64);
        for(byte value:actual){int n=value&255;hex.append(Character.forDigit(n>>>4,16));hex.append(Character.forDigit(n&15,16));}
        if(!digest.equals(hex.toString()))throw new IOException("文件内容与所选模型不符，请重新选择正确文件");
        check(cancellation);
    }
}

