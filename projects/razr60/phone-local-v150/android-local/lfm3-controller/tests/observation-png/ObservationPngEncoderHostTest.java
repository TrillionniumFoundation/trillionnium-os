package org.trillionnium.hepta.local;

import android.graphics.Bitmap;
import android.graphics.ColorSpace;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import javax.imageio.ImageIO;

/** Pure host pixels and explicitly synthetic Android metadata/clock endpoints. */
public final class ObservationPngEncoderHostTest {
    static int cases,assertions;
    static final List<String> passed=new ArrayList<String>();
    interface Work {void run() throws Exception;}
    static void need(boolean b,String m){assertions++;if(!b)throw new AssertionError(m);}
    static void one(String name,Work w)throws Exception{w.run();cases++;passed.add(name);}
    static final Runnable LIVE=()->{};
    static final class Stop extends RuntimeException {private static final long serialVersionUID=1L;}
    static int[] random(int width,int height,long seed){
        int[] p=new int[width*height];Random r=new Random(seed);
        for(int i=0;i<p.length;i++)p[i]=0xff000000|r.nextInt(0x1000000);return p;
    }
    static int[] ui(int width,int height){
        int[] p=new int[width*height];Random r=new Random(6001);
        for(int y=0;y<height;y++)for(int x=0;x<width;x++){
            int c=(x>30&&x<width-30&&(y%170)<40)?0xff303030:0xfff8f8f8;
            if(y<150)c=0xff1675d9;
            if(y>height/2&&y<height/2+240)c=0xff000000|r.nextInt(0x1000000);
            if((x%220)<130&&(y%170)>55&&(y%170)<150)c=0xffd9e8f8;
            p[y*width+x]=c;
        }return p;
    }
    static byte[] encode(int[] p,int w,int h)throws Exception{return ObservationPngEncoder.encode(p,w,h,LIVE);}
    static void roundTrip(int[] p,int width,int height)throws Exception {
        int[] unchanged=p.clone();byte[] encoded=encode(p,width,height);
        need(encoded!=null,"expected bounded opaque PNG");
        need(Arrays.equals(p,unchanged),"encoder changed original pixels");
        BufferedImage decoded=ImageIO.read(new ByteArrayInputStream(encoded));
        need(decoded!=null&&decoded.getWidth()==width&&decoded.getHeight()==height,"independent decoder dimensions");
        int[] actual=decoded.getRGB(0,0,width,height,null,0,width);
        need(Arrays.equals(p,actual),"independent ImageIO exact ARGB mismatch");
        DataInputStream input=new DataInputStream(new ByteArrayInputStream(encoded));
        need(input.readLong()==0x89504e470d0a1a0aL,"PNG signature");
        ByteArrayOutputStream zipped=new ByteArrayOutputStream();boolean header=false,srgb=false,end=false;int chunks=0;
        while(!end){
            int length=input.readInt();need(length>=0&&length<=32768,"bounded PNG chunk");
            byte[] type=new byte[4],data=new byte[length];input.readFully(type);input.readFully(data);
            long crc=Integer.toUnsignedLong(input.readInt());CRC32 check=new CRC32();check.update(type);check.update(data);
            need(crc==check.getValue(),"chunk CRC");
            String name=new String(type,"US-ASCII");chunks++;
            if("IHDR".equals(name)){
                need(!header&&chunks==1&&length==13,"unique first IHDR");header=true;
                DataInputStream ih=new DataInputStream(new ByteArrayInputStream(data));
                need(ih.readInt()==width&&ih.readInt()==height,"original dimensions");
                need(ih.readUnsignedByte()==8&&ih.readUnsignedByte()==2,"8-bit opaque RGB");
                need(ih.readUnsignedByte()==0&&ih.readUnsignedByte()==0&&ih.readUnsignedByte()==0,"standard compression filter noninterlace");
            }else if("sRGB".equals(name)){need(header&&!srgb&&zipped.size()==0&&length==1&&data[0]==0,"original sRGB declaration");srgb=true;}
            else if("IDAT".equals(name)){need(header&&srgb&&length>0,"ordered IDAT");zipped.write(data);}
            else if("IEND".equals(name)){need(length==0&&zipped.size()>0,"complete IEND");end=true;}
            else throw new AssertionError("unexpected PNG chunk "+name);
        }
        need(input.read()==-1,"no trailing bytes");
        InflaterInputStream inflater=new InflaterInputStream(new ByteArrayInputStream(zipped.toByteArray()));
        int position=0;
        for(int y=0;y<height;y++){
            need(inflater.read()==1,"Sub filter");
            int red=0,green=0,blue=0;
            for(int x=0;x<width;x++){
                int dr=inflater.read(),dg=inflater.read(),db=inflater.read();
                if(dr<0||dg<0||db<0)throw new AssertionError("short decompressed row");
                red=(red+dr)&255;green=(green+dg)&255;blue=(blue+db)&255;
                if(p[position++]!=(0xff000000|(red<<16)|(green<<8)|blue))throw new AssertionError("independent filter inversion mismatch");
            }
        }
        need(inflater.read()==-1,"exact decompressed pixel count");inflater.close();
    }
    static void rejects(Work work,Class<? extends Throwable> kind)throws Exception{
        try{work.run();throw new AssertionError("expected "+kind.getName());}
        catch(Throwable t){if(t instanceof AssertionError)throw (AssertionError)t;need(kind.isInstance(t),"wrong failure: "+t);}
    }
    static final class Fixture implements AutoCloseable {
        final Path file;final HeptaAccessibilityService service=new HeptaAccessibilityService();
        final HeptaAccessibilityService.ObservationRequest request=new HeptaAccessibilityService.ObservationRequest();
        Fixture(Path root,String name)throws Exception{file=root.resolve(name+".png");Files.createFile(file);}
        byte[] run(Bitmap b)throws Exception{try(FileOutputStream out=new FileOutputStream(file.toFile())){service.encode(request,b,out);}return Files.readAllBytes(file);}
        @Override public void close()throws IOException{Files.deleteIfExists(file);}
    }
    static Bitmap bitmap(){return new Bitmap(19,23,ui(19,23));}
    public static void main(String[] args)throws Exception{
        Path root=Paths.get(args[0]);Files.createDirectories(root);
        one("known_colors_opaque_srgb_exact",()->roundTrip(new int[]{0xff000000,0xffffffff,0xffff0000,0xff00ff00,0xff0000ff,0xff0180fe},3,2));
        one("single_pixel",()->roundTrip(new int[]{0xffa1b2c3},1,1));
        one("independent_random_RGB",()->roundTrip(random(257,259,7),257,259));
        one("exact_razr_dimensions_synthetic_ui",()->roundTrip(ui(1224,2992),1224,2992));
        one("maximum_bounded_pixels",()->roundTrip(ui(2048,2048),2048,2048));
        one("invalid_dimensions_and_array",()->{
            rejects(()->encode(new int[1],0,1),IllegalArgumentException.class);
            rejects(()->encode(new int[1],-1,1),IllegalArgumentException.class);
            rejects(()->encode(new int[1],Integer.MAX_VALUE,Integer.MAX_VALUE),IllegalArgumentException.class);
            rejects(()->encode(new int[1],8193,1),IllegalArgumentException.class);
            rejects(()->encode(new int[2],1,1),IllegalArgumentException.class);
            rejects(()->encode(null,1,1),IllegalArgumentException.class);
            rejects(()->ObservationPngEncoder.encode(new int[]{-1},1,1,null),IllegalArgumentException.class);
        });
        one("all_alpha_values_require_original_encoder",()->{
            for(int alpha=0;alpha<255;alpha++)need(encode(new int[]{(alpha<<24)|0x123456},1,1)==null,"nonopaque fallback");
        });
        one("last_nonopaque_pixel_not_lost",()->{
            int[] p=ui(257,259);p[p.length-1]=0x00ffffff;need(encode(p,257,259)==null,"late alpha fallback");
        });
        one("incompressible_output_bound_uses_original_encoder",()->need(encode(random(2048,2048,1234),2048,2048)==null,"8MiB output bound"));
        one("cancel_during_alpha_scan_propagates",()->{
            int[] calls={0};rejects(()->ObservationPngEncoder.encode(ui(100,100),100,100,()->{if(++calls[0]==3)throw new Stop();}),Stop.class);
            need(calls[0]==3,"no work after cancellation");
        });
        one("deadline_during_deflate_propagates",()->{
            int[] calls={0};int[] p=ui(100,200);
            rejects(()->ObservationPngEncoder.encode(p,100,200,()->{if(++calls[0]==50)throw new Stop();}),Stop.class);
            need(calls[0]==50,"no continuation after deadline");
        });
        one("actual_service_helper_uses_fast_path",()->{
            try(Fixture f=new Fixture(root,"fast")){Bitmap b=bitmap();byte[] png=f.run(b);
                need(b.compressCalls==0&&b.pixelReads==1,"one copied immutable pixel read");
                need(ImageIO.read(new ByteArrayInputStream(png)).getWidth()==19,"actual helper PNG");
                need(f.request.deadline==1000000&&f.request.now==0,"original deadline unchanged");
            }
        });
        for(final String name:Arrays.asList("wide_color","unknown_color","mutable","gainmap","unsupported_config","large_shape","nonopaque")){
            one("actual_service_original_fallback_"+name,()->{
                try(Fixture f=new Fixture(root,"fallback_"+name)){Bitmap b=bitmap();
                    if(name.equals("wide_color"))b.color=ColorSpace.WIDE;
                    if(name.equals("unknown_color"))b.color=null;
                    if(name.equals("mutable"))b.mutable=true;
                    if(name.equals("gainmap"))b.gainmap=true;
                    if(name.equals("unsupported_config"))b.config=Bitmap.Config.RGB_565;
                    if(name.equals("large_shape")){b.width=8193;b.height=1;}
                    if(name.equals("nonopaque"))b.pixels[b.pixels.length-1]=0x80123456;
                    byte[] bytes=f.run(b);
                    need(b.compressCalls==1&&Arrays.equals(bytes,Bitmap.ORIGINAL),"exact original PNG encoder used");
                    if(!name.equals("nonopaque"))need(b.pixelReads==0,"no unsupported pixel conversion");
                }
            });
        }
        one("original_encoder_false_remains_failure",()->{
            try(Fixture f=new Fixture(root,"false")){Bitmap b=bitmap();b.mutable=true;b.compressResult=false;
                rejects(()->f.run(b),IllegalStateException.class);need(b.compressCalls==1,"one original call");
            }
        });
        one("cancel_before_copy_never_writes_or_falls_back",()->{
            try(Fixture f=new Fixture(root,"cancel")){Bitmap b=bitmap();f.request.cancel=true;
                rejects(()->f.run(b),HeptaAccessibilityService.Stopped.class);
                need(b.pixelReads==0&&b.compressCalls==0&&Files.size(f.file)==0,"no pixel/output/fallback work");
            }
        });
        one("deadline_after_pixel_copy_never_falls_back",()->{
            try(Fixture f=new Fixture(root,"copy_deadline")){Bitmap b=bitmap();b.afterPixels=()->f.request.now=f.request.deadline;
                rejects(()->f.run(b),HeptaAccessibilityService.Stopped.class);
                need(b.pixelReads==1&&b.compressCalls==0&&Files.size(f.file)==0,"copied pixels cannot bypass original deadline");
            }
        });
        one("changed_pixel_generation_refuses_publication",()->{
            try(Fixture f=new Fixture(root,"mutation")){Bitmap b=bitmap();b.afterPixels=()->b.generation++;
                rejects(()->f.run(b),IllegalStateException.class);need(b.compressCalls==0&&Files.size(f.file)==0,"changed pixels not encoded");
            }
        });
        one("output_IO_failure_propagates_without_fallback",()->{
            try(Fixture f=new Fixture(root,"io")){Bitmap b=bitmap();
                try(FileOutputStream out=new FileOutputStream(f.file.toFile()){
                    @Override public void write(byte[] bytes)throws IOException{throw new IOException("injected output failure");}
                }){rejects(()->f.service.encode(f.request,b,out),IOException.class);}
                need(b.compressCalls==0&&Files.size(f.file)==0,"IO failure never invokes original encoder");
            }
        });
        one("deadline_crossing_output_write_fails_original_guard",()->{
            try(Fixture f=new Fixture(root,"write_deadline")){Bitmap b=bitmap();
                try(FileOutputStream out=new FileOutputStream(f.file.toFile()){
                    @Override public void write(byte[] bytes)throws IOException{super.write(bytes);f.request.now=f.request.deadline;}
                }){rejects(()->f.service.encode(f.request,b,out),HeptaAccessibilityService.Stopped.class);}
                need(Files.size(f.file)>0&&b.compressCalls==0,"partial stage retains failure for original product cleanup");
            }
        });
        one("original_fallback_still_checks_deadline_after_write",()->{
            try(Fixture f=new Fixture(root,"fallback_deadline")){Bitmap b=bitmap();b.mutable=true;b.afterCompress=()->f.request.now=f.request.deadline;
                rejects(()->f.run(b),HeptaAccessibilityService.Stopped.class);
                need(b.compressCalls==1,"fallback not repeated after deadline");
            }
        });
        int[] bench=ui(1224,2992);encode(bench,1224,2992);
        long start=System.nanoTime();byte[] fast=encode(bench,1224,2992);long fastNs=System.nanoTime()-start;
        BufferedImage image=new BufferedImage(1224,2992,BufferedImage.TYPE_INT_RGB);image.setRGB(0,0,1224,2992,bench,0,1224);
        ByteArrayOutputStream standard=new ByteArrayOutputStream();start=System.nanoTime();ImageIO.write(image,"png",standard);long standardNs=System.nanoTime()-start;
        System.out.println("{\"all_pass\":true,\"cases\":"+cases+",\"assertions\":"+assertions+",\"phone_operations\":0,\"android_execution\":false,"
                +"\"benchmark_kind\":\"synthetic_pixels_host_JDK_only_not_Android_Bitmap\","
                +"\"width\":1224,\"height\":2992,\"fast_ms\":"+(fastNs/1000000.0)+",\"jdk_imageio_ms\":"+(standardNs/1000000.0)+","
                +"\"fast_bytes\":"+fast.length+",\"jdk_imageio_bytes\":"+standard.size()+"}");
        for(String name:passed)System.out.println("PASS "+name);
    }
}
