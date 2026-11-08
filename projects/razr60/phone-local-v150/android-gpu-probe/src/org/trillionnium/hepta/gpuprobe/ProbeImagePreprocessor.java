package org.trillionnium.hepta.gpuprobe;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/** Explicit diagnostic downsampling; original bytes remain in the run directory. */
final class ProbeImagePreprocessor {
    static final long MAX_SOURCE_PIXELS=16L*1024*1024;
    static final long MAX_OUTPUT_PIXELS=262144L;
    static final class Result {
        final byte[] png;final JSONObject transform;
        Result(byte[] png,JSONObject transform){this.png=png;this.transform=transform;}
    }
    static Result prepare(byte[] original)throws Exception{
        BitmapFactory.Options bounds=new BitmapFactory.Options();bounds.inJustDecodeBounds=true;
        BitmapFactory.decodeByteArray(original,0,original.length,bounds);
        int w=bounds.outWidth,h=bounds.outHeight;
        if(w<1||h<1||(long)w*h>MAX_SOURCE_PIXELS)throw new IOException("diagnostic image dimensions are invalid or exceed 16 megapixels");
        double scale=Math.min(1.0,Math.sqrt((double)MAX_OUTPUT_PIXELS/((double)w*h)));
        int outputW=Math.max(1,(int)Math.floor(w*scale)),outputH=Math.max(1,(int)Math.floor(h*scale));
        if((long)outputW*outputH>MAX_OUTPUT_PIXELS)throw new IOException("diagnostic image pixel budget exceeded");
        BitmapFactory.Options options=new BitmapFactory.Options();options.inPreferredConfig=Bitmap.Config.ARGB_8888;
        options.inSampleSize=1;
        while(w/(options.inSampleSize*2)>=outputW&&h/(options.inSampleSize*2)>=outputH)options.inSampleSize*=2;
        Bitmap decoded=null,scaled=null;
        try{
            decoded=BitmapFactory.decodeByteArray(original,0,original.length,options);
            if(decoded==null)throw new IOException("diagnostic image decoding failed");
            scaled=Bitmap.createScaledBitmap(decoded,outputW,outputH,true);
            ByteArrayOutputStream encoded=new ByteArrayOutputStream();
            if(!scaled.compress(Bitmap.CompressFormat.PNG,100,encoded))throw new IOException("diagnostic PNG encoding failed");
            JSONObject transform=new JSONObject().put("kind","explicit_aspect_preserving_downsample")
                .put("source_width",w).put("source_height",h).put("output_width",outputW).put("output_height",outputH)
                .put("scale_x",(double)outputW/w).put("scale_y",(double)outputH/h)
                .put("cropped",false).put("padded",false).put("max_output_pixels",MAX_OUTPUT_PIXELS)
                .put("token_count_derived_from_pixels",false).put("original_bytes_retained",true);
            return new Result(encoded.toByteArray(),transform);
        }finally{if(scaled!=null&&scaled!=decoded)scaled.recycle();if(decoded!=null)decoded.recycle();}
    }
}
