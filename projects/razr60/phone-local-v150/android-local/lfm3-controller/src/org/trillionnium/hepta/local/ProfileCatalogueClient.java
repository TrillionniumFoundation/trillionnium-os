package org.trillionnium.hepta.local;

import android.content.Context;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.trillionnium.hepta.background.ProfileTarget;

/** Explicit owner-triggered, read-only privileged catalogue. It never creates or starts a profile. */
final class ProfileCatalogueClient {
    private static final int MAX_BYTES=65536;
    private ProfileCatalogueClient(){}
    static List<ProfileTarget> load(Context context)throws Exception{
        if(android.os.Looper.myLooper()==android.os.Looper.getMainLooper())
            throw new IllegalStateException("隔离资料核验须在后台读取");
        LocalProbeApplication.requirePermissionPreparationIdle(context);
        int uid=android.os.Process.myUid();
        if(uid<10000||uid>=90000)throw new IllegalStateException("控制器须位于个人空间");
        File apk=new File(context.getApplicationInfo().sourceDir).getCanonicalFile();
        if(!apk.isFile()||!apk.isAbsolute())throw new IllegalStateException("控制器安装文件不可用");
        String request=UUID.randomUUID().toString();
        String command="CLASSPATH="+quote(apk.getPath())+" /system/bin/app_process / org.trillionnium.hepta.background.ProfileCatalogueMain"
                +" --owner-uid "+uid+" --request-id "+request;
        final Process process=new ProcessBuilder("su","-c",command).redirectErrorStream(true).start();
        final ByteArrayOutputStream output=new ByteArrayOutputStream();final AtomicReference<Throwable> error=new AtomicReference<Throwable>();
        Thread reader=new Thread(() -> {
            try(InputStream input=process.getInputStream()){
                byte[] block=new byte[4096];int count;
                while((count=input.read(block))!=-1){
                    if(output.size()+count>MAX_BYTES)throw new java.io.IOException("profile catalogue output bound");
                    output.write(block,0,count);
                }
            }catch(Throwable failure){error.set(failure);}
        },"hepta-profile-catalogue-read");reader.setDaemon(true);reader.start();
        boolean exit=false;
        try{
            exit=process.waitFor(8000,TimeUnit.MILLISECONDS);
            if(!exit)throw new java.io.IOException("隔离资料只读核验超时");
            reader.join(500);
            if(reader.isAlive()||error.get()!=null||process.exitValue()!=0)
                throw new java.io.IOException("隔离资料核验未得到完整回执");
            String raw=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(output.toByteArray())).toString();
            JSONTokener parser=new JSONTokener(raw);Object value=parser.nextValue();
            if(!(value instanceof JSONObject)||parser.nextClean()!=0)throw new java.io.IOException("隔离资料回执格式无效");
            JSONObject result=(JSONObject)value;
            if(!"hepta.profile-catalogue.v1".equals(result.getString("schema"))
                    ||result.getInt("owner_uid")!=uid||!request.equals(result.getString("request_id")))
                throw new java.io.IOException("隔离资料回执身份不匹配");
            JSONArray rows=result.getJSONArray("targets");
            if(rows.length()>4)throw new java.io.IOException("隔离资料目录超出上限");
            List<ProfileTarget> targets=new ArrayList<ProfileTarget>();Set<Integer> users=new HashSet<Integer>();Set<Long> serials=new HashSet<Long>();
            for(int i=0;i<rows.length();i++){
                Object row=rows.get(i);if(!(row instanceof String))throw new java.io.IOException("隔离资料目标格式无效");
                ProfileTarget target=ProfileTarget.fromWire((String)row);
                if(!users.add(target.profile.userId)||!serials.add(target.profile.serial))throw new java.io.IOException("隔离资料目标重复");
                targets.add(target);
            }
            return Collections.unmodifiableList(targets);
        }finally{if(!exit)process.destroy();}
    }
    static void requireCurrent(Context context,ProfileTarget expected)throws Exception{
        if(expected==null)throw new IllegalArgumentException("profile target required");
        for(ProfileTarget actual:load(context))if(actual.same(expected))return;
        throw new IllegalStateException("隔离资料或携程安装身份发生变化，请重新选择");
    }
    private static String quote(String value){return "'"+value.replace("'","'\\''")+"'";}
}
