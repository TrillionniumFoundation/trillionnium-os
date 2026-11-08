package org.trillionnium.hepta.local;

import android.content.Context;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import org.json.JSONObject;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/** A launcher intent is not action authorization. Only a private one-use debug request can autorun. */
final class PrivateDebugTask {
    final String instruction,nonceSha256;
    private PrivateDebugTask(String instruction,String nonce){this.instruction=instruction;this.nonceSha256=HeptaAccessibilityService.sha(nonce.getBytes(StandardCharsets.UTF_8));}
    static PrivateDebugTask consume(Context context,String nonce)throws Exception{
        if(nonce==null||!nonce.matches("[0-9a-f]{64}"))throw new IOException("测试请求缺少有效的一次性标识");
        File files=context.getFilesDir().getCanonicalFile();
        File request=new File(files,"debug-task.json");
        if(!request.getCanonicalFile().equals(request))throw new IOException("测试请求路径无效");
        StructStat stat=Os.lstat(request.getPath());
        if((stat.st_mode&OsConstants.S_IFMT)!=OsConstants.S_IFREG||stat.st_uid!=android.os.Process.myUid()
                ||(stat.st_mode&0777)!=0600||stat.st_nlink!=1||stat.st_size<1||stat.st_size>8192)
            throw new IOException("测试请求必须是本应用私有的 0600 普通文件");
        byte[] data;
        try(InputStream in=new FileInputStream(request);ByteArrayOutputStream bytes=new ByteArrayOutputStream()){
            byte[] buf=new byte[1024];int n;
            while((n=in.read(buf))!=-1){if(bytes.size()+n>8192)throw new IOException("测试请求过长");bytes.write(buf,0,n);}
            data=bytes.toByteArray();
        }
        JSONObject object=new JSONObject(new String(data,StandardCharsets.UTF_8));
        Set<String> expected=new HashSet<>(Arrays.asList("schema","nonce","instruction","created_wall_ms","expires_wall_ms"));
        Iterator<String> keys=object.keys();while(keys.hasNext())if(!expected.remove(keys.next()))throw new IOException("测试请求包含未知字段");
        if(!expected.isEmpty()||!"hepta.private-debug-task.v1".equals(object.getString("schema")))throw new IOException("测试请求格式不匹配");
        if(!MessageDigest.isEqual(nonce.getBytes(StandardCharsets.UTF_8),object.getString("nonce").getBytes(StandardCharsets.UTF_8)))throw new IOException("一次性标识不匹配");
        long now=System.currentTimeMillis(),created=object.getLong("created_wall_ms"),expires=object.getLong("expires_wall_ms");
        if(created<0||created>now+30000||expires<=created||expires-created>600000||now>expires)throw new IOException("测试请求已过期或时间范围无效");
        String instruction=object.getString("instruction");
        if(instruction.trim().isEmpty()||instruction.indexOf('\0')>=0||instruction.getBytes(StandardCharsets.UTF_8).length>1600)
            throw new IOException("测试指令为空或超出本地任务范围");
        File consumedDir=new File(files,"debug-consumed");
        if(!consumedDir.isDirectory()&&!consumedDir.mkdir())throw new IOException("无法创建已消费请求目录");
        Os.chmod(consumedDir.getPath(),0700);
        File consumed=new File(consumedDir,nonce+".json");
        PrivateDebugTask value=new PrivateDebugTask(instruction,nonce);
        if(consumed.exists()||!request.renameTo(consumed))throw new IOException("测试请求已消费或无法原子消费");
        return value;
    }
}
