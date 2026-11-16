package org.trillionnium.hepta.local;

import android.content.Context;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;

/** A one-use private model-only request. A launcher intent alone supplies no fixture or authority. */
final class PrivateMobiProbe {
    static final String PROMPT_SOURCE_SHA="57b6fc209afc1387a0bce841cba8399736537dd5e8a2729875ec031ca93f0e7c";
    static final String PREFIX_SHA="ba6f7c4d4b6aca98b3fd6737a1ae6fed1bc8b554963777a3217e5c25d7db438e";
    static final String VARIABLE_SHA="895e4ef16d0940e96b2c1cc24ec97a3372cb2bfadf3519bd197461298c96a1a5";
    final String id,nonceSha,owner,ownerSha,promptSha,imageSha,fixtureSha,historySha;
    final byte[] prompt,image,fixture;
    final int width,height,maxTokens;final long deadlineMs;
    private PrivateMobiProbe(String id,String nonce,String owner,String history,byte[] prompt,byte[] image,byte[] fixture,
                             int width,int height,int maximum,long deadline){
        this.id=id;nonceSha=MobiMindContract.sha(nonce.getBytes(StandardCharsets.UTF_8));this.owner=owner;
        ownerSha=MobiMindContract.sha(owner.getBytes(StandardCharsets.UTF_8));historySha=MobiMindContract.sha(history.getBytes(StandardCharsets.UTF_8));
        this.prompt=prompt;this.image=image;this.fixture=fixture;promptSha=MobiMindContract.sha(prompt);
        imageSha=MobiMindContract.sha(image);fixtureSha=MobiMindContract.sha(fixture);
        this.width=width;this.height=height;maxTokens=maximum;deadlineMs=deadline;
    }
    static PrivateMobiProbe consume(Context context,String nonce)throws Exception{
        if(nonce==null||!nonce.matches("[0-9a-f]{64}"))throw new IOException("one-use diagnostic nonce required");
        File files=context.getFilesDir().getCanonicalFile();MobiMindPrivateFiles.directory(files,false);
        MobiMindPrivateFiles.Read request=MobiMindPrivateFiles.read(new File(files,"mobi-probe-request.json"),8192,true);
        Map<String,Object> value=MobiMindContract.jsonObject(request.bytes);
        if(!value.keySet().equals(new HashSet<String>(Arrays.asList("schema","nonce","request_id","fixture_sha256",
                "created_wall_ms","expires_wall_ms","deadline_ms","max_tokens"))))throw new IOException("unknown or missing diagnostic request field");
        require(value,"schema","hepta.private-mobimind-probe.v1");
        String requestedNonce=text(value,"nonce");
        if(!MessageDigest.isEqual(nonce.getBytes(StandardCharsets.UTF_8),requestedNonce.getBytes(StandardCharsets.UTF_8)))throw new IOException("nonce does not match private request");
        String id=text(value,"request_id"),fixtureSha=text(value,"fixture_sha256");
        if(!id.matches("[0-9a-f]{32}")||!fixtureSha.matches("[0-9a-f]{64}"))throw new IOException("invalid request or fixture identity");
        long now=System.currentTimeMillis(),created=integer(value,"created_wall_ms"),expires=integer(value,"expires_wall_ms");
        if(created<0||created>now+30000||expires<=created||expires-created>600000||now>expires)throw new IOException("diagnostic request expired or time range invalid");
        long deadline=integer(value,"deadline_ms"),tokens=integer(value,"max_tokens");
        if(deadline<1000||deadline>600000||tokens<1||tokens>512)throw new IOException("diagnostic budget outside fixed native contract");
        File inputs=new File(new File(files,"mobi-probe-inputs"),id).getCanonicalFile();
        if(!inputs.equals(new File(files,"mobi-probe-inputs/"+id)))throw new IOException("fixture must be in its exact private request directory");
        MobiMindPrivateFiles.directory(inputs,false);
        byte[] fixture=MobiMindPrivateFiles.read(new File(inputs,"fixture.json"),131072,true).bytes;
        if(!fixtureSha.equals(MobiMindContract.sha(fixture)))throw new IOException("fixture SHA mismatch");
        Map<String,Object> f=MobiMindContract.jsonObject(fixture);
        require(f,"schema","hepta.mobimind.private-gui-fixture.v1");require(f,"prefix_sha256",PREFIX_SHA);require(f,"variable_sha256",VARIABLE_SHA);
        require(f,"template_wrapping",Boolean.FALSE);require(f,"actions_executed",Boolean.FALSE);require(f,"one_shot_concatenation",Boolean.TRUE);
        String owner=text(f,"task_utf8"),history=text(f,"history_utf8");boundedSourceText(owner,32768);boundedSourceText(history,16384);
        require(f,"task_sha256",MobiMindContract.sha(owner.getBytes(StandardCharsets.UTF_8)));
        require(f,"history_sha256",MobiMindContract.sha(history.getBytes(StandardCharsets.UTF_8)));
        byte[] source=MobiMindPrivateFiles.read(new File(files,"mobi-prompt-source.json"),65536,true).bytes;
        if(!PROMPT_SOURCE_SHA.equals(MobiMindContract.sha(source)))throw new IOException("official GUI source asset pin mismatch");
        Map<String,Object> s=MobiMindContract.jsonObject(source);String prefix=text(s,"builtin_prefix"),variable=text(s,"builtin_variable");
        for(String key:new String[]{"source_repository","source_commit","source_path","source_git_blob"})require(f,key,s.get(key));
        if(!PREFIX_SHA.equals(MobiMindContract.sha(prefix.getBytes(StandardCharsets.UTF_8)))
                ||!VARIABLE_SHA.equals(MobiMindContract.sha(variable.getBytes(StandardCharsets.UTF_8)))
                ||occurrences(prefix,"{task}")!=1||occurrences(variable,"{history}")!=1||occurrences(variable,"<image_placeholder>")!=1)
            throw new IOException("pinned prompt placeholder contract differs");
        byte[] prompt=MobiMindPrivateFiles.read(new File(inputs,"prompt.txt"),65536,true).bytes;
        byte[] rendered=(prefix.replace("{task}",owner)+variable.replace("{history}",history).replace("<image_placeholder>","<img>screen</img>")).getBytes(StandardCharsets.UTF_8);
        if(!Arrays.equals(prompt,rendered))throw new IOException("prompt is not the exact pinned one-shot owner/history rendering");
        require(f,"prompt_sha256",MobiMindContract.sha(prompt));if(integer(f,"prompt_bytes")!=prompt.length)throw new IOException("prompt size mismatch");
        byte[] image=MobiMindPrivateFiles.read(new File(inputs,"image.png"),32*1024*1024,true).bytes;
        require(f,"image_sha256",MobiMindContract.sha(image));if(integer(f,"image_bytes")!=image.length)throw new IOException("image size mismatch");
        byte[] magic={(byte)137,80,78,71,13,10,26,10};
        if(image.length<33||!Arrays.equals(Arrays.copyOf(image,8),magic)||image[12]!='I'||image[13]!='H'||image[14]!='D'||image[15]!='R')throw new IOException("original PNG required");
        int width=be32(image,16),height=be32(image,20);
        if(width<32||height<32||width>8192||height>8192||(long)width*height>32000000L
                ||integer(f,"image_width")!=width||integer(f,"image_height")!=height)throw new IOException("PNG geometry mismatch");
        PrivateMobiProbe result=new PrivateMobiProbe(id,nonce,owner,history,prompt,image,fixture,width,height,(int)tokens,deadline);
        File claims=MobiMindPrivateFiles.directory(new File(files,"mobi-probe-consumed"),false);
        // Exclusive durable claim is the replay barrier. A later error never reuses this nonce.
        if(System.currentTimeMillis()>expires)throw new IOException("diagnostic request expired during input verification");
        request.unchangedPath();MobiMindPrivateFiles.writeNew(new File(claims,result.nonceSha+".json"),request.bytes);
        request.unchangedPath();if(!request.path.delete())throw new IOException("claimed request could not be removed");
        MobiMindPrivateFiles.syncDirectory(files);
        return result;
    }
    private static int be32(byte[] bytes,int at){return (bytes[at]&255)<<24|(bytes[at+1]&255)<<16|(bytes[at+2]&255)<<8|(bytes[at+3]&255);}
    private static void boundedSourceText(String value,int maximum)throws IOException{
        if(value.isEmpty()||value.indexOf('\0')>=0||value.getBytes(StandardCharsets.UTF_8).length>maximum)throw new IOException("bounded owner/history required");
        for(String reserved:new String[]{"<img>","</img>","<audio>","</audio>","<image_placeholder>","<|im_start|>","<|im_end|>"})
            if(value.contains(reserved))throw new IOException("owner/history contains reserved media/role token");
    }
    private static int occurrences(String text,String word){int n=0,at=0;while((at=text.indexOf(word,at))>=0){n++;at+=word.length();}return n;}
    static String text(Map<String,Object> value,String key)throws IOException{Object v=value.get(key);if(!(v instanceof String))throw new IOException("expected string: "+key);return (String)v;}
    static long integer(Map<String,Object> value,String key)throws IOException{Object v=value.get(key);if(!(v instanceof Long)&&!(v instanceof Integer))throw new IOException("expected integer: "+key);return ((Number)v).longValue();}
    static void require(Map<String,Object> value,String key,Object expected)throws IOException{if(!expected.equals(value.get(key)))throw new IOException("field binding mismatch: "+key);}
}
