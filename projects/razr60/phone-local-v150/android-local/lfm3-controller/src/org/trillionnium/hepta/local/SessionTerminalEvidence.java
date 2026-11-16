package org.trillionnium.hepta.local;

import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;

/** A bounded session projection, bound to the complete create-once private task result.
 * This reference records evidence; it never changes a terminal outcome or grants an action. */
final class SessionTerminalEvidence {
    static final String SCHEMA="hepta.session-terminal-evidence.v1";
    static final String SUMMARY="hepta.session-terminal-summary.v1";
    static final String REFERENCE="hepta.session-task-result-reference.v1";
    static final int MAX_RESULT_BYTES=8*1024*1024;
    private SessionTerminalEvidence(){}

    /** Projects only an oversized immutable queued snapshot. No live session fields are read. */
    static void capture(JSONObject session,JSONObject fullCompletion)throws Exception {
        session.put("terminal_evidence_schema",SCHEMA);
        session.put("completion_evidence",summary(fullCompletion));
    }
    static boolean referenced(JSONObject session)throws Exception {
        if(session.has("terminal_evidence_schema")||session.has("task_result_reference"))return true;
        if(!session.has("completion_evidence"))return false;
        Object value=session.get("completion_evidence");
        return value instanceof JSONObject&&((JSONObject)value).has("schema")
                &&SUMMARY.equals(((JSONObject)value).get("schema"));
    }
    static void bind(JSONObject session,File files,int uid)throws Exception {check(session,files,uid,false);}
    static void verify(JSONObject session,File files,int uid)throws Exception {check(session,files,uid,true);}

    private static void check(JSONObject session,File files,int uid,boolean existing)throws Exception {
        equal(session,"terminal_evidence_schema",SCHEMA);
        String task=hex(session,"task_id",32);
        String owner=hex(session,"instruction_sha256",64);
        String authority=hex(session,"task_authorization_sha256",64);
        require(session.get("completion_evidence") instanceof JSONObject,"terminal summary missing");
        JSONObject expectedSummary=session.getJSONObject("completion_evidence");
        equal(expectedSummary,"schema",SUMMARY);
        String relative="control-tasks/"+task+"/result.json";
        File tasks=new File(files,"control-tasks"),directory=new File(tasks,task),path=new File(directory,"result.json");
        require(files.isAbsolute()&&files.equals(files.getCanonicalFile())
                &&directory.equals(directory.getCanonicalFile()),"terminal result path must be canonical");
        // Legacy display hint only: Android can expose the same app files through bind-mount aliases.
        // Never open this supplied string. The only opened path is derived from the trusted files root.
        String displayed=string(session,"evidence_directory",4096);
        require(displayed.endsWith("/control-tasks/"+task),"terminal evidence task directory differs");
        JSONObject prior=null;
        if(existing){
            require(session.has("task_result_reference"),"terminal result reference missing");
            prior=session.getJSONObject("task_result_reference");
            equal(prior,"schema",REFERENCE);equal(prior,"task_id",task);equal(prior,"relative_path",relative);
        }else require(!session.has("task_result_reference"),"terminal result was already bound");
        try(Directory root=new Directory(files,uid);Directory parent=new Directory(tasks,uid);
                Directory taskDirectory=new Directory(directory,uid);ResultFile file=new ResultFile(path,uid)){
            byte[] bytes=file.read();
            JSONObject result=parse(bytes);
            equal(result,"task_id",task);equal(result,"task_authorization_sha256",authority);
            for(String key:new String[]{"status","steps","model_reported_success","completion_verified",
                    "goal_independently_verified","expected_scope_sha256","actual_scope_sha256"})
                scalarSame(result,key,session,key);
            scalarSame(result,"summary",session,"state");
            // A previously failed queue can only make the journal more restrictive.
            Object cleanup=session.get("cleanup_known");
            require(cleanup instanceof Boolean,"session cleanup type differs");
            require(result.get("cleanup_known") instanceof Boolean,"result cleanup type differs");
            if(!cleanup.equals(result.get("cleanup_known")))
                require(Boolean.FALSE.equals(cleanup)&&session.has("session_journal_failure_observed")
                        &&Boolean.TRUE.equals(session.get("session_journal_failure_observed"))
                        &&Boolean.TRUE.equals(session.get("blocked")),"terminal cleanup differs");
            equal(result,"external_model",Boolean.FALSE);equal(result,"automatic_replay",Boolean.FALSE);
            JSONObject completion=result.getJSONObject("completion_evidence");
            equal(completion,"owner_sha256",owner);
            JSONObject actualSummary=summary(completion);
            require(semanticSha(expectedSummary).equals(semanticSha(actualSummary)),"terminal completion differs from captured result");
            JSONObject reference=new JSONObject().put("schema",REFERENCE).put("task_id",task)
                    .put("relative_path",relative).put("bytes",bytes.length).put("sha256",sha(bytes))
                    .put("file_device",file.identity.st_dev).put("file_inode",file.identity.st_ino)
                    .put("file_uid",file.identity.st_uid).put("file_mode",file.identity.st_mode)
                    .put("file_nlink",file.identity.st_nlink)
                    .put("completion_evidence_sha256",expectedSummary.get("full_completion_evidence_sha256"))
                    .put("digest_encoding","typed_sorted_json_semantics.v1")
                    .put("grants_tool_authority",false);
            if(existing)require(semanticSha(prior).equals(semanticSha(reference)),"terminal result reference changed");
            // The producer syncs result data; independently establish current file and entry durability.
            // Every sync acts on the descriptor whose identity was checked, never a caller-chosen path.
            file.sync();taskDirectory.sync();parent.sync();root.sync();
            require(Arrays.equals(bytes,file.read()),"terminal result bytes changed during binding");
            file.unchanged();taskDirectory.unchanged();parent.unchanged();root.unchanged();
            if(!existing)session.put("task_result_reference",reference);
        }
    }

    private static JSONObject summary(JSONObject completion)throws Exception {
        String kind=string(completion,"kind",128);
        String owner=hex(completion,"owner_sha256",64),contract=hex(completion,"contract_sha256",64);
        JSONObject value=new JSONObject().put("schema",SUMMARY).put("kind",kind)
                .put("owner_sha256",owner).put("contract_sha256",contract)
                .put("full_completion_evidence_sha256",semanticSha(completion))
                .put("digest_encoding","typed_sorted_json_semantics.v1")
                .put("full_evidence_embedded",false).put("grants_tool_authority",false);
        for(String key:new String[]{"completion_verified","business_verified","terminal_binding_and_cleanup_verified"}){
            if(completion.has(key)){
                Object field=completion.get(key);
                require(field instanceof Boolean,"completion flag type differs: "+key);value.put(key,field);
            }
        }
        return value;
    }

    /** Key order and equivalent JSON number spellings do not affect the semantic digest.
     * Strings/keys are UTF-8 length-prefixed; every value has a type tag and containers a count. */
    static String semanticSha(Object value)throws Exception {
        MessageDigest digest=MessageDigest.getInstance("SHA-256");semantic(digest,value,0);return hexBytes(digest.digest());
    }
    private static void semantic(MessageDigest digest,Object value,int depth)throws Exception {
        require(depth<=64,"terminal JSON nesting exceeds bound");
        if(value==null||value==JSONObject.NULL){digest.update((byte)'n');return;}
        if(value instanceof Boolean){digest.update((byte)((Boolean)value?'t':'f'));return;}
        if(value instanceof String){digest.update((byte)'s');text(digest,(String)value);return;}
        if(value instanceof Number){
            String number;
            try{number=new BigDecimal(value.toString()).stripTrailingZeros().toPlainString();}
            catch(NumberFormatException failure){throw new IOException("terminal number is not finite",failure);}
            require(number.length()<=1024,"terminal number exceeds bound");
            digest.update((byte)'d');text(digest,number);return;
        }
        if(value instanceof JSONObject){
            digest.update((byte)'o');JSONObject object=(JSONObject)value;
            ArrayList<String> keys=new ArrayList<String>();Iterator<String> names=object.keys();
            while(names.hasNext())keys.add(names.next());Collections.sort(keys);count(digest,keys.size());
            for(String key:keys){text(digest,key);semantic(digest,object.get(key),depth+1);}return;
        }
        if(value instanceof JSONArray){
            digest.update((byte)'a');JSONArray array=(JSONArray)value;count(digest,array.length());
            for(int i=0;i<array.length();i++)semantic(digest,array.get(i),depth+1);return;
        }
        throw new IOException("unsupported terminal JSON value");
    }
    private static void text(MessageDigest digest,String text)throws Exception {
        for(int i=0;i<text.length();i++){
            char c=text.charAt(i);
            if(Character.isHighSurrogate(c)){require(i+1<text.length()&&Character.isLowSurrogate(text.charAt(i+1)),"invalid terminal Unicode");i++;}
            else require(!Character.isLowSurrogate(c),"invalid terminal Unicode");
        }
        byte[] bytes=text.getBytes(StandardCharsets.UTF_8);count(digest,bytes.length);digest.update(bytes);
    }
    private static void count(MessageDigest digest,int count){
        digest.update((byte)(count>>>24));digest.update((byte)(count>>>16));digest.update((byte)(count>>>8));digest.update((byte)count);
    }
    private static String sha(byte[] bytes)throws Exception {return hexBytes(MessageDigest.getInstance("SHA-256").digest(bytes));}
    private static String hexBytes(byte[] bytes){
        char[] alphabet="0123456789abcdef".toCharArray(),out=new char[bytes.length*2];
        for(int i=0;i<bytes.length;i++){out[2*i]=alphabet[(bytes[i]&255)>>>4];out[2*i+1]=alphabet[bytes[i]&15];}return new String(out);
    }
    private static JSONObject parse(byte[] bytes)throws Exception {
        String decoded=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
        JSONTokener parser=new JSONTokener(decoded);Object value=parser.nextValue();
        require(value instanceof JSONObject&&parser.nextClean()==0,"terminal result must be one JSON object");return (JSONObject)value;
    }
    private static String string(JSONObject object,String key,int maximum)throws Exception {
        Object value=object.get(key);require(value instanceof String,"terminal string required: "+key);
        String result=(String)value;require(!result.isEmpty()&&result.length()<=maximum&&result.indexOf('\0')<0,"terminal string bound: "+key);return result;
    }
    private static String hex(JSONObject object,String key,int length)throws Exception {
        String value=string(object,key,length);require(value.length()==length&&value.matches("[0-9a-f]+"),"terminal hex identity differs: "+key);return value;
    }
    private static void equal(JSONObject object,String key,Object expected)throws Exception {
        require(expected.equals(object.get(key)),"terminal field differs: "+key);
    }
    private static void scalarSame(JSONObject a,String ak,JSONObject b,String bk)throws Exception {
        Object av=a.get(ak),bv=b.get(bk);
        if(av==JSONObject.NULL||bv==JSONObject.NULL){require(av==JSONObject.NULL&&bv==JSONObject.NULL,"terminal null differs: "+ak);return;}
        if(av instanceof Integer||av instanceof Long){
            require((bv instanceof Integer||bv instanceof Long)&&((Number)av).longValue()==((Number)bv).longValue(),"terminal integer differs: "+ak);return;
        }
        require((av instanceof String||av instanceof Boolean)&&av.getClass()==bv.getClass()&&av.equals(bv),"terminal value differs: "+ak);
    }
    private static void require(boolean value,String why)throws IOException {if(!value)throw new IOException(why);}

    private static boolean sameIdentity(StructStat a,StructStat b){
        return a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_uid==b.st_uid&&a.st_mode==b.st_mode;
    }
    private static boolean sameFile(StructStat a,StructStat b){
        return sameIdentity(a,b)&&a.st_nlink==b.st_nlink&&a.st_size==b.st_size
                &&a.st_mtime==b.st_mtime&&a.st_ctime==b.st_ctime;
    }
    private static final class Directory implements Closeable {
        final File path;final FileDescriptor descriptor;final StructStat identity;
        Directory(File path,int uid)throws Exception {
            this.path=path;require(path.isAbsolute()&&path.equals(path.getCanonicalFile()),"terminal directory alias");
            descriptor=Os.open(path.getPath(),OsConstants.O_RDONLY|OsConstants.O_NOFOLLOW|OsConstants.O_CLOEXEC,0);
            try{identity=Os.fstat(descriptor);require(OsConstants.S_ISDIR(identity.st_mode)&&identity.st_uid==uid,"terminal directory identity");
                unchanged();}catch(Exception failure){
                try{Os.close(descriptor);}catch(Exception close){failure.addSuppressed(close);}throw failure;
            }
        }
        void unchanged()throws Exception {
            require(path.equals(path.getCanonicalFile())&&sameIdentity(identity,Os.fstat(descriptor))
                    &&sameIdentity(identity,Os.lstat(path.getPath())),"terminal directory changed");
        }
        void sync()throws Exception {unchanged();Os.fsync(descriptor);unchanged();}
        public void close()throws IOException {try{Os.close(descriptor);}catch(Exception error){throw new IOException("terminal directory close failed",error);}}
    }
    private static final class ResultFile implements Closeable {
        final File path;final FileDescriptor descriptor;final StructStat identity;final FileInputStream input;
        ResultFile(File path,int uid)throws Exception {
            this.path=path;require(path.isAbsolute()&&path.equals(path.getCanonicalFile()),"terminal result alias");
            descriptor=Os.open(path.getPath(),OsConstants.O_RDONLY|OsConstants.O_NOFOLLOW|OsConstants.O_CLOEXEC,0);
            try{
                identity=Os.fstat(descriptor);
                require(OsConstants.S_ISREG(identity.st_mode)&&identity.st_uid==uid&&identity.st_nlink==1
                        &&(identity.st_mode&0777)==0600&&identity.st_size>0&&identity.st_size<=MAX_RESULT_BYTES,"terminal result ownership/type/size/mode");
                unchanged();input=new FileInputStream(descriptor);
            }catch(Exception failure){
                try{Os.close(descriptor);}catch(Exception close){failure.addSuppressed(close);}throw failure;
            }
        }
        byte[] read()throws Exception {
            unchanged();input.getChannel().position(0);ByteArrayOutputStream data=new ByteArrayOutputStream();
            byte[] buffer=new byte[65536];int n;
            while((n=input.read(buffer))!=-1){require(data.size()+n<=MAX_RESULT_BYTES,"terminal result grew beyond bound");data.write(buffer,0,n);}
            require(data.size()==identity.st_size,"terminal result length changed");unchanged();return data.toByteArray();
        }
        void unchanged()throws Exception {
            require(path.equals(path.getCanonicalFile())&&sameFile(identity,Os.fstat(descriptor))
                    &&sameFile(identity,Os.lstat(path.getPath())),"terminal result identity changed");
        }
        void sync()throws Exception {unchanged();Os.fsync(descriptor);unchanged();}
        public void close()throws IOException {
            Exception failure=null;
            try{input.close();}catch(Exception error){failure=error;}
            // Android FileInputStream(FileDescriptor) does not own our Os.open descriptor.
            // A host JDK may already have closed it; do not close an invalid/reused descriptor.
            try{if(descriptor.valid())Os.close(descriptor);}
            catch(Exception close){if(failure==null)failure=close;else failure.addSuppressed(close);}
            if(failure!=null)throw new IOException("terminal result close failed",failure);
        }
    }
}
