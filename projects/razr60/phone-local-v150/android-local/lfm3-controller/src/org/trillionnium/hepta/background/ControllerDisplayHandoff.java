package org.trillionnium.hepta.background;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONObject;

/** Read-only, pre-create handoff. No serialized receipt authorizes an input,
 * task removal, display release or model request. The caller's own root reader
 * must finish before the existing background-create path may run. */
public final class ControllerDisplayHandoff {
    private ControllerDisplayHandoff(){}
    public static final String PACKAGE="org.trillionnium.hepta.local";
    public static final String COMPONENT=PACKAGE+"/"+PACKAGE+".MainActivity";
    public static final String REQUEST="hepta.controller-display-handoff.request.v1";
    public static final String SAMPLE="hepta.controller-display-handoff.census.v1";
    public static final String BEFORE="hepta.controller-display-handoff.before.v1";
    public static final String COMPLETE="hepta.controller-display-handoff.complete.v1";
    public static final long LIMIT_MS=30000, LOCATOR_MAX_AGE_MS=15000;
    public static final int MAX_WIRE=32768,MAX_OUTPUT=262144,PUBLIC_FLAGS=7040;
    public static void need(boolean value,String code)throws IOException{if(!value)throw new IOException(code);}
    public static String sha(byte[] bytes)throws Exception{
        byte[] digest=MessageDigest.getInstance("SHA-256").digest(bytes);StringBuilder out=new StringBuilder();
        for(byte value:digest)out.append(String.format(java.util.Locale.ROOT,"%02x",value&255));return out.toString();
    }
    public static String string(JSONObject o,String key)throws Exception{
        Object v=o.get(key);need(v instanceof String&&!((String)v).isEmpty(),"HANDOFF_STRING_"+key);return (String)v;
    }
    public static long number(JSONObject o,String key)throws Exception{
        Object v=o.get(key);need(v instanceof Integer||v instanceof Long,"HANDOFF_INTEGER_"+key);return ((Number)v).longValue();
    }
    private static int integer(JSONObject o,String key)throws Exception{
        long value=number(o,key);need(value>=Integer.MIN_VALUE&&value<=Integer.MAX_VALUE,"HANDOFF_INTEGER_RANGE_"+key);return (int)value;
    }
    public static void keys(JSONObject o,String... names)throws Exception{
        Set<String> found=new HashSet<String>();Iterator<String> it=o.keys();while(it.hasNext())found.add(it.next());
        need(found.equals(new HashSet<String>(Arrays.asList(names))),"HANDOFF_KEYS");
    }
    public static boolean same(JSONObject a,JSONObject b){
        if(a==null||b==null||a.length()!=b.length())return false;
        try{Iterator<String> keys=a.keys();while(keys.hasNext()){String key=keys.next();if(!b.has(key)||!equal(a.get(key),b.get(key)))return false;}return true;}
        catch(Exception unavailable){return false;}
    }
    private static boolean equal(Object a,Object b)throws Exception{
        if(a==JSONObject.NULL||b==JSONObject.NULL)return a==JSONObject.NULL&&b==JSONObject.NULL;
        if(a instanceof JSONObject&&b instanceof JSONObject)return same((JSONObject)a,(JSONObject)b);
        if(a instanceof JSONArray&&b instanceof JSONArray){JSONArray x=(JSONArray)a,y=(JSONArray)b;if(x.length()!=y.length())return false;
            for(int i=0;i<x.length();i++)if(!equal(x.get(i),y.get(i)))return false;return true;}
        if((a instanceof Integer||a instanceof Long)&&(b instanceof Integer||b instanceof Long))return ((Number)a).longValue()==((Number)b).longValue();
        return a!=null&&a.getClass()==b.getClass()&&a.equals(b);
    }
    public static JSONObject copy(JSONObject value)throws Exception{return new JSONObject(value.toString());}
    /** Only an already bound caller's removal is an incomplete waiting census.
     * Unknown/duplicate IDs or any other deletion/addition are never retried. */
    public static boolean onlyCallerRemoved(int[] before,int[] after,int caller){
        if(before==null||after==null||caller<=1||before.length<3||before.length>64||after.length!=before.length-1)return false;
        Set<Integer> a=new HashSet<Integer>(),b=new HashSet<Integer>();
        for(int id:before)if(id<0||!a.add(id))return false;
        for(int id:after)if(id<0||!b.add(id))return false;
        if(!a.contains(0)||!a.contains(1)||!b.contains(0)||!b.contains(1)||!a.remove(caller)||b.contains(caller))return false;
        return a.equals(b);
    }
    public static final class Locator {
        public final int uid,pid,task,display,flags;
        public final long startTicks,captured;
        public final String ownerSha,name,generation;
        private final String json;
        private Locator(JSONObject v)throws Exception{
            keys(v,"uid","pid","process_start_ticks","task_id","display_id","display_name","display_flags",
                    "component","owner_sha256","captured_elapsed_ms");
            uid=integer(v,"uid");pid=integer(v,"pid");task=integer(v,"task_id");display=integer(v,"display_id");
            flags=integer(v,"display_flags");startTicks=number(v,"process_start_ticks");captured=number(v,"captured_elapsed_ms");
            ownerSha=string(v,"owner_sha256");name=string(v,"display_name");
            String prefix="Hepta public own-group probe-";
            need(name.startsWith(prefix),"HANDOFF_CONTROLLER_DISPLAY_NAME");generation=name.substring(prefix.length());
            need(generation.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),"HANDOFF_CONTROLLER_GENERATION");
            need(uid>=10000&&uid<100000&&pid>1&&task>0&&display>1&&flags==PUBLIC_FLAGS&&startTicks>0&&captured>0
                    &&ownerSha.matches("[0-9a-f]{64}")&&name.length()<=256&&name.indexOf('\0')<0
                    &&COMPONENT.equals(string(v,"component")),"HANDOFF_LOCATOR_INVALID");json=v.toString();
        }
        public JSONObject json()throws Exception{return new JSONObject(json);}
    }
    /** All arguments here are captured by the actual visible MainActivity callback. */
    public static Locator fromOwnerButton(int uid,int pid,long ticks,int task,int display,String name,int flags,long now,String ownerSha)throws Exception{
        return new Locator(new JSONObject().put("uid",uid).put("pid",pid).put("process_start_ticks",ticks).put("task_id",task)
                .put("display_id",display).put("display_name",name).put("display_flags",flags).put("component",COMPONENT)
                .put("owner_sha256",ownerSha).put("captured_elapsed_ms",now));
    }
    public static final class Request {
        public final Locator locator;
        public final String taskId,nonce,requestSha;
        public final long started,deadline,taskDeadline;
        public final int boot;
        private final String json;
        private Request(JSONObject v)throws Exception{
            keys(v,"schema","task_id","nonce","started_elapsed_ms","deadline_elapsed_ms","task_deadline_elapsed_ms",
                    "boot_count","locator","installation");
            need(REQUEST.equals(string(v,"schema")),"HANDOFF_REQUEST_SCHEMA");locator=new Locator(v.getJSONObject("locator"));
            taskId=string(v,"task_id");nonce=string(v,"nonce");started=number(v,"started_elapsed_ms");deadline=number(v,"deadline_elapsed_ms");
            taskDeadline=number(v,"task_deadline_elapsed_ms");boot=integer(v,"boot_count");
            need(taskId.matches("[0-9a-f]{32}")&&nonce.matches("[0-9a-f]{32}")&&boot>=0&&started>=locator.captured
                    &&started-locator.captured<=LOCATOR_MAX_AGE_MS&&deadline>started&&deadline-started<=LIMIT_MS
                    &&deadline<=taskDeadline&&taskDeadline-started<=480000,"HANDOFF_REQUEST_BOUND");
            need(v.getJSONObject("installation").length()>0,"HANDOFF_INSTALLATION_MISSING");json=v.toString();
            need(json.getBytes(StandardCharsets.UTF_8).length<=MAX_WIRE,"HANDOFF_REQUEST_SIZE");requestSha=sha(json.getBytes(StandardCharsets.UTF_8));
        }
        public JSONObject json()throws Exception{return new JSONObject(json);}
        public JSONObject installation()throws Exception{return json().getJSONObject("installation");}
        public String wire(){return java.util.Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));}
        public void fence(long now,int currentBoot)throws Exception{need(now>=started&&now<deadline&&currentBoot==boot,"HANDOFF_DEADLINE_OR_BOOT");}
    }
    public static Request request(Locator l,String task,String nonce,long now,long taskDeadline,int boot,JSONObject installation)throws Exception{
        return new Request(new JSONObject().put("schema",REQUEST).put("task_id",task).put("nonce",nonce).put("locator",l.json())
                .put("started_elapsed_ms",now).put("deadline_elapsed_ms",Math.min(taskDeadline,now+LIMIT_MS))
                .put("task_deadline_elapsed_ms",taskDeadline).put("boot_count",boot).put("installation",copy(installation)));
    }
    public static Request fromWire(String value)throws Exception{
        need(value!=null&&value.length()<=MAX_WIRE*2,"HANDOFF_WIRE_SIZE");byte[] bytes=java.util.Base64.getDecoder().decode(value);
        need(bytes.length<=MAX_WIRE,"HANDOFF_WIRE_SIZE");return new Request(new JSONObject(new String(bytes,StandardCharsets.UTF_8)));
    }
    public static JSONObject envelope(String schema,Request r)throws Exception{
        return new JSONObject().put("schema",schema).put("request_sha256",r.requestSha).put("task_id",r.taskId).put("nonce",r.nonce)
                .put("owner_sha256",r.locator.ownerSha).put("controller_generation",r.locator.generation).put("deadline_elapsed_ms",r.deadline).put("read_only",true);
    }
    private static void envelope(JSONObject v,String schema,Request r)throws Exception{
        need(schema.equals(string(v,"schema"))&&r.requestSha.equals(string(v,"request_sha256"))&&r.taskId.equals(string(v,"task_id"))
                &&r.nonce.equals(string(v,"nonce"))&&r.locator.ownerSha.equals(string(v,"owner_sha256"))
                &&r.locator.generation.equals(string(v,"controller_generation"))
                &&number(v,"deadline_elapsed_ms")==r.deadline&&Boolean.TRUE.equals(v.get("read_only")),"HANDOFF_PROOF_BINDING");
    }
    private static JSONObject display(JSONArray rows,int id)throws Exception{
        JSONObject found=null;Set<Long> ids=new HashSet<Long>();
        need(rows.length()>=2&&rows.length()<=64,"HANDOFF_DISPLAY_CENSUS_BOUND");
        for(int i=0;i<rows.length();i++){JSONObject row=rows.getJSONObject(i);long rid=number(row,"id");
            need(rid>=0&&ids.add(rid)&&number(row,"group")>=0&&number(row,"type")>=0,"HANDOFF_DISPLAY_CENSUS_INVALID");
            string(row,"name");string(row,"unique_id");if(rid==id)found=row;
        }
        need(ids.contains(0L)&&ids.contains(1L),"HANDOFF_PHYSICAL_IDS_MISSING");return found;
    }
    private static void sample(JSONObject s,Request r)throws Exception{
        need(SAMPLE.equals(string(s,"schema"))&&Boolean.TRUE.equals(s.get("complete")),"HANDOFF_SAMPLE_INCOMPLETE");
        long begin=number(s,"started_elapsed_ms"),end=number(s,"finished_elapsed_ms");
        need(begin>=r.started&&end>=begin&&end<r.deadline,"HANDOFF_SAMPLE_TIME");
        need(number(s,"app_pid")==r.locator.pid&&number(s,"app_uid")==r.locator.uid
                &&number(s,"app_start_ticks")==r.locator.startTicks,"HANDOFF_PROCESS_CHANGED");
        JSONObject p=s.getJSONObject("physical");keys(p,"0","1");string(p,"0");string(p,"1");
        need(string(s,"foreign_history_sha256").matches("[0-9a-f]{64}")&&string(s,"recents_raw_sha256").matches("[0-9a-f]{64}"),"HANDOFF_HISTORY_HASH");
        display(s.getJSONArray("displays"),r.locator.display);
        s.getJSONArray("root_ids");s.getJSONArray("leaf_ids");s.getJSONArray("recent_ids");
    }
    private static boolean containsId(JSONArray ids,int wanted)throws Exception{
        boolean found=false;
        Set<Long> seen=new HashSet<Long>();for(int i=0;i<ids.length();i++){
            Object v=ids.get(i);need(v instanceof Integer||v instanceof Long,"HANDOFF_TASK_CENSUS_TYPE");long id=((Number)v).longValue();
            need(id>0&&id<=Integer.MAX_VALUE&&seen.add(id),"HANDOFF_TASK_CENSUS_INVALID");if(id==wanted)found=true;
        }return found;
    }
    private static void noId(JSONArray ids,int forbidden)throws Exception{
        need(!containsId(ids,forbidden),"HANDOFF_OLD_TASK_PRESENT");
    }
    public static JSONObject validateBefore(JSONObject before,Request r,long now,int boot)throws Exception{
        r.fence(now,boot);envelope(before,BEFORE,r);JSONObject s=before.getJSONObject("sample");sample(s,r);
        JSONObject own=display(s.getJSONArray("displays"),r.locator.display);need(own!=null,"HANDOFF_CALLER_DISPLAY_MISSING");
        need(string(own,"name").equals(r.locator.name)&&number(own,"flags")==r.locator.flags&&number(own,"type")==5
                &&number(own,"state")==2&&number(own,"owner_uid")==0&&"com.android.shell".equals(string(own,"owner_package")),"HANDOFF_CALLER_DISPLAY_INVALID");
        long group=number(own,"group");need(group>0,"HANDOFF_GROUP_INVALID");
        JSONArray rows=s.getJSONArray("displays");for(int i=0;i<rows.length();i++){
            JSONObject row=rows.getJSONObject(i);need(number(row,"id")==r.locator.display||number(row,"group")!=group,"HANDOFF_GROUP_NOT_EXCLUSIVE");
        }
        JSONObject task=s.getJSONObject("controller_task");
        need(number(task,"id")==r.locator.task&&number(task,"display")==r.locator.display&&number(task,"uid")==r.locator.uid
                &&number(task,"user")==0&&number(task,"parent")==-1&&COMPONENT.equals(string(task,"intent"))
                &&COMPONENT.equals(string(task,"real"))&&Boolean.TRUE.equals(s.get("controller_active_complete")),"HANDOFF_CALLER_TASK_INVALID");
        string(task,"token");need(number(before,"reader_uid")==0&&number(before,"reader_pid")>1&&number(before,"reader_start_ticks")>0,"HANDOFF_READER_IDENTITY");
        for(String key:new String[]{"root_ids","leaf_ids","recent_ids"})need(containsId(s.getJSONArray(key),r.locator.task),"HANDOFF_CALLER_CENSUS_MISSING");
        return copy(before);
    }
    /** Release may briefly leave a known OFF/UNKNOWN logical display or a
     * finishing task. Those remain pending, never absence; identity, singleton,
     * physical displays and foreign recents still have to match throughout. */
    public static boolean validateWaiting(JSONObject s,JSONObject before,Request r)throws Exception{
        sample(s,r);JSONObject initial=before.getJSONObject("sample");
        need(number(s,"started_elapsed_ms")>number(initial,"finished_elapsed_ms"),"HANDOFF_SAMPLE_ORDER");
        need(same(initial.getJSONObject("physical"),s.getJSONObject("physical"))
                &&string(initial,"foreign_history_sha256").equals(string(s,"foreign_history_sha256")),"HANDOFF_PHYSICAL_OR_HISTORY_CHANGED");
        for(int id:new int[]{0,1})need(same(display(initial.getJSONArray("displays"),id),display(s.getJSONArray("displays"),id)),"HANDOFF_PHYSICAL_DISPLAY_CHANGED");
        JSONObject old=display(initial.getJSONArray("displays"),r.locator.display),current=display(s.getJSONArray("displays"),r.locator.display);
        JSONArray rows=s.getJSONArray("displays");for(int i=0;i<rows.length();i++){
            JSONObject row=rows.getJSONObject(i);if(number(row,"id")!=r.locator.display){
                need(!string(row,"name").equals(r.locator.name)&&!string(row,"unique_id").equals(string(old,"unique_id")),"HANDOFF_DISPLAY_RELOCATED");
                if(current!=null)need(number(row,"group")!=number(old,"group"),"HANDOFF_GROUP_NOT_EXCLUSIVE");
            }
        }
        if(current!=null){long state=number(current,"state");need(state==0||state==1||state==2,"HANDOFF_RELEASE_DISPLAY_STATE");
            JSONObject a=copy(old),b=copy(current);a.remove("state");b.remove("state");need(same(a,b),"HANDOFF_CALLER_DISPLAY_CHANGED");}
        boolean taskPresent=!s.isNull("controller_task");if(taskPresent)need(same(initial.getJSONObject("controller_task"),s.getJSONObject("controller_task")),"HANDOFF_CALLER_TASK_CHANGED");
        boolean found=false;for(String key:new String[]{"root_ids","leaf_ids","recent_ids"})found|=containsId(s.getJSONArray(key),r.locator.task);
        return current==null&&!taskPresent&&!found;
    }
    /** Both after samples are fresh full censuses, not cached App visibility. */
    public static JSONObject validateComplete(JSONObject complete,JSONObject before,Request r,long now,int boot)throws Exception{
        validateBefore(before,r,now,boot);envelope(complete,COMPLETE,r);
        need(string(complete,"before_sha256").equals(sha(before.toString().getBytes(StandardCharsets.UTF_8)))
                &&number(complete,"reader_pid")==number(before,"reader_pid")
                &&number(complete,"reader_start_ticks")==number(before,"reader_start_ticks"),"HANDOFF_READER_OR_BEFORE_CHANGED");
        JSONArray pair=complete.getJSONArray("absence_samples");need(pair.length()==2,"HANDOFF_TWO_ABSENCE_REQUIRED");
        JSONObject initial=before.getJSONObject("sample"),oldDisplay=display(initial.getJSONArray("displays"),r.locator.display);
        long last=number(initial,"finished_elapsed_ms");
        for(int i=0;i<2;i++){
            JSONObject s=pair.getJSONObject(i);sample(s,r);need(number(s,"started_elapsed_ms")>last,"HANDOFF_ABSENCE_ORDER");last=number(s,"finished_elapsed_ms");
            need(display(s.getJSONArray("displays"),r.locator.display)==null&&s.isNull("controller_task"),"HANDOFF_DISPLAY_OR_TASK_PRESENT");
            for(int j=0;j<s.getJSONArray("displays").length();j++){JSONObject row=s.getJSONArray("displays").getJSONObject(j);
                need(!string(row,"name").equals(r.locator.name)&&!string(row,"unique_id").equals(string(oldDisplay,"unique_id")),"HANDOFF_DISPLAY_RELOCATED");}
            noId(s.getJSONArray("root_ids"),r.locator.task);noId(s.getJSONArray("leaf_ids"),r.locator.task);noId(s.getJSONArray("recent_ids"),r.locator.task);
            need(same(initial.getJSONObject("physical"),s.getJSONObject("physical"))
                    &&string(initial,"foreign_history_sha256").equals(string(s,"foreign_history_sha256")),"HANDOFF_PHYSICAL_OR_HISTORY_CHANGED");
            need(same(display(initial.getJSONArray("displays"),0),display(s.getJSONArray("displays"),0))
                    &&same(display(initial.getJSONArray("displays"),1),display(s.getJSONArray("displays"),1)),"HANDOFF_PHYSICAL_DISPLAY_CHANGED");
        }
        need(Boolean.TRUE.equals(complete.get("current_absence_verified"))&&Boolean.FALSE.equals(complete.get("business_success")),"HANDOFF_PROOF_SCOPE");
        return copy(complete);
    }
}
