package org.trillionnium.hepta.background;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.json.JSONObject;

/** Actual History and coordinator; reflection only opens the private observation
 * comparator. No Android calls, clocks, input or cleanup authority are simulated
 * by these diagnostic records. World supplies the existing inert Binder ports. */
public final class NotesHistoryDiagnosticsHostTest {
    private static final String CODE="NOTES_RETIREMENT_FOREIGN_HISTORY_CHANGED";
    private static final Set<Integer> OWN=new LinkedHashSet<Integer>(Arrays.asList(300,301));
    private static final List<String> names=new ArrayList<String>();
    private static final List<JSONObject> actual=new ArrayList<JSONObject>();
    private static int checks;
    private static Path output;
    private static Class<?> history;
    private static Constructor<?> constructor,plainConstructor;
    private static Method same,foreign;
    interface Work {void run()throws Exception;}
    private static void yes(boolean ok){checks++;if(!ok)throw new AssertionError("history diagnostic boundary");}
    private static void test(String name,Work work)throws Exception{work.run();names.add(name);}
    private static String hash(byte[] raw){return ProfileIdentity.sha(raw);}
    private static byte[] bytes(String text){return text.getBytes(StandardCharsets.UTF_8);}
    private static Object history(String text,long begin,long end)throws Exception{return constructor.newInstance(text,begin,end);}
    private static Throwable failure(String before,String after,Set<Integer> own)throws Exception{
        return failureAt(before,after,own,1000);
    }
    private static Throwable failureAt(String before,String after,Set<Integer> own,long begin)throws Exception{
        Object a=history(before,begin,1001),b=after==null?null:history(after,1002,1003);
        try{same.invoke(a,b,own,NotesTokenRetirementHostTest.UID,2L);}catch(InvocationTargetException e){
            Throwable t=e.getCause();yes(t.getClass()==IllegalStateException.class&&CODE.equals(t.getMessage()));return t;}
        throw new AssertionError("changed foreign history was accepted");
    }
    private static JSONObject evidence(Throwable t){Map<String,Object> m=PublicPersonalNotesRetirement.historyDiagnostic(t);yes(m!=null);return new JSONObject(m);}
    private static JSONObject difference(JSONObject value){return value.getJSONObject("first_difference");}
    private static byte[] unpack(JSONObject value)throws Exception{
        JSONObject pair=value.getJSONObject("raw_pair");
        yes(pair.getString("encoding").equals("gzip-base64-concatenated-original-utf8"));
        byte[] compressed=java.util.Base64.getDecoder().decode(pair.getString("data"));
        yes(compressed.length==pair.getInt("compressed_bytes")&&hash(compressed).equals(pair.getString("compressed_sha256")));
        java.io.ByteArrayOutputStream out=new java.io.ByteArrayOutputStream();
        try(java.util.zip.GZIPInputStream in=new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(compressed))){
            byte[] block=new byte[1024];int count;
            while((count=in.read(block))!=-1){yes(out.size()+count<=32768);out.write(block,0,count);}
        }
        byte[] raw=out.toByteArray();yes(raw.length==pair.getInt("decoded_bytes")&&hash(raw).equals(pair.getString("decoded_sha256")));
        return raw;
    }
    private static void exactPair(JSONObject value,String a,String b)throws Exception{
        yes(value.getBoolean("raw_pair_complete"));byte[] combined=unpack(value);
        int split=value.getJSONObject("baseline").getInt("bytes");
        byte[] left=Arrays.copyOfRange(combined,0,split),right=Arrays.copyOfRange(combined,split,combined.length);
        yes(Arrays.equals(left,bytes(a))&&Arrays.equals(right,bytes(b)));
        yes(value.getJSONObject("baseline").getInt("bytes")==left.length&&value.getJSONObject("baseline").getString("sha256").equals(hash(left)));
        yes(value.getJSONObject("current").getInt("bytes")==right.length&&value.getJSONObject("current").getString("sha256").equals(hash(right)));
        yes(!value.getBoolean("release_evidence")&&!value.getBoolean("diagnostics_grant_authority")&&!value.getBoolean("model_input"));
    }
    private static String replace(String input,String a,String b){yes(input.contains(a));return input.replace(a,b);}
    private static String pad(String text,int count){yes(count>=0);return entropy(text,String.join("",Collections.nCopies(count,"x")));}
    private static JSONObject emit(Throwable t)throws Exception{
        JSONObject original=new JSONObject().put("schema","hepta.background-broker-terminal.v1")
                .put("generation",NotesHistoryBrokerOutputHost.GEN).put("state","CLEANUP_UNKNOWN")
                .put("release_confirmed",false).put("original_fixture_field","unaltered");
        JSONObject terminal=new JSONObject(original.toString());
        NotesHistoryBrokerOutputHost.appendNotesHistoryDiagnostic(terminal,t,NotesHistoryBrokerOutputHost.TASK,
                NotesHistoryBrokerOutputHost.GEN,NotesTokenRetirementHostTest.SHA,7);
        JSONObject detail=terminal.getJSONObject("personal_notes_history_diagnostic");
        JSONObject copied=new JSONObject(terminal.toString());copied.remove("personal_notes_history_diagnostic");
        yes(copied.similar(original));yes(bytes(terminal.toString()).length<=32767);
        yes(2*(bytes(terminal.toString()).length+1)<=65536);
        yes(new JSONObject(terminal.toString()).getJSONObject("personal_notes_history_diagnostic").similar(detail));
        yes(detail.getString("task_id").equals(NotesHistoryBrokerOutputHost.TASK)
                &&detail.getString("generation").equals(NotesHistoryBrokerOutputHost.GEN)
                &&detail.getString("scope_sha256").equals(NotesTokenRetirementHostTest.SHA)&&detail.getInt("display_id")==7);
        return detail;
    }
    private static JSONObject augmented(JSONObject original,Throwable failure)throws Exception{
        JSONObject terminal=new JSONObject(original.toString());
        NotesHistoryBrokerOutputHost.appendNotesHistoryDiagnostic(terminal,failure,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                original.getString("generation"),original.getString("display_scope_sha256"),original.getInt("display_id"));
        JSONObject copy=new JSONObject(terminal.toString());copy.remove("personal_notes_history_diagnostic");
        yes(copy.similar(original)&&bytes(terminal.toString()).length<=32767);return terminal;
    }
    private static String entropy(String raw,String padding){int at=raw.indexOf("    lastActiveTime=");yes(at>=0);return raw.substring(0,at)+"    diagnosticFixture="+padding+"\n"+raw.substring(at);}
    private static JSONObject consumerFixtures(String before,String after,Path originalPath)throws Exception{
        JSONObject original=new JSONObject(new String(Files.readAllBytes(originalPath),StandardCharsets.UTF_8));
        Set<Integer> own=new LinkedHashSet<Integer>(Arrays.asList(2005,2006));
        JSONObject normal=augmented(original,failure(before,after,own));
        yes(normal.getJSONObject("personal_notes_history_diagnostic").getBoolean("raw_pair_complete"));
        java.util.Random random=new java.util.Random(600127);StringBuilder all=new StringBuilder();
        for(int i=0;i<6000;i++)all.append((char)('!'+random.nextInt(90)));
        // Newline-free deterministic entropy only controls the compressed fixture
        // size. The actual producer performs every compression/bound decision.
        String noise=all.toString().replace("\\","X").replace("\"","Y");
        int crossing=0;
        for(int n=0;n<=6000;n+=64){
            JSONObject t=augmented(original,failure(entropy(before,noise.substring(0,n)),entropy(after,noise.substring(0,n)),own));
            if(!t.getJSONObject("personal_notes_history_diagnostic").getBoolean("raw_pair_complete")){crossing=n;break;}
        }
        yes(crossing>0);JSONObject max=null;
        for(int n=Math.max(0,crossing-96);n<=Math.min(6000,crossing+32)&&max==null;n++){
            for(long begin:new long[]{1000,100,10,1}){
                Throwable t=failureAt(entropy(before,noise.substring(0,n)),entropy(after,noise.substring(0,n)),own,begin);
                JSONObject value=augmented(original,t),d=value.getJSONObject("personal_notes_history_diagnostic");
                if(d.getBoolean("raw_pair_complete")&&bytes(d.toString()).length==4608){max=value;break;}
            }
        }
        yes(max!=null);
        JSONObject omitted=augmented(original,failure(entropy(before,noise),entropy(after,noise),own));
        JSONObject omission=omitted.getJSONObject("personal_notes_history_diagnostic");
        yes(!omission.getBoolean("raw_pair_complete")&&!omission.has("raw_pair")
                &&omission.getString("raw_pair_omission_reason").equals("serialized_diagnostic_bound"));
        JSONObject result=new JSONObject().put("host_derived_fixtures",true).put("not_original_phone_evidence",true)
                .put("actual_terminal_source_path",originalPath.toString()).put("actual_terminal_source_sha256",hash(Files.readAllBytes(originalPath)));
        for(String label:new String[]{"normal","max","omitted"}){
            JSONObject terminal=label.equals("normal")?normal:label.equals("max")?max:omitted;
            byte[] raw=bytes(terminal.toString()+"\n");Path path=output.resolve("consumer-"+label+"-terminal.json");Files.write(path,raw);
            result.put(label,new JSONObject().put("path",path.toString()).put("bytes",raw.length).put("sha256",hash(raw))
                    .put("diagnostic_bytes",bytes(terminal.getJSONObject("personal_notes_history_diagnostic").toString()).length));
        }
        return result;
    }
    private static NotesTokenRetirementHostTest.World protectedWorld()throws Exception{
        NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(2);
        w.add(500,9,11001,"com.example.foreign/com.example.foreign.Main");
        java.util.LinkedHashMap<Integer,android.app.ActivityTaskManager.RootTaskInfo> rows=new java.util.LinkedHashMap<Integer,android.app.ActivityTaskManager.RootTaskInfo>(w.recent);
        w.recent.clear();w.recent.put(500,rows.remove(500));w.recent.putAll(rows);
        return w;
    }
    public static void main(String[] args)throws Exception{
        output=Paths.get(args[0]);Files.createDirectories(output);
        history=Class.forName("org.trillionnium.hepta.background.PublicPersonalNotesRetirement$History");
        constructor=history.getDeclaredConstructor(String.class,long.class,long.class);constructor.setAccessible(true);
        plainConstructor=history.getDeclaredConstructor(String.class);plainConstructor.setAccessible(true);
        same=history.getDeclaredMethod("requireSame",history,Set.class,int.class,long.class);same.setAccessible(true);
        foreign=history.getDeclaredMethod("protectedHistory",Set.class,int.class);foreign.setAccessible(true);
        NotesTokenRetirementHostTest.World fixture=protectedWorld();
        final String raw=fixture.recents();
        test("unchanged complete history retains original acceptance",()->{
            same.invoke(history(raw,1000,1001),history(raw,1002,1003),OWN,NotesTokenRetirementHostTest.UID,2L);
            yes(PublicPersonalNotesRetirement.historyDiagnostic(null)==null);
        });
        test("all owned tasks remain excluded from foreign comparison",()->{
            fixture.recent.remove(300);fixture.recent.remove(301);
            same.invoke(history(raw,1000,1001),history(fixture.recents(),1002,1003),OWN,NotesTokenRetirementHostTest.UID,2L);
        });
        test("preamble refusal preserves exact class code and byte pair",()->{
            String after=replace(raw,"mRecentsUid=1000","mRecentsUid=1001");
            JSONObject value=evidence(failure(raw,after,OWN));exactPair(value,raw,after);
            yes(difference(value).getString("section").equals("preamble"));
            yes(difference(value).getString("baseline_field_key").equals("mRecentsUid"));
            yes(value.getJSONObject("baseline").getLong("sample_begin_elapsed_ms")==1000
                    &&value.getJSONObject("current").getLong("sample_end_elapsed_ms")==1003);
            Files.write(output.resolve("preamble-pair.json"),bytes(value.toString()));
        });
        test("absolute foreign activity time remains a refusal",()->{
            String after=raw.replaceFirst("lastActiveTime=2000 \\(inactive for 0s\\)","lastActiveTime=2001 (inactive for 0s)");
            JSONObject value=evidence(failure(raw,after,OWN));exactPair(value,raw,after);
            yes(difference(value).getString("section").equals("internal")&&difference(value).getInt("task_id")==500);
            yes(difference(value).getString("baseline_field_key").equals("lastActiveTime"));
        });
        test("relative age allowed by original budget remains accepted",()->{
            String after=replace(raw,"(inactive for 0s)","(inactive for 1s)");
            same.invoke(history(raw,1000,1001),history(after,1002,1003),OWN,NotesTokenRetirementHostTest.UID,2L);yes(true);
        });
        test("relative age excess keeps original distinct refusal",()->{
            String after=replace(raw,"(inactive for 0s)","(inactive for 3s)");
            try{same.invoke(history(raw,1000,1001),history(after,1002,1003),OWN,NotesTokenRetirementHostTest.UID,2L);throw new AssertionError("age accepted");}
            catch(InvocationTargetException e){yes(e.getCause().getClass()==IllegalStateException.class
                    &&"NOTES_RETIREMENT_HISTORY_AGE_CHANGED".equals(e.getCause().getMessage()));
                yes(PublicPersonalNotesRetirement.historyDiagnostic(e.getCause())==null);}
        });
        test("visible foreign field remains protected",()->{
            String after=replace(raw,"id=500 userId=0 hasTask=true lastActiveTime=2000","id=500 userId=0 hasTask=true lastActiveTime=2001");
            JSONObject value=evidence(failure(raw,after,OWN));exactPair(value,raw,after);
            yes(difference(value).getString("section").equals("visible")&&difference(value).getInt("task_id")==500);
        });
        test("foreign membership remains protected",()->{
            NotesTokenRetirementHostTest.World w=protectedWorld();String before=w.recents();w.recent.remove(500);
            JSONObject value=evidence(failure(before,w.recents(),OWN));
            yes(difference(value).getString("kind").equals("membership_or_order_changed"));
            yes(difference(value).getString("section").equals("internal"));
        });
        test("UTF8 content and missing final newline round trip exactly",()->{
            String before=entropy(raw,"中文标记");
            String after=replace(before,"diagnosticFixture=中文标记","diagnosticFixture=另一标记");
            if(after.endsWith("\n"))after=after.substring(0,after.length()-1);
            JSONObject value=evidence(failure(before,after,OWN));exactPair(value,before,after);
            yes(!after.endsWith("\n"));
        });
        test("raw pair exact fixed byte cap is included",()->{
            String after=replace(raw,"mRecentsUid=1000","mRecentsUid=1001");
            String a=pad(raw,0),b=pad(after,0);int room=32768-bytes(a).length-bytes(b).length;
            a=pad(raw,room/2);b=pad(after,room-room/2);
            yes(bytes(a).length+bytes(b).length==32768);exactPair(evidence(failure(a,b,OWN)),a,b);
        });
        test("raw pair one byte beyond cap is explicitly omitted",()->{
            String after=replace(raw,"mRecentsUid=1000","mRecentsUid=1001");
            int room=32769-bytes(pad(raw,0)).length-bytes(pad(after,0)).length;
            String a=pad(raw,room/2),b=pad(after,room-room/2);JSONObject value=evidence(failure(a,b,OWN));
            yes(bytes(a).length+bytes(b).length==32769&&!value.getBoolean("raw_pair_complete")&&!value.has("raw_pair"));
            yes(value.getString("raw_pair_omission_reason").equals("raw_pair_byte_bound"));
            yes(value.getJSONObject("baseline").getString("sha256").equals(hash(bytes(a)))&&value.getJSONObject("current").getInt("bytes")==bytes(b).length);
        });
        test("UTF8 byte bound is not a character bound",()->{
            String pad=String.join("",Collections.nCopies(12000,"界"));
            String a=entropy(raw,pad);
            String b=replace(a,"mRecentsUid=1000","mRecentsUid=1001");
            JSONObject value=evidence(failure(a,b,OWN));yes(!value.getBoolean("raw_pair_complete")&&!value.has("raw_pair"));
        });
        test("null current retains original refusal and no invented raw",()->{
            JSONObject value=evidence(failure(raw,null,OWN));yes(!value.getBoolean("raw_pair_complete")&&value.isNull("current")&&!value.has("raw_pair"));
        });
        test("unrelated errors do not emit a diagnostic",()->{
            yes(PublicPersonalNotesRetirement.historyDiagnostic(new IllegalStateException(CODE))==null);
            yes(PublicPersonalNotesRetirement.historyDiagnostic(new RuntimeException(CODE))==null);
        });
        test("typed cause cannot be used under a different error",()->{
            Throwable t=failure(raw,replace(raw,"mRecentsUid=1000","mRecentsUid=1001"),OWN);
            yes(PublicPersonalNotesRetirement.historyDiagnostic(new IllegalStateException("DIFFERENT",t.getCause()))==null);
            yes(PublicPersonalNotesRetirement.historyDiagnostic(new RuntimeException(CODE,t.getCause()))==null);
        });
        test("actual broker formatter preserves terminal fields and bounded repeated output",()->{
            String after=replace(raw,"mRecentsUid=1000","mRecentsUid=1001");
            Throwable t=failure(raw,after,OWN);JSONObject value=emit(t);exactPair(value,raw,after);
            Files.write(output.resolve("broker-record.json"),bytes(value.toString()));
        });
        test("broker diagnostic bound omits pair without changing originals",()->{
            Throwable t=failure(raw,replace(raw,"mRecentsUid=1000","mRecentsUid=1001"),OWN);
            JSONObject original=new JSONObject().put("schema","hepta.background-broker-terminal.v1").put("state","CLEANUP_UNKNOWN");
            JSONObject probe=new JSONObject(original.toString());
            NotesHistoryBrokerOutputHost.appendNotesHistoryDiagnostic(probe,t,"t","g","s",7);
            int taskBytes=4609-bytes(probe.getJSONObject("personal_notes_history_diagnostic").toString()).length+1;
            String longTask=String.join("",Collections.nCopies(taskBytes,"x"));
            JSONObject terminal=new JSONObject(original.toString());
            NotesHistoryBrokerOutputHost.appendNotesHistoryDiagnostic(terminal,t,longTask,"g","s",7);
            JSONObject value=terminal.getJSONObject("personal_notes_history_diagnostic");
            yes(bytes(value.toString()).length<=4608&&bytes(terminal.toString()).length<=32767);
            yes(!value.getBoolean("raw_pair_complete")&&!value.has("raw_pair")&&value.getString("raw_pair_omission_reason").equals("serialized_diagnostic_bound"));
            terminal=new JSONObject(original.toString());
            NotesHistoryBrokerOutputHost.appendNotesHistoryDiagnostic(terminal,t,String.join("",Collections.nCopies(6000,"x")),"g","s",7);
            yes(terminal.similar(original));
        });
        test("whole-terminal bound leaves original fields and limits intact",()->{
            Throwable t=failure(raw,replace(raw,"mRecentsUid=1000","mRecentsUid=1001"),OWN);
            JSONObject original=new JSONObject().put("schema","hepta.background-broker-terminal.v1")
                    .put("state","CLEANUP_UNKNOWN").put("fixture_padding","");
            JSONObject probe=new JSONObject(original.toString());
            NotesHistoryBrokerOutputHost.appendNotesHistoryDiagnostic(probe,t,"t","g","s",7);
            original.put("fixture_padding",String.join("",Collections.nCopies(32768-bytes(probe.toString()).length,"x")));
            JSONObject terminal=new JSONObject(original.toString());
            NotesHistoryBrokerOutputHost.appendNotesHistoryDiagnostic(terminal,t,"t","g","s",7);
            yes(bytes(terminal.toString()).length<=32767);
            yes(!terminal.getJSONObject("personal_notes_history_diagnostic").getBoolean("raw_pair_complete")
                    &&terminal.getJSONObject("personal_notes_history_diagnostic").getString("raw_pair_omission_reason").equals("serialized_terminal_bound"));
            JSONObject stripped=new JSONObject(terminal.toString());
            stripped.remove("personal_notes_history_diagnostic");yes(stripped.similar(original));
            original.put("fixture_padding",String.join("",Collections.nCopies(33000,"x")));
            terminal=new JSONObject(original.toString());
            NotesHistoryBrokerOutputHost.appendNotesHistoryDiagnostic(terminal,t,"t","g","s",7);
            yes(terminal.similar(original));
        });
        test("actual coordinator pre-effect refusal does not dispatch",()->{
            NotesTokenRetirementHostTest.World w=protectedWorld();
            w.beforeEffect=x->x.recent.put(500,x.row(500,9,11001,"com.example.changed/com.example.changed.Main"));
            try{w.run();throw new AssertionError("foreign change accepted");}catch(IllegalStateException e){
                yes(e.getClass()==IllegalStateException.class&&CODE.equals(e.getMessage())&&w.calls==0&&!w.custody.known());
                JSONObject value=evidence(e);yes(value.getJSONObject("baseline").getLong("sample_begin_elapsed_ms")>=10000);
                yes(value.getJSONObject("current").getLong("sample_end_elapsed_ms")>value.getJSONObject("baseline").getLong("sample_end_elapsed_ms"));
            }
        });
        test("actual post-returned refusal retains single attempted effect",()->{
            NotesTokenRetirementHostTest.World w=protectedWorld();
            w.afterEffect=x->x.recent.put(500,x.row(500,9,11001,"com.example.changed/com.example.changed.Main"));
            try{w.run();throw new AssertionError("post-effect foreign change accepted");}catch(IllegalStateException e){
                yes(e.getClass()==IllegalStateException.class&&CODE.equals(e.getMessage())&&w.calls==1&&w.effects.equals(Arrays.asList(300))&&!w.custody.known());
                JSONObject value=evidence(e);yes(value.getJSONObject("current").getLong("sample_end_elapsed_ms")>value.getJSONObject("baseline").getLong("sample_end_elapsed_ms"));
                yes(value.getJSONArray("owned_task_ids_excluded").toString().equals("[300,301]"));
                Files.write(output.resolve("post-returned-pair.json"),bytes(value.toString()));
            }
        });
        if(args.length>1){
            yes(args.length==6);String before=new String(Files.readAllBytes(Paths.get(args[1])),StandardCharsets.UTF_8);
            for(int i=2;i<5;i++){
                String after=new String(Files.readAllBytes(Paths.get(args[i])),StandardCharsets.UTF_8);
                Set<Integer> ids=new LinkedHashSet<Integer>(Arrays.asList(2004,2005,2006));
                Object a=plainConstructor.newInstance(before),b=plainConstructor.newInstance(after);
                String left=(String)foreign.invoke(a,ids,NotesTokenRetirementHostTest.UID),right=(String)foreign.invoke(b,ids,NotesTokenRetirementHostTest.UID);
                JSONObject value=new JSONObject().put("baseline_path",args[1]).put("current_path",args[i])
                        .put("baseline_bytes",bytes(before).length).put("baseline_sha256",hash(bytes(before)))
                        .put("current_bytes",bytes(after).length).put("current_sha256",hash(bytes(after)))
                        .put("excluded_ids",new ArrayList<Integer>(ids)).put("foreign_projection_equal",left.equals(right))
                        .put("baseline_foreign_sha256",hash(bytes(left))).put("current_foreign_sha256",hash(bytes(right)))
                        .put("exact_failure_pair",false).put("cleanup_qualification",false).put("causal_attribution_to_original_failure",false);
                if(!left.equals(right)){
                    try{same.invoke(a,b,ids,NotesTokenRetirementHostTest.UID,2L);throw new AssertionError("unequal accepted");}catch(InvocationTargetException e){
                        JSONObject detail=evidence(e.getCause());exactPair(detail,before,after);value.put("diagnostic",detail);
                    }
                }
                actual.add(value);
            }
        }
        JSONObject transport=args.length==6?consumerFixtures(new String(Files.readAllBytes(Paths.get(args[1])),StandardCharsets.UTF_8),new String(Files.readAllBytes(Paths.get(args[2])),StandardCharsets.UTF_8),Paths.get(args[5])):null;
        JSONObject result=new JSONObject().put("schema","hepta.notes-history-diagnostic-cases.v1").put("all_pass",true)
                .put("case_count",names.size()).put("assertions",checks).put("case_names",names)
                .put("nearest_actual_comparisons",actual).put("consumer_transport_fixtures",transport==null?JSONObject.NULL:transport).put("phone_operations",0)
                .put("host_clock_and_binder_ports_only",true).put("original_failure_cause_proved",false)
                .put("diagnostics_change_cleanup_admission",false).put("physical_coexistence_policy_used",true);
        System.out.println(result);
    }
}
