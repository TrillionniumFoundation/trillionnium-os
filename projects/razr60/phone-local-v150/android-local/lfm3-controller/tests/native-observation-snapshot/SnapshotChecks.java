package org.trillionnium.hepta.local;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import org.json.JSONObject;
/** Host-only accounting; no device authority or native execution. */
final class SnapshotChecks {
    interface Case {void run()throws Exception;}
    static final String TASK="11111111111111111111111111111111",APP="com.xiaomi.shop";
    static final String OWNER=repeat('a',64),GENERATION="11111111-2222-3333-4444-555555555555";
    static final List<String> names=new ArrayList<String>(),failures=new ArrayList<String>();
    static final Map<String,Integer> caseAssertions=new LinkedHashMap<String,Integer>();
    static int assertions;static String current;
    static String repeat(char c,int n){StringBuilder b=new StringBuilder();for(int i=0;i<n;i++)b.append(c);return b.toString();}
    static void check(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    static void run(String name,Case body)throws Exception{
        if(names.contains(name))throw new AssertionError("duplicate case "+name);
        names.add(name);current=name;int start=assertions;
        try{body.run();}catch(Exception|AssertionError error){failures.add(name+": "+error);throw error;}
        finally{caseAssertions.put(name,assertions-start);current=null;}
    }
    static void finish(String output)throws Exception{
        JSONObject value=new JSONObject().put("schema","hepta.native-observation-snapshot-cases.v1")
            .put("all_pass",failures.isEmpty()).put("cases",names.size()).put("assertions",assertions)
            .put("case_names",names).put("case_assertions",caseAssertions).put("failures",failures)
            .put("phone_execution",false).put("android_execution",false).put("sdk_loaded",false)
            .put("business_completion_verified",false).put("action_freshness_relaxed",false).put("deadline_expanded",false);
        Files.write(Paths.get(output),value.toString(2).getBytes(StandardCharsets.UTF_8));System.out.println(value.toString());
    }
}
