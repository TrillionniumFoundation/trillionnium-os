package org.trillionnium.hepta.local;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONObject;
/** Host checks; never constructs device ownership or grants an effect. */
final class EventChecks {
    interface Case {void run()throws Exception;}
    static final String TASK="11111111111111111111111111111111",APP="com.xiaomi.shop";
    static final String OWNER=repeat('a',64),GENERATION="11111111-2222-3333-4444-555555555555";
    static final List<String> names=new ArrayList<String>();static int assertions;
    static String repeat(char c,int n){StringBuilder s=new StringBuilder();for(int i=0;i<n;i++)s.append(c);return s.toString();}
    static void check(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    static void run(String name,Case body)throws Exception{check(!names.contains(name),"unique case");body.run();names.add(name);}
    static void finish(String output)throws Exception{
        JSONObject value=new JSONObject().put("schema","hepta.native-observation-events-host.v1").put("all_pass",true)
                .put("cases",names.size()).put("assertions",assertions).put("case_names",names)
                .put("android_execution",false).put("phone_execution",false).put("business_completion_verified",false)
                .put("action_guard_changed",true).put("native_action_guard_qualification_claimed",false).put("deadline_expanded",false);
        Files.write(Paths.get(output),value.toString(2).getBytes(StandardCharsets.UTF_8));System.out.println(value.toString());
    }
}
