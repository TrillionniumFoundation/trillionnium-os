package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONObject;

/** Host assertions only; these values never become App/lease authority. */
final class DiagnosticChecks {
    interface Case { void run() throws Exception; }
    static final String TASK="11111111111111111111111111111111";
    static final String REQUEST="22222222222222222222222222222222";
    static final String OWNER=repeat('a',64), APP="com.xiaomi.shop", GENERATION="11111111-2222-3333-4444-555555555555";
    static final List<String> names=new ArrayList<String>();
    static int checks;
    static String repeat(char c,int n){StringBuilder s=new StringBuilder();for(int i=0;i<n;i++)s.append(c);return s.toString();}
    static void check(boolean ok,String why){checks++;if(!ok)throw new AssertionError(why);}
    static void run(String name,Case body)throws Exception{check(!names.contains(name),"duplicate case name");body.run();names.add(name);}
    static void finish(String path)throws Exception{
        JSONObject out=new JSONObject().put("schema","hepta.observation-diagnostics-host.v1").put("all_pass",true)
                .put("cases",names.size()).put("assertions",checks).put("case_names",names)
                .put("android_execution",false).put("phone_execution",false).put("business_completion_verified",false);
        Files.write(Paths.get(path),out.toString(2).getBytes(StandardCharsets.UTF_8));System.out.println(out.toString());
    }
}
