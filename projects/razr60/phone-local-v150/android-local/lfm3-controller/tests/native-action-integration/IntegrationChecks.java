package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;

/** Counters for new integration cases, not the old provider test main. */
final class IntegrationChecks {
    interface Work { void run() throws Exception; }
    private static int assertions;
    private static final List<String> names=new ArrayList<String>();
    private static final List<Integer> caseAssertions=new ArrayList<Integer>();
    static void yes(boolean condition,String message){assertions++;if(!condition)throw new AssertionError(message);}
    static void rejects(Work work,String message)throws Exception{
        assertions++;try{work.run();}catch(IllegalArgumentException|IllegalStateException|ActionDecision.InvalidActionException expected){return;}
        throw new AssertionError(message);
    }
    static void ioRejects(Work work,String message)throws Exception{
        assertions++;try{work.run();}catch(java.io.IOException expected){return;}
        throw new AssertionError(message);
    }
    static void immutable(Work work,String message)throws Exception{
        assertions++;try{work.run();}catch(UnsupportedOperationException expected){return;}
        throw new AssertionError(message);
    }
    static void addHelperAssertions(int count){if(count<0)throw new AssertionError("helper counter regressed");assertions+=count;}
    static int total(){return assertions+NativeAppProviderHostTest.checks+NativeResourceHomeHostTest.checks;}
    static void one(String name,Work work)throws Exception{
        if(names.contains(name))throw new AssertionError("duplicate integration case: "+name);
        int start=total();work.run();names.add(name);caseAssertions.add(Integer.valueOf(total()-start));
    }
    static void finish(Path output,String schema,String boundary)throws Exception{
        JSONObject result=new JSONObject().put("schema",schema).put("all_pass",true)
                .put("cases",names.size()).put("assertions",total()).put("case_names",new JSONArray(names))
                .put("case_assertions",new JSONArray(caseAssertions))
                .put("android_execution",false).put("phone_execution",false).put("model_executed",false)
                .put("business_completion_verified",false).put("platform_dispatch_executed",false)
                .put("boundary",boundary);
        Files.write(output,(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println(result.toString());
    }
    private IntegrationChecks(){}
}
