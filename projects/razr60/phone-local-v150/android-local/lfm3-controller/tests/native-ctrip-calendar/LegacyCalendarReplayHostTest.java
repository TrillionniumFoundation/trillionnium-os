package org.trillionnium.hepta.local;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.JSONObject;
/** Compiled against the exact retained f842 Page. Only original rejection is asserted. */
final class LegacyCalendarReplayHostTest {
    public static void main(String[] args)throws Exception{
        NativeAppProviderHostTest.fixtures=Paths.get(args[0]);NativeAppProviderHostTest.Harness h=new NativeAppProviderHostTest.Harness("old-calendar-replay");
        NativeCtripFlightPage.Page p=NativeCtripFlightPage.inspect(NativeAppProviderHostTest.goal(),h.frame("main-calendar.xml"));
        if(!NativeCtripFlightPage.UNAVAILABLE.equals(p.phase)||!p.missing.contains("unambiguous actual month headers required"))throw new AssertionError("exact previous parser must reject original duplicate headers: "+p.evidence());
        Map<String,Object> out=NativeAppEvidence.map();out.put("schema","hepta.native-ctrip-calendar-previous-replay.v1");out.put("all_pass",true);out.put("cases",1);out.put("assertions",2);
        out.put("case_names",Collections.singletonList("exact_f842_parser_rejects_actual_sticky_duplicate"));out.put("actual_previous_page",p.evidence());out.put("phone_operations",0);out.put("model_executed",false);out.put("business_verified",false);
        Files.write(Paths.get(args[1]),(new JSONObject(out).toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);System.out.println("previous actual rejection reproduced");
    }
}
