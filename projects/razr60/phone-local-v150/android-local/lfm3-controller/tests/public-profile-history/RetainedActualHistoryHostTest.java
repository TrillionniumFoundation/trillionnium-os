package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.json.JSONArray;
import org.json.JSONObject;

/** Replay real old owner/protected histories. A Java host never holds the former Android Binder token. */
public final class RetainedActualHistoryHostTest {
    public static void main(String[] args)throws Exception{
        if(args.length!=1)throw new IllegalArgumentException("four captured framework inventories required");
        JSONObject capture=new JSONObject(read(Paths.get(args[0])));
        ProfileTarget target=ProfileTarget.fromWire(capture.getString("profile_target_wire"));
        if(!capture.getBoolean("original_from_phone")||!capture.getBoolean("all_four_framework_dumps_bound")
                ||target.fullUid!=1010485||target.profile.userId!=10||!"com.xiaomi.shop".equals(target.packageName)
                ||capture.getInt("owned_root_id")!=1854||capture.getInt("owned_leaf_id")!=1000068||capture.getInt("owned_display_id")!=526)
            throw new AssertionError("4bd1 ownership or poststate mismatch");
        JSONArray paths=capture.getJSONArray("recents_paths"),times=capture.getJSONArray("times_ms");
        if(paths.length()!=4||times.length()!=4)throw new AssertionError("missing a scope sample");
        PublicProfileRecentHistory.Snapshot first=null;
        for(int i=0;i<4;i++){
            PublicProfileRecentHistory.Snapshot current=PublicProfileRecentHistory.absence(read(Paths.get(paths.getString(i))),target);
            if(i==0)first=current;else{
                if(times.getLong(i)<=times.getLong(i-1))throw new AssertionError("nonmonotonic captures");
                first.requireSame(current,(times.getLong(i)-times.getLong(0))/1000+2);
            }
        }
        System.out.println(new JSONObject().put("all_pass",true).put("real_framework_samples",4).put("original_retained_custody",true)
                .put("fresh_binder_tokens_on_host",false).put("original_records_preserved",true).put("phone_operations",0));
    }
    private static String read(Path p)throws Exception{return new String(Files.readAllBytes(p),StandardCharsets.UTF_8);}
}
