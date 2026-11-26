package org.trillionnium.hepta.background;
import org.json.JSONObject;
/** Executes the old complete coordinator, not a copied retirement algorithm. */
public final class ProfileCleanupSettleOldTimingHostTest {
    public static void main(String[] args)throws Exception{
        ProfileCleanupSettleFixtures.load(args[0]);
        ProfileCleanupSettleFixtures.Platform f=new ProfileCleanupSettleFixtures.Platform();
        ProfileOwnedTask p=f.active(true);String refusal=null;
        try{p.retire(f.originalDeadline);}catch(Exception e){refusal=e.getMessage();}
        boolean ok="PROFILE_LEAF_RETIRE_NOT_CONFIRMED".equals(refusal)&&f.removeCalls==1&&f.deleteCalls==0
            &&!p.cleanupKnown()&&f.f.now-f.started==1408;
        System.out.println(new JSONObject().put("expected_red",ok).put("refusal",refusal)
            .put("elapsed_ms",f.f.now-f.started).put("original_deadline_ms",1400)
            .put("latest_history_offset_ms",1383).put("leaf_effect_calls",f.removeCalls).put("root_effect_calls",f.deleteCalls)
            .put("synthetic_mixed_snapshot_projection",true).put("actual_277_per_read_timing_available",false)
            .put("phone_operations",0).put("events",f.events));
        System.exit(ok?3:1);
    }
}
