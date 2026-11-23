package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.util.*;
import org.json.*;

/** Synthetic old journals are fully re-bound after a deliberate v2 projection.
 * This exercises the real recovery entry and wire decoder, never a device. */
public final class ForegroundConcurrencyRecoveryHostTest {
    static int cases,checks;
    interface Work{void run()throws Exception;}
    static void yes(boolean v){checks++;if(!v)throw new AssertionError("v2 recovery entry contract");}
    static void test(String name,Work w)throws Exception{w.run();cases++;System.out.println("PASS "+name);}
    static void no(Work w)throws Exception{try{w.run();}catch(Exception expected){checks++;return;}throw new AssertionError("invalid v2 historical projection accepted");}
    static JSONObject object(byte[] raw){return new JSONObject(new String(raw,StandardCharsets.UTF_8));}
    static byte[] bytes(JSONObject o){return o.toString().getBytes(StandardCharsets.UTF_8);}
    static void upgrade(Object value,String mutation){
        if(value instanceof JSONArray){JSONArray a=(JSONArray)value;for(int i=0;i<a.length();i++)upgrade(a.get(i),mutation);return;}
        if(!(value instanceof JSONObject))return;JSONObject o=(JSONObject)value;
        if("hepta.public-personal-notes-cleanup.v1".equals(o.optString("schema"))){
            o.put("schema","hepta.public-personal-notes-cleanup.v2").put("history_preservation_scope","nonphysical_and_unresolved_recents")
                .put("history_preservation_interval","pre_release_to_absence").put("hidden_history_preservation_interval","initial_to_absence")
                .put("physical_history_frozen",false).put("unrelated_physical_history_changes_observed",true)
                .put("recents_presentation_changes_observed",false)
                .put("prior_hidden_history_preserved",false).put("nonphysical_history_preserved",false).put("nonphysical_hidden_history_preserved",false);
            if("scope".equals(mutation))o.put("history_preservation_scope","all_foreign_history_ignored");
            if("frozen".equals(mutation))o.put("physical_history_frozen",true);
            if("known".equals(mutation))o.put("nonphysical_history_preserved",true);
            if("interval".equals(mutation))o.remove("history_preservation_interval");
        }
        List<String> keys=new ArrayList<String>();Iterator<String> it=o.keys();while(it.hasNext())keys.add(it.next());
        for(String key:keys)upgrade(o.get(key),mutation);
    }
    static PersonalNotesAbsenceHostTest.Fixture fixture(String mutation)throws Exception{
        PersonalNotesAbsenceHostTest.Fixture f=new PersonalNotesAbsenceHostTest.Fixture();
        JSONObject terminal=object(f.inputs.get("broker_output"));upgrade(terminal,mutation);byte[] output=bytes(terminal);
        JSONObject broker=object(f.inputs.get("broker_receipt")).put("stored_bytes",output.length).put("observed_bytes",output.length).put("stored_sha256",ProfileIdentity.sha(output));
        JSONObject bootstrap=object(f.inputs.get("bootstrap")),cleanup=object(f.inputs.get("cleanup"));
        upgrade(bootstrap,mutation);upgrade(cleanup,mutation);bootstrap.put("broker_output",broker);cleanup.put("broker_output",broker);
        JSONObject result=object(f.inputs.get("result")).put("background_session",bootstrap).put("background_cleanup",cleanup);
        f.inputs.put("broker_output",output);f.inputs.put("broker_receipt",bytes(broker));
        f.inputs.put("bootstrap",bytes(bootstrap));f.inputs.put("cleanup",bytes(cleanup));f.inputs.put("result",bytes(result));return f;
    }
    public static void main(String[] args)throws Exception{
        test("legacy Notes v1 original entry remains valid",()->yes(new PersonalNotesAbsenceHostTest.Fixture().request().targetUid==23456));
        test("unknown v2 original entry and wire roundtrip keep historical failure",()->{
            PublicPersonalNotesAbsenceRecovery.Request r=fixture("").request(),again=PublicPersonalNotesAbsenceRecovery.fromWire(r.wire());
            yes(again.originalsSha256.equals(r.originalsSha256));yes(!object(again.original("result")).getBoolean("cleanup_known"));
            yes(object(again.original("broker_output")).getJSONObject("personal_notes_cleanup").getString("schema").endsWith(".v2"));
        });
        for(final String change:new String[]{"scope","frozen","known","interval"})test("v2 original refuses "+change,()->no(()->fixture(change).request()));
        System.out.println(new JSONObject().put("passed",true).put("cases",cases).put("assertions",checks).put("phone_operations",0).put("synthetic_originals_only",true));
    }
}
