package org.trillionnium.hepta.local;

import java.lang.reflect.*;
import org.json.JSONObject;
import org.trillionnium.hepta.background.ForegroundConcurrencyHostTest;
import org.trillionnium.hepta.background.PublicOwnGroupPolicy;

/** Actual producer JSON round-trip through the full App terminal validator.
 * Android transport and current system services remain explicit host ports. */
public final class ForegroundConcurrencySessionHostTest {
    static int cases,checks;
    interface Work{void run()throws Exception;}
    static void yes(boolean v){checks++;if(!v)throw new AssertionError("concurrent receipt contract");}
    static void test(String name,Work w)throws Exception{android.net.LocalSocket.reset();android.os.SystemClock.now=1000000;android.provider.Settings.Global.boot=10;
        w.run();cases++;System.out.println("PASS "+name);}
    static void no(Work w)throws Exception{try{w.run();}catch(Exception expected){checks++;return;}throw new AssertionError("unbound concurrency receipt accepted");}
    static JSONObject profile(PublicProfileCleanupHostTest.Env e)throws Exception{
        JSONObject response=e.response(),proof=response.getJSONObject("profile_cleanup");
        proof.put("public_foreign_recent_history",ForegroundConcurrencyHostTest.profileEvidence(e.target,e.scope.createdElapsedMs+1,e.scope.createdElapsedMs+2,1200,1234));
        proof.put("recents_absence_scope","owned_target_only_with_unrelated_physical_history_audited");return response;
    }
    static JSONObject notes(PersonalNotesSessionHostTest.Env e)throws Exception{
        return new JSONObject().put("ok",true).put("state","RELEASED").put("display_scope_sha256",e.scope.sha256)
                .put("personal_notes_cleanup",ForegroundConcurrencyHostTest.notesEvidence(e.session.generation,e.scope.sha256));
    }
    static JSONObject checked(PersonalNotesSessionHostTest.Env e,JSONObject response)throws Exception{
        Method m=BackgroundSession.class.getDeclaredMethod("checkedPersonalNotesCleanup",JSONObject.class,PublicOwnGroupPolicy.Scope.class,String.class,int.class);
        m.setAccessible(true);return (JSONObject)m.invoke(null,response,e.scope,e.session.generation,7);
    }
    public static void main(String[] args)throws Exception{
        test("actual profile v2 producer accepted with complete owned absence and audited user activity",()->{try(PublicProfileCleanupHostTest.Env e=new PublicProfileCleanupHostTest.Env()){
            JSONObject result=e.checked(profile(e));yes(result.getBoolean("cleanup_known"));yes(result.getJSONObject("public_foreign_recent_history").getBoolean("unrelated_physical_history_changes_observed"));}});
        for(final String mutation:new String[]{"scope","frozen","protected-digest","owned","missing","unknown"})
            test("profile v2 refuses "+mutation,()->{try(PublicProfileCleanupHostTest.Env e=new PublicProfileCleanupHostTest.Env()){
                JSONObject response=profile(e),proof=response.getJSONObject("profile_cleanup"),h=proof.getJSONObject("public_foreign_recent_history");
                if("scope".equals(mutation))proof.put("recents_absence_scope","owned_target_only_with_foreign_history_preserved");
                else if("frozen".equals(mutation))h.put("physical_history_frozen",true);
                else if("protected-digest".equals(mutation))h.put("current_protected_history_sha256",String.join("",java.util.Collections.nCopies(64,"0")));
                else if("owned".equals(mutation))h.getJSONArray("owned_task_ids").put(999);
                else if("missing".equals(mutation))h.remove("history_preservation_scope");
                else proof.put("cleanup_known",false);
                no(()->e.checked(response));}});
        test("legacy profile v1 remains accepted by its original complete-history scope",()->{try(PublicProfileCleanupHostTest.Env e=new PublicProfileCleanupHostTest.Env()){yes(e.checked(e.response()).getBoolean("cleanup_known"));}});
        test("actual Notes v2 producer accepted despite resolved unrelated hidden changes",()->{try(PersonalNotesSessionHostTest.Env e=new PersonalNotesSessionHostTest.Env()){
            JSONObject value=checked(e,notes(e));yes(value.getBoolean("cleanup_known"));yes(!value.getBoolean("prior_hidden_history_preserved")&&value.getBoolean("nonphysical_hidden_history_preserved"));}});
        for(final String mutation:new String[]{"scope","frozen","protected","unknown","absence","old-schema"})
            test("Notes v2 refuses "+mutation,()->{try(PersonalNotesSessionHostTest.Env e=new PersonalNotesSessionHostTest.Env()){
                JSONObject response=notes(e),proof=response.getJSONObject("personal_notes_cleanup");
                if("scope".equals(mutation))proof.put("history_preservation_scope","all_foreign_records_ignored");
                else if("frozen".equals(mutation))proof.put("physical_history_frozen",true);
                else if("protected".equals(mutation))proof.put("nonphysical_history_preserved",false);
                else if("unknown".equals(mutation))proof.put("cleanup_known",false);
                else if("absence".equals(mutation))proof.put("absence_reads",1);
                else proof.put("schema","hepta.public-personal-notes-cleanup.v1");
                no(()->checked(e,response));}});
        test("failed Notes operation retains false business outcome while complete RELEASED custody is accepted",()->{try(PersonalNotesSessionHostTest.Env e=new PersonalNotesSessionHostTest.Env()){
            JSONObject response=notes(e).put("ok",false).put("operation","notes.create").put("error","PUBLIC_SCOPE_RETIRED");
            yes(checked(e,response).getBoolean("cleanup_known"));yes(!response.getBoolean("ok")&&response.getString("operation").equals("notes.create"));}});
        test("full App close consumes already released failed operation without a second socket or release",()->{try(PersonalNotesSessionHostTest.Env e=new PersonalNotesSessionHostTest.Env()){
            JSONObject response=notes(e).put("ok",false).put("operation","notes.create").put("error","PUBLIC_SCOPE_RETIRED");
            PersonalNotesSessionHostTest.field(e.session,"state","RELEASED");PersonalNotesSessionHostTest.field(e.session,"lastResponse",response);
            e.context.displays.displays.remove(7);android.net.LocalSocket.missing=true;
            yes(e.session.close().known&&e.session.released()&&!e.journal());
            yes(android.net.LocalSocket.connections==0&&e.process.destroyed==0&&!response.getBoolean("ok"));
            yes(e.context.displays.getDisplay(0)!=null&&e.context.displays.getDisplay(1)!=null);}});
        for(final String mutation:new String[]{"scope","state","unknown","absence","retained","string-false","string-true","missing-ok"})
            test("failed business still requires complete typed Notes retirement "+mutation,()->{try(PersonalNotesSessionHostTest.Env e=new PersonalNotesSessionHostTest.Env()){
                JSONObject response=notes(e).put("ok",false),proof=response.getJSONObject("personal_notes_cleanup");
                if("scope".equals(mutation))response.put("display_scope_sha256",String.join("",java.util.Collections.nCopies(64,"0")));
                else if("state".equals(mutation))response.put("state","CLEANUP_UNKNOWN");
                else if("unknown".equals(mutation))proof.put("cleanup_known",false);
                else if("absence".equals(mutation))proof.put("absence_reads",1);
                else if("retained".equals(mutation))proof.put("custodian_retained",true);
                else if("string-false".equals(mutation))response.put("ok","false");
                else if("string-true".equals(mutation))response.put("ok","true");
                else response.remove("ok");
                no(()->checked(e,response));}});
        System.out.println(new JSONObject().put("passed",true).put("cases",cases).put("assertions",checks).put("phone_operations",0).put("actual_producer_consumer_roundtrip",true));
    }
}
