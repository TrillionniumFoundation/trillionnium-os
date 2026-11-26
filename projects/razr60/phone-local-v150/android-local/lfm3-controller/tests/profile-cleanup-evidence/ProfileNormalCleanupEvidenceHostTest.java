package org.trillionnium.hepta.local;

import android.net.LocalSocket;
import android.os.SystemClock;
import android.view.Display;
import java.io.*;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.function.BooleanSupplier;
import org.json.*;
import org.trillionnium.hepta.background.*;

/** Host-only replay of the frozen d4 producer reply plus the actual pure-value
 * producer method. Android, clock, display and socket boundaries remain fixtures. */
public final class ProfileNormalCleanupEvidenceHostTest {
    private static final List<String> names=new ArrayList<String>();
    private static int assertions;
    private static JSONObject archivedCleanup,archivedTerminal,archivedResult;
    private static final String GENERATION="a17672ea-79fb-46d8-bfc3-e11f3a8ff712";
    interface Check {void run()throws Exception;}
    interface Change {void apply(JSONObject value)throws Exception;}
    static void need(boolean value){assertions++;if(!value)throw new AssertionError("normal cleanup diagnostic contract failed");}
    static void test(String name,Check check)throws Exception{
        LocalSocket.reset();SystemClock.now=1000000;android.provider.Settings.Global.boot=10;
        android.system.Os.failUnlink=false;check.run();names.add(name);
    }
    static void rejected(Check check)throws Exception{
        try{check.run();}catch(IOException refused){assertions++;return;}
        throw new AssertionError("invalid cleanup evidence was accepted");
    }
    static JSONObject copy(JSONObject value)throws Exception{return new JSONObject(value.toString());}
    static JSONObject response()throws Exception{return copy(archivedCleanup.getJSONObject("last_broker_response"));}
    static JSONObject proof(JSONObject response)throws Exception{return response.getJSONObject("profile_cleanup");}
    static JSONObject phase(JSONObject response)throws Exception{return proof(response).getJSONObject("normal_cleanup_phase");}
    static JSONObject checked(JSONObject response)throws Exception{
        PublicOwnGroupPolicy.Scope scope=PublicOwnGroupPolicy.Scope.fromWire(archivedCleanup.getString("public_own_group_scope_wire"));
        ProfileTarget target=ProfileTarget.fromWire(archivedCleanup.getString("profile_target_wire"));
        SystemClock.now=proof(response).getJSONObject("public_foreign_recent_history").getLong("current_elapsed_ms")+100;
        return PublicProfileCleanupHostTest.checked(response,target,scope,scope.generation,717,true);
    }
    static void mutation(String name,Change change)throws Exception{
        test(name,()->{JSONObject response=response();change.apply(response);rejected(()->checked(response));});
    }
    static String sha(byte[] data)throws Exception{
        StringBuilder out=new StringBuilder();for(byte b:MessageDigest.getInstance("SHA-256").digest(data))
            out.append(String.format(Locale.ROOT,"%02x",b&255));return out.toString();
    }
    static JSONObject original(Path root,String leaf,String hash)throws Exception{
        byte[] data=Files.readAllBytes(root.resolve(leaf));need(hash.equals(sha(data)));
        return new JSONObject(new String(data,StandardCharsets.UTF_8));
    }
    static Set<String> keys(JSONObject object){
        Set<String> out=new TreeSet<String>();Iterator<String> keys=object.keys();
        while(keys.hasNext())out.add(keys.next());return out;
    }
    static JSONObject actualProducerPhase()throws Exception{
        Class<?> type=Class.forName("org.trillionnium.hepta.background.ProfileOwnedTask$CleanupPhase");
        Constructor<?> ctor=type.getDeclaredConstructor(ProfileOwnedTask.class,long.class,long.class,BooleanSupplier.class);
        ctor.setAccessible(true);
        // This constructor and evidence method only fill pure values. No owner,
        // Binder, cleanup method or SDK authority is supplied or invoked.
        Object phase=ctor.newInstance(null,1000000L,1003500L,(BooleanSupplier)()->true);
        Method evidence=type.getDeclaredMethod("evidence");evidence.setAccessible(true);
        return new JSONObject((Map<?,?>)evidence.invoke(phase));
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=2)throw new IllegalArgumentException("output and frozen actual raw directory required");
        Path actual=Paths.get(args[1]);
        archivedCleanup=original(actual,"background-cleanup.json","6b8636896ba63c1e17f4e022ccb38cb78fb4f0a24e0e1ba8fb3c7d2ee665f76a");
        archivedTerminal=original(actual,"background-broker-"+GENERATION+".bin","698c1c174bd99e56ef89483c07e62d2132db56beca1d39de9e433cea7013bb10");
        archivedResult=original(actual,"result.json","e6f4a1043df290b1064e59f98511113f9607e3bae768ff04d24f2ec0d16161c9");
        test("actual_d4_terminal_projection_accepts_known_diagnostic_without_rewriting_failure",()->{
            JSONObject response=response(),before=copy(response),accepted=checked(response);
            need("RELEASED".equals(response.getString("state")));
            need(!response.getBoolean("profile_current_identity_verified")&&!response.getBoolean("profile_custody_retained"));
            need(accepted.getBoolean("cleanup_known")&&accepted.has("normal_cleanup_phase"));
            need(proof(response).toString().equals(archivedTerminal.getJSONObject("profile_cleanup").toString()));
            need(response.toString().equals(before.toString()));
            need(archivedTerminal.getBoolean("release_confirmed"));
            need(!archivedCleanup.getBoolean("cleanup_known")&&"profile evidence fields differ".equals(archivedCleanup.getString("cleanup_error")));
            need(!archivedResult.getBoolean("completion_verified")&&!archivedResult.getBoolean("model_reported_success"));
            need(phase(response).getLong("display_effect_entered_elapsed_ms")==-1&&phase(response).getLong("display_effect_returned_elapsed_ms")==-1);
        });
        test("same_complete_terminal_authority_without_optional_diagnostic_remains_valid",()->{
            JSONObject response=response();proof(response).remove("normal_cleanup_phase");
            need(checked(response).length()==15);
        });
        test("actual_producer_evidence_method_shape_is_consumed_without_effect_authority",()->{
            JSONObject diagnostic=actualProducerPhase();
            need(keys(diagnostic).equals(keys(phase(response()))));
            need(!diagnostic.getBoolean("read_convergence_activated")&&!diagnostic.getBoolean("business_admission_restored"));
            need(diagnostic.getLong("leaf_effect_entered_elapsed_ms")==-1&&!diagnostic.getBoolean("serialized_evidence_is_authority"));
            try(PublicProfileCleanupHostTest.Env e=new PublicProfileCleanupHostTest.Env()){
                JSONObject response=e.response();proof(response).put("normal_cleanup_phase",diagnostic);
                need(e.checked(response).getJSONObject("normal_cleanup_phase").toString().equals(diagnostic.toString()));
            }
        });
        test("diagnostic_failed_or_not_activated_never_substitutes_terminal_authority",()->{
            JSONObject response=response();phase(response).put("failed",true).put("read_convergence_activated",false);
            need(checked(response).getBoolean("cleanup_known"));
            proof(response).put("cleanup_known",false);rejected(()->checked(response));
        });
        mutation("diagnostic_cannot_replace_live_absence",r->proof(r).put("live_tasks_absent",false));
        mutation("diagnostic_cannot_replace_recents_absence",r->proof(r).put("recents_tasks_absent",false));
        mutation("diagnostic_cannot_override_scope_binding",r->r.put("display_scope_sha256",String.join("",Collections.nCopies(64,"0"))));
        mutation("diagnostic_cannot_override_foreign_history",r->proof(r).getJSONObject("public_foreign_recent_history").put("nonphysical_history_preserved",false));
        mutation("unknown_top_level_cleanup_field_is_still_rejected",r->proof(r).put("future_cleanup_permission",true));
        mutation("unknown_diagnostic_field_is_rejected",r->phase(r).put("new_authority",false));
        mutation("wrong_diagnostic_schema_is_rejected",r->phase(r).put("schema","hepta.profile-normal-cleanup-phase.v2"));
        mutation("coerced_diagnostic_boolean_is_rejected",r->phase(r).put("read_convergence_activated","true"));
        mutation("diagnostic_cannot_restore_business_admission",r->phase(r).put("business_admission_restored",true));
        mutation("diagnostic_cannot_claim_serialized_authority",r->phase(r).put("serialized_evidence_is_authority",true));
        mutation("wrong_census_age_constant_is_rejected",r->phase(r).put("maximum_census_to_effect_age_ms",1501));
        mutation("coerced_diagnostic_clock_is_rejected",r->phase(r).put("leaf_effect_entered_elapsed_ms","1054087245"));
        mutation("fractional_diagnostic_clock_is_rejected",r->phase(r).put("leaf_effect_entered_elapsed_ms",1054087245.5));
        mutation("invalid_negative_diagnostic_clock_is_rejected",r->phase(r).put("display_effect_entered_elapsed_ms",-2));
        mutation("nonpositive_diagnostic_deadline_is_rejected",r->phase(r).put("original_task_reads_deadline_elapsed_ms",0));
        test("known_diagnostic_cannot_enter_private_thirteen_field_contract",()->{
            try(PublicProfileCleanupHostTest.Env e=new PublicProfileCleanupHostTest.Env()){
                JSONObject response=e.response();proof(response).remove("public_foreign_recent_history");proof(response).remove("recents_absence_scope");
                proof(response).put("normal_cleanup_phase",actualProducerPhase());
                rejected(()->PublicProfileCleanupHostTest.checked(response,e.target,null,e.session.generation,7,true));
            }
        });
        test("full_close_consumes_known_diagnostic_and_released_identity_false",()->{
            try(PublicProfileCleanupHostTest.Env e=new PublicProfileCleanupHostTest.Env()){
                e.live();LocalSocket.responder=b->e.closeResponse(b,r->{
                    proof(r).put("normal_cleanup_phase",actualProducerPhase());r.put("profile_current_identity_verified",false);
                });
                BackgroundSession.Cleanup result=e.session.close();
                need(result.known&&e.session.released()&&!e.journalPresent()&&LocalSocket.connections==1);
                need(result.evidence.getJSONObject("profile_cleanup").has("normal_cleanup_phase"));
            }
        });
        test("known_diagnostic_never_replaces_independent_display_absence",()->{
            final int originalConnections;
            try(PublicProfileCleanupHostTest.Env e=new PublicProfileCleanupHostTest.Env()){
                e.terminal(e.response(),true);e.context.displays.displays.put(7,new Display(7,e.session.displayName));
                need(!e.session.close().known&&e.journalPresent()&&!e.session.released());
                originalConnections=LocalSocket.connections;need(originalConnections==1);
            }
            LocalSocket.reset();SystemClock.now=1000000;
            try(PublicProfileCleanupHostTest.Env e=new PublicProfileCleanupHostTest.Env()){
                JSONObject response=e.response();proof(response).put("normal_cleanup_phase",actualProducerPhase());
                e.terminal(response,true);e.context.displays.displays.put(7,new Display(7,e.session.displayName));
                need(!e.session.close().known&&e.journalPresent()&&!e.session.released()&&LocalSocket.connections==originalConnections);
            }
        });
        JSONObject report=new JSONObject().put("schema","hepta.profile-normal-cleanup-evidence-host-tests.v1")
            .put("all_pass",true).put("cases",names.size()).put("assertions",assertions).put("case_names",new JSONArray(names))
            .put("actual_full_background_session",true).put("actual_producer_evidence_method_executed",true)
            .put("actual_d4_archived_producer_projection_replayed",true).put("archived_business_failure_preserved",true)
            .put("android_clock_display_root_transport_are_fakes",true).put("producer_constructor_uses_no_live_owner",true)
            .put("fresh_device_absence_or_recovery_claimed",false).put("phone_actions",0);
        Files.write(Paths.get(args[0]),(report.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println(report.toString());
    }
}
