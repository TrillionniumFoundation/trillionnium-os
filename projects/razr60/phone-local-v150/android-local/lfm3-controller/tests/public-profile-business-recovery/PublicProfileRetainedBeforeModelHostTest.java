package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;
import org.json.JSONObject;

/** The private historical inputs are complete external bytes. Current Android I/O is synthetic. */
final class PublicProfileRetainedBeforeModelHostTest {
    private static int cases;
    interface Check {void run()throws Exception;}
    interface Change {void edit(JSONObject proof)throws Exception;}
    static void rejected(Check check)throws Exception{
        try{check.run();}catch(Exception expected){cases++;return;}
        throw new AssertionError("invalid retained-custody recovery accepted");
    }
    static void proofReject(PublicProfileBusinessAbsenceRecovery.Request r,Change change)throws Exception{
        JSONObject p=PublicProfileBusinessRecoveryHostTest.syntheticProof(r);change.edit(p);
        rejected(()->PublicProfileBusinessAbsenceRecovery.validate(p,r,r.started+31,r.requestBoot));
    }
    public static void main(String[] args)throws Exception{
        JSONObject m=PublicProfileBusinessAbsenceRecovery.object(Files.readAllBytes(Paths.get(args[0])));
        Map<String,byte[]> files=PublicProfileBusinessRecoveryHostTest.loadExternalOriginals(Paths.get(args[1]));
        PublicProfileBusinessRecoveryHostTest.Fixture f=new PublicProfileBusinessRecoveryHostTest.Fixture(m,files);
        PublicProfileBusinessAbsenceRecovery.Request r=f.request();
        if(!r.retainedBeforeFirstModel||r.steps!=0||r.modelRequests!=0||!f.archived().request().retainedBeforeFirstModel)
            throw new AssertionError("initial and archived no-model origins required");cases+=2;
        JSONObject proof=PublicProfileBusinessRecoveryHostTest.syntheticProof(r);
        PublicProfileBusinessAbsenceRecovery.validate(proof,r,r.started+31,r.requestBoot);cases++;
        for(String field:new String[]{"historical_model_exit_verified","historical_broker_release_observed","acknowledges_control_session","broker_release_response","rewrites_business_outcome"})
            proofReject(r,p->p.put(field,true));
        proofReject(r,p->p.put("current_boot_count",r.requestBoot+1));
        proofReject(r,p->p.getJSONObject("after").put("firmware_fingerprint_sha256",ProfileIdentity.sha("another test firmware")));
        proofReject(r,p->p.getJSONObject("before").getJSONObject("process").put("old_creator_absent",false));
        proofReject(r,p->p.getJSONObject("after").getJSONObject("live").getJSONArray("all_task_ids").put(r.ownedRootTaskId));
        proofReject(r,p->p.getJSONObject("before").getJSONObject("displays").put("exact_name_absent",false));
        proofReject(r,p->p.getJSONObject("after").getJSONObject("physical").put("0",ProfileIdentity.sha("changed")));
        proofReject(r,p->p.put("originals_sha256",ProfileIdentity.sha("different bytes")));
        proofReject(r,p->p.getJSONObject("recorded_owned_identity").put("leaf_task_token","foreign"));
        String capture=f.taskPrefix+"background-broker-"+r.generation+".bin";
        PublicProfileBusinessRecoveryHostTest.Fixture truncated=f.copy();byte[] bytes=truncated.files.get(capture);
        truncated.put(capture,java.util.Arrays.copyOf(bytes,bytes.length/2));rejected(truncated::request);
        PublicProfileBusinessRecoveryHostTest.Fixture extra=f.copy();extra.put(extra.modelPrefix+"native-session-result.json","{}".getBytes(StandardCharsets.UTF_8));rejected(extra::request);
        PublicProfileBusinessRecoveryHostTest.Fixture action=f.copy();action.put(action.taskPrefix+"step-01-model-01.json","{}".getBytes(StandardCharsets.UTF_8));rejected(action::request);
        PublicProfileBusinessRecoveryHostTest.Fixture worker=f.copy();worker.edit(worker.sessionPath,j->j.put("process_started",true));rejected(worker::request);
        PublicProfileBusinessRecoveryHostTest.Fixture retired=f.copy();retired.edit(retired.taskPrefix+"native-app-retired.json",j->j.put("pending_action",true));rejected(retired::request);
        System.out.println(new JSONObject().put("passed",true).put("cases",cases).put("historical_inputs",files.size())
                .put("business_steps",r.steps).put("model_requests",r.modelRequests).put("actual_phone_current_absence_verified",false));
    }
}
