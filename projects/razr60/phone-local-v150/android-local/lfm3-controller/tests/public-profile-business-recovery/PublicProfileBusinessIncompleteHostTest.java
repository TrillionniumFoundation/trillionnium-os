package org.trillionnium.hepta.background;

import java.nio.file.Files;
import java.nio.file.Paths;
import org.json.JSONObject;
import org.trillionnium.hepta.background.PublicProfileBusinessRecoveryHostTest.Fixture;

/** Full external 5780 source files. Host clocks, Android metadata, and checker samples are explicit ports. */
public final class PublicProfileBusinessIncompleteHostTest {
    private interface Edit { void run(Fixture f)throws Exception; }
    private static int cases;
    private static String terminalPath(Fixture f){return f.taskPrefix+"step-07-controller-terminal.json";}
    private static void reject(Fixture actual,String code,Edit mutation)throws Exception{
        Fixture f=actual.copy();mutation.run(f);
        try{f.request();}catch(Exception e){if(e.getMessage()!=null&&e.getMessage().contains(code)){cases++;return;}throw e;}
        throw new AssertionError("unexpectedly accepted "+code);
    }
    public static void main(String[] args)throws Exception{
        Fixture f=new Fixture(PublicProfileBusinessAbsenceRecovery.object(Files.readAllBytes(Paths.get(args[0]))),
                PublicProfileBusinessRecoveryHostTest.loadExternalOriginals(Paths.get(args[1])));
        if(!f.task.equals("5780cdd59ead4b799ef38025ea9bb176")||!ProfileIdentity.sha(f.files.get(f.resultPath))
                .equals("fe0b85e55c1cbc54757c14024a9cebcae9380ef33c1ea5c1d37adf73a4d09643"))throw new AssertionError("expected original task");
        for(Fixture shape:new Fixture[]{f,f.archived()}){
            PublicProfileBusinessAbsenceRecovery.Request req=shape.request();
            if(req.steps!=7||req.modelRequests!=7||req.retainedBeforeFirstModel||req.displayId!=535||req.target.profile.userId!=10)throw new AssertionError("fixture identity");
            JSONObject proof=PublicProfileBusinessRecoveryHostTest.syntheticProof(req);
            PublicProfileBusinessAbsenceRecovery.validate(proof,req,req.started+31,req.requestBoot);
            if(!proof.getBoolean("historical_model_exit_verified")||!proof.getBoolean("historical_broker_release_observed")||proof.getBoolean("rewrites_business_outcome"))throw new AssertionError("disposition");
            cases++;
        }
        reject(f,"BUSINESS_MODEL_DISPOSITION",x->{JSONObject r=x.json(x.resultPath);r.put("model_done_status","success");x.result(r);});
        reject(f,"BUSINESS_EXPECTED_FALSE_model_done_synthesized",x->{JSONObject r=x.json(x.resultPath);r.put("model_done_synthesized",true);x.result(r);});
        reject(f,"BUSINESS_MODEL_TERMINAL_BINDING",x->x.edit(terminalPath(x),j->j.put("step",6)));
        reject(f,"BUSINESS_MODEL_TERMINAL_BINDING",x->x.edit(terminalPath(x),j->j.put("task_id","00000000000000000000000000000000")));
        reject(f,"BUSINESS_EXPECTED_FALSE_dispatched",x->x.edit(terminalPath(x),j->j.put("dispatched",true)));
        reject(f,"BUSINESS_EXPECTED_FALSE_service_perform_called",x->x.edit(terminalPath(x),j->j.put("service_perform_called",true)));
        reject(f,"BUSINESS_MODEL_TERMINAL_ACTION",x->x.edit(terminalPath(x),j->j.getJSONObject("action").put("status","success")));
        reject(f,"BUSINESS_MODEL_TERMINAL_RECEIPT",x->x.edit(x.taskPrefix+"step-07-model-0.json",j->j.put("raw_text","{}")));
        reject(f,"BUSINESS_MODEL_TERMINAL_BINDING",x->x.edit(terminalPath(x),j->j.put("task_authorization_sha256","bad")));
        reject(f,"BUSINESS_MODEL_TERMINAL_CLOCK",x->x.edit(terminalPath(x),j->j.put("controller_consumed_elapsed_ms",Long.MAX_VALUE)));
        System.out.println(new JSONObject().put("passed",true).put("cases",cases).put("original_files",f.files.size()).put("recorded_model_requests",7).put("phone_operations",0));
    }
}
