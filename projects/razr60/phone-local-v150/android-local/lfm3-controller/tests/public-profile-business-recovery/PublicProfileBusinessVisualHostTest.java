package org.trillionnium.hepta.background;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;
import org.json.JSONObject;

/** Replay external, app-produced visual task records. Synthetic file descriptors,
 * wall-independent expiry and current controller identity belong to this host test. */
public final class PublicProfileBusinessVisualHostTest {
    private interface Update { void change(PublicProfileBusinessRecoveryHostTest.Fixture f)throws Exception; }
    private static int cases;

    private static void rejects(PublicProfileBusinessRecoveryHostTest.Fixture original,Update mutation)throws Exception{
        PublicProfileBusinessRecoveryHostTest.Fixture draft=original.copy();
        mutation.change(draft);
        try{draft.request();}
        catch(Exception expected){cases++;return;}
        throw new AssertionError("a changed visual recovery record was accepted");
    }

    private static void result(PublicProfileBusinessRecoveryHostTest.Fixture f,JSONObject value)throws Exception{
        if(f.json("control-session.json").has("task_result_reference"))f.result(value);
        else f.put(f.resultPath,value.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private static void aggregate(PublicProfileBusinessRecoveryHostTest.Fixture f,String relative,JSONObject value)throws Exception{
        f.put(relative,value.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        JSONObject result=f.json(f.resultPath);
        result.getJSONObject("model_session").put("app_receipt_sha256",ProfileIdentity.sha(f.files.get(relative)));
        result(f,result);
    }

    public static void main(String[] args)throws Exception{
        if(args.length!=2)throw new IllegalArgumentException("manifest and original-file map required");
        JSONObject manifest=PublicProfileBusinessAbsenceRecovery.object(Files.readAllBytes(Paths.get(args[0])));
        JSONObject paths=PublicProfileBusinessAbsenceRecovery.object(Files.readAllBytes(Paths.get(args[1])));
        Map<String,byte[]> files=new TreeMap<String,byte[]>();
        for(Iterator<String> it=paths.keys();it.hasNext();){String key=it.next();files.put(key,Files.readAllBytes(Paths.get(paths.getString(key))));}
        PublicProfileBusinessRecoveryHostTest.Fixture original=new PublicProfileBusinessRecoveryHostTest.Fixture(manifest,files);
        PublicProfileBusinessAbsenceRecovery.Request valid=original.request();
        if(valid.modelRequests<=0||valid.steps<=0||!valid.taskId.equals(original.task))throw new AssertionError("missing original visual work");
        cases++;
        if(original.archived().request().modelRequests!=valid.modelRequests)throw new AssertionError("archived original lost model proof");
        cases++;
        rejects(original,f->{JSONObject x=f.json("control-session.json");x.getJSONObject("completion_evidence").put("owner_sha256","foreign");
            f.put("control-session.json",x.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));});
        rejects(original,f->{JSONObject x=f.json("control-session.json");x.put("terminal_evidence_schema","hepta.session-terminal-evidence.v1");
            f.put("control-session.json",x.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));});
        String terminal=original.modelPrefix+"vlm-task-terminal.json";
        JSONObject first=original.json(terminal).getJSONArray("requests").getJSONObject(0);
        String worker=first.getString("generation"),request=first.getString("request_id"),round="runs/"+worker+"/vlm/"+request+"/";
        rejects(original,f->f.remove(round+"owner.json"));
        rejects(original,f->{JSONObject x=f.json(round+"owner.json");x.put("task_owner_sha256",worker+worker);
            f.put(round+"owner.json",x.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));});
        rejects(original,f->f.remove(round+"app-delivery.json"));
        rejects(original,f->f.remove("runs/"+worker+"/worker-generation.identity"));
        rejects(original,f->f.remove(original.modelPrefix+"vlm-task-pending.json"));
        rejects(original,f->f.remove("runs/"+worker+"/generation-cleanup-"+first.getJSONObject("generation_cleanup").getString("cleanup_nonce")+".json"));
        rejects(original,f->f.put(round+"raw.txt",new byte[]{123}));
        rejects(original,f->{JSONObject x=f.json(terminal);x.put("cleanup_known",false);aggregate(f,terminal,x);});
        rejects(original,f->{JSONObject x=f.json(terminal);x.getJSONArray("requests").getJSONObject(0).put("actual_exit_code",1);aggregate(f,terminal,x);});
        rejects(original,f->{JSONObject x=f.json(terminal);x.getJSONArray("requests").getJSONObject(0).put("background_generation","unrelated");aggregate(f,terminal,x);});
        rejects(original,f->{JSONObject x=f.json(terminal);x.getJSONArray("requests").getJSONObject(0).put("request_id","../../foreign");aggregate(f,terminal,x);});
        rejects(original,f->{JSONObject x=f.json(terminal);x.getJSONArray("requests").put(x.getJSONArray("requests").getJSONObject(0));aggregate(f,terminal,x);});
        rejects(original,f->f.put(original.modelPrefix+"app-session-receipt.json",new byte[]{123,125}));
        rejects(original,f->{JSONObject x=f.json(f.resultPath);x.put("completion_verified",true);result(f,x);});
        System.out.println(new JSONObject().put("passed",true).put("cases",cases).put("model_requests",valid.modelRequests)
                .put("business_steps",valid.steps).put("phone_operations",0).put("current_absence_verified",false));
    }
    private PublicProfileBusinessVisualHostTest(){}
}
