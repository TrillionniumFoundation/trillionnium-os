package org.trillionnium.hepta.background;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;
import org.json.JSONObject;

/** Actual archived files stay on the operator host. Only the current absence samples here are fixtures. */
public final class PersonalNotesLostLaunchHostTest {
    private static int cases,assertions;
    private interface Change {void run(JSONObject value)throws Exception;}
    private interface Work {void run()throws Exception;}
    private static void need(boolean yes,String message){assertions++;if(!yes)throw new AssertionError(message);}
    private static void refuses(String tag,Work work)throws Exception{
        try{work.run();}catch(Exception e){need(e.getMessage()!=null,tag);cases++;return;}
        throw new AssertionError("unsafe "+tag);
    }
    private static byte[] raw(JSONObject o){return o.toString().getBytes(StandardCharsets.UTF_8);}
    private static final class Input{
        final Map<String,byte[]> files=new LinkedHashMap<String,byte[]>();
        final JSONObject control,controller;final byte[] controlRaw;final long now;final int uid,boot;
        Input(JSONObject paths)throws Exception{
            JSONObject records=paths.getJSONObject("records");
            for(String n:records.keySet()){
                JSONObject ref=records.getJSONObject(n);byte[] b=Files.readAllBytes(Paths.get(ref.getString("path")));
                need(ProfileIdentity.sha(b).equals(ref.getString("sha256"))&&b.length==ref.getInt("bytes"),"unchanged "+n);files.put(n,b);
            }
            controlRaw=files.remove("current_control");control=obj(controlRaw);controller=paths.getJSONObject("controller");
            JSONObject j=obj(files.get("journal"));uid=j.getInt("app_uid");boot=j.getInt("boot_count");now=j.getLong("expires_elapsed_ms")+3000;
        }
        PublicPersonalNotesAbsenceRecovery.Request request()throws Exception{
            return PublicPersonalNotesAbsenceRecovery.request(files,PublicPersonalNotesAbsenceRecovery.same(control,obj(controlRaw))?controlRaw:raw(control),controller,uid,"11111111-2222-4333-8444-555555555555",now,boot);
        }
        void change(String key,Change edit)throws Exception{JSONObject j=obj(files.get(key));edit.run(j);files.put(key,raw(j));}
        void terminal(Change edit)throws Exception{
            change("broker_output",edit);final byte[] out=files.get("broker_output");change("broker_receipt",j->j.put("stored_bytes",out.length)
                    .put("observed_bytes",out.length).put("stored_sha256",ProfileIdentity.sha(out)));
            final JSONObject receipt=obj(files.get("broker_receipt"));change("cleanup",j->j.put("broker_output",receipt));
            final JSONObject clean=obj(files.get("cleanup"));change("result",j->{j.put("background_cleanup",clean);
                JSONObject session=obj(raw(clean));session.remove("cleanup_known");session.remove("cleanup_error");j.put("background_session",session);});
        }
    }
    private static JSONObject obj(byte[] b)throws Exception{return PublicPersonalNotesAbsenceRecovery.object(b);}
    public static void main(String[] args)throws Exception{
        JSONObject paths=obj(Files.readAllBytes(Paths.get(args[0])));Input real=new Input(paths);
        PublicPersonalNotesAbsenceRecovery.Request original=real.request(),r=PublicPersonalNotesAbsenceRecovery.fromWire(original.wire());
        need(r.currentControlSha256.equals(ProfileIdentity.sha(real.controlRaw)),"exact current blocked control bytes");
        need(r.inputHashes().length()==10&&r.recordedTaskIds.size()==1&&r.recordedTaskIds.contains(1825),"one recorded physical task in the original");
        need(r.displayId==502&&r.targetUid==10382&&!r.postModelDrained,"original Notes target and no model");
        JSONObject identity=r.recordedOwnedIdentity();need(identity.getBoolean("broker_launch_dispatched")&&!identity.getBoolean("app_observed_launch_response"),"truthful statement of historical operations");
        JSONObject proof=PersonalNotesAbsenceHostTest.proof(r);proof.put("historical_broker_release_observed",true);
        need(PublicPersonalNotesAbsenceRecovery.validate(proof,r,r.started+21,r.requestBoot).getBoolean("current_absence_verified"),"two independent samples");cases++;
        for(String fault:new String[]{"uid","launch","absence","release","reason","foreign_task","recents","physical_freeze","token_authority"}){
            Input v=new Input(paths);v.terminal(t->{JSONObject c=t.getJSONObject("personal_notes_cleanup");
                if("uid".equals(fault))c.put("target_uid",12399);
                if("launch".equals(fault))c.put("launch_dispatched",false);
                if("absence".equals(fault))c.put("absence_reads",1);
                if("release".equals(fault))t.put("release_confirmed",false);
                if("reason".equals(fault))t.put("reason","OTHER");
                if("foreign_task".equals(fault))c.getJSONArray("actual_observed_tasks").getJSONObject(0).put("display_id",0);
                if("recents".equals(fault))c.put("initial_recents_sha256",ProfileIdentity.sha("other recents"));
                if("physical_freeze".equals(fault))c.put("physical_history_frozen",true);
                if("token_authority".equals(fault))c.getJSONArray("actual_observed_tasks").getJSONObject(0).put("serialized_token_grants_authority",true);
            });refuses(fault,()->v.request());
        }
        for(String fault:new String[]{"scope","initial","apk","extra","model","time","proof","control"}){
            Input v=new Input(paths);
            if("scope".equals(fault))v.change("scope_binding",j->j.put("restricted",true));
            if("initial".equals(fault))v.change("initial_binding",j->j.put("bootstrap_dispatched",true));
            if("apk".equals(fault))v.change("completion_identity",j->j.getJSONObject("apk_hashes").put("base",ProfileIdentity.sha("other")));
            if("extra".equals(fault))v.files.put("step_model",new byte[]{42});
            if("model".equals(fault))v.change("result",j->j.getJSONObject("model_session").put("process_started",true));
            if("control".equals(fault))v.control.put("blocked",false);
            if("time".equals(fault))refuses(fault,()->r.requireFence(r.expires,r.oldBoot));
            else if("proof".equals(fault))refuses(fault,()->PublicPersonalNotesAbsenceRecovery.validate(new JSONObject(proof.toString()).put("historical_broker_release_observed",false),r,r.started+21,r.requestBoot));
            else refuses(fault,()->v.request());
        }
        System.out.println(new JSONObject().put("all_pass",true).put("cases",cases).put("assertions",assertions).put("recorded_task",r.taskId)
                .put("actual_originals",r.inputHashes().length()).put("current_absence_samples","host fixtures").put("phone_operations",0));
    }
}
