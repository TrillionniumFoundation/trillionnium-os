package org.trillionnium.hepta.local;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.io.IOException;
import org.json.*;

public final class WorkerGenerationHostTest {
    private static int checks;
    private static final List<String> names=new ArrayList<>();
    interface Throwing { void run()throws Exception; }
    static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    static void pass(String name,Throwing body)throws Exception{
        if(names.contains(name))throw new AssertionError("duplicate case");
        body.run();names.add(name);
    }
    static void rejects(String name,Throwing body)throws Exception{
        pass(name,()->{boolean rejected=false;try{body.run();}catch(IOException expected){rejected=true;}
            check(rejected,name+" must reject");});
    }
    static final class Fixture {
        final JSONObject row,r;
        final WorkerGenerationProof.Expected expected;
        final WorkerGenerationProof.Identity identity;
        final long submitted,deadline,finisherSubmitted,finisherDeadline;
        final String nonce;
        Fixture(JSONObject row)throws Exception{
            this.row=row;r=row.optJSONObject("native");
            JSONObject e=row.getJSONObject("expected");
            expected=new WorkerGenerationProof.Expected(e.getString("task"),e.getString("generation"),
                e.getString("token"),e.getString("boot"),e.getLong("uid"),e.getLong("appPid"),e.getLong("appStart"));
            identity=WorkerGenerationProof.identity(row.getString("identity").getBytes(StandardCharsets.US_ASCII),expected);
            submitted=row.getLong("submitted");deadline=row.getLong("deadline");nonce=row.getString("nonce");
            finisherSubmitted=submitted;finisherDeadline=deadline-submitted<4000000000L?deadline+1500000000L:submitted+44000000000L;
        }
        JSONObject copy()throws Exception{return r==null?null:new JSONObject(r.toString());}
        JSONObject bind(JSONObject value)throws Exception{
            return WorkerGenerationProof.bindCleanup(identity,nonce,submitted,deadline,finisherSubmitted,finisherDeadline,
                    value,true,row.getInt("helper_exit"),false);
        }
    }
    static void wrong(Fixture f,String field,Object value)throws Exception{
        rejects("wrong_"+field,()->{JSONObject r=f.copy();r.put(field,value);f.bind(r);});
    }
    public static void main(String[] args)throws Exception{
        JSONObject input=new JSONObject(new String(Files.readAllBytes(Paths.get(args[0])),StandardCharsets.UTF_8));
        JSONArray rows=input.getJSONArray("records");
        Fixture normal=null,forced=null;
        for(int i=0;i<rows.length();i++){
            JSONObject row=rows.getJSONObject(i);if(!row.has("expected_clean"))continue;
            if(row.getBoolean("expected_clean")){
                Fixture f=new Fixture(row);
                pass("actual_native_"+row.getString("case"),()->{
                    JSONObject bound=f.bind(f.r);
                    check(bound.getBoolean("cleanup_known"),"actual bound cleanup");
                    int force=WorkerGenerationProof.boundForceAttempts(f.identity,f.nonce,f.r);
                    check(force==f.r.getInt("kill_attempts"),"actual force count");
                    EngineReleaseProjection.Scope.Cleanup c=new EngineReleaseProjection.Scope.Cleanup(true,true,force>0,bound);
                    check(c.unforced()==(force==0),"real Cleanup.unforced method");
                });
                if(row.getString("case").equals("empty_normal0"))normal=f;
                if(row.getString("case").equals("descendant_KILL_is_force"))forced=f;
            }else{
                rejects("actual_refusal_"+row.getString("case"),()->{
                    Fixture f=new Fixture(row);f.bind(f.r);
                });
            }
        }
        if(normal==null||forced==null)throw new AssertionError("actual native fixtures missing");
        final Fixture n=normal,k=forced;
        wrong(n,"task_id","00000000000000000000000000000000");
        wrong(n,"worker_generation","00000000000000000000000000000000");
        wrong(n,"scope_token","00000000000000000000000000000000");
        wrong(n,"app_uid",n.expected.uid+1);
        wrong(n,"app_pid",n.expected.appPid+1);
        wrong(n,"app_start_ticks",n.expected.appStart+1);
        wrong(n,"leader_pid",n.identity.leaderPid+1);
        wrong(n,"leader_start_ticks",n.identity.leaderStart+1);
        wrong(n,"pgid",n.identity.pgid+1);
        wrong(n,"boot_id","00000000-0000-0000-0000-000000000000");
        wrong(n,"identity_sha256","0000000000000000000000000000000000000000000000000000000000000000");
        wrong(n,"cleanup_nonce","00000000000000000000000000000000");
        wrong(n,"helper_pgid",n.identity.pgid);
        wrong(n,"unknown_count",1);
        wrong(n,"remaining_owned_count",1);
        wrong(n,"escaped_generation_count",1);
        wrong(n,"scan_complete",false);
        wrong(n,"pidfd_supported",false);
        wrong(n,"numeric_pid_signal_used",true);
        wrong(n,"group_signal_used",true);
        wrong(n,"sdk_called",true);
        wrong(n,"worker_started",true);
        wrong(n,"empty_readbacks",1);
        wrong(n,"group_presence_probe_used",false);
        wrong(n,"group_presence_probe_signal",15);
        rejects("kernel_group_still_present",()->{
            JSONObject r=n.copy();JSONArray a=r.getJSONArray("group_presence_observations");
            a.getJSONObject(a.length()-1).put("result",0).put("errno",0);n.bind(r);
        });
        rejects("kernel_group_permission_unknown",()->{
            JSONObject r=n.copy();JSONArray a=r.getJSONArray("group_presence_observations");
            a.getJSONObject(a.length()-1).put("result",-1).put("errno",1);n.bind(r);
        });
        rejects("kernel_foreign_group_id",()->{
            JSONObject r=n.copy();r.getJSONArray("group_presence_observations").getJSONObject(0).put("pgid",n.identity.pgid+1);n.bind(r);
        });
        rejects("wrong_numeric_type",()->{JSONObject r=n.copy();r.put("app_uid",Double.valueOf(n.expected.uid));n.bind(r);});
        rejects("helper_exit_unobserved",()->WorkerGenerationProof.bindCleanup(n.identity,n.nonce,n.submitted,n.deadline,
            n.finisherSubmitted,n.finisherDeadline,n.r,false,0,false));
        rejects("helper_nonzero_exit",()->WorkerGenerationProof.bindCleanup(n.identity,n.nonce,n.submitted,n.deadline,
            n.finisherSubmitted,n.finisherDeadline,n.r,true,143,false));
        rejects("helper_forced",()->WorkerGenerationProof.bindCleanup(n.identity,n.nonce,n.submitted,n.deadline,
            n.finisherSubmitted,n.finisherDeadline,n.r,true,0,true));
        rejects("force_count_mismatch",()->{JSONObject r=k.copy();r.put("kill_attempts",0);k.bind(r);});
        rejects("target_process_reused_identity",()->{
            JSONObject r=k.copy();r.getJSONArray("targets").getJSONObject(0).put("start_ticks",k.identity.leaderStart-1);k.bind(r);
        });
        rejects("target_is_app",()->{
            JSONObject r=k.copy();r.getJSONArray("targets").getJSONObject(0).put("pid",k.expected.appPid);k.bind(r);
        });
        rejects("signal_permission_denied",()->{
            JSONObject r=k.copy();r.getJSONArray("targets").getJSONObject(0).put("kill_errno",13);k.bind(r);
        });
        rejects("duplicate_target",()->{
            JSONObject r=k.copy();r.getJSONArray("targets").put(new JSONObject(r.getJSONArray("targets").getJSONObject(0).toString()));k.bind(r);
        });
        final long initial=1000000000L,finish=initial+44000000000L;
        pass("budget_full_four_seconds",()->check(WorkerGenerationProof.cleanupDeadline(initial,initial,finish)==initial+4000000000L,"full cap"));
        pass("budget_shortens_after_queue",()->{
            long later=finish-1800000000L;
            check(WorkerGenerationProof.cleanupDeadline(later,initial,finish)==finish-1500000000L,"queue counts");
            check(WorkerGenerationProof.cleanupDeadline(later,initial,finish)-later==300000000L,"300ms actual");
        });
        pass("budget_minimum_200ms",()->{
            long later=finish-1700000000L;
            check(WorkerGenerationProof.cleanupDeadline(later,initial,finish)-later==200000000L,"minimum included");
        });
        rejects("budget_queue_expired",()->WorkerGenerationProof.cleanupDeadline(finish,initial,finish));
        rejects("budget_less_than_200ms",()->WorkerGenerationProof.cleanupDeadline(finish-1699999999L,initial,finish));
        rejects("budget_before_submission",()->WorkerGenerationProof.cleanupDeadline(initial-1,initial,finish));
        rejects("budget_above_original44",()->WorkerGenerationProof.cleanupDeadline(initial,initial,finish+1));
        rejects("helper_deadline_after_finisher_reserve",()->WorkerGenerationProof.bindCleanup(n.identity,n.nonce,n.submitted,n.deadline,
            n.submitted,n.deadline+1499999999L,n.r,true,0,false));
        // Exact production release/claim blocks, with only platform/SDK IO stubbed.
        for(int exit:new int[]{0,143,70}){
            final int code=exit;
            pass("parent_"+exit+"_cannot_release_live_generation",()->{
                EngineReleaseProjection e=new EngineReleaseProjection();
                LocalInference.TaskCleanup result=e.release(true,true,false,true,code);
                check(!result.cleanupKnown,"unknown generation blocks cleanup");
                check(e.slotRetained(),"all owner references retained");
                check(!e.tryNext(),"actual claimProcess rejects next admission");
            });
        }
        pass("durable_absence_releases_slot",()->{
            EngineReleaseProjection e=new EngineReleaseProjection();
            LocalInference.TaskCleanup result=e.release(true,true,true,true,0);
            check(result.cleanupKnown&&!e.slotRetained(),"known generation releases");
            check(e.tryNext(),"next admission after physical proof");
        });
        pass("missing_durable_app_receipt_keeps_slot",()->{
            EngineReleaseProjection e=new EngineReleaseProjection();
            check(!e.release(false,true,true,true,0).cleanupKnown&&e.slotRetained(),"write acknowledgement required");
            check(!e.tryNext(),"no next admission");
        });
        pass("descendant_force_cannot_be_cooperative143",()->{
            EngineReleaseProjection.Scope.Cleanup c=new EngineReleaseProjection.Scope.Cleanup(true,true,true,k.r);
            JSONObject r=EngineReleaseProjection.cancelClassification(false,true,true,c);
            check(r.getBoolean("force")&&!r.getBoolean("cooperative"),"actual force/conjunction blocks cooperative claim");
        });
        pass("unknown_force_cannot_be_cooperative143",()->{
            EngineReleaseProjection.Scope.Cleanup c=new EngineReleaseProjection.Scope.Cleanup(false,false,false,new JSONObject());
            JSONObject r=EngineReleaseProjection.cancelClassification(false,true,false,c);
            check(!r.getBoolean("cooperative"),"unknown remains unknown");
        });
        JSONObject result=new JSONObject().put("schema","hepta.owned-generation-java-host.v1").put("all_pass",true)
            .put("cases",names.size()).put("checks",checks).put("case_names",new JSONArray(names))
            .put("actual_native_receipts_bound",true).put("android_platform_io_executed",false)
            .put("release_and_claim_blocks_extracted_from_production",true);
        Files.write(Paths.get(args[1]),(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println(result.toString());
    }
}
