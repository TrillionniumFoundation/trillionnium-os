package org.trillionnium.hepta.background;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;
import org.json.JSONObject;

/** Actual extracted producer methods and actual ownership/custody classes.
 * Android, Binder objects, pipe endpoints and elapsed clock are synthetic IO.
 * No device cleanup, qualification, business outcome or model result is implied. */
public final class ProfileFailureSnapshotHostTest {
    interface Work {void run()throws Exception;}
    static final JSONArray cases=new JSONArray();
    static int assertions,failures;
    static void yes(boolean condition,String message){assertions++;if(!condition)throw new AssertionError(message);}
    static void test(String name,Work work){
        int before=assertions;
        try{work.run();cases.put(new JSONObject().put("name",name).put("passed",true).put("assertions",assertions-before));}
        catch(Throwable failure){failures++;cases.put(new JSONObject().put("name",name).put("passed",false)
            .put("assertions",assertions-before).put("error",failure.toString()));}
    }
    static byte[] capture(Work work)throws Exception{
        PrintStream original=System.out;ByteArrayOutputStream buffer=new ByteArrayOutputStream();
        try(PrintStream stream=new PrintStream(buffer,true,"UTF-8")){System.setOut(stream);work.run();}
        finally{System.setOut(original);}
        return buffer.toByteArray();
    }
    static JSONObject object(byte[] bytes){return new JSONObject(new String(bytes,StandardCharsets.UTF_8));}
    static boolean same(JSONObject a,JSONObject b){return a.similar(b);}
    static ProfileCleanupBrokerHost broker()throws Exception{
        ProfileTaskPlatform p=new ProfileTaskPlatform();p.active(true);return new ProfileCleanupBrokerHost(p);
    }
    static ProfileCleanupBrokerHost blocked()throws Exception{
        ProfileCleanupBrokerHost b=broker();
        b.io.mixedReached=new CountDownLatch(1);b.io.continueMixed=new CountDownLatch(1);
        b.forceDeadlineBeforeWatchdog=true;return b;
    }
    static void finishWorker(ProfileCleanupBrokerHost b)throws Exception{
        b.io.continueMixed.countDown();yes(b.cleanupDone.await(5,TimeUnit.SECONDS),"original normal worker did not drain");
    }
    static JSONObject[] records(byte[] bytes){
        String[] lines=new String(bytes,StandardCharsets.UTF_8).split("\n",-1);
        yes(lines.length==3&&lines[2].isEmpty(),"not exactly two LF-terminated records");
        return new JSONObject[]{new JSONObject(lines[0]),new JSONObject(lines[1])};
    }
    static byte[] pair(ProfileCleanupBrokerHost b)throws Exception{
        return capture(()->{
            b.runWatchdogCleanup(b.io.f.now);
            finishWorker(b);
            b.runMainFinally();
        });
    }
    static void unknown(ProfileCleanupBrokerHost b)throws Exception{
        yes("CLEANUP_UNKNOWN".equals(b.state),"unknown decision missing");
        yes(b.profileCustody.retain()&&!b.profileCustody.known(),"unknown custody promoted");
        yes(!b.profileCustody.normalCleanupAllowed(),"normal cleanup revived");
        yes(b.io.removeCalls==1&&b.io.deleteCalls==0&&b.displayReleaseCalls==0,"failure repeated or widened effects");
    }
    static void baselineRed()throws Exception{
        ProfileCleanupBrokerHost b=blocked();
        try{
            JSONObject reply=b.closeResult();
            yes("CLOSING".equals(reply.getString("state")),"old close no longer reproduces boundary");
            yes(b.cleanupDone.getCount()==1,"blocked actual worker already drained");
            byte[] bytes=pair(b);JSONObject[] lines=records(bytes);
            yes("CLEANUP_UNKNOWN".equals(lines[0].getString("state"))&&"CLEANUP_UNKNOWN".equals(lines[1].getString("state")),"old watchdog missing");
            yes(!same(lines[0],lines[1]),"old live evidence unexpectedly immutable");
            yes(!lines[0].getJSONObject("profile_cleanup").has("normal_cleanup_phase")
                &&lines[1].getJSONObject("profile_cleanup").has("normal_cleanup_phase"),"old late worker detail not exercised");
            yes(!RetainedPairHost.accepts(bytes,lines[0]),"old unequal pair unexpectedly acknowledged");
        }finally{b.io.continueMixed.countDown();b.cleanupDone.await(5,TimeUnit.SECONDS);}
    }
    public static void main(String[] args)throws Exception{
        ProfileCleanupSettleFixtures.load(args[0]);
        if(args.length>2&&"baseline-red".equals(args[2])){
            test("unmodified_producer_close_before_watchdog_exposes_closing_and_changed_terminal_pair",ProfileFailureSnapshotHostTest::baselineRed);
            System.out.println(new JSONObject().put("all_pass",failures==0).put("expected_old_failure_demonstrated",failures==0)
                .put("cases",cases).put("assertions",assertions).put("phone_operations",0));
            if(failures!=0)System.exit(1);return;
        }
        test("expired_original_wait_quarantines_before_next_watchdog_tick_without_worker_drain_claim",()->{
            ProfileCleanupBrokerHost b=blocked();
            try{
                JSONObject reply=b.closeResult();unknown(b);
                yes("CLEANUP_UNKNOWN".equals(reply.getString("state"))&&!reply.getBoolean("ok"),"close returned stale CLOSING");
                yes(b.io.f.now==b.io.started+3100&&b.requestDeadline==b.io.started+3500,"original absolute budgets changed");
                yes(b.cleanupDone.getCount()==1&&!reply.getJSONObject("profile_failure_decision_snapshot").getBoolean("normal_cleanup_worker_drained"),"early snapshot claims drain");
                yes(!reply.getJSONObject("profile_failure_decision_snapshot").getBoolean("provides_cleanup_proof"),"diagnostic grants cleanup");
            }finally{finishWorker(b);}
        });
        test("watchdog_then_finally_use_same_bytes_after_real_worker_refresh_and_close_fields_match",()->{
            ProfileCleanupBrokerHost b=blocked();
            try{
                JSONObject reply=b.closeResult();byte[] bytes=pair(b);JSONObject[] lines=records(bytes);
                yes(same(lines[0],lines[1]),"two original publishers differ");
                int half=bytes.length/2;yes(Arrays.equals(Arrays.copyOf(bytes,half),Arrays.copyOfRange(bytes,half,bytes.length)),"not byte-identical");
                for(String key:new String[]{"profile_cleanup","profile_last_leaf_validation","public_surface_detach","profile_cleanup_diagnostics","profile_failure_decision_snapshot"})
                    yes(same(reply.getJSONObject(key),lines[0].getJSONObject(key)),"close mismatch: "+key);
                yes(!lines[0].getJSONObject("profile_cleanup").has("normal_cleanup_phase"),"first failure cut not retained");
                yes(b.profileCleanupReadback.containsKey("normal_cleanup_phase"),"actual late worker did not publish diagnostics");
                yes(RetainedPairHost.accepts(bytes,lines[0]),"unchanged actual ACK parser refused equal pair");
                unknown(b);yes(b.lastMainExit==70,"old failed business exit changed");
            }finally{b.io.continueMixed.countDown();b.cleanupDone.await(5,TimeUnit.SECONDS);}
        });
        test("main_finally_then_watchdog_keep_pair_and_phase_observation_at_first_cut",()->{
            ProfileCleanupBrokerHost b=broker();b.io.leafThrows=true;JSONObject reply=b.closeResult();
            yes(reply.getJSONObject("profile_cleanup").has("normal_cleanup_phase"),"phase-at-first-cut not covered");
            byte[] bytes=capture(()->{b.runMainFinally();b.io.f.now=b.io.started+1500;b.runWatchdogCleanup(b.io.f.now);});
            JSONObject[] rows=records(bytes);yes(same(rows[0],rows[1]),"reverse publication order changed snapshot");
            yes(RetainedPairHost.accepts(bytes,rows[0]),"phase-bearing pair refused ACK");
        });
        test("valid_second_interval_finishes_release_without_freezing_unknown",()->{
            ProfileCleanupBrokerHost b=broker();b.io.mixedReached=new CountDownLatch(1);b.io.continueMixed=new CountDownLatch(1);b.forceFirstAwaitExpiry=true;
            JSONObject reply=b.closeResult();
            yes(reply.getBoolean("ok")&&"RELEASED".equals(b.state)&&b.profileCustody.known(),"valid cleanup lost success");
            yes(b.frozenFailure()==null&&!reply.has("profile_failure_decision_snapshot"),"normal close froze failure");
            yes(b.io.f.now==b.io.started+1500&&b.awaitCalls==2,"original bounded phase changed");
        });
        test("verified_success_wins_late_quarantine_without_marking_phase_failed",()->{
            ProfileCleanupBrokerHost b=broker();b.closeResult();
            yes("RELEASED".equals(b.state)&&b.profileCustody.known(),"normal success prerequisite");
            b.lateWatchdogQuarantine();
            yes("RELEASED".equals(b.state)&&b.profileCustody.known()&&!b.profileCustody.retain(),"late tick overwrote release");
            yes(Boolean.FALSE.equals(b.normalProfileCleanup.evidence().get("failed"))&&b.frozenFailure()==null,"late tick froze failure");
        });
        test("frozen_worker_diagnostic_does_not_upgrade_pending_surface_detach",()->{
            ProfileCleanupBrokerHost b=blocked();b.detachFinished=false;
            try{
                JSONObject r=b.closeResult();yes(!r.getJSONObject("public_surface_detach").getBoolean("worker_finished"),"surface drain invented");
                yes(!r.getJSONObject("profile_failure_decision_snapshot").getBoolean("provides_cleanup_proof"),"snapshot grants cleanup");
                unknown(b);
            }finally{finishWorker(b);}
        });
        test("actual_original_owner_retained_absence_can_publish_new_release_without_old_unknown_override",()->{
            ProfileCleanupBrokerHost b=blocked();
            try{
                b.closeResult();byte[] original=pair(b);String frozen=b.frozenFailure();
                long deadline=b.io.f.now+10000;b.retainedReadDeadline.set(deadline);
                try{
                    b.profileOwnedTask.closeRetainedEmptyDisplay(deadline,new ProfileOwnedTask.RetiredDisplay(){
                        public void requireState(boolean before){yes(b.displayPresent==before,"synthetic owned display state mismatch");}
                        public void awaitAbsent(){yes(!b.displayPresent,"owned release did not remove display");}
                        public void releaseOriginalHandle()throws Exception{
                            b.virtual.release();b.io.f.root=false; // Fake destroy-content result of this original handle only.
                        }
                    });
                    byte[] released=capture(()->b.commitRetainedRecheck(b.profileOwnedTask));JSONObject record=object(released);
                    yes("RELEASED".equals(record.getString("state"))&&record.getBoolean("release_confirmed"),"old UNKNOWN overrode later verified interval");
                    yes(!record.getBoolean("profile_custody_retained")&&b.profileCustody.known(),"actual private owner absence not consumed");
                    yes(frozen.equals(b.frozenFailure())&&original.length==2*(frozen.getBytes(StandardCharsets.UTF_8).length+1),"original failure changed");
                    yes(!record.has("profile_failure_decision_snapshot")&&!b.profileCustody.normalCleanupAllowed(),"new release reopened business");
                    yes(b.publicAdmissionRetired.get()&&b.closing.get()&&!b.serve&&b.io.deleteCalls==0,"retained release widened authority");
                }finally{b.retainedReadDeadline.remove();}
            }finally{b.io.continueMixed.countDown();b.cleanupDone.await(5,TimeUnit.SECONDS);}
        });
        test("late_selected_observations_live_only_in_separate_retained_reply_and_link_original_line",()->{
            ProfileCleanupBrokerHost b=blocked();
            try{
                b.closeResult();byte[] old=pair(b);JSONObject[] rows=records(old);String frozen=b.frozenFailure();
                JSONObject late=b.lateDiagnostic();yes(late.getBoolean("normal_cleanup_worker_drained")&&late.getBoolean("complete"),"late cache not observed");
                yes(late.getJSONObject("observation").getJSONObject("profile_cleanup").has("normal_cleanup_phase"),"late phase lost");
                yes(late.getString("original_terminal_line_sha256").equals(ProfileIdentity.sha((frozen+"\n").getBytes(StandardCharsets.UTF_8))),"diagnostic origin unbound");
                yes(!late.getBoolean("provides_cleanup_proof")&&!late.getBoolean("business_admission_restored")&&!late.getBoolean("old_failure_rewritten"),"late diagnostic grants authority");
                JSONObject base=new JSONObject().put("schema","synthetic-base-attempt").put("current_absence_verified",false);
                JSONObject reply=object(b.retainedReply(base,late));yes(reply.has("prior_normal_cleanup_diagnostic"),"late diagnostic not in independent reply");
                yes(!reply.getBoolean("current_absence_verified")&&frozen.equals(b.frozenFailure()),"diagnostic promoted outcome or changed original");
                byte[] later=capture(b::publishTerminal);yes(Arrays.equals(later,Arrays.copyOf(old,old.length/2)),"late diagnostics polluted original terminal channel");
                yes(RetainedPairHost.accepts(old,rows[0]),"original pair changed after late diagnostic");
            }finally{b.io.continueMixed.countDown();b.cleanupDone.await(5,TimeUnit.SECONDS);}
        });
        test("late_diagnostic_does_not_take_actual_owner_monitor",()->{
            ProfileCleanupBrokerHost b=blocked();
            try{
                b.closeResult();CountDownLatch finished=new CountDownLatch(1);Throwable[] failed=new Throwable[1];
                yes(b.cleanupDone.getCount()==1,"normal worker is not paused inside actual synchronized retire");
                Thread t=new Thread(()->{try{if(b.lateDiagnostic()==null)throw new AssertionError("late diagnostic absent");}
                    catch(Throwable e){failed[0]=e;}finally{finished.countDown();}});
                t.start();yes(finished.await(2,TimeUnit.SECONDS),"diagnostic waited on owner monitor");t.join(1000);
                yes(b.cleanupDone.getCount()==1,"test released owner before diagnostic completed");
                yes(failed[0]==null,"diagnostic threw while owner held");
            }finally{finishWorker(b);}
        });
        test("combined_retained_reply_stays_under_original_limit_and_marks_diagnostic_omission",()->{
            ProfileCleanupBrokerHost b=broker();
            JSONObject base=new JSONObject().put("proof",new String(new char[40000]).replace('\0','x'));
            JSONObject diagnostic=new JSONObject().put("schema","synthetic-diagnostic").put("observation",new String(new char[30000]).replace('\0','y')).put("complete",true);
            byte[] bytes=b.retainedReply(base,diagnostic);yes(bytes.length<=BrokerProtocol.MAX_RESPONSE,"combined frame exceeded original limit");
            JSONObject r=object(bytes),d=r.getJSONObject("prior_normal_cleanup_diagnostic");
            yes(r.getString("proof").equals(base.getString("proof"))&&!d.getBoolean("complete")&&d.isNull("observation"),"original proof displaced");
            yes("original_reply_frame_limit".equals(d.getString("omission_reason")),"omission hidden");
        });
        test("no_space_even_for_diagnostic_metadata_preserves_original_reply_bytes",()->{
            ProfileCleanupBrokerHost b=broker();JSONObject base=new JSONObject().put("proof","");
            int overhead=base.toString().getBytes(StandardCharsets.UTF_8).length;
            base.put("proof",new String(new char[BrokerProtocol.MAX_RESPONSE-overhead]).replace('\0','x'));
            byte[] original=base.toString().getBytes(StandardCharsets.UTF_8);
            byte[] actual=b.retainedReply(base,new JSONObject().put("observation","late").put("complete",true));
            yes(original.length==BrokerProtocol.MAX_RESPONSE&&Arrays.equals(actual,original),"optional diagnostic broke existing full frame");
        });
        test("same_pair_consumer_still_refuses_one_three_and_unequal_records",()->{
            ProfileCleanupBrokerHost b=broker();b.io.leafThrows=true;b.closeResult();
            byte[] line=capture(b::publishTerminal);JSONObject terminal=object(line);
            byte[] two=new byte[line.length*2];System.arraycopy(line,0,two,0,line.length);System.arraycopy(line,0,two,line.length,line.length);
            yes(RetainedPairHost.accepts(two,terminal),"equal pair refused");
            yes(!RetainedPairHost.accepts(line,terminal),"one record incorrectly grants original ACK");
            byte[] three=new byte[line.length*3];for(int i=0;i<3;i++)System.arraycopy(line,0,three,i*line.length,line.length);
            yes(!RetainedPairHost.accepts(three,terminal),"three records accepted");
            two[two.length-3]=(byte)'x';yes(!RetainedPairHost.accepts(two,terminal),"unequal pair accepted");
        });
        if(!args[1].isEmpty())test("actual_ce5d_two_different_original_records_remain_rejected",()->{
            byte[] raw=Files.readAllBytes(Paths.get(args[1]));
            yes(raw.length==11334&&ProfileIdentity.sha(raw).equals("41dc7715aa7e7516a56bac7737dbb6c9a4a2ef621bfc5414e00c57c311d14b9f"),"actual original bytes changed");
            JSONObject[] rows=records(raw);yes(!same(rows[0],rows[1]),"actual difference disappeared");
            yes(!RetainedPairHost.accepts(raw,rows[0]),"old raw was retroactively accepted");
        });
        System.out.println(new JSONObject().put("schema","hepta.profile-failure-snapshot-host.v1").put("all_pass",failures==0)
            .put("cases",cases).put("case_count",cases.length()).put("assertions",assertions)
            .put("actual_changed_methods_compiled",true).put("full_android_broker_compiled",false)
            .put("framework_binder_clock_and_pipe_ports_synthetic",true).put("phone_operations",0).put("device_qualified",false));
        if(failures!=0)System.exit(1);
    }
}
