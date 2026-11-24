package org.trillionnium.hepta.background;

import android.app.ActivityTaskManager.RootTaskInfo;
import android.os.Binder;
import android.os.SystemClock;
import android.window.WindowContainerToken;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.json.JSONObject;

/** Actual production adapter/coordinator with complete, inert framework rows.
 * Timing injection is explicit host data, never a claim about failed phone rows. */
public final class NotesPendingRetirementReadHostTest {
    private static int cases,checks;
    private static final List<String> names=new ArrayList<String>();
    interface Work{void run()throws Exception;}
    static void yes(boolean value){checks++;if(!value)throw new AssertionError("pending retirement read boundary");}
    static void test(String name,Work work)throws Exception{work.run();cases++;names.add(name);System.out.println("PASS "+name);}
    static String message(Throwable error){while(error.getCause()!=null)error=error.getCause();return String.valueOf(error.getMessage());}
    static void rejects(String fragment,Work work)throws Exception{
        try{work.run();}catch(Exception error){yes(fragment==null||message(error).contains(fragment));return;}
        throw new AssertionError("unsafe pending read accepted: "+fragment);
    }
    static void drop(NotesTokenRetirementHostTest.World w,int id){w.live.remove(id);w.recent.remove(id);}
    static void finish(NotesTokenRetirementHostTest.World w)throws Exception{
        w.run();w.released();yes(w.forbidden==0);
        yes(w.custody.evidence().get("cleanup_known").equals(Boolean.TRUE));
        yes(w.evidence().getInt("pre_release_absence_reads")>=2);
    }
    static NotesTokenRetirementHostTest.World delayed(final int trigger,final boolean both)throws Exception{
        final NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(2);w.pending=true;
        final int[] reads={0};
        w.afterEffect=x->{
            if(x.calls==1)x.beforeRootRead=y->{if(++reads[0]==trigger){drop(y,300);if(both)drop(y,301);}};
            else drop(x,301);
        };return w;
    }
    public static void main(String[] args)throws Exception{
        for(int position=1;position<=10;position++){
            final int selected=position;
            test("whole_read_restarts_for_owned_disappearance_at_query_"+position,()->{
                NotesTokenRetirementHostTest.World w=delayed(selected,false);finish(w);yes(w.effects.equals(Arrays.asList(300,301)));yes(w.calls==2);
            });
        }
        test("shared_process_removes_both_original_owned_tasks",()->{
            NotesTokenRetirementHostTest.World w=delayed(2,true);finish(w);yes(w.effects.equals(Arrays.asList(300)));yes(w.calls==1);
        });
        test("second_owned_disappears_before_its_final_dispatch_read",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(2);
            w.beforeEffect=x->{if(x.calls==1)drop(x,301);};
            finish(w);yes(w.effects.equals(Arrays.asList(300)));yes(w.calls==1);
            yes(w.evidence().getJSONArray("attempted_task_ids").length()==1);
        });
        test("known_detached_second_recent_only_polls_until_gone",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(2);w.pending=true;final int[] reads={0};
            w.afterEffect=x->{drop(x,300);x.live.remove(301);x.beforeRootRead=y->{if(++reads[0]==7)y.recent.remove(301);};};
            finish(w);yes(w.effects.equals(Arrays.asList(300)));yes(w.calls==1);
        });
        test("persistent_detached_recent_never_becomes_sample_or_action",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(2);w.pending=true;
            w.afterEffect=x->{drop(x,300);x.live.remove(301);};
            rejects("PENDING_DETACHED_RECENT",()->w.run());yes(w.calls==1);yes(w.evidence().getInt("pre_release_absence_reads")==0);
        });
        test("getTasks_owned_state_change_requires_whole_new_read",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1);w.pending=true;final boolean[] changed={false};final int[] reads={0};
            w.afterEffect=x->{
                x.beforeRunningRead=y->{if(!changed[0]){y.live.get(300).isVisible=false;changed[0]=true;}};
                x.beforeRootRead=y->{if(changed[0]&&++reads[0]==5)drop(y,300);};
            };
            finish(w);yes(w.calls==1);yes(changed[0]);
        });
        test("identity_preserving_empty_leaf_then_disappearance",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1);w.pending=true;final int[] reads={0};
            w.afterEffect=x->{x.beforeRootRead=y->{int n=++reads[0];if(n==2)y.empty(y.live.get(300));if(n==8)drop(y,300);};};
            finish(w);yes(w.calls==1);
        });
        test("foreign_global_change_is_sticky_even_if_next_read_would_restore",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1);w.pending=true;final int[] reads={0};
            final RootTaskInfo old=w.live.get(100);
            w.afterEffect=x->x.beforeRootRead=y->{int n=++reads[0];if(n==2)y.live.get(100).numActivities=2;if(n==3)old.numActivities=1;};
            rejects("FOREIGN_GLOBAL_CHANGED",()->w.run());yes(w.calls==1);yes(reads[0]==2);
        });
        test("same_uid_foreign_task_added_is_not_owned_progress",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1);w.pending=true;
            w.afterEffect=x->x.beforeRootRead=y->{y.beforeRootRead=null;y.add(800,8,NotesTokenRetirementHostTest.UID,NotesTokenRetirementHostTest.COMP);};
            rejects(null,()->w.run());yes(w.calls==1);
        });
        test("owned_binder_replacement_is_terminal",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1);w.pending=true;
            w.afterEffect=x->x.beforeRootRead=y->{y.beforeRootRead=null;y.live.get(300).token=new WindowContainerToken(new Binder());};
            rejects("IDENTITY_CHANGED",()->w.run());yes(w.calls==1);
        });
        test("owned_uid_replacement_is_terminal",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1);w.pending=true;
            w.afterEffect=x->x.beforeRootRead=y->{y.beforeRootRead=null;y.live.get(300).effectiveUid++;};
            rejects(null,()->w.run());yes(w.calls==1);
        });
        test("owned_display_migration_is_terminal",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1);w.pending=true;
            w.afterEffect=x->x.beforeRootRead=y->{y.beforeRootRead=null;y.live.get(300).displayId=8;};
            rejects(null,()->w.run());yes(w.calls==1);
        });
        test("owned_user_change_is_terminal",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1);w.pending=true;
            w.afterEffect=x->x.beforeRootRead=y->{y.beforeRootRead=null;y.live.get(300).userId=10;};
            rejects(null,()->w.run());yes(w.calls==1);
        });
        test("owned_activity_growth_is_terminal",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1);w.pending=true;
            w.afterEffect=x->x.beforeRootRead=y->{y.beforeRootRead=null;y.live.get(300).numActivities=2;};
            rejects("ACTIVITY_GREW",()->w.run());yes(w.calls==1);
        });
        test("owned_visibility_reversal_is_terminal",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1);w.pending=true;final int[] reads={0};
            w.afterEffect=x->x.beforeRootRead=y->{int n=++reads[0];if(n==1){y.live.get(300).visible=false;y.live.get(300).isVisible=false;}if(n==2){y.live.get(300).visible=true;y.live.get(300).isVisible=true;}};
            rejects("ACTIVITY_GREW",()->w.run());yes(w.calls==1);
        });
        test("same_binder_owned_reappearance_after_observed_absence_refused",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1);w.pending=true;final int[] reads={0};final RootTaskInfo original=w.live.get(300);
            w.afterEffect=x->x.beforeRootRead=y->{int n=++reads[0];if(n==1)drop(y,300);if(n==2){y.live.put(300,original);y.recent.put(300,original);}};
            rejects("REAPPEARED",()->w.run());yes(w.calls==1);
        });
        test("foreign_binder_change_in_running_census_refused",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1);w.pending=true;
            w.afterEffect=x->x.beforeRunningRead=y->{y.beforeRunningRead=null;y.live.get(100).token=new WindowContainerToken(new Binder());};
            rejects(null,()->w.run());yes(w.calls==1);
        });
        test("physical_change_on_discarded_read_is_terminal",()->{
            NotesTokenRetirementHostTest.World w=delayed(6,false);
            w.afterEffect=x->{x.beforeRootRead=y->{y.beforeRootRead=null;y.physicalSuffix="Window{de u0 ctrip.android.view/ctrip.android.view.Main}";drop(y,300);};};
            rejects(null,()->w.run());yes(w.calls==1);
        });
        test("foreign_history_change_on_discarded_read_is_terminal",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1);w.pending=true;
            w.afterEffect=x->x.beforeRootRead=y->{y.beforeRootRead=null;y.recent.remove(100);drop(y,300);};
            rejects(null,()->w.run());yes(w.calls==1);
        });
        test("original_deadline_is_not_renewed_after_return",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1);w.deadlineAdvance=1400;
            rejects("DEADLINE",()->w.run());yes(w.calls==1);yes(w.evidence().getInt("pre_release_absence_reads")==0);
        });
        test("read_context_unavailable_before_real_call_return",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1);
            w.beforeEffect=x->{try{x.adapter.readAfter(x.observedEffect);}catch(Exception error){throw new IllegalStateException(error);}};
            rejects("RETURNED_EFFECT_REQUIRED",()->w.run());yes(w.calls==0);
        });
        test("returned_effect_cannot_be_replayed_after_retirement_ready",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1);w.run();int calls=w.calls;
            rejects(null,()->w.adapter.remove(w.observedEffect));yes(w.calls==calls);
        });
        test("pending_task_never_disappears_no_retry_of_action",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1);w.pending=true;
            rejects(null,()->w.run());yes(w.calls==1);
        });
        for(String kind:new String[]{"uid","binder","physical","history"}){
            final String selected=kind;
            test("discarded_owned_transition_preserves_observed_foreign_"+kind+"_failure",()->{
                NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1);w.pending=true;final int[] reads={0};
                final RootTaskInfo foreign=w.live.get(100);final int uid=foreign.effectiveUid;
                final WindowContainerToken token=foreign.token;
                w.afterEffect=x->x.beforeRootRead=y->{
                    int n=++reads[0];
                    if(n==2){
                        drop(y,300);
                        if(selected.equals("uid"))foreign.effectiveUid=uid+1;
                        if(selected.equals("binder"))foreign.token=new WindowContainerToken(new Binder());
                        if(selected.equals("physical"))y.physicalSuffix="Window{de u0 ctrip.android.view/ctrip.android.view.Main}";
                        if(selected.equals("history"))y.recent.remove(100);
                    }
                    // Restoration is deliberately later than this batch's full
                    // actual/physical/history observations. It cannot undo them.
                    if(n==7){foreign.effectiveUid=uid;foreign.token=token;y.physicalSuffix="";y.recent.put(100,foreign);}
                };
                rejects(null,()->w.run());yes(w.calls==1);yes(w.evidence().getInt("pre_release_absence_reads")==0);
            });
        }
        test("absolute_deadline_expires_inside_first_full_batch",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1);w.pending=true;final int[] reads={0};
            w.afterEffect=x->x.beforeRootRead=y->{if(++reads[0]==2){drop(y,300);SystemClock.now=y.deadline;}};
            rejects(null,()->w.run());yes(w.calls==1);yes(reads[0]==2);yes(w.evidence().getInt("pre_release_absence_reads")==0);
        });
        test("refusal_diagnostic_identifies_actual_foreign_global_row",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1);w.pending=true;
            w.afterEffect=x->x.beforeRootRead=y->{y.beforeRootRead=null;y.live.get(100).numActivities=2;};
            try{w.run();throw new AssertionError("foreign changed frame accepted");}
            catch(PublicPersonalNotesReader.TaskInfoReadFailure error){
                yes(error.evidence.get("diagnostics_grant_authority").equals(Boolean.FALSE));
                Object changed=error.evidence.get("differing_global_root_ids");
                yes(changed instanceof List&&((List<?>)changed).contains(Integer.valueOf(100)));
                yes(error.evidence.get("effect_returned").equals(Boolean.TRUE));
            }
            yes(w.calls==1);
        });
        System.out.println(new JSONObject().put("schema","hepta.notes-pending-retirement-read-host.v1").put("all_pass",true)
                .put("cases",cases).put("checks",checks).put("case_names",names).put("phone_operations",0)
                .put("actual_failed_phone_before_after_rows_available",false).put("scheduling_inputs_are_authored",true).toString());
    }
}
