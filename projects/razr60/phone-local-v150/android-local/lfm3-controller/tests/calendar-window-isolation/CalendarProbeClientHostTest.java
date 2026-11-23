package org.trillionnium.hepta.local;

import android.net.LocalSocket;
import android.os.SystemClock;
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONArray;
import org.json.JSONObject;

/** Complete production BackgroundSession; only Android/socket/clock are host ports.
 * Synthetic response fields test client validation, not broker or ROM qualification. */
public final class CalendarProbeClientHostTest {
    interface Work {void run() throws Exception;}
    interface Change {void apply(JSONObject response,JSONObject probe) throws Exception;}
    static final List<JSONObject> rows=new ArrayList<JSONObject>();
    static final HeptaAccessibilityService.Cancellation LIVE=()->false;
    static int checks;
    static void yes(boolean value,String why){checks++;if(!value)throw new AssertionError(why);}
    static void no(Work work,String why)throws Exception{
        try{work.run();}catch(Exception expected){checks++;return;}
        throw new AssertionError("accepted: "+why);
    }
    static void test(String name,Work work)throws Exception{
        LocalSocket.reset();SystemClock.now=1000000;android.provider.Settings.Global.boot=10;
        android.os.Looper.worker=true;android.system.Os.failUnlink=false;
        int before=checks;JSONObject row=new JSONObject().put("name",name);
        try{work.run();row.put("passed",true);}catch(Throwable error){row.put("passed",false).put("error",error.toString());}
        row.put("assertions",checks-before);rows.add(row);
        System.out.println(row.toString());
    }
    static final class Env implements AutoCloseable {
        final PublicOwnGroupSessionHostTest.Env actual;
        Change change;
        Env(boolean profile)throws Exception{
            actual=new PublicOwnGroupSessionHostTest.Env(profile);actual.active();
            LocalSocket.responder=this::reply;
        }
        byte[] reply(byte[] bytes)throws Exception{
            JSONObject request=BackgroundSessionHostTest.decode(bytes);
            JSONObject response=BackgroundSessionHostTest.decode(actual.reply(bytes));
            JSONObject isolation=new JSONObject().put("schema","hepta.input-channel-isolation-readonly.v1")
                .put("display_id",7).put("full_uid",actual.target.fullUid)
                .put("target_profile_user_id",actual.target.profile.userId)
                .put("accessibility_namespace_user_id",actual.target.profile.parentUserId)
                .put("package",actual.target.packageName).put("accessibility_window_id",request.getInt("window_id"))
                .put("observed_task_id",request.getInt("task_id")).put("actual_window_token_match_count",1)
                .put("cross_display_input_or_window_token_aliases",0).put("grants_dispatch",false).put("input_attempts",0);
            JSONObject life=new JSONObject().put("schema","hepta.window-infos-listener-lifecycle.v1")
                .put("registration_returned",true).put("retired",true).put("unregister_returned",true)
                .put("local_callbacks_drained",true).put("retains_current_census",false)
                .put("register_cache_grants_currentness",false).put("callbacks_in_flight",0)
                .put("callback_arrivals",1L).put("callback_finishes",1L).put("grants_dispatch",false).put("input_attempts",0);
            JSONObject probe=new JSONObject().put("schema","hepta.calendar-window-probe.v1")
                .put("request_id",request.getString("request_id")).put("generation",actual.session.generation)
                .put("target_sha256",actual.target.sha256).put("display_scope_sha256",actual.scope.sha256)
                .put("original_request_deadline_elapsed_ms",request.getLong("deadline_elapsed_ms"))
                .put("probe_deadline_elapsed_ms",request.getLong("deadline_elapsed_ms"))
                .put("entered_elapsed_ms",SystemClock.now).put("read_finished_elapsed_ms",SystemClock.now)
                .put("qualified_elapsed_ms",SystemClock.now).put("qualified",true).put("grants_dispatch",false)
                .put("dispatched",false).put("calendar_date_effect_integrated",false).put("input_attempts",0)
                .put("phase","readonly_window_channel_isolation_verified").put("isolation",isolation)
                .put("listener_lifecycle",life);
            response.put("calendar_window_probe",probe);if(change!=null)change.apply(response,probe);
            return BackgroundSessionHostTest.frame(response.toString().getBytes(StandardCharsets.UTF_8));
        }
        BackgroundSession.CalendarWindowProbeReceipt read(long deadline)throws Exception{
            return actual.session.readCalendarWindowProbe(17,1234,LIVE,deadline);
        }
        public void close()throws java.io.IOException{actual.close();}
    }
    public static void main(String[] args)throws Exception{
        test("actual_root_socket_issues_private_historical_receipt",()->{try(Env e=new Env(true)){
            int before=LocalSocket.connections;BackgroundSession.CalendarWindowProbeReceipt receipt=e.read(SystemClock.now+8000);
            yes(LocalSocket.connections==before+1,"one actual exchange");
            yes(receipt.belongsTo(e.actual.session)&&!receipt.belongsTo(null),"actual instance binding");
            yes(!receipt.grantsDispatch(),"historical receipt cannot dispatch");
            yes(receipt.windowId==17&&receipt.observedTaskId==1234,"window/task binding");
            JSONObject q=BackgroundSessionHostTest.decode(LocalSocket.sent);
            Set<String> keys=new HashSet<String>();for(java.util.Iterator<String> it=q.keys();it.hasNext();)keys.add(it.next());
            yes(keys.equals(new HashSet<String>(Arrays.asList("version","request_id","generation","deadline_elapsed_ms","op","display_scope_sha256","target_sha256","package","window_id","task_id"))),"strict ten-field read request");
            yes(q.getInt("version")==4&&"calendar_probe".equals(q.getString("op")),"dedicated readonly op");
            yes(receipt.requestId.equals(q.getString("request_id")),"actual request id");
            yes(receipt.originalDeadlineElapsedMs==SystemClock.now+4000&&q.getLong("deadline_elapsed_ms")==receipt.originalDeadlineElapsedMs,"4s clipped deadline");
            yes(LocalSocket.events.lastIndexOf("peer")<LocalSocket.events.lastIndexOf("output"),"authenticated peer before bytes");
        }});
        test("receipt_copies_cannot_mutate_private_snapshot_or_change_owner",()->{try(Env e=new Env(true)){
            BackgroundSession.CalendarWindowProbeReceipt receipt=e.read(SystemClock.now+8000);
            receipt.evidence().getJSONObject("calendar_window_probe").put("grants_dispatch",true);
            receipt.requestEvidence().put("task_id",999);
            yes(!receipt.evidence().getJSONObject("calendar_window_probe").getBoolean("grants_dispatch"),"response snapshot immutable");
            yes(receipt.requestEvidence().getInt("task_id")==1234,"request snapshot immutable");
            try(Env other=new Env(true)){yes(!receipt.belongsTo(other.actual.session),"equal-valued different session refused");}
            int sourceConstructors=0;
            for(Constructor<?> constructor:BackgroundSession.CalendarWindowProbeReceipt.class.getDeclaredConstructors())
                if(!constructor.isSynthetic()){sourceConstructors++;yes(Modifier.isPrivate(constructor.getModifiers()),"source receipt constructor private");}
            yes(sourceConstructors==1,"one private source constructor; compiler synthetic accessor is not a source API");
        }});
        test("short_original_deadline_is_not_refreshed",()->{try(Env e=new Env(true)){
            long deadline=SystemClock.now+700;BackgroundSession.CalendarWindowProbeReceipt receipt=e.read(deadline);
            yes(receipt.originalDeadlineElapsedMs==deadline,"caller deadline retained");
            yes(BackgroundSessionHostTest.decode(LocalSocket.sent).getLong("deadline_elapsed_ms")==deadline,"wire deadline clipped");
        }});
        test("main_thread_personal_scope_and_bad_identity_reject_before_rpc",()->{
            try(Env e=new Env(false)){int n=LocalSocket.connections;no(()->e.read(SystemClock.now+8000),"personal session");yes(LocalSocket.connections==n,"no personal rpc");}
            try(Env e=new Env(true)){int n=LocalSocket.connections;android.os.Looper.worker=false;no(()->e.read(SystemClock.now+8000),"main thread");android.os.Looper.worker=true;
                no(()->e.actual.session.readCalendarWindowProbe(-1,1234,LIVE,SystemClock.now+8000),"bad window");
                no(()->e.actual.session.readCalendarWindowProbe(17,0,LIVE,SystemClock.now+8000),"bad task");yes(LocalSocket.connections==n,"no invalid rpc");}
        });
        test("null_cancel_cancelled_and_expired_deadline_reject_before_rpc",()->{try(Env e=new Env(true)){
            int n=LocalSocket.connections;no(()->e.actual.session.readCalendarWindowProbe(17,1234,null,SystemClock.now+8000),"null cancel");
            no(()->e.actual.session.readCalendarWindowProbe(17,1234,()->true,SystemClock.now+8000),"cancelled");
            no(()->e.read(SystemClock.now),"expired original deadline");yes(LocalSocket.connections==n,"no rejected admission rpc");
        }});
        test("nonroot_peer_refuses_before_any_request_bytes",()->{
            for(int peer:new int[]{2000,1000,10123})try(Env e=new Env(true)){
                LocalSocket.events.clear();LocalSocket.sent=new byte[0];LocalSocket.peerUid=peer;int n=LocalSocket.connections;
                no(()->e.read(SystemClock.now+8000),"peer "+peer);yes(LocalSocket.connections==n+1,"one denied connection");
                yes(!LocalSocket.events.contains("output")&&LocalSocket.sent.length==0,"peer refused before bytes");LocalSocket.peerUid=0;
            }
        });
        test("probe_request_generation_scope_target_binding_rejects",()->{
            for(String key:new String[]{"request_id","generation","display_scope_sha256","target_sha256"})try(Env e=new Env(true)){
                e.change=(r,p)->p.put(key,"different");int n=LocalSocket.connections;
                no(()->e.read(SystemClock.now+8000),key);yes(LocalSocket.connections==n+1,"no retry for "+key);
            }
        });
        test("actual_window_profile_namespace_uid_and_alias_binding_rejects",()->{
            for(String key:new String[]{"display_id","full_uid","target_profile_user_id","accessibility_namespace_user_id","accessibility_window_id","observed_task_id","actual_window_token_match_count","cross_display_input_or_window_token_aliases"})try(Env e=new Env(true)){
                e.change=(r,p)->{JSONObject x=p.getJSONObject("isolation");x.put(key,x.getInt(key)+1);};
                no(()->e.read(SystemClock.now+8000),key);
            }
        });
        test("unqualified_dispatched_or_inputful_receipt_cannot_mint",()->{
            for(String key:new String[]{"qualified","grants_dispatch","dispatched","calendar_date_effect_integrated","input_attempts"})try(Env e=new Env(true)){
                e.change=(r,p)->p.put(key,"input_attempts".equals(key)?Integer.valueOf(1):Boolean.valueOf(!"qualified".equals(key)));
                no(()->e.read(SystemClock.now+8000),key);
            }
        });
        test("unregistered_undrained_cached_or_inflight_listener_cannot_mint",()->{
            for(String key:new String[]{"registration_returned","retired","unregister_returned","local_callbacks_drained","retains_current_census","register_cache_grants_currentness","callbacks_in_flight","callback_arrivals","callback_finishes"})try(Env e=new Env(true)){
                e.change=(r,p)->{JSONObject x=p.getJSONObject("listener_lifecycle");
                    if("callbacks_in_flight".equals(key))x.put(key,1);
                    else if("callback_arrivals".equals(key)||"callback_finishes".equals(key))x.put(key,0L);
                    else x.put(key,!x.getBoolean(key));};
                no(()->e.read(SystemClock.now+8000),key);
            }
        });
        test("probe_clocks_and_original_deadline_cannot_be_replaced",()->{
            for(String key:new String[]{"original_request_deadline_elapsed_ms","probe_deadline_elapsed_ms","entered_elapsed_ms","read_finished_elapsed_ms","qualified_elapsed_ms"})try(Env e=new Env(true)){
                e.change=(r,p)->p.put(key,p.getLong(key)+("entered_elapsed_ms".equals(key)||"read_finished_elapsed_ms".equals(key)?-1L:1L));
                no(()->e.read(SystemClock.now+8000),key);
            }
        });
        test("late_or_cancelled_return_never_mints_or_retries",()->{
            try(Env e=new Env(true)){int n=LocalSocket.connections;e.change=(r,p)->SystemClock.now=p.getLong("probe_deadline_elapsed_ms");
                no(()->e.read(SystemClock.now+8000),"late return");yes(LocalSocket.connections==n+1,"no timeout retry");}
            try(Env e=new Env(true)){AtomicBoolean cancel=new AtomicBoolean();int n=LocalSocket.connections;e.change=(r,p)->cancel.set(true);
                no(()->e.actual.session.readCalendarWindowProbe(17,1234,cancel::get,SystemClock.now+8000),"cancel at return");yes(LocalSocket.connections==n+1,"no cancellation retry");}
        });
        test("retired_lease_and_changed_current_public_policy_do_not_mint",()->{
            try(Env e=new Env(true)){BackgroundSessionHostTest.field(e.actual.session,"retired",true);int n=LocalSocket.connections;
                no(()->e.read(SystemClock.now+8000),"retired lease");yes(LocalSocket.connections==n,"no retired exchange");}
            try(Env e=new Env(true)){e.actual.unique="virtual:changed";no(()->e.read(SystemClock.now+8000),"actual policy identity changed");}
        });
        boolean passed=true;JSONArray values=new JSONArray();for(JSONObject row:rows){values.put(row);passed&=row.getBoolean("passed");}
        JSONObject result=new JSONObject().put("schema","hepta.calendar-probe-client-host.v1").put("all_pass",passed)
            .put("cases",rows.size()).put("assertions",checks).put("rows",values)
            .put("actual_full_BackgroundSession",true).put("android_socket_clock_ports",true)
            .put("broker_or_vendor_rom_qualified",false).put("android_input_calls",0).put("phone_actions",0);
        Files.write(Paths.get(args[0]),(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        if(!passed)throw new AssertionError("calendar client case failed");
    }
}
