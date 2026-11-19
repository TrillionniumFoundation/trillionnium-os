package org.trillionnium.hepta.local;

import android.net.LocalSocket;
import java.io.*;
import java.lang.reflect.*;
import org.json.*;
import org.trillionnium.hepta.background.NotesCreateFailureBrokerHostTest;

/** Full production root exchange, accept and close with the original inert socket
 * and Android ports. Failed create remains a failure even when cleanup is known. */
public final class NotesCreateFailureSessionHostTest {
    static int cases,checks;
    interface Work{void run()throws Exception;}
    static void yes(boolean value){checks++;if(!value)throw new AssertionError("failed-create session boundary");}
    static void refuse(Work work)throws Exception{try{work.run();}catch(Exception expected){checks++;return;}throw new AssertionError("invalid failed-create release accepted");}
    static void test(String name,Work work)throws Exception{
        LocalSocket.reset();android.os.SystemClock.now=1000000;android.provider.Settings.Global.boot=10;
        work.run();cases++;System.out.println("PASS "+name);
    }
    static PersonalNotesSessionHostTest.Env initial()throws Exception{
        PersonalNotesSessionHostTest.Env e=new PersonalNotesSessionHostTest.Env();
        PersonalNotesSessionHostTest.field(e.session,"state","INITIAL");
        PersonalNotesSessionHostTest.field(e.session,"displayId",-1);
        PersonalNotesSessionHostTest.call(e.session,"saveJournal",new Class<?>[]{});return e;
    }
    static JSONObject reply(PersonalNotesSessionHostTest.Env e,byte[] bytes)throws Exception{
        return e.reply(bytes,"RELEASED",false).put("error","PUBLIC_SCOPE_DISPLAY_INFORMATION_UNKNOWN")
                .put("dispatched",true).put("public_own_group_readback_wire",JSONObject.NULL)
                .put("personal_notes_cleanup",NotesCreateFailureBrokerHostTest.emptyProof(e.scope));
    }
    static JSONObject create(PersonalNotesSessionHostTest.Env e)throws Exception{
        return (JSONObject)PersonalNotesSessionHostTest.call(e.session,"call",new Class<?>[]{String.class,String.class,int.class},"create",null,3000);
    }
    static void acceptFailure(PersonalNotesSessionHostTest.Env e,JSONObject response)throws Exception{
        refuse(()->PersonalNotesSessionHostTest.call(e.session,"accept",new Class<?>[]{JSONObject.class,boolean.class},response,true));
    }
    static void goodReply(PersonalNotesSessionHostTest.Env e){
        LocalSocket.responder=bytes->{e.context.displays.displays.remove(7);return PersonalNotesSessionHostTest.frame(reply(e,bytes));};
    }
    public static void main(String[] args)throws Exception{
        test("authenticated create failure closes from full real custody proof while preserving ok false",()->{try(PersonalNotesSessionHostTest.Env e=initial()){
            goodReply(e);JSONObject response=create(e);acceptFailure(e,response);int before=LocalSocket.connections;
            BackgroundSession.Cleanup closed=e.session.close();
            yes(closed.known&&e.session.released()&&!e.journal());yes(LocalSocket.connections==before&&e.process.destroyed==0);
            JSONObject historical=(JSONObject)PersonalNotesSessionHostTest.field(e.session,"lastResponse");
            yes(!historical.getBoolean("ok")&&"create".equals(historical.getString("operation"))
                    &&"PUBLIC_SCOPE_DISPLAY_INFORMATION_UNKNOWN".equals(historical.getString("error")));
            yes(!((Boolean)PersonalNotesSessionHostTest.field(e.session,"bootstrapDispatched")));e.intact();
        }});
        test("ordinary success-proof API continues to refuse the failed operation",()->{try(PersonalNotesSessionHostTest.Env e=initial()){
            goodReply(e);JSONObject response=create(e);
            Method method=BackgroundSession.class.getDeclaredMethod("checkedPersonalNotesCleanup",JSONObject.class,
                    org.trillionnium.hepta.background.PublicOwnGroupPolicy.Scope.class,String.class,int.class);method.setAccessible(true);
            refuse(()->method.invoke(null,response,e.scope,e.session.generation,7));
        }});
        test("non-root transport peer is rejected before any request bytes",()->{try(PersonalNotesSessionHostTest.Env e=initial()){
            goodReply(e);LocalSocket.peerUid=2000;refuse(()->create(e));
            yes(LocalSocket.sent.length==0&&PersonalNotesSessionHostTest.field(e.session,"notesCreateFailureRelease")==null);
            LocalSocket.missing=true;yes(!e.session.close().known&&e.journal());
        }});
        test("already ACTIVE session cannot acquire failed-initial-create authority",()->{try(PersonalNotesSessionHostTest.Env e=initial()){
            goodReply(e);PersonalNotesSessionHostTest.field(e.session,"state","ACTIVE");refuse(()->create(e));
            yes(PersonalNotesSessionHostTest.field(e.session,"notesCreateFailureRelease")==null);
        }});
        for(final String field:new String[]{"bootstrapDispatched","profileLaunchAttempted","permissionPreparing"}){
            test("prior "+field+" prevents capability capture",()->{try(PersonalNotesSessionHostTest.Env e=initial()){
                goodReply(e);PersonalNotesSessionHostTest.field(e.session,field,true);refuse(()->create(e));
                yes(PersonalNotesSessionHostTest.field(e.session,"notesCreateFailureRelease")==null);
                LocalSocket.missing=true;yes(!e.session.close().known&&e.journal()&&e.process.destroyed==0);
            }});
            test("later "+field+" prevents cleanup consumption",()->{try(PersonalNotesSessionHostTest.Env e=initial()){
                goodReply(e);acceptFailure(e,create(e));PersonalNotesSessionHostTest.field(e.session,field,true);
                yes(!e.session.close().known&&e.journal()&&e.process.destroyed==0);
            }});
        }
        test("unchanged authenticated reply is mandatory at close",()->{try(PersonalNotesSessionHostTest.Env e=initial()){
            goodReply(e);acceptFailure(e,create(e));JSONObject changed=(JSONObject)PersonalNotesSessionHostTest.field(e.session,"lastResponse");
            changed.put("error","different_failure");yes(!e.session.close().known&&e.journal()&&e.process.destroyed==0);
        }});
        test("actual display absence is mandatory even with complete root proof",()->{try(PersonalNotesSessionHostTest.Env e=initial()){
            LocalSocket.responder=bytes->PersonalNotesSessionHostTest.frame(reply(e,bytes));acceptFailure(e,create(e));
            yes(!e.session.close().known&&e.journal()&&e.process.destroyed==0);
        }});
        test("lost create reply cannot be recovered from process exit or empty display",()->{try(PersonalNotesSessionHostTest.Env e=initial()){
            LocalSocket.responder=bytes->{throw new IOException("lost_create_reply");};refuse(()->create(e));
            e.context.displays.displays.remove(7);e.process.exited=true;LocalSocket.missing=true;
            yes(PersonalNotesSessionHostTest.field(e.session,"notesCreateFailureRelease")==null);
            yes(!e.session.close().known&&e.journal()&&e.process.destroyed==0);
        }});
        for(final String bad:new String[]{"request-id","generation","scope","operation","false-dispatch","active-readback",
                "fixed-intent","launch-policy","owned-task","target-launch","observed-task","pending-task","no-create",
                "one-absence","release-api","live-absence","recent-absence","history","hidden-history","unknown-identity"})
            test("failed-create proof refuses "+bad,()->{try(PersonalNotesSessionHostTest.Env e=initial()){
                LocalSocket.responder=bytes->{JSONObject response=reply(e,bytes);JSONObject proof=response.getJSONObject("personal_notes_cleanup");
                    if("request-id".equals(bad))response.put("request_id","00000000-0000-0000-0000-000000000000");
                    else if("generation".equals(bad))response.put("generation","00000000-0000-0000-0000-000000000000");
                    else if("scope".equals(bad))response.put("display_scope_sha256",new String(new char[64]).replace('\0','0'));
                    else if("operation".equals(bad))response.put("operation","launch");
                    else if("false-dispatch".equals(bad))response.put("dispatched",false);
                    else if("active-readback".equals(bad))response.put("public_own_group_readback_wire","not-retired");
                    else if("fixed-intent".equals(bad))response.put("fixed_intent",new JSONObject());
                    else if("launch-policy".equals(bad))response.put("task_launch_policy",new JSONObject());
                    else if("owned-task".equals(bad))response.put("owned_single_task",new JSONObject());
                    else if("target-launch".equals(bad))proof.put("launch_dispatched",true);
                    else if("observed-task".equals(bad))proof.put("actual_observed_tasks",new JSONArray().put(new JSONObject()));
                    else if("pending-task".equals(bad))proof.put("pending_owned_reads",1);
                    else if("no-create".equals(bad))proof.put("no_display_create_attempted",true);
                    else if("one-absence".equals(bad))proof.put("absence_reads",1);
                    else if("release-api".equals(bad))proof.put("release_api_returned",false);
                    else if("live-absence".equals(bad))proof.put("live_tasks_absent",false);
                    else if("recent-absence".equals(bad))proof.put("all_recents_sections_absent",false);
                    else if("history".equals(bad))proof.put("nonphysical_history_preserved",false);
                    else if("hidden-history".equals(bad))proof.put("nonphysical_hidden_history_preserved",false);
                    else if("unknown-identity".equals(bad))proof.put("identity_unknown",true);
                    response.put("personal_notes_cleanup",proof);return PersonalNotesSessionHostTest.frame(response);
                };
                refuse(()->create(e));yes(PersonalNotesSessionHostTest.field(e.session,"notesCreateFailureRelease")==null);
                LocalSocket.missing=true;yes(!e.session.close().known&&e.journal()&&e.process.destroyed==0);
            }});
        test("unknown failed create never acquires cleanup authority",()->{
            try(PersonalNotesSessionHostTest.Env e=initial()){
                LocalSocket.responder=bytes->{
                    JSONObject response=reply(e,bytes).put("state","CLEANUP_UNKNOWN");
                    JSONObject proof=response.getJSONObject("personal_notes_cleanup");
                    proof.put("cleanup_known",false).put("identity_unknown",true);
                    response.put("personal_notes_cleanup",proof);
                    return PersonalNotesSessionHostTest.frame(response);
                };
                JSONObject response=create(e);acceptFailure(e,response);
                yes("CLEANUP_UNKNOWN".equals(response.getString("state"))&&!response.getBoolean("ok"));
                yes(PersonalNotesSessionHostTest.field(e.session,"notesCreateFailureRelease")==null);
                LocalSocket.missing=true;yes(!e.session.close().known&&e.journal()&&e.process.destroyed==0);
            }
        });
        System.out.println("{\"cases\":"+cases+",\"assertions\":"+checks+",\"passed\":true,\"phone_contacted\":false}");
    }
}
