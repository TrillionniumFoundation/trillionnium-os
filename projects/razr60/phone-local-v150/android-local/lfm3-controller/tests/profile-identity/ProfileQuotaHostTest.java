package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

/** Actual bounded Receipts and authentication; synthetic identities, no Android IO. */
public final class ProfileQuotaHostTest {
    static final String G="11111111-1111-4111-8111-111111111111";
    static final byte[] OK="accepted".getBytes(StandardCharsets.UTF_8);
    static int assertions;
    static final List<String> cases=new ArrayList<String>();
    interface Check {void run()throws Exception;}
    static void need(boolean value){assertions++;if(!value)throw new AssertionError("quota boundary failed");}
    static void test(String name,Check check)throws Exception{check.run();cases.add(name);}
    static void refusal(String code,Check check)throws Exception{
        try{check.run();}catch(BrokerProtocol.Refusal error){need(code.equals(error.code));return;}
        throw new AssertionError("expected "+code);
    }
    static ProfileTarget target(){
        char[] a=new char[64];Arrays.fill(a,'a');String h=new String(a);
        return new ProfileTarget(new ProfileIdentity(10,20,0,ProfileIdentity.MANAGED),1010367,
            ProfileTarget.CTRIP,ProfileTarget.CTRIP+"/ctrip.android.view.SplashActivity",1779,
            Collections.singletonMap("base",h),Collections.singleton(h));
    }
    static BrokerProtocol.Config config(int version)throws Exception{
        List<String> args=new ArrayList<String>(Arrays.asList("--socket","hepta-bg-"+G,"--owner-uid","10245",
            "--generation",G,"--allowed-packages",ProfileTarget.CTRIP,"--ttl-ms","540000","--expires-elapsed-ms","600000"));
        if(version==2)args.addAll(Arrays.asList("--profile-target",target().wire()));
        return BrokerProtocol.Config.parse(args.toArray(new String[0]));
    }
    static BrokerProtocol.Request request(int version,int index,String op,long deadline)throws Exception{
        String id=UUID.nameUUIDFromBytes(("quota-"+index).getBytes(StandardCharsets.UTF_8)).toString();
        String raw="{\"version\":"+version+",\"request_id\":\""+id+"\",\"generation\":\""+G
            +"\",\"deadline_elapsed_ms\":"+deadline+",\"op\":\""+op+"\""
            +(version==2?",\"target_sha256\":\""+target().sha256+"\"":"")+"}";
        return BrokerProtocol.Request.parse(raw.getBytes(StandardCharsets.UTF_8));
    }
    static void filled(int version,int maximum)throws Exception{
        final BrokerProtocol.Receipts receipts=new BrokerProtocol.Receipts();
        final BrokerProtocol.Config cfg=config(version);
        for(int i=0;i<maximum-1;i++){
            BrokerProtocol.Request q=request(version,i,"state",2000);q.authenticate(cfg,10245);
            if(receipts.replay(q)!=null)throw new AssertionError("new request already replayed");
            receipts.remember(q,OK);
        }
        final BrokerProtocol.Request next=request(version,maximum,"state",2000);
        test("v"+version+"_ordinary_reserved_close_slot",()->refusal("SESSION_REQUEST_LIMIT",()->receipts.replay(next)));
        test("v"+version+"_remember_enforces_same_limit",()->refusal("SESSION_REQUEST_LIMIT",()->receipts.remember(next,OK)));
        final BrokerProtocol.Request close=request(version,maximum+1,"close",2000);
        test("v"+version+"_close_fills_exact_final_slot",()->{
            close.authenticate(cfg,10245);need(receipts.replay(close)==null);receipts.remember(close,OK);
            need(Arrays.equals(OK,receipts.replay(close)));
        });
        test("v"+version+"_second_close_cannot_exceed_cap",()->{
            BrokerProtocol.Request extra=request(version,maximum+2,"close",2000);
            refusal("SESSION_REQUEST_LIMIT",()->receipts.replay(extra));
            refusal("SESSION_REQUEST_LIMIT",()->receipts.remember(extra,OK));
        });
        test("v"+version+"_first_receipt_not_evicted_and_copy_isolated",()->{
            BrokerProtocol.Request first=request(version,0,"state",2000);
            byte[] r=receipts.replay(first);r[0]='x';need(Arrays.equals(OK,receipts.replay(first)));
        });
        test("v"+version+"_conflict_refused_after_full_capacity",()->{
            refusal("REQUEST_ID_REUSED",()->receipts.replay(request(version,0,"close",2000)));
            refusal("REQUEST_ID_REUSED",()->receipts.replay(request(version,0,"state",2001)));
            refusal("REQUEST_ALREADY_RECORDED",()->receipts.remember(request(version,0,"state",2000),OK));
        });
        test("v"+version+"_unauthenticated_replay_still_rejected",()->{
            BrokerProtocol.Request first=request(version,0,"state",2000);
            refusal("CALLER_UID_MISMATCH",()->{first.authenticate(cfg,0);receipts.replay(first);});
            refusal("PROFILE_SCOPE_MISMATCH",()->{BrokerProtocol.Request other=request(version==1?2:1,0,"state",2000);other.authenticate(cfg,10245);receipts.replay(other);});
        });
    }
    public static void main(String[] args)throws Exception{
        filled(1,128);System.out.println("legacy_quota_completed");filled(2,512);
        StringBuilder names=new StringBuilder();for(String name:cases){if(names.length()>0)names.append(',');names.append('"').append(name).append('"');}
        String result="{\"schema\":\"hepta.profile-request-quota-host.v1\",\"all_pass\":true,\"cases\":"+cases.size()
            +",\"assertions\":"+assertions+",\"legacy_cap\":128,\"profile_cap\":512,\"close_slots_reserved\":1"
            +",\"case_names\":["+names+"],\"actual_production_receipts\":true,\"android_runtime\":false,\"phone_actions\":0}";
        Files.write(Paths.get(args[0]),(result+"\n").getBytes(StandardCharsets.UTF_8));System.out.println(result);
    }
}
