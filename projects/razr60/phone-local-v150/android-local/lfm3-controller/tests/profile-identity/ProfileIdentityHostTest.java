package org.trillionnium.hepta.background;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Real immutable contracts/protocol; synthetic identities, no Android/process/phone IO. */
public final class ProfileIdentityHostTest {
    private static final String G="11111111-1111-4111-8111-111111111111";
    private static final String R="22222222-2222-4222-8222-222222222222";
    private static final String T="33333333-3333-4333-8333-333333333333";
    private static final String P="44444444-4444-4444-8444-444444444444";
    private static final String H=repeat('a'),J=repeat('b');
    private static int assertions;
    private static final List<String> cases=new ArrayList<String>();
    interface Check { void run() throws Exception; }
    static String repeat(char c){char[] a=new char[64];Arrays.fill(a,c);return new String(a);}
    static void need(boolean v){assertions++;if(!v)throw new AssertionError("required boundary failed");}
    static void test(String name,Check c)throws Exception{c.run();cases.add(name);}
    static void reject(Check c)throws Exception{try{c.run();}catch(IllegalArgumentException expected){assertions++;return;}throw new AssertionError("invalid identity admitted");}
    static void refused(String code,Check c)throws Exception{try{c.run();}catch(BrokerProtocol.Refusal e){need(code.equals(e.code));return;}throw new AssertionError("expected "+code);}
    static Map<String,String> apks(){Map<String,String> x=new LinkedHashMap<String,String>();x.put("base",H);x.put("split:feature",J);return x;}
    static Set<String> signers(){return new TreeSet<String>(Arrays.asList(H,J));}
    static ProfileTarget target(int user,long serial){return new ProfileTarget(new ProfileIdentity(user,serial,0,ProfileIdentity.MANAGED),user*100000+10367,ProfileTarget.CTRIP,ProfileTarget.CTRIP+"/ctrip.android.view.SplashActivity",1779,apks(),signers());}
    static String malformed(ProfileTarget t,String kind)throws Exception{
        ByteArrayOutputStream b=new ByteArrayOutputStream();DataOutputStream o=new DataOutputStream(b);
        o.writeUTF(ProfileTarget.SCHEMA);o.writeInt(t.profile.userId);o.writeLong(t.profile.serial);o.writeInt(0);o.writeUTF(ProfileIdentity.MANAGED);
        o.writeInt(t.fullUid);o.writeUTF(t.packageName);o.writeUTF(t.component);o.writeLong(t.versionCode);
        if("apk_count".equals(kind)){o.writeInt(33);}else{
            o.writeInt(2);
            if("apk_order".equals(kind)){o.writeUTF("split:feature");o.writeUTF(J);o.writeUTF("base");o.writeUTF(H);}
            else{o.writeUTF("base");o.writeUTF(H);o.writeUTF("duplicate_apk".equals(kind)?"base":"split:feature");o.writeUTF(J);}
            o.writeInt(2);o.writeUTF("signer_order".equals(kind)?J:H);o.writeUTF("duplicate_signer".equals(kind)?H:("signer_order".equals(kind)?H:J));
            if("trailing".equals(kind))o.writeByte(1);
        }
        o.flush();return Base64.getUrlEncoder().withoutPadding().encodeToString(b.toByteArray());
    }
    static String[] config(ProfileTarget t){return new String[]{"--socket","hepta-bg-"+G,"--owner-uid","10245","--generation",G,"--allowed-packages",t.packageName,"--ttl-ms","540000","--expires-elapsed-ms","600000","--profile-target",t.wire()};}
    static String request(ProfileTarget t,String op){return "{\"version\":2,\"request_id\":\""+R+"\",\"generation\":\""+G+"\",\"op\":\""+op+"\",\"deadline_elapsed_ms\":2000,\"target_sha256\":\""+t.sha256+"\""+("window".equals(op)?",\"package\":\""+t.packageName+"\",\"window_id\":17,\"task_id\":1234":"")+"}";}
    static BrokerProtocol.Request parse(String s)throws Exception{return BrokerProtocol.Request.parse(s.getBytes(StandardCharsets.UTF_8));}
    public static void main(String[] args)throws Exception{
        final ProfileTarget t=target(10,20),otherSerial=target(10,21),otherUser=target(11,20);
        test("canonical_roundtrip",()->{ProfileTarget read=ProfileTarget.fromWire(t.wire());need(t.same(read));need(t.sha256.equals(read.sha256));need(t.apkSetSha256.equals(read.apkSetSha256));});
        test("source_maps_are_copied_and_exposure_immutable",()->{Map<String,String> m=apks();Set<String> ss=signers();ProfileTarget x=new ProfileTarget(t.profile,t.fullUid,t.packageName,t.component,t.versionCode,m,ss);m.clear();ss.clear();need(x.same(t));try{x.apkHashes.put("base",J);throw new AssertionError();}catch(UnsupportedOperationException ok){assertions++;}try{x.evidence().put("grants_action_authority",true);throw new AssertionError();}catch(UnsupportedOperationException ok){assertions++;}});
        test("serial_reuse_changes_identity",()->{need(!t.same(otherSerial));need(!t.profile.same(otherSerial.profile));});
        test("same_appid_other_user_not_same_installation",()->{need(t.fullUid%100000==otherUser.fullUid%100000);need(!t.same(otherUser));});
        test("user0_not_managed_target",()->reject(()->new ProfileIdentity(0,20,0,ProfileIdentity.MANAGED)));
        test("different_parent_not_admitted",()->reject(()->new ProfileIdentity(10,20,1,ProfileIdentity.MANAGED)));
        test("secondary_user_type_not_profile",()->reject(()->new ProfileIdentity(10,20,0,"android.os.usertype.full.SECONDARY")));
        test("uid_from_other_user_not_admitted",()->reject(()->new ProfileTarget(t.profile,otherUser.fullUid,t.packageName,t.component,t.versionCode,apks(),signers())));
        test("parent_rewritten_accessibility_uid_not_full_uid",()->reject(()->new ProfileTarget(t.profile,10367,t.packageName,t.component,t.versionCode,apks(),signers())));
        test("first_version_is_ctrip_only",()->reject(()->new ProfileTarget(t.profile,t.fullUid,"com.example.other","com.example.other/Main",1,apks(),signers())));
        for(final String kind:Arrays.asList("duplicate_apk","duplicate_signer","apk_order","signer_order","trailing","apk_count"))test("wire_"+kind+"_refused",()->reject(()->ProfileTarget.fromWire(malformed(t,kind))));
        test("padding_not_canonical",()->reject(()->ProfileTarget.fromWire(t.wire()+"=")));
        test("truncated_wire_refused",()->reject(()->ProfileTarget.fromWire(t.wire().substring(0,t.wire().length()-8))));
        final WindowOwnership w=new WindowOwnership(t,G,7,17,1234,1200,T,P,10,20,t.fullUid,1000,5000);
        test("window_roundtrip_is_data_without_action_authority",()->{WindowOwnership x=WindowOwnership.fromWire(w.wire(),t);x.requireMatches(t,G,7,17,1234,1001);need(x.sha256.equals(w.sha256));need(Boolean.FALSE.equals(x.evidence().get("grants_action_authority")));need(Boolean.FALSE.equals(x.evidence().get("serialized_token_is_authority")));});
        test("window_serial_mismatch_refused",()->reject(()->WindowOwnership.fromWire(w.wire(),otherSerial)));
        test("window_user_mismatch_refused",()->reject(()->WindowOwnership.fromWire(w.wire(),otherUser)));
        test("window_actual_parent_uid_refused",()->reject(()->new WindowOwnership(t,G,7,17,1234,1200,T,P,10,20,10367,1000,5000)));
        test("window_main_display_refused",()->reject(()->new WindowOwnership(t,G,0,17,1234,1200,T,P,10,20,t.fullUid,1000,5000)));
        test("window_root_not_leaf_refused",()->reject(()->new WindowOwnership(t,G,7,17,1200,1200,T,P,10,20,t.fullUid,1000,5000)));
        test("window_ttl_bounded",()->reject(()->new WindowOwnership(t,G,7,17,1234,1200,T,P,10,20,t.fullUid,1000,11001)));
        test("window_at_expiry_refused",()->reject(()->w.requireMatches(t,G,7,17,1234,5000)));
        test("window_other_observed_task_refused",()->reject(()->w.requireMatches(t,G,7,17,1235,1001)));
        final BrokerProtocol.Config cfg=BrokerProtocol.Config.parse(config(t));
        test("profile_config_separates_owner_and_target_uid",()->{need(cfg.ownerUid==10245);need(cfg.profileTarget.fullUid==1010367);});
        test("profile_window_exact_nine_field_contract",()->{BrokerProtocol.Request q=parse(request(t,"window"));q.authenticate(cfg,10245);need(q.windowId==17&&q.observedTaskId==1234);need(q.version==2&&q.profileTargetSha256.equals(t.sha256));q.checkDeadline(1000,600000);});
        test("profile_peer_cannot_be_target_full_uid",()->refused("CALLER_UID_MISMATCH",()->parse(request(t,"state")).authenticate(cfg,t.fullUid)));
        test("profile_config_owner_stays_user0",()->{String[] c=config(t);c[3]=Integer.toString(t.fullUid);refused("OWNER_USER_UNSUPPORTED",()->BrokerProtocol.Config.parse(c));});
        test("profile_wire_digest_not_current_serial",()->refused("PROFILE_SCOPE_MISMATCH",()->parse(request(otherSerial,"state")).authenticate(cfg,10245)));
        test("profile_request_cannot_drop_scope",()->refused("REQUEST_FIELDS",()->parse(request(t,"state").replace(",\"target_sha256\":\""+t.sha256+"\"",""))));
        test("legacy_request_not_admitted_to_profile",()->{String s="{\"version\":1,\"request_id\":\""+R+"\",\"generation\":\""+G+"\",\"op\":\"state\",\"deadline_elapsed_ms\":2000}";refused("PROFILE_SCOPE_MISMATCH",()->parse(s).authenticate(cfg,10245));});
        test("profile_fixed_intent_has_no_user0_fallback",()->refused("PROFILE_FIXED_INTENT_NOT_ALLOWED",()->parse(request(t,"notes.create"))));
        test("profile_window_extra_authority_field_refused",()->refused("REQUEST_FIELDS",()->parse(request(t,"window").replace("}",",\"display_id\":0}"))));
        StringBuilder names=new StringBuilder();for(String name:cases){if(names.length()>0)names.append(',');names.append('"').append(name).append('"');}
        String result="{\"schema\":\"hepta.profile-identity-host-tests.v1\",\"all_pass\":true,\"cases\":"+cases.size()+",\"assertions\":"+assertions+",\"case_names\":["+names+"],\"android_runtime\":false,\"live_broker_authority_tested\":false,\"phone_actions\":0}";
        Files.write(Paths.get(args[0]),(result+"\n").getBytes(StandardCharsets.UTF_8));System.out.println(result);
    }
}
