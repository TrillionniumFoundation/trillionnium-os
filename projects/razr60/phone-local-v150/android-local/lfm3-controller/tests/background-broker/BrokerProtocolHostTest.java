package org.trillionnium.hepta.background;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/** Actual production protocol logic; no Android IO, display, model, or on-device claims. */
public final class BrokerProtocolHostTest {
    private static final String G = "cd68504a-7fc7-40c3-a1c1-02ed5bcab8bb";
    private static final String I = "abe8fba6-998b-47c9-9df3-362c77357e5b";
    private static final List<String> passed = new ArrayList<String>();
    interface Check { void run() throws Exception; }
    static void test(String name, Check check) throws Exception { check.run(); passed.add(name); }
    static void require(boolean value) { if (!value) throw new AssertionError("requirement failed"); }
    static void refusal(String code, Check check) throws Exception {
        try { check.run(); } catch (BrokerProtocol.Refusal error) { require(code.equals(error.code)); return; }
        throw new AssertionError("expected refusal " + code);
    }
    static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    static String json(String id, String gen, String op, long deadline, String pkg) {
        return "{\"version\":1,\"request_id\":\""+id+"\",\"generation\":\""+gen
            +"\",\"deadline_elapsed_ms\":"+deadline+",\"op\":\""+op+"\""
            +(pkg == null ? "" : ",\"package\":\""+pkg+"\"")+"}";
    }
    static BrokerProtocol.Request request(String op, String pkg) throws Exception {
        return BrokerProtocol.Request.parse(bytes(json(I,G,op,2000,pkg)));
    }
    static String[] args() {
        return new String[] {"--socket","hepta-bg-"+G,"--owner-uid","10245","--generation",G,
            "--allowed-packages","com.motorola.cn.calculator,com.example.notes","--ttl-ms","540000",
            "--expires-elapsed-ms","600000"};
    }
    static java.util.Map<String,Integer> displayConstants(){
        java.util.Map<String,Integer> value=new java.util.LinkedHashMap<String,Integer>();
        value.put("FLAG_TRUSTED",128);value.put("FLAG_OWN_FOCUS",2048);value.put("FLAG_STEAL_TOP_FOCUS_DISABLED",4096);
        value.put("FLAG_SECURE",2);value.put("FLAG_ALWAYS_UNLOCKED",512);return value;
    }
    public static void main(String[] ignored) throws Exception {
        final BrokerProtocol.Config config = BrokerProtocol.Config.parse(args());
        test("display_numeric_policy_validates_runtime_mapping",()->{
            BrokerProtocol.DisplayPolicy value=BrokerProtocol.DisplayPolicy.checked(6272,displayConstants(),2,2);
            require(value.requiredMask==6272&&value.forbiddenMask==514&&value.flags==6272&&value.imeActual==2);
            try{value.constants.put("FLAG_SECURE",1);throw new AssertionError();}catch(UnsupportedOperationException expected){}
        });
        for(int flags:new int[]{128,2176,4224,6274,6784,-1})test("display_required_or_forbidden_bits_refused_"+flags,()->
            refusal("DISPLAY_FLAGS_NOT_ACCEPTED",()->BrokerProtocol.DisplayPolicy.checked(flags,displayConstants(),2,2)));
        test("display_ime_actual_readback_must_match_hide",()->refusal("IME_POLICY_NOT_ACCEPTED",()->BrokerProtocol.DisplayPolicy.checked(6272,displayConstants(),0,2)));
        test("display_mapping_missing_name_refused",()->{java.util.Map<String,Integer> m=displayConstants();m.remove("FLAG_OWN_FOCUS");refusal("DISPLAY_FLAG_CONSTANTS_INVALID",()->BrokerProtocol.DisplayPolicy.checked(6272,m,2,2));});
        test("display_mapping_extra_name_refused",()->{java.util.Map<String,Integer> m=displayConstants();m.put("VIRTUAL_DISPLAY_FLAG_PUBLIC",1);refusal("DISPLAY_FLAG_CONSTANTS_INVALID",()->BrokerProtocol.DisplayPolicy.checked(6272,m,2,2));});
        for(int value:new int[]{0,3,128,-1})test("display_mapping_zero_multibit_alias_negative_refused_"+value,()->{java.util.Map<String,Integer> m=displayConstants();m.put("FLAG_OWN_FOCUS",value);refusal("DISPLAY_FLAG_CONSTANTS_INVALID",()->BrokerProtocol.DisplayPolicy.checked(6272,m,2,2));});

        test("valid_config_has_immutable_exact_scope", () -> {
            require(config.ownerUid == 10245 && config.ttlMs == 540000 && config.expiresElapsedMs == 600000);
            require(config.packages.size() == 2);
            try { config.packages.add("com.foreign.app"); throw new AssertionError(); }
            catch (UnsupportedOperationException expected) { }
        });
        test("duplicate_startup_argument_rejected", () -> { String[] a=args();a[2]="--socket";
            refusal("INVALID_ARGUMENTS",()->BrokerProtocol.Config.parse(a)); });
        test("unknown_startup_argument_rejected", () -> { String[] a=args();a[2]="--command";
            refusal("INVALID_ARGUMENTS",()->BrokerProtocol.Config.parse(a)); });
        test("missing_absolute_expiry_rejected", () -> refusal("INVALID_ARGUMENTS",()->BrokerProtocol.Config.parse(Arrays.copyOf(args(),10))));
        test("root_cannot_be_configured_as_app_owner", () -> { String[] a=args();a[3]="0";
            refusal("OWNER_USER_UNSUPPORTED",()->BrokerProtocol.Config.parse(a)); });
        test("secondary_user_requires_separate_implementation", () -> { String[] a=args();a[3]="1010245";
            refusal("OWNER_USER_UNSUPPORTED",()->BrokerProtocol.Config.parse(a)); });
        test("ttl_above_ten_minutes_rejected", () -> { String[] a=args();a[9]="600001";
            refusal("INVALID_EXPIRY",()->BrokerProtocol.Config.parse(a)); });
        test("package_scope_wildcard_rejected", () -> { String[] a=args();a[7]="com.*";
            refusal("INVALID_PACKAGE_SCOPE",()->BrokerProtocol.Config.parse(a)); });
        test("package_scope_duplicates_rejected", () -> { String[] a=args();a[7]="com.example.notes,com.example.notes";
            refusal("INVALID_PACKAGE_SCOPE",()->BrokerProtocol.Config.parse(a)); });
        test("startup_socket_requires_private_generation_name", () -> { String[] a=args();a[1]="shared-control";
            refusal("INVALID_SOCKET_NAME",()->BrokerProtocol.Config.parse(a)); });
        test("five_operation_requests_parse", () -> {
            for(String op:Arrays.asList("create","state","close")) require(op.equals(request(op,null).operation));
            require("com.example.notes".equals(request("launch","com.example.notes").packageName));
            require("com.example.notes".equals(request("back","com.example.notes").packageName));
        });
        test("exact_app_uid_is_authenticated", () -> request("state",null).authenticate(config,10245));
        test("other_uid_rejected", () -> refusal("CALLER_UID_MISMATCH",()->request("create",null).authenticate(config,10246)));
        test("root_client_has_no_uid_bypass", () -> refusal("CALLER_UID_MISMATCH",()->request("create",null).authenticate(config,0)));
        test("shell_client_has_no_uid_bypass", () -> refusal("CALLER_UID_MISMATCH",()->request("create",null).authenticate(config,2000)));
        test("foreign_generation_rejected", () -> refusal("GENERATION_MISMATCH",()->
            BrokerProtocol.Request.parse(bytes(json(I,I,"state",2000,null))).authenticate(config,10245)));
        test("foreign_package_rejected", () -> refusal("PACKAGE_NOT_ALLOWED",()->request("launch","com.foreign.app").authenticate(config,10245)));
        test("arbitrary_shell_operation_rejected", () -> refusal("OPERATION_NOT_ALLOWED",()->request("exec",null)));
        test("home_operation_rejected", () -> refusal("OPERATION_NOT_ALLOWED",()->request("home",null)));
        test("caller_supplied_display_id_rejected", () -> refusal("REQUEST_FIELDS",()->
            BrokerProtocol.Request.parse(bytes(json(I,G,"state",2000,null).replace("}",",\"display_id\":0}")))));
        test("launch_requires_explicit_package", () -> refusal("REQUEST_FIELDS",()->request("launch",null)));
        test("back_requires_expected_package", () -> refusal("REQUEST_FIELDS",()->request("back",null)));
        test("state_cannot_smuggle_package", () -> refusal("REQUEST_FIELDS",()->request("state","com.example.notes")));
        test("back_foreign_package_rejected", () -> refusal("PACKAGE_NOT_ALLOWED",()->request("back","com.foreign.app").authenticate(config,10245)));
        test("expired_request_rejected", () -> refusal("REQUEST_EXPIRED",()->request("state",null).checkDeadline(2000,5000)));
        test("expired_session_rejected", () -> refusal("SESSION_EXPIRED",()->request("state",null).checkDeadline(1000,1000)));
        test("unbounded_request_deadline_rejected", () -> refusal("REQUEST_DEADLINE_TOO_LONG",()->
            BrokerProtocol.Request.parse(bytes(json(I,G,"state",20000,null))).checkDeadline(1000,30000)));
        test("valid_bounded_deadline", () -> request("state",null).checkDeadline(1000,5000));
        test("duplicate_json_key_rejected", () -> refusal("DUPLICATE_FIELD",()->
            BrokerProtocol.Request.parse(bytes(json(I,G,"state",2000,null).replace("}",",\"op\":\"close\"}")))));
        test("trailing_json_rejected", () -> refusal("TRAILING_JSON",()->BrokerProtocol.Request.parse(bytes(json(I,G,"state",2000,null)+"{}"))));
        test("string_version_rejected", () -> refusal("FIELD_TYPE",()->BrokerProtocol.Request.parse(bytes(json(I,G,"state",2000,null).replace("\"version\":1","\"version\":\"1\"")))));
        test("invalid_utf8_rejected", () -> refusal("INVALID_UTF8",()->BrokerProtocol.Request.parse(new byte[]{(byte)0xc3,0x28})));
        test("zero_frame_rejected", () -> refusal("REQUEST_SIZE",()->BrokerProtocol.readFrame(new ByteArrayInputStream(new byte[4]))));
        test("negative_frame_rejected", () -> refusal("REQUEST_SIZE",()->BrokerProtocol.readFrame(new ByteArrayInputStream(new byte[]{-1,-1,-1,-1}))));
        test("oversize_frame_rejected_before_allocation", () -> {
            ByteArrayOutputStream buffer=new ByteArrayOutputStream();new DataOutputStream(buffer).writeInt(16385);
            refusal("REQUEST_SIZE",()->BrokerProtocol.readFrame(new ByteArrayInputStream(buffer.toByteArray())));
        });
        test("truncated_frame_is_not_a_request", () -> {
            try { BrokerProtocol.readFrame(new ByteArrayInputStream(new byte[]{0,0,0,4,1}));throw new AssertionError(); }
            catch(EOFException expected) { }
        });
        test("frame_round_trip_exact_bytes", () -> {
            byte[] payload=bytes(json(I,G,"state",2000,null));ByteArrayOutputStream b=new ByteArrayOutputStream();
            BrokerProtocol.writeFrame(b,payload);require(Arrays.equals(payload,BrokerProtocol.readFrame(new ByteArrayInputStream(b.toByteArray()))));
        });
        test("response_bound_enforced", () -> refusal("RESPONSE_SIZE",()->BrokerProtocol.writeFrame(new ByteArrayOutputStream(),new byte[65537])));
        test("receipt_replay_returns_recorded_effect_without_execution", () -> {
            BrokerProtocol.Receipts receipts=new BrokerProtocol.Receipts();BrokerProtocol.Request r=request("launch","com.example.notes");
            require(receipts.replay(r)==null);receipts.remember(r,bytes("committed"));
            require(Arrays.equals(bytes("committed"),receipts.replay(r)));
        });
        test("same_id_different_operation_rejected", () -> {
            BrokerProtocol.Receipts receipts=new BrokerProtocol.Receipts();receipts.remember(request("create",null),bytes("ok"));
            refusal("REQUEST_ID_REUSED",()->receipts.replay(request("close",null)));
        });
        test("same_id_extended_deadline_rejected", () -> {
            BrokerProtocol.Receipts receipts=new BrokerProtocol.Receipts();receipts.remember(request("state",null),bytes("ok"));
            refusal("REQUEST_ID_REUSED",()->receipts.replay(BrokerProtocol.Request.parse(bytes(json(I,G,"state",3000,null)))));
        });
        test("receipt_and_request_copies_are_immutable", () -> {
            BrokerProtocol.Receipts receipts=new BrokerProtocol.Receipts();BrokerProtocol.Request r=request("state",null);byte[] b=bytes("ok");
            receipts.remember(r,b);b[0]='x';byte[] result=receipts.replay(r);result[0]='x';
            require(Arrays.equals(bytes("ok"),receipts.replay(r)));
        });
        test("receipt_cap_never_evicts_old_effect_identity", () -> {
            BrokerProtocol.Receipts receipts=new BrokerProtocol.Receipts();BrokerProtocol.Request first=null;
            for(int i=0;i<127;i++) { BrokerProtocol.Request r=BrokerProtocol.Request.parse(bytes(json(UUID.nameUUIDFromBytes(bytes("id"+i)).toString(),G,"state",2000,null)));
                if(i==0)first=r;receipts.remember(r,bytes("ok")); }
            require(Arrays.equals(bytes("ok"),receipts.replay(first)));
            refusal("SESSION_REQUEST_LIMIT",()->receipts.replay(request("state",null)));
            require(receipts.replay(request("close",null))==null);
            receipts.remember(request("close",null),bytes("released"));
            require(Arrays.equals(bytes("released"),receipts.replay(request("close",null))));
        });
        StringBuilder output=new StringBuilder("{\"schema\":\"hepta.background-broker-host-tests.v1\",\"passed\":")
            .append(passed.size()).append(",\"failed\":0,\"android_runtime\":false,\"model_inference\":false,\"phone_operations\":false,\"cases\":[");
        for(int i=0;i<passed.size();i++) {if(i>0)output.append(',');output.append('"').append(passed.get(i)).append('"');}
        System.out.println(output.append("]}").toString());
    }
}
