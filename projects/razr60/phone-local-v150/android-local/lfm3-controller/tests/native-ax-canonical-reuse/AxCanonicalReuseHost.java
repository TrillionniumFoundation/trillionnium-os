package org.trillionnium.hepta.local;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.json.JSONObject;

/** Calls the whole production capture class. Fixture preparation reuses the
 * unchanged Xiaomi/Ctrip host factories; it creates no Android or effect authority. */
public final class AxCanonicalReuseHost {
    private static final List<Map<String,Object>> cases=new ArrayList<Map<String,Object>>();
    private static int assertions;
    private static Path out;
    private static Field counter;
    private interface Work {void run()throws Exception;}
    private static void yes(boolean value){assertions++;if(!value)throw new AssertionError("false assertion");}
    private static String repeat(char c,int count){char[] chars=new char[count];Arrays.fill(chars,c);return new String(chars);}
    @SuppressWarnings("unchecked") private static Map<String,Object> copy(Map<String,Object> value){
        return (Map<String,Object>)copyValue(value);
    }
    // Preserve explicit null keys and original integer carriers in the host fixture.
    private static Object copyValue(Object value){
        if(value instanceof Map){Map<String,Object> result=new LinkedHashMap<String,Object>();
            for(Map.Entry<?,?> e:((Map<?,?>)value).entrySet())result.put((String)e.getKey(),copyValue(e.getValue()));
            return result;
        }
        if(value instanceof List){List<Object> result=new ArrayList<Object>();
            for(Object item:(List<?>)value)result.add(copyValue(item));return result;
        }
        return value;
    }
    @SuppressWarnings("unchecked") private static Map<String,Object> object(Map<String,Object> value,String key){
        return (Map<String,Object>)value.get(key);
    }
    private static void setFixture(String name,Object value)throws Exception{
        Field field=NativeXiaomiSearchInputHostTest.class.getDeclaredField(name);field.setAccessible(true);field.set(null,value);
    }
    private static void resetCount()throws Exception{if(counter!=null)counter.setInt(null,0);}
    private static int count()throws Exception{return counter==null?-1:counter.getInt(null);}
    private static byte[] bytes(String kind,Map<String,Object> receipt){
        if(ObservationCaptureEvidence.NATIVE_AX.equals(kind))return ObservationCaptureEvidence.nativeAxBytes(receipt);
        if(ObservationCaptureEvidence.NATIVE_AX_FORM_HISTORY.equals(kind))return ObservationCaptureEvidence.nativeAxFormHistoryBytes(receipt);
        if(ObservationCaptureEvidence.NATIVE_AX_INPUT_HISTORY.equals(kind))return ObservationCaptureEvidence.nativeAxInputHistoryBytes(receipt);
        throw new AssertionError("unknown test capture kind");
    }
    private static ObservationCaptureEvidence seal(String kind,Map<String,Object> receipt,byte[] persisted,String hash){
        if(ObservationCaptureEvidence.NATIVE_AX.equals(kind))return ObservationCaptureEvidence.fromSealedNativeAx(receipt,persisted,hash);
        if(ObservationCaptureEvidence.NATIVE_AX_FORM_HISTORY.equals(kind))return ObservationCaptureEvidence.fromSealedNativeAxFormHistory(receipt,persisted,hash);
        if(ObservationCaptureEvidence.NATIVE_AX_INPUT_HISTORY.equals(kind))return ObservationCaptureEvidence.fromSealedNativeAxInputHistory(receipt,persisted,hash);
        throw new AssertionError("unknown test capture kind");
    }
    private static void record(String name,Map<String,Object> detail){
        for(Map<String,Object> old:cases)if(name.equals(old.get("name")))throw new AssertionError("duplicate case");
        detail.put("name",name);detail.put("passed",true);cases.add(detail);
    }
    private static void negative(String name,Work work)throws Exception{
        String reason=null;try{work.run();}catch(IllegalArgumentException expected){reason=expected.getMessage();}
        yes(reason!=null);Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("refusal",reason);record(name,row);
    }
    private static void positive(String name,String kind,Map<String,Object> receipt)throws Exception{
        resetCount();byte[] raw=bytes(kind,receipt);int prewrite=count();
        String hash=ObservationCaptureEvidence.hash(raw);
        ObservationCaptureEvidence capture=seal(kind,receipt,raw,hash);int total=count();
        yes(kind.equals(capture.kind));yes(hash.equals(capture.receiptSha256));
        yes(Boolean.FALSE.equals(capture.evidence().get("grants_action_authority")));
        yes(Boolean.FALSE.equals(capture.evidence().get("business_completion_verified")));
        yes(((Number)capture.evidence().get("receipt_bytes")).intValue()==raw.length);
        String file=name+".canonical.json";Files.write(out.resolve(file),raw);
        Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("kind",kind);row.put("bytes",raw.length);row.put("sha256",hash);
        row.put("canonical_file",file);row.put("full_receipt_canonical_calls_prewrite",prewrite);
        row.put("full_receipt_canonical_calls_roundtrip",total);record(name,row);
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=2)throw new IllegalArgumentException("fixture and output directory required");
        out=Paths.get(args[1]);
        try{counter=ObservationCaptureEvidence.class.getDeclaredField("hostFullReceiptCanonicalCalls");counter.setAccessible(true);}
        catch(NoSuchFieldException uninstrumented){counter=null;}
        JSONObject fixture=new JSONObject(new String(Files.readAllBytes(Paths.get(args[0])),StandardCharsets.UTF_8));
        setFixture("fixture",fixture);
        JSONObject ax=NativeXiaomiSearchInputHostTest.source("a57e1dedb06a4e739823379bd472f953-native-ax.json");
        setFixture("ax",ax);
        setFixture("installed",fixture.getJSONObject("profile_target_from_original_prompt").getString("apk_set_sha256"));
        final Map<String,Object> ordinary=ax.toMap();
        Map<String,Object> input=NativeXiaomiSearchInputHostTest.history(false).toMap();
        Map<String,Object> form=NativeXiaomiSearchInputHostTest.history(true).toMap();
        List<Map<String,Object>> receipts=Arrays.asList(ordinary,input,form);
        List<String> kinds=Arrays.asList(ObservationCaptureEvidence.NATIVE_AX,
                ObservationCaptureEvidence.NATIVE_AX_INPUT_HISTORY,ObservationCaptureEvidence.NATIVE_AX_FORM_HISTORY);
        for(int i=0;i<receipts.size();i++){
            final String kind=kinds.get(i);final Map<String,Object> receipt=receipts.get(i);
            positive("valid_"+kind,kind,receipt);
            final byte[] raw=bytes(kind,receipt);
            final String hash=ObservationCaptureEvidence.hash(raw);
            negative("corrupt_persisted_"+kind,()->{byte[] bad=raw.clone();bad[bad.length-1]=' ';
                seal(kind,receipt,bad,ObservationCaptureEvidence.hash(bad));});
            negative("wrong_digest_"+kind,()->seal(kind,receipt,raw,repeat('0',64)));
            negative("mutation_between_write_and_seal_"+kind,()->{Map<String,Object> bad=copy(receipt);
                bad.put("diagnostic_mutation","after serialized bytes");seal(kind,bad,raw,hash);});
            negative("missing_binding_"+kind,()->{Map<String,Object> bad=copy(receipt);object(bad,"binding").remove("display_id");bytes(kind,bad);});
            negative("wrong_kind_"+kind,()->{Map<String,Object> bad=copy(receipt);bad.put("kind","pixels");bytes(kind,bad);});
        }
        Map<String,Object> unicode=copy(ordinary);
        unicode.put("diagnostic_text","中文手机\u0000\u0001\n\t\"\\\ud83d\ude80");
        unicode.put("diagnostic_numbers",Arrays.asList(Integer.MIN_VALUE,Integer.MAX_VALUE,Long.MIN_VALUE,Long.MAX_VALUE));
        positive("unicode_escapes_and_integral_limits",ObservationCaptureEvidence.NATIVE_AX,unicode);
        Map<String,Object> edge=copy(ordinary);edge.put("diagnostic_padding","");
        int remaining=ObservationCaptureEvidence.MAX_RECEIPT_BYTES-bytes(ObservationCaptureEvidence.NATIVE_AX,edge).length;
        yes(remaining>0);edge.put("diagnostic_padding",repeat('中',remaining/3)+repeat('x',remaining%3));
        positive("exact_utf8_byte_limit",ObservationCaptureEvidence.NATIVE_AX,edge);
        yes(bytes(ObservationCaptureEvidence.NATIVE_AX,edge).length==ObservationCaptureEvidence.MAX_RECEIPT_BYTES);
        negative("one_utf8_byte_over_limit",()->{Map<String,Object> bad=copy(edge);
            bad.put("diagnostic_padding",bad.get("diagnostic_padding")+"x");bytes(ObservationCaptureEvidence.NATIVE_AX,bad);});
        negative("invalid_utf16",()->{Map<String,Object> bad=copy(ordinary);bad.put("diagnostic_text",String.valueOf((char)0xd800));
            bytes(ObservationCaptureEvidence.NATIVE_AX,bad);});
        Map<String,Object> mutable=copy(ordinary);byte[] original=bytes(ObservationCaptureEvidence.NATIVE_AX,mutable);
        ObservationCaptureEvidence sealed=seal(ObservationCaptureEvidence.NATIVE_AX,mutable,original,ObservationCaptureEvidence.hash(original));
        ObservationCaptureEvidence reference=seal(ObservationCaptureEvidence.NATIVE_AX,ordinary,original,ObservationCaptureEvidence.hash(original));
        object(mutable,"binding").put("task_id",repeat('f',32));original[0]=0;yes(sealed.sameSource(reference));
        record("sealed_maps_and_persisted_bytes_remain_copied",new LinkedHashMap<String,Object>());
        Map<String,Object> report=new LinkedHashMap<String,Object>();
        report.put("schema","hepta.ax-canonical-reuse-cases.v1");report.put("all_pass",true);report.put("cases",cases.size());
        report.put("assertions",assertions);report.put("results",cases);report.put("counter_instrumented_host_copy",counter!=null);
        report.put("android_execution",false);report.put("phone_operations",0);report.put("model_executed",false);
        report.put("business_completion_verified",false);report.put("actual_full_production_capture_class",true);
        report.put("fixtures","original recorded Xiaomi AX plus existing explicit synthetic Ctrip factory; extra mutations are synthetic");
        Files.write(out.resolve("CASES.json"),(new JSONObject(report).toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println("cases="+cases.size()+" assertions="+assertions+" full_production_class=true counter="+(counter!=null));
    }
}
