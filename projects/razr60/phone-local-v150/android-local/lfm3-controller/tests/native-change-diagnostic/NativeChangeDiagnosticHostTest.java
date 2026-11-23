package org.trillionnium.hepta.local;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebDomCanonical;

/** Synthetic failure-metadata boundary only; no native authority or phone operation. */
public final class NativeChangeDiagnosticHostTest {
    private static int assertions,cases;
    private static Method diagnostic;
    private static Constructor<WebNativeObservationChanged> constructor;
    private static void check(boolean condition,String message){
        assertions++;if(!condition)throw new AssertionError(message);
    }
    private static String details(String path,JSONObject before,JSONObject after)throws Exception{
        return (String)diagnostic.invoke(null,path,before,after);
    }
    private static JSONObject row(String text){
        return new JSONObject().put("path","0/1").put("text",text).put("description","")
                .put("visible",true).put("enabled",true).put("bounds",new JSONArray(new int[]{0,0,10,10}))
                .put("input_sha256",JSONObject.NULL);
    }
    private static JSONObject event(String detail,WebObservationTiming.Phase phase,long finish)throws Exception{
        final long[] clock={1};WebObservationTiming timing=new WebObservationTiming("synthetic",10,()->clock[0]);
        WebObservationTiming.Span span=WebObservationTiming.begin(timing,phase,10);
        WebNativeObservationChanged failure=constructor.newInstance("unchanged rejection: ","0/1",detail);
        check(failure.getMessage().equals("unchanged rejection: 0/1"),"original rejection message changed");
        check(failure.nativePath.equals("0/1"),"original native path changed");
        clock[0]=finish;WebObservationTiming.failed(span,failure);
        return timing.snapshot().getJSONArray("spans").getJSONObject(0);
    }
    public static void main(String[] args)throws Exception{
        try{
            diagnostic=WebShoppingObservationStability.class.getDeclaredMethod("nativeChangeDiagnostic",String.class,JSONObject.class,JSONObject.class);
            constructor=WebNativeObservationChanged.class.getDeclaredConstructor(String.class,String.class,String.class);
        }catch(NoSuchMethodException absent){throw new AssertionError("missing bounded private-native change metadata",absent);}
        diagnostic.setAccessible(true);constructor.setAccessible(true);
        final String secretBefore="synthetic-private-before",secretAfter="synthetic-private-after";
        JSONObject before=row(secretBefore),after=row(secretAfter);
        after.put("description","synthetic-private-description").put("visible",false)
                .put("bounds",new JSONArray(new int[]{0,0,10,11}));
        String beforeCanonical=WebDomCanonical.canonical(before),afterCanonical=WebDomCanonical.canonical(after);
        String raw=details("0/1",before,after);JSONObject metadata=new JSONObject(raw);
        check(metadata.getBoolean("available"),"valid change metadata unavailable");
        check(metadata.getJSONArray("changed_fields").toString().equals("[\"bounds\",\"description\",\"text\",\"visible\"]"),"changed field names differ");
        check(metadata.getString("before_canonical_sha256").equals(WebDomCanonical.sha256(before))
                &&metadata.getString("after_canonical_sha256").equals(WebDomCanonical.sha256(after)),"row hashes differ");
        check(!raw.contains(secretBefore)&&!raw.contains(secretAfter)&&!raw.contains("synthetic-private-description"),"text leaked");
        check(!metadata.getBoolean("contains_page_text")&&!metadata.getBoolean("grants_action_capability")&&raw.length()<=4096,"diagnostic scope or bound changed");
        check(beforeCanonical.equals(WebDomCanonical.canonical(before))&&afterCanonical.equals(WebDomCanonical.canonical(after)),"original row mutated");cases++;

        JSONObject nativeRow=row("").put("parent_class","android.view.View").put("package","org.trillionnium.hepta.webhelper")
                .put("window_id",37).put("class","android.view.View").put("view_id","")
                .put("clickable",false).put("editable",false).put("scrollable",false).put("focused",false)
                .put("password",false).put("children",0).put("scroll_actions","[]").put("ime_enter","none");
        JSONObject nativeAfter=new JSONObject(nativeRow.toString());String privateHash=new String(new char[64]).replace('\0','f');
        nativeAfter.put("input_sha256",privateHash);
        JSONObject nativeMetadata=new JSONObject(details("0/1",nativeRow,nativeAfter));
        check(nativeRow.length()==20&&nativeMetadata.getBoolean("available"),"production 20-field namespace unavailable");
        check(nativeMetadata.getJSONArray("changed_fields").toString().equals("[\"input_sha256\"]")
                &&!nativeMetadata.toString().contains(privateHash),"digit-bearing field name lost or its value exposed");cases++;

        JSONObject nullBefore=row(""),nullAfter=row("");nullBefore.put("nullable",JSONObject.NULL);
        check(new JSONObject(details("0/1",nullBefore,nullAfter)).getJSONArray("changed_fields").toString().equals("[\"nullable\"]"),"missing and explicit null conflated");cases++;
        JSONObject integer=row(""),decimal=row("");integer.put("count",1);decimal.put("count",1.0);
        check(new JSONObject(details("0/1",integer,decimal)).getJSONArray("changed_fields").length()==0,"canonical numeric equality changed");cases++;

        JSONObject changed=row("");changed.put("private field name",secretAfter);
        check(!new JSONObject(details("0/1",before,changed)).getBoolean("available"),"unbounded field name admitted");cases++;
        changed=row("");for(int i=0;i<65;i++)changed.put("x"+i,i);
        check(!new JSONObject(details("0/1",before,changed)).getBoolean("available"),"unbounded field count admitted");cases++;
        changed=row("\ud800");String unavailable=details("0/1",before,changed);
        check(!new JSONObject(unavailable).getBoolean("available")&&!unavailable.contains(secretBefore),"canonical failure escaped or leaked");cases++;
        check(!new JSONObject(details("private-path",before,after)).getBoolean("available")
                &&!new JSONObject(details("0/1",null,after)).getBoolean("available"),"invalid input diagnostics admitted");cases++;

        JSONObject fail=event(raw,WebObservationTiming.Phase.NATIVE_DOM_BRACKET,5);
        check(fail.getString("outcome").equals("failed")&&!fail.getBoolean("deadline_exceeded_at_finish"),"original pre-deadline failure changed");
        check(WebDomCanonical.same(metadata,fail.getJSONObject("native_change_diagnostic")),"trace metadata lost");cases++;
        JSONObject expired=event(raw,WebObservationTiming.Phase.NATIVE_DOM_BRACKET,10);
        check(expired.getString("outcome").equals("deadline_expired")&&expired.getBoolean("deadline_exceeded_at_finish"),"fixed deadline changed");cases++;
        check(!event(raw,WebObservationTiming.Phase.NATIVE_READ,5).has("native_change_diagnostic"),"metadata duplicated outside comparison span");cases++;
        check(!event(new String(new char[4097]).replace('\0','x'),WebObservationTiming.Phase.NATIVE_DOM_BRACKET,5).has("native_change_diagnostic"),"constructor bound lost");cases++;
        check(!event("invalid-json",WebObservationTiming.Phase.NATIVE_DOM_BRACKET,5).getJSONObject("native_change_diagnostic").getBoolean("available"),"malformed diagnostic changed failure recording");cases++;

        final long[] time={1};WebObservationTiming timing=new WebObservationTiming("synthetic",100,()->time[0]);
        WebObservationTiming.Span span=WebObservationTiming.begin(timing,WebObservationTiming.Phase.NATIVE_DOM_BRACKET,100);
        WebObservationTiming.failed(span,constructor.newInstance("p","0/1",raw));
        timing.snapshot().getJSONArray("spans").getJSONObject(0).getJSONObject("native_change_diagnostic").put("contains_page_text",true);
        check(!timing.snapshot().getJSONArray("spans").getJSONObject(0).getJSONObject("native_change_diagnostic").getBoolean("contains_page_text"),"snapshot alias escaped");cases++;
        WebNativeObservationChanged legacy=new WebNativeObservationChanged("old ","0/1");
        check(legacy.getMessage().equals("old 0/1")&&legacy.nativePath.equals("0/1"),"old constructor changed");cases++;
        System.out.println(new JSONObject().put("schema","hepta.native-change-diagnostic-host.v1").put("all_pass",true)
                .put("cases",cases).put("assertions",assertions).put("phone_actions",0)
                .put("synthetic_metadata_and_timing_boundaries",true).put("native_authority_tested_here",false));
    }
}
