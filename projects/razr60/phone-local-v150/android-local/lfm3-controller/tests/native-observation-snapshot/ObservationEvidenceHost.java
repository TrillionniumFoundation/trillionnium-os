package org.trillionnium.hepta.local;
import android.graphics.Rect;
import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.json.JSONObject;
/** Full production PhoneObservation and pinned real JSON; only Rect is a value-only Android fixture. */
final class ObservationEvidenceHost {
    private static void check(boolean value,String why){SnapshotChecks.check(value,why);}
    private static Map<String,Object> evidence(){
        Map<String,Object> v=new LinkedHashMap<String,Object>();
        v.put("schema","hepta.observation-capture.v1");v.put("mode","pre_encoding_paired_history");
        v.put("capture_requested_elapsed_ms",Long.valueOf(1000));v.put("published_elapsed_ms",Long.valueOf(1600));
        v.put("capture_age_at_publication_ms",Long.valueOf(600));
        v.put("publication_refreshes_capture_age",false);v.put("grants_action_authority",false);
        v.put("business_completion_verified",false);v.put("fresh_action_validation_required",true);
        return v;
    }
    private static ObservationState state(){return new ObservationState(SnapshotChecks.OWNER,ImeVisibility.HIDDEN);}
    private static ObservedWindowMetadata metadata(){
        return ObservedWindowMetadata.observed(new int[]{0,0,1080,2400},"android.widget.FrameLayout",
            1,0,new int[]{0,0,1080,2400},"fixture");
    }
    private static PhoneObservation legacy(){
        return new PhoneObservation(SnapshotChecks.TASK,SnapshotChecks.APP,1000L,1080,2400,0,7,new Rect(0,0,1080,2400),
            new File("host-only-not-created.png"),SnapshotChecks.OWNER,SnapshotChecks.OWNER,state(),metadata(),false,
            Collections.<PhoneObservation.Node>emptyList());
    }
    private static PhoneObservation current(Map<String,Object> value)throws Exception{
        // Reflection is only a constructor call bridge so the exact R17 class also compiles
        // for the counterfactual. No source is replaced; R17 fails its pipeline case first.
        Constructor<PhoneObservation> c=PhoneObservation.class.getDeclaredConstructor(String.class,String.class,long.class,
            int.class,int.class,int.class,int.class,Rect.class,File.class,String.class,String.class,
            ObservationState.class,ObservedWindowMetadata.class,boolean.class,List.class,String.class,String.class,List.class,
            PhoneObservation.CollectionStats.class,JSONObject.class,String.class,Map.class);
        try{return c.newInstance(SnapshotChecks.TASK,SnapshotChecks.APP,Long.valueOf(1000),Integer.valueOf(1080),Integer.valueOf(2400),
            Integer.valueOf(0),Integer.valueOf(7),new Rect(0,0,1080,2400),new File("host-only-not-created.png"),
            SnapshotChecks.OWNER,SnapshotChecks.OWNER,state(),metadata(),Boolean.FALSE,Collections.<PhoneObservation.Node>emptyList(),
            null,null,Collections.<String>emptyList(),null,null,null,value);}
        catch(InvocationTargetException failure){
            Throwable cause=failure.getCause();if(cause instanceof Exception)throw (Exception)cause;
            if(cause instanceof Error)throw (Error)cause;throw failure;
        }
    }
    private static void refused(Map<String,Object> value)throws Exception{
        boolean rejected=false;try{current(value);}catch(IllegalArgumentException expected){rejected=true;}
        check(rejected,"invalid capture metadata accepted by actual constructor");
    }
    static void run()throws Exception{
        SnapshotChecks.run("actual_observation_legacy_constructor_keeps_age_without_invented_capture",()->{
            PhoneObservation value=legacy();JSONObject json=value.toJson();
            check(value.capturedElapsedMillis==1000L&&json.getLong("captured_elapsed_ms")==1000L,"original capture age lost in evidence");
            check(!json.has("capture"),"legacy constructor invented capture lineage");
            check(json.getJSONArray("nodes").length()==0&&!json.getBoolean("nodes_truncated"),"legacy observed nodes changed");
        });
        SnapshotChecks.run("actual_observation_serializes_history_without_freshness_or_effect_grant",()->{
            PhoneObservation value=current(evidence());JSONObject json=value.toJson(),e=json.getJSONObject("capture");
            check(json.getLong("captured_elapsed_ms")==1000L&&e.getLong("capture_requested_elapsed_ms")==1000L,"publish replaced capture time");
            check(e.getLong("published_elapsed_ms")==1600L&&e.getLong("capture_age_at_publication_ms")==600L,"historical age not preserved");
            check(!e.getBoolean("publication_refreshes_capture_age")&&!e.getBoolean("grants_action_authority")
                &&!e.getBoolean("business_completion_verified")&&e.getBoolean("fresh_action_validation_required"),"evidence acquired authority");
        });
        SnapshotChecks.run("actual_observation_freezes_input_and_returns_independent_json",()->{
            Map<String,Object> v=evidence(),nested=new LinkedHashMap<String,Object>();nested.put("value","before");
            List<Object> list=new ArrayList<Object>();list.add(nested);v.put("fixture_nested_values",list);
            PhoneObservation value=current(v);String original=value.toJson().toString();
            nested.put("value","after");list.add("new");v.put("published_elapsed_ms",Long.valueOf(9000));
            check(original.equals(value.toJson().toString()),"caller mutated frozen observation evidence");
            JSONObject returned=value.toJson();returned.getJSONObject("capture").put("published_elapsed_ms",9000);
            returned.put("captured_elapsed_ms",9000);
            check(original.equals(value.toJson().toString()),"returned JSON changed original observation evidence");
        });
        SnapshotChecks.run("actual_observation_rejects_capture_age_replacement_and_nonlong_time",()->{
            Map<String,Object> v=evidence();v.put("capture_requested_elapsed_ms",Long.valueOf(1600));refused(v);
            v=evidence();v.put("capture_requested_elapsed_ms",Integer.valueOf(1000));refused(v);
        });
        SnapshotChecks.run("actual_observation_rejects_authority_or_age_refresh_flags",()->{
            for(String key:new String[]{"publication_refreshes_capture_age","grants_action_authority","business_completion_verified"}){
                Map<String,Object> v=evidence();v.put(key,true);refused(v);
                v=evidence();v.remove(key);refused(v);
            }
        });
        SnapshotChecks.run("actual_observation_rejects_unknown_capture_schema",()->{
            Map<String,Object> v=evidence();v.put("schema","unexpected");refused(v);
        });
        SnapshotChecks.run("actual_observation_enforces_utf8_evidence_byte_bound",()->{
            Map<String,Object> v=evidence();v.put("fixture_large",SnapshotChecks.repeat('\u4e2d',3000));
            String raw=new JSONObject(v).toString();
            check(raw.length()<8192&&raw.getBytes(StandardCharsets.UTF_8).length>8192,"fixture must distinguish UTF8 bytes from chars");
            refused(v);
        });
    }
}
