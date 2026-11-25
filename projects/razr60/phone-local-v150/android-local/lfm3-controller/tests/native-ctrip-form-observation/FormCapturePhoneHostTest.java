
package org.trillionnium.hepta.local;
import android.graphics.Rect;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;
/** Full production PhoneObservation constructor. Rect and empty frame rows are
 * explicit host values; evidence comes from the real observer-body test output. */
public final class FormCapturePhoneHostTest {
    static int checks;static final List<String> names=new ArrayList<String>();
    interface Body{void run()throws Exception;}
    static void need(boolean ok,String why){checks++;if(!ok)throw new AssertionError(why);}
    static void run(String name,Body body)throws Exception{body.run();names.add(name);System.out.println("PASS "+name);}
    static Map<String,Object> evidence(JSONObject row){
        Map<String,Object> e=row.getJSONObject("capture_evidence").toMap();
        // JSON transports do not preserve Java Integer/Long distinction. The
        // actual producer supplies this primitive long; restore only its type.
        e.put("capture_requested_elapsed_ms",Long.valueOf(((Number)e.get("capture_requested_elapsed_ms")).longValue()));
        return e;
    }
    static PhoneObservation current(Map<String,Object> e,JSONObject artifact)throws Exception{
        long at=((Number)e.get("capture_requested_elapsed_ms")).longValue();String h=artifact.getString("png_sha256");
        return new PhoneObservation(artifact.getString("observation_id"),"ctrip.android.view",at,1224,2992,0,96,
                new Rect(0,0,1224,2992),new File("host-only-not-created.png"),h,h,
                new ObservationState(h,ImeVisibility.HIDDEN),
                ObservedWindowMetadata.observed(new int[]{0,0,1224,2992},"android.widget.FrameLayout",1,0,new int[]{0,0,1224,2992},"ctrip.android.view"),
                false,Collections.<PhoneObservation.Node>emptyList(),null,null,Collections.<String>emptyList(),null,null,null,e);
    }
    static void refused(Map<String,Object> e,JSONObject artifact,String reason)throws Exception{
        boolean no=false;try{current(e,artifact);}catch(IllegalArgumentException expected){
            no=true;if(reason!=null)need(expected.getMessage().equals(reason),"specific constructor refusal: "+expected.getMessage());}
        need(no,"actual constructor must refuse");
    }
    public static void main(String[] args)throws Exception{
        JSONObject source=new JSONObject(new String(Files.readAllBytes(Paths.get(args[0])),StandardCharsets.UTF_8));
        Map<String,JSONObject> rows=new LinkedHashMap<String,JSONObject>();
        JSONArray data=source.getJSONArray("records");
        for(int i=0;i<data.length();i++){JSONObject row=data.getJSONObject(i);String name=row.getString("scenario");
            if(Arrays.asList("post_region_early","post_region_content","post_region_margin").contains(name))rows.put(name,row);}
        need(rows.size()==3,"all actual observer-produced scope cases");
        for(Map.Entry<String,JSONObject> entry:rows.entrySet()){
            final JSONObject row=entry.getValue(),artifact=row.getJSONObject("full_form_artifact");
            run(entry.getKey()+"_actual_PhoneObservation_accepts_compact",()->{
                Map<String,Object> e=evidence(row);PhoneObservation actual=current(e,artifact);
                JSONObject journal=actual.toEvidenceJson(),serialized=journal.getJSONObject("capture");
                need(serialized.toString().getBytes(StandardCharsets.UTF_8).length<=8192,"same actual UTF8 cap");
                need(actual.capturedElapsedMillis==row.getLong("captured_at"),"original captured clock");
                need(journal.getLong("captured_elapsed_ms")==row.getLong("captured_at"),"journal age");
                need(actual.screenshotSha256.equals(artifact.getString("png_sha256")),"original image digest");
                need(!serialized.getBoolean("grants_action_authority")&&!serialized.getBoolean("publication_refreshes_capture_age"),"no grant");
                need(!actual.toJson().has("capture"),"diagnostic metadata not a semantic action grant");
            });
        }
        final JSONObject first=rows.get("post_region_early"),artifact=first.getJSONObject("full_form_artifact");
        run("full_inline_proof_would_exceed_original_cap",()->{
            Map<String,Object> e=evidence(first);e.put("form_pair_comparison",artifact.getJSONObject("pre_encoding").toMap());
            need(new JSONObject(e).toString().getBytes(StandardCharsets.UTF_8).length>8192,"actual full proof exceeds original bound");
            refused(e,artifact,"capture evidence exceeds fixed byte bound");
        });
        run("constructor_still_rejects_UTF8_overflow",()->{
            Map<String,Object> e=evidence(first);StringBuilder large=new StringBuilder();for(int i=0;i<3000;i++)large.append('中');
            e.put("extra_host_text",large.toString());refused(e,artifact,"capture evidence exceeds fixed byte bound");
        });
        run("constructor_still_rejects_age_and_authority_replacement",()->{
            for(String key:Arrays.asList("grants_action_authority","publication_refreshes_capture_age","business_completion_verified")){
                Map<String,Object> e=evidence(first);e.put(key,true);refused(e,artifact,"capture evidence cannot replace observation age or grant authority");
            }
            Map<String,Object> e=evidence(first);e.put("capture_requested_elapsed_ms",Integer.valueOf(((Number)e.get("capture_requested_elapsed_ms")).intValue()));
            refused(e,artifact,"capture evidence cannot replace observation age or grant authority");
        });
        run("complete_artifact_reference_is_frozen_by_actual_constructor",()->{
            Map<String,Object> e=evidence(first);PhoneObservation actual=current(e,artifact);String before=actual.toEvidenceJson().toString();
            e.put("form_pair_comparison",Collections.singletonMap("changed","invalid"));
            need(before.equals(actual.toEvidenceJson().toString()),"caller cannot mutate frozen evidence");
            actual.toEvidenceJson().getJSONObject("capture").put("form_pair_comparison","invalid");
            need(before.equals(actual.toEvidenceJson().toString()),"returned JSON cannot mutate original");
        });
        JSONObject report=new JSONObject().put("schema","hepta.ctrip-form-actual-phone-consumer-host.v1").put("all_pass",true)
                .put("cases",names.size()).put("assertions",checks).put("case_names",names)
                .put("actual_PhoneObservation_full_class",true).put("android_Rect_and_frame_values_synthetic",true)
                .put("phone_operations",0).put("business_completion_verified",false);
        Files.write(Paths.get(args[1]),report.toString(2).getBytes(StandardCharsets.UTF_8));
    }
}
