package org.trillionnium.hepta.local;
import android.graphics.Rect;
import java.io.File;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;
/** Actual full production PhoneObservation; Android Rect is the existing value-only fixture. */
final class ActualAxPhoneChecks {
    private ActualAxPhoneChecks(){}
    private static Map<String,Object> metadata(ObservationCaptureEvidence capture,long at){
        Map<String,Object> value=new LinkedHashMap<String,Object>(capture.evidence());
        value.put("schema","hepta.observation-capture.native-ax.v1");value.put("capture_requested_elapsed_ms",at);return value;
    }
    private static PhoneObservation make(ObservationCaptureEvidence capture,JSONObject b,Map<String,Object> meta,
            File image,String imageHash,long at,String owner)throws Exception{
        String pkg=b.getString("package");int width=b.getInt("width"),height=b.getInt("height"),display=b.getInt("display_id");
        JSONObject selection=new JSONObject().put("mode","background").put("allowed_packages",new JSONArray(Collections.singletonList(pkg)))
                .put("bootstrap_package",pkg).put("bootstrap_source","owner_selected_initial_app").put("bootstrap_model_issued",false)
                .put("home_allowed",false).put("main_display_fallback",false);
        return new PhoneObservation(b.getString("observation_id"),pkg,at,width,height,b.getInt("rotation"),b.getInt("window_id"),
                new Rect(b.getInt("left"),b.getInt("top"),b.getInt("right"),b.getInt("bottom")),image,imageHash,
                b.getString("observation_state_sha256"),new ObservationState(b.getString("app_tree_sha256"),ImeVisibility.HIDDEN),
                ObservedWindowMetadata.observed(new int[]{0,0,width,height},"android.widget.FrameLayout",1,display,new int[]{0,0,width,height},pkg),
                false,Collections.<PhoneObservation.Node>emptyList(),b.getString("background_generation"),pkg,Collections.singletonList(pkg),
                new PhoneObservation.CollectionStats(1536,512,6144,3,0,0,0,0,0,0,0),selection,owner,meta,null,capture);
    }
    private interface Attempt {void run()throws Exception;}
    private static void refused(Attempt attempt)throws Exception{
        boolean yes=false;try{attempt.run();}catch(IllegalArgumentException expected){yes=true;}
        SnapshotChecks.check(yes,"actual PhoneObservation accepted an incompatible capture");
    }
    static void runRecheck(final ObservationCaptureEvidence original,final ObservationCaptureEvidence capture,
            final JSONObject b,final Map<String,Object> actual)throws Exception{
        final long at=b.getLong("captured_elapsed_ms");final String owner=b.getString("owner_sha256");
        SnapshotChecks.run("actual_phone_publication_witness_consumed_with_original_identity",()->{
            PhoneObservation observed=make(capture,b,actual,null,null,at,owner);
            SnapshotChecks.check(observed.id.equals(b.getString("observation_id"))&&observed.capturedElapsedMillis==at,
                    "C refreshed original capture identity");
            SnapshotChecks.check(observed.toEvidenceJson().getJSONObject("capture").has("publication_recheck"),
                    "actual C witness not retained by full PhoneObservation");
        });
        SnapshotChecks.run("actual_phone_rejects_C_metadata_without_typed_complete_witness",()->{
            refused(()->make(original,b,actual,null,null,at,owner));
        });
        SnapshotChecks.run("actual_phone_rejects_missing_C_witness_metadata",()->{
            Map<String,Object> meta=new LinkedHashMap<String,Object>(actual);meta.remove("publication_recheck");
            refused(()->make(capture,b,meta,null,null,at,owner));
        });
        for(final String key:new String[]{"original_receipt_sha256","original_observation_id","original_captured_elapsed_ms",
                "receipt_persisted_elapsed_ms","graph_started_elapsed_ms","graph_completed_elapsed_ms",
                "complete_census_endpoint_elapsed_ms","complete_census_sha256","start_watermark","completed_watermark",
                "full_identity_nodes_windows_profile_owner_equal","receipt_rewritten"}){
            SnapshotChecks.run("actual_phone_rejects_tampered_C_"+key,()->{
                Map<String,Object> meta=new LinkedHashMap<String,Object>(actual);
                Map<String,Object> proof=new JSONObject((Map<?,?>)meta.get("publication_recheck")).toMap();
                Object value=proof.get(key);
                proof.put(key,value instanceof Number?Long.valueOf(((Number)value).longValue()+1):
                        value instanceof Boolean?Boolean.valueOf(!((Boolean)value).booleanValue()):"changed");
                meta.put("publication_recheck",proof);refused(()->make(capture,b,meta,null,null,at,owner));
            });
        }
        for(final String key:new String[]{"capture_requested_elapsed_ms","capture_age_at_publication_ms","pair_graph_started_elapsed_ms",
                "pair_graph_completed_elapsed_ms","pair_sealed_elapsed_ms","receipt_persisted_and_hashed_elapsed_ms",
                "event_fence_complete_census_endpoint_elapsed_ms","publication_full_graph_recheck_count"}){
            SnapshotChecks.run("actual_phone_rejects_relabelled_C_clock_"+key,()->{
                Map<String,Object> meta=new LinkedHashMap<String,Object>(actual);
                meta.put(key,Long.valueOf(((Number)meta.get(key)).longValue()+1));refused(()->make(capture,b,meta,null,null,at,owner));
            });
        }
        SnapshotChecks.run("actual_phone_rejects_post_C_publication_watermark_change",()->{
            Map<String,Object> meta=new LinkedHashMap<String,Object>(actual);
            Map<String,Object> watermark=new JSONObject((Map<?,?>)meta.get("publication_event_watermark")).toMap();
            watermark.put("events",Long.valueOf(((Number)watermark.get("events")).longValue()+1));
            meta.put("publication_event_watermark",watermark);refused(()->make(capture,b,meta,null,null,at,owner));
        });
        SnapshotChecks.run("actual_phone_rejects_C_window_check_before_complete_endpoint",()->{
            Map<String,Object> meta=new LinkedHashMap<String,Object>(actual);
            long endpoint=((Number)meta.get("event_fence_complete_census_endpoint_elapsed_ms")).longValue();
            meta.put("publication_check_started_elapsed_ms",Long.valueOf(endpoint-1));
            refused(()->make(capture,b,meta,null,null,at,owner));
        });
        SnapshotChecks.run("actual_phone_rejects_C_declaring_admitted_late_content",()->{
            Map<String,Object> meta=new LinkedHashMap<String,Object>(actual);meta.put("events_after_complete_census_admitted",true);
            refused(()->make(capture,b,meta,null,null,at,owner));
        });
    }
    static void run(final ObservationCaptureEvidence capture,final JSONObject b)throws Exception{
        final long at=b.getLong("captured_elapsed_ms");final String owner=b.getString("owner_sha256");
        SnapshotChecks.run("actual_phone_ax_constructor_retains_typed_receipt_and_explicit_no_image",()->{
            PhoneObservation observed=make(capture,b,metadata(capture,at),null,null,at,owner);JSONObject out=observed.toEvidenceJson();
            SnapshotChecks.check(observed.capture==capture&&ObservationCaptureEvidence.NATIVE_AX.equals(observed.captureKind),"AX type lost");
            SnapshotChecks.check(observed.screenshot==null&&observed.screenshotSha256==null,"AX fabricated image fields");
            SnapshotChecks.check(out.has("screen_sha256")&&out.isNull("screen_sha256")&&out.has("screenshot_path")&&out.isNull("screenshot_path"),"null image fields omitted");
            SnapshotChecks.check(!out.getBoolean("screenshot_observed")&&out.getLong("captured_elapsed_ms")==at,"AX invented image or refreshed age");
            SnapshotChecks.check(out.getJSONObject("ax_capture").getString("receipt_sha256").equals(capture.receiptSha256),"AX receipt hash replaced");
        });
        SnapshotChecks.run("actual_phone_ax_rejects_missing_receipt",()->refused(()->make(null,b,metadata(capture,at),null,null,at,owner)));
        SnapshotChecks.run("actual_phone_ax_rejects_fake_image",()->refused(()->make(capture,b,metadata(capture,at),new File("not-a-real-ax-image.png"),owner,at,owner)));
        SnapshotChecks.run("actual_phone_ax_rejects_pixel_capture_schema",()->{
            Map<String,Object> meta=metadata(capture,at);meta.put("schema","hepta.observation-capture.v1");
            refused(()->make(capture,b,meta,null,null,at,owner));
        });
        SnapshotChecks.run("actual_phone_ax_rejects_wrong_metadata_kind_and_receipt_hash",()->{
            Map<String,Object> kind=metadata(capture,at);kind.put("kind",ObservationCaptureEvidence.PIXELS);
            refused(()->make(capture,b,kind,null,null,at,owner));
            Map<String,Object> hash=metadata(capture,at);hash.put("receipt_sha256",SnapshotChecks.repeat('f',64));
            refused(()->make(capture,b,hash,null,null,at,owner));
        });
        SnapshotChecks.run("actual_phone_ax_rejects_capture_clock_and_owner_change",()->{
            refused(()->make(capture,b,metadata(capture,at+1),null,null,at+1,owner));
            refused(()->make(capture,b,metadata(capture,at),null,null,at,SnapshotChecks.repeat('f',64)));
        });
        SnapshotChecks.run("actual_phone_legacy_missing_image_remains_rejected",()->{
            Map<String,Object> meta=metadata(capture,at);meta.put("schema","hepta.observation-capture.v1");
            refused(()->make(null,b,meta,null,owner,at,owner));
        });
        SnapshotChecks.run("actual_phone_pixels_cannot_accept_ax_schema_without_receipt",()->{
            refused(()->make(null,b,metadata(capture,at),new File("host-pixel.png"),owner,at,owner));
        });
    }
}
