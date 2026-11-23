package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;

/** Consume the Session fixture's actual sealed/published planning object. No
 * alternate permission fixture, fake Offer, Android read, or model run. */
final class NativeSearchPlanningContractHostTest {
    private NativeSearchPlanningContractHostTest(){}
    interface Check {void run()throws Exception;}
    static final class Tests {
        int assertions;final List<String> cases=new ArrayList<String>();
        void yes(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
        void test(String name,Check body)throws Exception{body.run();cases.add(name);}
        void rejects(Check body)throws Exception{boolean refused=false;try{body.run();}catch(Exception expected){refused=true;}yes(refused,"must reject invalid receipt/context");}
    }
    @SuppressWarnings("unchecked") static Map<String,Object> object(Map<String,Object> v,String key){return (Map<String,Object>)v.get(key);}
    static long number(Map<String,Object> v,String key){return ((Number)v.get(key)).longValue();}
    static Map<String,Object> copy(Map<String,Object> value)throws Exception{return NativeSearchPlanning.map(NativeSearchPlanning.json(value));}
    static byte[] bytes(JSONObject value){return value.toString().getBytes(StandardCharsets.UTF_8);}
    static NativeSearchPlanning decode(byte[] value,Map<String,Object> binding,long at)throws Exception{
        return NativeSearchPlanning.fromSealedBytes(value,QualificationScope.hash(value),binding,at);
    }
    static NativeSearchPlanning.EventMark mark(Map<String,Object> value){return NativeSearchPlanning.EventMark.read(value);}
    static NativeSearchPlanning.WindowCheck check(NativeSearchPlanning p,Map<String,Object> facts,
            NativeSearchPlanning.EventMark before,NativeSearchPlanning.EventMark after){
        Map<String,Object> worker=object(p.publication,"worker_window_check");
        return new NativeSearchPlanning.WindowCheck(facts,number(worker,"started_elapsed_ms"),number(worker,"completed_elapsed_ms"),before,after);
    }
    static Map<String,Object> verify(final NativeSearchPlanning good,Path output)throws Exception{
        if(good==null||good.publication==null)throw new IllegalArgumentException("actual Session fixture's published planning required");
        if(Files.exists(output))throw new IllegalArgumentException("fresh contract receipt path required");
        final Tests t=new Tests();
        final byte[] original=NativeSearchPlanning.encode(good.id,good.first,good.second,good.binding,good.timing,good.context);
        final NativeSearchPlanning sealed=decode(original,good.binding,good.persistedElapsed);
        final Map<String,Object> window=object(good.publication,"current_window_facts");
        final Map<String,Object> worker=object(good.publication,"worker_window_check");
        final NativeSearchPlanning.EventMark workerBefore=mark(object(worker,"before")),workerAfter=mark(object(worker,"after"));
        final NativeSearchPlanning.EventMark publicationMark=mark(object(good.publication,"watermark"));
        t.test("actual_fixture_core_roundtrip_preserves_complete_sources_and_original_clocks",()->{
            t.yes(sealed.first.sha.equals(good.first.sha)&&sealed.second.sha.equals(good.second.sha),"both complete censuses exact");
            t.yes(sealed.capturedElapsed==good.timing.bCensusCaptured&&sealed.completedElapsed==good.timing.bReadCompleted,"B read/census clocks unchanged");
            t.yes(NativeSearchPlanning.equal(sealed.context.evidence(),good.context.evidence()),"full actual source windows and all event counts preserved");
            t.yes(sealed.publication==null&&sealed.publishedElapsed==-1,"core alone is not publication");
            t.yes(Boolean.FALSE.equals(sealed.evidence().get("generic_action_authority"))&&Boolean.FALSE.equals(sealed.evidence().get("completion_authority")),"core grants no old action/completion");
        });
        t.test("expected_encoded_sha_binds_actual_readback_bytes",()->{
            byte[] changed=original.clone();changed[changed.length-1]^=1;
            t.rejects(()->NativeSearchPlanning.fromSealedBytes(changed,QualificationScope.hash(original),good.binding,good.persistedElapsed));
        });
        t.test("readback_input_bytes_are_not_retained_mutably",()->{
            byte[] mutable=original.clone();NativeSearchPlanning owned=decode(mutable,good.binding,good.persistedElapsed);String digest=owned.receiptSha256;
            mutable[0]^=1;t.yes(digest.equals(owned.receiptSha256)&&owned.first.sha.equals(good.first.sha),"owned snapshot immune to later caller-byte mutation");
        });
        t.test("empty_receipt_rejected",()->t.rejects(()->decode(new byte[0],good.binding,good.persistedElapsed)));
        t.test("actual_utf8_receipt_cap_rejected_before_parse",()->t.rejects(()->decode(new byte[NativeSearchPlanning.MAX_BYTES+1],good.binding,good.persistedElapsed)));
        t.test("invalid_utf8_rejected_with_matching_byte_sha",()->t.rejects(()->decode(new byte[]{(byte)0xc3,(byte)0x28},good.binding,good.persistedElapsed)));
        t.test("empty_session_binding_rejected",()->t.rejects(()->NativeSearchPlanning.encode(good.id,good.first,good.second,Collections.<String,Object>emptyMap(),good.timing,good.context)));
        t.test("missing_session_binding_key_rejected",()->{Map<String,Object> b=new TreeMap<String,Object>(good.binding);b.remove("installed_set_sha256");t.rejects(()->NativeSearchPlanning.encode(good.id,good.first,good.second,b,good.timing,good.context));});
        t.test("extra_session_binding_key_rejected",()->{Map<String,Object> b=new TreeMap<String,Object>(good.binding);b.put("invented_authority",true);t.rejects(()->NativeSearchPlanning.encode(good.id,good.first,good.second,b,good.timing,good.context));});
        t.test("session_full_uid_wrong_type_rejected",()->{Map<String,Object> b=new TreeMap<String,Object>(good.binding);b.put("profile_full_uid",String.valueOf(b.get("profile_full_uid")));t.rejects(()->NativeSearchPlanning.encode(good.id,good.first,good.second,b,good.timing,good.context));});
        t.test("readback_requires_same_expected_session_identity",()->{Map<String,Object> b=new TreeMap<String,Object>(good.binding);b.put("owner_sha256",NativeActionSnapshotCheck.hash("other synthetic owner"));t.rejects(()->decode(original,b,good.persistedElapsed));});
        t.test("observation_id_must_match_both_actual_censuses",()->t.rejects(()->NativeSearchPlanning.encode("ffffffffffffffffffffffffffffffff",good.first,good.second,good.binding,good.timing,good.context)));
        t.test("full_tree_equal_claim_is_recomputed",()->{JSONObject forged=new JSONObject(new String(original,StandardCharsets.UTF_8));forged.put("full_tree_equal",!good.fullTreeEqual);t.rejects(()->decode(bytes(forged),good.binding,good.persistedElapsed));});
        t.test("planning_cannot_claim_old_action_authority",()->{JSONObject forged=new JSONObject(new String(original,StandardCharsets.UTF_8));forged.put("generic_action_authority",true);t.rejects(()->decode(bytes(forged),good.binding,good.persistedElapsed));});
        t.test("planning_cannot_claim_pixels_or_image_hash",()->{JSONObject forged=new JSONObject(new String(original,StandardCharsets.UTF_8));forged.put("screenshot_observed",true);forged.put("screenshot_sha256",NativeActionSnapshotCheck.hash("not an image"));t.rejects(()->decode(bytes(forged),good.binding,good.persistedElapsed));});
        t.test("old_native_ax_factory_rejects_planning_kind",()->t.rejects(()->ObservationCaptureEvidence.fromSealedNativeAx(
                NativeSearchPlanning.map(new JSONObject(new String(original,StandardCharsets.UTF_8))),original,QualificationScope.hash(original))));
        t.test("census_capture_clock_cannot_be_refreshed_by_encoding",()->{
            JSONObject b=NativeSearchPlanning.json(NativeSearchPlanning.snapshot(good.second));b.getJSONObject("envelope").put("captured_elapsed_ms",good.capturedElapsed+1);
            NativeActionSnapshotCheck.Snapshot changed=NativeSearchPlanning.readSnapshot(NativeSearchPlanning.map(b));
            t.rejects(()->NativeSearchPlanning.encode(good.id,good.first,changed,good.binding,good.timing,good.context));
        });
        t.test("original_twelve_second_request_bound_retained",()->t.rejects(()->new NativeSearchPlanning.Timing(0,12001,10,30,20,220,240,230,250)));
        t.test("original_ten_second_settle_bound_retained",()->t.rejects(()->new NativeSearchPlanning.Timing(0,12000,10,30,20,9990,10000,9995,10001)));
        t.test("separated_complete_samples_retained",()->t.rejects(()->new NativeSearchPlanning.Timing(0,12000,10,30,20,40,60,50,70)));
        t.test("persistence_cannot_precede_seal_or_extend_request",()->{
            t.rejects(()->decode(original,good.binding,good.timing.sealedElapsed-1));
            t.rejects(()->decode(original,good.binding,good.timing.requestDeadline));
        });
        t.test("unknown_boundary_content_and_untyped_late_events_remain_historical_only",()->{
            NativeSearchPlanning.EventMark s=sealed.context.sealed;
            NativeSearchPlanning.EventMark late=new NativeSearchPlanning.EventMark(s.events+3,s.unknown+1,s.content+1,s.boundary+1);
            NativeSearchPlanning p=sealed.published(good.publishedElapsed,late,check(good,window,s,late));
            t.yes(number(p.publication,"late_unknown_events")==1&&number(p.publication,"late_boundary_events")==1
                    &&number(p.publication,"late_content_events")==1&&number(p.publication,"late_untyped_events")==1,"every actual counter category recorded, none assumed neutral");
            t.yes(Boolean.TRUE.equals(p.publication.get("planning_as_of_B"))&&Boolean.TRUE.equals(p.publication.get("no_event_neutrality_claim")),"historical material stated explicitly");
            t.yes(Boolean.FALSE.equals(p.publication.get("current_full_tree_claimed"))&&Boolean.FALSE.equals(p.evidence().get("generic_action_authority")),"late unknown does not grant current frame or generic actions");
            t.yes(p.capturedElapsed==good.capturedElapsed&&p.completedElapsed==good.completedElapsed,"publication never refreshes B age");
        });
        t.test("actual_window_owner_change_rejected",()->{
            Map<String,Object> changed=copy(window);object(changed,"profile_window").put("full_uid",((Number)object(changed,"profile_window").get("full_uid")).intValue()+1);
            t.rejects(()->sealed.published(good.publishedElapsed,publicationMark,check(good,changed,workerBefore,workerAfter)));
        });
        t.test("actual_window_geometry_change_rejected",()->{
            Map<String,Object> changed=copy(window);object(changed,"window").put("left",1);
            t.rejects(()->sealed.published(good.publishedElapsed,publicationMark,check(good,changed,workerBefore,workerAfter)));
        });
        t.test("actual_reported_windows_change_rejected",()->{
            Map<String,Object> changed=copy(window);Map<String,Object> reported=object(changed,"reported_windows");reported.put("target_layer",((Number)reported.get("target_layer")).intValue()+1);
            t.rejects(()->sealed.published(good.publishedElapsed,publicationMark,check(good,changed,workerBefore,workerAfter)));
        });
        t.test("unknown_ime_never_normalized_to_hidden",()->{
            Map<String,Object> changed=copy(window);changed.put("ime_visibility","unknown");
            t.rejects(()->sealed.published(good.publishedElapsed,publicationMark,check(good,changed,workerBefore,workerAfter)));
        });
        t.test("profile_proof_expired_at_publication_rejected",()->{
            Map<String,Object> changed=copy(window);object(changed,"profile_window").put("expires_elapsed_ms",good.publishedElapsed);
            t.rejects(()->sealed.published(good.publishedElapsed,publicationMark,check(good,changed,workerBefore,workerAfter)));
        });
        t.test("publication_cannot_extend_original_capture_age",()->t.rejects(()->sealed.published(good.capturedElapsed+2001,publicationMark,check(good,window,workerBefore,workerAfter))));
        t.test("published_object_cannot_be_republished",()->t.rejects(()->good.published(good.publishedElapsed,publicationMark,check(good,window,workerBefore,workerAfter))));
        t.test("event_counter_regression_rejected",()->{
            NativeSearchPlanning.EventMark later=new NativeSearchPlanning.EventMark(3,1,1,1);
            NativeSearchPlanning.EventMark earlier=new NativeSearchPlanning.EventMark(2,1,1,1);
            t.rejects(()->new NativeSearchPlanning.CaptureContext(window,window,later,earlier,earlier,earlier,earlier));
        });
        t.test("bounded_publication_source_values_are_deep_immutable",()->{
            Map<String,Object> input=copy(window);NativeSearchPlanning.WindowCheck wc=check(good,input,workerBefore,workerAfter);
            object(input,"window").put("left",1);t.yes(number(object(wc.facts,"window"),"left")==number(object(window,"window"),"left"),"window evidence deep copied");
            boolean refused=false;try{object(sealed.context.secondWindowFacts,"window").put("left",1);}catch(UnsupportedOperationException expected){refused=true;}t.yes(refused,"nested captured source immutable");
        });
        Map<String,Object> result=new LinkedHashMap<String,Object>();result.put("schema","hepta.native-search-planning-contract-host-gate.v1");
        result.put("all_pass",true);result.put("cases",t.cases.size());result.put("assertions",t.assertions);result.put("case_names",t.cases);
        result.put("input_fixture_receipt_sha256",good.receiptSha256);result.put("roundtrip_receipt_sha256",sealed.receiptSha256);
        result.put("fixture_boundary","Shared actual Session fixture; Android clocks/nodes/window transport are explicitly synthetic. No second authority fixture or phone sampling.");
        result.put("phone_actions",0);result.put("device_qualified",false);result.put("business_verified",false);
        Files.write(output,(NativeSearchPlanning.json(result).toString(2)+"\n").getBytes(StandardCharsets.UTF_8));return result;
    }
}
