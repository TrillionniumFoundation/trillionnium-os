package org.trillionnium.hepta.local;

import android.os.SystemClock;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;
import static org.trillionnium.hepta.local.NativeFormHistoryConsumersHostTest.*;

/** Complete actual consumers and lossless codec. Recorded 060c geometry is
 * rebound to explicit synthetic host owner/profile/window/clock/NodeRef ports.
 * This is neither a new phone capture nor a proof of an Android effect. */
public final class CtripPurposeConsumersHost {
    private static JSONObject recorded;
    static Map<String,Object> object(JSONObject value)throws Exception{
        Map<String,Object> out=new TreeMap<String,Object>();
        for(Iterator<String> k=value.keys();k.hasNext();){String key=k.next();out.put(key,copy(value.get(key)));}
        return out;
    }
    static Object copy(Object value)throws Exception{
        if(value==null||value==JSONObject.NULL)return null;
        if(value instanceof JSONObject)return object((JSONObject)value);
        if(value instanceof JSONArray){List<Object> out=new ArrayList<Object>();JSONArray a=(JSONArray)value;
            for(int i=0;i<a.length();i++)out.add(copy(a.get(i)));return out;}
        return value;
    }
    static NativeActionSnapshotCheckHostTest.Fixture recorded(String side)throws Exception{
        NativeActionSnapshotCheckHostTest.Fixture f=form();f.nodes.clear();
        JSONArray rows=recorded.getJSONObject("pairs").getJSONObject(side).getJSONArray("nodes");
        for(int i=0;i<rows.length();i++){
            Map<String,Object> n=object(rows.getJSONObject(i));String path=(String)n.get("path");
            n.put("window_id",96);
            if(n.get("ref_signature_sha256")!=null)n.put("ref_signature_sha256",hash(fullSignature(path)));
            f.nodes.put(path,n);
        }
        f.env.put("window_id",96);f.env.put("width",1224);f.env.put("height",2992);
        f.env.put("root_bounds",Arrays.asList(0,0,1224,2992));f.env.put("visited",f.nodes.size());
        return f;
    }
    static Pack pair(Fixture f)throws Exception{return new Pack(f,START+(f.sequence++*1000),true,true,recorded("before"),recorded("after"));}
    static Map<String,Object> proof(Pack p){return obj(obj(p.receipt.get("form_history")).get("comparison"));}
    static Map<String,Object> pixelMetadata(Pack p,Map<String,Object> comparison,boolean late){
        Map<String,Object> m=map();
        m.put("schema","hepta.observation-capture.v1");m.put("mode",late?"post_encoding_form_pair_history":"pre_encoding_form_pair_history");
        m.put("capture_requested_elapsed_ms",p.captured);m.put("publication_refreshes_capture_age",false);
        m.put("grants_action_authority",false);m.put("business_completion_verified",false);
        m.put("published_pair_is_current_tree_claimed",false);
        m.put(late?"post_encoding_form_pair_comparison":"form_pair_comparison",NativeAppObservation.pixelFormPair(comparison));
        return m;
    }
    static NativeAppEvidence.Frame pixel(Pack p,Map<String,Object> metadata)throws Exception{
        Path image=p.owner.env.directory.resolve(id()+"-synthetic-pixel-port.bin");
        byte[] bytes="explicit synthetic host pixel IO port; no PNG or VLM qualification".getBytes(StandardCharsets.UTF_8);
        Files.write(image,bytes,StandardOpenOption.CREATE_NEW);
        PhoneObservation phone=p.phone(metadata,null,p.captured,image.toFile(),ObservationCaptureEvidence.hash(bytes),p.nodes);
        Path record=p.owner.env.directory.resolve(id()+"-pixel-frame.json");
        Files.write(record,phone.toEvidenceJson().toString().getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        SystemClock.now=p.start+250;
        return NativeAppObservation.copy(p.owner.task.taskId,p.owner.gate,p.owner.env.session,phone,p.completion,
                ObservationCaptureEvidence.hash(Files.readAllBytes(record)));
    }
    static NativeAppEvidence.Frame rebound(NativeAppEvidence.Frame f,String observation,String owner,List<NativeAppEvidence.Node> nodes,Map<String,Object> q){
        return new NativeAppEvidence.Frame(f.taskId,owner,f.targetSha,f.authorizationSha,f.selectionSha,observation,
                f.packageName,f.generation,f.treeSha,f.stateSha,f.screenshotSha,f.sourceRecordSha,f.completionFrameSha,
                f.displayId,f.windowId,f.rotation,f.width,f.height,f.left,f.top,f.right,f.bottom,
                f.capturedElapsedMs,false,true,nodes,1,true,f.profileWindow,f.capture,q);
    }
    static void rejects(Work body)throws Exception{
        boolean failed=false;
        try{body.run();}catch(Exception expected){failed=true;}
        check(failed,"actual complete consumer/codec must reject");
    }
    static JSONObject wrapper(byte[] raw)throws Exception{
        java.util.zip.Deflater d=new java.util.zip.Deflater();
        java.io.ByteArrayOutputStream out=new java.io.ByteArrayOutputStream();
        try{d.setInput(raw);d.finish();byte[] b=new byte[4096];while(!d.finished()){int n=d.deflate(b);if(n<1)throw new AssertionError("test compression");out.write(b,0,n);}}finally{d.end();}
        return new JSONObject().put("schema","hepta.ctrip-form-pair-transport.v1").put("codec","zlib-deflate-base64")
                .put("uncompressed_utf8_bytes",raw.length).put("uncompressed_sha256",ObservationCaptureEvidence.hash(raw))
                .put("payload_base64",Base64.getEncoder().encodeToString(out.toByteArray()));
    }
    static JSONObject wrapped(Pack p){return new JSONObject(NativeAppObservation.pixelFormPair(proof(p)));}
    static void transportMutation(String name,String key,Object value){
        one(name,()->{try(Fixture f=new Fixture()){JSONObject bad=wrapped(pair(f));bad.put(key,value);rejects(()->NativeAppObservation.decodePixelFormPair(bad));}});
    }
    public static void main(String[] args)throws Exception{
        Path output=Paths.get(args[0]);NativeProfileIdentityHostTest.workspace=Paths.get(args[1]);
        Files.createDirectories(NativeProfileIdentityHostTest.workspace);
        recorded=new JSONObject(new String(Files.readAllBytes(Paths.get(args[2])),StandardCharsets.UTF_8));
        one("ax_receipt_recomputes_recorded_geometry_and_real_phone_copy_frame",()->{try(Fixture f=new Fixture()){
            Pack p=pair(f);check(p.capture.formHistory()&&p.frame.formPurposeGeometry!=null,"actual receipt and copied certificate");
            check(p.frame.formPurposeGeometry.equals(p.capture.formPurposeGeometry()),"same immutable receipt source");
            check(p.original.nodes.size()==276&&p.second.nodes.size()==276&&p.frame.nodes.size()<276,"whole receipt versus retained nodes");
            check(p.observation.equals(p.frame.formPurposeGeometry.get("planning_observation_id")),"new planning observation exact binding");
        }});
        one("actual_session_date_domain_guard_claim_uses_restricted_ax_source",()->{try(Fixture f=new Fixture()){
            Pack p=pair(f);String run=id();NativeAppSession.ActionGuard g=dateGuard(f,p,run);
            check(f.task.domain().clickIds.equals(Collections.singleton(p.path("0/0/2/5").id)),"date only before year roundtrip");
            check(g.frame==p.frame&&NativeActionSnapshotCheck.YEAR.equals(g.purpose),"actual original restricted guard");
            g.claim(g.action,run,p.start+330);g.requireClaimed();rejects(()->g.claim(g.action,run,p.start+331));
        }});
        one("actual_session_query_before_calendar_roundtrip_still_refused",()->{try(Fixture f=new Fixture()){
            Pack p=pair(f);f.task.observed(p.frame);rejects(()->f.task.beforeModelAction(1,action(p,"click",null,p.path("0/0/2/13").id),id(),p.start+300));
        }});
        one("actual_ax_receipt_changed_certificate_cannot_be_sealed",()->{try(Fixture f=new Fixture()){
            Pack p=pair(f);Map<String,Object> receipt=object(new JSONObject(p.receipt));
            Map<String,Object> q=obj(obj(obj(receipt.get("form_history")).get("comparison")).get("form_purpose_geometry"));
            q.put("first_nodes_sha256",hash("not the recorded census"));
            obj(obj(receipt.get("form_history")).get("comparison")).put("form_purpose_geometry",q);
            Map<String,Object> comparison=obj(obj(receipt.get("form_history")).get("comparison"));comparison.put("form_purpose_geometry",q);
            Map<String,Object> history=obj(receipt.get("form_history"));history.put("comparison",comparison);receipt.put("form_history",history);
            rejects(()->ObservationCaptureEvidence.nativeAxFormHistoryBytes(receipt));
        }});
        one("actual_ax_receipt_changed_original_node_cannot_borrow_comparison",()->{try(Fixture f=new Fixture()){
            Pack p=pair(f);JSONObject receipt=new JSONObject(p.receipt);
            receipt.getJSONObject("first").getJSONArray("nodes").getJSONObject(0).put("description","changed root");
            rejects(()->ObservationCaptureEvidence.nativeAxFormHistoryBytes(object(receipt)));
        }});
        one("ax_capture_exact_purpose_and_path_are_jointly_required",()->{try(Fixture f=new Fixture()){
            Pack p=pair(f);p.capture.requireFormHistoryTarget("0/0/2/5",NativeActionSnapshotCheck.YEAR);
            p.capture.requireFormHistoryTarget("0/0/2/13",NativeActionSnapshotCheck.QUERY);
            rejects(()->p.capture.requireFormHistoryTarget("0/0/2/5",NativeActionSnapshotCheck.QUERY));
            rejects(()->p.capture.requireFormHistoryTarget("0/0/2/13",NativeActionSnapshotCheck.YEAR));
        }});
        one("pixel_pre_encoding_actual_phone_metadata_decode_copy_session_guard",()->{try(Fixture f=new Fixture()){
            Pack p=pair(f);NativeAppEvidence.Frame frame=pixel(p,pixelMetadata(p,proof(p),false));f.task.observed(frame);
            check(frame.capture==null&&frame.formPurposeGeometry!=null,"actual pixel copy carries restricted proof");
            ActionDecision click=action(p,"click",null,p.path("0/0/2/5").id);String run=id();
            f.task.beforeModelAction(1,click,run,p.start+300);
            NativeAppSession.ActionGuard g=f.task.actionGuard(click,run,p.observation,p.start+310,p.start+8310);
            check(g.frame==frame&&NativeActionSnapshotCheck.YEAR.equals(g.purpose),"actual pixel restricted guard");
        }});
        one("pixel_post_encoding_actual_phone_metadata_decode_copy",()->{try(Fixture f=new Fixture()){
            Pack p=pair(f);NativeAppEvidence.Frame frame=pixel(p,pixelMetadata(p,proof(p),true));
            check(p.observation.equals(frame.formPurposeGeometry.get("planning_observation_id")),"post encoding observation binding");
        }});
        one("pixel_certificate_cannot_cross_observation_or_owner",()->{try(Fixture f=new Fixture()){
            Pack p=pair(f);NativeAppEvidence.Frame frame=pixel(p,pixelMetadata(p,proof(p),false));
            rejects(()->rebound(frame,id(),frame.ownerSha,frame.nodes,frame.formPurposeGeometry));
            rejects(()->rebound(frame,frame.observationId,hash("different owner"),frame.nodes,frame.formPurposeGeometry));
        }});
        one("pixel_frame_missing_exact_target_is_refused",()->{try(Fixture f=new Fixture()){
            Pack p=pair(f);NativeAppEvidence.Frame frame=pixel(p,pixelMetadata(p,proof(p),false));
            List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>(frame.nodes);nodes.remove(frame.byId.get(p.path("0/0/2/5").id));
            rejects(()->rebound(frame,frame.observationId,frame.ownerSha,nodes,frame.formPurposeGeometry));
        }});
        one("pixel_frame_source_identity_distinguishes_certificate_removal",()->{try(Fixture f=new Fixture()){
            Pack p=pair(f);NativeAppEvidence.Frame frame=pixel(p,pixelMetadata(p,proof(p),false));
            NativeAppEvidence.Frame without=rebound(frame,frame.observationId,frame.ownerSha,frame.nodes,null);
            check(!frame.sameSource(without),"same pixels cannot erase purpose source");
        }});
        one("pixel_domain_rejects_trip_generic_back_and_calendar_authority",()->{try(Fixture f=new Fixture()){
            Pack p=pair(f);NativeAppEvidence.Frame frame=pixel(p,pixelMetadata(p,proof(p),false));
            for(String purpose:Arrays.asList("generic_click","trip","calendar","select_departure_date")){
                final String wrong=purpose;rejects(()->frame.requireFormPurposeTarget(wrong,frame.byId.get(p.path("0/0/2/5").id)));
            }
            rejects(()->new NativeAppDomain(frame,NativeCtripFlightPage.CALENDAR,Collections.<String>emptySet(),Collections.<String,String>emptyMap(),
                    Collections.<String,String>emptyMap(),false,Collections.<String,Object>emptyMap(),null,Collections.<String>emptyList()));
            rejects(()->new NativeAppDomain(frame,NativeCtripFlightPage.FORM,Collections.<String>emptySet(),Collections.<String,String>emptyMap(),
                    Collections.<String,String>emptyMap(),true,Collections.<String,Object>emptyMap(),null,Collections.<String>emptyList()));
        }});
        one("pixel_raw_certificate_cannot_replace_new_observation_binding",()->{try(Fixture f=new Fixture()){
            Pack p=pair(f);Map<String,Object> comparison=proof(p),q=obj(comparison.get("form_purpose_geometry"));
            q.put("planning_observation_id",id());comparison.put("form_purpose_geometry",q);
            rejects(()->pixel(p,pixelMetadata(p,comparison,false)));
        }});
        one("pixel_complete_original_nodes_hash_checked_before_comparator",()->{try(Fixture f=new Fixture()){
            Pack p=pair(f);NativeAppEvidence.Frame frame=pixel(p,pixelMetadata(p,proof(p),false));
            NativeActionSnapshotCheck.requireCtripPurposeSource(frame.formPurposeGeometry,NativeActionSnapshotCheck.YEAR,"0/0/2/5",p.snapshot(p.original,p.start+80));
            NativeActionSnapshotCheckHostTest.Fixture changed=p.original.copy();changed.nodes.get("0").put("description","changed original graph");
            rejects(()->NativeActionSnapshotCheck.requireCtripPurposeSource(frame.formPurposeGeometry,NativeActionSnapshotCheck.YEAR,"0/0/2/5",p.snapshot(changed,p.start+80)));
        }});
        one("lossless_purpose_bytes_hash_and_semantics_are_exact",()->{try(Fixture f=new Fixture()){
            Pack p=pair(f);Map<String,Object> comparison=proof(p);
            byte[] raw=new JSONObject(comparison).toString().getBytes(StandardCharsets.UTF_8);JSONObject packed=wrapped(p);
            check(Arrays.equals(raw,NativeAppObservation.pixelFormPairBytes(packed)),"complete original UTF-8 bytes");
            check(NativeAppEvidence.fingerprint(comparison).equals(NativeAppEvidence.fingerprint(object(NativeAppObservation.decodePixelFormPair(packed)))),"complete original map");
        }});
        one("lossless_strict_comparison_keeps_all_literal_facts_and_phone_8192_bound",()->{try(Fixture f=new Fixture()){
            Pack p=pair(f);Map<String,Object> strict=NativeCtripFormObservation.compare(p.snapshot(p.original,p.start+80),p.snapshot(p.original,p.start+180));
            check(strict.containsKey("literal_form_facts")&&!strict.containsKey("form_purpose_geometry"),"unchanged original strict first path");
            byte[] raw=new JSONObject(strict).toString().getBytes(StandardCharsets.UTF_8);
            JSONObject packed=new JSONObject(NativeAppObservation.pixelFormPair(strict));
            check(Arrays.equals(raw,NativeAppObservation.pixelFormPairBytes(packed)),"strict original facts bytes lossless");
            NativeAppEvidence.Frame frame=pixel(p,pixelMetadata(p,strict,false));
            check(frame.formPurposeGeometry==null,"strict pair gains no new authority");
        }});
        transportMutation("transport_wrong_codec_refused","codec","gzip");
        transportMutation("transport_wrong_schema_refused","schema","hepta.ctrip-form-pair-transport.v2");
        transportMutation("transport_bad_hash_refused","uncompressed_sha256",hash("wrong raw"));
        transportMutation("transport_zero_length_refused","uncompressed_utf8_bytes",0);
        transportMutation("transport_oversize_length_refused","uncompressed_utf8_bytes",262145);
        transportMutation("transport_fractional_length_refused","uncompressed_utf8_bytes",3.5);
        transportMutation("transport_string_length_refused","uncompressed_utf8_bytes","100");
        transportMutation("transport_unknown_field_refused","unexpected",true);
        transportMutation("transport_bad_base64_refused","payload_base64","%%%");
        transportMutation("transport_nonstring_base64_refused","payload_base64",7);
        one("transport_missing_codec_field_refused",()->{try(Fixture f=new Fixture()){JSONObject b=wrapped(pair(f));b.remove("codec");rejects(()->NativeAppObservation.decodePixelFormPair(b));}});
        one("transport_dictionary_stream_refused",()->{byte[] raw="explicit dictionary stream".getBytes(StandardCharsets.UTF_8);
            java.util.zip.Deflater d=new java.util.zip.Deflater();java.io.ByteArrayOutputStream out=new java.io.ByteArrayOutputStream();
            try{d.setDictionary("dictionary".getBytes(StandardCharsets.UTF_8));d.setInput(raw);d.finish();byte[] block=new byte[128];
                while(!d.finished()){int n=d.deflate(block);if(n<1)throw new AssertionError("test dictionary compression");out.write(block,0,n);}}
            finally{d.end();}
            JSONObject b=wrapper(raw);b.put("payload_base64",Base64.getEncoder().encodeToString(out.toByteArray()));
            rejects(()->NativeAppObservation.decodePixelFormPair(b));
        });

        one("transport_wrong_actual_length_refused",()->{try(Fixture f=new Fixture()){JSONObject b=wrapped(pair(f));b.put("uncompressed_utf8_bytes",b.getInt("uncompressed_utf8_bytes")+1);rejects(()->NativeAppObservation.decodePixelFormPair(b));}});
        one("transport_truncated_zlib_refused",()->{try(Fixture f=new Fixture()){JSONObject b=wrapped(pair(f));byte[] z=Base64.getDecoder().decode(b.getString("payload_base64"));b.put("payload_base64",Base64.getEncoder().encodeToString(Arrays.copyOf(z,z.length-1)));rejects(()->NativeAppObservation.decodePixelFormPair(b));}});
        one("transport_trailing_zlib_bytes_refused",()->{try(Fixture f=new Fixture()){JSONObject b=wrapped(pair(f));byte[] z=Base64.getDecoder().decode(b.getString("payload_base64"));b.put("payload_base64",Base64.getEncoder().encodeToString(Arrays.copyOf(z,z.length+1)));rejects(()->NativeAppObservation.decodePixelFormPair(b));}});
        one("transport_noncanonical_base64_refused",()->{try(Fixture f=new Fixture()){JSONObject b=wrapped(pair(f));b.put("payload_base64",b.getString("payload_base64")+"\n");rejects(()->NativeAppObservation.decodePixelFormPair(b));}});
        one("transport_bomb_over_declared_bound_refused",()->{byte[] raw=new byte[262145];Arrays.fill(raw,(byte)'a');JSONObject b=wrapper(raw);b.put("uncompressed_utf8_bytes",262144);rejects(()->NativeAppObservation.decodePixelFormPair(b));});
        one("transport_invalid_utf8_refused_after_matching_hash",()->{JSONObject b=wrapper(new byte[]{(byte)0xc3,(byte)0x28});rejects(()->NativeAppObservation.decodePixelFormPair(b));});
        one("transport_valid_json_with_trailing_value_refused",()->{try(Fixture f=new Fixture()){Pack p=pair(f);byte[] raw=(new JSONObject(proof(p)).toString()+" {}").getBytes(StandardCharsets.UTF_8);rejects(()->NativeAppObservation.decodePixelFormPair(wrapper(raw)));}});
        one("transport_unknown_inner_proof_schema_refused",()->{try(Fixture f=new Fixture()){Pack p=pair(f);JSONObject inner=new JSONObject(proof(p));inner.put("schema","foreign");rejects(()->NativeAppObservation.decodePixelFormPair(wrapper(inner.toString().getBytes(StandardCharsets.UTF_8))));}});
        one("transport_inner_grant_claim_refused",()->{try(Fixture f=new Fixture()){Pack p=pair(f);JSONObject inner=new JSONObject(proof(p));inner.put("grants_action_authority",true);rejects(()->NativeAppObservation.decodePixelFormPair(wrapper(inner.toString().getBytes(StandardCharsets.UTF_8))));}});
        one("pixel_capture_outer_8192_bound_is_unchanged",()->{try(Fixture f=new Fixture()){Pack p=pair(f);Map<String,Object> metadata=pixelMetadata(p,proof(p),false);char[] text=new char[8193];Arrays.fill(text,'x');metadata.put("host_oversize_negative",new String(text));rejects(()->pixel(p,metadata));}});
        boolean all=true;for(Map<String,Object> row:results)if(!Boolean.TRUE.equals(row.get("passed")))all=false;
        Map<String,Object> report=map();report.put("schema","hepta.ctrip-purpose-consumers-host.v1");report.put("all_pass",all);
        report.put("cases",names.size());report.put("assertions",assertions);report.put("case_names",names);report.put("results",results);
        report.put("phone_operations",0);report.put("platform_effect_tested",false);report.put("model_executed",false);report.put("business_verified",false);
        report.put("boundary","Actual full Phone/adapter/Frame/receipt/Session/Domain/Guard/codec over recorded 060c geometry with explicit host identity, clocks, refs and pixel IO. No Android service validate/dispatch or phone capture qualification.");
        Files.write(output,(new JSONObject(report).toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println(new JSONObject(report).toString());if(!all)System.exit(1);
    }
}
