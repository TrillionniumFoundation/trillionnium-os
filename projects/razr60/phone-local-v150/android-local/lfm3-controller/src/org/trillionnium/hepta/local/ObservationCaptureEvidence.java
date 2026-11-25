package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/** A sealed, complete native AX pair. It grants neither action freshness nor completion.
 * Only actual private-file bytes, checked against the complete canonical receipt, can
 * construct this value. A kind string or an absent screenshot is never AX evidence. */
final class ObservationCaptureEvidence {
    static final String PIXELS="pixels",NATIVE_AX="native_ax",NATIVE_AX_FORM_HISTORY="native_ax_form_history",
            NATIVE_AX_INPUT_HISTORY="native_ax_empty_search_input_history";
    static final int MAX_RECEIPT_BYTES=2*1024*1024,MAX_NODES=1536;
    private static final String SCHEMA="hepta.native-ax-capture.v1",FORM_SCHEMA="hepta.native-ax-form-history.v1",
            INPUT_SCHEMA="hepta.native-ax-empty-search-input-history.v1";
    private static final Set<String> BINDING_KEYS=keys(
            "task_id owner_sha256 execution_target_sha256 task_authorization_sha256 actual_selection_sha256 "
            +"native_goal_sha256 observation_id package background_generation app_tree_sha256 observation_state_sha256 "
            +"display_id window_id rotation width height left top right bottom captured_elapsed_ms profile_window profile_action_identity original_census_captured_elapsed_ms");
    final String kind,receiptSha256;
    private final Map<String,Object> receipt,binding,publicationRecheck;
    private final byte[] raw;
    private ObservationCaptureEvidence(Map<String,Object> receipt,byte[] persisted,String digest,String kind){
        need(NATIVE_AX.equals(kind)||NATIVE_AX_FORM_HISTORY.equals(kind)||NATIVE_AX_INPUT_HISTORY.equals(kind),"explicit native capture constructor");
        this.kind=kind;this.receipt=freezeMap(receipt);binding=map(this.receipt,"binding");publicationRecheck=null;validate(this.receipt,kind);
        byte[] expected=canonicalBytes(this.receipt);
        need(persisted!=null&&persisted.length>0&&persisted.length<=MAX_RECEIPT_BYTES
                &&Arrays.equals(expected,persisted),"canonical persisted AX receipt bytes required");
        need(sha(digest)&&digest.equals(hash(persisted)),"actual persisted AX receipt hash differs");
        raw=persisted.clone();receiptSha256=digest;
    }
    /** Retain the already persisted A/B bytes. C proves publication currentness only;
     * it cannot replace the original observation ID, capture clock or action checks. */
    private ObservationCaptureEvidence(ObservationCaptureEvidence original,Map<String,Object> recheck){
        kind=original.kind;receipt=original.receipt;binding=original.binding;raw=original.raw;
        receiptSha256=original.receiptSha256;publicationRecheck=freezeMap(recheck);
    }
    void requirePersistedBytes(byte[] persisted){
        need(persisted!=null&&Arrays.equals(raw,persisted)&&receiptSha256.equals(hash(persisted)),
                "original persisted AX receipt changed before publication recheck");
    }
    boolean publicationRechecked(){return publicationRecheck!=null;}
    ObservationCaptureEvidence withPublicationRecheck(Map<String,Object> current,Map<String,Object> start,
            Map<String,Object> completed,long persistedAt,long endpoint){
        need(NATIVE_AX.equals(kind)&&publicationRecheck==null,"one ordinary AX publication recheck required");
        Map<String,Object> census=freezeMap(current),first=map(receipt,"first");validateCensus(census);
        for(String key:new String[]{"identity","nodes","reported_windows","window","profile_owner"})
            need(canonical(first.get(key)).equals(canonical(census.get(key))),"complete publication census differs: "+key);
        long began=num(census,"read_started_elapsed_ms"),ended=num(census,"read_completed_elapsed_ms");
        need(persistedAt>=num(receipt,"sealed_elapsed_ms")&&began>=persistedAt&&ended>=began
                &&endpoint>=ended&&endpoint<num(receipt,"request_deadline_elapsed_ms"),
                "publication recheck must be a fresh complete read within the original deadline");
        onlyContent(map(receipt,"second_completed_watermark"),start);onlyContent(start,completed);
        onlyContent(map(receipt,"capture_watermark"),completed);
        Map<String,Object> proof=new TreeMap<String,Object>();
        proof.put("schema","hepta.native-ax-publication-recheck.v1");
        proof.put("original_receipt_sha256",receiptSha256);proof.put("original_observation_id",binding.get("observation_id"));
        proof.put("original_captured_elapsed_ms",binding.get("captured_elapsed_ms"));
        proof.put("receipt_persisted_elapsed_ms",persistedAt);
        proof.put("graph_started_elapsed_ms",began);proof.put("graph_completed_elapsed_ms",ended);
        proof.put("complete_census_endpoint_elapsed_ms",endpoint);
        proof.put("start_watermark",start);proof.put("completed_watermark",completed);
        proof.put("complete_census_sha256",hash(canonicalBytes(census)));
        proof.put("full_identity_nodes_windows_profile_owner_equal",true);
        proof.put("receipt_rewritten",false);proof.put("grants_action_authority",false);
        return new ObservationCaptureEvidence(this,proof);
    }
    private void requirePublicationRecheck(Map<String,Object> e){
        if(publicationRecheck==null){
            need(!e.containsKey("publication_recheck"),"unsealed publication recheck metadata");return;
        }
        need(canonical(publicationRecheck).equals(canonical(e.get("publication_recheck")))
                &&num(e,"publication_full_graph_recheck_count")==1
                &&"post_persistence_complete_census".equals(e.get("events_after_complete_census_admitted_endpoint"))
                &&Boolean.FALSE.equals(e.get("events_after_complete_census_admitted"))
                &&Boolean.TRUE.equals(e.get("publication_window_matched")),"actual publication recheck proof differs");
        need(canonical(publicationRecheck.get("completed_watermark")).equals(canonical(e.get("publication_event_watermark"))),
                "publication event watermark differs from the complete recheck");
        long endpoint=num(publicationRecheck,"complete_census_endpoint_elapsed_ms");
        long windowStart=num(e,"publication_check_started_elapsed_ms"),windowEnd=num(e,"publication_check_completed_elapsed_ms");
        long published=num(e,"published_elapsed_ms");
        need(num(e,"capture_requested_elapsed_ms")==num(binding,"captured_elapsed_ms")
                &&num(e,"capture_age_at_publication_ms")==published-num(binding,"captured_elapsed_ms")
                &&num(e,"pair_graph_started_elapsed_ms")==num(map(receipt,"second"),"read_started_elapsed_ms")
                &&num(e,"pair_graph_completed_elapsed_ms")==num(map(receipt,"second"),"read_completed_elapsed_ms")
                &&num(e,"pair_sealed_elapsed_ms")==num(receipt,"sealed_elapsed_ms")
                &&num(e,"receipt_persisted_and_hashed_elapsed_ms")==num(publicationRecheck,"receipt_persisted_elapsed_ms")
                &&num(e,"event_fence_complete_census_endpoint_elapsed_ms")==endpoint
                &&windowStart>=endpoint&&windowEnd>=windowStart&&published>=windowEnd
                &&published<num(receipt,"request_deadline_elapsed_ms"),"publication recheck clocks or original pair changed");
    }
    static ObservationCaptureEvidence fromSealedNativeAx(Map<String,Object> receipt,byte[] persisted,String digest){
        return new ObservationCaptureEvidence(receipt,persisted,digest,NATIVE_AX);
    }
    /** Called before private create-only persistence; actual readback is still required. */
    static byte[] nativeAxBytes(Map<String,Object> receipt){
        Map<String,Object> frozen=freezeMap(receipt);validate(frozen,NATIVE_AX);return canonicalBytes(frozen);
    }
    static ObservationCaptureEvidence fromSealedNativeAxFormHistory(Map<String,Object> receipt,byte[] persisted,String digest){
        return new ObservationCaptureEvidence(receipt,persisted,digest,NATIVE_AX_FORM_HISTORY);
    }
    static byte[] nativeAxFormHistoryBytes(Map<String,Object> receipt){
        Map<String,Object> frozen=freezeMap(receipt);validate(frozen,NATIVE_AX_FORM_HISTORY);return canonicalBytes(frozen);
    }
    static ObservationCaptureEvidence fromSealedNativeAxInputHistory(Map<String,Object> receipt,byte[] persisted,String digest){
        return new ObservationCaptureEvidence(receipt,persisted,digest,NATIVE_AX_INPUT_HISTORY);
    }
    static byte[] nativeAxInputHistoryBytes(Map<String,Object> receipt){
        Map<String,Object> frozen=freezeMap(receipt);validate(frozen,NATIVE_AX_INPUT_HISTORY);return canonicalBytes(frozen);
    }
    boolean formHistory(){return NATIVE_AX_FORM_HISTORY.equals(kind);}
    boolean inputHistory(){return NATIVE_AX_INPUT_HISTORY.equals(kind);}
    boolean planningHistory(){return formHistory()||inputHistory();}
    boolean nativeText(){return NATIVE_AX.equals(kind)||planningHistory();}
    String metadataSchema(){return inputHistory()?"hepta.observation-capture.native-ax-empty-search-input-history.v1":
            formHistory()?"hepta.observation-capture.native-ax-form-history.v1":"hepta.observation-capture.native-ax.v1";}
    Map<String,Object> inputHistoryEvidence(){
        need(inputHistory(),"explicit empty search-input history required");
        Map<String,Object> proof=map(map(receipt,"input_history"),"comparison"),e=new TreeMap<String,Object>();
        e.put("schema","hepta.native-ax-empty-search-input-history-summary.v1");e.put("phase","search_input");
        e.put("source_census","first");e.put("planning_only",true);e.put("empty_query",true);
        e.put("query_path",proof.get("query_path"));e.put("protected_subtrees",proof.get("protected_subtrees"));
        e.put("whole_graph_equal",proof.get("whole_graph_equal"));e.put("full_census_compared",true);
        e.put("first_snapshot_sha256",proof.get("before_snapshot_sha256"));e.put("second_snapshot_sha256",proof.get("after_snapshot_sha256"));
        e.put("comparison_sha256",hash(canonicalBytes(proof)));e.put("changed_path_count",((List<?>)proof.get("changed_paths")).size());
        e.put("complete_census_endpoint_elapsed_ms",receipt.get("complete_census_endpoint_elapsed_ms"));
        e.put("published_pair_is_current_tree_claimed",false);e.put("grants_action_authority",false);
        e.put("query_dispatched",false);e.put("business_completion_verified",false);return Collections.unmodifiableMap(e);
    }
    void requireInputHistoryTarget(String path){
        if(inputHistory())need("0/1".equals(path)&&path.equals(map(map(receipt,"input_history"),"comparison").get("query_path")),
                "empty input history exposes only the original query field");
    }
    private void requireInputHistoryPublication(Map<String,Object> e){
        need(metadataSchema().equals(e.get("schema"))&&"complete_native_ax_empty_search_input_history".equals(e.get("mode"))
                &&Boolean.TRUE.equals(e.get("historical_empty_input_planning_only"))
                &&Boolean.FALSE.equals(e.get("published_pair_is_current_tree_claimed")),"input history cannot claim a current executable graph");
        need(canonical(inputHistoryEvidence()).equals(canonical(e.get("input_history"))),"actual complete input-history proof differs");
        Map<String,Object> complete=map(receipt,"second_completed_watermark"),published=map(e,"publication_event_watermark");
        onlyContent(complete,published);
        need(Boolean.valueOf(num(published,"events")!=num(complete,"events")).equals(e.get("events_after_complete_census_admitted"))
                &&"historical_empty_input_planning_only".equals(e.get("post_census_events_use"))
                &&Boolean.TRUE.equals(e.get("publication_window_matched")),"historical input event/window facts missing");
        long at=num(e,"published_elapsed_ms");
        need(at>=num(receipt,"sealed_elapsed_ms")&&at<num(receipt,"request_deadline_elapsed_ms")
                &&num(e,"capture_requested_elapsed_ms")==num(binding,"captured_elapsed_ms"),"original input history clocks/deadline required");
    }
    /** Compact facts about the actual preserved pair; never a current tree or result. */
    Map<String,Object> formHistoryEvidence(){
        need(formHistory(),"explicit form-history capture required");
        Map<String,Object> history=map(receipt,"form_history"),proof=map(history,"comparison");
        Map<String,Object> e=new TreeMap<String,Object>();
        e.put("schema","hepta.native-ax-form-history-summary.v1");e.put("phase","ctrip_single_flight_form");
        e.put("source_census","first");e.put("planning_only",true);e.put("whole_graph_equal",proof.get("whole_graph_equal"));
        e.put("published_pair_is_current_tree_claimed",false);e.put("full_census_compared",true);
        e.put("first_snapshot_sha256",proof.get("before_snapshot_sha256"));e.put("second_snapshot_sha256",proof.get("after_snapshot_sha256"));
        e.put("comparison_sha256",hash(canonicalBytes(proof)));e.put("changed_path_count",((List<?>)proof.get("changed_paths")).size());
        e.put("protected_subtrees",proof.get("protected_subtrees"));
        e.put("complete_census_endpoint_elapsed_ms",receipt.get("complete_census_endpoint_elapsed_ms"));
        e.put("grants_action_authority",false);e.put("query_history_proved",false);e.put("business_completion_verified",false);
        return Collections.unmodifiableMap(e);
    }
    void requireFormHistoryTarget(String path){
        if(!formHistory())return;
        Object roots=map(map(receipt,"form_history"),"comparison").get("protected_subtrees");
        boolean protectedTarget=false;for(Object root:(List<?>)roots)
            if(path!=null&&(path.equals(root)||path.startsWith((String)root+"/")))protectedTarget=true;
        need(protectedTarget,"history cannot expose a recommendation or unrelated target");
    }
    void requireHistoricalPublication(Map<String,Object> e){
        requirePublicationRecheck(e);
        if(inputHistory()){requireInputHistoryPublication(e);return;}
        if(!formHistory())return;
        need(metadataSchema().equals(e.get("schema"))&&"complete_native_ax_form_history".equals(e.get("mode"))
                &&Boolean.TRUE.equals(e.get("historical_form_planning_only"))
                &&Boolean.FALSE.equals(e.get("published_pair_is_current_tree_claimed")),"form history cannot claim a current executable graph");
        need(canonical(formHistoryEvidence()).equals(canonical(e.get("form_history"))),"actual complete form-history proof differs");
        Map<String,Object> complete=map(receipt,"second_completed_watermark"),published=map(e,"publication_event_watermark");
        onlyContent(complete,published);
        need(Boolean.valueOf(num(published,"events")!=num(complete,"events")).equals(e.get("events_after_complete_census_admitted"))
                &&"historical_form_planning_only".equals(e.get("post_census_events_use"))
                &&Boolean.TRUE.equals(e.get("publication_window_matched")),"historical event/window facts missing");
        long at=num(e,"published_elapsed_ms");
        need(at>=num(receipt,"sealed_elapsed_ms")&&at<num(receipt,"request_deadline_elapsed_ms")
                &&num(e,"capture_requested_elapsed_ms")==num(binding,"captured_elapsed_ms"),"original history clocks/deadline required");
    }
    static boolean nativeTextMode(boolean supportedNativeGoal,boolean profileVisual,boolean adapterVisual){
        need(profileVisual==adapterVisual,"runtime profile and actual image adapter disagree");
        return supportedNativeGoal&&!profileVisual;
    }
    void requireBinding(Map<String,Object> expected){
        need(expected!=null&&!expected.isEmpty(),"explicit AX consumer identity required");
        for(Map.Entry<String,Object> e:expected.entrySet())
            need(binding.containsKey(e.getKey())&&canonical(binding.get(e.getKey())).equals(canonical(e.getValue())),
                    "AX receipt binding differs: "+e.getKey());
    }
    boolean sameSource(ObservationCaptureEvidence other){
        return other!=null&&kind.equals(other.kind)&&receiptSha256.equals(other.receiptSha256)
                &&Arrays.equals(raw,other.raw);
    }
    Map<String,Object> evidence(){
        Map<String,Object> e=new TreeMap<String,Object>();
        e.put("kind",kind);e.put("receipt_schema",inputHistory()?INPUT_SCHEMA:formHistory()?FORM_SCHEMA:SCHEMA);
        e.put("receipt_file",binding.get("observation_id")+"-native-ax.json");
        e.put("receipt_sha256",receiptSha256);e.put("receipt_bytes",raw.length);
        e.put("screenshot_present",false);e.put("screen_sha256",null);
        e.put("full_two_censuses",true);e.put("publication_refreshes_capture_age",false);
        if(publicationRecheck!=null)e.put("publication_recheck",publicationRecheck);
        if(formHistory()){e.put("historical_form_planning_only",true);e.put("published_pair_is_current_tree_claimed",false);e.put("form_history",formHistoryEvidence());}
        if(inputHistory()){e.put("historical_empty_input_planning_only",true);e.put("published_pair_is_current_tree_claimed",false);e.put("input_history",inputHistoryEvidence());}
        e.put("grants_action_authority",false);e.put("business_completion_verified",false);
        return Collections.unmodifiableMap(e);
    }
    private static void validate(Map<String,Object> r,String kind){
        final boolean form=NATIVE_AX_FORM_HISTORY.equals(kind),input=NATIVE_AX_INPUT_HISTORY.equals(kind),history=form||input;
        need((input?INPUT_SCHEMA:form?FORM_SCHEMA:SCHEMA).equals(r.get("schema"))&&kind.equals(r.get("kind")),"explicit native AX receipt kind/schema required");
        need(Boolean.FALSE.equals(r.get("visual_model"))&&Boolean.FALSE.equals(r.get("screenshot_present"))
                &&Boolean.FALSE.equals(r.get("publication_refreshes_capture_age"))
                &&Boolean.FALSE.equals(r.get("grants_action_authority"))
                &&Boolean.FALSE.equals(r.get("business_completion_verified")),"AX receipt cannot supply pixels or grant authority");
        Map<String,Object> b=map(r,"binding");
        need(b.keySet().equals(BINDING_KEYS),"complete exact AX identity binding required");
        for(String k:keys("owner_sha256 execution_target_sha256 task_authorization_sha256 actual_selection_sha256 native_goal_sha256 app_tree_sha256 observation_state_sha256"))
            need(sha(b.get(k)),"AX binding hash missing: "+k);
        need(id(b.get("task_id"))&&id(b.get("observation_id")),"actual task and observation IDs required");
        need(b.get("package") instanceof String&&((String)b.get("package")).matches("[A-Za-z0-9_.]+"),"AX package required");
        need(b.get("background_generation") instanceof String&&((String)b.get("background_generation")).matches(
                "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),"AX generation required");
        need(num(b,"display_id")>0&&num(b,"window_id")>=0&&num(b,"rotation")>=0&&num(b,"rotation")<=3
                &&num(b,"width")>0&&num(b,"height")>0
                &&num(b,"right")>num(b,"left")&&num(b,"bottom")>num(b,"top"),"actual AX background geometry required");
        Map<String,Object> a=map(r,"first"),z=map(r,"second");
        validateCensus(a);validateCensus(z);
        need(canonical(a.get("reported_windows")).equals(canonical(z.get("reported_windows")))
                &&canonical(a.get("window")).equals(canonical(z.get("window"))),"complete AX windows differ");
        if(!history)need(canonical(a.get("nodes")).equals(canonical(z.get("nodes")))
                &&canonical(a.get("identity")).equals(canonical(z.get("identity"))),"complete AX trees/identity differ");
        else{
            Map<String,Object> left=new TreeMap<String,Object>(map(a,"identity")),right=new TreeMap<String,Object>(map(z,"identity"));
            left.remove("app_tree_sha256");left.remove("observation_state_sha256");
            right.remove("app_tree_sha256");right.remove("observation_state_sha256");
            need(canonical(left).equals(canonical(right)),"historical form task/window/identity differs");
        }
        Map<String,Object> identity=map(a,"identity");
        Set<String> censusKeys=new TreeSet<String>(BINDING_KEYS);
        censusKeys.remove("observation_id");censusKeys.remove("captured_elapsed_ms");censusKeys.remove("profile_window");
        censusKeys.remove("profile_action_identity");censusKeys.remove("original_census_captured_elapsed_ms");
        need(identity.keySet().equals(censusKeys),"complete AX census identity required");
        for(String k:censusKeys)need(canonical(identity.get(k)).equals(canonical(b.get(k))),"AX census binding differs: "+k);
        need(canonical(a.get("profile_window")).equals(canonical(b.get("profile_window"))),"original profile window binding differs");
        need(canonical(a.get("profile_owner")).equals(canonical(b.get("profile_action_identity"))),"original profile action identity differs");
        need(num(a,"census_captured_elapsed_ms")==num(b,"original_census_captured_elapsed_ms"),"original census clock differs");
        // A fresh profile proof may have a later timestamp, but its stable owner tuple cannot change.
        need(canonical(a.get("profile_owner")).equals(canonical(z.get("profile_owner"))),"AX profile owner changed");
        long start=num(r,"request_started_elapsed_ms"),deadline=num(r,"request_deadline_elapsed_ms");
        long captured=num(b,"captured_elapsed_ms"),sealed=num(r,"sealed_elapsed_ms");
        need(start>=0&&deadline>start&&num(a,"read_started_elapsed_ms")>=start
                &&num(a,"read_completed_elapsed_ms")>=num(a,"read_started_elapsed_ms")
                &&num(a,"read_completed_elapsed_ms")<=captured
                &&captured<=num(z,"read_started_elapsed_ms")
                &&num(z,"read_started_elapsed_ms")<=num(z,"read_completed_elapsed_ms")
                &&num(z,"read_completed_elapsed_ms")<=sealed&&sealed<deadline,"AX receipt clock/deadline differs");
        Map<String,Object> capture=map(r,"capture_watermark"),before=map(r,"second_start_watermark"),end=map(r,"second_completed_watermark");
        onlyContent(capture,before);onlyContent(before,end);onlyContent(capture,end);
        need(Boolean.TRUE.equals(r.get("complete_census_endpoint_frozen")),"complete AX endpoint watermark required");
        if(input){
            Map<String,Object> h=map(r,"input_history");
            need(h.keySet().equals(keys("phase installed_set_sha256 provider_version_code provider_base_apk_sha256 comparison"))
                    &&"search_input".equals(h.get("phase"))&&sha(h.get("installed_set_sha256"))
                    &&num(h,"provider_version_code")==NativeXiaomiSearchInputObservation.VERSION_CODE
                    &&NativeXiaomiSearchInputObservation.BASE_APK_SHA256.equals(h.get("provider_base_apk_sha256")),
                    "explicit installed Xiaomi empty-input provider required");
            Map<String,Object> proof=NativeXiaomiSearchInputObservation.compareAxCensuses(a,z,b,(String)h.get("installed_set_sha256"));
            need(canonical(proof).equals(canonical(h.get("comparison"))),"recomputed complete input-history proof differs");
            need(Boolean.TRUE.equals(r.get("historical_empty_input_planning_only"))
                    &&Boolean.FALSE.equals(r.get("published_pair_is_current_tree_claimed"))
                    &&!r.containsKey("form_history")&&!r.containsKey("historical_form_planning_only"),"empty input history scope missing");
        }else if(history){
            need(!r.containsKey("input_history")&&!r.containsKey("historical_empty_input_planning_only"),"form history cannot include input-history semantics");
            Map<String,Object> h=map(r,"form_history");
            need(h.keySet().equals(keys("phase installed_set_sha256 provider_version_code provider_base_apk_sha256 comparison"))
                    &&"ctrip_single_flight_form".equals(h.get("phase"))&&sha(h.get("installed_set_sha256"))
                    &&num(h,"provider_version_code")==1779
                    &&"666ce1e8234682c89247d5109c5cfa36451c6e67238ee38a545c2d84c88360fa".equals(h.get("provider_base_apk_sha256")),
                    "explicit installed Ctrip form provider required");
            Map<String,Object> proof=NativeCtripFormObservation.compareAxCensuses(a,z,b,(String)h.get("installed_set_sha256"));
            need(canonical(proof).equals(canonical(h.get("comparison"))),"recomputed complete form-history proof differs");
            need(Boolean.TRUE.equals(r.get("historical_form_planning_only"))
                    &&Boolean.FALSE.equals(r.get("published_pair_is_current_tree_claimed")),"form history scope missing");
        }else need(!r.containsKey("form_history")&&!r.containsKey("input_history")
                &&!Boolean.TRUE.equals(r.get("historical_form_planning_only"))&&!Boolean.TRUE.equals(r.get("historical_empty_input_planning_only")),
                "ordinary equal AX cannot hide history semantics");
        canonicalBytes(r); // UTF-8, including real Chinese text and JSON escapes, is the byte limit.
    }
    private static void validateCensus(Map<String,Object> c){
        need(Boolean.TRUE.equals(c.get("complete"))&&Boolean.FALSE.equals(c.get("truncated")),"complete AX census required");
        Object nodes=c.get("nodes");need(nodes instanceof List,"actual AX census nodes required");
        List<?> rows=(List<?>)nodes;need(!rows.isEmpty()&&rows.size()<=MAX_NODES,"bounded complete AX census required");
        need(num(c,"visited")==rows.size()&&num(c,"pending")==0&&num(c,"child_slots_omitted")==0
                &&num(c,"node_budget_omissions")==0&&num(c,"text_budget_omissions")==0,"complete AX census counters differ");
        map(c,"reported_windows");map(c,"window");map(c,"identity");
        Set<String> paths=new TreeSet<String>();
        for(Object row:rows){need(row instanceof Map,"AX raw node map required");Map<?,?> n=(Map<?,?>)row;
            need(n.get("path") instanceof String&&paths.add((String)n.get("path")),"unique actual AX paths required");}
        need(paths.contains("0"),"complete AX root required");
        need(c.containsKey("profile_window")&&c.containsKey("profile_owner"),"explicit AX profile provenance required");
    }
    private static void onlyContent(Map<String,Object> before,Map<String,Object> after){
        long ae=num(after,"events"),be=num(before,"events"),ac=num(after,"content"),bc=num(before,"content");
        need(num(before,"unknown")==0&&num(after,"unknown")==0
                &&num(before,"boundary")==num(after,"boundary")&&be>=0&&bc>=0&&ae>=be&&ac>=bc&&ae-be==ac-bc,
                "AX unknown/boundary event or incomplete endpoint coverage");
    }
    private static long num(Map<String,Object> m,String k){
        Object v=m.get(k);need(v instanceof Integer||v instanceof Long,"integer AX field required: "+k);return ((Number)v).longValue();
    }
    private static boolean sha(Object v){return v instanceof String&&((String)v).matches("[0-9a-f]{64}");}
    private static boolean id(Object v){return v instanceof String&&((String)v).matches("[0-9a-f]{32}");}
    private static Set<String> keys(String values){return Collections.unmodifiableSet(new TreeSet<String>(Arrays.asList(values.split(" "))));}
    private static Map<String,Object> map(Map<String,Object> parent,String key){
        Object v=parent.get(key);need(v instanceof Map,"AX object missing: "+key);
        Map<String,Object> out=new TreeMap<String,Object>();
        for(Map.Entry<?,?> e:((Map<?,?>)v).entrySet()){need(e.getKey() instanceof String,"AX object key required");out.put((String)e.getKey(),e.getValue());}
        return Collections.unmodifiableMap(out);
    }
    static Map<String,Object> freezeMap(Map<String,Object> value){
        need(value!=null,"AX receipt required");return map(Collections.<String,Object>singletonMap("value",freeze(value,0)),"value");
    }
    private static Object freeze(Object v,int depth){
        need(depth<=32,"AX receipt nesting bound");
        if(v==null||v instanceof Boolean||v instanceof Integer||v instanceof Long)return v;
        if(v instanceof String){validString((String)v);return v;}
        if(v instanceof Map){Map<String,Object> out=new TreeMap<String,Object>();need(((Map<?,?>)v).size()<=16384,"AX map bound");
            for(Map.Entry<?,?> e:((Map<?,?>)v).entrySet()){
                need(e.getKey() instanceof String,"AX key string required");String k=(String)e.getKey();validString(k);
                out.put(k,freeze(e.getValue(),depth+1));}return Collections.unmodifiableMap(out);}
        if(v instanceof List){List<Object> out=new ArrayList<Object>();need(((List<?>)v).size()<=16384,"AX list bound");
            for(Object x:(List<?>)v)out.add(freeze(x,depth+1));return Collections.unmodifiableList(out);}
        throw new IllegalArgumentException("unsupported AX receipt value");
    }
    private static void validString(String value){
        need(value.length()<=MAX_RECEIPT_BYTES,"AX string bound");
        for(int i=0;i<value.length();i++){char c=value.charAt(i);
            if(Character.isHighSurrogate(c))need(++i<value.length()&&Character.isLowSurrogate(value.charAt(i)),"AX invalid UTF-16");
            else need(!Character.isLowSurrogate(c),"AX invalid UTF-16");}
    }
    static byte[] canonicalBytes(Object v){
        byte[] bytes=canonical(v).getBytes(StandardCharsets.UTF_8);need(bytes.length>0&&bytes.length<=MAX_RECEIPT_BYTES,"AX receipt UTF-8 byte bound");return bytes;
    }
    private static String canonical(Object v){StringBuilder out=new StringBuilder();append(out,v,0);return out.toString();}
    private static void append(StringBuilder out,Object v,int depth){
        need(depth<=32,"AX canonical depth bound");
        if(v==null){out.append("null");return;}
        if(v instanceof Boolean||v instanceof Integer||v instanceof Long){out.append(v);return;}
        if(v instanceof String){quote(out,(String)v);return;}
        if(v instanceof Map){out.append('{');boolean comma=false;Map<String,Object> sorted=new TreeMap<String,Object>();
            for(Map.Entry<?,?> e:((Map<?,?>)v).entrySet()){need(e.getKey() instanceof String,"AX canonical key");sorted.put((String)e.getKey(),e.getValue());}
            for(Map.Entry<String,Object> e:sorted.entrySet()){if(comma)out.append(',');comma=true;quote(out,e.getKey());out.append(':');append(out,e.getValue(),depth+1);}
            out.append('}');}
        else if(v instanceof List){out.append('[');boolean comma=false;for(Object item:(List<?>)v){if(comma)out.append(',');comma=true;append(out,item,depth+1);}out.append(']');}
        else throw new IllegalArgumentException("AX canonical value");
        need(out.length()<=MAX_RECEIPT_BYTES,"AX canonical character bound");
    }
    private static void quote(StringBuilder out,String s){
        validString(s);out.append('"');for(int i=0;i<s.length();i++){char c=s.charAt(i);
            if(c=='"'||c=='\\')out.append('\\').append(c);
            else if(c<32){String h=Integer.toHexString(c);out.append("\\u");for(int p=h.length();p<4;p++)out.append('0');out.append(h);}
            else out.append(c);
        }out.append('"');need(out.length()<=MAX_RECEIPT_BYTES,"AX canonical character bound");
    }
    static String hash(byte[] bytes){
        try{byte[] digest=MessageDigest.getInstance("SHA-256").digest(bytes);StringBuilder out=new StringBuilder(64);
            for(byte b:digest){out.append(Character.forDigit((b&255)>>>4,16));out.append(Character.forDigit(b&15,16));}return out.toString();}
        catch(java.security.NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
    }
    private static void need(boolean value,String reason){if(!value)throw new IllegalArgumentException(reason);}
}
