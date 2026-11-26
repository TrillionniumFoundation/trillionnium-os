package org.trillionnium.hepta.local;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.zip.CRC32;

/** Complete census of the very graph published with original pixels.
 * This is read-only historical evidence, not a native_ax capture, a fresh tree,
 * a simultaneous screenshot claim, a NodeRef, or an action/completion permit. */
final class PixelNativeCensusEvidence {
    // Complete pure members copied byte-for-byte from NativeAppEvidence; the host gate
    // checks all three full bodies against that source before any compilation.
    static String fingerprint(Object value){StringBuilder out=new StringBuilder();canonical(out,value,0);return hash(out.toString());}
    private static void canonical(StringBuilder out,Object value,int depth){
        need(depth<=16,"evidence nesting budget");
        if(value==null){out.append('n');return;}
        if(value instanceof String){String s=(String)value;out.append('s').append(s.getBytes(StandardCharsets.UTF_8).length).append(':').append(s);return;}
        if(value instanceof Boolean){out.append(Boolean.TRUE.equals(value)?'t':'f');return;}
        if(value instanceof Byte||value instanceof Short||value instanceof Integer||value instanceof Long){out.append('i').append(value).append(';');return;}
        if(value instanceof Map<?,?>){TreeMap<String,Object> sorted=new TreeMap<String,Object>();for(Map.Entry<?,?> e:((Map<?,?>)value).entrySet()){
            need(e.getKey() instanceof String,"evidence map key");sorted.put((String)e.getKey(),e.getValue());}
            out.append('{');for(Map.Entry<String,Object> e:sorted.entrySet()){canonical(out,e.getKey(),depth+1);canonical(out,e.getValue(),depth+1);}out.append('}');return;}
        if(value instanceof Iterable<?>){out.append('[');for(Object x:(Iterable<?>)value)canonical(out,x,depth+1);out.append(']');return;}
        throw new IllegalArgumentException("native evidence scalar type: "+Objects.toString(value.getClass()));
    }
    static String hash(String value){
        try{byte[] bytes=MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));StringBuilder out=new StringBuilder(64);
            char[] h="0123456789abcdef".toCharArray();for(byte b:bytes)out.append(h[(b>>>4)&15]).append(h[b&15]);return out.toString();
        }catch(NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
    }
    static final int MAX_PNG_BYTES=16*1024*1024;
    private static final String SCHEMA="hepta.pixels-native-census.v1";
    private static final Set<String> CENSUS_KEYS=keys("identity complete truncated read_started_elapsed_ms read_completed_elapsed_ms census_captured_elapsed_ms ime_visibility visited retained pending child_slots_omitted node_budget_omissions text_budget_omissions reported_windows window profile_window profile_owner nodes");
    private static final Set<String> FRAME_KEYS=keys("observation_id package owner_sha256 background_generation app_tree_sha256 observation_state_sha256 display_id window_id rotation width height left top right bottom captured_elapsed_ms profile_window screen_sha256");
    private static final String[] CLOCK_KEYS={"sample_graph_started_elapsed_ms","sample_graph_completed_elapsed_ms",
        "capture_requested_elapsed_ms","screenshot_callback_elapsed_ms","pair_graph_started_elapsed_ms",
        "pair_graph_completed_elapsed_ms","pair_sealed_elapsed_ms","png_encode_started_elapsed_ms",
        "png_encode_completed_elapsed_ms","png_persisted_and_hashed_elapsed_ms",
        "publication_check_started_elapsed_ms","publication_check_completed_elapsed_ms"};
    final String receiptSha256;
    final int receiptBytes;
    private final byte[] raw;
    private final Map<String,Object> receipt,binding,clocks;
    private final NativeActionSnapshotCheck.Snapshot snapshot;
    private final boolean persisted;

    /** Obtained by one full bounded read of the original PNG, not a caller-supplied hash. */
    static final class Png {
        final String sha256;final int bytes,width,height;
        private Png(String sha256,int bytes,int width,int height){this.sha256=sha256;this.bytes=bytes;this.width=width;this.height=height;}
    }
    static Png readPng(InputStream stream,int expectedWidth,int expectedHeight)throws IOException{
        need(stream!=null&&expectedWidth>0&&expectedHeight>0,"actual original PNG input/dimensions");
        final MessageDigest digest;
        try{digest=MessageDigest.getInstance("SHA-256");}
        catch(java.security.NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
        byte[] header=new byte[33],tail=new byte[12],buffer=new byte[16384];int count=0,got;
        while((got=stream.read(buffer))!=-1){
            if(got==0)throw new IOException("PNG read made no progress");
            if(got>MAX_PNG_BYTES-count)throw new IOException("original PNG exceeds fixed byte bound");
            digest.update(buffer,0,got);
            for(int i=0;i<got;i++){if(count<33)header[count]=buffer[i];tail[count%12]=buffer[i];count++;}
        }
        need(count>=45,"complete original PNG header/end");
        byte[] signature={(byte)137,80,78,71,13,10,26,10};
        for(int i=0;i<8;i++)need(header[i]==signature[i],"original PNG signature");
        need(u32(header,8)==13&&header[12]=='I'&&header[13]=='H'&&header[14]=='D'&&header[15]=='R',"original PNG IHDR");
        long width=u32(header,16),height=u32(header,20);
        need(width==expectedWidth&&height==expectedHeight,"original PNG dimensions differ from published graph");
        CRC32 crc=new CRC32();crc.update(header,12,17);need(crc.getValue()==u32(header,29),"original PNG IHDR checksum");
        byte[] end={0,0,0,0,73,69,78,68,(byte)174,66,96,(byte)130};
        for(int i=0;i<12;i++)need(tail[(count+i)%12]==end[i],"original PNG terminal chunk");
        return new Png(hex(digest.digest()),count,expectedWidth,expectedHeight);
    }

    static PixelNativeCensusEvidence fromCapturedGraph(Map<String,Object> input,String observationId,long capturedAt,
            String installedSetSha256,Png png,Map<String,Object> timeline){
        return new PixelNativeCensusEvidence(input,observationId,capturedAt,installedSetSha256,png,timeline);
    }
    private PixelNativeCensusEvidence(Map<String,Object> input,String id,long capturedAt,String installed,Png png,Map<String,Object> timeline){
        Map<String,Object> census=ObservationCaptureEvidence.freezeMap(input);
        need(census.keySet().equals(CENSUS_KEYS),"exact complete census fields");
        need(Boolean.TRUE.equals(census.get("complete"))&&Boolean.FALSE.equals(census.get("truncated"))
            &&"hidden".equals(census.get("ime_visibility")),"complete untruncated census with known IME");
        Map<String,Object> identity=map(census,"identity"),window=map(census,"window"),owner=map(census,"profile_owner");
        need(id!=null&&id.matches("[0-9a-f]{32}")&&sha(installed)&&png!=null,"original observation/installed set/PNG");
        need(png.width==number(identity,"width")&&png.height==number(identity,"height"),"same original PNG/census dimensions");
        need(number(identity,"display_id")>1&&owner.keySet().equals(NativeActionSnapshotCheck.PROFILE_IDENTITY),"actual managed profile census");
        need(census.get("profile_window") instanceof Map,"actual profile window witness");
        for(String key:new String[]{"package","window_id","display_id","rotation","left","top","right","bottom","width","height"})
            need(Objects.equals(window.get(key),identity.get(key)),"same full census window "+key);
        need(window.get("metadata") instanceof String&&!((String)window.get("metadata")).isEmpty(),"actual window metadata");
        Map<String,Object> windows=map(census,"reported_windows");
        need(number(windows,"display_id")==number(identity,"display_id")
            &&number(windows,"target_window_id")==number(identity,"window_id"),"same reported display/window");
        need(windows.get("windows") instanceof List&&!((List<?>)windows.get("windows")).isEmpty(),"complete reported windows");
        Map<String,Object> env=new TreeMap<String,Object>();
        env.put("task_id",identity.get("task_id"));env.put("owner_sha256",identity.get("owner_sha256"));
        env.put("target_sha256",identity.get("execution_target_sha256"));env.put("authorization_sha256",identity.get("task_authorization_sha256"));
        env.put("selection_sha256",identity.get("actual_selection_sha256"));env.put("installed_set_sha256",installed);
        env.put("goal_sha256",identity.get("native_goal_sha256"));env.put("background_generation",identity.get("background_generation"));
        env.put("origin_observation_id",id);env.putAll(owner);
        for(String key:new String[]{"package","display_id","window_id","rotation","width","height"})env.put(key,identity.get(key));
        env.put("root_bounds",Arrays.asList(integer(identity,"left"),integer(identity,"top"),integer(identity,"right"),integer(identity,"bottom")));
        env.put("window_metadata_sha256",ObservationCaptureEvidence.hash(((String)window.get("metadata")).getBytes(StandardCharsets.UTF_8)));
        env.put("reported_windows_sha256",fingerprint(windows));env.put("reported_windows_complete",true);
        env.put("ime_visibility","hidden");env.put("captured_elapsed_ms",Long.valueOf(number(census,"census_captured_elapsed_ms")));
        env.put("full_native_complete",true);env.put("visited",integer(census,"visited"));env.put("pending",integer(census,"pending"));
        env.put("node_omissions",integer(census,"node_budget_omissions"));env.put("text_omissions",integer(census,"text_budget_omissions"));
        env.put("child_omissions",integer(census,"child_slots_omitted"));
        need(census.get("nodes") instanceof List,"complete original node list");
        List<NativeActionSnapshotCheck.Node> nodes=new ArrayList<NativeActionSnapshotCheck.Node>();
        int retained=0;
        for(Object value:(List<?>)census.get("nodes")){
            need(value instanceof Map,"actual complete node");
            Map<String,Object> row=stringMap((Map<?,?>)value);
            nodes.add(new NativeActionSnapshotCheck.Node(row));
            if(row.get("ref_signature_sha256")!=null)retained++;
        }
        snapshot=new NativeActionSnapshotCheck.Snapshot(env,nodes);
        need(retained==number(census,"retained"),"full census retained projection count");
        clocks=ObservationCaptureEvidence.freezeMap(timeline);
        Set<String> required=new TreeSet<String>(Arrays.asList(CLOCK_KEYS));
        required.addAll(Arrays.asList("request_started_elapsed_ms","request_deadline_elapsed_ms","proof_copied_elapsed_ms"));
        need(clocks.keySet().equals(required),"exact original clock domain");
        long previous=number(clocks,"request_started_elapsed_ms");need(previous>=0,"original elapsed clock");
        for(String key:CLOCK_KEYS){long at=number(clocks,key);need(at>=previous,"original capture timeline "+key);previous=at;}
        long copied=number(clocks,"proof_copied_elapsed_ms"),deadline=number(clocks,"request_deadline_elapsed_ms");
        need(copied>=previous&&copied<deadline,"proof within original request deadline");
        need(number(clocks,"sample_graph_started_elapsed_ms")==number(census,"read_started_elapsed_ms")
            &&number(clocks,"sample_graph_completed_elapsed_ms")==number(census,"read_completed_elapsed_ms")
            &&number(census,"census_captured_elapsed_ms")>=number(census,"read_started_elapsed_ms")
            &&number(census,"census_captured_elapsed_ms")<=number(census,"read_completed_elapsed_ms")
            &&number(clocks,"capture_requested_elapsed_ms")==capturedAt,"original graph and capture clocks");
        Map<String,Object> bound=new TreeMap<String,Object>(identity);
        bound.put("observation_id",id);bound.put("captured_elapsed_ms",Long.valueOf(capturedAt));
        bound.put("profile_window",census.get("profile_window"));bound.put("screen_sha256",png.sha256);
        need(sha((String)identity.get("app_tree_sha256"))&&sha((String)identity.get("observation_state_sha256")),"actual graph hashes");
        binding=ObservationCaptureEvidence.freezeMap(bound);
        Map<String,Object> value=new TreeMap<String,Object>();
        value.put("schema",SCHEMA);value.put("capture_kind",ObservationCaptureEvidence.PIXELS);
        value.put("binding",binding);value.put("png_file",id+".png");value.put("png_sha256",png.sha256);value.put("png_bytes",png.bytes);
        value.put("png_width",png.width);value.put("png_height",png.height);
        value.put("installed_set_sha256",installed);value.put("snapshot_sha256",snapshot.sha);
        value.put("census",census);value.put("capture_stages",clocks);
        value.put("complete_original_graph",true);value.put("retained_subset_used_as_full_census",false);
        value.put("same_instant_pixels_and_ax_claimed",false);value.put("current_tree_claimed",false);
        value.put("publication_refreshes_capture_age",false);value.put("grants_action_authority",false);
        value.put("business_completion_verified",false);value.put("navigation_route_bound",false);
        receipt=ObservationCaptureEvidence.freezeMap(value);raw=ObservationCaptureEvidence.canonicalBytes(receipt);
        receiptBytes=raw.length;receiptSha256=ObservationCaptureEvidence.hash(raw);persisted=false;
    }
    private PixelNativeCensusEvidence(PixelNativeCensusEvidence original){
        raw=original.raw;receipt=original.receipt;binding=original.binding;clocks=original.clocks;snapshot=original.snapshot;
        receiptBytes=original.receiptBytes;receiptSha256=original.receiptSha256;persisted=true;
    }
    PixelNativeCensusEvidence withPersistedReceipt(byte[] actual){
        need(!persisted&&actual!=null&&Arrays.equals(raw,actual),"complete actual persisted pixel/census receipt bytes");
        return new PixelNativeCensusEvidence(this);
    }
    byte[] receiptBytes(){return raw.clone();}
    Map<String,Object> completeReceipt(){return receipt;}
    Map<String,Object> summary(){
        need(persisted,"actual persisted census required");
        Map<String,Object> out=new TreeMap<String,Object>();
        out.put("schema",SCHEMA);out.put("capture_kind",ObservationCaptureEvidence.PIXELS);
        out.put("receipt_file",binding.get("observation_id")+"-pixels-native-census.json");
        out.put("receipt_sha256",receiptSha256);out.put("receipt_bytes",receiptBytes);
        out.put("png_file",receipt.get("png_file"));out.put("png_sha256",receipt.get("png_sha256"));out.put("png_bytes",receipt.get("png_bytes"));
        out.put("snapshot_sha256",snapshot.sha);out.put("full_native_nodes",snapshot.nodes.size());
        out.put("original_capture_elapsed_ms",binding.get("captured_elapsed_ms"));
        out.put("complete_original_graph",true);out.put("same_instant_pixels_and_ax_claimed",false);
        out.put("current_tree_claimed",false);out.put("grants_action_authority",false);
        out.put("business_completion_verified",false);out.put("navigation_route_bound",false);
        return ObservationCaptureEvidence.freezeMap(out);
    }
    void requirePublished(Map<String,Object> actual,Map<String,Object> capture,int visited,int retained){
        need(persisted,"actual persisted census required");
        need(actual!=null&&actual.keySet().equals(FRAME_KEYS),"complete actual published pixel identity");
        for(String key:FRAME_KEYS)need(Objects.equals(binding.get(key),actual.get(key)),"published pixel/census identity changed: "+key);
        need(capture!=null&&"hepta.observation-capture.v1".equals(capture.get("schema"))
            &&"pre_encoding_paired_history".equals(capture.get("mode")),"ordinary original pixel pair required");
        for(String key:CLOCK_KEYS)if(!key.startsWith("publication_check_"))
            need(Objects.equals(clocks.get(key),capture.get(key)),"published capture stage changed: "+key);
        long rechecks=number(capture,"post_effect_window_recheck_count");
        need(rechecks==0||rechecks==1,"original bounded publication recheck");
        if(rechecks==0){
            for(String key:new String[]{"publication_check_started_elapsed_ms","publication_check_completed_elapsed_ms"})
                need(Objects.equals(clocks.get(key),capture.get(key)),"published original window check differs");
        }else{
            need(Objects.equals(clocks.get("publication_check_started_elapsed_ms"),capture.get("first_publication_check_started_elapsed_ms"))
                &&Objects.equals(clocks.get("publication_check_completed_elapsed_ms"),capture.get("first_publication_check_completed_elapsed_ms"))
                &&Boolean.TRUE.equals(capture.get("historical_pair_after_known_target_event")),"original window-check history missing");
            need(number(capture,"publication_check_started_elapsed_ms")>=number(clocks,"proof_copied_elapsed_ms")
                &&number(capture,"publication_check_completed_elapsed_ms")>=number(capture,"publication_check_started_elapsed_ms"),"later original window check clock");
        }
        long published=number(capture,"published_elapsed_ms"),at=number(binding,"captured_elapsed_ms");
        need(published>=number(clocks,"proof_copied_elapsed_ms")&&published>=number(capture,"publication_check_completed_elapsed_ms")
            &&published<number(clocks,"request_deadline_elapsed_ms")
            &&number(capture,"capture_age_at_publication_ms")==published-at,"original publication clock/deadline");
        for(String key:new String[]{"same_instant_pixels_and_ax_claimed","publication_refreshes_capture_age","grants_action_authority","business_completion_verified"})
            need(Boolean.FALSE.equals(capture.get(key)),"pixels evidence cannot grant "+key);
        need(Boolean.TRUE.equals(capture.get("fresh_action_validation_required")),"original action gate retained");
        need(visited==snapshot.nodes.size()&&retained==number(map(receipt,"census"),"retained"),"published complete counters differ");
    }
    static String retainedValue(String text,int max){if(text.length()<=max)return text;int end=max;if(end>0&&Character.isHighSurrogate(text.charAt(end-1)))end--;return text.substring(0,end)+"…";}
    private static Set<String> keys(String value){return Collections.unmodifiableSet(new TreeSet<String>(Arrays.asList(value.split(" "))));}
    private static Map<String,Object> map(Map<String,Object> value,String key){need(value.get(key) instanceof Map,"map "+key);return stringMap((Map<?,?>)value.get(key));}
    private static Map<String,Object> stringMap(Map<?,?> value){
        Map<String,Object> result=new TreeMap<String,Object>();
        for(Map.Entry<?,?> entry:value.entrySet()){need(entry.getKey() instanceof String,"string evidence key");result.put((String)entry.getKey(),entry.getValue());}
        return result;
    }
    private static long number(Map<String,Object> value,String key){
        Object n=value.get(key);need(n instanceof Integer||n instanceof Long,"integer original evidence "+key);
        return ((Number)n).longValue();
    }
    private static int integer(Map<String,Object> value,String key){long n=number(value,key);need(n>=Integer.MIN_VALUE&&n<=Integer.MAX_VALUE,"bounded integer "+key);return (int)n;}
    private static boolean sha(String value){return value!=null&&value.matches("[0-9a-f]{64}");}
    private static long u32(byte[] value,int at){return ((long)(value[at]&255)<<24)|((long)(value[at+1]&255)<<16)|((long)(value[at+2]&255)<<8)|(value[at+3]&255);}
    private static String hex(byte[] bytes){StringBuilder out=new StringBuilder();for(byte b:bytes){out.append(Character.forDigit((b&255)>>>4,16)).append(Character.forDigit(b&15,16));}return out.toString();}
    private static void need(boolean value,String why){if(!value)throw new IllegalArgumentException(why);}
}
