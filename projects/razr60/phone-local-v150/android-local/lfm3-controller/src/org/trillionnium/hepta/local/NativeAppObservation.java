package org.trillionnium.hepta.local;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;

/** Android-side copying of one actual retained observation. No field is read
 * from model output, uiautomator fixtures, a previous task or a screenshot. */
final class NativeAppObservation {
    private NativeAppObservation() {}
    static String selectionSha(BackgroundSession.Selection selection)throws Exception{
        NativeAppEvidence.need(selection!=null,"actual native Selection missing");return NativeAppEvidence.fingerprint(value(selection.json()));
    }
    static NativeAppEvidence.Frame copy(String task,TaskAuthorization.Gate authorization,BackgroundSession background,
            PhoneObservation observed,NotesCompletionEvidence.Frame completion,String originalRecordSha)throws Exception{
        NativeAppEvidence.need(background!=null&&observed!=null&&completion!=null&&task.equals(background.taskId)
                &&authorization!=null&&task.equals(authorization.taskId),"actual native background/task observation required");
        BackgroundSession.Selection selected=background.selection;authorization.authorization.requireCompletionSelection(selected);
        BackgroundTaskTarget target=selected.taskTarget;
        NativeAppEvidence.need(target!=null&&target.nativeGoal!=null&&!target.webHelper()&&target.explicitSelection
                &&background.ownerSha256.equals(target.ownerSha256)&&target.packageName.equals(observed.packageName)
                &&background.generation.equals(observed.backgroundGeneration)&&background.displayId()==completion.displayId
                &&observed.backgroundAllowedPackages.size()==1&&observed.backgroundAllowedPackages.contains(target.packageName)
                &&target.packageName.equals(observed.backgroundBootstrapPackage),"same native lease/package/selection required");
        NativeAppEvidence.requireProfileTarget(background.profileTarget(),observed.profileWindow);
        if(observed.profileWindow!=null)background.requireHistoricalProfileWindow(observed.profileWindow,
                observed.windowId,observed.profileWindow.taskId,observed.capturedElapsedMillis);
        String expected=selectionSha(selected),actual=NativeAppEvidence.fingerprint(value(observed.backgroundSelectionEvidence()));
        NativeAppEvidence.need(expected.equals(actual),"actual observed native Selection projection differs");
        if(observed.capture!=null&&observed.capture.nativeText()&&observed.capture.kind.equals(observed.captureKind)){
            NativeAppEvidence.need(observed.capture!=null&&observed.screenshot==null&&observed.screenshotSha256==null,
                    "typed AX observation cannot claim pixels");
            Map<String,Object> goalBinding=NativeAppEvidence.map();goalBinding.put("native_goal_sha256",target.nativeGoal.contractSha256);
            observed.capture.requireBinding(goalBinding);
            if(observed.capture.formHistory())NativeAppEvidence.need(NativeCtripFlightPage.supported(target.nativeGoal)
                    &&background.profileTarget()!=null,"historical form requires the actual supported Ctrip profile goal");
            if(observed.capture.inputHistory())NativeAppEvidence.need(target.nativeGoal.readsXiaomiProduct()
                    &&NativeAppGoal.PRODUCT_MODEL.equals(target.nativeGoal.productModel)&&background.profileTarget()!=null,
                    "historical empty input requires the actual supported Xiaomi profile goal");
        }else NativeAppEvidence.need(ObservationCaptureEvidence.PIXELS.equals(observed.captureKind)&&observed.capture==null
                &&observed.screenshot!=null&&NativeAppEvidence.sha(observed.screenshotSha256),"actual original pixel observation required");
        List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>();
        for(PhoneObservation.Node n:observed.nodes){
            String label=n.label();if(n.text.trim().isEmpty()&&n.description.trim().isEmpty()
                    &&!"derived".equals(n.childText.status))label="";
            label=ObservedTargetLabels.project(label);
            nodes.add(new NativeAppEvidence.Node(n.id,n.packageName,n.className,n.viewId,n.text,n.description,
                    n.nativeTreePath,n.nativeParentClass,n.observedAppTreeSignature,label,
                    n.bounds.left,n.bounds.top,n.bounds.right,n.bounds.bottom,n.enabled,n.password,n.clickable,n.editable,n.scrollable,
                    n.selected,n.checkable,n.checked,new TreeSet<String>(n.scrollActions.directions)));
        }
        PhoneObservation.CollectionStats stats=observed.collectionStats;
        boolean complete=stats!=null&&!stats.truncated()&&stats.retained==nodes.size()&&stats.pending==0
                &&stats.childSlotsOmitted==0&&stats.nodeBudgetOmissions==0&&stats.textBudgetOmissions==0;
        return new NativeAppEvidence.Frame(task,target.ownerSha256,target.targetSha256,authorization.authorization.sha256,actual,
                observed.id,observed.packageName,observed.backgroundGeneration,observed.state.appTreeSha256,observed.treeSha256,
                observed.screenshotSha256,originalRecordSha,TaskCompletionGate.webFrameSha(completion),completion.displayId,
                observed.windowId,observed.rotation,observed.width,observed.height,observed.windowBounds.left,observed.windowBounds.top,
                observed.windowBounds.right,observed.windowBounds.bottom,observed.capturedElapsedMillis,observed.nodesTruncated,complete,nodes,
                completion.windowType,completion.metadataObserved,observed.profileWindow,observed.capture,formPurposeGeometry(observed));
    }
    /** Copies only the producer's bounded original certificate. It cannot
     * manufacture a current tree, model action, calendar source or a NodeRef. */
    static Map<String,Object> formPurposeGeometry(PhoneObservation observed)throws Exception{
        if(observed==null||!NativeAppGoal.CTRIP_PACKAGE.equals(observed.packageName))return null;
        if(observed.capture!=null)return observed.capture.formPurposeGeometry();
        JSONObject metadata=observed.captureMetadata();if(metadata==null)return null;
        Map<String,Object> found=null;
        for(String key:new String[]{"form_pair_comparison","post_encoding_form_pair_comparison"}){
            JSONObject encoded=metadata.optJSONObject(key);if(encoded==null)continue;
            JSONObject pair=decodePixelFormPair(encoded);
            if(!pair.has("form_purpose_geometry"))continue;
            NativeAppEvidence.need(found==null&&"hepta.ctrip-native-form-purpose-pair.v1".equals(pair.optString("schema"))
                    &&pair.optBoolean("fresh_action_validation_required")&&!pair.optBoolean("grants_action_authority")
                    &&!pair.optBoolean("published_pair_is_current_tree_claimed")
                    &&("form_pair_comparison".equals(key)?"pre_encoding_form_pair_history":"post_encoding_form_pair_history")
                        .equals(metadata.optString("mode")),"exact purpose-limited original pixel form pair required");
            Object copied=value(pair.getJSONObject("form_purpose_geometry"));
            NativeAppEvidence.need(copied instanceof Map,"actual purpose qualification map required");
            Map<String,Object> checked=NativeAppEvidence.map();
            for(Map.Entry<?,?> entry:((Map<?,?>)copied).entrySet()){
                NativeAppEvidence.need(entry.getKey() instanceof String,"purpose qualification string fields required");
                checked.put((String)entry.getKey(),entry.getValue());
            }
            NativeAppEvidence.need(!checked.containsKey("planning_observation_id"),"raw pixel proof cannot replace its observation binding");
            checked.put("planning_observation_id",observed.id);
            found=NativeAppEvidence.immutableMap(checked);
        }
        return found;
    }

    /** Lossless transport of a completed native form comparison inside the existing
     * 8192-byte pixel capture envelope. It grants no observation or action authority.
     * AX receipts keep their complete original maps and canonical validation. */
    private static final int PIXEL_FORM_BYTES=262144;
    private static final String PIXEL_FORM_SCHEMA="hepta.ctrip-form-pair-transport.v1",
            PIXEL_FORM_CODEC="zlib-deflate-base64";
    static Map<String,Object> pixelFormPair(Map<String,Object> proof){
        try{
            JSONObject original=new JSONObject(proof);requirePixelFormSchema(original);
            byte[] raw=original.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            NativeAppEvidence.need(raw.length>0&&raw.length<=PIXEL_FORM_BYTES,"complete form comparison UTF-8 bound");
            java.util.zip.Deflater zip=new java.util.zip.Deflater(java.util.zip.Deflater.DEFAULT_COMPRESSION);
            java.io.ByteArrayOutputStream packed=new java.io.ByteArrayOutputStream();
            try{
                zip.setInput(raw);zip.finish();byte[] block=new byte[4096];
                while(!zip.finished()){
                    int n=zip.deflate(block);
                    NativeAppEvidence.need(n>0&&packed.size()+n<=PIXEL_FORM_BYTES,"bounded form compression progress");
                    packed.write(block,0,n);
                }
            }finally{zip.end();}
            Map<String,Object> out=NativeAppEvidence.map();
            out.put("schema",PIXEL_FORM_SCHEMA);out.put("codec",PIXEL_FORM_CODEC);
            out.put("uncompressed_utf8_bytes",raw.length);
            out.put("uncompressed_sha256",ObservationCaptureEvidence.hash(raw));
            out.put("payload_base64",java.util.Base64.getEncoder().encodeToString(packed.toByteArray()));
            return NativeAppEvidence.immutableMap(out);
        }catch(org.json.JSONException malformed){
            throw new IllegalArgumentException("complete form comparison JSON required",malformed);
        }
    }
    /** Exact original bytes are restored before the proof is interpreted. The
     * producer's fixed bound, zlib end, UTF-8 and digest are independently checked. */
    static byte[] pixelFormPairBytes(JSONObject wrapper)throws Exception{
        java.util.Set<String> keys=new java.util.TreeSet<String>();
        for(java.util.Iterator<String> it=wrapper.keys();it.hasNext();)keys.add(it.next());
        NativeAppEvidence.need(keys.equals(new java.util.TreeSet<String>(java.util.Arrays.asList(
                "schema","codec","uncompressed_utf8_bytes","uncompressed_sha256","payload_base64")))
                &&PIXEL_FORM_SCHEMA.equals(wrapper.get("schema"))&&PIXEL_FORM_CODEC.equals(wrapper.get("codec")),
                "closed form transport schema and codec required");
        Object size=wrapper.get("uncompressed_utf8_bytes"),digest=wrapper.get("uncompressed_sha256"),
                payload=wrapper.get("payload_base64");
        NativeAppEvidence.need((size instanceof Integer||size instanceof Long)
                &&((Number)size).longValue()>0&&((Number)size).longValue()<=PIXEL_FORM_BYTES
                &&digest instanceof String&&((String)digest).matches("[0-9a-f]{64}")
                &&payload instanceof String&&!((String)payload).isEmpty()
                &&((String)payload).length()<=4*((PIXEL_FORM_BYTES+2)/3),"bounded form transport values required");
        int expected=((Number)size).intValue();String encoded=(String)payload;
        byte[] packed=java.util.Base64.getDecoder().decode(encoded);
        NativeAppEvidence.need(packed.length>=6&&packed.length<=PIXEL_FORM_BYTES
                &&java.util.Base64.getEncoder().encodeToString(packed).equals(encoded),"canonical bounded form base64 required");
        java.util.zip.Inflater unzip=new java.util.zip.Inflater();
        java.io.ByteArrayOutputStream restored=new java.io.ByteArrayOutputStream(Math.min(expected,4096));
        try{
            unzip.setInput(packed);byte[] block=new byte[4096];
            while(!unzip.finished()){
                int n=unzip.inflate(block);
                NativeAppEvidence.need(n>0||unzip.finished(),"form stream truncated, dictionary or no progress");
                NativeAppEvidence.need(restored.size()+n<=expected&&restored.size()+n<=PIXEL_FORM_BYTES,
                        "form decompression exceeds fixed original bound");
                restored.write(block,0,n);
            }
            NativeAppEvidence.need(unzip.getRemaining()==0,"form stream trailing bytes");
        }finally{unzip.end();}
        byte[] raw=restored.toByteArray();
        NativeAppEvidence.need(raw.length==expected&&digest.equals(ObservationCaptureEvidence.hash(raw)),
                "form original UTF-8 length or SHA differs");
        // REPORT rejects malformed or unmappable byte sequences rather than replacing them.
        java.nio.charset.StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                .decode(java.nio.ByteBuffer.wrap(raw));
        return raw;
    }
    static JSONObject decodePixelFormPair(JSONObject wrapper)throws Exception{
        byte[] raw=pixelFormPairBytes(wrapper);
        org.json.JSONTokener input=new org.json.JSONTokener(new String(raw,java.nio.charset.StandardCharsets.UTF_8));
        JSONObject decoded=new JSONObject(input);
        NativeAppEvidence.need(input.nextClean()==0,"form JSON trailing values");
        requirePixelFormSchema(decoded);return decoded;
    }
    private static void requirePixelFormSchema(JSONObject proof)throws org.json.JSONException{
        Object schema=proof.get("schema");
        NativeAppEvidence.need(("hepta.ctrip-native-form-observation-pair.v1".equals(schema)
                ||"hepta.ctrip-native-form-purpose-pair.v1".equals(schema))
                &&Boolean.TRUE.equals(proof.get("full_census_compared"))
                &&Boolean.TRUE.equals(proof.get("fresh_action_validation_required"))
                &&Boolean.FALSE.equals(proof.get("published_pair_is_current_tree_claimed"))
                &&Boolean.FALSE.equals(proof.get("grants_action_authority"))
                &&Boolean.FALSE.equals(proof.get("business_completion_verified")),
                "actual non-authoritative complete form comparison required");
    }

    private static Object value(Object v)throws Exception{
        if(v==null||v==JSONObject.NULL)return null;
        if(v instanceof JSONObject){Map<String,Object> out=NativeAppEvidence.map();JSONObject o=(JSONObject)v;
            for(java.util.Iterator<String> keys=o.keys();keys.hasNext();){String key=keys.next();out.put(key,value(o.get(key)));}return out;}
        if(v instanceof JSONArray){List<Object> out=new ArrayList<Object>();JSONArray a=(JSONArray)v;for(int i=0;i<a.length();i++)out.add(value(a.get(i)));return out;}
        if(v instanceof String||v instanceof Boolean||v instanceof Integer||v instanceof Long)return v;
        throw new IllegalArgumentException("native Selection has an unsupported actual field");
    }
}
