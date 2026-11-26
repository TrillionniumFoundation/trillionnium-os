package org.trillionnium.hepta.local;

import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
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
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Values for one explicitly named manual fixture task.
 *
 * No model decision, Android node, action dispatch, grant, replay or completion
 * exists in this class. All three page routes are deliberately UNBOUND. The
 * original query/model path may reach a real detail page; this distinct port
 * can only preserve a reviewed request and refuse it until actual route
 * evidence and a separately reviewed final-effect bridge exist.
 */
final class NativeOrderPreviewManual {
    static final String RECOGNITION = "complete_literal_manual_order_preview_fixture.v1/";
    static final String READY_SCHEMA = "hepta.order-preview.manual-fixture-ready.v1";
    static final String REQUEST_SCHEMA = "hepta.order-preview.manual-fixture-request.v1";
    static final String REFUSAL_SCHEMA = "hepta.order-preview.manual-fixture-refusal.v1";
    static final long REVIEW_LIMIT_MS = 30000;
    static final int REQUEST_MAX = 4096;
    static final Set<String> PURPOSES = keys("preview_open_sku,preview_select_requested_variant,preview_open_confirmation");
    private static final Set<String> REQUEST_KEYS = keys("schema,request_id,task_id,owner_sha256,ready_sha256,nonce,purpose,node");
    private static final Set<String> NODE_KEYS = keys("tree_path,facts_sha256");
    private NativeOrderPreviewManual() { }

    /** Read actual packaged build bytes independently of opt-in scope state.
     * The result is historical identity metadata only, never task authority.
     * The caller owns/closes the AssetManager stream and retains its live owner. */
    static String packagedBuildSha(java.io.InputStream input,String expectedSha)throws Exception {
        need(input!=null,"packaged controller build asset is unavailable");
        java.io.ByteArrayOutputStream output=new java.io.ByteArrayOutputStream();
        byte[] buffer=new byte[8192];int count;
        while((count=input.read(buffer))!=-1) {
            need(count>0,"packaged controller build asset made no read progress");
            need(output.size()+count<=131072,"packaged controller build asset byte bound");
            output.write(buffer,0,count);
        }
        byte[] raw=output.toByteArray();
        need(raw.length>0,"packaged controller build asset is empty");
        String text=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString();
        JSONObject value=WebEvidenceJson.parse(text,131072);
        need("hepta.actual-build-inputs.v1".equals(WebEvidenceJson.text(value,"schema"))
                &&WebEvidenceJson.number(value,"version_code")>0
                &&value.get("source_inputs") instanceof JSONArray
                &&((JSONArray)value.get("source_inputs")).length()>0,"packaged controller build asset contract differs");
        String actual=sha256(raw);
        need(expectedSha==null||(sha(expectedSha)&&expectedSha.equals(actual)),
                "packaged controller build asset differs from captured scope");
        return actual;
    }

    static final class Owner {
        final NativeAppGoal goal;
        final String purpose;
        private Owner(NativeAppGoal goal,String purpose) {
            this.goal=goal;this.purpose=purpose;
        }
        Map<String,Object> evidence() {
            Map<String,Object> out=map();
            out.put("schema","hepta.order-preview.manual-fixture-owner.v1");
            out.put("owner_sha256",goal.ownerSha256);
            out.put("goal_contract_sha256",goal.contractSha256);
            out.put("purpose",purpose);out.put("goal",goal.evidence());
            out.put("manual_navigation_origin","owner_manual_fixture");
            out.put("requested_quantity",Integer.valueOf(1));
            out.put("quantity_modification_authorized",false);
            out.put("order_submission_authorized",false);
            out.put("payment_authorized",false);
            out.put("page_route_bound",false);
            return freeze(out);
        }
    }

    static Owner recognize(NativeAppGoal goal) {
        if(goal==null||!goal.recognition.startsWith(RECOGNITION))return null;
        String purpose=goal.recognition.substring(RECOGNITION.length());
        need(PURPOSES.contains(purpose)
                &&NativeAppGoal.PRODUCT_ORDER_PREVIEW.equals(goal.kind)
                &&NativeAppGoal.XIAOMI_PACKAGE.equals(goal.packageName)
                &&NativeAppGoal.PRODUCT_MODEL.equals(goal.productModel)
                &&goal.orderPreview!=null&&goal.orderPreview.quantity==1,
                "complete explicit manual-preview owner required");
        goal.requireBinding(goal.immutableOwner,goal.packageName);
        return new Owner(goal,purpose);
    }

    /** Exact bytes of an immutable task-private artifact; never a Phone path supplied by a request. */
    static final class Artifact {
        final String leaf,sha256;
        final long bytes;
        Artifact(String leaf,long bytes,String sha256) {
            need(leaf!=null&&leaf.matches("[a-z][a-z0-9-]{0,95}\\.(?:json|png)")
                    &&bytes>0&&bytes<=16L*1024*1024&&sha(sha256),"bounded private artifact required");
            this.leaf=leaf;this.bytes=bytes;this.sha256=sha256;
        }
        Map<String,Object> evidence() {
            Map<String,Object> out=map();out.put("leaf",leaf);out.put("bytes",Long.valueOf(bytes));out.put("sha256",sha256);
            return freeze(out);
        }
    }

    /**
     * Historical review material only. Its nonce binds a request to one live
     * owner; neither this nonce nor a valid request authorizes a click.
     */
    static final class Ready {
        final Owner owner;
        final NativeActionSnapshotCheck.Snapshot census;
        final String taskId,readyId,nonce,sha256;
        final long created,reviewDeadline,taskDeadline,leaseDeadline;
        final Map<String,Object> binding;
        private final byte[] serialized;
        private boolean consumed;
        Ready(Owner owner,NativeActionSnapshotCheck.Snapshot census,Map<String,Object> binding,
                List<Artifact> artifacts,String readyId,String nonce,long created,long taskDeadline,long leaseDeadline) {
            need(owner!=null&&census!=null&&binding!=null&&id(readyId)&&sha(nonce),"actual bounded READY inputs required");
            this.owner=owner;this.census=census;this.binding=freeze(binding);
            this.taskId=text(census.env,"task_id");this.readyId=readyId;this.nonce=nonce;
            this.created=created;this.taskDeadline=taskDeadline;this.leaseDeadline=leaseDeadline;
            need(created>=0&&created>=integer(census.env,"captured_elapsed_ms")
                    &&created<taskDeadline&&created<leaseDeadline,"original task/lease deadline expired");
            reviewDeadline=Math.min(Math.min(taskDeadline,leaseDeadline),Math.addExact(created,REVIEW_LIMIT_MS));
            need(census.env.keySet().equals(NativeActionSnapshotCheck.PROFILE_ENVELOPE)
                    &&integer(census.env,"display_id")>1
                    &&NativeAppGoal.XIAOMI_PACKAGE.equals(census.env.get("package"))
                    &&owner.goal.ownerSha256.equals(census.env.get("owner_sha256"))
                    &&owner.goal.contractSha256.equals(census.env.get("goal_sha256")),
                    "same complete managed-profile Xiaomi census required");
            Set<String> identity=new TreeSet<String>(NativeActionSnapshotCheck.PROFILE_AUTHORITY);
            identity.remove("origin_observation_id");
            for(String key:identity)need(census.env.get(key).equals(binding.get(key)),"READY binding differs: "+key);
            need(binding.keySet().equals(union(identity,keys("controller_build_identity_sha256")))
                    &&sha(text(binding,"controller_build_identity_sha256")),"closed live binding required");
            need(artifacts!=null&&artifacts.size()==3,"frame, PNG and full census originals required");
            Set<String> leaves=new TreeSet<String>();List<Object> originals=new ArrayList<Object>();
            for(Artifact artifact:artifacts) {
                need(artifact!=null&&leaves.add(artifact.leaf),"duplicate original artifact");
                originals.add(artifact.evidence());
            }
            need(leaves.equals(keys("before-census.json,before-frame.json,before.png")),"complete before artifact set required");
            Map<String,Object> out=map();out.put("schema",READY_SCHEMA);out.put("ready_id",readyId);
            out.put("task_id",taskId);out.put("nonce",nonce);out.put("owner",owner.evidence());out.put("binding",this.binding);
            out.put("observation_id",census.env.get("origin_observation_id"));out.put("census_sha256",census.sha);
            out.put("node_facts_digest_format","hepta.native-value-fingerprint.v1");
            out.put("created_elapsed_ms",Long.valueOf(created));out.put("review_deadline_elapsed_ms",Long.valueOf(reviewDeadline));
            out.put("original_task_deadline_elapsed_ms",Long.valueOf(taskDeadline));out.put("original_lease_deadline_elapsed_ms",Long.valueOf(leaseDeadline));
            out.put("before_originals",originals);out.put("request_leaf","request.json");
            out.put("publication_marker_leaf","published.json");out.put("request_publication_marker_leaf","request-published.json");
            out.put("ready_is_fresh_action_authority",false);out.put("sdk_references_retained",false);
            out.put("manual_navigation_bound",false);out.put("grants_dispatch",false);out.put("business_success",false);
            serialized=json(out);sha256=sha256(serialized);
        }
        byte[] bytes(){return serialized.clone();}
        synchronized ManualPreviewGuard consume(Request request,long now) {
            need(!consumed,"manual request already consumed");
            need(request!=null&&now>=created&&now<reviewDeadline&&now<taskDeadline&&now<leaseDeadline,
                    "manual request expired or clock moved backwards");
            need(taskId.equals(request.taskId)&&owner.goal.ownerSha256.equals(request.ownerSha)
                    &&sha256.equals(request.readySha)&&nonce.equals(request.nonce)
                    &&owner.purpose.equals(request.purpose),"request does not name this live READY");
            NativeActionSnapshotCheck.Node node=census.node(request.path);
            need(node.click()&&node.label!=null&&!node.label.isEmpty()
                    &&sha((String)node.v.get("ref_signature_sha256"))&&request.nodeSha.equals(nodeFacts(node)),
                    "reviewed real clickable node facts differ");
            consumed=true;return new ManualPreviewGuard(this,request,now);
        }
    }

    static final class Request {
        final String requestId,taskId,ownerSha,readySha,nonce,purpose,path,nodeSha,sha256;
        private final byte[] serialized;
        private Request(byte[] raw,JSONObject value)throws Exception {
            WebEvidenceJson.keys(value,REQUEST_KEYS);
            need(REQUEST_SCHEMA.equals(WebEvidenceJson.text(value,"schema")),"request schema differs");
            requestId=WebEvidenceJson.text(value,"request_id");taskId=WebEvidenceJson.text(value,"task_id");
            ownerSha=WebEvidenceJson.text(value,"owner_sha256");readySha=WebEvidenceJson.text(value,"ready_sha256");
            nonce=WebEvidenceJson.text(value,"nonce");purpose=WebEvidenceJson.text(value,"purpose");
            Object actualNode=value.get("node");need(actualNode instanceof JSONObject,"request node must be an object");
            JSONObject node=(JSONObject)actualNode;WebEvidenceJson.keys(node,NODE_KEYS);
            path=WebEvidenceJson.text(node,"tree_path");nodeSha=WebEvidenceJson.text(node,"facts_sha256");
            need(id(requestId)&&id(taskId)&&sha(ownerSha)&&sha(readySha)&&sha(nonce)&&PURPOSES.contains(purpose)
                    &&path.matches("0(?:/[0-9]{1,4}){0,32}")&&sha(nodeSha),"closed manual request values required");
            serialized=raw.clone();sha256=sha256(raw);
        }
        static Request parse(byte[] raw)throws Exception {
            need(raw!=null&&raw.length>0&&raw.length<=REQUEST_MAX,"bounded request required");
            String decoded=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString();
            return new Request(raw,WebEvidenceJson.parse(decoded,REQUEST_MAX));
        }
        byte[] bytes(){return serialized.clone();}
    }

    /**
     * A refusal-only guard. No constructor or method in this revision creates
     * an executable permit. In particular a request is not a ModelAction.
     */
    static final class ManualPreviewGuard {
        private final Ready ready;
        final Request request;
        final long consumedElapsed;
        private boolean reported;
        private ManualPreviewGuard(Ready ready,Request request,long now) {
            this.ready=ready;this.request=request;consumedElapsed=now;
        }
        synchronized Map<String,Object> refuseUnbound(long now) {
            need(!reported,"manual refusal already reported");reported=true;
            need(now>=consumedElapsed&&now<ready.taskDeadline&&now<ready.leaseDeadline,
                    "original lifetime ended before refusal publication");
            Map<String,Object> out=map();out.put("schema",REFUSAL_SCHEMA);
            out.put("task_id",ready.taskId);out.put("owner_sha256",ready.owner.goal.ownerSha256);
            out.put("ready_sha256",ready.sha256);out.put("request_sha256",request.sha256);
            out.put("request_id",request.requestId);out.put("purpose",request.purpose);out.put("tree_path",request.path);
            out.put("request_consumed_elapsed_ms",Long.valueOf(consumedElapsed));out.put("refused_elapsed_ms",Long.valueOf(now));
            out.put("reason","page_navigation_route_unbound");out.put("origin","owner_manual_fixture");
            out.put("model_proposal_created",false);out.put("dispatch_claimed",false);out.put("platform_call_entered",false);
            out.put("effect",false);out.put("automatic_continuation",false);out.put("business_success",false);
            out.put("order_submitted",false);out.put("payment_attempted",false);
            return freeze(out);
        }
    }

    static Map<String,Object> censusEvidence(NativeActionSnapshotCheck.Snapshot census) {
        need(census!=null,"actual complete census required");
        Map<String,Object> out=map();out.put("envelope",census.env);
        List<Object> nodes=new ArrayList<Object>();for(NativeActionSnapshotCheck.Node node:census.nodes.values())nodes.add(node.v);
        out.put("nodes",nodes);return freeze(out);
    }
    static String nodeFacts(NativeActionSnapshotCheck.Node node) {need(node!=null,"actual node required");return NativeAppEvidence.fingerprint(node.v);}
    static Set<String> keys(String csv) {return Collections.unmodifiableSet(new TreeSet<String>(Arrays.asList(csv.split(","))));}
    private static Set<String> union(Set<String> a,Set<String> b) {Set<String> out=new TreeSet<String>(a);out.addAll(b);return out;}
    static Map<String,Object> map(){return new TreeMap<String,Object>();}
    static Map<String,Object> freeze(Map<String,Object> value){return NativeAppEvidence.immutableMap(value);}
    static String text(Map<String,Object> value,String key) {
        Object x=value.get(key);need(x instanceof String,"string required: "+key);return (String)x;
    }
    static long integer(Map<String,Object> value,String key) {
        Object x=value.get(key);need(x instanceof Integer||x instanceof Long,"integer required: "+key);return ((Number)x).longValue();
    }
    static boolean id(String value){return value!=null&&value.matches("[0-9a-f]{32}");}
    static boolean sha(String value){return value!=null&&value.matches("[0-9a-f]{64}");}
    static void need(boolean value,String reason){if(!value)throw new IllegalArgumentException(reason);}
    static String sha256(byte[] bytes) {
        try {
            byte[] digest=MessageDigest.getInstance("SHA-256").digest(bytes);StringBuilder out=new StringBuilder(64);
            for(byte b:digest)out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return out.toString();
        }catch(java.security.NoSuchAlgorithmException unavailable){throw new IllegalStateException(unavailable);}
    }
    /** Preserve all nullable fields; JSONObject(Map) is intentionally not used. */
    static byte[] json(Object value) {
        try{return (jsonValue(value).toString()+"\n").getBytes(StandardCharsets.UTF_8);}
        catch(Exception invalid){throw new IllegalArgumentException("manual evidence is not a bounded JSON value",invalid);}
    }
    private static Object jsonValue(Object value)throws Exception {
        if(value==null)return JSONObject.NULL;
        if(value instanceof Map) {
            JSONObject out=new JSONObject();Map<?,?> input=(Map<?,?>)value;Set<String> names=new TreeSet<String>();
            for(Object key:input.keySet()){need(key instanceof String,"JSON map key");names.add((String)key);}
            for(String key:names)out.put(key,jsonValue(input.get(key)));return out;
        }
        if(value instanceof List){JSONArray out=new JSONArray();for(Object item:(List<?>)value)out.put(jsonValue(item));return out;}
        need(value instanceof String||value instanceof Boolean||value instanceof Integer||value instanceof Long,"pure bounded JSON scalar");
        return value;
    }
}
