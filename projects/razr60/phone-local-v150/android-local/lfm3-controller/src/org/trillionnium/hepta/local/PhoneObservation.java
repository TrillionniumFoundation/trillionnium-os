package org.trillionnium.hepta.local;

import android.graphics.Rect;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.WindowOwnership;

/** Immutable description of one observed active window and original-size screenshot. */
public final class PhoneObservation {
    /** Counters from the real bounded traversal, never inferred from a flat
     * archived node list. Legacy observations have no counters. These describe
     * collection limits; they do not supply node actions or business evidence. */
    public static final class CollectionStats {
        public static final String SCHEMA="hepta.observation-collection.v1";
        public final int visitLimit,nodeLimit,textLimit,visited,retained,textUtf16,pending,
                nodeBudgetOmissions,textBudgetOmissions;
        public final long childSlotsOmitted,elapsedMs;
        public final List<String> limitReasons;
        CollectionStats(int visitLimit,int nodeLimit,int textLimit,int visited,int retained,int textUtf16,
                        int pending,int nodeBudgetOmissions,int textBudgetOmissions,long childSlotsOmitted,long elapsedMs){
            if(visitLimit<=0||nodeLimit<=0||textLimit<=0||visited<0||visited>visitLimit
                    ||retained<0||retained>nodeLimit||textUtf16<0||textUtf16>=textLimit
                    ||pending<0||pending>visitLimit||nodeBudgetOmissions<0||textBudgetOmissions<0
                    ||childSlotsOmitted<0||elapsedMs<0)throw new IllegalArgumentException("invalid actual collection counters");
            this.visitLimit=visitLimit;this.nodeLimit=nodeLimit;this.textLimit=textLimit;
            this.visited=visited;this.retained=retained;this.textUtf16=textUtf16;this.pending=pending;
            this.nodeBudgetOmissions=nodeBudgetOmissions;this.textBudgetOmissions=textBudgetOmissions;
            this.childSlotsOmitted=childSlotsOmitted;this.elapsedMs=elapsedMs;
            List<String> reasons=new ArrayList<String>();
            if(childSlotsOmitted>0||pending>0)reasons.add("traversal_limit");
            if(nodeBudgetOmissions>0)reasons.add("node_limit");
            if(textBudgetOmissions>0)reasons.add("text_limit");
            limitReasons=Collections.unmodifiableList(reasons);
        }
        public boolean truncated(){return !limitReasons.isEmpty();}
        JSONObject json()throws JSONException{
            return new JSONObject().put("schema",SCHEMA).put("source","same_observed_accessibility_traversal")
                    .put("visit_limit",visitLimit).put("node_limit",nodeLimit).put("text_utf16_exclusive_limit",textLimit)
                    .put("visited_nodes",visited).put("retained_nodes",retained).put("retained_text_utf16",textUtf16)
                    .put("pending_nodes_at_stop",pending).put("child_slots_omitted_by_traversal_limit",childSlotsOmitted)
                    .put("nodes_omitted_by_node_limit",nodeBudgetOmissions).put("nodes_omitted_by_text_limit",textBudgetOmissions)
                    .put("truncation_reasons",new JSONArray(limitReasons)).put("elapsed_ms",elapsedMs)
                    .put("unvisited_descendant_count_known",false).put("grants_action_capability",false);
        }
    }
    public static final class Node {
        public final String id, packageName, className, viewId, text, description;
        public final ObservedChildText.Result childText;
        public final ObservedScrollActions scrollActions;
        public final ObservedImeEnter imeEnter;
        public final String inputTextSha256;
        /** Actual NodeRef signature, never reconstructed from serialized labels. */
        public final String observedAppTreeSignature;
        /** Position recorded by the same native traversal; legacy/omitted positions remain null. */
        public final String nativeTreePath,nativeParentClass;
        public final boolean submitAvailable;
        public final Rect bounds;
        public final boolean clickable, editable, scrollable, enabled, focused, password;
        /** Null means not collected; false is a real observed native value. */
        public final Boolean selected, checkable, checked;
        public final boolean selectionStateObserved;
        Node(String id, String packageName, String className, String viewId, String text,
             String description, Rect bounds, boolean clickable, boolean editable,
             boolean scrollable, boolean enabled, boolean focused, boolean password,ObservedChildText.Result childText,
             ObservedScrollActions scrollActions) {
            this(id,packageName,className,viewId,text,description,bounds,clickable,editable,scrollable,enabled,focused,password,
                    childText,scrollActions,ObservedImeEnter.UNKNOWN,null,false);
        }
        Node(String id, String packageName, String className, String viewId, String text,
             String description, Rect bounds, boolean clickable, boolean editable,
             boolean scrollable, boolean enabled, boolean focused, boolean password,ObservedChildText.Result childText,
             ObservedScrollActions scrollActions,ObservedImeEnter imeEnter,String inputTextSha256,boolean submitAvailable) {
            this(id,packageName,className,viewId,text,description,bounds,clickable,editable,scrollable,enabled,focused,password,
                    childText,scrollActions,imeEnter,inputTextSha256,submitAvailable,null);
        }
        Node(String id, String packageName, String className, String viewId, String text,
             String description, Rect bounds, boolean clickable, boolean editable,
             boolean scrollable, boolean enabled, boolean focused, boolean password,ObservedChildText.Result childText,
             ObservedScrollActions scrollActions,ObservedImeEnter imeEnter,String inputTextSha256,boolean submitAvailable,String observedAppTreeSignature) {
            this(id,packageName,className,viewId,text,description,bounds,clickable,editable,scrollable,enabled,focused,password,
                    childText,scrollActions,imeEnter,inputTextSha256,submitAvailable,observedAppTreeSignature,null,null);
        }
        Node(String id, String packageName, String className, String viewId, String text,
             String description, Rect bounds, boolean clickable, boolean editable,
             boolean scrollable, boolean enabled, boolean focused, boolean password,ObservedChildText.Result childText,
             ObservedScrollActions scrollActions,ObservedImeEnter imeEnter,String inputTextSha256,boolean submitAvailable,
             String observedAppTreeSignature,String nativeTreePath,String nativeParentClass) {
            this(id,packageName,className,viewId,text,description,bounds,clickable,editable,scrollable,enabled,focused,password,
                    childText,scrollActions,imeEnter,inputTextSha256,submitAvailable,observedAppTreeSignature,nativeTreePath,nativeParentClass,
                    null,null,null);
        }
        Node(String id, String packageName, String className, String viewId, String text,
             String description, Rect bounds, boolean clickable, boolean editable,
             boolean scrollable, boolean enabled, boolean focused, boolean password,ObservedChildText.Result childText,
             ObservedScrollActions scrollActions,ObservedImeEnter imeEnter,String inputTextSha256,boolean submitAvailable,
             String observedAppTreeSignature,String nativeTreePath,String nativeParentClass,
             Boolean selected,Boolean checkable,Boolean checked) {
            if((selected==null)!=(checkable==null)||(selected==null)!=(checked==null))
                throw new IllegalArgumentException("native selection facts must be observed together");
            this.selected=selected;this.checkable=checkable;this.checked=checked;
            selectionStateObserved=selected!=null;
            if(nativeTreePath==null){
                if(nativeParentClass!=null)throw new IllegalArgumentException("native parent without an actual traversal path");
            }else if(nativeParentClass==null||nativeParentClass.length()>96
                    ||!nativeTreePath.matches("0(?:/(?:0|[1-9][0-9]{0,5})){0,127}"))
                throw new IllegalArgumentException("invalid bounded actual native traversal path");
            this.nativeTreePath=nativeTreePath;this.nativeParentClass=nativeParentClass;
            this.id=id; this.packageName=packageName; this.className=className; this.viewId=viewId;
            this.text=text; this.description=description; this.bounds=new Rect(bounds);
            this.childText=childText;
            if(observedAppTreeSignature!=null&&!ObservedImeEnter.isSha(observedAppTreeSignature))
                throw new IllegalArgumentException("actual node signature must be a SHA-256 value");
            this.observedAppTreeSignature=observedAppTreeSignature;
            if(scrollActions==null)throw new IllegalArgumentException("observed scroll action state required");
            this.scrollActions=scrollActions;
            if(imeEnter==null)throw new IllegalArgumentException("observed IME action state required");
            if(submitAvailable&&(!editable||!focused||!enabled||password||!imeEnter.queryAllowed()||!ObservedImeEnter.isSha(inputTextSha256)))
                throw new IllegalArgumentException("submit capability lacks observed field facts");
            this.imeEnter=imeEnter;this.inputTextSha256=inputTextSha256;this.submitAvailable=submitAvailable;
            this.clickable=clickable; this.editable=editable; this.scrollable=scrollable;
            this.enabled=enabled; this.focused=focused; this.password=password;
        }
        public String label(){return ObservedChildText.displayLabel(text,description,childText);}
        JSONObject json() throws JSONException {
            JSONObject value=new JSONObject();
            value.put("id",id); value.put("bounds",new JSONArray(new int[]{bounds.left,bounds.top,bounds.right,bounds.bottom}));
            value.put("package",packageName).put("class_name",className);
            if (!text.isEmpty()) value.put("text",text);
            if (!description.isEmpty()) value.put("description",description);
            if (!"not_applicable".equals(childText.status)) {
                value.put("child_text_status",childText.status).put("child_text_truncated",childText.truncated)
                        .put("child_text_sources_complete",childText.sourcesComplete).put("child_text_visited",childText.visited);
                if(!childText.text.isEmpty()) {
                    value.put("child_text",childText.text).put("child_text_source",ObservedChildText.SOURCE)
                            .put("child_text_root_signature",childText.rootSignature);
                    JSONArray sources=new JSONArray();for(ObservedChildText.Source source:childText.sources)
                        sources.put(new JSONObject().put("descendant_path",source.descendantPath).put("property",source.property)
                                .put("text_sha256",source.textSha256).put("node_signature",source.nodeSignature).put("view_id",source.viewId));
                    value.put("child_text_sources",sources);
                }
            }
            if (!viewId.isEmpty()) value.put("view_id",viewId);
            if(observedAppTreeSignature!=null)value.put("node_app_tree_sha256",observedAppTreeSignature);
            if(nativeTreePath!=null)value.put("native_tree_position",new JSONObject()
                    .put("schema","hepta.native-tree-position.v1").put("path",nativeTreePath)
                    .put("parent_class",nativeParentClass).put("source","same_bounded_accessibility_traversal")
                    .put("grants_action_capability",false));
            if(selectionStateObserved)value.put("native_selection_state",new JSONObject()
                    .put("schema","hepta.native-selection-state.v1").put("observed",true)
                    .put("selected",selected).put("checkable",checkable).put("checked",checked)
                    .put("source","same_bounded_accessibility_traversal").put("grants_action_capability",false));
            if (clickable) value.put("clickable",true);
            if (editable) value.put("editable",true);
            if (scrollable) value.put("scrollable",true); // Platform isScrollable, not a direction grant.
            value.put("scroll_actions_observed",scrollActions.observed);
            value.put("scroll_directions",scrollActions.observed?new JSONArray(scrollActions.directions):JSONObject.NULL);
            value.put("input_text_sha256",inputTextSha256==null?JSONObject.NULL:inputTextSha256);
            value.put("ime_enter",new JSONObject(imeEnter.evidence())).put("submit_available",submitAvailable);
            if (!enabled) value.put("enabled",false);
            if (focused) value.put("focused",true);
            if (password) value.put("password",true);
            return value;
        }
    }
    public final String id, packageName, screenshotSha256, treeSha256;
    public final String captureKind;
    final ObservationCaptureEvidence capture;
    final PixelNativeCensusEvidence pixelNativeCensus;
    public final long capturedElapsedMillis;
    private final String captureEvidenceRaw;
    public final int width, height, rotation, windowId;
    public final boolean nodesTruncated;
    public final CollectionStats collectionStats;
    public final File screenshot;
    public final List<Node> nodes;
    public final String backgroundGeneration,backgroundBootstrapPackage;
    public final List<String> backgroundAllowedPackages;
    private final String backgroundSelectionRaw;
    public static final String PROFILE_WINDOW_TASK_SOURCE="android16_a11y_public_parcel_checked_v1";
    public final ProfileTarget profileTarget;
    public final WindowOwnership profileWindow;
    public final ObservationState state;
    public final ObservedWindowMetadata windowMetadata;
    final Rect windowBounds;
    PhoneObservation(String id,String packageName,long at,int width,int height,int rotation,int windowId,
                     Rect bounds,File screenshot,String screenshotSha256,String treeSha256,
                     ObservationState state,ObservedWindowMetadata windowMetadata,boolean truncated,List<Node> nodes) {
        this(id,packageName,at,width,height,rotation,windowId,bounds,screenshot,screenshotSha256,treeSha256,state,windowMetadata,truncated,nodes,null,null,Collections.<String>emptyList());
    }
    PhoneObservation(String id,String packageName,long at,int width,int height,int rotation,int windowId,
                     Rect bounds,File screenshot,String screenshotSha256,String treeSha256,
                     ObservationState state,ObservedWindowMetadata windowMetadata,boolean truncated,List<Node> nodes,
                     String backgroundGeneration,String backgroundBootstrapPackage,List<String> backgroundAllowedPackages) {
        this(id,packageName,at,width,height,rotation,windowId,bounds,screenshot,screenshotSha256,treeSha256,
                state,windowMetadata,truncated,nodes,backgroundGeneration,backgroundBootstrapPackage,backgroundAllowedPackages,null);
    }
    PhoneObservation(String id,String packageName,long at,int width,int height,int rotation,int windowId,
                     Rect bounds,File screenshot,String screenshotSha256,String treeSha256,
                     ObservationState state,ObservedWindowMetadata windowMetadata,boolean truncated,List<Node> nodes,
                     String backgroundGeneration,String backgroundBootstrapPackage,List<String> backgroundAllowedPackages,CollectionStats collectionStats) {
        this(id,packageName,at,width,height,rotation,windowId,bounds,screenshot,screenshotSha256,treeSha256,
                state,windowMetadata,truncated,nodes,backgroundGeneration,backgroundBootstrapPackage,backgroundAllowedPackages,
                collectionStats,null,null);
    }
    PhoneObservation(String id,String packageName,long at,int width,int height,int rotation,int windowId,
                     Rect bounds,File screenshot,String screenshotSha256,String treeSha256,
                     ObservationState state,ObservedWindowMetadata windowMetadata,boolean truncated,List<Node> nodes,
                     String backgroundGeneration,String backgroundBootstrapPackage,List<String> backgroundAllowedPackages,
                     CollectionStats collectionStats,JSONObject actualSelection,String actualOwnerSha256) {
        this(id,packageName,at,width,height,rotation,windowId,bounds,screenshot,screenshotSha256,treeSha256,state,windowMetadata,
                truncated,nodes,backgroundGeneration,backgroundBootstrapPackage,backgroundAllowedPackages,collectionStats,actualSelection,actualOwnerSha256,null);
    }
    PhoneObservation(String id,String packageName,long at,int width,int height,int rotation,int windowId,
                      Rect bounds,File screenshot,String screenshotSha256,String treeSha256,
                      ObservationState state,ObservedWindowMetadata windowMetadata,boolean truncated,List<Node> nodes,
                      String backgroundGeneration,String backgroundBootstrapPackage,List<String> backgroundAllowedPackages,
                      CollectionStats collectionStats,JSONObject actualSelection,String actualOwnerSha256,java.util.Map<String,Object> captureEvidence) {
        this(id,packageName,at,width,height,rotation,windowId,bounds,screenshot,screenshotSha256,treeSha256,state,windowMetadata,
                truncated,nodes,backgroundGeneration,backgroundBootstrapPackage,backgroundAllowedPackages,collectionStats,
                actualSelection,actualOwnerSha256,captureEvidence,null);
    }
    PhoneObservation(String id,String packageName,long at,int width,int height,int rotation,int windowId,
                      Rect bounds,File screenshot,String screenshotSha256,String treeSha256,
                      ObservationState state,ObservedWindowMetadata windowMetadata,boolean truncated,List<Node> nodes,
                      String backgroundGeneration,String backgroundBootstrapPackage,List<String> backgroundAllowedPackages,
                      CollectionStats collectionStats,JSONObject actualSelection,String actualOwnerSha256,
                      java.util.Map<String,Object> captureEvidence,WindowOwnership actualProfileWindow) {
        this(id,packageName,at,width,height,rotation,windowId,bounds,screenshot,screenshotSha256,treeSha256,state,windowMetadata,
                truncated,nodes,backgroundGeneration,backgroundBootstrapPackage,backgroundAllowedPackages,collectionStats,
                actualSelection,actualOwnerSha256,captureEvidence,actualProfileWindow,null);
    }
    PhoneObservation(String id,String packageName,long at,int width,int height,int rotation,int windowId,
                      Rect bounds,File screenshot,String screenshotSha256,String treeSha256,
                      ObservationState state,ObservedWindowMetadata windowMetadata,boolean truncated,List<Node> nodes,
                      String backgroundGeneration,String backgroundBootstrapPackage,List<String> backgroundAllowedPackages,
                      CollectionStats collectionStats,JSONObject actualSelection,String actualOwnerSha256,
                      java.util.Map<String,Object> captureEvidence,WindowOwnership actualProfileWindow,ObservationCaptureEvidence capture) {
        this(id,packageName,at,width,height,rotation,windowId,bounds,screenshot,screenshotSha256,treeSha256,state,windowMetadata,
                truncated,nodes,backgroundGeneration,backgroundBootstrapPackage,backgroundAllowedPackages,collectionStats,
                actualSelection,actualOwnerSha256,captureEvidence,actualProfileWindow,capture,null);
    }
    PhoneObservation(String id,String packageName,long at,int width,int height,int rotation,int windowId,
                      Rect bounds,File screenshot,String screenshotSha256,String treeSha256,
                      ObservationState state,ObservedWindowMetadata windowMetadata,boolean truncated,List<Node> nodes,
                      String backgroundGeneration,String backgroundBootstrapPackage,List<String> backgroundAllowedPackages,
                      CollectionStats collectionStats,JSONObject actualSelection,String actualOwnerSha256,
                      java.util.Map<String,Object> captureEvidence,WindowOwnership actualProfileWindow,ObservationCaptureEvidence capture,
                      PixelNativeCensusEvidence pixelNativeCensus) {
        this.capture=capture;captureKind=capture==null?ObservationCaptureEvidence.PIXELS:capture.kind;
        if(capture!=null){
            if(!capture.nativeText()||screenshot!=null||screenshotSha256!=null
                    ||captureEvidence==null||actualSelection==null||actualOwnerSha256==null||backgroundGeneration==null
                    ||state==null||windowMetadata==null||windowMetadata.displayId==null||windowMetadata.displayId.intValue()<=0
                    ||truncated||collectionStats==null||collectionStats.truncated())
                throw new IllegalArgumentException("native AX evidence requires complete bound background values and no pixels");
            java.util.Map<String,Object> bound=new java.util.LinkedHashMap<String,Object>();
            bound.put("observation_id",id);bound.put("package",packageName);bound.put("owner_sha256",actualOwnerSha256);
            bound.put("background_generation",backgroundGeneration);bound.put("app_tree_sha256",state.appTreeSha256);
            bound.put("observation_state_sha256",treeSha256);bound.put("display_id",windowMetadata.displayId);
            bound.put("window_id",windowId);bound.put("rotation",rotation);bound.put("width",width);bound.put("height",height);
            bound.put("left",bounds.left);bound.put("top",bounds.top);bound.put("right",bounds.right);bound.put("bottom",bounds.bottom);
            bound.put("captured_elapsed_ms",at);bound.put("profile_window",actualProfileWindow==null?null:actualProfileWindow.evidence());
            capture.requireBinding(bound);capture.requireHistoricalPublication(captureEvidence);
            if(!capture.receiptSha256.equals(captureEvidence.get("receipt_sha256"))
                    ||!capture.kind.equals(captureEvidence.get("kind")))
                throw new IllegalArgumentException("AX capture metadata differs from real receipt");
        }else if(captureEvidence!=null&&(screenshot==null||screenshotSha256==null||!screenshotSha256.matches("[0-9a-f]{64}"))){
            throw new IllegalArgumentException("legacy pixel capture requires actual image and hash");
        }
        if(collectionStats!=null&&(collectionStats.retained!=nodes.size()||collectionStats.truncated()!=truncated))
            throw new IllegalArgumentException("collection counters differ from actual observed nodes");
        this.collectionStats=collectionStats;
        this.backgroundGeneration=backgroundGeneration;this.backgroundBootstrapPackage=backgroundBootstrapPackage;
        this.backgroundAllowedPackages=Collections.unmodifiableList(new ArrayList<String>(backgroundAllowedPackages));
        if(actualSelection==null){
            if(actualOwnerSha256!=null)throw new IllegalArgumentException("owner without actual selection");
            backgroundSelectionRaw=null;
        }else{
            if(backgroundGeneration==null||windowMetadata==null||windowMetadata.displayId==null
                    ||windowMetadata.displayId.intValue()<=0||windowId<0)
                throw new IllegalArgumentException("actual selection lacks its observed background window");
            backgroundSelectionRaw=checkedSelection(actualSelection,actualOwnerSha256,
                    backgroundBootstrapPackage,this.backgroundAllowedPackages);
        }
        ProfileTarget selectedProfile=null;
        if(actualSelection!=null&&actualSelection.has("profile_target_wire"))try{
            selectedProfile=ProfileTarget.fromWire(actualSelection.getString("profile_target_wire"));
        }catch(JSONException malformed){throw new IllegalArgumentException("profile Selection malformed",malformed);}
        if(selectedProfile==null){
            if(actualProfileWindow!=null)throw new IllegalArgumentException("profile window on a user0 observation");
        }else{
            if(actualProfileWindow==null||!selectedProfile.packageName.equals(packageName))
                throw new IllegalArgumentException("actual profile window provenance missing");
            actualProfileWindow.requireMatches(selectedProfile,backgroundGeneration,windowMetadata.displayId.intValue(),
                    windowId,actualProfileWindow.taskId,at);
        }
        profileTarget=selectedProfile;profileWindow=actualProfileWindow;
        this.id=id;this.packageName=packageName;this.capturedElapsedMillis=at;
        if(captureEvidence!=null){
            Object captureClock=captureEvidence.get("capture_requested_elapsed_ms");
            if(!(captureClock instanceof Long)||((Long)captureClock).longValue()!=at
                    ||!(capture==null?"hepta.observation-capture.v1":capture.metadataSchema()).equals(captureEvidence.get("schema"))
                    ||!Boolean.FALSE.equals(captureEvidence.get("publication_refreshes_capture_age"))
                    ||!Boolean.FALSE.equals(captureEvidence.get("grants_action_authority"))
                    ||!Boolean.FALSE.equals(captureEvidence.get("business_completion_verified")))
                throw new IllegalArgumentException("capture evidence cannot replace observation age or grant authority");
            captureEvidenceRaw=new JSONObject(captureEvidence).toString();
            if(captureEvidenceRaw.getBytes(java.nio.charset.StandardCharsets.UTF_8).length>8192)
                throw new IllegalArgumentException("capture evidence exceeds fixed byte bound");
        }else captureEvidenceRaw=null;
        this.width=width;this.height=height;this.rotation=rotation;this.windowId=windowId;
        this.windowBounds=new Rect(bounds);this.screenshot=screenshot;this.screenshotSha256=screenshotSha256;
        this.treeSha256=treeSha256;this.nodesTruncated=truncated;
        this.state=state;this.windowMetadata=windowMetadata;
        this.nodes=Collections.unmodifiableList(new ArrayList<Node>(nodes));
        if(pixelNativeCensus!=null){
            if(capture!=null||screenshot==null||screenshotSha256==null||actualSelection==null||actualOwnerSha256==null
                    ||actualProfileWindow==null||state==null||state.imeVisibility!=ImeVisibility.HIDDEN
                    ||windowMetadata==null||windowMetadata.displayId==null||truncated
                    ||collectionStats==null||collectionStats.truncated())
                throw new IllegalArgumentException("complete bound actual pixels required for native census companion");
            java.util.Map<String,Object> bound=new java.util.LinkedHashMap<String,Object>();
            bound.put("observation_id",id);bound.put("package",packageName);bound.put("owner_sha256",actualOwnerSha256);
            bound.put("background_generation",backgroundGeneration);bound.put("app_tree_sha256",state.appTreeSha256);
            bound.put("observation_state_sha256",treeSha256);bound.put("display_id",windowMetadata.displayId);
            bound.put("window_id",windowId);bound.put("rotation",rotation);bound.put("width",width);bound.put("height",height);
            bound.put("left",bounds.left);bound.put("top",bounds.top);bound.put("right",bounds.right);bound.put("bottom",bounds.bottom);
            bound.put("captured_elapsed_ms",at);bound.put("profile_window",actualProfileWindow.evidence());bound.put("screen_sha256",screenshotSha256);
            pixelNativeCensus.requirePublished(bound,captureEvidence,collectionStats.visited,collectionStats.retained);
            requirePixelNativeProjection(pixelNativeCensus,nodes);
        }
        this.pixelNativeCensus=pixelNativeCensus;
    }
    /** The compact published rows must be the same projection of the full original graph. */
    private static void requirePixelNativeProjection(PixelNativeCensusEvidence proof,List<Node> nodes){
        java.util.Map<?,?> census=(java.util.Map<?,?>)proof.completeReceipt().get("census");
        java.util.Map<String,java.util.Map<?,?>> full=new java.util.HashMap<String,java.util.Map<?,?>>();
        for(Object value:(java.util.List<?>)census.get("nodes")){
            java.util.Map<?,?> row=(java.util.Map<?,?>)value;full.put((String)row.get("path"),row);
        }
        java.util.Set<String> paths=new java.util.HashSet<String>();
        for(Node n:nodes){
            java.util.Map<?,?> row=full.get(n.nativeTreePath);
            require(row!=null&&paths.add(n.nativeTreePath)&&n.selectionStateObserved&&n.observedAppTreeSignature!=null,
                    "actual retained path/reference missing from full pixel census");
            // The real managed-profile producers support Xiaomi/Ctrip. Their retained
            // text/description/view ID are the original 96-unit projection, while the
            // complete census retains bounded original strings from the same getters.
            String label=n.label();
            if(n.text.trim().isEmpty()&&n.description.trim().isEmpty()&&!"derived".equals(n.childText.status))label="";
            require(n.packageName.equals(row.get("package"))&&n.className.equals(row.get("class"))
                    &&n.nativeParentClass.equals(row.get("parent_class"))
                    &&n.viewId.equals(PixelNativeCensusEvidence.retainedValue((String)row.get("view_id"),96))
                    &&n.text.equals(PixelNativeCensusEvidence.retainedValue((String)row.get("text"),96))
                    &&n.description.equals(PixelNativeCensusEvidence.retainedValue((String)row.get("description"),96))
                    &&ObservedTargetLabels.project(label).equals(row.get("label"))
                    &&java.util.Arrays.asList(n.bounds.left,n.bounds.top,n.bounds.right,n.bounds.bottom).equals(row.get("bounds"))
                    &&Boolean.TRUE.equals(row.get("visible"))&&Boolean.valueOf(n.enabled).equals(row.get("enabled"))
                    &&Boolean.valueOf(n.clickable).equals(row.get("clickable"))&&Boolean.valueOf(n.editable).equals(row.get("editable"))
                    &&Boolean.valueOf(n.scrollable).equals(row.get("scrollable"))&&Boolean.valueOf(n.focused).equals(row.get("focused"))
                    &&Boolean.valueOf(n.password).equals(row.get("password"))&&n.selected.equals(row.get("selected"))
                    &&n.checkable.equals(row.get("checkable"))&&n.checked.equals(row.get("checked"))
                    &&n.scrollActions.fingerprintInput().equals(row.get("scroll_actions"))
                    &&n.imeEnter.fingerprintInput().equals(row.get("ime_enter"))
                    &&java.util.Objects.equals(n.inputTextSha256,row.get("input_sha256"))
                    &&ObservationCaptureEvidence.hash((n.imeEnter.bindFreshness(n.scrollActions.bindFreshness(n.observedAppTreeSignature),
                            n.focused,n.inputTextSha256)).getBytes(java.nio.charset.StandardCharsets.UTF_8)).equals(row.get("ref_signature_sha256")),
                    "actual retained values differ from full original pixel census");
        }
    }

    /** Window title/class are untrusted metadata, not a classifier or a page title guarantee. */
    JSONObject windowJson() throws JSONException {
        ObservedWindowMetadata value=windowMetadata;
        JSONObject result=new JSONObject().put("scope",ObservedWindowMetadata.SCOPE)
                .put("metadata_status",value.status).put("window_id",windowId)
                .put("root_bounds",new JSONArray(value.rootBounds()))
                .put("root_class",value.rootClass==null?JSONObject.NULL:value.rootClass)
                .put("root_class_truncated",value.rootClassTruncated)
                .put("type",value.type==null?JSONObject.NULL:value.type)
                .put("display_id",value.displayId==null?JSONObject.NULL:value.displayId)
                .put("bounds",value.windowBounds()==null?JSONObject.NULL:new JSONArray(value.windowBounds()))
                .put("title",value.title==null?JSONObject.NULL:value.title)
                .put("title_truncated",value.titleTruncated);
        return result;
    }
    /** Compact projection keeps the same facts; detailed identity stays in the private observation. */
    JSONObject windowPromptJson() throws JSONException {
        ObservedWindowMetadata value=windowMetadata;
        JSONObject result=new JSONObject().put("scope",ObservedWindowMetadata.SCOPE)
                .put("root_bounds",new JSONArray(value.rootBounds()))
                .put("bounds",value.windowBounds()==null?JSONObject.NULL:new JSONArray(value.windowBounds()))
                .put("type",value.type==null?JSONObject.NULL:value.type)
                .put("title",value.title==null?JSONObject.NULL:value.promptTitle())
                .put("root_class",value.rootClass==null?JSONObject.NULL:value.promptRootClass());
        if(value.promptTitleTruncated())result.put("title_truncated",true);
        if(value.promptRootClassTruncated())result.put("root_class_truncated",true);
        return result;
    }
    JSONObject backgroundJson() throws JSONException {
        if(backgroundGeneration==null)return null;
        // Preserve the complete real Selection projection, including its original
        // OWNER/UI derivation. Never replace it with a fixed provenance label.
        JSONObject actual=backgroundSelectionEvidence();
        if(actual==null)throw new IllegalStateException("actual background Selection provenance is missing");
        actual.put("generation",backgroundGeneration).put("display_id",windowMetadata.displayId);
        if(profileWindow!=null)actual.put("actual_profile_window",new JSONObject(profileWindow.evidence())
                .put("accessibility_task_id_source",PROFILE_WINDOW_TASK_SOURCE));
        return actual;
    }
    JSONObject backgroundSelectionEvidence()throws JSONException{
        return backgroundSelectionRaw==null?null:new JSONObject(backgroundSelectionRaw);
    }
    private static String checkedSelection(JSONObject original,String owner,String initial,List<String> allowed){
        try{
            if(owner==null||!owner.matches("[0-9a-f]{64}"))throw new IllegalArgumentException("actual task OWNER SHA required");
            JSONObject value=new JSONObject(original.toString());
            java.util.Set<String> keys=new java.util.HashSet<String>(java.util.Arrays.asList(
                    "mode","allowed_packages","bootstrap_package","bootstrap_source","bootstrap_model_issued","home_allowed","main_display_fallback"));
            if(value.has("owner_task_selection"))keys.add("owner_task_selection");
            boolean profileWire=value.has("profile_target_wire"),profileSha=value.has("profile_target_sha256");
            require(profileWire==profileSha,"profile Selection requires wire and digest together");
            if(profileWire){keys.add("profile_target_wire");keys.add("profile_target_sha256");}
            boolean displayMode=value.has("display_scope_mode"),displaySource=value.has("display_scope_mode_source"),
                    displayAuthority=value.has("display_scope_mode_grants_authority");
            require(displayMode==displaySource&&displayMode==displayAuthority,"display Selection requires its complete provenance");
            if(displayMode){
                keys.add("display_scope_mode");keys.add("display_scope_mode_source");keys.add("display_scope_mode_grants_authority");
                Object mode=value.get("display_scope_mode");
                boolean profileMode="public_own_group_no_credentials_v1".equals(mode),
                        personalMode="public_own_group_personal_no_credentials_v1".equals(mode);
                require((profileMode||personalMode)&&profileMode==profileWire
                        &&"immutable_start_selection".equals(value.get("display_scope_mode_source"))
                        &&Boolean.FALSE.equals(value.get("display_scope_mode_grants_authority"))
                        &&value.has("owner_task_selection")&&allowed.equals(Collections.singletonList(initial)),
                        "display Selection mode or provenance differs from its explicit target");
                if(personalMode)require("com.motorola.stylus".equals(initial)||"com.xiaomi.shop".equals(initial),
                        "personal display Selection app is unsupported");
            }
            exactKeys(value,keys);
            if(profileWire){
                Object wire=value.get("profile_target_wire"),digest=value.get("profile_target_sha256");
                require(wire instanceof String&&digest instanceof String,"profile Selection fields require exact strings");
                ProfileTarget profile=ProfileTarget.fromWire((String)wire);
                require(profile.sha256.equals(digest)&&profile.packageName.equals(initial)
                        &&allowed.equals(Collections.singletonList(profile.packageName)),
                        "profile Selection differs from its exact target installation");
            }
            require("background".equals(value.get("mode"))&&initial.equals(value.get("bootstrap_package"))
                    &&new JSONArray(allowed).toString().equals(value.getJSONArray("allowed_packages").toString()),
                    "observed Selection scope differs from its background lease");
            for(String key:new String[]{"bootstrap_model_issued","home_allowed","main_display_fallback"})
                require(Boolean.FALSE.equals(value.get(key)),"Selection scope flag differs: "+key);
            if(!value.has("owner_task_selection")){
                require("owner_selected_initial_app".equals(value.get("bootstrap_source")),
                        "explicit UI Selection provenance differs");
            }else{
                require("owner_intent_within_explicit_ui_selection".equals(value.get("bootstrap_source")),
                        "derived Selection provenance differs");
                JSONObject proof=value.getJSONObject("owner_task_selection");
                exactKeys(proof,new java.util.HashSet<String>(java.util.Arrays.asList("schema","owner_sha256","recognition",
                        "original_ui_initial_package","original_ui_allowed_packages","effective_initial_package","effective_allowed_packages",
                        "effective_scope_within_selected_apps","effective_scope_strictly_smaller","initial_app_changed",
                        "package_from_model_or_screen","grants_tool_authority","changes_saved_preferences")));
                require("hepta.owner-task-app-selection.v1".equals(proof.get("schema"))&&owner.equals(proof.get("owner_sha256"))
                        &&initial.equals(proof.get("effective_initial_package"))
                        &&new JSONArray(allowed).toString().equals(proof.getJSONArray("effective_allowed_packages").toString())
                        &&allowed.size()==1,"actual OWNER/effective Selection differs");
                Object recognition=proof.get("recognition");
                require(recognition instanceof String&&((String)recognition).matches("[A-Za-z0-9_.]{1,96}"),
                        "actual Selection recognition missing");
                JSONArray choices=proof.getJSONArray("original_ui_allowed_packages");
                require(choices.length()>0&&choices.length()<=6,"actual original UI scope budget");
                java.util.Set<String> originals=new java.util.TreeSet<String>();
                for(int i=0;i<choices.length();i++){
                    Object choice=choices.get(i);require(choice instanceof String&&originals.add((String)choice),"original UI scope differs");
                }
                Object oldInitial=proof.get("original_ui_initial_package");
                if(displayMode)require(initial.equals(oldInitial),"display Selection must retain its explicit initial app");
                require(oldInitial instanceof String&&originals.contains(oldInitial)&&originals.containsAll(allowed)
                        &&Boolean.TRUE.equals(proof.get("effective_scope_within_selected_apps"))
                        &&Boolean.valueOf(allowed.size()<originals.size()).equals(proof.get("effective_scope_strictly_smaller"))
                        &&Boolean.valueOf(!initial.equals(oldInitial)).equals(proof.get("initial_app_changed")),
                        "Selection narrowing facts differ from the actual original UI scope");
                for(String key:new String[]{"package_from_model_or_screen","grants_tool_authority","changes_saved_preferences"})
                    require(Boolean.FALSE.equals(proof.get(key)),"Selection derivation flag differs: "+key);
            }
            return value.toString();
        }catch(JSONException malformed){throw new IllegalArgumentException("malformed actual Selection projection",malformed);}
    }
    private static void exactKeys(JSONObject value,java.util.Set<String> expected){
        java.util.Set<String> actual=new java.util.HashSet<String>();java.util.Iterator<String> keys=value.keys();
        while(keys.hasNext())actual.add(keys.next());require(actual.equals(expected),"exact Selection projection fields required");
    }
    private static void require(boolean value,String reason){if(!value)throw new IllegalArgumentException(reason);}
    /** Existing frame semantics used by page comparisons; node content remains untrusted. */
    public JSONObject toJson() throws JSONException {
        return json(false);
    }
    /** Journal evidence retains the original capture clock and lineage without granting freshness. */
    public JSONObject toEvidenceJson() throws JSONException {
        return json(true);
    }
    private JSONObject json(boolean includeCaptureEvidence) throws JSONException {
        JSONObject value=new JSONObject();value.put("observation_id",id);value.put("package",packageName);
        if(includeCaptureEvidence){
            value.put("captured_elapsed_ms",capturedElapsedMillis);
            if(captureEvidenceRaw!=null)value.put("capture",new JSONObject(captureEvidenceRaw));
            if(pixelNativeCensus!=null)value.put("pixels_native_census",new JSONObject(pixelNativeCensus.summary()));
        }
        value.put("screen_width",width);value.put("screen_height",height);value.put("rotation",rotation);
        value.put("window_id",windowId);value.put("screen_sha256",screenshotSha256==null?JSONObject.NULL:screenshotSha256);
        value.put("capture_kind",captureKind);
        if(capture!=null){
            value.put("ax_capture",new JSONObject(capture.evidence()));
            value.put("screenshot_observed",false);value.put("screenshot_path",JSONObject.NULL);
        }
        value.put("window",windowJson());
        if(backgroundGeneration!=null)value.put("background_session",backgroundJson());
        value.put("app_tree_sha256",state.appTreeSha256);value.put("observation_state_sha256",treeSha256);
        value.put("ime_visible",state.imeVisibility.value()==null?JSONObject.NULL:state.imeVisibility.value());
        value.put("scroll_actions_schema",ObservedScrollActions.SCHEMA);
        value.put("node_data_is_untrusted",true);value.put("nodes_truncated",nodesTruncated);
        value.put("collection",collectionStats==null?JSONObject.NULL:collectionStats.json());
        JSONArray array=new JSONArray();for(Node node:nodes) array.put(node.json());value.put("nodes",array);
        return value;
    }
}
