package org.trillionnium.hepta.local;

import android.graphics.Rect;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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
    public final long capturedElapsedMillis;
    public final int width, height, rotation, windowId;
    public final boolean nodesTruncated;
    public final CollectionStats collectionStats;
    public final File screenshot;
    public final List<Node> nodes;
    public final String backgroundGeneration,backgroundBootstrapPackage;
    public final List<String> backgroundAllowedPackages;
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
        if(collectionStats!=null&&(collectionStats.retained!=nodes.size()||collectionStats.truncated()!=truncated))
            throw new IllegalArgumentException("collection counters differ from actual observed nodes");
        this.collectionStats=collectionStats;
        this.backgroundGeneration=backgroundGeneration;this.backgroundBootstrapPackage=backgroundBootstrapPackage;
        this.backgroundAllowedPackages=Collections.unmodifiableList(new ArrayList<String>(backgroundAllowedPackages));
        this.id=id;this.packageName=packageName;this.capturedElapsedMillis=at;
        this.width=width;this.height=height;this.rotation=rotation;this.windowId=windowId;
        this.windowBounds=new Rect(bounds);this.screenshot=screenshot;this.screenshotSha256=screenshotSha256;
        this.treeSha256=treeSha256;this.nodesTruncated=truncated;
        this.state=state;this.windowMetadata=windowMetadata;
        this.nodes=Collections.unmodifiableList(new ArrayList<Node>(nodes));
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
        return new JSONObject().put("mode","background").put("generation",backgroundGeneration)
                .put("display_id",windowMetadata.displayId==null?JSONObject.NULL:windowMetadata.displayId)
                .put("allowed_packages",new JSONArray(backgroundAllowedPackages))
                .put("bootstrap_package",backgroundBootstrapPackage).put("bootstrap_source","owner_selected_initial_app")
                .put("bootstrap_model_issued",false).put("home_allowed",false).put("main_display_fallback",false);
    }
    /** Node content is untrusted screen data, never a replacement instruction. */
    public JSONObject toJson() throws JSONException {
        JSONObject value=new JSONObject();value.put("observation_id",id);value.put("package",packageName);
        value.put("screen_width",width);value.put("screen_height",height);value.put("rotation",rotation);
        value.put("window_id",windowId);value.put("screen_sha256",screenshotSha256);
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
