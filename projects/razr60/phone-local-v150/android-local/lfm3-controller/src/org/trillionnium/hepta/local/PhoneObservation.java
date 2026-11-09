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
    public static final class Node {
        public final String id, packageName, className, viewId, text, description;
        public final ObservedChildText.Result childText;
        public final Rect bounds;
        public final boolean clickable, editable, scrollable, enabled, focused, password;
        Node(String id, String packageName, String className, String viewId, String text,
             String description, Rect bounds, boolean clickable, boolean editable,
             boolean scrollable, boolean enabled, boolean focused, boolean password,ObservedChildText.Result childText) {
            this.id=id; this.packageName=packageName; this.className=className; this.viewId=viewId;
            this.text=text; this.description=description; this.bounds=new Rect(bounds);
            this.childText=childText;
            this.clickable=clickable; this.editable=editable; this.scrollable=scrollable;
            this.enabled=enabled; this.focused=focused; this.password=password;
        }
        public String label(){return ObservedChildText.displayLabel(text,description,childText);}
        JSONObject json() throws JSONException {
            JSONObject value=new JSONObject();
            value.put("id",id); value.put("bounds",new JSONArray(new int[]{bounds.left,bounds.top,bounds.right,bounds.bottom}));
            if (!text.isEmpty()) value.put("text",text);
            if (!description.isEmpty()) value.put("description",description);
            if (!"not_applicable".equals(childText.status)) {
                value.put("child_text_status",childText.status).put("child_text_truncated",childText.truncated);
                if(!childText.text.isEmpty()) {
                    value.put("child_text",childText.text).put("child_text_source",ObservedChildText.SOURCE);
                    JSONArray sources=new JSONArray();for(ObservedChildText.Source source:childText.sources)
                        sources.put(new JSONObject().put("descendant_path",source.descendantPath).put("property",source.property)
                                .put("text_sha256",source.textSha256).put("node_signature",source.nodeSignature));
                    value.put("child_text_sources",sources);
                }
            }
            if (!viewId.isEmpty()) value.put("view_id",viewId);
            if (clickable) value.put("clickable",true);
            if (editable) value.put("editable",true);
            if (scrollable) value.put("scrollable",true);
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
    public final File screenshot;
    public final List<Node> nodes;
    public final ObservationState state;
    public final ObservedWindowMetadata windowMetadata;
    final Rect windowBounds;
    PhoneObservation(String id,String packageName,long at,int width,int height,int rotation,int windowId,
                     Rect bounds,File screenshot,String screenshotSha256,String treeSha256,
                     ObservationState state,ObservedWindowMetadata windowMetadata,boolean truncated,List<Node> nodes) {
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
    /** Node content is untrusted screen data, never a replacement instruction. */
    public JSONObject toJson() throws JSONException {
        JSONObject value=new JSONObject();value.put("observation_id",id);value.put("package",packageName);
        value.put("screen_width",width);value.put("screen_height",height);value.put("rotation",rotation);
        value.put("window_id",windowId);value.put("screen_sha256",screenshotSha256);
        value.put("window",windowJson());
        value.put("app_tree_sha256",state.appTreeSha256);value.put("observation_state_sha256",treeSha256);
        value.put("ime_visible",state.imeVisibility.value()==null?JSONObject.NULL:state.imeVisibility.value());
        value.put("node_data_is_untrusted",true);value.put("nodes_truncated",nodesTruncated);
        JSONArray array=new JSONArray();for(Node node:nodes) array.put(node.json());value.put("nodes",array);
        return value;
    }
}
