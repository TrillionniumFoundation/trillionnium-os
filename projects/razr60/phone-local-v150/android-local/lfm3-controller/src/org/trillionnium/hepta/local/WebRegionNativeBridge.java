package org.trillionnium.hepta.local;

import android.graphics.Rect;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebDomCanonical;
import org.trillionnium.hepta.webprotocol.WebDomStability;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import org.trillionnium.hepta.webprotocol.WebMiActionRegion;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Exact native semantic bridge for the independently checked mainland-Mi card.
 * DOM paths and CSS rectangles are never translated into native IDs or input.
 * The fixed relative native relationships come from the full original AX tree
 * 83696c2a0838d4821e5bcedc3034c0f473adfcdc0443cc078ef58bcf8edac0c7.
 * Live native refresh/ancestry/window-overlay checks remain mandatory at dispatch.
 */
final class WebRegionNativeBridge {
    static final String SCHEMA="hepta.mi-native-search-card-bridge.v1";
    private static final String VIEW="android.view.View",TEXT="android.widget.TextView",WEBVIEW="android.webkit.WebView";
    final PhoneObservation.Node anchor;
    final String regionRoot,anchorDomPath,semanticFingerprint;
    final String nativeWebViewId,nativeWebViewPath,nativeWebViewSignature;
    final String bindingSha,generation,instance;
    final long epoch;
    final int displayId,windowId;
    private final List<Role> actualRoles;
    private final String immutableEvidence;
    private final String sourceObservationId,sourceStateSha;
    private final int[] anchorBounds,webViewBounds;

    /** A snapshot, including cloned geometry, of the actual collected native node. */
    static final class Role {
        final String role,nodeId,nativePath,parentClass,nodeSignature,packageName,className,viewId,text,description;
        final boolean clickable,editable,scrollable,enabled,focused,password;
        private final int[] rectangle;
        Role(String role,PhoneObservation.Node node){
            this.role=role;nodeId=node.id;nativePath=node.nativeTreePath;parentClass=node.nativeParentClass;
            nodeSignature=node.observedAppTreeSignature;packageName=node.packageName;className=node.className;
            viewId=node.viewId;text=node.text;description=node.description;clickable=node.clickable;
            editable=node.editable;scrollable=node.scrollable;enabled=node.enabled;focused=node.focused;password=node.password;
            rectangle=new int[]{node.bounds.left,node.bounds.top,node.bounds.right,node.bounds.bottom};
        }
        int[] bounds(){return rectangle.clone();}
        boolean matches(PhoneObservation.Node node){
            return node!=null&&nodeId.equals(node.id)&&nativePath.equals(node.nativeTreePath)
                    &&parentClass.equals(node.nativeParentClass)&&nodeSignature.equals(node.observedAppTreeSignature)
                    &&packageName.equals(node.packageName)&&className.equals(node.className)&&viewId.equals(node.viewId)
                    &&text.equals(node.text)&&description.equals(node.description)&&clickable==node.clickable
                    &&editable==node.editable&&scrollable==node.scrollable&&enabled==node.enabled
                    &&focused==node.focused&&password==node.password
                    &&rectangle[0]==node.bounds.left&&rectangle[1]==node.bounds.top
                    &&rectangle[2]==node.bounds.right&&rectangle[3]==node.bounds.bottom;
        }
        JSONObject evidence()throws Exception{
            return new JSONObject().put("role",role).put("node_id",nodeId).put("native_tree_path",nativePath)
                    .put("native_parent_class",parentClass).put("node_app_tree_sha256",nodeSignature)
                    .put("package",packageName).put("class_name",className).put("view_id",viewId)
                    .put("text",text).put("description",description).put("native_bounds",new JSONArray(rectangle))
                    .put("clickable",clickable).put("editable",editable).put("scrollable",scrollable)
                    .put("enabled",enabled).put("focused",focused).put("password",password);
        }
    }
    private WebRegionNativeBridge(PhoneObservation frame,WebEvidenceReceipt receipt,WebNativeGeometry geometry,
            WebMiActionRegion region,PhoneObservation.Node anchor,PhoneObservation.Node model,
            PhoneObservation.Node currentPrice,PhoneObservation.Node comparisonPrice,PhoneObservation.Node nativeWebView)throws Exception{
        this.anchor=anchor;regionRoot=region.rootPath;anchorDomPath=region.anchorPath;
        bindingSha=receipt.bindingSha;generation=frame.backgroundGeneration;instance=receipt.instance;epoch=receipt.epoch;
        displayId=receipt.displayId;windowId=receipt.windowId;sourceObservationId=frame.id;sourceStateSha=frame.treeSha256;
        nativeWebViewId=nativeWebView.id;nativeWebViewPath=nativeWebView.nativeTreePath;
        nativeWebViewSignature=nativeWebView.observedAppTreeSignature;
        anchorBounds=new int[]{anchor.bounds.left,anchor.bounds.top,anchor.bounds.right,anchor.bounds.bottom};
        webViewBounds=new int[]{nativeWebView.bounds.left,nativeWebView.bounds.top,nativeWebView.bounds.right,nativeWebView.bounds.bottom};
        List<Role> roles=new ArrayList<Role>();
        roles.add(new Role("anchor",anchor));roles.add(new Role("model",model));
        roles.add(new Role("current_price",currentPrice));roles.add(new Role("comparison_price",comparisonPrice));
        actualRoles=Collections.unmodifiableList(roles);JSONArray nodes=new JSONArray();
        for(Role role:actualRoles)nodes.put(role.evidence());
        JSONObject semantic=new JSONObject().put("schema",SCHEMA).put("binding_sha256",bindingSha)
                .put("background_generation",generation).put("display_id",displayId).put("window_id",windowId)
                .put("webview_instance",instance).put("navigation_epoch",epoch)
                .put("region_root_path",regionRoot).put("anchor_dom_path",anchorDomPath)
                .put("region_sha256",region.fullRegionSha256).put("region_ancestor_sha256",region.ancestorSha256)
                .put("native_geometry_sha256",geometry.fingerprint)
                .put("native_webview_id",nativeWebViewId).put("native_webview_path",nativeWebViewPath)
                .put("native_webview_node_sha256",nativeWebViewSignature).put("native_webview_bounds",new JSONArray(webViewBounds))
                .put("native_roles",nodes);
        semanticFingerprint=WebDomCanonical.sha256(semantic);
        JSONObject proof=new JSONObject(WebDomCanonical.canonical(semantic))
                .put("semantic_fingerprint",semanticFingerprint)
                .put("source_observation_id",frame.id).put("source_observation_state_sha256",frame.treeSha256)
                .put("source_app_tree_sha256",frame.state.appTreeSha256)
                .put("source_capture_ended_elapsed_ms",receipt.ended)
                .put("source_before_dom_sha256",receipt.stability().beforeRawSha256)
                .put("source_dom_sha256",receipt.domSha)
                .put("source_stability_sha256",WebDomCanonical.sha256(receipt.stability().evidence()))
                .put("comparison_scope",receipt.stability().comparisonScope)
                .put("native_relationship_source","same_bounded_accessibility_traversal")
                .put("native_relative_relationship","model=anchor/1;current=anchor/2/0;comparison=anchor/2/1")
                .put("dom_price_boundary_rule","trim_only_U+0020_edges_preserve_numeric_spelling_and_CNY_suffix")
                .put("comparison_label_rule","one_observed_leading_ascii_space_before_boundary_trimmed_del_price")
                .put("dom_id_required",false).put("css_to_native_coordinate_mapping",false)
                .put("dom_path_used_as_native_path",false).put("coordinates_used_for_input",false)
                .put("live_native_ancestry_recheck_required",true).put("live_native_overlay_check_required",true)
                .put("native_dispatch_verified",false).put("fully_unoccluded_claimed",false)
                .put("detail_price_verified",false).put("transaction_authority",false).put("business_verified",false);
        immutableEvidence=WebDomCanonical.canonical(proof);
    }
    JSONObject evidence()throws Exception{return new JSONObject(immutableEvidence);}
    List<Role> roles(){return actualRoles;}
    int[] anchorBounds(){return anchorBounds.clone();}
    int[] webViewBounds(){return webViewBounds.clone();}

    static WebRegionNativeBridge bind(PhoneObservation frame,WebEvidenceReceipt receipt)throws Exception{
        if(frame==null||receipt==null||!"captured".equals(receipt.status)||receipt.stability()==null
                ||receipt.stability().region==null)return null;
        WebDomStability.Result checked=receipt.stability();WebMiActionRegion region=checked.region;
        if(!checked.permitsActionTargetPath(region.anchorPath)||!"_blank".equals(region.linkTarget)
                ||!WebEvidenceProtocol.HELPER_PACKAGE.equals(frame.packageName)||frame.nodesTruncated
                ||frame.collectionStats==null||frame.collectionStats.truncated()||frame.nodes.size()>512
                ||frame.windowMetadata==null||!"observed".equals(frame.windowMetadata.status)
                ||!Integer.valueOf(1).equals(frame.windowMetadata.type)||frame.windowMetadata.displayId==null
                ||frame.windowMetadata.displayId.intValue()!=receipt.displayId||frame.windowId!=receipt.windowId
                ||receipt.displayId<=0||frame.backgroundGeneration==null
                ||!Boolean.FALSE.equals(frame.state.imeVisibility.value())
                ||!frame.backgroundAllowedPackages.equals(Collections.singletonList(WebEvidenceProtocol.HELPER_PACKAGE)))
            return null;
        JSONObject capture=receipt.capture(),background=capture.getJSONObject("binding").getJSONObject("background");
        if(!frame.backgroundGeneration.equals(background.get("generation"))
                ||WebEvidenceJson.number(background,"display_id")!=receipt.displayId
                ||frame.backgroundSelectionEvidence()==null)return null;
        WebNativeGeometry geometry=WebNativeGeometry.read(capture,receipt.dom(),receipt.displayId,receipt.windowId,checked);
        if(geometry==null)return null;
        Map<String,PhoneObservation.Node> byPath=new HashMap<String,PhoneObservation.Node>();Set<String> ids=new HashSet<String>();
        for(PhoneObservation.Node node:frame.nodes){
            if(node==null||node.id==null||!ids.add(node.id))return null;
            if(node.nativeTreePath!=null&&byPath.put(node.nativeTreePath,node)!=null)return null;
        }
        String currentLabel=priceLabel(region.currentPriceRaw),comparisonLabel=priceLabel(region.comparisonPriceRaw);
        if(currentLabel==null||comparisonLabel==null)return null;
        String description=region.modelLabel+" "+currentLabel+" "+comparisonLabel;
        List<PhoneObservation.Node> anchors=new ArrayList<PhoneObservation.Node>();
        // Count every matching label before visibility/state filtering.
        for(PhoneObservation.Node node:frame.nodes)if(description.equals(node.description))anchors.add(node);
        if(anchors.size()!=1)return null;
        PhoneObservation.Node anchor=anchors.get(0);String path=anchor.nativeTreePath;
        if(path==null||!readable(frame,geometry,anchor)||!VIEW.equals(anchor.className)||!VIEW.equals(anchor.nativeParentClass)
                ||!anchor.viewId.isEmpty()||!anchor.text.isEmpty()||!anchor.clickable||anchor.scrollable)return null;
        PhoneObservation.Node model=byPath.get(path+"/1"),current=byPath.get(path+"/2/0"),comparison=byPath.get(path+"/2/1");
        if(!role(frame,geometry,model,TEXT,region.modelLabel,true)
                ||!role(frame,geometry,current,TEXT,currentLabel,false)
                ||!role(frame,geometry,comparison,VIEW," "+comparisonLabel,false)
                ||model==anchor||current==anchor||comparison==anchor||model==current||model==comparison||current==comparison)
            return null;
        for(PhoneObservation.Node node:Arrays.asList(model,current,comparison))
            if(!VIEW.equals(node.nativeParentClass)||!inside(anchor.bounds,node.bounds))return null;
        if(countTextUnder(frame,path,region.modelLabel)!=1||countTextUnder(frame,path,currentLabel)!=1
                ||countTextUnder(frame,path," "+comparisonLabel)!=1)return null;
        PhoneObservation.Node nativeWebView=null;
        for(PhoneObservation.Node node:frame.nodes)if(WEBVIEW.equals(node.className)&&node.nativeTreePath!=null
                &&path.startsWith(node.nativeTreePath+"/")&&readableWebView(frame,geometry,node)){
            if(nativeWebView==null||node.nativeTreePath.length()>nativeWebView.nativeTreePath.length())nativeWebView=node;
        }
        if(nativeWebView==null||!inside(nativeWebView.bounds,anchor.bounds))return null;
        return new WebRegionNativeBridge(frame,receipt,geometry,region,anchor,model,current,comparison,nativeWebView);
    }
    /** Rechecks the exact original frame snapshot, never a serialized replacement. */
    void requireFrame(PhoneObservation frame){
        need(frame!=null&&sourceObservationId.equals(frame.id)&&sourceStateSha.equals(frame.treeSha256)
                &&generation.equals(frame.backgroundGeneration)&&frame.windowId==windowId
                &&frame.windowMetadata.displayId!=null&&frame.windowMetadata.displayId.intValue()==displayId
                &&!frame.nodesTruncated,"native bridge frame identity changed");
        for(Role role:actualRoles){
            PhoneObservation.Node match=null;int count=0;
            for(PhoneObservation.Node node:frame.nodes)if(role.nodeId.equals(node.id)){match=node;count++;}
            need(count==1&&role.matches(match),"native bridge role snapshot changed: "+role.role);
        }
        PhoneObservation.Node web=null;int count=0;
        for(PhoneObservation.Node node:frame.nodes)if(nativeWebViewId.equals(node.id)){web=node;count++;}
        need(count==1&&nativeWebViewPath.equals(web.nativeTreePath)&&nativeWebViewSignature.equals(web.observedAppTreeSignature)
                &&webViewBounds[0]==web.bounds.left&&webViewBounds[1]==web.bounds.top
                &&webViewBounds[2]==web.bounds.right&&webViewBounds[3]==web.bounds.bottom,"native WebView snapshot changed");
    }
    /** DOM price spans and native AX expose different observed boundary spaces.
     * Only ASCII spaces at the two DOM edges are ignored; the decimal spelling
     * and 元 suffix remain exact. Raw DOM and native labels stay in the proof. */
    private static String priceLabel(String raw){
        if(raw==null||!raw.matches(" *(?:0|[1-9][0-9]{0,7})(?:\\.[0-9]{1,2})?元 *"))return null;
        int left=0,right=raw.length();while(left<right&&raw.charAt(left)==' ')left++;
        while(right>left&&raw.charAt(right-1)==' ')right--;return raw.substring(left,right);
    }
    private static boolean role(PhoneObservation frame,WebNativeGeometry geometry,PhoneObservation.Node node,String cls,String text,boolean clickable){
        return node!=null&&readable(frame,geometry,node)&&cls.equals(node.className)&&text.equals(node.text)
                &&node.description.isEmpty()&&node.viewId.isEmpty()&&node.clickable==clickable&&!node.scrollable;
    }
    private static boolean readable(PhoneObservation frame,WebNativeGeometry geometry,PhoneObservation.Node node){
        return node!=null&&WebEvidenceProtocol.HELPER_PACKAGE.equals(node.packageName)&&node.enabled&&!node.editable&&!node.password
                &&node.nativeTreePath!=null&&node.nativeParentClass!=null
                &&node.observedAppTreeSignature!=null&&node.observedAppTreeSignature.matches("[0-9a-f]{64}")
                &&node.bounds.left<node.bounds.right&&node.bounds.top<node.bounds.bottom
                &&geometry.contains(node.bounds.left,node.bounds.top,node.bounds.right,node.bounds.bottom)
                &&inside(frame.windowMetadata.rootBounds(),node.bounds)&&inside(frame.windowMetadata.windowBounds(),node.bounds)
                &&node.bounds.left>=0&&node.bounds.top>=0&&node.bounds.right<=frame.width&&node.bounds.bottom<=frame.height;
    }
    private static boolean readableWebView(PhoneObservation frame,WebNativeGeometry geometry,PhoneObservation.Node node){
        return readable(frame,geometry,node)&&node.bounds.left==geometry.bounds[0]&&node.bounds.top==geometry.bounds[1]
                &&node.bounds.right==geometry.bounds[2]&&node.bounds.bottom==geometry.bounds[3];
    }
    private static int countTextUnder(PhoneObservation frame,String path,String text){
        int count=0;for(PhoneObservation.Node node:frame.nodes)
            if(node.nativeTreePath!=null&&node.nativeTreePath.startsWith(path+"/")&&text.equals(node.text))count++;
        return count;
    }
    private static boolean inside(Rect outer,Rect inner){return outer.left<=inner.left&&outer.top<=inner.top&&inner.right<=outer.right&&inner.bottom<=outer.bottom;}
    private static boolean inside(int[] outer,Rect inner){return outer!=null&&outer.length==4&&outer[0]<=inner.left&&outer[1]<=inner.top&&inner.right<=outer[2]&&inner.bottom<=outer[3];}
    private static void need(boolean value,String reason){if(!value)throw new IllegalArgumentException(reason);}
}
