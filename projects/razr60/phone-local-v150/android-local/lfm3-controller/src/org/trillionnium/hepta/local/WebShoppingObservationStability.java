package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebDomCanonical;
import org.trillionnium.hepta.webprotocol.WebDomStability;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import org.trillionnium.hepta.webprotocol.WebMiActionRegion;
import org.trillionnium.hepta.webprotocol.WebSitePolicy;
import org.trillionnium.hepta.webprotocol.WebTaskPurpose;

/**
 * Read-only admission of the fixed Mi search card across an observed recommendation
 * rotation. A complete private native snapshot and live service checks are mandatory.
 * This class creates no action Permit, link ARM, navigation or detail-price result.
 */
final class WebShoppingObservationStability {
    static final int MAX_NATIVE_NODES=1024;
    static final String TITLE="Xiaomi路由器AX3000T 白色";
    private static final String OBSERVER_SHA="05bb7c1e4e1929b961c42af1e5c0e01918bf6ff64f153132ca11c7d85873e705";
    private static final String PRICE="(?:0|[1-9][0-9]{0,7})(?:\\.[0-9]{1,2})?元";
    private WebShoppingObservationStability(){}

    /** Main handoff selects only a unique frozen row; it performs no native IO. */
    static PhoneObservation.Node target(java.util.List<PhoneObservation.Node> rows){
        PhoneObservation.Node selected=null;
        for(PhoneObservation.Node row:rows)if(row.description!=null&&row.description.startsWith(TITLE+" ")){
            if(selected!=null)return null;selected=row;
        }
        return selected!=null&&selected.description.matches(TITLE+" "+PRICE+" "+PRICE)
                &&"android.view.View".equals(selected.className)&&selected.text.isEmpty()
                &&selected.viewId.isEmpty()&&WebEvidenceProtocol.HELPER_PACKAGE.equals(selected.packageName)
                &&selected.clickable&&selected.enabled&&!selected.password&&!selected.editable&&!selected.scrollable
                &&selected.nativeTreePath!=null?selected:null;
    }

    /** A pure eligibility probe only. The owned service replays everything before publication. */
    static boolean supportsCaptures(JSONObject first,JSONObject last){
        try{captureDom(first,last);return true;}catch(Exception rejected){return false;}
    }

    /** Read-only eligibility may reuse each immutable receipt's own-pair proof.
     * The owned native admission below still independently replays the full JSON path. */
    static boolean supportsCaptures(WebEvidenceReceipt first,WebEvidenceReceipt last){
        try{captureDom(first.capture(),last.capture(),first,last);return true;}catch(Exception rejected){return false;}
    }

    private enum CaptureUse { STRICT, READONLY_OBSERVATION }
    /** A private immutable, capture-bound eligibility result, never a dispatch or completion permit. */
    static final class ReadObservationEligibility {
        private final String bindingSha,firstBeforeSha,firstAfterSha,lastBeforeSha,lastAfterSha;
        private ReadObservationEligibility(JSONObject first,JSONObject proof)throws Exception{
            bindingSha=WebDomCanonical.sha256(first.getJSONObject("binding"));
            firstBeforeSha=proof.getString("first_before_sha256");firstAfterSha=proof.getString("first_after_sha256");
            lastBeforeSha=proof.getString("last_before_sha256");lastAfterSha=proof.getString("last_after_sha256");
        }
    }
    /** Only the price-only purpose may explain the named footer change; every other purpose remains strict. */
    static ReadObservationEligibility readObservationEligibility(WebEvidenceReceipt first,WebEvidenceReceipt last){
        try{
            JSONObject raw=first.capture();
            return new ReadObservationEligibility(raw,captureDom(raw,last.capture(),first,last,CaptureUse.READONLY_OBSERVATION));
        }catch(Exception rejected){return null;}
    }

    static JSONObject compareDom(JSONObject before,JSONObject after)throws Exception{
        return compareDom(before,after,null);
    }
    private static JSONObject compareDom(JSONObject before,JSONObject after,FooterVisibilityObservation footer)throws Exception{
        Map<String,JSONObject> a=WebDomStability.index(before),b=WebDomStability.index(after);
        requireDomCounts(before,a);requireDomCounts(after,b);
        need(a.keySet().equals(b.keySet()),"complete search DOM membership changed");
        WebMiActionRegion first=WebMiActionRegion.read(before),last=WebMiActionRegion.read(after);
        need(first.sameRegion(last),"complete selected card, ancestors, styles or hit observations changed");
        // URL, viewport, top-layer and selected-card observations remain exact.
        // The known empty loading decoration is checked separately; all unknown clipping changes reject.
        // Recomputed text totals may change only with the explicit outside text changes below.
        need(WebDomCanonical.same(without(before,"nodes","text_utf16_units","clipping_context_observations"),without(after,"nodes","text_utf16_units","clipping_context_observations")),
                "search document metadata, geometry, styles or occlusion changed");
        JSONArray clipChanges=compareClip(before,after,a,b,first);
        String recommendation=unique(a,"id","J_recommend_search");
        need(recommendation.equals(unique(b,"id","J_recommend_search")),"recommendation identity changed");
        JSONObject rec=a.get(recommendation);String widget=parent(recommendation);
        need("div".equals(rec.get("tag"))&&!first.containsPath(recommendation)&&!first.isAncestorPath(recommendation)
                &&a.containsKey(widget)&&"div".equals(a.get(widget).get("tag"))
                &&WebDomCanonical.same(rec,b.get(recommendation))&&WebDomCanonical.same(a.get(widget),b.get(widget)),
                "fixed separate recommendation container changed");
        need(!first.overlaps(WebDomStability.rect(rec.getJSONArray("rect_css_pixels")))
                &&!first.overlaps(WebDomStability.rect(a.get(widget).getJSONArray("rect_css_pixels"))),
                "recommendation container overlaps the selected card");
        String previous=slideControl(a,widget,"Previous slide"),next=slideControl(a,widget,"Next slide");
        need(previous.equals(slideControl(b,widget,"Previous slide"))&&next.equals(slideControl(b,widget,"Next slide"))
                &&parent(previous).equals(parent(next))&&!previous.equals(next),"same two recommendation controls required");
        JSONArray changes=new JSONArray();int geometryOnly=0,semantic=0;
        for(String path:a.keySet()){
            JSONObject x=a.get(path),y=b.get(path);if(WebDomCanonical.same(x,y))continue;
            need(!first.containsPath(path)&&!first.isAncestorPath(path),"selected card or ancestor changed");
            String scope;
            if(path.startsWith(recommendation+"/")){
                need(WebDomCanonical.same(without(x,"text","visible_in_viewport","rect_css_pixels"),
                        without(y,"text","visible_in_viewport","rect_css_pixels")),
                        "recommendation link, control, DOM kind or other semantic field changed");
                need(!oneOf(x.getString("tag"),"input","select","textarea","iframe","frame","object","embed","canvas","video","svg","dialog")
                        &&!"dialog".equals(x.getString("role"))&&!"alertdialog".equals(x.getString("role"))
                        &&!"true".equals(x.getString("aria_modal")),"unsupported recommendation content");
                scope="observed_recommendation_text_and_geometry";semantic++;
            }else if(path.equals(previous)||path.equals(next)){
                need(WebDomCanonical.same(without(x,"aria_disabled"),without(y,"aria_disabled"))
                        &&booleanText(x.get("aria_disabled"))&&booleanText(y.get("aria_disabled")),
                        "recommendation control changed beyond its disabled observation");
                scope="observed_recommendation_control_disabled_state";
            }else if(footer!=null&&footer.explains(path,x,y)){
                scope="observed_footer_IMG_visibility_exchange";semantic++;
            }else{
                need(WebDomCanonical.same(without(x,"rect_css_pixels"),without(y,"rect_css_pixels")),
                        "non-recommendation semantic data changed");
                need(++geometryOnly<=32,"too many outside geometry changes");
                scope="outside_geometry_only";
            }
            need(!first.overlaps(WebDomStability.rect(x.getJSONArray("rect_css_pixels")))
                    &&!last.overlaps(WebDomStability.rect(y.getJSONArray("rect_css_pixels"))),
                    "changed outside rectangle overlaps selected card");
            changes.put(new JSONObject().put("dom_path",path).put("scope",scope).put("before",x).put("after",y));
        }
        need(semantic<=256&&changes.length()<=320,"bounded explicit outside differences");
        JSONObject proof=new JSONObject().put("schema","hepta.mi-search-readonly-dom-scope.v1")
                .put("scope","fixed_selected_card_with_explicit_recommendation_changes")
                .put("selected_region",last.evidence()).put("recommendation_dom_path",recommendation)
                .put("recommendation_widget_dom_path",widget).put("previous_slide_dom_path",previous).put("next_slide_dom_path",next)
                .put("before_visited",before.get("visited")).put("after_visited",after.get("visited"))
                .put("before_text_utf16_units",before.get("text_utf16_units")).put("after_text_utf16_units",after.get("text_utf16_units"))
                .put("each_dom_counts_recomputed",true).put("all_selected_region_and_ancestors_equal",true)
                .put("all_other_semantics_equal",true).put("outside_changes",changes).put("outside_clip_style_changes",clipChanges)
                .put("whole_dom_equal",WebDomCanonical.same(before,after))
                .put("outside_content_verified_as_task_result",false).put("fully_unoccluded_claimed",false)
                .put("grants_action_authority",false).put("detail_price_verified",false).put("business_verified",false);
        if(footer!=null)proof.put("observed_footer_visibility",footer.evidence());
        return proof;
    }

    private static JSONObject captureDom(JSONObject first,JSONObject last)throws Exception{
        return captureDom(first,last,null,null);
    }
    private static JSONObject captureDom(JSONObject first,JSONObject last,WebEvidenceReceipt verifiedFirst,WebEvidenceReceipt verifiedLast)throws Exception{
        return captureDom(first,last,verifiedFirst,verifiedLast,CaptureUse.STRICT);
    }
    private static JSONObject captureDom(JSONObject first,JSONObject last,WebEvidenceReceipt verifiedFirst,WebEvidenceReceipt verifiedLast,CaptureUse use)throws Exception{
        need((verifiedFirst==null)==(verifiedLast==null),"complete private receipt pair required");
        JSONObject binding=first.getJSONObject("binding");WebTaskPurpose purpose=WebTaskPurpose.requireBinding(binding);
        need(purpose.shopping!=null&&WebMiActionRegion.POLICY.equals(purpose.sitePolicyId)
                &&WebDomCanonical.same(binding,last.getJSONObject("binding")),"same original shopping binding required");
        for(String key:new String[]{"webview_instance","navigation_epoch","helper_uid","helper_pid","display_id","actual_window_id",
                "commit_elapsed_ms","observer_script_sha256","committed_main_frame_url","current_native_url"})
            need(WebDomCanonical.same(first.get(key),last.get(key)),"capture identity changed: "+key);
        need(first.getInt("display_id")>0&&first.getInt("actual_window_id")>=0
                &&!first.getString("webview_instance").isEmpty()
                &&first.getLong("ended_elapsed_ms")<=last.getLong("started_elapsed_ms"),"ordered actual capture bracket required");
        JSONObject[] doms=new JSONObject[4];int at=0;
        JSONArray ownProofs=new JSONArray();int receiptIndex=0;
        WebDomStability.Result[] ownResults=new WebDomStability.Result[2];
        WebEvidenceReceipt[] verified=new WebEvidenceReceipt[]{verifiedFirst,verifiedLast};
        for(JSONObject capture:new JSONObject[]{first,last}){
            need(OBSERVER_SHA.equals(capture.get("observer_script_sha256"))
                    &&WebSitePolicy.INITIAL_URL.equals(capture.get("committed_main_frame_url"))
                    &&WebSitePolicy.INITIAL_URL.equals(capture.get("current_native_url"))
                    &&WebEvidenceProtocol.HELPER_PACKAGE.equals(capture.get("helper_package"))
                    &&capture.isNull("observed_link_navigation")&&!capture.getBoolean("truncated"),
                    "readonly exception is only for the unchanged original Mi search page");
            String x=capture.getString("before_dom_raw_utf8"),y=capture.getString("dom_raw_utf8");
            need(x.getBytes(StandardCharsets.UTF_8).length<=1024*1024&&y.getBytes(StandardCharsets.UTF_8).length<=1024*1024,
                    "bounded original raw DOM values required");
            doms[at++]=WebEvidenceJson.parseDom(x);doms[at++]=WebEvidenceJson.parseDom(y);
            WebEvidenceReceipt receipt=verified[receiptIndex++];
            WebDomStability.Result own=receipt==null
                    ?WebDomStability.verify(x,y,WebMiActionRegion.POLICY,capture.getJSONObject("dom_stability"))
                    :receipt.verifiedStability(capture);
            need(own.region!=null&&own.beforeRawSha256.equals(capture.get("before_dom_sha256"))
                    &&own.afterRawSha256.equals(capture.get("dom_sha256"))
                    &&WebDomCanonical.sha256(own.evidence()).equals(capture.get("dom_stability_sha256")),
                    "each capture must retain its original independently verified card proof");
            ownResults[receiptIndex-1]=own;
            ownProofs.put(own.evidence());
        }
        FooterVisibilityObservation footer=use==CaptureUse.READONLY_OBSERVATION
                ?FooterVisibilityObservation.ifChanged(purpose,first,last,doms,ownResults[0].region):null;
        JSONObject middle=compareDom(doms[1],doms[2],footer);
        // Validate all four independently; neither a changed counter nor an omitted node is normalized away.
        for(JSONObject d:doms)requireDomCounts(d,WebDomStability.index(d));
        WebMiActionRegion region=WebMiActionRegion.read(doms[0]);
        for(JSONObject d:doms)need(region.sameRegion(WebMiActionRegion.read(d)),"all four complete card regions must agree");
        WebNativeGeometry a=WebNativeGeometry.read(first,doms[1],first.getInt("display_id"),first.getInt("actual_window_id"),ownResults[0]);
        WebNativeGeometry b=WebNativeGeometry.read(last,doms[3],last.getInt("display_id"),last.getInt("actual_window_id"),ownResults[1]);
        need(a!=null&&a.same(b),"original native WebView geometry changed across captures");
        return new JSONObject().put("dom_scope",middle).put("capture_stability_proofs",ownProofs)
                .put("native_geometry_sha256",b.fingerprint).put("native_webview_bounds",new JSONArray(b.bounds))
                .put("first_before_sha256",first.get("before_dom_sha256")).put("first_after_sha256",first.get("dom_sha256"))
                .put("last_before_sha256",last.get("before_dom_sha256")).put("last_after_sha256",last.get("dom_sha256"));
    }

    static JSONObject compareObservationBracket(String taskId,JSONObject beforeFrame,JSONArray beforeNative,
            JSONObject afterFrame,JSONArray afterNative,JSONObject first,JSONObject last,String targetPath)throws Exception{
        return compareObservationBracket(taskId,beforeFrame,beforeNative,afterFrame,afterNative,first,last,targetPath,CaptureUse.STRICT);
    }
    /** The owned service independently replays original captures; eligibility is never accepted as authority. */
    static JSONObject compareReadonlyObservationBracket(String taskId,JSONObject beforeFrame,JSONArray beforeNative,
            JSONObject afterFrame,JSONArray afterNative,JSONObject first,JSONObject last,String targetPath)throws Exception{
        return compareObservationBracket(taskId,beforeFrame,beforeNative,afterFrame,afterNative,first,last,targetPath,CaptureUse.READONLY_OBSERVATION);
    }
    private static JSONObject compareObservationBracket(String taskId,JSONObject beforeFrame,JSONArray beforeNative,
            JSONObject afterFrame,JSONArray afterNative,JSONObject first,JSONObject last,String targetPath,CaptureUse use)throws Exception{
        requireCompleteObservation(beforeFrame,beforeNative);requireCompleteObservation(afterFrame,afterNative);
        need(WebDomCanonical.same(without(beforeFrame,"observation_id","screen_sha256","app_tree_sha256","observation_state_sha256","nodes","collection"),
                without(afterFrame,"observation_id","screen_sha256","app_tree_sha256","observation_state_sha256","nodes","collection")),
                "observation window, Selection, IME or frame metadata changed");
        need(WebDomCanonical.same(without(beforeFrame.getJSONObject("collection"),"elapsed_ms","retained_nodes","retained_text_utf16"),
                without(afterFrame.getJSONObject("collection"),"elapsed_ms","retained_nodes","retained_text_utf16")),
                "complete traversal budget or membership count changed");
        JSONObject dom=captureDom(first,last,null,null,use),binding=first.getJSONObject("binding"),bg=binding.getJSONObject("background");
        JSONObject selected=beforeFrame.getJSONObject("background_session");int display=first.getInt("display_id"),window=first.getInt("actual_window_id");
        need(taskId!=null&&taskId.equals(binding.get("task_id"))&&beforeFrame.getInt("window_id")==window
                &&beforeFrame.getJSONObject("window").getInt("display_id")==display&&bg.getInt("display_id")==display
                &&bg.getString("generation").equals(selected.get("generation"))
                &&WebDomCanonical.same(bg.getJSONArray("selected_packages"),selected.getJSONArray("allowed_packages")),
                "captures must belong to the actual task and original native background Selection");
        JSONObject nativeProof=compareNative(beforeNative,afterNative,targetPath);
        Map<String,JSONObject> a=nativeNodes(beforeNative);
        String webview=ancestorClass(a,targetPath,"android.webkit.WebView");
        need(webview!=null&&WebDomCanonical.same(a.get(webview).getJSONArray("bounds"),dom.getJSONArray("native_webview_bounds")),
                "native target WebView ancestor differs from original capture geometry");
        WebMiActionRegion region=WebMiActionRegion.read(WebEvidenceJson.parseDom(last.getString("dom_raw_utf8")));
        requireTargetRoles(a,targetPath,region);
        requireTargetRoles(nativeNodes(afterNative),targetPath,region);
        nativeProof.put("retained_node_pairing",compareRetained(beforeFrame.getJSONArray("nodes"),afterFrame.getJSONArray("nodes"),
                nativeProof.getString("recommendation_native_path")));
        return new JSONObject().put("schema","hepta.mi-search-readonly-observation-bracket.v1")
                .put("purpose","readonly_current_selected_search_card").put("task_id",taskId)
                .put("binding_sha256",WebDomCanonical.sha256(binding)).put("webview_instance",first.get("webview_instance"))
                .put("navigation_epoch",first.get("navigation_epoch")).put("display_id",display).put("window_id",window)
                .put("first_observation",beforeFrame).put("last_observation",afterFrame)
                .put("first_capture_challenge",first.get("challenge")).put("last_capture_challenge",last.get("challenge"))
                .put("dom",dom).put("native",nativeProof).put("complete_native_snapshot_structure_replayed",true)
                .put("retained_rows_are_not_the_complete_traversal",true).put("action_permit_created",false)
                .put("grants_action_authority",false).put("coordinates_used_for_input",false)
                .put("css_to_screen_mapping_claimed",false).put("pixel_equality_claimed",false)
                .put("fully_unoccluded_claimed",false).put("detail_price_verified",false).put("business_verified",false);
    }

    static JSONObject compareNative(JSONArray before,JSONArray after,String targetPath)throws Exception{
        Map<String,JSONObject> a=nativeNodes(before),b=nativeNodes(after);
        need(a.keySet().equals(b.keySet()),"complete native membership changed");
        JSONObject target=a.get(targetPath);need(target!=null,"original selected native target missing");
        need("android.view.View".equals(target.get("class"))&&target.getString("text").isEmpty()
                &&target.getString("description").matches(TITLE+" "+PRICE+" "+PRICE)&&target.getString("view_id").isEmpty()
                &&target.getBoolean("visible")&&target.getBoolean("enabled")&&target.getBoolean("clickable")
                &&!target.getBoolean("editable")&&!target.getBoolean("password")&&!target.getBoolean("scrollable"),
                "exact native search-card target required");
        String rec=unique(a,"view_id","J_recommend_search");
        need(rec.equals(unique(b,"view_id","J_recommend_search"))&&!inside(targetPath,rec)&&!inside(rec,targetPath)
                &&WebDomCanonical.same(a.get(rec),b.get(rec))&&"android.view.View".equals(a.get(rec).get("class"))
                &&ancestorClass(a,targetPath,"android.webkit.WebView")!=null
                &&ancestorClass(a,targetPath,"android.webkit.WebView").equals(ancestorClass(a,rec,"android.webkit.WebView")),
                "separate stable native recommendation container and target required");
        int[] box=intRect(a.get(rec)),targetBox=intRect(target);need(!overlap(box,targetBox),"native recommendation overlaps selected card");
        JSONArray changes=new JSONArray();int scoped=0;
        for(String path:a.keySet()){
            JSONObject x=a.get(path),y=b.get(path);
            if(!path.startsWith(rec+"/")){
                if(!WebDomCanonical.same(x,y))throw new WebNativeObservationChanged("native target, ancestor or outside recommendation node changed: ",path,nativeChangeDiagnostic(path,x,y));
            }else{
                need(++scoped<=512&&WebDomCanonical.same(without(x,"text","description","bounds","visible"),
                        without(y,"text","description","bounds","visible")),"native recommendation identity or action state changed");
                need(!x.getBoolean("editable")&&!x.getBoolean("password")&&!x.getBoolean("focused")
                        &&!x.getBoolean("scrollable"),"native recommendation carries unsupported input state");
                for(JSONObject row:new JSONObject[]{x,y})if(row.getBoolean("visible"))
                    needRecommendationContainment(contains(box,intRect(row))&&!overlap(targetBox,intRect(row)),
                            before,after,targetPath,rec,path,row==x,box,targetBox,row);
                if(!WebDomCanonical.same(x,y))changes.put(new JSONObject().put("native_path",path).put("before",x).put("after",y));
            }
            for(JSONObject row:new JSONObject[]{x,y})if(row.getBoolean("visible")&&!inside(path,targetPath)&&!inside(targetPath,path))
                need(!overlap(targetBox,intRect(row)),"foreign native node overlaps selected card");
        }
        return new JSONObject().put("schema","hepta.mi-search-readonly-native-scope.v1").put("target_native_path",targetPath)
                .put("recommendation_native_path",rec).put("before",before).put("after",after).put("outside_changes",changes)
                .put("complete_native_membership_equal",true).put("all_non_recommendation_native_records_equal",true)
                .put("action_permit_created",false).put("business_verified",false);
    }

    private static final String CONTAINMENT_FAILURE="visible native recommendation escaped its container";
    private static final int PRIVATE_NATIVE_PAIR_BYTES=2*1024*1024;
    /** A private, stackless locator attached at the actual first rejection; never an action capability. */
    private static final class NativeContainmentPoint extends Exception {
        private static final long serialVersionUID = 1L;
        final JSONArray before,after;final JSONObject row;
        final String target,container,path;final boolean beforeSide;
        final int[] containerBox,targetBox,rowBox;
        NativeContainmentPoint(JSONArray before,JSONArray after,String target,String container,String path,
                               boolean beforeSide,int[] containerBox,int[] targetBox,JSONObject row)throws Exception{
            super("native containment failure locator",null,false,false);
            this.before=before;this.after=after;this.target=target;this.container=container;this.path=path;
            this.beforeSide=beforeSide;this.containerBox=containerBox.clone();this.targetBox=targetBox.clone();
            this.row=row;this.rowBox=intRect(row);
        }
    }
    private static void needRecommendationContainment(boolean condition,JSONArray before,JSONArray after,
            String target,String container,String path,boolean beforeSide,int[] box,int[] targetBox,JSONObject row){
        if(condition)return;
        try{need(false,CONTAINMENT_FAILURE);}
        catch(IllegalArgumentException original){
            try{original.addSuppressed(new NativeContainmentPoint(before,after,target,container,path,beforeSide,box,targetBox,row));}
            catch(Throwable unavailable){/* Preserve the exact original rejection even if diagnostics cannot be made. */}
            throw original;
        }
    }
    /** Called only after the original native-dom span has ended. Raw strings are the service's full snapshots. */
    static String[] containmentFailureDiagnostic(Throwable failure,JSONArray before,JSONArray after,
            String beforeRaw,String afterRaw,String targetPath){
        if(failure==null||failure.getClass()!=IllegalArgumentException.class||!CONTAINMENT_FAILURE.equals(failure.getMessage()))return null;
        NativeContainmentPoint point=null;
        try{
            Throwable[] markers=failure.getSuppressed();
            if(markers.length!=1||!(markers[0] instanceof NativeContainmentPoint))return null;
            point=(NativeContainmentPoint)markers[0];
            need(point.before==before&&point.after==after&&point.target.equals(targetPath),"diagnostic snapshot identity");
            if(beforeRaw==null||afterRaw==null||beforeRaw.length()>PRIVATE_NATIVE_PAIR_BYTES||afterRaw.length()>PRIVATE_NATIVE_PAIR_BYTES
                    ||(long)beforeRaw.getBytes(StandardCharsets.UTF_8).length+afterRaw.getBytes(StandardCharsets.UTF_8).length>PRIVATE_NATIVE_PAIR_BYTES)
                return containmentUnavailable("private_pair_exceeds_cap");
            JSONArray parsedBefore=WebEvidenceJson.parseEvidence("{\"nodes\":"+beforeRaw+"}",PRIVATE_NATIVE_PAIR_BYTES).getJSONArray("nodes");
            JSONArray parsedAfter=WebEvidenceJson.parseEvidence("{\"nodes\":"+afterRaw+"}",PRIVATE_NATIVE_PAIR_BYTES).getJSONArray("nodes");
            Map<String,JSONObject> a=nativeNodes(parsedBefore),b=nativeNodes(parsedAfter);
            need(WebDomCanonical.same(parsedBefore,before)&&WebDomCanonical.same(parsedAfter,after),"diagnostic raw snapshot differs");
            need(a.keySet().equals(b.keySet())&&a.containsKey(point.path)&&a.containsKey(point.target)&&a.containsKey(point.container),
                    "diagnostic full membership differs");
            JSONObject row=(point.beforeSide?a:b).get(point.path);
            need((point.beforeSide?nativeNodes(before):nativeNodes(after)).get(point.path)==point.row
                    &&Arrays.equals(point.rowBox,intRect(row))&&Arrays.equals(point.containerBox,intRect(a.get(point.container)))
                    &&Arrays.equals(point.targetBox,intRect(a.get(point.target)))&&Boolean.TRUE.equals(row.get("visible")),
                    "diagnostic failure point differs");
            boolean contained=contains(point.containerBox,point.rowBox),overlaps=overlap(point.targetBox,point.rowBox);
            need(!contained||overlaps,"diagnostic failure predicate no longer fails");
            String beforeSha=WebDomCanonical.sha256Utf8(beforeRaw),afterSha=WebDomCanonical.sha256Utf8(afterRaw);
            JSONObject metadata=new JSONObject().put("schema","hepta.native-containment-failure.v1").put("available",true)
                    .put("native_path",point.path).put("side",point.beforeSide?"before":"after")
                    .put("recommendation_native_path",point.container).put("target_native_path",point.target)
                    .put("row_bounds",new JSONArray(point.rowBox)).put("container_bounds",new JSONArray(point.containerBox))
                    .put("target_bounds",new JSONArray(point.targetBox)).put("visible",true)
                    .put("container_contains_row",contained).put("row_overlaps_target",overlaps)
                    .put("original_overlap_evaluated",contained).put("before_raw_sha256",beforeSha).put("after_raw_sha256",afterSha)
                    .put("before_row_count",parsedBefore.length()).put("after_row_count",parsedAfter.length())
                    .put("complete_source_snapshots",true).put("contains_page_text",false).put("grants_action_capability",false);
            String payload=new JSONObject().put("schema","hepta.native-containment-private-pair.v1")
                    .put("before_snapshot_raw",beforeRaw).put("after_snapshot_raw",afterRaw)
                    .put("before_raw_sha256",beforeSha).put("after_raw_sha256",afterSha)
                    .put("before_row_count",parsedBefore.length()).put("after_row_count",parsedAfter.length())
                    .put("failure_metadata",metadata).put("complete",true).put("contains_page_text",true)
                    .put("grants_action_capability",false).toString();
            if(payload.getBytes(StandardCharsets.UTF_8).length>PRIVATE_NATIVE_PAIR_BYTES)
                return containmentUnavailable("private_pair_exceeds_cap");
            return new String[]{metadata.toString(),payload};
        }catch(Throwable unavailable){return containmentUnavailable("diagnostic_unavailable");}
    }
    private static String[] containmentUnavailable(String reason){
        try{return new String[]{new JSONObject().put("schema","hepta.native-containment-failure.v1").put("available",false)
                .put("reason",reason).put("contains_page_text",false).put("grants_action_capability",false).toString(),null};}
        catch(Throwable unavailable){return null;}
    }

    /** Failure-only metadata. Never publishes a row value or changes the rejection. */
    private static String nativeChangeDiagnostic(String path,JSONObject before,JSONObject after){
        final String unavailable="{\"schema\":\"hepta.native-row-change-diagnostic.v1\",\"available\":false,\"contains_page_text\":false,\"grants_action_capability\":false}";
        try{
            if(path==null||path.length()>1024||!path.matches("0(?:/(?:0|[1-9][0-9]{0,5})){0,127}")
                    ||before==null||after==null||before.length()>64||after.length()>64)return unavailable;
            Set<String> keys=new TreeSet<String>();
            for(java.util.Iterator<String> it=before.keys();it.hasNext();)keys.add(it.next());
            for(java.util.Iterator<String> it=after.keys();it.hasNext();)keys.add(it.next());
            if(keys.size()>64)return unavailable;
            JSONArray fields=new JSONArray();
            for(String key:keys){
                if(!key.matches("[a-z][a-z0-9_]{0,63}"))return unavailable;
                if(before.has(key)!=after.has(key)||!WebDomCanonical.same(before.get(key),after.get(key)))fields.put(key);
            }
            String result=new JSONObject().put("schema","hepta.native-row-change-diagnostic.v1")
                    .put("available",true).put("native_path",path).put("changed_fields",fields)
                    .put("before_canonical_sha256",WebDomCanonical.sha256(before))
                    .put("after_canonical_sha256",WebDomCanonical.sha256(after))
                    .put("contains_page_text",false).put("grants_action_capability",false).toString();
            return result.length()<=4096?result:unavailable;
        }catch(Exception ignored){return unavailable;}
    }

    static JSONObject compareRetained(JSONArray before,JSONArray after,String recommendation)throws Exception{
        Map<String,JSONObject> a=retained(before),b=retained(after);Set<String> paths=new TreeSet<String>();paths.addAll(a.keySet());paths.addAll(b.keySet());
        JSONArray changedScope=new JSONArray(),ordinal=new JSONArray();
        for(String path:paths){
            JSONObject x=a.get(path),y=b.get(path);
            if(inside(path,recommendation)){
                if(x==null||y==null||!WebDomCanonical.same(x,y))changedScope.put(new JSONObject().put("native_path",path)
                        .put("before",x==null?JSONObject.NULL:x).put("after",y==null?JSONObject.NULL:y));
            }else{
                need(x!=null&&y!=null&&WebDomCanonical.same(without(x,"id"),without(y,"id")),"non-recommendation retained semantics or signature changed");
                if(!x.get("id").equals(y.get("id")))ordinal.put(new JSONObject().put("native_path",path).put("before_id",x.get("id")).put("after_id",y.get("id")));
            }
        }
        return new JSONObject().put("all_non_recommendation_records_equal_except_ordinal_id",true)
                .put("outside_recommendation_retained_changes",changedScope).put("ordinal_changes",ordinal)
                .put("recommendation_child_text_completeness_claimed",false).put("original_node_ref_rebound",false);
    }

    private static void requireTargetRoles(Map<String,JSONObject> nodes,String path,WebMiActionRegion region)throws Exception{
        JSONObject anchor=nodes.get(path);String current=region.currentPriceRaw.trim(),comparison=region.comparisonPriceRaw.trim();
        need((region.modelLabel+" "+current+" "+comparison).equals(anchor.get("description")),"native and DOM selected card labels differ");
        String[] paths={path+"/1",path+"/2/0",path+"/2/1"};
        String[] classes={"android.widget.TextView","android.widget.TextView","android.view.View"};
        String[] texts={TITLE,current," "+comparison};
        for(int i=0;i<paths.length;i++){
            JSONObject role=nodes.get(paths[i]);need(role!=null&&classes[i].equals(role.get("class"))&&texts[i].equals(role.get("text"))
                    &&role.getString("description").isEmpty()&&role.getBoolean("visible")&&role.getBoolean("enabled")
                    &&!role.getBoolean("editable")&&!role.getBoolean("password")&&!role.getBoolean("scrollable")
                    &&contains(intRect(anchor),intRect(role)),"original native title or price role differs from DOM card");
        }
    }

    private static String slideControl(Map<String,JSONObject> nodes,String widget,String label)throws Exception{
        String result=null;
        for(Map.Entry<String,JSONObject> e:nodes.entrySet()){
            JSONObject row=e.getValue();String path=e.getKey();
            if(!inside(path,widget)||!label.equals(row.get("aria_label")))continue;
            need(result==null&&"span".equals(row.get("tag"))&&"button".equals(row.get("role"))
                    &&row.getString("text").isEmpty()&&row.isNull("href_raw")&&row.isNull("href_resolved")
                    &&booleanText(row.get("aria_disabled"))&&!row.getBoolean("visible_in_viewport")
                    &&Arrays.equals(WebDomStability.rect(row.getJSONArray("rect_css_pixels")),new double[]{0,0,0,0}),
                    "exact hidden recommendation navigation label required");result=path;
        }
        need(result!=null,"missing recommendation navigation label");return result;
    }

    private static JSONArray compareClip(JSONObject before,JSONObject after,Map<String,JSONObject> a,Map<String,JSONObject> b,
            WebMiActionRegion region)throws Exception{
        JSONObject x=before.getJSONObject("clipping_context_observations"),y=after.getJSONObject("clipping_context_observations");
        need("hepta.raw-clip-context-observations.v1".equals(x.get("schema"))&&Boolean.TRUE.equals(x.get("complete"))
                &&Boolean.FALSE.equals(x.get("fully_clipped_inferred"))&&Boolean.FALSE.equals(x.get("closed_shadow_contents_inspected"))
                &&Boolean.FALSE.equals(x.get("grants_action_authority"))
                &&WebDomCanonical.same(without(x,"style_contexts"),without(y,"style_contexts")),"raw clipping metadata changed");
        JSONArray left=x.getJSONArray("style_contexts"),right=y.getJSONArray("style_contexts");
        need(left.length()==right.length()&&left.length()<=128,"complete raw clip context membership required");
        String menu=unique(a,"id","J_miniCartMenu");
        need(menu.equals(unique(b,"id","J_miniCartMenu"))&&WebDomCanonical.same(a.get(menu),b.get(menu)),"fixed mini-cart DOM identity changed");
        JSONArray changes=new JSONArray();Set<String> paths=new HashSet<String>();
        for(int i=0;i<left.length();i++){
            JSONObject s=left.getJSONObject(i),t=right.getJSONObject(i);String path=s.getString("path");
            need(paths.add(path)&&path.equals(t.get("path"))&&a.containsKey(path)&&b.containsKey(path),"clip style path membership changed");
            if(WebDomCanonical.same(s,t))continue;
            // This exact empty three-bar loading decoration is a read-only observation.
            // Its existing unknown clipping is never treated as proof that it is invisible.
            need(changes.length()==0&&path.equals(menu+"/0/0/0")&&!region.containsPath(path)&&!region.isAncestorPath(path),
                    "unknown outside style context changed");
            JSONObject da=a.get(path),db=b.get(path);
            need("div".equals(da.get("tag"))&&da.getString("text").isEmpty()&&da.getString("role").isEmpty()
                    &&da.isNull("href_raw")&&da.isNull("value")&&WebDomCanonical.same(without(da,"rect_css_pixels"),without(db,"rect_css_pixels")),
                    "loading decoration acquired semantic or input content");
            double[] ar=WebDomStability.rect(da.getJSONArray("rect_css_pixels")),br=WebDomStability.rect(db.getJSONArray("rect_css_pixels"));
            need(ar[0]==br[0]&&ar[2]==br[2]&&ar[2]-ar[0]==4&&ar[3]>ar[1]&&br[3]>br[1]
                    &&ar[3]-ar[1]<=32&&br[3]-br[1]<=32&&!region.overlaps(ar)&&!region.overlaps(br),
                    "loading bar horizontal placement, bounds or selected-region overlap changed");
            need(WebDomCanonical.same(without(s,"opacity","transform","pseudo_before","pseudo_after"),
                    without(t,"opacity","transform","pseudo_before","pseudo_after"))
                    &&"relative".equals(s.get("position"))&&"block".equals(s.get("display"))&&"visible".equals(s.get("visibility"))
                    &&s.getInt("element_child_count")==0&&Boolean.FALSE.equals(s.get("accessible_shadow_root_present"))
                    &&Boolean.FALSE.equals(s.get("closed_shadow_contents_inspected")),"loading decoration style or subtree changed");
            for(JSONObject style:new JSONObject[]{s,t})requireVerticalFade(style);
            for(String key:new String[]{"pseudo_before","pseudo_after"}){
                JSONObject p=s.getJSONObject(key),q=t.getJSONObject(key);
                need(WebDomCanonical.same(without(p,"opacity","transform"),without(q,"opacity","transform"))
                        &&"\"\"".equals(p.get("content"))&&"absolute".equals(p.get("position"))
                        &&"block".equals(p.get("display"))&&"visible".equals(p.get("visibility")),"loading pseudo content or placement changed");
                requireVerticalFade(p);requireVerticalFade(q);
            }
            changes.put(new JSONObject().put("dom_path",path).put("scope","fixed_empty_header_loading_bar_vertical_fade")
                    .put("before",s).put("after",t).put("fully_clipped_inferred",false));
        }
        return changes;
    }

    private static void requireVerticalFade(JSONObject style)throws Exception{
        String alpha=style.getString("opacity"),matrix=style.getString("transform");
        need(alpha.matches("(?:0(?:\\.[0-9]+)?|1(?:\\.0+)?)"),"bounded observed fade opacity required");
        java.util.regex.Matcher m=java.util.regex.Pattern.compile("matrix\\(1, 0, 0, ([0-9]+(?:\\.[0-9]+)?), 0, 0\\)").matcher(matrix);
        need(m.matches(),"loading decoration is no longer a pure CSS vertical scale");
        double scale=Double.parseDouble(m.group(1));need(scale>0&&scale<=1,"bounded nonexpanding vertical scale required");
    }


    /** Observed footer fields only: the parent remains a link; no unobserved CSS/listener or action proof. */
    private static final class FooterVisibilityObservation {
        private static final String LINK="https://webcert.cnmstl.net/cert/grade?sn=3af21034e35011eab3ea00163e068ceb";
        private static final Set<String> NODE_KEYS=new TreeSet<String>(Arrays.asList(
                "path","parent_path","tag","id","role","name","aria_label","href_raw","href_resolved","link_target",
                "item_scope","item_type","item_prop","hidden_attr","inert_attr","aria_hidden","aria_modal","aria_selected",
                "aria_checked","aria_pressed","text","value","disabled","aria_disabled","visible_in_viewport",
                "rect_css_pixels","iframe_contents_read"));
        private final String x,y,bx,ax,by,ay,proofRaw;
        private FooterVisibilityObservation(String x,String y,JSONObject beforeX,JSONObject afterX,
                JSONObject beforeY,JSONObject afterY,JSONObject proof)throws Exception{
            this.x=x;this.y=y;bx=WebDomCanonical.canonical(beforeX);ax=WebDomCanonical.canonical(afterX);
            by=WebDomCanonical.canonical(beforeY);ay=WebDomCanonical.canonical(afterY);proofRaw=WebDomCanonical.canonical(proof);
        }
        boolean explains(String path,JSONObject before,JSONObject after)throws Exception{
            if(path.equals(x))return bx.equals(WebDomCanonical.canonical(before))&&ax.equals(WebDomCanonical.canonical(after));
            if(path.equals(y))return by.equals(WebDomCanonical.canonical(before))&&ay.equals(WebDomCanonical.canonical(after));return false;
        }
        JSONObject evidence()throws Exception{return new JSONObject(proofRaw);}
        static FooterVisibilityObservation ifChanged(WebTaskPurpose purpose,JSONObject first,JSONObject last,
                JSONObject[] doms,WebMiActionRegion region)throws Exception{
            @SuppressWarnings({"unchecked","rawtypes"}) Map<String,JSONObject>[] all=new Map[4];
            for(int i=0;i<4;i++)all[i]=WebDomStability.index(doms[i]);
            String anchor=null;
            for(Map.Entry<String,JSONObject> entry:all[1].entrySet()){
                JSONObject n=entry.getValue();
                if("a".equals(n.opt("tag"))&&LINK.equals(n.opt("href_raw"))&&LINK.equals(n.opt("href_resolved"))){
                    if(anchor!=null)return null;anchor=entry.getKey();
                }
            }
            // Absent or unchanged recognized pair leaves the original strict comparison in charge.
            if(anchor==null)return null;
            String x=anchor+"/0",y=anchor+"/1";
            if(!all[1].containsKey(x)||!all[1].containsKey(y)||!all[2].containsKey(x)||!all[2].containsKey(y))return null;
            if(WebDomCanonical.same(all[1].get(x).opt("visible_in_viewport"),all[2].get(x).opt("visible_in_viewport"))
                    &&WebDomCanonical.same(all[1].get(y).opt("visible_in_viewport"),all[2].get(y).opt("visible_in_viewport")))return null;
            need(purpose.shopping!=null&&purpose.shopping.naturalReadOnlyIntent
                    &&!purpose.shopping.singleUnitRequested&&!purpose.shopping.specificationsRequested
                    &&WebMiActionRegion.POLICY.equals(purpose.sitePolicyId),
                    "footer visibility scope requires the original price-only observation purpose");
            Set<String> expectedChildren=new TreeSet<String>(Arrays.asList(x,y));
            java.util.List<String> footer=ancestors(all[0],anchor),card=ancestors(all[0],region.rootPath);
            Set<String> common=new HashSet<String>(footer);common.retainAll(card);
            java.util.List<String> footerBranch=exclusive(footer,common),cardBranch=exclusive(card,common);
            need(!footerBranch.isEmpty()&&!cardBranch.isEmpty()&&!inside(anchor,region.rootPath)&&!inside(region.rootPath,anchor),
                    "footer and selected card require separate observed branches");
            JSONObject referenceAnchor=all[0].get(anchor),referenceX=all[0].get(x),referenceY=all[0].get(y);
            need(referenceAnchor!=null&&referenceX!=null&&referenceY!=null,"all four original footer records required");
            double[] image=rect(referenceX,"rect_css_pixels"),parentBox=rect(referenceAnchor,"rect_css_pixels");
            need(positive(image)&&positive(parentBox)&&contains(parentBox,image)
                    &&WebDomCanonical.same(referenceX.get("rect_css_pixels"),referenceY.get("rect_css_pixels")),
                    "equal positive IMG rectangles contained by their actual link required");
            JSONArray states=new JSONArray();
            for(int i=0;i<4;i++){
                Map<String,JSONObject> nodes=all[i];need(nodes.keySet().equals(all[0].keySet()),"footer cannot explain DOM membership changes");
                Set<String> children=new TreeSet<String>();int links=0;
                for(Map.Entry<String,JSONObject> entry:nodes.entrySet()){
                    String path=entry.getKey();JSONObject value=entry.getValue();
                    if("a".equals(value.opt("tag"))&&LINK.equals(value.opt("href_raw"))&&LINK.equals(value.opt("href_resolved")))links++;
                    if(anchor.equals(entry.getValue().opt("parent_path")))children.add(path);
                    need(!path.startsWith(x+"/")&&!path.startsWith(y+"/"),"footer IMG must remain an observed leaf");
                }
                need(links==1&&children.equals(expectedChildren),"one exact link and exactly two direct footer IMG children required");
                for(String p:footer){
                    JSONObject n=nodes.get(p);need(n!=null&&WebDomCanonical.same(n,all[0].get(p)),"footer link or ancestor changed");
                    need(Boolean.FALSE.equals(n.get("hidden_attr"))&&Boolean.FALSE.equals(n.get("inert_attr"))
                            &&Boolean.FALSE.equals(n.get("disabled"))&&!"true".equals(n.get("aria_hidden"))
                            &&!"true".equals(n.get("aria_modal")),"hidden, inert or modal footer ancestry");
                }
                observedRecord(nodes.get(anchor),true);observedRecord(nodes.get(x),false);observedRecord(nodes.get(y),false);
                need(WebDomCanonical.same(without(nodes.get(x),"visible_in_viewport"),without(referenceX,"visible_in_viewport"))
                        &&WebDomCanonical.same(without(nodes.get(y),"visible_in_viewport"),without(referenceY,"visible_in_viewport")),
                        "footer IMG changed beyond the observed visibility boolean");
                boolean vx=nodes.get(x).getBoolean("visible_in_viewport"),vy=nodes.get(y).getBoolean("visible_in_viewport");
                need(vx!=vy,"exactly one observed footer IMG must be visible");states.put(new JSONArray().put(vx).put(vy));
                for(String f:footerBranch)for(String c:cardBranch)
                    need(!overlap(rect(nodes.get(f),"rect_css_pixels"),rect(nodes.get(c),"rect_css_pixels")),
                            "footer overlaps the selected card or its exclusive ancestor");
                for(Map.Entry<String,JSONObject> entry:nodes.entrySet()){
                    JSONObject n=entry.getValue();
                    if(region.containsPath(entry.getKey()))need(!overlap(image,rect(n,"rect_css_pixels")),"footer IMG overlaps selected-card content");
                    if(!entry.getKey().equals(anchor)&&observedControl(n))
                        need(!overlap(image,rect(n,"rect_css_pixels")),"footer IMG overlaps another observed control or link");
                }
                need(WebDomCanonical.same(doms[0].get("action_region_observations"),doms[i].get("action_region_observations")),
                        "selected card style, hit or overlay observations changed");
            }

            need(states.getJSONArray(0).toString().equals(states.getJSONArray(1).toString())
                    &&states.getJSONArray(2).toString().equals(states.getJSONArray(3).toString())
                    &&states.getJSONArray(0).getBoolean(0)!=states.getJSONArray(2).getBoolean(0),
                    "own-pairs must retain one state and the middle pair must exchange both booleans");
            JSONObject proof=new JSONObject().put("schema","hepta.mi-footer-observed-img-visibility.v1")
                    .put("purpose","readonly_price_observation_only").put("binding_sha256",WebDomCanonical.sha256(first.getJSONObject("binding")))
                    .put("first_before_sha256",first.get("before_dom_sha256")).put("first_after_sha256",first.get("dom_sha256"))
                    .put("last_before_sha256",last.get("before_dom_sha256")).put("last_after_sha256",last.get("dom_sha256"))
                    .put("anchor_dom_path",anchor).put("anchor_record",referenceAnchor).put("img_dom_paths",new JSONArray().put(x).put(y))
                    .put("four_observed_visibility_states",states).put("img_rect_css_pixels",referenceX.get("rect_css_pixels"))
                    .put("footer_ancestor_records_sha256",recordsSha(all[0],footer))
                    .put("selected_region_observations_sha256",WebDomCanonical.sha256(doms[0].getJSONObject("action_region_observations")))
                    .put("all_non_visibility_IMG_fields_equal",true).put("parent_link_and_ancestor_records_equal",true)
                    .put("exclusive_branches_and_other_controls_disjoint",true).put("parent_link_interactive",true)
                    .put("unobserved_css_or_listeners_proved",false).put("whole_page_pixel_visibility_proved",false)
                    .put("grants_action_authority",false).put("business_verified",false);
            return new FooterVisibilityObservation(x,y,all[1].get(x),all[2].get(x),all[1].get(y),all[2].get(y),proof);
        }
        private static void observedRecord(JSONObject node,boolean anchor)throws Exception{
            need(node!=null,"original footer record required");
            Set<String> keys=new TreeSet<String>();for(java.util.Iterator<String> it=node.keys();it.hasNext();)keys.add(it.next());
            need(keys.equals(NODE_KEYS)&&(anchor?"a":"img").equals(node.get("tag")),"exact observed footer record shape required");
            for(String k:new String[]{"id","role","name","aria_label","item_type","item_prop","aria_hidden","aria_modal",
                    "aria_selected","aria_checked","aria_pressed","text"})need("".equals(node.get(k)),"unexpected observed footer label/control field");
            for(String k:new String[]{"item_scope","hidden_attr","inert_attr","disabled","iframe_contents_read"})
                need(Boolean.FALSE.equals(node.get(k)),"unexpected observed footer state");
            for(String k:new String[]{"value","aria_disabled"})need(node.get(k)==JSONObject.NULL,"unexpected observed footer value");
            need(node.get("visible_in_viewport") instanceof Boolean,"actual observed visibility boolean required");
            if(anchor)need(LINK.equals(node.get("href_raw"))&&LINK.equals(node.get("href_resolved"))
                    &&"".equals(node.get("link_target"))&&Boolean.TRUE.equals(node.get("visible_in_viewport")),
                    "exact unchanged observed certificate link required");
            else for(String k:new String[]{"href_raw","href_resolved","link_target"})
                need(node.get(k)==JSONObject.NULL,"IMG acquired observed link semantics");
        }
        private static java.util.List<String> ancestors(Map<String,JSONObject> nodes,String start)throws Exception{
            java.util.List<String> paths=new java.util.ArrayList<String>();
            for(String p=start;!p.isEmpty();p=parent(p)){
                need(paths.size()<128&&nodes.containsKey(p),"complete bounded ancestor chain required");paths.add(p);
            }return paths;
        }
        private static java.util.List<String> exclusive(java.util.List<String> paths,Set<String> common){
            java.util.List<String> out=new java.util.ArrayList<String>();
            for(String p:paths){if(common.contains(p))break;out.add(p);}return out;
        }
        private static String recordsSha(Map<String,JSONObject> nodes,java.util.List<String> paths)throws Exception{
            JSONArray values=new JSONArray();for(String p:paths)values.put(nodes.get(p));
            return WebEvidenceJson.sha(WebDomCanonical.canonical(values));
        }
        private static boolean observedControl(JSONObject n)throws Exception{
            return oneOf(n.getString("tag"),"a","input","textarea","select","button","option","label","summary","details",
                    "iframe","frame","object","embed","svg","canvas","dialog")
                    ||oneOf(n.getString("role").toLowerCase(java.util.Locale.ROOT),"button","link","menuitem","menuitemcheckbox","menuitemradio","checkbox","radio",
                    "textbox","combobox","listbox","option","slider","spinbutton","switch","tab","treeitem","dialog","alertdialog")
                    ||n.get("href_raw")!=JSONObject.NULL||n.get("href_resolved")!=JSONObject.NULL||n.get("value")!=JSONObject.NULL;
        }
        private static boolean positive(double[] a){return a[2]>a[0]&&a[3]>a[1];}
        private static boolean contains(double[] a,double[] b){return b[0]>=a[0]&&b[1]>=a[1]&&b[2]<=a[2]&&b[3]<=a[3];}
        private static boolean overlap(double[] a,double[] b){return positive(a)&&positive(b)
                &&a[0]<b[2]&&b[0]<a[2]&&a[1]<b[3]&&b[1]<a[3];}
    }

    private static void requireDomCounts(JSONObject dom,Map<String,JSONObject> nodes)throws Exception{
        need(dom.getInt("visited")==nodes.size(),"DOM visited count differs from complete retained records");
        long units=0;
        // Exact bounded() accounting in the pinned helper6 readonly_dom.js asset.
        // aria_disabled is raw getAttribute(), while viewport_meta_content is bounded().
        for(JSONObject row:nodes.values())for(String key:new String[]{"id","role","name","aria_label","href_raw","href_resolved","link_target",
                "item_type","item_prop","aria_hidden","aria_modal","aria_selected","aria_checked","aria_pressed","text","value"}){
            Object value=row.get(key);if(value instanceof String)units+=((String)value).length();
        }
        Object meta=dom.get("viewport_meta_content");
        need(meta==JSONObject.NULL||meta instanceof String&&((String)meta).length()<=4096,"bounded observed viewport meta text required");
        if(meta instanceof String)units+=((String)meta).length();
        need((dom.get("text_utf16_units") instanceof Integer||dom.get("text_utf16_units") instanceof Long)
                &&units==dom.getLong("text_utf16_units")&&units<=65536,"independently recomputed complete DOM text count differs");
    }

    static void requireCompleteObservation(JSONObject frame,JSONArray nativeRows)throws Exception{
        need(WebEvidenceProtocol.HELPER_PACKAGE.equals(frame.get("package"))&&Boolean.FALSE.equals(frame.get("nodes_truncated"))
                &&Boolean.FALSE.equals(frame.get("ime_visible"))&&!frame.getString("observation_id").isEmpty(),"complete helper frame with hidden IME required");
        JSONObject window=frame.getJSONObject("window"),bg=frame.getJSONObject("background_session"),c=frame.getJSONObject("collection");
        need("observed".equals(window.get("metadata_status"))&&window.getInt("window_id")==frame.getInt("window_id")
                &&window.getInt("display_id")>0&&window.getInt("type")==1&&Boolean.FALSE.equals(window.get("root_class_truncated"))
                &&Boolean.FALSE.equals(window.get("title_truncated"))&&"background".equals(bg.get("mode"))
                &&bg.getInt("display_id")==window.getInt("display_id")&&WebEvidenceProtocol.HELPER_PACKAGE.equals(bg.get("bootstrap_package"))
                &&bg.getJSONArray("allowed_packages").length()==1&&WebEvidenceProtocol.HELPER_PACKAGE.equals(bg.getJSONArray("allowed_packages").get(0)),
                "exact native background window required");
        need("hepta.observation-collection.v1".equals(c.get("schema"))&&"same_observed_accessibility_traversal".equals(c.get("source"))
                &&nativeRows!=null&&nativeRows.length()==c.getInt("visited_nodes")&&frame.getJSONArray("nodes").length()==c.getInt("retained_nodes")
                &&c.getJSONArray("truncation_reasons").length()==0,"same complete native traversal counters required");
        for(String key:new String[]{"pending_nodes_at_stop","child_slots_omitted_by_traversal_limit","nodes_omitted_by_node_limit","nodes_omitted_by_text_limit"})
            need(c.getLong(key)==0,"omitted native traversal records");
        long text=0;JSONArray rows=frame.getJSONArray("nodes");
        for(int i=0;i<rows.length();i++){JSONObject row=rows.getJSONObject(i);text+=row.optString("text","").length()+row.optString("description","").length()+row.optString("child_text","").length();}
        need(text==c.getLong("retained_text_utf16")&&rows.length()<=c.getInt("node_limit")&&text<c.getLong("text_utf16_exclusive_limit"),
                "retained text budget differs from original rows");
        JSONObject root=nativeNodes(nativeRows).get("0");
        need(root.getInt("window_id")==frame.getInt("window_id")&&root.get("class").equals(window.get("root_class"))
                &&WebDomCanonical.same(root.getJSONArray("bounds"),window.getJSONArray("root_bounds")),"native root differs from observed window");
    }

    private static boolean booleanText(Object v){return "true".equals(v)||"false".equals(v);}
    private static boolean oneOf(String value,String...choices){for(String choice:choices)if(choice.equals(value))return true;return false;}
    private static boolean overlap(int[] a,int[] b){return a[0]<b[2]&&b[0]<a[2]&&a[1]<b[3]&&b[1]<a[3];}
    private static Map<String,JSONObject> nativeNodes(JSONArray nodes)throws Exception{
        need(nodes!=null&&nodes.length()>0&&nodes.length()<=MAX_NATIVE_NODES,"complete bounded native snapshot required");
        Map<String,JSONObject> out=new TreeMap<String,JSONObject>();
        for(int i=0;i<nodes.length();i++){
            JSONObject n=nodes.getJSONObject(i);String path=n.getString("path");
            need(path.matches("0(?:/(?:0|[1-9][0-9]{0,5})){0,127}")
                    &&WebEvidenceProtocol.HELPER_PACKAGE.equals(n.get("package"))
                    &&n.getInt("children")>=0&&n.getInt("children")<=MAX_NATIVE_NODES
                    &&out.put(path,n)==null,"invalid native path/package/children");
            int[] bounds=intRect(n);
            need(!n.getBoolean("visible")||bounds[0]<bounds[2]&&bounds[1]<bounds[3],"visible native bounds missing");
        }
        need(out.containsKey("0")&&out.get("0").getInt("window_id")>=0,"actual native root missing");
        for(Map.Entry<String,JSONObject> e:out.entrySet()){
            String path=e.getKey();JSONObject n=e.getValue();
            need(n.getInt("window_id")==out.get("0").getInt("window_id"),"mixed native windows");
            if(!path.equals("0")){JSONObject p=out.get(parent(path));need(p!=null
                    &&Integer.parseInt(path.substring(path.lastIndexOf('/')+1))<p.getInt("children")
                    &&p.getString("class").equals(n.getString("parent_class")),"native ancestor missing");}
            for(int i=0;i<n.getInt("children");i++)need(out.containsKey(path+"/"+i),"native traversal omitted a child");
        }
        return out;
    }

    private static Map<String,JSONObject> retained(JSONArray nodes)throws Exception{
        need(nodes!=null&&nodes.length()>0&&nodes.length()<=MAX_NATIVE_NODES,"bounded retained native rows");
        Map<String,JSONObject> out=new TreeMap<String,JSONObject>();Set<String> ids=new HashSet<String>();
        for(int i=0;i<nodes.length();i++){
            JSONObject n=nodes.getJSONObject(i);String path=n.getJSONObject("native_tree_position").getString("path");
            need(path.matches("0(?:/(?:0|[1-9][0-9]{0,5})){0,127}")
                    &&ids.add(n.getString("id"))&&out.put(path,n)==null,"duplicate retained native identity");
        }return out;
    }

    private static String ancestorClass(Map<String,JSONObject> nodes,String path,String clazz)throws Exception{
        String p=parent(path);
        while(!p.isEmpty()){JSONObject n=nodes.get(p);need(n!=null,"native ancestor missing");
            if(clazz.equals(n.get("class")))return p;p=parent(p);}
        return null;
    }

    private static JSONObject without(JSONObject value,String...keys)throws Exception{
        return WebDomCanonical.without(value,keys);
    }

    private static String unique(Map<String,JSONObject> nodes,String key,String value)throws Exception{
        String found=null;for(Map.Entry<String,JSONObject> e:nodes.entrySet())if(value.equals(e.getValue().opt(key))){
            need(found==null,"ambiguous "+key);found=e.getKey();
        }need(found!=null,"missing "+key+" "+value);return found;
    }

    private static double[] rect(JSONObject n,String field)throws Exception{
        JSONArray r=n.getJSONArray(field);need(r.length()==4,"rectangle shape");double[] out=new double[4];
        for(int i=0;i<4;i++){Object value=r.get(i);need(value instanceof Number,"numeric rectangle required");
            out[i]=((Number)value).doubleValue();need(!Double.isNaN(out[i])&&!Double.isInfinite(out[i]),"finite rectangle required");}
        need(out[2]>=out[0]&&out[3]>=out[1],"ordered rectangle required");return out;
    }

    private static int[] intRect(JSONObject n)throws Exception{
        double[] d=rect(n,"bounds");int[] out=new int[4];
        for(int i=0;i<4;i++){need(d[i]>=Integer.MIN_VALUE&&d[i]<=Integer.MAX_VALUE&&d[i]==Math.rint(d[i]),"native integer bounds required");out[i]=(int)d[i];}
        return out;
    }

    private static boolean contains(int[] a,int[] b){return b[0]>=a[0]&&b[1]>=a[1]&&b[2]<=a[2]&&b[3]<=a[3];}

    private static String parent(String path){int i=path.lastIndexOf('/');return i<0?"":path.substring(0,i);}

    private static boolean inside(String path,String ancestor){return path.equals(ancestor)||path.startsWith(ancestor+"/");}

    private static void need(boolean condition,String message){if(!condition)throw new IllegalArgumentException(message);}
}
