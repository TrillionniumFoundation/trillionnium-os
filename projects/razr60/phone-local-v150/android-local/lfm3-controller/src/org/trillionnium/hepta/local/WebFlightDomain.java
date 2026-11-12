package org.trillionnium.hepta.local;

import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.local.web.WebFlightGoal;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Current-page restriction, intersected with actual AX capabilities and original OWNER authority. */
final class WebFlightDomain {
    static final String SCHEMA="hepta.csair-current-action-domain.v1";
    final String taskId,ownerSha,authorizationSha,observationId,stateSha,generation,instance,url,phase,pageKey;
    final int displayId,windowId;
    final long epoch;
    final Set<String> clickIds;
    final Map<String,String> editValues;
    private final Map<String,Object> proof;
    private WebFlightDomain(String task,TaskAuthorization.Gate auth,PhoneObservation frame,WebEvidenceReceipt receipt,
                            String phase,String pageKey,Set<String> clicks,Map<String,String> edits,Map<String,Object> proof){
        taskId=task;ownerSha=auth.authorization.instructionSha256;authorizationSha=auth.authorization.sha256;
        observationId=frame.id;stateSha=frame.treeSha256;generation=frame.backgroundGeneration;displayId=frame.windowMetadata.displayId;
        windowId=frame.windowId;instance=receipt.instance;epoch=receipt.epoch;url=receipt.url;this.phase=phase;this.pageKey=pageKey;
        clickIds=Collections.unmodifiableSet(new HashSet<String>(clicks));editValues=Collections.unmodifiableMap(new LinkedHashMap<String,String>(edits));
        this.proof=Collections.unmodifiableMap(new LinkedHashMap<String,Object>(proof));
    }
    static WebFlightDomain observed(String task,WebFlightGoal goal,TaskAuthorization.Gate auth,PhoneObservation frame,
                                   WebEvidenceReceipt receipt,String bindingSha)throws Exception{
        need(goal!=null&&auth!=null&&task.equals(auth.taskId)&&goal.ownerSha256.equals(auth.authorization.instructionSha256),"same immutable flight owner required");
        need(frame!=null&&WebEvidenceProtocol.HELPER_PACKAGE.equals(frame.packageName)&&!frame.nodesTruncated
                &&frame.windowMetadata!=null&&"observed".equals(frame.windowMetadata.status)
                &&Integer.valueOf(1).equals(frame.windowMetadata.type)&&frame.windowMetadata.displayId!=null
                &&frame.windowMetadata.displayId==receipt.displayId&&frame.windowId==receipt.windowId
                &&frame.backgroundGeneration!=null&&bindingSha.equals(receipt.bindingSha),"same current AX/DOM application window required");
        JSONObject dom=receipt.dom(),capture=receipt.capture();need(dom!=null&&capture!=null,"bound DOM capture required");
        JSONArray entries=dom.getJSONArray("nodes");need(entries.length()>0&&entries.length()<=1024,"bounded actual DOM nodes required");
        Set<String> paths=new HashSet<String>();Map<String,JSONObject> byPath=new LinkedHashMap<String,JSONObject>();
        for(int i=0;i<entries.length();i++){
            JSONObject node=entries.getJSONObject(i);String path=node.getString("path");
            need(path.matches("0(?:/[0-9]{1,5}){0,32}")&&paths.add(path),"unique bounded DOM path");
            byPath.put(path,node);
        }
        for(JSONObject node:byPath.values()){
            Object parent=node.get("parent_path");
            need(parent==JSONObject.NULL&&node.getString("path").equals("0")||parent instanceof String
                    &&byPath.containsKey(parent)&&node.getString("path").substring(0,node.getString("path").lastIndexOf('/')).equals(parent),"actual DOM parent path required");
        }
        Map<String,Object> evidence=new LinkedHashMap<String,Object>();evidence.put("schema",SCHEMA);
        evidence.put("task_id",task);evidence.put("owner_sha256",goal.ownerSha256);evidence.put("contract_sha256",goal.contractSha256);
        evidence.put("authorization_sha256",auth.authorization.sha256);evidence.put("observation_id",frame.id);
        evidence.put("observation_state_sha256",frame.treeSha256);evidence.put("app_tree_sha256",frame.state.appTreeSha256);
        evidence.put("binding_sha256",bindingSha);evidence.put("webview_instance",receipt.instance);evidence.put("navigation_epoch",receipt.epoch);
        evidence.put("display_id",receipt.displayId);evidence.put("window_id",receipt.windowId);evidence.put("background_generation",frame.backgroundGeneration);
        evidence.put("current_native_url",receipt.url);evidence.put("dom_sha256",receipt.domSha);
        evidence.put("query_executed",false);evidence.put("business_verified",false);evidence.put("grants_tool_authority",false);
        Set<String> clicks=new HashSet<String>();Map<String,String> edits=new LinkedHashMap<String,String>();
        String phase="unsupported_current_page",pageKey="unavailable";
        List<Map<String,Object>> capabilities=new ArrayList<Map<String,Object>>();
        WebNativeGeometry geometry=WebNativeGeometry.read(capture,dom,receipt.displayId,receipt.windowId);
        evidence.put("native_geometry",geometry==null?null:geometry.evidence());
        evidence.put("css_to_screen_mapping_verified",false);
        evidence.put("css_to_screen_mapping_used",false);
        evidence.put("dom_visible_is_screen_visibility_proof",false);
        // The source of every dispatched target remains the real NodeRef in this
        // AX frame. A DOM path, CSS rectangle or device pixel ratio is never a target.
        List<JSONObject> booking=new ArrayList<JSONObject>();
        for(JSONObject node:byPath.values())if("booking".equals(node.optString("id"))
                &&"div".equals(node.optString("tag"))&&visibleAncestors(node,byPath))booking.add(node);
        if(booking.size()==1&&"https://m.csair.com/".equals(receipt.url)){
            JSONObject container=booking.get(0);String prefix=container.getString("path")+"/";
            List<JSONObject> labels=new ArrayList<JSONObject>();
            for(JSONObject node:byPath.values())if(node.getString("path").startsWith(prefix)
                    &&"span".equals(node.optString("tag"))&&"机票预订".equals(node.optString("text"))
                    &&visibleAncestors(node,byPath))labels.add(node);
            if(labels.size()==1){
                phase=geometry==null?"official_home_geometry_pending":"official_home";
                evidence.put("observed_entry_dom_path",labels.get(0).getString("path"));
                evidence.put("observed_entry_parent_dom_path",container.getString("path"));
                if(geometry!=null){
                    PhoneObservation.Node target=uniqueNative(frame,geometry,"","android.widget.Button",
                            "机票预订按钮，点按两次即可激活",
                            Collections.singletonList("机票预订按钮，点按两次即可激活"),false);
                    if(target!=null)addCapability(clicks,capabilities,target,labels.get(0).getString("path"),
                            "booking","机票预订","open_public_booking_form");
                }
            }
        }
        java.net.URI page=new java.net.URI(receipt.url);
        if("/booking_new/".equals(page.getPath())){
            CsairFlightForm form=CsairFlightForm.read(dom);
            if(form!=null){
                // Require the form root's complete visible ancestry as well as
                // the provider's field-to-tab ancestry. Hidden sibling IDs remain data.
                need(visibleAncestors(byPath.get(form.formPath),byPath),"form ancestor is not currently visible");
                phase=geometry==null?"official_query_form_geometry_pending":"official_query_form";
                evidence.put("observed_query_form",form.evidence());
                if(geometry!=null){
                    addFormControl(frame,geometry,form.departure,"choose_departure_city",clicks,capabilities);
                    addFormControl(frame,geometry,form.arrival,"choose_arrival_city",clicks,capabilities);
                    addFormControl(frame,geometry,form.departureDate,"choose_departure_date",clicks,capabilities);
                }
                // No query capability is minted from placeholders or a month/day
                // without a year. Real city/date selection and results are separate proofs.
                evidence.put("query_control_withheld",true);
                evidence.put("query_control_withheld_reason","actual OWNER cities and complete date not yet proven");
            }
        }
        JSONObject semantic=new JSONObject().put("native_url",receipt.url).put("instance",receipt.instance)
                .put("epoch",receipt.epoch).put("phase",phase)
                .put("native_geometry_sha256",geometry==null?JSONObject.NULL:geometry.fingerprint)
                .put("capabilities",new JSONArray(capabilities));
        if(evidence.containsKey("observed_query_form"))semantic.put("form",new JSONObject((Map<?,?>)evidence.get("observed_query_form")));
        pageKey=WebEvidenceJson.sha(semantic.toString());
        evidence.put("capabilities_withheld_reason",geometry==null?"actual native/visual-viewport bracket absent":
                clicks.isEmpty()?"no unique visible native AX target matches the actual page semantics":null);
        evidence.put("phase",phase);evidence.put("allowed_click_ids",new ArrayList<String>(clicks));
        evidence.put("native_ax_capabilities",capabilities);
        evidence.put("semantic_region_sha256",pageKey);evidence.put("flight_result_inferred",false);
        evidence.put("next_goal",clicks.isEmpty()?"当前页面没有已验证的只读控件；等待加载或报告未完成。":
                "official_home".equals(phase)?"选择实际『机票预订』入口，再观察公开查询表单。":
                "只用本帧原生节点选择出发城市、到达城市或出发日期；查询仍等待完整目标值验证。");
        evidence.put("missing",java.util.Arrays.asList("actual_city_selection_provider","actual_complete_date_provider",
                "model_bound_public_query_dispatch","actual_same_record_flight_result"));
        return new WebFlightDomain(task,auth,frame,receipt,phase,pageKey,clicks,edits,evidence);
    }
    static WebFlightDomain waiting(String task,WebFlightGoal goal,TaskAuthorization.Gate auth,PhoneObservation frame,
                                   WebEvidenceReceipt receipt,String bindingSha)throws Exception{
        need(goal!=null&&auth!=null&&task.equals(auth.taskId)&&goal.ownerSha256.equals(auth.authorization.instructionSha256),
                "same immutable flight owner required for metadata wait");
        need(("unavailable".equals(receipt.status)||"state_changed".equals(receipt.status))&&!receipt.cleanupKnown
                &&frame!=null&&WebEvidenceProtocol.HELPER_PACKAGE.equals(frame.packageName)
                &&frame.windowMetadata!=null&&"observed".equals(frame.windowMetadata.status)
                &&Integer.valueOf(1).equals(frame.windowMetadata.type)&&frame.windowMetadata.displayId!=null
                &&frame.windowMetadata.displayId==receipt.displayId&&frame.windowId==receipt.windowId
                &&frame.backgroundGeneration!=null&&bindingSha.equals(receipt.bindingSha),"same live AX/helper wait domain");
        Map<String,Object> evidence=new LinkedHashMap<String,Object>();
        evidence.put("schema",SCHEMA);evidence.put("task_id",task);evidence.put("owner_sha256",goal.ownerSha256);
        evidence.put("contract_sha256",goal.contractSha256);evidence.put("authorization_sha256",auth.authorization.sha256);
        evidence.put("observation_id",frame.id);evidence.put("observation_state_sha256",frame.treeSha256);
        evidence.put("binding_sha256",bindingSha);evidence.put("background_generation",frame.backgroundGeneration);
        evidence.put("display_id",receipt.displayId);evidence.put("window_id",receipt.windowId);
        evidence.put("webview_instance",receipt.instance);evidence.put("navigation_epoch",receipt.epoch);
        evidence.put("phase","official_page_capture_pending");evidence.put("capture_status",receipt.status);
        evidence.put("capture_callback",receipt.callback());evidence.put("allowed_click_ids",Collections.emptyList());
        evidence.put("native_ax_capabilities",Collections.emptyList());evidence.put("grants_tool_authority",false);
        evidence.put("query_executed",false);evidence.put("business_verified",false);evidence.put("cleanup_known",false);
        evidence.put("next_goal","官网证据尚未稳定；只可等待或报告未完成，不能点击、输入或宣称查询成功。");
        String key=WebEvidenceJson.sha(receipt.callback().toString()+"\\n"+frame.id);
        return new WebFlightDomain(task,auth,frame,receipt,"official_page_capture_pending",key,
                Collections.<String>emptySet(),Collections.<String,String>emptyMap(),evidence);
    }
    Map<String,Object> evidence(){return new LinkedHashMap<String,Object>(proof);}
    Set<String> clicks(Set<String> original){Set<String> out=new HashSet<String>(original);out.retainAll(clickIds);return out;}
    Set<String> edits(Set<String> original){Set<String> out=new HashSet<String>(original);out.retainAll(editValues.keySet());return out;}
    <T> Map<String,T> noNodeActions(Map<String,T> original){return Collections.emptyMap();}
    Set<String> openPackages(Set<String> original){return Collections.emptySet();}
    Set<String> toolMask(Set<String> original){
        Set<String> allowed=new HashSet<String>(java.util.Arrays.asList("done","wait"));
        if(!clickIds.isEmpty())allowed.add("click");if(!editValues.isEmpty())allowed.add("type");
        if(original!=null)allowed.retainAll(original);return allowed;
    }
    void requireCurrent(ActionDecision action){
        need(action!=null&&observationId.equals(action.observationId)&&WebEvidenceProtocol.HELPER_PACKAGE.equals(action.packageName),"web action belongs to another frame");
        if("done".equals(action.action)){need(!"success".equals(action.status),"actual flight results have not been independently verified");return;}
        if("wait".equals(action.action))return;
        if("click".equals(action.action)){need(action.nodeId!=null&&clickIds.contains(action.nodeId),"web click is not a proved current public navigation target");return;}
        if("type".equals(action.action)){need(action.nodeId!=null&&editValues.containsKey(action.nodeId)&&editValues.get(action.nodeId).equals(action.text),"web input differs from exact OWNER field");return;}
        throw new IllegalArgumentException("当前官网页面没有该只读操作的真实证据");
    }
    private static void addFormControl(PhoneObservation frame,WebNativeGeometry geometry,CsairFlightForm.Control control,
                                       String purpose,Set<String> clicks,List<Map<String,Object>> capabilities)throws Exception{
        if(control.disabled)return;
        PhoneObservation.Node node=uniqueNative(frame,geometry,control.id,"android.view.View",
                control.requiredLabel,control.visibleTexts,true);
        if(node!=null)addCapability(clicks,capabilities,node,control.path,control.id,control.requiredLabel,purpose);
    }
    private static void addCapability(Set<String> clicks,List<Map<String,Object>> capabilities,PhoneObservation.Node node,
                                      String domPath,String domId,String label,String purpose){
        need(clicks.add(node.id),"one native AX node cannot stand for two DOM controls");
        Map<String,Object> value=new LinkedHashMap<String,Object>();
        value.put("node_id",node.id);value.put("node_app_tree_sha256",node.observedAppTreeSignature);
        value.put("native_view_id",node.viewId);value.put("native_class",node.className);
        value.put("native_bounds",java.util.Arrays.asList(node.bounds.left,node.bounds.top,node.bounds.right,node.bounds.bottom));
        value.put("native_label",node.label());value.put("dom_path",domPath);value.put("dom_id",domId);
        value.put("expected_control_label",label);value.put("purpose",purpose);
        value.put("target_source","same_frame_native_accessibility_node_id");
        value.put("dom_rect_used_as_target",false);value.put("child_label_sources_complete",node.childText.sourcesComplete);
        capabilities.add(value);
    }
    private static PhoneObservation.Node uniqueNative(PhoneObservation frame,WebNativeGeometry geometry,
            String resourceId,String nativeClass,String label,List<String> knownTexts,boolean derivedAllowed)throws Exception{
        List<PhoneObservation.Node> candidates=new ArrayList<PhoneObservation.Node>();
        for(PhoneObservation.Node node:frame.nodes){
            boolean sameId=resourceId.isEmpty()?node.viewId.isEmpty()&&label.equals(node.label()):resourceId.equals(node.viewId);
            if(sameId)candidates.add(node);
        }
        // Count first, before state filtering: a disabled or otherwise invalid
        // duplicate does not silently disappear to create apparent uniqueness.
        if(candidates.size()!=1)return null;
        PhoneObservation.Node node=candidates.get(0);
        if(!WebEvidenceProtocol.HELPER_PACKAGE.equals(node.packageName)||!nativeClass.equals(node.className)
                ||!node.clickable||!node.enabled||node.editable||node.password||node.scrollable
                ||node.observedAppTreeSignature==null||!node.observedAppTreeSignature.matches("[0-9a-f]{64}")
                ||!geometry.contains(node.bounds.left,node.bounds.top,node.bounds.right,node.bounds.bottom)
                ||!inside(frame.windowMetadata.rootBounds(),node)||!inside(frame.windowMetadata.windowBounds(),node)
                ||node.bounds.left<0||node.bounds.top<0||node.bounds.right>frame.width||node.bounds.bottom>frame.height)return null;
        String own=node.text.isEmpty()?node.description:node.text;
        if(!own.isEmpty())return label.equals(own)?node:null;
        if(!derivedAllowed)return null;
        ObservedChildText.Result child=node.childText;
        if(!"derived".equals(child.status)||child.truncated||child.sources.isEmpty()
                ||!child.rootSignature.matches("[0-9a-f]{64}")
                ||!child.bind(child.rootSignature).equals(node.observedAppTreeSignature))return null;
        Set<String> hashes=new HashSet<String>();for(String value:knownTexts)hashes.add(WebEvidenceJson.sha(value));
        boolean required=false;
        for(ObservedChildText.Source source:child.sources){
            if(!source.descendantPath.matches("[0-9]+(?:/[0-9]+){0,3}")
                    ||!("text".equals(source.property)||"description".equals(source.property))
                    ||source.nodeSignature==null||!source.nodeSignature.matches("[0-9a-f]{64}")
                    ||!hashes.contains(source.textSha256))return null;
            if(WebEvidenceJson.sha(label).equals(source.textSha256))required=true;
        }
        // The real collector de-duplicates identical visible strings. Its
        // sourcesComplete=false for such duplicates is retained in the proof;
        // it is not a claim that all field values have been read.
        return required?node:null;
    }
    private static boolean inside(int[] bounds,PhoneObservation.Node node){
        return bounds!=null&&bounds.length==4&&bounds[0]<=node.bounds.left&&bounds[1]<=node.bounds.top
                &&node.bounds.right<=bounds[2]&&node.bounds.bottom<=bounds[3];
    }
    private static boolean visibleAncestors(JSONObject node,Map<String,JSONObject> byPath)throws Exception{
        if(node==null)return false;
        while(true){
            if(!Boolean.TRUE.equals(node.get("visible_in_viewport")))return false;
            Object parent=node.get("parent_path");
            if(parent==JSONObject.NULL)return "0".equals(node.getString("path"));
            if(!(parent instanceof String)||(node=byPath.get(parent))==null)return false;
        }
    }
    private static double finite(Object value){
        need(value instanceof Number,"actual numeric DOM geometry required");double n=((Number)value).doubleValue();
        need(!Double.isNaN(n)&&!Double.isInfinite(n),"finite DOM geometry required");return n;
    }
    private static void need(boolean ok,String why){WebEvidenceJson.need(ok,why);}
}
