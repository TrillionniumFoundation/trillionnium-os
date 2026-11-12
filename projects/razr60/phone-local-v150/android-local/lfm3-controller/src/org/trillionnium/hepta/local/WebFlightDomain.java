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
    final WebFlightGoal goal;
    final String contractSha,bindingSha,domSha;
    final long captureStarted,captureEnded;
    final CsairFlightForm form;
    final Map<String,Map<String,Object>> nativeReadbacks;
    final Map<String,Object> queryCandidate;
    private final List<Map<String,Object>> capabilities;
    private final WebFlightProgress progress;
    private final Map<String,Object> proof;
    private WebFlightDomain(String task,WebFlightGoal goal,TaskAuthorization.Gate auth,PhoneObservation frame,WebEvidenceReceipt receipt,
                            String phase,String pageKey,Set<String> clicks,Map<String,String> edits,Map<String,Object> proof,
                            CsairFlightForm form,Map<String,Map<String,Object>> readbacks,Map<String,Object> query,
                            List<Map<String,Object>> capabilities){
        taskId=task;ownerSha=auth.authorization.instructionSha256;authorizationSha=auth.authorization.sha256;
        observationId=frame.id;stateSha=frame.treeSha256;generation=frame.backgroundGeneration;displayId=frame.windowMetadata.displayId;
        windowId=frame.windowId;instance=receipt.instance;epoch=receipt.epoch;url=receipt.url;this.phase=phase;this.pageKey=pageKey;
        clickIds=Collections.unmodifiableSet(new HashSet<String>(clicks));editValues=Collections.unmodifiableMap(new LinkedHashMap<String,String>(edits));
        this.goal=goal;contractSha=goal.contractSha256;bindingSha=receipt.bindingSha;domSha=receipt.domSha;
        captureStarted=receipt.started;captureEnded=receipt.ended;this.form=form;
        nativeReadbacks=Collections.unmodifiableMap(new LinkedHashMap<String,Map<String,Object>>(readbacks));
        queryCandidate=query==null?null:Collections.unmodifiableMap(new LinkedHashMap<String,Object>(query));
        this.capabilities=Collections.unmodifiableList(new ArrayList<Map<String,Object>>(capabilities));progress=null;
        this.proof=Collections.unmodifiableMap(new LinkedHashMap<String,Object>(proof));
    }
    private WebFlightDomain(WebFlightDomain original,WebFlightProgress progress)throws Exception{
        taskId=original.taskId;ownerSha=original.ownerSha;authorizationSha=original.authorizationSha;
        observationId=original.observationId;stateSha=original.stateSha;generation=original.generation;
        instance=original.instance;url=original.url;displayId=original.displayId;windowId=original.windowId;epoch=original.epoch;
        goal=original.goal;contractSha=original.contractSha;bindingSha=original.bindingSha;domSha=original.domSha;
        captureStarted=original.captureStarted;captureEnded=original.captureEnded;form=original.form;
        nativeReadbacks=original.nativeReadbacks;queryCandidate=original.queryCandidate;this.progress=progress;
        need(progress.matches(original),"same flight progression scope required");
        List<Map<String,Object>> targets=new ArrayList<Map<String,Object>>();
        Set<String> clicks=new HashSet<String>();
        boolean submitted=progress.queryAttempted(),pending=progress.selectionPending(),ready=progress.queryReady(original);
        if(!submitted&&!pending){
            for(Map<String,Object> capability:original.capabilities){
                String purpose=(String)capability.get("purpose");boolean keep=true;
                if("choose_departure_city".equals(purpose))keep=!progress.selectionConfirmed("departure",original);
                if("choose_arrival_city".equals(purpose))keep=!progress.selectionConfirmed("arrival",original);
                if("choose_departure_date".equals(purpose))keep=progress.hasConfirmedCities()
                        &&!progress.selectionConfirmed("date",original);
                if("choose_departure_date_from_immutable_owner".equals(purpose))keep=progress.hasConfirmedCities();
                if(keep&&!ready){targets.add(capability);clicks.add((String)capability.get("node_id"));}
            }
            if(ready){targets.add(queryCandidate);clicks.add((String)queryCandidate.get("node_id"));}
        }
        phase=submitted?(progress.queryDispatched()?"official_query_result_pending":"official_query_attempt_unconfirmed"):pending?"official_selection_readback_pending":
                ready?"official_query_ready":original.phase;
        capabilities=Collections.unmodifiableList(targets);clickIds=Collections.unmodifiableSet(clicks);
        editValues=Collections.emptyMap();
        Map<String,Object> out=new LinkedHashMap<String,Object>(original.proof);
        Map<String,Object> actual=progress.evidence(original);
        out.put("model_selection_and_query_progress",actual);out.put("phase",phase);
        out.put("native_ax_capabilities",capabilities);out.put("allowed_click_ids",new ArrayList<String>(clickIds));
        out.put("query_control_withheld",!ready);out.put("query_attempted",submitted);
        out.put("query_executed",progress.queryDispatched());out.put("server_query_completed",false);
        out.put("result_ready_for_completion_gate",false);out.put("query_retry_permitted",false);
        out.put("query_control_withheld_reason",ready?null:submitted?"the one query attempt is consumed":
                pending?"actual selection is awaiting fresh form/native readback":"same-lease city and complete-date confirmations are incomplete");
        out.put("next_goal",submitted?"查询尝试已经记录；只读观察真实结果，不能重复查询、点击航班预订或声称已经查到航班。":
                pending?"上次城市或日期点击等待实际表单读回；只可等待，不要重复点击。":
                ready?"出发城市、到达城市、完整日期和人数已由本任务真实操作及当前表单核对；仅点击一次本帧『查询』，随后等待真实结果。":
                progress.hasConfirmedCities()?original.proof.get("next_goal"):
                "先选择并读回出发城市与到达城市，再选择完整年月日；不能直接提交查询。");
        List<String> missing=new ArrayList<String>();
        if(!progress.selectionConfirmed("departure",original))missing.add("actual_selected_departure_city_confirmation");
        if(!progress.selectionConfirmed("arrival",original))missing.add("actual_selected_arrival_city_confirmation");
        if(!progress.selectionConfirmed("date",original))missing.add("actual_selected_complete_date_confirmation");
        if(!progress.queryDispatched())missing.add("model_bound_public_query_dispatch");
        missing.add("actual_same_record_flight_result");out.put("missing",missing);
        pageKey=WebEvidenceJson.sha(new JSONObject().put("observed_page_key",original.pageKey)
                .put("progress",new JSONObject(actual)).put("phase",phase)
                .put("capabilities",new JSONArray(capabilities)).toString());
        out.put("semantic_region_sha256",pageKey);proof=Collections.unmodifiableMap(out);
    }
    WebFlightDomain withProgress(WebFlightProgress value)throws Exception{return new WebFlightDomain(this,value);}
    Map<String,Object> progressEvidence(){return progress==null?null:progress.evidence(this);}
    boolean queryAttempted(){return progress!=null&&progress.queryAttempted();}
    boolean queryDispatched(){return progress!=null&&progress.queryDispatched();}
    boolean nativeValueMatches(String kind){return nativeReadbacks.containsKey(kind);}
    String purpose(String nodeId){Map<String,Object> value=capability(nodeId);return value==null?null:(String)value.get("purpose");}
    Map<String,Object> capability(String nodeId){
        if(nodeId==null)return null;
        for(Map<String,Object> value:capabilities)if(nodeId.equals(value.get("node_id")))return Collections.unmodifiableMap(value);
        return null;
    }
    /** Only an explicitly known booking document with no visible body is a
     * loading case. Ambiguous or malformed recognized controls still fail. */
    static boolean bookingBodyPending(JSONObject dom)throws Exception{
        java.net.URI uri=new java.net.URI(dom.getString("href"));
        if(!"https".equals(uri.getScheme())||!"m.csair.com".equals(uri.getHost())
                ||!"/booking_new/".equals(uri.getPath()))return false;
        JSONArray nodes=dom.getJSONArray("nodes");
        Map<String,Integer> ids=new LinkedHashMap<String,Integer>();
        int calendars=0,cities=0,hot=0;
        for(int i=0;i<nodes.length();i++){
            JSONObject n=nodes.getJSONObject(i);if(!Boolean.TRUE.equals(n.get("visible_in_viewport")))continue;
            String text=n.optString("text"),id=n.optString("id"),tag=n.optString("tag");
            if("选择日期".equals(text))calendars++;
            if("选择出发地".equals(text)||"选择目的地".equals(text))cities++;
            if("热门城市".equals(text))hot++;
            String key=tag+"#"+id;ids.put(key,ids.containsKey(key)?ids.get(key)+1:1);
        }
        // A known overlay is handled by its own strict parser. A city header
        // without its actual body is a read-only loading state.
        if(calendars>0)return false;
        if(cities>0)return cities==1&&hot==0;
        String[] required={"div#flightQuery","div#queryBox","div#tabControl","div#tabContent",
                "div#single","li#single","div#depport","div#arrport","div#depDate","button#queryBtn","div#psgBox"};
        boolean absent=false;
        for(String key:required){
            int count=ids.containsKey(key)?ids.get(key):0;
            if(count>1)return false; // ambiguity must be rejected, not treated as readiness
            if(count==0)absent=true;
        }
        return absent;
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
        CsairFlightForm observedForm=null;Map<String,Map<String,Object>> readbacks=new LinkedHashMap<String,Map<String,Object>>();
        Map<String,Object> query=null;
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
            boolean bodyPending=bookingBodyPending(dom);
            CsairCalendar calendar=bodyPending?null:CsairCalendar.read(dom);
            CsairCityPicker picker=!bodyPending&&calendar==null?CsairCityPicker.read(dom):null;
            CsairFlightForm form=!bodyPending&&calendar==null&&picker==null?CsairFlightForm.read(dom):null;
            if(bodyPending){
                phase="official_booking_content_pending";
                evidence.put("document_content_pending",true);evidence.put("query_control_withheld",true);
            }else if(calendar!=null){
                CsairCalendar.Selection requested=calendar.forDate(goal.departureDate.toString());
                phase=calendar.headerOnly?"official_calendar_content_pending":
                        !requested.ready?"official_calendar_date_unavailable":
                        geometry==null?"official_calendar_geometry_pending":"official_calendar";
                Map<String,Object> date=new LinkedHashMap<String,Object>();
                date.put("schema",CsairCalendar.SCHEMA);date.put("title_dom_path",calendar.titlePath);
                date.put("page_dom_path",calendar.pagePath);date.put("months_dom_path",calendar.monthsPath);
                date.put("requested_iso_date",goal.departureDate.toString());
                date.put("exact_date_metadata_ready",requested.ready);date.put("reason",requested.reason);
                date.put("selected_date_verified",false);date.put("url_date_used_as_evidence",false);
                date.put("native_parent_relationship_required",true);
                if(requested.target!=null){
                    CsairCalendar.DateTarget target=requested.target;
                    date.put("observed_year",target.year);date.put("observed_month",target.month);date.put("observed_day",target.day);
                    date.put("month_header_text",target.monthHeaderText);date.put("month_header_dom_path",target.monthHeaderPath);
                    date.put("month_dom_path",target.monthPath);date.put("day_list_dom_path",target.dayListPath);
                    date.put("day_dom_path",target.dayPath);date.put("day_dom_text",target.dayText);
                    date.put("dom_disabled",target.domDisabled);date.put("dom_visible_in_viewport",target.domVisibleInViewport);
                    date.put("zero_height_layout_list",target.zeroHeightDayList);
                    if(requested.ready&&geometry!=null&&nativePickerTitle(frame,geometry,"选择日期")
                            &&nativePickerTitle(frame,geometry,target.monthHeaderText)){
                        PhoneObservation.Node node=calendarNativeDay(frame,geometry,target);
                        if(node!=null){
                            addCapability(clicks,capabilities,node,target.dayPath,target.domId,target.dayText,
                                    "choose_departure_date_from_immutable_owner");
                            Map<String,Object> capability=capabilities.get(capabilities.size()-1);
                            capability.put("observed_iso_date",target.isoDate);
                            capability.put("observed_month_header",target.monthHeaderText);
                            capability.put("observed_month_header_dom_path",target.monthHeaderPath);
                            capability.put("observed_month_dom_path",target.monthPath);
                            capability.put("native_target_semantics","same_frame_month_heading_then_list_direct_day");
                            capability.put("native_tree_path",node.nativeTreePath);
                            capability.put("native_parent_class",node.nativeParentClass);
                            capability.put("native_month_heading_path",calendarMonthHeading(frame,target.monthHeaderText).nativeTreePath);
                            capability.put("native_parent_relationship_claimed",true);
                        }
                    }
                }
                evidence.put("observed_calendar",date);
                evidence.put("document_content_pending",calendar.headerOnly);
                evidence.put("query_control_withheld",true);
                evidence.put("underlying_form_capabilities_withheld",true);
            }else if(picker!=null){
                phase=geometry==null?"official_city_picker_geometry_pending":"official_city_picker";
                evidence.put("observed_city_picker",picker.evidence());
                String expected="departure".equals(picker.kind)?goal.fromCity:goal.toCity;
                evidence.put("requested_city_from_immutable_owner",expected);
                evidence.put("selected_city_verified",false);
                CsairCityPicker.City city=picker.city(expected);
                if(geometry!=null&&city!=null&&nativePickerTitle(frame,geometry,picker.title)){
                    PhoneObservation.Node target=uniqueNative(frame,geometry,"","android.view.View",expected,
                            Collections.singletonList(expected),false);
                    if(target!=null)addCapability(clicks,capabilities,target,city.path,"",expected,
                            "choose_"+picker.kind+"_city_from_immutable_owner");
                }
                // The still-visible form behind this picker never receives a capability.
                evidence.put("underlying_form_capabilities_withheld",true);
                evidence.put("query_control_withheld",true);
            }else if(form!=null){
                // Require the form root's complete visible ancestry as well as
                // the provider's field-to-tab ancestry. Hidden sibling IDs remain data.
                need(visibleAncestors(byPath.get(form.formPath),byPath),"form ancestor is not currently visible");
                phase=geometry==null?"official_query_form_geometry_pending":"official_query_form";
                observedForm=form;evidence.put("observed_query_form",form.evidence());
                if(geometry!=null){
                    Map<String,Object> depRead=nativeFormReadback(frame,geometry,form.departure);
                    Map<String,Object> arrRead=nativeFormReadback(frame,geometry,form.arrival);
                    Map<String,Object> dateRead=nativeFormReadback(frame,geometry,form.departureDate);
                    if(depRead!=null)readbacks.put("departure",depRead);
                    if(arrRead!=null)readbacks.put("arrival",arrRead);
                    if(dateRead!=null)readbacks.put("date",dateRead);
                    if(!form.query.disabled){
                        PhoneObservation.Node q=uniqueNative(frame,geometry,form.query.id,"android.widget.Button",
                                "查询",form.query.visibleTexts,false);
                        if(q!=null){
                            List<Map<String,Object>> isolated=new ArrayList<Map<String,Object>>();
                            addCapability(new HashSet<String>(),isolated,q,form.query.path,form.query.id,"查询",WebFlightProgress.QUERY);
                            query=isolated.get(0);
                        }
                    }

                    addFormControl(frame,geometry,form.departure,"choose_departure_city",clicks,capabilities);
                    addFormControl(frame,geometry,form.arrival,"choose_arrival_city",clicks,capabilities);
                    addFormControl(frame,geometry,form.departureDate,"choose_departure_date",clicks,capabilities);
                }
                // A current query control is data until the actual model selection
                // chain confirms both cities and the full calendar date.
                evidence.put("native_form_field_readback",readbacks);
                evidence.put("observed_query_control",query);
                evidence.put("query_control_withheld",true);
                evidence.put("query_control_withheld_reason","actual model selection chain not yet applied");
            }
        }
        JSONObject semantic=new JSONObject().put("native_url",receipt.url).put("instance",receipt.instance)
                .put("epoch",receipt.epoch).put("phase",phase)
                .put("native_geometry_sha256",geometry==null?JSONObject.NULL:geometry.fingerprint)
                .put("capabilities",new JSONArray(capabilities));
        if(evidence.containsKey("observed_query_form"))semantic.put("form",new JSONObject((Map<?,?>)evidence.get("observed_query_form")));
        if(evidence.containsKey("observed_city_picker"))semantic.put("city_picker",new JSONObject((Map<?,?>)evidence.get("observed_city_picker")));
        if(evidence.containsKey("observed_calendar"))semantic.put("calendar",new JSONObject((Map<?,?>)evidence.get("observed_calendar")));
        pageKey=WebEvidenceJson.sha(semantic.toString());
        evidence.put("capabilities_withheld_reason",geometry==null?"actual native/visual-viewport bracket absent":
                clicks.isEmpty()?"no unique visible native AX target matches the actual page semantics":null);
        evidence.put("phase",phase);evidence.put("allowed_click_ids",new ArrayList<String>(clicks));
        evidence.put("native_ax_capabilities",capabilities);
        evidence.put("semantic_region_sha256",pageKey);evidence.put("flight_result_inferred",false);
        evidence.put("next_goal",clicks.isEmpty()?"当前页面没有已验证的只读控件；等待加载或报告未完成。":
                "official_home".equals(phase)?"选择实际『机票预订』入口，再观察公开查询表单。":
                "official_city_picker".equals(phase)?"仅选择本次原始指令中对应的城市；使用原生语义点击，选择结果须下一帧重新核对。":
                "official_calendar".equals(phase)?"仅用本帧原生节点选择原始指令的完整年月日；选择结果须下一帧重新核对，不能把日历显示当作已选择。":
                "只用本帧原生节点选择出发城市、到达城市或出发日期；查询仍等待完整目标值验证。");
        evidence.put("missing",java.util.Arrays.asList("actual_selected_city_confirmation","actual_selected_complete_date_confirmation",
                "model_bound_public_query_dispatch","actual_same_record_flight_result"));
        return new WebFlightDomain(task,goal,auth,frame,receipt,phase,pageKey,clicks,edits,evidence,
                observedForm,readbacks,query,capabilities);
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
        return new WebFlightDomain(task,goal,auth,frame,receipt,"official_page_capture_pending",key,
                Collections.<String>emptySet(),Collections.<String,String>emptyMap(),evidence,
                null,Collections.<String,Map<String,Object>>emptyMap(),null,Collections.<Map<String,Object>>emptyList());
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
    private static boolean nativePickerTitle(PhoneObservation frame,WebNativeGeometry geometry,String title){
        List<PhoneObservation.Node> matches=new ArrayList<PhoneObservation.Node>();
        for(PhoneObservation.Node node:frame.nodes)if(title.equals(node.text))matches.add(node);
        if(matches.size()!=1)return false;
        PhoneObservation.Node node=matches.get(0);
        return WebEvidenceProtocol.HELPER_PACKAGE.equals(node.packageName)&&"android.widget.TextView".equals(node.className)
                &&node.enabled&&!node.clickable&&!node.editable&&!node.password&&!node.scrollable
                &&node.observedAppTreeSignature!=null&&node.observedAppTreeSignature.matches("[0-9a-f]{64}")
                &&geometry.contains(node.bounds.left,node.bounds.top,node.bounds.right,node.bounds.bottom)
                &&inside(frame.windowMetadata.rootBounds(),node)&&inside(frame.windowMetadata.windowBounds(),node)
                &&node.bounds.left>=0&&node.bounds.top>=0&&node.bounds.right<=frame.width&&node.bounds.bottom<=frame.height;
    }
    private static PhoneObservation.Node calendarMonthHeading(PhoneObservation frame,String title){
        PhoneObservation.Node found=null;
        for(PhoneObservation.Node node:frame.nodes)if(title.equals(node.text)){
            if(found!=null)return null;found=node;
        }
        return found;
    }
    private static PhoneObservation.Node calendarNativeDay(PhoneObservation frame,WebNativeGeometry geometry,
                                                            CsairCalendar.DateTarget target)throws Exception{
        PhoneObservation.Node day=uniqueNative(frame,geometry,target.domId,"android.view.View",target.dayText,
                Collections.singletonList(target.dayText),false);
        PhoneObservation.Node heading=calendarMonthHeading(frame,target.monthHeaderText);
        if(day==null||heading==null||day.nativeTreePath==null||heading.nativeTreePath==null
                ||!"android.widget.ListView".equals(day.nativeParentClass)
                ||!nativePickerTitle(frame,geometry,target.monthHeaderText))return null;
        String dayPath=day.nativeTreePath,headerPath=heading.nativeTreePath;
        int daySlash=dayPath.lastIndexOf('/'),headerSlash=headerPath.lastIndexOf('/');
        if(daySlash<0||headerSlash<0)return null;
        String listPath=dayPath.substring(0,daySlash);int listSlash=listPath.lastIndexOf('/');
        if(listSlash<0||!listPath.substring(0,listSlash).equals(headerPath.substring(0,headerSlash)))return null;
        int listIndex=Integer.parseInt(listPath.substring(listSlash+1));
        int headerIndex=Integer.parseInt(headerPath.substring(headerSlash+1));
        // The month heading and immediately following native ListView share an actual parent.
        return listIndex==headerIndex+1?day:null;
    }
    /** Each known DOM field string must also occur in this same native field's
     * own label or real bounded descendant sources. A clickable label alone is
     * insufficient to prove the selected value. No CSS coordinate is consulted. */
    private static Map<String,Object> nativeFormReadback(PhoneObservation frame,WebNativeGeometry geometry,
                                                        CsairFlightForm.Control control)throws Exception{
        if(control.disabled)return null;
        PhoneObservation.Node root=uniqueNative(frame,geometry,control.id,"android.view.View",
                control.requiredLabel,control.visibleTexts,true);
        if(root==null)return null;
        Set<String> wanted=new HashSet<String>(),observed=new HashSet<String>();
        for(String value:control.visibleTexts)wanted.add(WebEvidenceJson.sha(value));
        List<String> nativePaths=new ArrayList<String>();
        for(String value:new String[]{root.text,root.description})if(!value.isEmpty()){
            String sha=WebEvidenceJson.sha(value);if(!wanted.contains(sha))return null;observed.add(sha);
        }
        ObservedChildText.Result child=root.childText;
        if("derived".equals(child.status)){
            if(child.truncated||child.sources.isEmpty()||!child.rootSignature.matches("[0-9a-f]{64}")
                    ||!child.bind(child.rootSignature).equals(root.observedAppTreeSignature))return null;
            for(ObservedChildText.Source source:child.sources){
                if(!source.descendantPath.matches("[0-9]+(?:/[0-9]+){0,3}")
                        ||!("text".equals(source.property)||"description".equals(source.property))
                        ||source.nodeSignature==null||!source.nodeSignature.matches("[0-9a-f]{64}")
                        ||!wanted.contains(source.textSha256))return null;
                observed.add(source.textSha256);
            }
        }
        if(root.nativeTreePath!=null)for(PhoneObservation.Node node:frame.nodes){
            if(node.nativeTreePath==null||!node.nativeTreePath.startsWith(root.nativeTreePath+"/"))continue;
            if(!WebEvidenceProtocol.HELPER_PACKAGE.equals(node.packageName)||node.password||node.editable
                    ||node.observedAppTreeSignature==null||!node.observedAppTreeSignature.matches("[0-9a-f]{64}")
                    ||!geometry.contains(node.bounds.left,node.bounds.top,node.bounds.right,node.bounds.bottom)
                    ||!inside(new int[]{root.bounds.left,root.bounds.top,root.bounds.right,root.bounds.bottom},node))return null;
            for(String value:new String[]{node.text,node.description})if(!value.isEmpty()){
                String sha=WebEvidenceJson.sha(value);if(!wanted.contains(sha))return null;observed.add(sha);
            }
            nativePaths.add(node.nativeTreePath);
        }
        if(!observed.equals(wanted))return null;
        Map<String,Object> out=new LinkedHashMap<String,Object>();
        out.put("node_id",root.id);out.put("native_view_id",root.viewId);out.put("native_class",root.className);
        out.put("node_app_tree_sha256",root.observedAppTreeSignature);out.put("native_tree_path",root.nativeTreePath);
        out.put("native_descendant_paths",nativePaths);out.put("dom_path",control.path);
        out.put("observed_literal_texts",control.visibleTexts);out.put("all_dom_field_strings_observed_natively",true);
        out.put("derived_sources_complete",child.sourcesComplete);out.put("dom_rect_used_as_target",false);
        return Collections.unmodifiableMap(out);
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
