package org.trillionnium.hepta.local;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/** A restriction over one actual native frame. The existing OWNER, grammar,
 * NodeRef and service action lease remain necessary for every dispatch. */
final class NativeAppDomain {
    static final String SCHEMA="hepta.native-app-action-domain.v1";
    final NativeAppEvidence.Frame frame;
    final String phase;
    final Set<String> clickIds,resourceClickIds;
    final Map<String,String> editValues,purposes;
    final boolean backAllowed,resultReady;
    final List<String> missing;
    private final Map<String,Object> providerView,result;

    NativeAppDomain(NativeAppEvidence.Frame frame,String phase,Set<String> clicks,Map<String,String> edits,
            Map<String,String> purposes,boolean back,Map<String,Object> providerView,Map<String,Object> result,List<String> missing){
        NativeAppEvidence.need(frame!=null&&phase!=null,"native action domain source required");
        this.frame=frame;this.phase=phase;clickIds=Collections.unmodifiableSet(new TreeSet<String>(clicks));
        editValues=Collections.unmodifiableMap(new TreeMap<String,String>(edits));this.purposes=Collections.unmodifiableMap(new TreeMap<String,String>(purposes));
        Set<String> resourceIds=new TreeSet<String>();
        for(String id:clickIds)if(NativeCtripFlightPage.HOME.equals(phase)&&"open_flight_form".equals(this.purposes.get(id))
                &&NativeCtripFlightPage.resourceHomeClick(frame,id))resourceIds.add(id);
        resourceClickIds=Collections.unmodifiableSet(resourceIds);
        for(String id:clickIds)requireNode(id,true,false);
        for(Map.Entry<String,String> e:editValues.entrySet()){requireNode(e.getKey(),false,true);NativeAppEvidence.need(e.getValue()!=null,"native literal edit value");}
        for(String id:this.purposes.keySet())NativeAppEvidence.need("back".equals(id)||clickIds.contains(id)||editValues.containsKey(id),"purpose without granted target");
        backAllowed=back;this.providerView=NativeAppEvidence.immutableMap(providerView);
        this.result=result==null?null:NativeAppEvidence.immutableMap(result);resultReady=result!=null;
        this.missing=Collections.unmodifiableList(new ArrayList<String>(missing));
    }
    private void requireNode(String id,boolean click,boolean edit){NativeAppEvidence.Node n=frame.byId.get(id);
        NativeAppEvidence.need(frame.collectionComplete&&!frame.nodesTruncated&&frame.usable(n)&&n.enabled&&!n.password
                &&(!click||n.clickable&&(!n.label.isEmpty()||resourceClickIds.contains(id)))&&(!edit||n.editable),"native permission must name its actual current node");}
    boolean permitsResourceClick(String id){return resourceClickIds.contains(id);}
    Set<String> clicks(Set<String> original){Set<String> out=new TreeSet<String>(original);out.retainAll(clickIds);return out;}
    Set<String> edits(Set<String> original){Set<String> out=new TreeSet<String>(original);out.retainAll(editValues.keySet());return out;}
    Set<String> openPackages(Set<String> original){return Collections.emptySet();}
    <T> Map<String,T> noNodeActions(Map<String,T> original){return Collections.emptyMap();}
    /** The same phase restriction used by requireCurrent; this grants no action. */
    Set<String> doneStatuses(){
        if(NativeXiaomiProductPage.HOME_LOADING.equals(phase))return Collections.emptySet();
        if(NativeXiaomiProductPage.HOME_LOADING_EXHAUSTED.equals(phase)
                ||NativeXiaomiProductPage.LOGIN.equals(phase)||NativeXiaomiProductPage.LOGIN_BLOCKED.equals(phase))
            return Collections.singleton("failure");
        return Collections.unmodifiableSet(new TreeSet<String>(java.util.Arrays.asList(resultReady
                ?new String[]{"failure","partial","success"}:new String[]{"failure","partial"})));
    }
    Set<String> toolMask(Set<String> original){Set<String> out=new TreeSet<String>(
            java.util.Arrays.asList("click","type","back","wait","done"));
        if(original!=null)out.retainAll(original);
        if(clickIds.isEmpty())out.remove("click");if(editValues.isEmpty())out.remove("type");if(!backAllowed)out.remove("back");
        if(NativeXiaomiProductPage.HOME_LOADING.equals(phase))out.retainAll(Collections.singleton("wait"));
        if(NativeXiaomiProductPage.HOME_LOADING_EXHAUSTED.equals(phase))out.retainAll(Collections.singleton("done"));
        if(NativeXiaomiProductPage.LOGIN.equals(phase))out.retainAll(java.util.Arrays.asList("click","done"));
        if(NativeXiaomiProductPage.LOGIN_BLOCKED.equals(phase))out.retainAll(Collections.singleton("done"));
        return out;}
    DecisionGrammar boundedWaitGrammar(ObservedTargetLabels targets,ObservedAppLabels apps,TaskAuthorization.Frame authorization,Set<String> original){
        NativeAppEvidence.need(NativeXiaomiProductPage.HOME_LOADING.equals(phase)&&frame.metadataObserved&&frame.windowType==1
                &&frame.displayId>0&&frame.collectionComplete&&!frame.nodesTruncated&&clickIds.isEmpty()&&editValues.isEmpty()
                &&!backAllowed&&!resultReady&&toolMask(original).equals(Collections.singleton("wait")),
                "bounded readiness grammar requires the current complete loading-only domain");
        return DecisionGrammar.createBoundedWaitAuthorized(frame.observationId,frame.packageName,targets,apps,authorization,toolMask(original));
    }
    void requireCurrent(ActionDecision action)throws ActionDecision.InvalidActionException{
        try{
            NativeAppEvidence.need(action!=null&&action.toolChildOrigin==null&&frame.observationId.equals(action.observationId)
                    &&frame.packageName.equals(action.packageName),"same native model/frame/package required");
            if(NativeXiaomiProductPage.HOME_LOADING.equals(phase)){
                NativeAppEvidence.need("wait".equals(action.action),"home content is loading; bounded model wait required");return;
            }
            if(NativeXiaomiProductPage.HOME_LOADING_EXHAUSTED.equals(phase)){
                NativeAppEvidence.need("done".equals(action.action)&&"failure".equals(action.status),"home loading budget exhausted; failure only");return;
            }
            if(NativeXiaomiProductPage.LOGIN_BLOCKED.equals(phase)){
                NativeAppEvidence.need("done".equals(action.action)&&"failure".equals(action.status),"native login requires user handling; failure only");return;
            }
            if(NativeXiaomiProductPage.LOGIN.equals(phase)){
                NativeAppEvidence.need("click".equals(action.action)||"done".equals(action.action)&&"failure".equals(action.status),
                        "native login admits only its explicit return control or failure");
            }
            if("done".equals(action.action)){NativeAppEvidence.need(!"success".equals(action.status)||resultReady,"native result not verified");return;}
            if("wait".equals(action.action))return;
            NativeAppEvidence.need(frame.collectionComplete&&!frame.nodesTruncated,"incomplete native frame cannot grant action");
            if("back".equals(action.action)){NativeAppEvidence.need(backAllowed,"native Back not in current phase");return;}
            NativeAppEvidence.Node n=frame.byId.get(action.nodeId);
            NativeAppEvidence.need(n!=null&&n.label.equals(action.nodeLabel),"exact observed native label required");
            if("click".equals(action.action)){NativeAppEvidence.need(clickIds.contains(action.nodeId),"native click target not in current read-only query phase");return;}
            if("type".equals(action.action)){NativeAppEvidence.need(editValues.containsKey(action.nodeId)
                    &&editValues.get(action.nodeId).equals(action.text),"native input must equal the immutable product query");return;}
            throw new IllegalArgumentException("native App query does not admit this tool");
        }catch(IllegalArgumentException refusal){throw new ActionDecision.InvalidActionException(refusal.getMessage());}
    }
    Map<String,Object> resultRecord(){return result;}
    Map<String,Object> promptEvidence(){Map<String,Object> out=new LinkedHashMap<String,Object>();
        out.put("schema",SCHEMA);out.put("phase",phase);out.put("observation_id",frame.observationId);
        out.put("package",frame.packageName);out.put("background_generation",frame.generation);out.put("read_only_query_targets",purposes);
        out.put("literal_edit_values",editValues);out.put("back_allowed",backAllowed);out.put("provider",providerView);
        if(!resourceClickIds.isEmpty()){
            Map<String,Object> resources=new TreeMap<String,Object>();
            for(String id:resourceClickIds){Map<String,Object> r=frame.byId.get(id).fact("description");
                r.put("capability_source","installed_version_bound_native_provider");r.put("provider_version_code",NativeCtripFlightPage.VERSION_CODE);
                r.put("provider_base_apk_sha256",NativeCtripFlightPage.BASE_APK_SHA256);r.put("purpose",purposes.get(id));
                r.put("node_label",frame.byId.get(id).label);r.put("visible_label_inferred",false);resources.put(id,r);}
            out.put("resource_clicks",resources);
        }
        out.put("result_ready",resultReady);out.put("missing",missing);out.put("booking_purchase_or_payment_allowed",false);
        out.put("web_helper_allowed",false);out.put("external_model_allowed",false);return out;}
    Map<String,Object> evidence(){Map<String,Object> out=promptEvidence();out.put("source_frame",frame.evidence());
        out.put("click_ids",new ArrayList<String>(clickIds));out.put("result",result);out.put("grants_service_dispatch",false);return out;}
}
