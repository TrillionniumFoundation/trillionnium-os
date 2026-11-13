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
    final Set<String> clickIds;
    final Map<String,String> editValues,purposes;
    final boolean backAllowed,resultReady;
    final List<String> missing;
    private final Map<String,Object> providerView,result;

    NativeAppDomain(NativeAppEvidence.Frame frame,String phase,Set<String> clicks,Map<String,String> edits,
            Map<String,String> purposes,boolean back,Map<String,Object> providerView,Map<String,Object> result,List<String> missing){
        NativeAppEvidence.need(frame!=null&&phase!=null,"native action domain source required");
        this.frame=frame;this.phase=phase;clickIds=Collections.unmodifiableSet(new TreeSet<String>(clicks));
        editValues=Collections.unmodifiableMap(new TreeMap<String,String>(edits));this.purposes=Collections.unmodifiableMap(new TreeMap<String,String>(purposes));
        for(String id:clickIds)requireNode(id,true,false);
        for(Map.Entry<String,String> e:editValues.entrySet()){requireNode(e.getKey(),false,true);NativeAppEvidence.need(e.getValue()!=null,"native literal edit value");}
        for(String id:this.purposes.keySet())NativeAppEvidence.need("back".equals(id)||clickIds.contains(id)||editValues.containsKey(id),"purpose without granted target");
        backAllowed=back;this.providerView=NativeAppEvidence.immutableMap(providerView);
        this.result=result==null?null:NativeAppEvidence.immutableMap(result);resultReady=result!=null;
        this.missing=Collections.unmodifiableList(new ArrayList<String>(missing));
    }
    private void requireNode(String id,boolean click,boolean edit){NativeAppEvidence.Node n=frame.byId.get(id);
        NativeAppEvidence.need(frame.collectionComplete&&!frame.nodesTruncated&&frame.usable(n)&&n.enabled&&!n.password
                &&(!click||n.clickable&&!n.label.isEmpty())&&(!edit||n.editable),"native permission must name its actual current node");}
    Set<String> clicks(Set<String> original){Set<String> out=new TreeSet<String>(original);out.retainAll(clickIds);return out;}
    Set<String> edits(Set<String> original){Set<String> out=new TreeSet<String>(original);out.retainAll(editValues.keySet());return out;}
    Set<String> openPackages(Set<String> original){return Collections.emptySet();}
    <T> Map<String,T> noNodeActions(Map<String,T> original){return Collections.emptyMap();}
    Set<String> toolMask(Set<String> original){Set<String> out=new TreeSet<String>(
            java.util.Arrays.asList("click","type","back","wait","done"));
        if(original!=null)out.retainAll(original);
        if(clickIds.isEmpty())out.remove("click");if(editValues.isEmpty())out.remove("type");if(!backAllowed)out.remove("back");return out;}
    void requireCurrent(ActionDecision action)throws ActionDecision.InvalidActionException{
        try{
            NativeAppEvidence.need(action!=null&&action.toolChildOrigin==null&&frame.observationId.equals(action.observationId)
                    &&frame.packageName.equals(action.packageName),"same native model/frame/package required");
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
        out.put("result_ready",resultReady);out.put("missing",missing);out.put("booking_purchase_or_payment_allowed",false);
        out.put("web_helper_allowed",false);out.put("external_model_allowed",false);return out;}
    Map<String,Object> evidence(){Map<String,Object> out=promptEvidence();out.put("source_frame",frame.evidence());
        out.put("click_ids",new ArrayList<String>(clickIds));out.put("result",result);out.put("grants_service_dispatch",false);return out;}
}
