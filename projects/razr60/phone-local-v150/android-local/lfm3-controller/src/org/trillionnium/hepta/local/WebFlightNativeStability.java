package org.trillionnium.hepta.local;

import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebDomCanonical;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * A compiled, homepage-only booking predicate. It is neither a general
 * stable-tree waiver nor an action executor. The service keeps the original
 * NodeRef and all ordinary authority, freshness and platform-action checks.
 */
final class WebFlightNativeStability {
    static final String PURPOSE="open_public_booking_form";
    static final String LABEL="机票预订按钮，点按两次即可激活";
    static final int MAX_NATIVE_NODES=512;
    private WebFlightNativeStability(){}

    static final class Permit {
        final PhoneObservation frame;
        final String taskId,targetId,targetPath,run,actionKey,bindingSha,instance;
        final int displayId,windowId;
        final long epoch;
        private final int[] targetBounds;
        private final String domProof;
        private Permit(WebTaskDomain domain,PhoneObservation frame,PhoneObservation.Node target,
                       String run,ActionDecision action,WebEvidenceReceipt receipt,JSONObject proof)throws Exception{
            this.frame=frame;taskId=domain.taskId;targetId=target.id;targetPath=target.nativeTreePath;
            this.run=run;actionKey=key(action);bindingSha=receipt.bindingSha;instance=receipt.instance;
            displayId=receipt.displayId;windowId=receipt.windowId;epoch=receipt.epoch;
            targetBounds=new int[]{target.bounds.left,target.bounds.top,target.bounds.right,target.bounds.bottom};
            domProof=WebDomCanonical.canonical(proof);
        }
        int[] bounds(){return targetBounds.clone();}
        JSONObject domEvidence()throws Exception{return new JSONObject(domProof);}
        boolean matches(PhoneObservation current,ActionDecision action,String actualRun){
            return frame==current&&run.equals(actualRun)&&actionKey.equals(key(action))
                    &&targetId.equals(action.nodeId)&&frame.id.equals(action.observationId);
        }
    }

    static Permit prepare(WebTaskDomain domain,PhoneObservation frame,ActionDecision action,String run,
                          WebEvidenceReceipt observed,WebEvidenceReceipt fresh)throws Exception{
        if(domain==null||domain.flight==null||!"click".equals(action.action)
                ||!"official_home".equals(domain.phase)||!PURPOSE.equals(domain.flight.purpose(action.nodeId)))return null;
        need("https://m.csair.com/".equals(domain.url)&&frame!=null&&observed!=null&&fresh!=null,
                "booking exception requires the actual official homepage captures");
        need(!frame.nodesTruncated&&frame.collectionStats!=null&&!frame.collectionStats.truncated()
                &&frame.collectionStats.pending==0&&frame.collectionStats.childSlotsOmitted==0,
                "complete original native observation required");
        PhoneObservation.Node target=null;
        for(PhoneObservation.Node node:frame.nodes)if(node.id.equals(action.nodeId)){
            need(target==null,"duplicate original native target");target=node;
        }
        need(target!=null&&target.nativeTreePath!=null&&target.nativeParentClass!=null
                &&"android.widget.Button".equals(target.className)&&LABEL.equals(target.label())
                &&WebEvidenceProtocol.HELPER_PACKAGE.equals(target.packageName)&&target.viewId.isEmpty()
                &&target.clickable&&target.enabled&&!target.password&&!target.editable&&!target.scrollable,
                "original native booking button required");
        need("captured".equals(observed.status)&&"captured".equals(fresh.status)
                &&observed.stability().rawEqual&&fresh.stability().rawEqual
                &&observed.bindingSha.equals(fresh.bindingSha)&&observed.instance.equals(fresh.instance)
                &&observed.epoch==fresh.epoch&&observed.windowId==fresh.windowId
                &&observed.displayId==fresh.displayId&&observed.url.equals(fresh.url)
                &&domain.instance.equals(fresh.instance)&&domain.epoch==fresh.epoch
                &&frame.windowId==fresh.windowId&&domain.displayId==fresh.displayId,
                "same verified full-raw capture lease required");
        WebNativeGeometry before=WebNativeGeometry.read(observed.capture(),observed.dom(),observed.displayId,
                observed.windowId,observed.stability());
        WebNativeGeometry after=WebNativeGeometry.read(fresh.capture(),fresh.dom(),fresh.displayId,
                fresh.windowId,fresh.stability());
        need(before!=null&&after!=null&&before.same(after),"native capture geometry changed");
        JSONObject proof=compareDom(observed.dom(),fresh.dom())
                .put("first_dom_sha256",observed.domSha).put("fresh_dom_sha256",fresh.domSha)
                .put("first_capture_request_nonce",observed.callback().get("request_nonce"))
                .put("fresh_capture_request_nonce",fresh.callback().get("request_nonce"))
                .put("native_geometry_sha256",after.fingerprint);
        return new Permit(domain,frame,target,run,action,fresh,proof);
    }

    /** Complete DOM comparison; only this observed eight-image slider may move. */
    static JSONObject compareDom(JSONObject before,JSONObject after)throws Exception{
        Map<String,JSONObject> a=domNodes(before),b=domNodes(after);
        need(a.keySet().equals(b.keySet()),"homepage DOM membership changed");
        need(WebDomCanonical.same(without(before,"nodes"),without(after,"nodes")),
                "homepage DOM metadata changed");
        String slider=unique(a,"id","slider4"),booking=unique(a,"id","booking");
        need("ul".equals(a.get(slider).get("tag"))&&"div".equals(a.get(booking).get("tag"))
                &&!inside(booking,slider)&&a.get(booking).getBoolean("visible_in_viewport"),
                "known slider and separate visible booking region required");
        Set<String> allowed=new HashSet<String>();allowed.add(slider);
        Set<String> ids=new HashSet<String>();
        for(Map.Entry<String,JSONObject> e:a.entrySet()){
            JSONObject n=e.getValue();String path=e.getKey();
            if(slider.equals(n.opt("parent_path"))){
                need("li".equals(n.get("tag"))&&n.getString("id").matches("advertising[0-7]")
                        &&ids.add(n.getString("id")),"unexpected slider child");
                allowed.add(path);int images=0;
                for(Map.Entry<String,JSONObject> child:a.entrySet())if(path.equals(child.getValue().opt("parent_path"))){
                    need("img".equals(child.getValue().get("tag"))&&child.getValue().getString("id").isEmpty(),
                            "slider child is not an observed plain image");
                    allowed.add(child.getKey());images++;
                }
                need(images==1,"slider image membership changed");
            }
        }
        need(ids.size()==8&&allowed.size()==17,"exact eight-image carousel required");
        double delta=rect(b.get(slider),"rect_css_pixels")[0]-rect(a.get(slider),"rect_css_pixels")[0];
        double[] root=rect(a.get(slider),"rect_css_pixels");
        need(Math.abs(delta)<=root[2]-root[0],"carousel translation exceeds its observed width");
        JSONArray changes=new JSONArray();
        boolean button=false;
        for(String path:a.keySet()){
            JSONObject x=a.get(path),y=b.get(path);String tag=x.getString("tag");
            if(x.getBoolean("visible_in_viewport")&&("iframe".equals(tag)||"canvas".equals(tag)
                    ||"video".equals(tag)||"dialog".equals(tag)||"dialog".equals(x.optString("role"))
                    ||"true".equals(x.optString("aria_modal"))))throw new IllegalArgumentException("observed overlay or embedded surface");
            if(inside(path,booking)&&"button".equals(x.optString("role"))
                    &&LABEL.equals(x.optString("aria_label"))&&"机票预订".equals(x.optString("text"))
                    &&x.getBoolean("visible_in_viewport")){need(!button,"ambiguous booking label");button=true;}
            if(inside(path,slider))need(allowed.contains(path),"unrecognized carousel descendant");
            if(!allowed.contains(path)){
                need(WebDomCanonical.same(x,y),"non-carousel DOM changed: "+path);continue;
            }
            need(x.getString("text").trim().isEmpty()&&x.optString("role").isEmpty()
                    &&x.optString("aria_label").isEmpty()&&x.isNull("href_raw")&&x.isNull("href_resolved")
                    &&x.isNull("link_target")&&!x.getBoolean("hidden_attr")&&!x.getBoolean("inert_attr"),
                    "carousel node carries unapproved semantics");
            need(WebDomCanonical.same(without(x,"rect_css_pixels","visible_in_viewport"),
                    without(y,"rect_css_pixels","visible_in_viewport")),"carousel semantics changed");
            double[] r=rect(x,"rect_css_pixels"),s=rect(y,"rect_css_pixels");
            need(s[1]==r[1]&&s[3]==r[3]&&s[2]-s[0]==r[2]-r[0]
                    &&s[0]-r[0]==delta&&s[2]-r[2]==delta,"carousel is not one horizontal translation");
            if(!WebDomCanonical.same(x,y))changes.put(new JSONObject().put("path",path).put("before",x).put("after",y));
        }
        need(button,"complete unchanged booking button missing");
        return new JSONObject().put("schema","hepta.csair-home-dom-scope.v1")
                .put("scope","official_home_booking_with_observed_slider4_horizontal_translation")
                .put("slider_dom_path",slider).put("booking_dom_path",booking)
                .put("horizontal_translation_css_pixels",delta).put("changes",changes)
                .put("whole_dom_equal",WebDomCanonical.same(before,after))
                .put("all_other_dom_records_equal",true).put("coordinates_used_for_input",false)
                .put("fully_unoccluded_claimed",false).put("business_verified",false);
    }

    /**
     * Both arrays are complete snapshots of the service's actual native traversal,
     * including ancestors and nonretained nodes. Native path pairs observations;
     * the model's original NodeRef is separately checked by the service.
     */
    static JSONObject compareNative(JSONArray before,JSONArray after,String targetPath)throws Exception{
        Map<String,JSONObject> a=nativeNodes(before),b=nativeNodes(after);
        need(a.keySet().equals(b.keySet()),"native traversal membership changed");
        JSONObject target=a.get(targetPath);
        need(target!=null&&"android.widget.Button".equals(target.get("class"))
                &&LABEL.equals(target.get("text"))&&target.getString("description").isEmpty()
                &&target.getBoolean("visible")&&target.getBoolean("enabled")
                &&target.getBoolean("clickable")&&!target.getBoolean("editable")
                &&!target.getBoolean("scrollable")&&!target.getBoolean("password"),
                "same actual native booking target required");
        String slider=unique(a,"view_id","slider4"),booking=unique(a,"view_id","booking");
        JSONObject container=a.get(slider);
        need("android.widget.ListView".equals(container.get("class"))&&container.getBoolean("visible")
                &&container.getInt("children")==8&&inside(targetPath,booking)
                &&!inside(targetPath,slider)&&!inside(booking,slider),"separate original native booking and slider required");
        need(ancestorClass(a,targetPath,"android.webkit.WebView")!=null
                &&ancestorClass(a,targetPath,"android.webkit.WebView").equals(ancestorClass(a,slider,"android.webkit.WebView")),
                "booking and carousel must retain the same actual WebView ancestor");
        Set<String> changedScope=new HashSet<String>(),ids=new HashSet<String>();
        for(Map.Entry<String,JSONObject> e:a.entrySet())if(parent(e.getKey()).equals(slider)){
            JSONObject n=e.getValue();
            need("android.view.View".equals(n.get("class"))&&n.getString("view_id").matches("advertising[0-7]")
                    &&ids.add(n.getString("view_id"))&&n.getInt("children")==1,"unexpected native carousel child");
            String image=e.getKey()+"/0";JSONObject child=a.get(image);
            need(child!=null&&"android.widget.Image".equals(child.get("class"))&&child.getInt("children")==0,
                    "native carousel image missing");
            changedScope.add(e.getKey());changedScope.add(image);
        }
        need(ids.size()==8&&changedScope.size()==16,"native carousel membership must be complete");
        int[] box=intRect(container),targetBox=intRect(target);
        JSONArray changes=new JSONArray();List<int[]> oldCover=new ArrayList<int[]>(),newCover=new ArrayList<int[]>();
        for(String path:a.keySet()){
            JSONObject x=a.get(path),y=b.get(path);
            if(!changedScope.contains(path)){
                need(!inside(path,slider)||path.equals(slider),"unrecognized native carousel descendant");
                need(WebDomCanonical.same(x,y),"native target, ancestor or non-carousel node changed: "+path);continue;
            }
            need(WebDomCanonical.same(without(x,"bounds","visible"),without(y,"bounds","visible")),
                    "native carousel nongeometry field changed");
            need(!x.getBoolean("editable")&&!x.getBoolean("scrollable")&&!x.getBoolean("password")
                    &&!x.getBoolean("focused"),"carousel carries another action state");
            if(x.getBoolean("visible")){int[] r=intRect(x);need(contains(box,r),"visible old carousel escaped its container");oldCover.add(r);}
            if(y.getBoolean("visible")){int[] r=intRect(y);need(contains(box,r),"visible new carousel escaped its container");newCover.add(r);}
            if(!WebDomCanonical.same(x,y))changes.put(new JSONObject().put("native_path",path).put("before",x).put("after",y));
        }
        need(sameCoverage(oldCover,newCover,targetBox),"observed carousel overlap with booking changed");
        double cx=((double)targetBox[0]+targetBox[2])/2,cy=((double)targetBox[1]+targetBox[3])/2;
        need(!covered(oldCover,cx,cy)&&!covered(newCover,cx,cy),"observed carousel covers the booking interior");
        return new JSONObject().put("schema","hepta.csair-home-native-scope.v1")
                .put("scope","complete_native_tree_except_observed_carousel_geometry")
                .put("native_target_path",targetPath).put("native_slider_path",slider)
                .put("native_booking_path",booking).put("before",before).put("after",after)
                .put("changes",changes).put("all_non_carousel_records_equal_by_native_path",true)
                .put("ordinal_node_ids_used_for_rebinding",false)
                .put("existing_target_overlap_unchanged",true)
                .put("existing_target_overlap",intersections(oldCover,targetBox))
                .put("observed_target_interior_clear",true).put("fully_unoccluded_claimed",false)
                .put("coordinates_used_for_input",false).put("business_verified",false);
    }

    static JSONObject compareRetained(JSONArray before,JSONArray after,String sliderPath)throws Exception{
        Map<String,JSONObject> a=retained(before),b=retained(after);JSONArray ordinalChanges=new JSONArray();
        Set<String> paths=new TreeSet<String>();paths.addAll(a.keySet());paths.addAll(b.keySet());
        for(String path:paths){
            if(path.startsWith(sliderPath+"/"))continue;
            JSONObject x=a.get(path),y=b.get(path);
            need(x!=null&&y!=null&&WebDomCanonical.same(without(x,"id"),without(y,"id")),
                    "non-carousel retained native semantics or signature changed");
            if(!x.getString("id").equals(y.getString("id")))ordinalChanges.put(new JSONObject()
                    .put("native_path",path).put("original_model_node_id",x.get("id")).put("fresh_ordinal_node_id",y.get("id")));
        }
        return new JSONObject().put("all_non_carousel_records_equal_except_ordinal_id",true)
                .put("ordinal_changes",ordinalChanges).put("original_node_ref_rebound",false);
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
    private static Map<String,JSONObject> domNodes(JSONObject dom)throws Exception{
        need("https://m.csair.com/".equals(dom.get("href"))&&"complete".equals(dom.get("ready_state"))
                &&Boolean.FALSE.equals(dom.get("truncated")),"complete official homepage DOM required");
        JSONArray nodes=dom.getJSONArray("nodes");need(nodes.length()>0&&nodes.length()<=1024,"homepage DOM budget");
        Map<String,JSONObject> out=new TreeMap<String,JSONObject>();
        for(int i=0;i<nodes.length();i++){
            JSONObject n=nodes.getJSONObject(i);String path=n.getString("path");
            need(path.matches("0(?:/(?:0|[1-9][0-9]{0,5})){0,127}")&&out.put(path,n)==null,"duplicate DOM path");
        }
        return out;
    }
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
    private static String ancestorClass(Map<String,JSONObject> nodes,String path,String clazz)throws Exception{
        String p=parent(path);
        while(!p.isEmpty()){JSONObject n=nodes.get(p);need(n!=null,"native ancestor missing");
            if(clazz.equals(n.get("class")))return p;p=parent(p);}
        return null;
    }
    private static JSONObject without(JSONObject value,String...keys)throws Exception{
        JSONObject copy=new JSONObject(WebDomCanonical.canonical(value));for(String key:keys)copy.remove(key);return copy;
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
    private static String key(ActionDecision action){return action.action+"\n"+(action.nodeId==null?"":action.nodeId);}
    private static boolean covered(List<int[]> rects,double x,double y){
        for(int[] r:rects)if(x>=r[0]&&x<r[2]&&y>=r[1]&&y<r[3])return true;return false;
    }
    private static boolean sameCoverage(List<int[]> before,List<int[]> after,int[] target){
        Set<Integer> xs=new TreeSet<Integer>(),ys=new TreeSet<Integer>();
        xs.add(target[0]);xs.add(target[2]);ys.add(target[1]);ys.add(target[3]);
        for(List<int[]> values:java.util.Arrays.asList(before,after))for(int[] r:values){
            xs.add(Math.max(target[0],Math.min(target[2],r[0])));xs.add(Math.max(target[0],Math.min(target[2],r[2])));
            ys.add(Math.max(target[1],Math.min(target[3],r[1])));ys.add(Math.max(target[1],Math.min(target[3],r[3])));
        }
        List<Integer> x=new ArrayList<Integer>(xs),y=new ArrayList<Integer>(ys);
        for(int i=1;i<x.size();i++)for(int j=1;j<y.size();j++){
            double px=((double)x.get(i-1)+x.get(i))/2,py=((double)y.get(j-1)+y.get(j))/2;
            if(covered(before,px,py)!=covered(after,px,py))return false;
        }return true;
    }
    private static JSONArray intersections(List<int[]> rects,int[] target)throws Exception{
        JSONArray out=new JSONArray();Set<String> seen=new HashSet<String>();
        for(int[] r:rects){int[] c={Math.max(r[0],target[0]),Math.max(r[1],target[1]),Math.min(r[2],target[2]),Math.min(r[3],target[3])};
            if(c[0]<c[2]&&c[1]<c[3]&&seen.add(java.util.Arrays.toString(c)))out.put(new JSONArray(c));}return out;
    }
    private static void need(boolean condition,String message){if(!condition)throw new IllegalArgumentException(message);}
}
