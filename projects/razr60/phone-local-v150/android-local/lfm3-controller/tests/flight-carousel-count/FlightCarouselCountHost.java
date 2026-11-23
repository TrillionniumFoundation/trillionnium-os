package org.trillionnium.hepta.local;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import org.json.*;
import org.trillionnium.hepta.webprotocol.*;
/** Pure synthetic policy tests, plus optional external raw DOM replay. No service authority. */
public final class FlightCarouselCountHost {
    static final String TARGET="0/0/1/0", SLIDER="0/0/0";
    static final JSONArray names=new JSONArray(); static int assertions;
    interface Work {void run() throws Exception;}
    static void check(boolean v,String why){assertions++;if(!v)throw new AssertionError(why);}
    static void test(String n,Work w)throws Exception{w.run();names.put(n);}
    static void denied(Work w)throws Exception{boolean no=false;try{w.run();}catch(IllegalArgumentException|IllegalStateException|JSONException e){no=true;}check(no,"invalid evidence accepted");}
    static JSONObject copy(JSONObject x){return new JSONObject(x.toString());}
    static JSONArray copy(JSONArray x){return new JSONArray(x.toString());}
    static JSONObject at(JSONArray rows,String path)throws Exception{for(int i=0;i<rows.length();i++)if(path.equals(rows.getJSONObject(i).getString("path")))return rows.getJSONObject(i);throw new IllegalArgumentException("missing fixture path");}
    static JSONArray drop(JSONArray rows,String path){JSONArray out=new JSONArray();for(int i=0;i<rows.length();i++){JSONObject n=rows.getJSONObject(i);String p=n.getString("path");if(!p.equals(path)&&!p.startsWith(path+"/"))out.put(n);}return out;}
    static JSONObject dom(int count)throws Exception{
        JSONObject d=FlightObservationBracketHost.dom();JSONArray rows=d.getJSONArray("nodes");
        for(int i=count;i<8;i++)rows=drop(rows,"0/0/"+i);
        if(count==9){JSONObject li=copy(at(rows,"0/0/0")),im=copy(at(rows,"0/0/0/0"));li.put("path","0/0/8").put("id","advertising8");im.put("path","0/0/8/0").put("parent_path","0/0/8");rows.put(li).put(im);}
        return d.put("nodes",rows).put("visited",rows.length());
    }
    static JSONObject shifted(JSONObject d)throws Exception{JSONObject out=copy(d);JSONArray rows=out.getJSONArray("nodes");for(int i=0;i<rows.length();i++){JSONObject n=rows.getJSONObject(i);String p=n.getString("path");if(p.equals("0/0")||p.startsWith("0/0/")){JSONArray r=n.getJSONArray("rect_css_pixels");r.put(0,r.getDouble(0)+20).put(2,r.getDouble(2)+20);}}return out;}
    static JSONArray nativeRows(int count,int visible)throws Exception{
        JSONArray rows=FlightObservationBracketHost.nativeTree(visible);
        for(int i=count;i<8;i++)rows=drop(rows,SLIDER+"/"+i);
        if(count==9){JSONObject li=copy(at(rows,SLIDER+"/0")),im=copy(at(rows,SLIDER+"/0/0"));li.put("path",SLIDER+"/8").put("view_id","advertising8");im.put("path",SLIDER+"/8/0");rows.put(li).put(im);}
        at(rows,SLIDER).put("children",count);return rows;
    }
    static JSONObject proof(int count)throws Exception{JSONObject d=dom(count);return WebFlightNativeStability.compareDom(d,shifted(d));}
    static JSONObject nativeProof(int count,JSONObject domProof)throws Exception{return WebFlightNativeStability.compareNative(nativeRows(count,0),nativeRows(count,1),TARGET,domProof);}
    static FlightObservationBracketHost.Pair pair(int domCount,int nativeCount)throws Exception{
        FlightObservationBracketHost.Pair p=new FlightObservationBracketHost.Pair();JSONObject d=dom(domCount);
        p.first=FlightObservationBracketHost.capture(p.binding,d,1000);p.last=FlightObservationBracketHost.capture(p.binding,shifted(d),1100);
        p.nativeBefore=nativeRows(nativeCount,0);p.nativeAfter=nativeRows(nativeCount,1);
        p.before=FlightObservationBracketHost.frame(p.binding,p.nativeBefore,"before");p.after=FlightObservationBracketHost.frame(p.binding,p.nativeAfter,"after");return p;
    }
    public static void main(String[] args)throws Exception{
        for(final int count:new int[]{7,8}){
            test("complete_"+count+"_dom_native_translation",()->{JSONObject d=proof(count),n=nativeProof(count,d);check(d.getInt("carousel_image_count")==count&&n.getInt("carousel_image_count")==count,"count");check(d.getJSONArray("changes").length()==1+2*count,"bounded changed scope");check(WebDomCanonical.same(d.get("carousel_ids"),n.get("carousel_ids")),"membership");});
            test("complete_"+count+"_observation_bracket",()->{JSONObject p=pair(count,count).verify();check(p.getJSONObject("dom").getInt("carousel_image_count")==count,"bracket count");check(!p.getBoolean("action_permit_created")&&!p.getBoolean("business_verified"),"read-only evidence only");});
        }
        test("observed_seven_id_order_is_not_assumed_sorted",()->{JSONObject d=dom(7);int[] order={6,4,3,2,1,0,5};for(int i=0;i<7;i++)at(d.getJSONArray("nodes"),"0/0/"+i).put("id","advertising"+order[i]);JSONObject p=WebFlightNativeStability.compareDom(d,shifted(d));check(p.getInt("carousel_image_count")==7,"seven set");});
        for(final int count:new int[]{6,9}){
            test("unsupported_dom_count_"+count,()->{JSONObject d=dom(count);denied(()->WebFlightNativeStability.compareDom(d,copy(d)));});
            test("unsupported_native_count_"+count,()->denied(()->nativeProof(count,proof(8))));
        }
        test("seven_dom_missing_continuous_id",()->{JSONObject d=dom(7);at(d.getJSONArray("nodes"),"0/0/6").put("id","advertising7");denied(()->WebFlightNativeStability.compareDom(d,copy(d)));});
        test("seven_dom_duplicate_id",()->{JSONObject d=dom(7);at(d.getJSONArray("nodes"),"0/0/6").put("id","advertising0");denied(()->WebFlightNativeStability.compareDom(d,copy(d)));});
        test("seven_native_missing_continuous_id",()->{JSONArray a=nativeRows(7,0);at(a,SLIDER+"/6").put("view_id","advertising7");denied(()->WebFlightNativeStability.compareNative(a,copy(a),TARGET,proof(7)));});
        test("seven_native_duplicate_id",()->{JSONArray a=nativeRows(7,0);at(a,SLIDER+"/6").put("view_id","advertising0");denied(()->WebFlightNativeStability.compareNative(a,copy(a),TARGET,proof(7)));});
        test("dom_before_after_count_change",()->denied(()->WebFlightNativeStability.compareDom(dom(7),dom(8))));
        test("native_before_after_count_change",()->denied(()->WebFlightNativeStability.compareNative(nativeRows(7,0),nativeRows(8,1),TARGET,proof(7))));
        test("dom_membership_same_count_changed",()->{JSONObject a=dom(7),b=copy(a);at(b.getJSONArray("nodes"),"0/0/0").put("id","advertising1");at(b.getJSONArray("nodes"),"0/0/1").put("id","advertising0");denied(()->WebFlightNativeStability.compareDom(a,b));});
        test("native_membership_same_count_changed",()->{JSONArray a=nativeRows(7,0),b=copy(a);at(b,SLIDER+"/0").put("view_id","advertising1");at(b,SLIDER+"/1").put("view_id","advertising0");denied(()->WebFlightNativeStability.compareNative(a,b,TARGET,proof(7)));});
        test("missing_dom_image",()->{JSONObject d=dom(7);d.put("nodes",drop(d.getJSONArray("nodes"),"0/0/4/0"));denied(()->WebFlightNativeStability.compareDom(d,copy(d)));});
        test("native_declared_children_disagree",()->{JSONArray a=nativeRows(7,0);at(a,SLIDER).put("children",8);denied(()->WebFlightNativeStability.compareNative(a,copy(a),TARGET,proof(7)));});
        test("seven_noncarousel_dom_change",()->{JSONObject a=dom(7),b=copy(a);at(b.getJSONArray("nodes"),"0/1").put("text","changed");denied(()->WebFlightNativeStability.compareDom(a,b));});
        test("seven_native_noncarousel_change",()->{JSONArray a=nativeRows(7,0),b=copy(a);at(b,TARGET).put("text","changed");denied(()->WebFlightNativeStability.compareNative(a,b,TARGET,proof(7)));});
        test("seven_mixed_native_window",()->{JSONArray a=nativeRows(7,0),b=copy(a);at(b,SLIDER+"/0").put("window_id",72);denied(()->WebFlightNativeStability.compareNative(a,b,TARGET,proof(7)));});
        test("required_pair_rejects_dom7_native8",()->denied(()->nativeProof(8,proof(7))));
        test("required_pair_rejects_dom8_native7",()->denied(()->nativeProof(7,proof(8))));
        test("required_pair_rejects_missing_dom_proof",()->denied(()->nativeProof(7,null)));
        test("required_pair_rejects_missing_membership",()->{JSONObject d=proof(7);d.remove("carousel_ids");denied(()->nativeProof(7,d));});
        test("required_pair_rejects_duplicate_membership",()->{JSONObject d=proof(7);d.getJSONArray("carousel_ids").put(6,"advertising0");denied(()->nativeProof(7,d));});
        test("required_pair_rejects_string_count",()->{JSONObject d=proof(7);d.put("carousel_image_count","7");denied(()->nativeProof(7,d));});
        test("required_pair_accepts_strict_parsed_long_count",()->{JSONObject d=proof(7);d.put("carousel_image_count",Long.valueOf(7));check(nativeProof(7,d).getInt("carousel_image_count")==7,"valid parsed Long count");});
        test("required_pair_rejects_double_count",()->{JSONObject d=proof(7);d.put("carousel_image_count",Double.valueOf(7.0));denied(()->nativeProof(7,d));});
        test("bracket_rejects_dom7_native8",()->denied(()->pair(7,8).verify()));
        test("bracket_rejects_dom8_native7",()->denied(()->pair(8,7).verify()));
        test("bracket_keeps_generation_gate",()->{FlightObservationBracketHost.Pair p=pair(7,7);JSONObject b=copy(p.last.getJSONObject("binding"));b.getJSONObject("background").put("generation","foreign");p.last.put("binding",b);denied(p::verify);});
        test("bracket_keeps_epoch_gate",()->{FlightObservationBracketHost.Pair p=pair(7,7);p.last.put("navigation_epoch",2);denied(p::verify);});
        for(int i=1;i<args.length;i++){final boolean reject=args[i].startsWith("reject:");final String path=reject?args[i].substring(7):args[i];final int index=i;test("external_complete_raw_dom_"+index+(reject?"_missing_aria_still_rejected":"_admitted"),()->{JSONObject raw=new JSONObject(new String(Files.readAllBytes(Paths.get(path)),StandardCharsets.UTF_8));JSONObject c=raw.getJSONObject("capture");String a=c.getString("before_dom_raw_utf8"),b=c.getString("dom_raw_utf8");check(a.equals(b),"original before/after full raws differ");JSONObject d=WebEvidenceJson.parseDom(a);if(reject){boolean refused=false;try{WebFlightNativeStability.compareDom(d,WebEvidenceJson.parseDom(b));}catch(IllegalArgumentException e){check("complete unchanged booking button missing".equals(e.getMessage()),"wrong rejection boundary for pre-aria capture");refused=true;}check(refused,"pre-aria capture was accepted");}else{JSONObject p=WebFlightNativeStability.compareDom(d,WebEvidenceJson.parseDom(b));check(p.getInt("carousel_image_count")==7,"actual seven-image fixture");check(p.getBoolean("whole_dom_equal"),"actual full raw equality");}});}
        JSONObject report=new JSONObject().put("schema","hepta.carousel-seven-eight-host.v1").put("all_pass",true).put("cases",names.length()).put("assertions",assertions).put("case_names",names).put("external_raw_replays",args.length-1).put("phone_operations",0).put("android_service_authority_tested",false).put("business_verified",false);
        Files.write(Paths.get(args[0]),(report.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);System.out.println(report.toString());
    }
}
