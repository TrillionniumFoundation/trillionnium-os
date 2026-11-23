package org.trillionnium.hepta.local;
import android.graphics.Rect;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import org.trillionnium.hepta.webprotocol.WebTaskPurpose;

/** Portable synthetic boundaries; optional original DOM/AX replay has a synthetic lease. */
public final class WebCalendarDisplayLabelHostTest {
    static final String OWNER="查一下2026年11月17日北京到上海的单程机票，1名成人";
    static final String HELPER=WebEvidenceProtocol.HELPER_PACKAGE,TASK="11111111111111111111111111111111",GEN="22345678-1234-1234-1234-123456789012";
    static final String HOLDER="0/1/0/0/0/1/2/0",MONTH=HOLDER+"/0",DAY=MONTH+"/1/0",PRICE=DAY+"/0";
    static final List<String> passed=new ArrayList<String>();static int assertions;
    interface Checked {void run()throws Exception;} interface Mutation {void apply(JSONObject d,List<PhoneObservation.Node> r)throws Exception;}
    static void check(boolean v,String why){assertions++;if(!v)throw new AssertionError(why);}
    static void test(String name,Checked body)throws Exception{body.run();passed.add(name);}
    static Object fixture(String name,Class<?>[] types,Object... args)throws Exception{
        Method m=WebTaskCompositionHostTest.class.getDeclaredMethod(name,types);m.setAccessible(true);
        try{return m.invoke(null,args);}catch(InvocationTargetException e){if(e.getCause() instanceof Exception)throw (Exception)e.getCause();throw e;}
    }
    static JSONObject node(String path,String tag,String text,boolean visible,int[] rect)throws Exception{
        JSONObject n=new JSONObject().put("path",path).put("parent_path","0".equals(path)?JSONObject.NULL:path.substring(0,path.lastIndexOf('/')))
                .put("tag",tag).put("text",text).put("visible_in_viewport",visible).put("rect_css_pixels",new JSONArray(rect));
        for(String k:new String[]{"id","role","name","aria_label","aria_hidden","aria_modal","aria_selected","aria_checked","aria_pressed","item_type","item_prop"})n.put(k,"");
        for(String k:new String[]{"disabled","hidden_attr","inert_attr","item_scope","iframe_contents_read"})n.put(k,false);
        for(String k:new String[]{"href_raw","href_resolved","link_target","value","aria_disabled"})n.put(k,JSONObject.NULL);return n;
    }
    static void add(JSONArray r,String p,String tag,String text)throws Exception{r.put(node(p,tag,text,true,new int[]{0,0,400,800}));}
    static JSONObject calendar()throws Exception{
        JSONObject d=(JSONObject)fixture("oldFixture",new Class<?>[]{String.class},"dom");
        d.put("href","https://m.csair.com/booking_new/#/newCalendar?depDate=2099-01-01&rangePicker=false");
        JSONArray r=new JSONArray();add(r,"0","html","");add(r,"0/0","head","");add(r,"0/1","body","");add(r,"0/1/0","div","");r.getJSONObject(3).put("id","root");
        for(String p:new String[]{"0/1/0/0","0/1/0/0/0","0/1/0/0/0/0","0/1/0/0/0/0/0","0/1/0/0/0/0/0/0"})add(r,p,"div","");
        add(r,"0/1/0/0/0/0/0/1","div","选择日期");add(r,"0/1/0/0/0/1","div","");add(r,"0/1/0/0/0/1/0","div","");add(r,"0/1/0/0/0/1/0/0","ul","");
        String[] w={"日","一","二","三","四","五","六"};for(int i=0;i<7;i++)add(r,"0/1/0/0/0/1/0/0/"+i,"li",w[i]);
        add(r,"0/1/0/0/0/1/1","div","");add(r,"0/1/0/0/0/1/2","div","");add(r,HOLDER,"div","");
        for(int i=0;i<2;i++){String m=HOLDER+"/"+i;add(r,m,"div","");add(r,m+"/0","h1","2026年"+(11+i)+"月");
            r.put(node(m+"/1","ul","",false,new int[]{0,0,400,0}));r.put(node(m+"/1/0","li","17",true,new int[]{0,0,100,100}));
            r.put(node(m+"/1/0/0","span","¥540",true,new int[]{0,20,100,40}));}
        return d.put("nodes",r).put("visited",r.length());
    }
    static JSONObject at(JSONObject d,String path)throws Exception{
        JSONArray r=d.getJSONArray("nodes");JSONObject n=null;for(int i=0;i<r.length();i++)if(path.equals(r.getJSONObject(i).getString("path"))){check(n==null,"fixture unique path");n=r.getJSONObject(i);}
        check(n!=null,"fixture path exists");return n;
    }
    static void sorted(JSONObject d)throws Exception{
        JSONArray old=d.getJSONArray("nodes");List<JSONObject> r=new ArrayList<JSONObject>();for(int i=0;i<old.length();i++)r.add(old.getJSONObject(i));
        Collections.sort(r,new Comparator<JSONObject>(){public int compare(JSONObject a,JSONObject b){String[] x=a.optString("path").split("/"),y=b.optString("path").split("/");
            for(int i=0;i<Math.min(x.length,y.length);i++){int c=Integer.compare(Integer.parseInt(x[i]),Integer.parseInt(y[i]));if(c!=0)return c;}return Integer.compare(x.length,y.length);}});
        d.put("nodes",new JSONArray(r)).put("visited",r.size());
    }
    static void removeBelow(JSONObject d,String path)throws Exception{
        JSONArray old=d.getJSONArray("nodes"),r=new JSONArray();for(int i=0;i<old.length();i++)if(!old.getJSONObject(i).getString("path").startsWith(path+"/"))r.put(old.getJSONObject(i));
        d.put("nodes",r).put("visited",r.length());
    }
    static PhoneObservation.Node ax(String id,String text,String type,String path,String parent,boolean click,Rect b)throws Exception{
        return new PhoneObservation.Node(id,HELPER,type,"",text,"",b,click,false,false,true,false,false,ObservedChildText.notApplicable(),
                ObservedScrollActions.observed(Collections.<String>emptyList()),ObservedImeEnter.UNKNOWN,null,false,WebEvidenceJson.sha("synthetic "+id+" "+text),path,parent);
    }
    static List<PhoneObservation.Node> rows()throws Exception{
        List<PhoneObservation.Node> r=new ArrayList<PhoneObservation.Node>();
        r.add(ax("n0","选择日期","android.widget.TextView","0/0/0","android.view.View",false,new Rect(400,400,700,450)));
        r.add(ax("n1","2026年11月","android.widget.TextView","0/1/0","android.view.View",false,new Rect(300,600,800,670)));
        r.add(ax("n2","17¥540","android.view.View","0/1/1/0","android.widget.ListView",true,new Rect(350,900,525,1100)));
        r.add(ax("n3","2026年12月","android.widget.TextView","0/1/2","android.view.View",false,new Rect(300,1800,800,1870)));
        r.add(ax("n4","17¥540","android.view.View","0/1/3/0","android.widget.ListView",true,new Rect(350,2000,525,2200)));return r;
    }
    static PhoneObservation.Node replace(PhoneObservation.Node n,String id,String text,String path,String parent,boolean enabled,Rect b)throws Exception{
        return new PhoneObservation.Node(id,n.packageName,n.className,n.viewId,text,n.description,b,n.clickable,n.editable,n.scrollable,enabled,n.focused,n.password,
                n.childText,n.scrollActions,n.imeEnter,n.inputTextSha256,n.submitAvailable,WebEvidenceJson.sha("synthetic "+id+" "+text),path,parent);
    }
    static PhoneObservation frame(List<PhoneObservation.Node> r)throws Exception{
        return new PhoneObservation("22222222222222222222222222222222",HELPER,1005,1224,2992,0,19,new Rect(0,0,1224,2992),null,WebEvidenceJson.sha("synthetic screen"),
                WebEvidenceJson.sha("synthetic graph"),new ObservationState(WebEvidenceJson.sha("synthetic tree"),ImeVisibility.HIDDEN),
                ObservedWindowMetadata.observed(new int[]{0,0,1224,2992},"android.widget.FrameLayout",1,7,new int[]{0,0,1224,2992},"synthetic owned lease"),false,r,GEN,HELPER,Collections.singletonList(HELPER));
    }
    static WebFlightDomain domain(String owner,JSONObject d,List<PhoneObservation.Node> r)throws Exception{
        JSONObject b=(JSONObject)fixture("binding",new Class<?>[]{String.class},owner);
        JSONObject raw=(JSONObject)fixture("rawCapture",new Class<?>[]{JSONObject.class,JSONObject.class,long.class,long.class},b,d,7L,1000L);
        WebEvidenceReceipt receipt=(WebEvidenceReceipt)fixture("receipt",new Class<?>[]{JSONObject.class,JSONObject.class},b,raw);
        WebTaskPurpose p=WebTaskPurpose.requireBinding(b);return WebTaskDomain.observed(TASK,p,p.authorization.bind(TASK),frame(r),receipt,b).flight;
    }
    static void denied(String name,Mutation mutate)throws Exception{
        test(name,()->{JSONObject d=calendar();List<PhoneObservation.Node> r=rows();mutate.apply(d,r);sorted(d);boolean denied=false;
            try{denied=domain(OWNER,d,r).clickIds.isEmpty();}catch(IllegalArgumentException expected){denied=true;}check(denied,"must withhold: "+name);});
    }
    public static void main(String[] args)throws Exception{
        String index=null;boolean probe=false;for(int i=0;i<args.length;i++)if("--actual-fixtures".equals(args[i]))index=args[++i];else if("--baseline-probe".equals(args[i]))probe=true;else throw new IllegalArgumentException("unknown argument");
        if(probe){check(domain(OWNER,calendar(),rows()).clickIds.isEmpty(),"baseline composite refusal");int n=actual(index,true);
            System.out.println(new JSONObject().put("baseline_refusal_reproduced",true).put("actual_replays",n).put("phone_actions",0));return;}
        test("priced_day_same_label_in_other_month",()->{
            WebFlightDomain d=domain(OWNER,calendar(),rows());check(d.clickIds.size()==1&&d.clickIds.contains("n2"),"priced calendar target must be admitted in its explicit month");
            Map<String,Object> c=d.capability("n2");check("17¥540".equals(c.get("expected_control_label")),"complete native label");
            ObservedTargetLabels labels=ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,d.observationId,HELPER,Collections.singletonMap("n2",ObservedTargetLabels.project((String)c.get("native_label"))));
            check(labels.matches(d.observationId,HELPER,"n2","17¥540")&&!labels.matches(d.observationId,HELPER,"n2","17"),"old bare label cannot substitute for the actual composite node label");
            check("2026-11-17".equals(c.get("observed_iso_date")),"literal date retained");check("same_frame_bound_month_list".equals(c.get("native_label_uniqueness_scope")),"target-month uniqueness");
            check(Boolean.FALSE.equals(c.get("price_annotation_is_flight_result"))&&!d.resultReady()&&d.queryCandidate==null,"annotation is not a flight result or query");
        });
        test("other_month_owner_binds_other_list",()->{WebFlightDomain d=domain(OWNER.replace("11月","12月"),calendar(),rows());check(d.clickIds.size()==1&&d.clickIds.contains("n4"),"December binds December list");});
        test("legacy_bare_day_strict",()->{JSONObject d=calendar();removeBelow(d,DAY);List<PhoneObservation.Node> r=rows();PhoneObservation.Node n=r.get(2);
            r.set(2,replace(n,n.id,"17",n.nativeTreePath,n.nativeParentClass,true,n.bounds));check(domain(OWNER,d,r).clickIds.contains("n2"),"legacy bare day works");
            n=r.get(4);r.set(4,replace(n,n.id,"17",n.nativeTreePath,n.nativeParentClass,true,n.bounds));check(domain(OWNER,d,r).clickIds.isEmpty(),"legacy global bare duplicate refuses");});
        denied("same_month_duplicate",(d,r)->{PhoneObservation.Node n=r.get(2);r.add(replace(n,"n5",n.text,"0/1/1/1",n.nativeParentClass,true,n.bounds));});
        denied("same_month_disabled_duplicate",(d,r)->{PhoneObservation.Node n=r.get(2);r.add(replace(n,"n5",n.text,"0/1/1/1",n.nativeParentClass,false,n.bounds));});
        denied("same_month_invalid_parent_duplicate",(d,r)->{PhoneObservation.Node n=r.get(2);r.add(replace(n,"n5",n.text,"0/1/1/1","android.view.View",true,n.bounds));});
        denied("same_month_wrong_class_duplicate",(d,r)->r.add(ax("n5","17¥540","android.widget.Button","0/1/1/1","android.widget.ListView",true,new Rect(350,900,525,1100))));
        denied("same_month_different_view_id_duplicate",(d,r)->{PhoneObservation.Node n=r.get(2);r.add(new PhoneObservation.Node("n5",n.packageName,n.className,"unexpected_id",n.text,n.description,n.bounds,
                n.clickable,n.editable,n.scrollable,n.enabled,n.focused,n.password,n.childText,n.scrollActions,n.imeEnter,null,false,n.observedAppTreeSignature,"0/1/1/1",n.nativeParentClass));});
        denied("only_wrong_month_target",(d,r)->r.remove(2));
        denied("nonadjacent_list",(d,r)->{PhoneObservation.Node n=r.get(2);r.set(2,replace(n,n.id,n.text,"0/1/4/0",n.nativeParentClass,true,n.bounds));});
        denied("not_list_parent",(d,r)->{PhoneObservation.Node n=r.get(2);r.set(2,replace(n,n.id,n.text,n.nativeTreePath,"android.view.View",true,n.bounds));});
        denied("missing_native_path",(d,r)->{PhoneObservation.Node n=r.get(2);r.set(2,replace(n,n.id,n.text,null,null,true,n.bounds));});
        denied("disabled_target",(d,r)->{PhoneObservation.Node n=r.get(2);r.set(2,replace(n,n.id,n.text,n.nativeTreePath,n.nativeParentClass,false,n.bounds));});
        denied("outside_webview",(d,r)->{PhoneObservation.Node n=r.get(2);r.set(2,replace(n,n.id,n.text,n.nativeTreePath,n.nativeParentClass,true,new Rect(350,100,525,200)));});
        denied("wrong_native_month",(d,r)->{PhoneObservation.Node n=r.get(1);r.set(1,replace(n,n.id,"2027年11月",n.nativeTreePath,n.nativeParentClass,true,n.bounds));});
        denied("duplicate_native_heading",(d,r)->{PhoneObservation.Node n=r.get(1);r.add(replace(n,"n5",n.text,"0/9/0",n.nativeParentClass,true,n.bounds));});
        denied("surplus_price_span",(d,r)->d.getJSONArray("nodes").put(node(DAY+"/1","span","¥540",true,new int[]{0,40,100,60})));
        denied("surplus_text",(d,r)->d.getJSONArray("nodes").put(node(DAY+"/1","span","促销",true,new int[]{0,40,100,60})));
        denied("hidden_control",(d,r)->d.getJSONArray("nodes").put(node(DAY+"/1","button","继续",false,new int[]{0,0,0,0})));
        denied("nested_control",(d,r)->d.getJSONArray("nodes").put(node(PRICE+"/0","button","继续",true,new int[]{0,20,100,40})));
        for(String field:new String[]{"hidden_attr","inert_attr","disabled"}){final String f=field;denied("price_"+f,(d,r)->at(d,PRICE).put(f,true));}
        denied("aria_hidden_price",(d,r)->at(d,PRICE).put("aria_hidden","true"));
        denied("invisible_price",(d,r)->at(d,PRICE).put("visible_in_viewport",false));
        denied("price_button_role",(d,r)->at(d,PRICE).put("role","button"));
        denied("price_aria_label",(d,r)->at(d,PRICE).put("aria_label","继续"));
        denied("price_link",(d,r)->at(d,PRICE).put("href_raw","https://example.invalid"));
        denied("price_outside_cell",(d,r)->at(d,PRICE).put("rect_css_pixels",new JSONArray(new int[]{0,20,101,40})));
        test("missing_passive_fact_not_invented",()->{JSONObject d=calendar();at(d,PRICE).remove("hidden_attr");check(CsairCalendar.read(d).forDate("2026-11-17").target.evidence().get("observed_priced_display_label")==null,"missing fact cannot create composite label");});
        String[] bad={"540","¥540起","¥540继续","¥54.0","￥540","¥-540","¥0","","售罄"};for(int i=0;i<bad.length;i++){final String v=bad[i];denied("non_price_"+i,(d,r)->at(d,PRICE).put("text",v));}
        denied("nonnumeric_day",(d,r)->at(d,DAY).put("text","今天"));
        denied("wrong_dom_year",(d,r)->at(d,MONTH+"/0").put("text","2027年11月"));
        denied("wrong_dom_month",(d,r)->at(d,MONTH+"/0").put("text","2026年10月"));
        denied("duplicate_dom_day",(d,r)->d.getJSONArray("nodes").put(node(MONTH+"/1/1","li","17",true,new int[]{100,0,200,100})));
        denied("stale_native_price",(d,r)->at(d,PRICE).put("text","¥541"));
        test("fresh_full_label_changes_page_key",()->{WebFlightDomain old=domain(OWNER,calendar(),rows());JSONObject d=calendar();at(d,PRICE).put("text","¥541");
            List<PhoneObservation.Node> r=rows();PhoneObservation.Node n=r.get(2);r.set(2,replace(n,n.id,"17¥541",n.nativeTreePath,n.nativeParentClass,true,n.bounds));WebFlightDomain now=domain(OWNER,d,r);
            check(now.clickIds.contains("n2")&&!old.pageKey.equals(now.pageKey),"fresh label cannot reuse old page-key guard");});
        test("no_url_or_owner_date_inference",()->{JSONObject d=calendar();check(!CsairCalendar.read(d).forDate("2099-01-01").ready,"URL date not authoritative");
            check(domain(OWNER.replace("2026年","2027年"),d,rows()).clickIds.isEmpty(),"owner date without heading unavailable");});
        int actual=actual(index,false);
        System.out.println(new JSONObject().put("schema","hepta.calendar-display-label-host-test.v1").put("all_pass",true).put("synthetic_cases",passed.size())
                .put("assertions",assertions).put("cases",passed).put("actual_replays",actual).put("actual_replay_lease","synthetic; original DOM values and every native row retained")
                .put("phone_actions",0).put("live_binding_or_dispatch_tested",false).put("flight_results_verified",false));
    }
    static String exact(String path,String sha)throws Exception{
        byte[] bytes=Files.readAllBytes(Paths.get(path));check(WebEvidenceJson.sha(bytes).equals(sha),"exact private original SHA");return new String(bytes,StandardCharsets.UTF_8);
    }
    static int actual(String index,boolean baseline)throws Exception{
        if(index==null)return 0;JSONArray cases=new JSONObject(new String(Files.readAllBytes(Paths.get(index)),StandardCharsets.UTF_8)).getJSONArray("cases");
        for(int i=0;i<cases.length();i++){
            JSONObject c=cases.getJSONObject(i),raw=new JSONObject(exact(c.getString("raw_path"),c.getString("raw_sha256")));
            JSONObject d=new JSONObject(raw.getJSONObject("capture").getString("dom_raw_utf8")),a=new JSONObject(exact(c.getString("ax_path"),c.getString("ax_sha256")));
            check(CsairCalendar.read(d).forDate("2026-11-17").ready,"actual literal date already recognized");
            WebFlightDomain result=domain(OWNER,d,actualRows(a));check(baseline?result.clickIds.isEmpty():result.clickIds.size()==1&&result.clickIds.contains(c.getString("target_node_id")),
                    baseline?"baseline actual composite label refusal":"actual bound full-label capability");check(!result.resultReady(),"not a flight result proof");
        }return cases.length();
    }
    static List<PhoneObservation.Node> actualRows(JSONObject frame)throws Exception{
        List<PhoneObservation.Node> out=new ArrayList<PhoneObservation.Node>();JSONArray nodes=frame.getJSONArray("nodes");
        for(int i=0;i<nodes.length();i++){
            JSONObject n=nodes.getJSONObject(i),p=n.optJSONObject("native_tree_position");JSONArray b=n.getJSONArray("bounds");
            ObservedChildText.Result child=n.has("child_text_status")?new ObservedChildText.Result(n.optString("child_text",""),n.getString("child_text_status"),
                    n.getBoolean("child_text_truncated"),n.getInt("child_text_visited"),Collections.<ObservedChildText.Source>emptyList()):ObservedChildText.notApplicable();
            // Every label/path/state remains, including potential duplicates. Calendar admits own labels only, never descendant provenance.
            out.add(new PhoneObservation.Node(n.getString("id"),n.getString("package"),n.getString("class_name"),n.optString("view_id",""),n.optString("text",""),
                    n.optString("description",""),new Rect(b.getInt(0),b.getInt(1),b.getInt(2),b.getInt(3)),n.optBoolean("clickable",false),n.optBoolean("editable",false),
                    n.optBoolean("scrollable",false),n.optBoolean("enabled",true),n.optBoolean("focused",false),n.optBoolean("password",false),child,
                    ObservedScrollActions.observed(Collections.<String>emptyList()),ObservedImeEnter.UNKNOWN,null,false,n.optString("node_app_tree_sha256",null),
                    p==null?null:p.getString("path"),p==null?null:p.getString("parent_class")));
        }
        check(out.size()==nodes.length(),"every original native row retained");return out;
    }
}
