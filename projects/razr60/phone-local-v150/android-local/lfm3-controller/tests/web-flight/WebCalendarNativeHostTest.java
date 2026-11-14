package org.trillionnium.hepta.local;

import android.graphics.Rect;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebEvidenceBinding;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import org.trillionnium.hepta.webprotocol.WebTaskPurpose;

/**
 * Exact manual calendar DOM/AX originals inside an explicitly synthetic v3 lease.
 * This exercises production provider/receipt code, not Binder, A11y delivery or a device action.
 */
public final class WebCalendarNativeHostTest {
    private static final String OWNER="查一下2026年11月17日北京到上海的单程机票，1名成人";
    private static final String HELPER=WebEvidenceProtocol.HELPER_PACKAGE;
    private static final String TASK="11111111111111111111111111111111";
    private static final String GENERATION="22345678-1234-1234-1234-123456789012";
    private static final List<String> names=new ArrayList<String>();
    private static int assertions;
    private interface Checked{void run()throws Exception;}
    private static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    private static void test(String name,Checked body)throws Exception{body.run();names.add(name);}
    private static JSONObject binding(String owner)throws Exception{
        return (JSONObject)fixture("binding",new Class<?>[]{String.class},owner);
    }
    private static Object fixture(String name,Class<?>[] types,Object... args)throws Exception{
        Method m=WebTaskCompositionHostTest.class.getDeclaredMethod(name,types);m.setAccessible(true);
        try{return m.invoke(null,args);}catch(InvocationTargetException e){
            if(e.getCause() instanceof Exception)throw (Exception)e.getCause();throw e;
        }
    }
    private static String read(String path,String sha)throws Exception{
        byte[] raw=Files.readAllBytes(Paths.get(path));check(WebEvidenceJson.sha(raw).equals(sha),"exact original fixture SHA");
        return new String(raw,StandardCharsets.UTF_8);
    }
    private static JSONObject dom(String raw)throws Exception{
        JSONObject d=new JSONObject(new JSONObject(raw).getJSONObject("capture").getString("dom_raw_utf8"));
        // Explicit unit-only envelope adaptation. Every page node/value remains from the exact v2 observation.
        return d.put("schema","hepta.fixed-top-document-dom.v3");
    }
    private static List<PhoneObservation.Node> ax(String xml)throws Exception{
        DocumentBuilderFactory f=DocumentBuilderFactory.newInstance();
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
        f.setFeature("http://xml.org/sax/features/external-general-entities",false);
        f.setFeature("http://xml.org/sax/features/external-parameter-entities",false);
        f.setXIncludeAware(false);f.setExpandEntityReferences(false);
        Element hierarchy=f.newDocumentBuilder().parse(new java.io.ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8))).getDocumentElement();
        List<PhoneObservation.Node> rows=new ArrayList<PhoneObservation.Node>();
        NodeList children=hierarchy.getChildNodes();int roots=0;
        for(int i=0;i<children.getLength();i++)if(children.item(i) instanceof Element){
            roots++;visit((Element)children.item(i),"0","",rows);
        }
        check(roots==1,"one original XML active root");
        return rows;
    }
    private static boolean flag(Element e,String name){return "true".equals(e.getAttribute(name));}
    private static void visit(Element e,String path,String parentClass,List<PhoneObservation.Node> rows)throws Exception{
        java.util.regex.Matcher m=java.util.regex.Pattern.compile("\\[(-?[0-9]+),(-?[0-9]+)\\]\\[(-?[0-9]+),(-?[0-9]+)\\]")
                .matcher(e.getAttribute("bounds"));
        check(m.matches(),"original AX bounds shape");
        Rect bounds=new Rect(Integer.parseInt(m.group(1)),Integer.parseInt(m.group(2)),Integer.parseInt(m.group(3)),Integer.parseInt(m.group(4)));
        String text=e.getAttribute("text"),desc=e.getAttribute("content-desc"),type=e.getAttribute("class");
        // XML does not prove a new native visibility call. Positive rectangles are a unit-fixture projection only.
        if(bounds.left<bounds.right&&bounds.top<bounds.bottom&&
                (flag(e,"clickable")||flag(e,"scrollable")||!text.isEmpty()||!desc.isEmpty())){
            String id="xml"+rows.size(),pkg=e.getAttribute("package"),view=e.getAttribute("resource-id");
            rows.add(new PhoneObservation.Node(id,pkg,type,view,text,desc,bounds,flag(e,"clickable"),
                    false,flag(e,"scrollable"),flag(e,"enabled"),flag(e,"focused"),flag(e,"password"),
                    ObservedChildText.notApplicable(),ObservedScrollActions.observed(Collections.<String>emptyList()),
                    ObservedImeEnter.UNKNOWN,null,false,WebEvidenceJson.sha("synthetic AX projection "+path+" "+text),
                    path,parentClass));
        }
        NodeList children=e.getChildNodes();
        for(int i=0;i<children.getLength();i++)if(children.item(i) instanceof Element){
            Element child=(Element)children.item(i);String index=child.getAttribute("index");
            check(index.matches("0|[1-9][0-9]*"),"actual native child index");
            visit(child,path+"/"+index,type,rows);
        }
    }
    private static PhoneObservation frame(List<PhoneObservation.Node> rows)throws Exception{
        return new PhoneObservation("22222222222222222222222222222222",HELPER,1005,1224,2992,0,19,
                new Rect(0,0,1224,2992),null,WebEvidenceJson.sha("synthetic screen"),WebEvidenceJson.sha("synthetic graph"),
                new ObservationState(WebEvidenceJson.sha("synthetic app tree"),ImeVisibility.HIDDEN),
                ObservedWindowMetadata.observed(new int[]{0,0,1224,2992},"android.widget.FrameLayout",1,7,
                        new int[]{0,0,1224,2992},"synthetic owned lease"),false,rows,GENERATION,HELPER,Collections.singletonList(HELPER));
    }
    private static WebTaskDomain domain(String owner,JSONObject dom,List<PhoneObservation.Node> rows)throws Exception{
        JSONObject b=binding(owner),raw=(JSONObject)fixture("rawCapture",
                new Class<?>[]{JSONObject.class,JSONObject.class,long.class,long.class},b,dom,7L,1000L);
        WebEvidenceReceipt r=(WebEvidenceReceipt)fixture("receipt",new Class<?>[]{JSONObject.class,JSONObject.class},b,raw);
        WebTaskPurpose p=WebTaskPurpose.requireBinding(b);
        return WebTaskDomain.observed(TASK,p,p.authorization.bind(TASK),frame(rows),r,b);
    }
    private static PhoneObservation.Node replace(PhoneObservation.Node n,String path,String parent,boolean enabled,Rect rect,String id){
        return new PhoneObservation.Node(id,n.packageName,n.className,n.viewId,n.text,n.description,rect,n.clickable,n.editable,
                n.scrollable,enabled,n.focused,n.password,n.childText,n.scrollActions,n.imeEnter,n.inputTextSha256,n.submitAvailable,
                n.observedAppTreeSignature,path,parent);
    }
    private static List<PhoneObservation.Node> changed(List<PhoneObservation.Node> rows,PhoneObservation.Node old,PhoneObservation.Node next){
        List<PhoneObservation.Node> out=new ArrayList<PhoneObservation.Node>(rows);out.set(out.indexOf(old),next);return out;
    }
    public static void main(String[] argv)throws Exception{
        check(argv.length==4,"pending DOM, stable DOM, same-case AX, new result path");
        final String pendingRaw=read(argv[0],"386f86ef76923ce994574893bc05eec906f3ef839f32d8a77a68092e0115d986");
        final String stableRaw=read(argv[1],"f61fd86cb24b212c3434bb5eda1a4e29b65c06c22d3fc4238366f31a324dd7fa");
        final String xml=read(argv[2],"59d753e32edd620eb2e1fb0947c898df89eb7bf8dbc63dc4138a1636272b82ec");
        final JSONObject stable=dom(stableRaw),pending=dom(pendingRaw);
        final List<PhoneObservation.Node> rows=ax(xml);
        final PhoneObservation.Node day=rows.stream().filter(n->"17".equals(n.text)).findFirst().get();
        final PhoneObservation.Node heading=rows.stream().filter(n->"2026年11月".equals(n.text)).findFirst().get();
        check(rows.stream().filter(n->"17".equals(n.text)).count()==1,"only one positive-area 17 in the actual XML projection");
        final WebTaskDomain ready=domain(OWNER,stable,rows);
        test("literal_date_and_native_month_parent_intersection",()->{
            check(ready.flight!=null&&ready.clickIds.equals(Collections.singleton(day.id)),"one native 17, no guessed coordinates");
            JSONObject flight=new JSONObject(ready.evidence());
            check(!ready.resultReady()&&!flight.getBoolean("query_executed"),"calendar presence is neither query nor business completion");
        });
        test("old_complete_document_without_days_is_pending",()->{
            WebTaskDomain value=domain(OWNER,pending,rows);
            check(value.clickIds.isEmpty()&&"official_calendar_content_pending".equals(value.flight.phase),
                    "readyState complete and URL default date do not create a day");
        });
        test("native_position_not_present_in_legacy_node",()->check(domain(OWNER,stable,
                changed(rows,day,replace(day,null,null,true,day.bounds,day.id))).clickIds.isEmpty(),"legacy flat labels cannot authorize a date"));
        test("wrong_native_month_list",()->{
            String list=day.nativeTreePath.substring(0,day.nativeTreePath.lastIndexOf('/'));
            String foreign=list.substring(0,list.lastIndexOf('/')+1)+"3"+day.nativeTreePath.substring(day.nativeTreePath.lastIndexOf('/'));
            check(domain(OWNER,stable,changed(rows,day,replace(day,foreign,day.nativeParentClass,true,day.bounds,day.id))).clickIds.isEmpty(),
                    "same 17 under December cannot stand for November");
        });
        test("wrong_parent_class",()->check(domain(OWNER,stable,
                changed(rows,day,replace(day,day.nativeTreePath,"android.view.View",true,day.bounds,day.id))).clickIds.isEmpty(),
                "day must be a direct native ListView child"));
        test("month_heading_path_absent",()->check(domain(OWNER,stable,
                changed(rows,heading,replace(heading,null,null,true,heading.bounds,heading.id))).clickIds.isEmpty(),"label alone is insufficient"));
        test("month_heading_not_adjacent",()->check(domain(OWNER,stable,
                changed(rows,heading,replace(heading,heading.nativeTreePath.substring(0,heading.nativeTreePath.lastIndexOf('/')+1)+"5",
                        heading.nativeParentClass,true,heading.bounds,heading.id))).clickIds.isEmpty(),"actual preceding sibling required"));
        test("disabled_day",()->check(domain(OWNER,stable,
                changed(rows,day,replace(day,day.nativeTreePath,day.nativeParentClass,false,day.bounds,day.id))).clickIds.isEmpty(),"native disabled rejects"));
        test("duplicate_day_even_disabled",()->{
            List<PhoneObservation.Node> duplicate=new ArrayList<PhoneObservation.Node>(rows);
            duplicate.add(replace(day,day.nativeTreePath,day.nativeParentClass,false,day.bounds,"duplicate"));
            check(domain(OWNER,stable,duplicate).clickIds.isEmpty(),"count duplicate labels before native state filtering");
        });
        test("duplicate_month_heading",()->{
            List<PhoneObservation.Node> duplicate=new ArrayList<PhoneObservation.Node>(rows);
            duplicate.add(replace(heading,heading.nativeTreePath,heading.nativeParentClass,true,heading.bounds,"duplicate-month"));
            check(domain(OWNER,stable,duplicate).clickIds.isEmpty(),"month header remains unique");
        });
        test("empty_native_day_bounds",()->check(domain(OWNER,stable,
                changed(rows,day,replace(day,day.nativeTreePath,day.nativeParentClass,true,new Rect(349,2920,525,2920),day.id))).clickIds.isEmpty(),
                "zero-height native day never authorizes action"));
        test("another_requested_year_is_not_filled",()->check(domain(
                "查一下2027年11月17日北京到上海的单程机票，1名成人",stable,rows).clickIds.isEmpty(),"actual visible year is required"));
        test("native_path_record_is_not_authority",()->{
            JSONObject position=day.json().getJSONObject("native_tree_position");
            check(!position.getBoolean("grants_action_capability")&&day.nativeTreePath.equals(position.getString("path")),
                    "same traversal position is a fact, not a standalone action");
        });
        JSONObject result=new JSONObject().put("schema","hepta.csair-calendar-native-host.v1").put("all_pass",true)
                .put("cases",names.size()).put("assertions",assertions).put("case_names",new JSONArray(names))
                .put("actual_fixture_dom_nodes",stable.getJSONArray("nodes").length()).put("actual_fixture_ax_rows_projected",rows.size())
                .put("source_dom_schema","hepta.fixed-top-document-dom.v2").put("unit_envelope_schema","hepta.fixed-top-document-dom.v3")
                .put("lease_and_native_ref_signatures_synthetic",true).put("original_dom_values_preserved",true)
                .put("phone_actions",0).put("binder_authenticated",false).put("business_verified",false);
        Files.write(Paths.get(argv[3]),(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println("calendar native cases="+names.size()+" assertions="+assertions);
    }
}
