package org.trillionnium.hepta.local;

import android.graphics.Rect;
import android.view.accessibility.AccessibilityNodeInfo;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.json.JSONObject;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/** Actual old/new production traversal on a separately captured XML topology.
 * Android IO is synthetic: XML has no actual action list, visibility or editable
 * query. No phone, native model, click, scroll or business completion is tested. */
public final class ObservationCollectionHostTest {
    private static final String PACKAGE="com.zui.browser";
    private static final String XML_SHA="019d38ed44e7c0fa118bb9e596703053c594427d46a8b04e74409d9cf880c598";
    private static final Pattern BOUNDS=Pattern.compile("\\[(-?\\d+),(-?\\d+)\\]\\[(-?\\d+),(-?\\d+)\\]");
    private static int checks;
    private interface Checked {void run()throws Exception;}
    private static void check(boolean value,String why){checks++;if(!value)throw new AssertionError(why);}
    private static void invalid(Checked action)throws Exception{
        boolean refused=false;try{action.run();}catch(IllegalArgumentException expected){refused=true;}
        check(refused,"invalid collection facts must fail closed");
    }
    private static Rect bounds(String text){
        Matcher m=BOUNDS.matcher(text);if(!m.matches())throw new AssertionError("bad archived bounds");
        return new Rect(Integer.parseInt(m.group(1)),Integer.parseInt(m.group(2)),Integer.parseInt(m.group(3)),Integer.parseInt(m.group(4)));
    }
    private static final class XmlProjection {
        final List<AccessibilityNodeInfo> all=new ArrayList<AccessibilityNodeInfo>();
        final AccessibilityNodeInfo root;
        XmlProjection(Path file)throws Exception{
            byte[] bytes=Files.readAllBytes(file);
            check(bytes.length==366281&&XML_SHA.equals(ObservedImeEnter.hash(new String(bytes,StandardCharsets.UTF_8))),"original independent terminal XML exact bytes");
            DocumentBuilderFactory f=DocumentBuilderFactory.newInstance();
            f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING,true);
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
            f.setFeature("http://xml.org/sax/features/external-general-entities",false);
            f.setFeature("http://xml.org/sax/features/external-parameter-entities",false);
            f.setXIncludeAware(false);f.setExpandEntityReferences(false);
            Element document=f.newDocumentBuilder().parse(file.toFile()).getDocumentElement();
            Element first=null;NodeList children=document.getChildNodes();
            for(int i=0;i<children.getLength();i++)if(children.item(i) instanceof Element){
                check(first==null,"one XML application root");first=(Element)children.item(i);
            }
            check(first!=null,"archived root exists");root=read(first);
            root.window.root=root;root.window.bounds=new Rect(root.bounds);root.window.display=0;
            for(AccessibilityNodeInfo node:all)node.window=root.window;
            check(all.size()==975,"whole independent archived tree, not either model-bound flat list");
        }
        private AccessibilityNodeInfo read(Element e){
            check("node".equals(e.getTagName()),"only archived accessibility XML nodes");
            AccessibilityNodeInfo n=new AccessibilityNodeInfo(e.getAttribute("package"),7);
            n.text=e.getAttribute("text");n.description=e.getAttribute("content-desc");
            n.className=e.getAttribute("class");n.viewId=e.getAttribute("resource-id");n.bounds=bounds(e.getAttribute("bounds"));
            n.clickable=Boolean.parseBoolean(e.getAttribute("clickable"));n.scrollable=Boolean.parseBoolean(e.getAttribute("scrollable"));
            n.enabled=Boolean.parseBoolean(e.getAttribute("enabled"));n.password=Boolean.parseBoolean(e.getAttribute("password"));
            n.focused=Boolean.parseBoolean(e.getAttribute("focused"));
            // These queries are absent from XML. They are explicitly unknown or
            // a declared host projection assumption, never observed capabilities.
            n.visible=true;n.editable=false;n.actionListUnknown=true;n.actionOverride=null;
            all.add(n);NodeList children=e.getChildNodes();
            for(int i=0;i<children.getLength();i++)if(children.item(i) instanceof Element)n.children.add(read((Element)children.item(i)));
            return n;
        }
        void noEffects(){for(AccessibilityNodeInfo n:all)check(n.actions==0,"XML replay never dispatches Android actions");}
    }
    private static PhoneObservation.Node find(PhoneObservation frame,String view){
        for(PhoneObservation.Node n:frame.nodes)if(view.equals(n.viewId))return n;
        return null;
    }
    private static AccessibilityNodeInfo root(){
        AccessibilityNodeInfo n=new AccessibilityNodeInfo(PACKAGE,7);n.clickable=false;n.focused=false;n.viewId="synthetic:id/root";
        n.text="";n.description="";n.actionListUnknown=true;n.bounds=new Rect(0,0,1080,2400);
        n.window.root=n;n.window.bounds=new Rect(n.bounds);return n;
    }
    private static PhoneObservation capture(AccessibilityNodeInfo root){
        BackgroundObservationFixture f=new BackgroundObservationFixture();f.foreground=root;return f.snapshot();
    }
    private static AccessibilityNodeInfo child(AccessibilityNodeInfo root,String text,String description,int index){
        AccessibilityNodeInfo n=new AccessibilityNodeInfo(PACKAGE,7);n.clickable=false;n.focused=false;n.text=text;n.description=description;
        n.viewId="synthetic:id/"+index;n.actionListUnknown=true;n.window=root.window;root.children.add(n);return n;
    }
    private static String repeat(char value,int count){char[] result=new char[count];Arrays.fill(result,value);return new String(result);}
    private static JSONObject replay(Path fixture)throws Exception{
        XmlProjection oldTree=new XmlProjection(fixture),newTree=new XmlProjection(fixture);
        LegacyObservationFixture oldCollector=new LegacyObservationFixture();oldCollector.foreground=oldTree.root;
        BackgroundObservationFixture collector=new BackgroundObservationFixture();collector.foreground=newTree.root;
        PhoneObservation old=oldCollector.snapshot(),current=collector.snapshot();
        String late="header_submit_btn";
        check(old.nodesTruncated&&old.collectionStats==null,"old actual method hits its cap; unavailable historical counters remain unknown");
        check(find(old,late)==null,"old acquisition does not reach the independently archived later control");
        PhoneObservation.Node reached=find(current,late);
        check(reached!=null&&"搜索".equals(reached.text)&&reached.clickable,"new bounded traversal preserves the real later XML attributes");
        check(current.collectionStats!=null&&current.collectionStats.visited==975&&!current.nodesTruncated,"new traversal covers this finite XML projection");
        check(current.collectionStats.pending==0&&current.collectionStats.childSlotsOmitted==0&&current.collectionStats.limitReasons.isEmpty(),"actual counters describe completed projection acquisition");
        check(current.nodes.size()>old.nodes.size()&&current.nodes.size()<=128&&current.collectionStats.textUtf16<6144,"retained rows and text still have independent limits");
        for(PhoneObservation.Node n:current.nodes){
            check(!n.scrollActions.observed&&!n.scrollActions.hasAny()&&!n.submitAvailable&&!n.editable,"XML does not manufacture platform scroll/IME/edit capabilities");
            JSONObject row=n.json();check(n.packageName.equals(row.getString("package"))&&n.className.equals(row.getString("class_name")),"archived node includes its actual sampled namespace and class facts");
        }
        PhoneObservation same=collector.snapshot();
        check(current.treeSha256.equals(same.treeSha256)&&current.state.appTreeSha256.equals(same.state.appTreeSha256),"collection timing is not a fabricated visible tree change");
        oldTree.noEffects();newTree.noEffects();
        return new JSONObject().put("old_rows",old.nodes.size()).put("new_rows",current.nodes.size()).put("new_collection",current.collectionStats.json())
                .put("same_time_as_model_bound_frames",false).put("android_queries_are_fakes",true).put("action_lists_observed",false);
    }
    private static void boundedCounters()throws Exception{
        AccessibilityNodeInfo rows=root();for(int i=0;i<140;i++)child(rows,"label-"+i,"",i);
        PhoneObservation retained=capture(rows);PhoneObservation.CollectionStats s=retained.collectionStats;
        check(s.visited==141&&s.retained==128&&s.nodeBudgetOmissions==12&&s.textBudgetOmissions==0,"row limit counts actual useful nodes rejected during traversal");
        check(s.limitReasons.equals(Collections.singletonList("node_limit"))&&retained.nodesTruncated,"row reason is distinct from acquisition and text bounds");
        AccessibilityNodeInfo text=root();for(int i=0;i<100;i++)child(text,repeat('x',96),repeat('y',96),i);
        PhoneObservation words=capture(text);s=words.collectionStats;
        check(s.visited==101&&s.retained==31&&s.textUtf16==5952&&s.textBudgetOmissions==69&&s.nodeBudgetOmissions==0,"exclusive text limit records complete rejected row count");
        check(s.limitReasons.equals(Collections.singletonList("text_limit")),"text reason never pretends traversal was cut off");
        AccessibilityNodeInfo many=root();for(int i=0;i<1600;i++)child(many,"","",i);
        PhoneObservation traversal=capture(many);s=traversal.collectionStats;
        check(s.visited==1536&&s.retained==0&&s.childSlotsOmitted==65&&s.pending==0&&s.limitReasons.equals(Collections.singletonList("traversal_limit")),"structural child-slot omission is explicit, not an invented descendant total");
        JSONObject archived=s.json();check(!archived.getBoolean("unvisited_descendant_count_known")&&!archived.getBoolean("grants_action_capability"),"counter evidence neither invents a total nor grants actions");
        PhoneObservation legacy=new PhoneObservation(retained.id,retained.packageName,retained.capturedElapsedMillis,retained.width,retained.height,
                retained.rotation,retained.windowId,retained.windowBounds,retained.screenshot,retained.screenshotSha256,retained.treeSha256,
                retained.state,retained.windowMetadata,retained.nodesTruncated,retained.nodes);
        check(legacy.collectionStats==null&&legacy.toJson().isNull("collection"),"legacy observations never acquire guessed collection counters");
        invalid(()->new PhoneObservation.CollectionStats(1536,128,6144,1537,0,0,0,0,0,0,0));
        invalid(()->new PhoneObservation.CollectionStats(1536,128,6144,0,0,6144,0,0,0,0,0));
        invalid(()->new PhoneObservation.CollectionStats(1536,128,6144,0,0,0,0,-1,0,0,0));
        PhoneObservation.CollectionStats mismatch=new PhoneObservation.CollectionStats(1536,128,6144,1,1,1,0,0,0,0,0);
        invalid(()->new PhoneObservation(retained.id,retained.packageName,retained.capturedElapsedMillis,retained.width,retained.height,
                retained.rotation,retained.windowId,retained.windowBounds,retained.screenshot,retained.screenshotSha256,retained.treeSha256,
                retained.state,retained.windowMetadata,retained.nodesTruncated,retained.nodes,null,null,Collections.<String>emptyList(),mismatch));
    }
    public static void main(String[] args)throws Exception{
        Path fixture=Paths.get(args[0]),output=Paths.get(args[1]);JSONObject xml=replay(fixture);boundedCounters();
        JSONObject result=new JSONObject().put("schema","hepta.observation-collection-host.v1").put("passed",true).put("checks",checks)
                .put("xml_projection",xml).put("phone_tested",false).put("native_inference",false).put("business_goal_verified",false);
        Files.write(output,result.toString(2).getBytes(StandardCharsets.UTF_8));
        System.out.println("PASS "+checks+" actual collection assertions; XML is a separate snapshot; phone_tested=false");
    }
}
