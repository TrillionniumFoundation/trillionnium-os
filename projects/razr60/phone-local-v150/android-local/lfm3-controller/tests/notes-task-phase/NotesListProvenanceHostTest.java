package org.trillionnium.hepta.local;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import android.graphics.Rect;
import org.json.JSONObject;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Frame;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Node;

/** Real saved manual UI topology through the production collector/provider.
 * XML flags and node identities are explicit host Reader IO. This is neither
 * an archived Hepta observation nor proof of a model-created/saved note. */
public final class NotesListProvenanceHostTest {
    private static final String SHA="56b5f62e246a9945c1c4c0e9eea1273eb44152014d3d272cd8769776185cb7db";
    private static final String P=NotesCompletionEvidence.NOTES;
    private static final String BODY="Hepta-v45r1-fa929fc0cc3c。购物清单：牛奶、鸡蛋、面包。";
    private static int checks,sequence;
    private static Document document;
    private static void check(boolean ok,String why){checks++;if(!ok)throw new AssertionError(why);}
    private static boolean yes(Element e,String name){return "true".equals(e.getAttribute(name));}
    private static List<Element> children(Element e){
        List<Element> out=new ArrayList<Element>();NodeList nodes=e.getChildNodes();
        for(int i=0;i<nodes.getLength();i++)if(nodes.item(i) instanceof Element)out.add((Element)nodes.item(i));return out;
    }
    private static int[] bounds(Element e){
        Matcher m=Pattern.compile("\\[([0-9]+),([0-9]+)\\]\\[([0-9]+),([0-9]+)\\]").matcher(e.getAttribute("bounds"));
        if(!m.matches())throw new AssertionError("actual bounds missing");
        return new int[]{Integer.parseInt(m.group(1)),Integer.parseInt(m.group(2)),Integer.parseInt(m.group(3)),Integer.parseInt(m.group(4))};
    }
    private static String identity(Element e){
        StringBuilder s=new StringBuilder("host-xml-node-io:");
        for(String k:Arrays.asList("index","package","class","resource-id","bounds","text","content-desc","enabled","clickable","scrollable","password"))
            s.append(k).append('=').append(e.getAttribute(k)).append('\u0001');
        return ObservedImeEnter.hash(s.toString());
    }
    private static final ObservedChildText.Reader<Element> READER=new ObservedChildText.Reader<Element>(){
        public ObservedChildText.Metadata metadata(Element e){
            boolean edit=e.getAttribute("class").endsWith("EditText"),click=yes(e,"clickable");
            return new ObservedChildText.Metadata(true,P.equals(e.getAttribute("package")),click,click,edit,yes(e,"password"),
                    click||edit||yes(e,"long-clickable")||yes(e,"scrollable")||yes(e,"checkable"));
        }
        public String text(Element e){return e.getAttribute("text");}
        public String description(Element e){return e.getAttribute("content-desc");}
        public String identity(Element e){return NotesListProvenanceHostTest.identity(e);}
        public String viewId(Element e){return e.getAttribute("resource-id");}
        public int childCount(Element e){return children(e).size();}
        public Element child(Element e,int i){return children(e).get(i);}
        public void release(Element e){}
    };
    private static List<Element> ids(String suffix){
        List<Element> out=new ArrayList<Element>();NodeList all=document.getElementsByTagName("node");
        for(int i=0;i<all.getLength();i++){Element e=(Element)all.item(i);if((P+":id/"+suffix).equals(e.getAttribute("resource-id")))out.add(e);}return out;
    }
    private static Element leaf(Element root,String suffix){
        NodeList all=root.getElementsByTagName("node");
        for(int i=0;i<all.getLength();i++){Element e=(Element)all.item(i);if((P+":id/"+suffix).equals(e.getAttribute("resource-id")))return e;}
        throw new AssertionError("missing actual "+suffix);
    }
    private static Node node(String id,Element e,ObservedChildText.Result child,String bound){
        String text=e.getAttribute("text"),label=ObservedChildText.displayLabel(text,e.getAttribute("content-desc"),child);
        return new Node(id,e.getAttribute("package"),text,label,e.getAttribute("resource-id"),null,bounds(e),false,yes(e,"clickable"),yes(e,"scrollable"),yes(e,"enabled"),yes(e,"password"),child,bound);
    }
    private static Node node(String id,Element e){ObservedChildText.Result child=ObservedChildText.collect(e,READER);return node(id,e,child,child.bind(identity(e)));}
    private static Frame frame(Node... cards){
        List<Node> nodes=new ArrayList<Node>();nodes.add(node("n0",ids("title_text").get(0)));nodes.add(node("n1",ids("view_pager2").get(0)));nodes.addAll(Arrays.asList(cards));
        return new Frame(String.format(java.util.Locale.ROOT,"%032x",++sequence),P,7,0,null,1,true,false,nodes);
    }
    private static Element copy(Element e){return (Element)e.cloneNode(true);}
    private static boolean list(Element card,String body){return NotesCompletionEvidence.list(frame(node("n2",card)),body).matched;}
    private static void actualBridge(Frame source)throws Exception{
        List<PhoneObservation.Node> rows=new ArrayList<PhoneObservation.Node>();
        for(Node n:source.nodes)rows.add(new PhoneObservation.Node(n.id,n.packageName,"",n.viewId,n.text,"",new Rect(n.left,n.top,n.right,n.bottom),
                n.clickable,n.editable,n.scrollable,n.enabled,false,n.password,n.childText,ObservedScrollActions.UNKNOWN,ObservedImeEnter.UNKNOWN,
                n.inputTextSha256,false,n.observedAppTreeSignature));
        PhoneObservation observed=new PhoneObservation(source.observationId,P,1,1224,2992,0,7,new Rect(0,0,1224,2992),
                new File("manual-XML-host-envelope-not-a-phone-frame"),ObservedImeEnter.hash("host screenshot IO"),ObservedImeEnter.hash("host graph IO"),
                new ObservationState(ObservedImeEnter.hash("host app tree IO"),ImeVisibility.HIDDEN),
                ObservedWindowMetadata.observed(new int[]{0,0,1224,2992},"FrameLayout",1,0,new int[]{0,0,1224,2992},"Moto 笔记"),false,rows);
        Method bridge=LocalTaskController.class.getDeclaredMethod("completionFrame",PhoneObservation.class);bridge.setAccessible(true);
        Frame bridged=(Frame)bridge.invoke(null,observed);
        check(NotesCompletionEvidence.list(bridged,BODY).matched,"actual controller bridge carries complete summary proof");
        for(int i=0;i<rows.size();i++)check(bridged.nodes.get(i).childText==rows.get(i).childText
                &&java.util.Objects.equals(bridged.nodes.get(i).observedAppTreeSignature,rows.get(i).observedAppTreeSignature),"bridge preserves same-node provenance identity");
        JSONObject recorded=rows.get(2).json();
        check(recorded.getBoolean("child_text_sources_complete")&&recorded.getInt("child_text_visited")==4
                &&recorded.getString("child_text_root_signature").equals(rows.get(2).childText.rootSignature)
                &&recorded.getString("node_app_tree_sha256").equals(rows.get(2).observedAppTreeSignature),"private observation preserves every completeness/root condition");
        check(recorded.getJSONArray("child_text_sources").getJSONObject(2).getString("view_id").equals(P+":id/note_summary"),"private observation preserves actual summary source resource ID");
    }
    public static void main(String[] args)throws Exception{
        byte[] raw=Files.readAllBytes(Paths.get(args[0]));check(SHA.equals(ObservedImeEnter.hash(new String(raw,StandardCharsets.UTF_8))),"exact manual XML hash");
        DocumentBuilderFactory factory=DocumentBuilderFactory.newInstance();factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
        document=factory.newDocumentBuilder().parse(new ByteArrayInputStream(raw));
        check(ids("title_text").size()==1&&ids("view_pager2").size()==1&&ids("note_item_content").size()==2,"real list has unique header/pager and two cards");
        Element first=ids("note_item_content").get(0),second=ids("note_item_content").get(1);
        check(first.getAttribute("text").isEmpty()&&first.getAttribute("content-desc").isEmpty()&&yes(first,"clickable"),"actual executable card is unlabeled");
        ObservedChildText.Result collected=ObservedChildText.collect(first,READER);
        check("文字笔记 · 今天 · ".concat(BODY).equals(collected.text),"actual composite label follows original collector joins");
        check(!collected.truncated&&collected.sourcesComplete&&collected.sources.size()==3&&collected.visited==4,"actual three-source subtree is complete");
        check(identity(first).equals(collected.rootSignature)&&"0/2".equals(collected.sources.get(2).descendantPath),"actual root and nested summary path recorded");
        check((P+":id/note_summary").equals(collected.sources.get(2).viewId)&&ObservedImeEnter.hash(BODY).equals(collected.sources.get(2).textSha256),"full raw accessible summary is source-bound");
        Node real=node("n2",first),other=node("n3",second);NotesCompletionEvidence.ListEvidence evidence=NotesCompletionEvidence.list(frame(real,other),BODY);
        check(evidence.matched&&"n2".equals(evidence.item.nodeId)&&"bound_note_summary_accessibility_text".equals(evidence.matchRule),"real summary identifies one executable card");
        check(evidence.evidence().get("text_scope").equals(NotesCompletionEvidence.LIST_TEXT_SCOPE),"proof does not claim all visual characters were displayed");
        actualBridge(frame(real,other));
        check(PromptActionDomain.textOnlyClickLabel("","",collected),"existing text-only click gate remains independent and accepts real labeled descendants");
        Node borrowed=node("n3",second,collected,other.observedAppTreeSignature);
        check(!NotesCompletionEvidence.list(frame(borrowed),BODY).matched,"another row cannot borrow the first row's child proof");
        Node wrongParent=node("n2",first,collected,collected.bind(ObservedImeEnter.hash("wrong parent")));
        check(!NotesCompletionEvidence.list(frame(wrongParent),BODY).matched,"independent parent signature must match");
        ObservedChildText.Result historical=new ObservedChildText.Result(collected.text,"derived",false,collected.visited,collected.sources);
        check(!NotesCompletionEvidence.list(frame(node("n2",first,historical,real.observedAppTreeSignature)),BODY).matched,"legacy result without captured root is unknown");
        check(!NotesCompletionEvidence.list(frame(real,node("n9",first)),BODY).matched,"two matching executable cards are ambiguous");
        Element changed=copy(first);leaf(changed,"note_summary").setAttribute("text",BODY+" ");
        check(!list(changed,BODY),"raw source SHA never trims requested body");
        changed=copy(first);Element summary=leaf(changed,"note_summary");summary.setAttribute("text","");summary.setAttribute("content-desc",BODY);
        check(!list(changed,BODY),"description is not a summary text source");
        changed=copy(first);leaf(changed,"note_summary").setAttribute("resource-id",P+":id/note_title");
        check(!list(changed,BODY),"a body hash in a title field cannot become a summary");
        check(!list(first,"今天")&&!list(first,"文字笔记"),"date/title collisions never prove the body");
        for(String only:new String[]{"note_title","note_date"}){
            changed=copy(first);
            for(String id:new String[]{"note_title","note_date","note_summary"})if(!only.equals(id))leaf(changed,id).setAttribute("text","");
            String body=only.equals("note_title")?"文字笔记":"今天";
            check(body.equals(ObservedChildText.collect(changed,READER).text)&&!list(changed,body),"derived exact label cannot fall back around summary provenance");
        }
        changed=copy(first);leaf(changed,"contentRoot").setAttribute("clickable","true");
        check(!list(changed,BODY),"interactive descendant subtree cannot lend a label");
        changed=copy(first);leaf(changed,"note_summary").setAttribute("package","com.example.foreign");
        check(!list(changed,BODY),"foreign descendant source is outside scope");
        changed=copy(first);Element extra=(Element)leaf(changed,"note_summary").cloneNode(true);extra.setAttribute("text","another field");leaf(changed,"contentRoot").appendChild(extra);
        check(ObservedChildText.collect(changed,READER).truncated&&!list(changed,BODY),"unobserved source tail cannot prove complete card");
        changed=copy(first);leaf(changed,"note_title").setAttribute("text","");leaf(changed,"note_date").setAttribute("text","");
        extra=(Element)leaf(changed,"note_summary").cloneNode(true);extra.setAttribute("text","different summary");leaf(changed,"contentRoot").appendChild(extra);
        check(!list(changed,BODY),"multiple distinct summary sources rejected");
        extra.setAttribute("text",BODY);
        check(!ObservedChildText.collect(changed,READER).sourcesComplete&&!list(changed,BODY),"deduplicated equal summary source is explicit incomplete provenance");
        changed=copy(first);leaf(changed,"note_summary").setAttribute("resource-id",P+":id/other");
        check(!ObservedChildText.collect(changed,READER).fingerprint.equals(collected.fingerprint),"source view ID participates in fingerprint");
        System.out.println("PASS "+checks+" actual XML topology/source provenance cases; manual_fixture_only=true; model_task_success=false; phone_tested=false");
    }
}
