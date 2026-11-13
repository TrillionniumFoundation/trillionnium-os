package org.trillionnium.hepta.local;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;

/** Test-only adapter for original manual UI hierarchy XML.
 * Text, descriptions, resource IDs, XML native paths, geometry and boolean
 * attributes come from the raw fixture. Node IDs/signatures are synthetic.
 * Android action lists, isVisibleToUser, window identity and native child-slot
 * enumeration are modelled from the retained XML; no Android IPC is asserted.
 * The exact production ObservedChildText and ObservedTargetLabels are invoked.
 * This creates no task, lease, installed identity, action or completion proof.
 */
final class NativeXmlFixture {
    private NativeXmlFixture(){}
    static final class Snapshot {
        final List<NativeAppEvidence.Node> nodes;
        final String sourceSha256;
        final int[] rootBounds;
        final Map<String,Map<String,Object>> childLabels;
        final Map<String,ObservedChildText.Result> childTextById;
        Snapshot(List<NativeAppEvidence.Node> nodes,String hash,int[] bounds,Map<String,Map<String,Object>> labels,Map<String,ObservedChildText.Result> collected){
            this.nodes=Collections.unmodifiableList(new ArrayList<NativeAppEvidence.Node>(nodes));
            sourceSha256=hash;rootBounds=bounds.clone();
            Map<String,Map<String,Object>> copied=new LinkedHashMap<String,Map<String,Object>>();
            for(Map.Entry<String,Map<String,Object>> e:labels.entrySet())copied.put(e.getKey(),NativeAppEvidence.immutableMap(e.getValue()));
            childLabels=Collections.unmodifiableMap(copied);
            childTextById=Collections.unmodifiableMap(new LinkedHashMap<String,ObservedChildText.Result>(collected));
        }
    }
    private static final class Input {
        final List<Element> elements=new ArrayList<Element>();
        final Map<Element,String> paths=new IdentityHashMap<Element,String>();
        final Map<Element,String> signatures=new IdentityHashMap<Element,String>();
        final String sourceSha;
        Input(String sourceSha){this.sourceSha=sourceSha;}
        void visit(Element e,String path){
            paths.put(e,path);elements.add(e);
            signatures.put(e,NativeAppEvidence.hash("HOST_XML_NOT_ANDROID_NODE_REF\n"+sourceSha+"\n"+path+"\n"
                    +e.getAttribute("text")+"\n"+e.getAttribute("content-desc")+"\n"+e.getAttribute("bounds")));
            for(Element c:children(e)){
                String index=c.getAttribute("index");
                if(!index.matches("0|[1-9][0-9]{0,5}"))throw new IllegalArgumentException("original XML child index missing");
                visit(c,path+"/"+index);
            }
        }
    }
    static Snapshot read(Path source)throws Exception{
        byte[] bytes=Files.readAllBytes(source);String raw=new String(bytes,StandardCharsets.UTF_8);
        if(!java.util.Arrays.equals(bytes,raw.getBytes(StandardCharsets.UTF_8)))throw new IllegalArgumentException("UTF-8 fixture required");
        DocumentBuilderFactory factory=DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING,true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities",false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities",false);
        factory.setXIncludeAware(false);factory.setExpandEntityReferences(false);
        Element document=factory.newDocumentBuilder().parse(new ByteArrayInputStream(bytes)).getDocumentElement();
        List<Element> roots=children(document);
        if(roots.size()!=1)throw new IllegalArgumentException("one original XML application root required");
        Element root=roots.get(0);Input input=new Input(NativeAppEvidence.hash(raw));input.visit(root,"0");
        List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>();
        Map<String,Map<String,Object>> labels=new LinkedHashMap<String,Map<String,Object>>();
        Map<String,ObservedChildText.Result> collected=new LinkedHashMap<String,ObservedChildText.Result>();
        for(Element e:input.elements){
            final String id="n"+nodes.size(),text=e.getAttribute("text"),description=e.getAttribute("content-desc");
            ObservedChildText.Result child=collect(e,input);collected.put(id,child);
            String original=ObservedTargetLabels.project(ObservedChildText.displayLabel(text,description,child));
            String legacyR4=original,effective=original;
            // Preserve the prior refusal as audit evidence. Current r5 retains
            // the original bounded derived label, never a substituted title.
            if(text.trim().isEmpty()&&description.trim().isEmpty()&&(child.truncated||!"derived".equals(child.status)))legacyR4="";
            if(text.trim().isEmpty()&&description.trim().isEmpty()&&!"derived".equals(child.status))effective="";
            effective=ObservedTargetLabels.project(effective);
            int[] b=bounds(e);String cls=e.getAttribute("class"),path=input.paths.get(e);
            org.w3c.dom.Node parent=e.getParentNode();
            String parentClass=parent instanceof Element&&"node".equals(((Element)parent).getTagName())?((Element)parent).getAttribute("class"):"";
            Set<String> directions=flag(e,"scrollable")?Collections.singleton("forward"):Collections.<String>emptySet();
            nodes.add(new NativeAppEvidence.Node(id,e.getAttribute("package"),cls,e.getAttribute("resource-id"),text,description,path,parentClass,
                    child.bind(input.signatures.get(e)),effective,b[0],b[1],b[2],b[3],flag(e,"enabled"),flag(e,"password"),flag(e,"clickable"),
                    "android.widget.EditText".equals(cls),flag(e,"scrollable"),Boolean.valueOf(flag(e,"selected")),Boolean.valueOf(flag(e,"checkable")),
                    Boolean.valueOf(flag(e,"checked")),directions));
            Map<String,Object> audit=NativeAppEvidence.map();audit.put("status",child.status);audit.put("truncated",child.truncated);
            audit.put("sources_complete",child.sourcesComplete);audit.put("visited",child.visited);audit.put("raw_derived_text",child.text);
            audit.put("original_projected_label",original);audit.put("native_observation_r4_effective_label",legacyR4);audit.put("native_observation_r5_effective_label",effective);
            audit.put("fingerprint",child.fingerprint);audit.put("xml_values_actual",true);
            audit.put("android_actions_visibility_window_and_child_slots_modelled",true);
            List<Object> sources=new ArrayList<Object>();for(ObservedChildText.Source s:child.sources){
                Map<String,Object> fact=NativeAppEvidence.map();fact.put("retained_reader_descendant_path",s.descendantPath);fact.put("property",s.property);
                fact.put("raw_text_sha256",s.textSha256);fact.put("synthetic_node_signature",s.nodeSignature);fact.put("view_id",s.viewId);sources.add(fact);
            }audit.put("sources",sources);labels.put(id,audit);
        }
        return new Snapshot(nodes,input.sourceSha,bounds(root),labels,collected);
    }
    private static ObservedChildText.Result collect(final Element root,final Input input){
        final int[] rb=bounds(root);final String packageName=root.getAttribute("package");
        return ObservedChildText.collect(root,new ObservedChildText.Reader<Element>(){
            public ObservedChildText.Metadata metadata(Element n){
                int[] b=bounds(n);boolean click=flag(n,"clickable"),in="android.widget.EditText".equals(n.getAttribute("class"));
                boolean positive=b[2]>b[0]&&b[3]>b[1],intersects=Math.min(rb[2],b[2])>Math.max(rb[0],b[0])&&Math.min(rb[3],b[3])>Math.max(rb[1],b[1]);
                return new ObservedChildText.Metadata(positive,packageName.equals(n.getAttribute("package"))&&intersects,click,click,in,flag(n,"password"),
                        click||flag(n,"long-clickable")||in||flag(n,"scrollable")||flag(n,"checkable"));
            }
            public String text(Element n){return n.getAttribute("text");}
            public String description(Element n){return n.getAttribute("content-desc");}
            public String identity(Element n){return input.signatures.get(n);}
            public String viewId(Element n){return n.getAttribute("resource-id");}
            public int childCount(Element n){return children(n).size();}
            public Element child(Element n,int index){return children(n).get(index);}
            public void release(Element n){}
        });
    }
    private static List<Element> children(Element e){
        List<Element> result=new ArrayList<Element>();for(org.w3c.dom.Node n=e.getFirstChild();n!=null;n=n.getNextSibling())if(n instanceof Element)result.add((Element)n);
        return result;
    }
    private static boolean flag(Element e,String attribute){
        String value=e.getAttribute(attribute);if(!"true".equals(value)&&!"false".equals(value))throw new IllegalArgumentException("original boolean missing: "+attribute);
        return "true".equals(value);
    }
    private static int[] bounds(Element e){
        java.util.regex.Matcher m=java.util.regex.Pattern.compile("\\[(-?[0-9]+),(-?[0-9]+)\\]\\[(-?[0-9]+),(-?[0-9]+)\\]").matcher(e.getAttribute("bounds"));
        if(!m.matches())throw new IllegalArgumentException("original bounds missing");
        return new int[]{Integer.parseInt(m.group(1)),Integer.parseInt(m.group(2)),Integer.parseInt(m.group(3)),Integer.parseInt(m.group(4))};
    }
}
