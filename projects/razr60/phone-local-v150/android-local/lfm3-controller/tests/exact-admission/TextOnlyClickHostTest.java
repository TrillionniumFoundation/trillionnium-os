package org.trillionnium.hepta.local;

import android.graphics.Rect;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;

/** Exact production prompt/dispatch guard with a saved failure observation.
 * All additional nodes are explicit host-only boundary cases, not phone results.
 */
public final class TextOnlyClickHostTest {
    private static final String FIXTURE_SHA="a9e83eb50aabfd71ec967ba74b98ebe60176002700380e68b81775cccc076d75";
    private static final LocalRuntimeConfig CONFIG=new LocalRuntimeConfig(ModelProfile.GEMMA4_E4B,"npu",8192,4);
    private static int checks;
    private static final List<Object> grammarCases=new ArrayList<Object>();
    private interface Call { void run()throws Exception; }
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static void rejects(Call call,String message)throws Exception{
        try{call.run();throw new AssertionError(message+": accepted");}
        catch(ActionDecision.InvalidActionException expected){checks++;}
    }
    private static String repeat(String value,int count){StringBuilder out=new StringBuilder();for(int i=0;i<count;i++)out.append(value);return out.toString();}
    private static String hash(byte[] bytes)throws Exception{
        StringBuilder value=new StringBuilder();for(byte b:MessageDigest.getInstance("SHA-256").digest(bytes))value.append(String.format(Locale.ROOT,"%02x",b&255));return value.toString();
    }
    private static PhoneObservation.Node node(PhoneObservation observation,String id){
        for(PhoneObservation.Node node:observation.nodes)if(id.equals(node.id))return node;
        throw new AssertionError("missing recorded node "+id);
    }
    private static PhoneObservation withNodes(PhoneObservation source,List<PhoneObservation.Node> nodes){
        return new PhoneObservation(source.id,source.packageName,source.capturedElapsedMillis,source.width,source.height,source.rotation,source.windowId,
                source.windowBounds,source.screenshot,source.screenshotSha256,source.treeSha256,source.state,source.windowMetadata,source.nodesTruncated,nodes);
    }
    private static PromptAdmissionFixture.Result build(String owner,PhoneObservation observation)throws Exception{
        Map<String,String> apps=new LinkedHashMap<String,String>();apps.put(observation.packageName,"Moto 笔记");
        return PromptAdmissionFixture.build(owner,new AppCatalogueRanker(apps,owner).search("",0),observation,new JSONArray(),CONFIG);
    }
    private static String action(PromptAdmissionFixture.Result frame,String action,String id)throws Exception{
        Map<String,Object> row=new LinkedHashMap<String,Object>();
        row.put("reason","Use only observed current action facts.");row.put("action",action);
        row.put("observation_id",frame.grammar.observationId);row.put("package",frame.grammar.currentPackage);
        if(id!=null){row.put("node_label",frame.grammar.targets.labels.get(id));row.put("node_id",id);}
        if("type".equals(action))row.put("text","host boundary test");
        if("scroll".equals(action))row.put("direction","forward");
        return new JSONObject(row).toString();
    }
    private static void grammarCase(String name,String grammar,String raw,boolean expected){
        Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name);row.put("grammar",grammar);row.put("json",raw);row.put("accepted",expected);grammarCases.add(row);
    }
    @SuppressWarnings("unchecked") private static List<?> projectedNode(PromptAdmissionFixture.Result frame,String id)throws Exception{
        String json=frame.text.substring("UNTRUSTED_DATA\n".length(),frame.text.indexOf("\nOWNER\n"));
        Map<String,Object> data=MobiMindContract.jsonObject(json.getBytes(StandardCharsets.UTF_8));
        for(Object value:(List<?>)((Map<String,Object>)data.get("screen")).get("nodes")){
            List<?> row=(List<?>)value;if(id.equals(row.get(0)))return row;
        }
        throw new AssertionError("missing projected node "+id);
    }
    private static final class Child {
        final String text;final List<Child> children=new ArrayList<Child>();
        Child(String text){this.text=text;}
    }
    private static ObservedChildText.Result children(String... labels){
        final Child root=new Child("");for(String label:labels)root.children.add(new Child(label));
        return ObservedChildText.collect(root,new ObservedChildText.Reader<Child>(){
            public ObservedChildText.Metadata metadata(Child item){return new ObservedChildText.Metadata(true,true,item==root,item==root,false,false,false);}
            public String text(Child item){return item.text;}public String description(Child item){return "";}
            public String identity(Child item){return "host-child-"+root.children.indexOf(item);}
            public int childCount(Child item){return item.children.size();}public Child child(Child item,int index){return item.children.get(index);}
            public void release(Child item){}
        });
    }
    private static PhoneObservation.Node synthetic(String id,String text,String description,String view,boolean editable,boolean scroll,boolean submit,ObservedChildText.Result child)throws Exception{
        return new PhoneObservation.Node(id,"com.motorola.stylus","android.widget.Button",view,text,description,new Rect(0,0,100,100),true,editable,scroll,true,editable,false,child,
                ObservedScrollActions.observed(scroll?Arrays.asList("forward"):Collections.<String>emptyList()),
                submit?ObservedImeEnter.present("搜索"):ObservedImeEnter.ABSENT,editable?hash(text.getBytes(StandardCharsets.UTF_8)):null,submit);
    }
    public static void main(String[] args)throws Exception{
        Path fixture=Paths.get(args[0]),output=Paths.get(args[1]);Files.createDirectories(output);
        byte[] raw=Files.readAllBytes(fixture);check(FIXTURE_SHA.equals(hash(raw)),"exact saved failure observation");
        PhoneObservation observed=ObservationHintsHostTest.recorded(MobiMindContract.jsonObject(raw));
        PhoneObservation.Node blank=node(observed,"n10");
        check(blank.clickable&&blank.label().isEmpty()&&blank.viewId.isEmpty()&&blank.className.isEmpty(),"real n10 has no observed semantic label or structural name");
        String owner="打开 Moto 笔记（com.motorola.stylus），新建一条笔记，正文完整写入以下一行："+node(observed,"n11").text
                +" 保存这条新笔记，然后回到笔记列表，重新打开它并停留在正文完整可见的页面。不要修改或删除已有笔记，不分享或发送。";
        final PromptAdmissionFixture.Result frame=build(owner,observed);
        check(frame.ids.contains("n10")&&"".equals(frame.grammar.targets.labels.get("n10")),"raw blank node and exact label remain in target facts");
        check(!frame.clickIds.contains("n10")&&!((String)projectedNode(frame,"n10").get(3)).contains("c"),"real blank n10 has no click capability");
        check(frame.clickIds.contains("n1")&&"标题".equals(frame.grammar.targets.labels.get("n1")),"real labeled title remains selectable");
        check(frame.clickIds.contains("n11")&&((String)projectedNode(frame,"n11").get(3)).contains("t"),"real labeled editor retains both applicable capabilities");
        final ActionDecision forged=ActionDecision.parse(action(frame,"click","n10"),frame.grammar.schema);
        // The older pair-only guard accepted this exact pair. The new independent
        // eligibility guard must reject it even if grammar generation is bypassed.
        ActionPolicy.validateTextDecision(forged,observed.packageName,frame.grammar.appLabels.labels.keySet(),frame.grammar.targets,frame.grammar.appLabels);
        rejects(new Call(){public void run()throws Exception{frame.requireTextOnlyClick(forged);}},"postparse rejects real blank click");
        final ActionDecision wrong=ActionDecision.parse(action(frame,"click","n1").replace("标题","保存"),frame.grammar.schema);
        rejects(new Call(){public void run()throws Exception{frame.requireTextOnlyClick(wrong);}},"different label cannot reuse a permitted ID");
        final ActionDecision stale=ActionDecision.parse(action(frame,"click","n1").replace(observed.id,repeat("a",32)),frame.grammar.schema);
        rejects(new Call(){public void run()throws Exception{frame.requireTextOnlyClick(stale);}},"old observation cannot reuse click membership");
        frame.requireTextOnlyClick(ActionDecision.parse(action(frame,"click","n1"),frame.grammar.schema));
        frame.requireTextOnlyClick(ActionDecision.parse(action(frame,"back",null),frame.grammar.schema));
        check(frame.grammar.actions.contains("back"),"system back remains available, without claiming save success");
        boolean immutable=false;try{frame.clickIds.add("n10");}catch(UnsupportedOperationException expected){immutable=true;}check(immutable,"final click domain is immutable");
        Files.write(output.resolve("actual.gbnf"),frame.grammar.text.getBytes(StandardCharsets.UTF_8));
        grammarCase("real blank n10","actual.gbnf",action(frame,"click","n10"),false);
        grammarCase("real labeled title","actual.gbnf",action(frame,"click","n1"),true);
        grammarCase("system back","actual.gbnf",action(frame,"back",null),true);
        grammarCase("wrong label","actual.gbnf",action(frame,"click","n1").replace("标题","保存"),false);

        for(String label:new String[]{"", " \t\r\n", "\u00a0\u2007\u202f", "\u200b\u200c\u200d\ufeff", "\u202e\u2060", "\u0000\u0001", "\u0301\u034f\ufe0f", "\u115f\u1160\u3164\uffa0\u2800", repeat(" ",36)+"保存", repeat(" ",35)+"😀"})
            check(!PromptActionDomain.textOnlyClickLabel(label),"invisible-only supplied prefix has no click: "+label.length());
        for(String label:new String[]{"+","×","=","−","÷","保存","列表条目","😀","·","…","\u200b查找\u200d",repeat(" ",35)+"×尾",repeat(" ",34)+"😀"})
            check(PromptActionDomain.textOnlyClickLabel(label),"actual visible symbols/text survive: "+label);
        ObservedChildText.Result invisible=children("\u200b","\u200c"),realDot=children("\u200b · \u200c"),realChild=children("日期","列表条目");
        check(invisible.text.contains(" · ")&&!PromptActionDomain.textOnlyClickLabel("","",invisible),"artificial descendant separator cannot create click semantics");
        check(PromptActionDomain.textOnlyClickLabel("","",realDot),"middle dot actually observed in a child is retained");
        check(PromptActionDomain.textOnlyClickLabel("","",realChild),"actual labeled descendant card remains clickable");
        check(!PromptActionDomain.textOnlyClickLabel("","",children(repeat("\u200b",40),"保存")),"real child text beyond the visible prefix cannot borrow an artificial separator");
        check(!PromptActionDomain.textOnlyClickLabel("","",children(repeat("\u200b",120))),"collector truncation ellipsis is not an observed label");
        List<PhoneObservation.Node> nodes=new ArrayList<PhoneObservation.Node>();
        nodes.add(synthetic("n20","","","com.motorola.stylus:id/search",true,false,true,ObservedChildText.notApplicable()));
        nodes.add(synthetic("n21","","","com.motorola.stylus:id/list",false,true,false,ObservedChildText.notApplicable()));
        nodes.add(synthetic("n22","","","com.motorola.stylus:id/save",false,false,false,ObservedChildText.notApplicable()));
        nodes.add(synthetic("n23","","","",false,false,false,realChild));
        nodes.add(synthetic("n24","","","",false,false,false,invisible));
        nodes.add(synthetic("n25","+","","",false,false,false,ObservedChildText.notApplicable()));
        nodes.add(synthetic("n26","×","","",false,false,false,ObservedChildText.notApplicable()));
        nodes.add(synthetic("n27","=","","",false,false,false,ObservedChildText.notApplicable()));
        nodes.add(synthetic("n28","","保存","",false,false,false,ObservedChildText.notApplicable()));
        final PromptAdmissionFixture.Result boundary=build(owner,withNodes(observed,nodes));
        check(!boundary.clickIds.contains("n20")&&((String)projectedNode(boundary,"n20").get(3)).contains("t")&&boundary.grammar.allowsSubmit("n20"),"empty editor has type and observed query submit without click");
        check(!boundary.clickIds.contains("n21")&&boundary.grammar.allowsScroll("n21","forward"),"blank scroll capability survives independently");
        check(!boundary.clickIds.contains("n22")&&"".equals(boundary.grammar.targets.labels.get("n22")),"resource ID and class never become a save label");
        check(boundary.clickIds.containsAll(Arrays.asList("n23","n25","n26","n27","n28"))&&!boundary.clickIds.contains("n24"),"actual child and mathematical labels survive; inserted delimiter does not");
        Files.write(output.resolve("boundary.gbnf"),boundary.grammar.text.getBytes(StandardCharsets.UTF_8));
        for(String id:Arrays.asList("n20","n21","n22","n23","n24","n25","n26","n27","n28")){
            final ActionDecision decision=ActionDecision.parse(action(boundary,"click",id),boundary.grammar.schema);
            boolean allowed=boundary.clickIds.contains(id);grammarCase("boundary click "+id,"boundary.gbnf",action(boundary,"click",id),allowed);
            if(allowed)boundary.requireTextOnlyClick(decision);else rejects(new Call(){public void run()throws Exception{boundary.requireTextOnlyClick(decision);}},"postparse boundary denied "+id);
        }
        for(String kind:Arrays.asList("type","submit")){
            String value=action(boundary,kind,"n20");boundary.requireTextOnlyClick(ActionDecision.parse(value,boundary.grammar.schema));grammarCase("empty editor "+kind,"boundary.gbnf",value,true);
        }
        String scroll=action(boundary,"scroll","n21");boundary.requireTextOnlyClick(ActionDecision.parse(scroll,boundary.grammar.schema));grammarCase("blank scroll","boundary.gbnf",scroll,true);
        Map<String,Object> cases=new LinkedHashMap<String,Object>();cases.put("schema","hepta.text-only-click-host.v1");cases.put("phone_contacted",false);cases.put("saved_failure_fixture_sha256",FIXTURE_SHA);cases.put("cases",grammarCases);
        Files.write(output.resolve("CASES.json"),new JSONObject(cases).toString().getBytes(StandardCharsets.UTF_8));
        System.out.println("TextOnlyClickHostTest checks="+checks+" fixture_sha256="+FIXTURE_SHA+" phone_or_model_run=false");
    }
}
