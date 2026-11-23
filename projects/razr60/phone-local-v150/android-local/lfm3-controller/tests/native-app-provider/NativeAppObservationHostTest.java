package org.trillionnium.hepta.local;

import android.content.Context;
import android.graphics.Rect;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;

/** Compile/call the complete actual Android adapter. Platform IO and lease
 * allocation are the retained explicit host fixture, not Android authority. */
final class NativeAppObservationHostTest {
    static final String OWNER="查一下小米AX3000T的价格";
    static Path fixtures,privateRoot;static int checks,serial;
    static final List<String> names=new ArrayList<String>();
    interface Test{void run()throws Exception;}
    static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    static void rejected(Test test,String message)throws Exception{checks++;try{test.run();}catch(IllegalArgumentException|IllegalStateException|ActionDecision.InvalidActionException expected){return;}throw new AssertionError(message);}
    static void one(String name,Test test)throws Exception{test.run();names.add(name);}
    static String hash(String text){return NativeAppEvidence.hash(text);}static String id(String text){return hash(text).substring(0,32);}
    static final class Env {
        final String task=id("synthetic-adapter-task:"+(++serial));
        final BackgroundTaskTarget target=BackgroundTaskTarget.resolveExplicitSelection(OWNER,NativeAppGoal.XIAOMI_PACKAGE,Collections.singleton(NativeAppGoal.XIAOMI_PACKAGE));
        final BackgroundSession.Selection selected=new BackgroundSession.Selection(target);
        final TaskAuthorization authorization=TaskAuthorization.parse(OWNER).forExecutionSelection(selected);
        final TaskAuthorization.Gate gate=authorization.bind(task);
        final BackgroundSession background;
        final NativeXmlFixture.Snapshot raw;
        final List<PhoneObservation.Node> nodes=new ArrayList<PhoneObservation.Node>();
        PhoneObservation observed;NotesCompletionEvidence.Frame completion;NativeAppEvidence.Frame frame;
        Env()throws Exception{
            Path dir=privateRoot.resolve("case-"+serial);Files.createDirectories(dir);Context context=new Context(dir.toFile());
            background=new BackgroundSession(context,task,OWNER,selected,new QualificationScopeConfig.FilesRoot(context));
            // Only the host-only display allocation endpoint is supplied. No
            // BackgroundSession.start, broker process, socket or phone is used.
            java.lang.reflect.Field display=BackgroundSession.class.getDeclaredField("displayId");display.setAccessible(true);display.setInt(background,7);
            raw=NativeXmlFixture.read(fixtures.resolve("xiaomi-search-results.xml"));
            for(NativeAppEvidence.Node n:raw.nodes)nodes.add(node(n,raw.childTextById.get(n.id)));
            rebuild(background.generation,false);copy();
        }
        PhoneObservation.Node node(NativeAppEvidence.Node n,ObservedChildText.Result child){
            return new PhoneObservation.Node(n.id,n.packageName,n.className,n.viewId,n.text,n.description,new Rect(n.left,n.top,n.right,n.bottom),
                    n.clickable,n.editable,n.scrollable,n.enabled,false,n.password,child,ObservedScrollActions.observed(n.scrollDirections),
                    ObservedImeEnter.UNKNOWN,null,false,n.signature,n.path,n.parentClass,n.selected,n.checkable,n.checked);
        }
        void rebuild(String generation,boolean truncated)throws Exception{
            String observation=id("synthetic-observation:"+task+":"+nodes.hashCode()+":"+generation+":"+truncated);
            int[] b=raw.rootBounds;List<NotesCompletionEvidence.Node> complete=new ArrayList<NotesCompletionEvidence.Node>();
            for(PhoneObservation.Node n:nodes)complete.add(new NotesCompletionEvidence.Node(n.id,n.packageName,n.text,n.label(),n.viewId,null,
                    new int[]{n.bounds.left,n.bounds.top,n.bounds.right,n.bounds.bottom},n.editable,n.clickable,n.scrollable,n.enabled,n.password,n.childText,n.observedAppTreeSignature));
            completion=new NotesCompletionEvidence.Frame(observation,NativeAppGoal.XIAOMI_PACKAGE,90,7,generation,1,true,truncated,complete);
            PhoneObservation.CollectionStats stats=new PhoneObservation.CollectionStats(1536,512,6144,nodes.size(),nodes.size(),0,0,truncated?1:0,0,0,1);
            observed=new PhoneObservation(observation,NativeAppGoal.XIAOMI_PACKAGE,100,1224,2992,0,90,new Rect(b[0],b[1],b[2],b[3]),
                    privateRoot.resolve("synthetic-screenshot-not-read.png").toFile(),hash("synthetic-screen"),hash("synthetic-state"),
                    new ObservationState(raw.sourceSha256,ImeVisibility.UNKNOWN),ObservedWindowMetadata.observed(b,"android.widget.FrameLayout",1,7,b,""),
                    truncated,nodes,generation,NativeAppGoal.XIAOMI_PACKAGE,Collections.singletonList(NativeAppGoal.XIAOMI_PACKAGE),stats,selected.json(),target.ownerSha256);
        }
        void copy()throws Exception{frame=NativeAppObservation.copy(task,gate,background,observed,completion,hash("synthetic-original-phone-json:"+observed.id));}
        NativeXiaomiProductPage.Page page(){return NativeXiaomiProductPage.inspect(target.nativeGoal,frame);}
        String card(){for(Map.Entry<String,String> e:page().purposes.entrySet())if("open_exact_product".equals(e.getValue()))return e.getKey();throw new AssertionError("actual product card not identified");}
        NativeAppDomain domain(){NativeXiaomiProductPage.Page p=page();return new NativeAppDomain(frame,p.phase,p.clickIds,p.editValues,p.purposes,false,p.modelView(),null,p.missing);}
        ActionDecision click(String node,String label,String observation,String pkg)throws Exception{return ActionDecision.parse(new JSONObject().put("action","click").put("package",pkg).put("observation_id",observation).put("node_id",node).put("node_label",label).toString(),ActionDecision.IME_ACTION_SCHEMA);}
        ActionDecision cardAction()throws Exception{String id=card();return click(id,frame.byId.get(id).label,frame.observationId,frame.packageName);}
    }
    public static void main(String[] args)throws Exception{
        fixtures=Paths.get(args[0]);privateRoot=Paths.get(args[1]);Files.createDirectories(privateRoot);Path output=Paths.get(args[2]);
        one("actual_adapter_preserves_original_bounded_derived_product_card_label",()->{
            Env e=new Env();String card=e.card();ObservedChildText.Result child=e.raw.childTextById.get(card);
            check("derived".equals(child.status)&&child.truncated,"actual original bounded child collector fixture");
            PhoneObservation.Node source=null;for(PhoneObservation.Node n:e.nodes)if(n.id.equals(card))source=n;
            check(source!=null&&source.text.isEmpty()&&source.description.isEmpty(),"actual unlabeled clickable card ancestor");
            String original=ObservedTargetLabels.project(source.label());
            check(!original.isEmpty()&&original.length()<=ObservedTargetLabels.PROJECTION_UTF16_LIMIT+1&&original.endsWith("…"),"original bounded target projection");
            check(original.equals(e.frame.byId.get(card).label),"complete actual adapter retains exact original projection");
            check("".equals(e.raw.childLabels.get(card).get("native_observation_r4_effective_label")),"legacy r4 refusal retained explicitly");
            e.domain().requireCurrent(e.cardAction());check(true,"actual projected parent ID+label admitted by current Domain");
        });
        one("raw_description_and_price_are_not_replaced_by_derived_action_label",()->{Env e=new Env();String c=e.card();check(e.frame.byId.get(c).text.isEmpty()&&e.frame.byId.get(c).description.isEmpty(),"card raw fields preserved empty");check("159".equals(e.page().quote.amountDecimal)&&"199".equals(e.page().quote.comparisonAmountDecimal),"same-card raw price still independent of bounded label");});
        one("empty_and_nonderived_card_cannot_grant_click",()->{Env e=new Env();String c=e.card();for(int i=0;i<e.nodes.size();i++)if(e.nodes.get(i).id.equals(c))e.nodes.set(i,e.node(e.raw.nodes.get(i),ObservedChildText.notApplicable()));e.rebuild(e.background.generation,false);e.copy();check(e.frame.byId.get(c).label.isEmpty(),"no own text or derived label stays empty");rejected(()->e.domain(),"empty native parent remains ungrantable");});
        one("bare_empty_node_keeps_empty_projection",()->{Env e=new Env();NativeAppEvidence.Node found=null;for(NativeAppEvidence.Node n:e.frame.nodes)if(n.text.isEmpty()&&n.description.isEmpty()&&n.label.isEmpty()){found=n;break;}check(found!=null,"actual empty graph node retained");final String nid=found.id;rejected(()->new NativeAppDomain(e.frame,"negative",Collections.singleton(nid),Collections.<String,String>emptyMap(),Collections.singletonMap(nid,"synthetic_forbidden"),false,Collections.<String,Object>emptyMap(),null,Collections.<String>emptyList()),"empty target cannot be promoted");});
        one("different_node_id_with_card_label_is_rejected",()->{Env e=new Env();String c=e.card(),other=null;for(NativeAppEvidence.Node n:e.frame.nodes)if(!n.id.equals(c)&&!n.label.equals(e.frame.byId.get(c).label)){other=n.id;break;}final String n=other;rejected(()->e.domain().requireCurrent(e.click(n,e.frame.byId.get(c).label,e.frame.observationId,e.frame.packageName)),"node id binding stays exact");});
        one("substituted_full_title_instead_of_original_label_is_rejected",()->{Env e=new Env();String c=e.card();rejected(()->e.domain().requireCurrent(e.click(c,"Xiaomi路由器AX3000T",e.frame.observationId,e.frame.packageName)),"title does not substitute parent projection");});
        one("different_observation_id_is_rejected",()->{Env e=new Env();String c=e.card();rejected(()->e.domain().requireCurrent(e.click(c,e.frame.byId.get(c).label,id("foreign-observation"),e.frame.packageName)),"current frame ID required");});
        one("different_package_is_rejected",()->{Env e=new Env();String c=e.card();rejected(()->e.domain().requireCurrent(e.click(c,e.frame.byId.get(c).label,e.frame.observationId,NativeAppGoal.CTRIP_PACKAGE)),"same App required");});
        one("adapter_rejects_changed_background_generation",()->{Env e=new Env();e.rebuild("12345678-1234-4234-8234-123456789abc",false);rejected(()->e.copy(),"actual lease UUID required");});
        one("adapter_rejects_equal_looking_replaced_selection_authority",()->{Env e=new Env();BackgroundSession.Selection s=new BackgroundSession.Selection(e.target);TaskAuthorization.Gate other=TaskAuthorization.parse(OWNER).forExecutionSelection(s).bind(e.task);rejected(()->NativeAppObservation.copy(e.task,other,e.background,e.observed,e.completion,hash("record")),"same Selection object required");});
        one("truncated_whole_collection_does_not_grant_bounded_label_click",()->{Env e=new Env();e.rebuild(e.background.generation,true);rejected(()->e.copy(),"truncated completion frame has no authoritative frame hash; actual adapter refuses before any Domain");});
        one("copied_parent_signature_geometry_and_selection_tuple_remain_exact",()->{Env e=new Env();String c=e.card();NativeAppEvidence.Node n=e.frame.byId.get(c),r=e.raw.nodes.get(Integer.parseInt(c.substring(1)));check(n.signature.equals(r.signature)&&n.path.equals(r.path)&&n.left==r.left&&n.right==r.right&&n.top==r.top&&n.bottom==r.bottom,"same actual modeled NodeRef geometry and path");check(n.selected.equals(r.selected)&&n.checked.equals(r.checked)&&n.checkable.equals(r.checkable),"flags copied, not inferred from label");});
        JSONObject result=new JSONObject().put("schema","hepta.native-app-observation-domain-host.v1").put("all_pass",true).put("cases",names.size()).put("assertions",checks).put("case_names",new JSONArray(names))
            .put("phone_operations",0).put("android_runtime",false).put("model_executed",false).put("business_verified",false)
            .put("boundary","Actual full NativeAppObservation.copy + original PhoneObservation.Node.label/ObservedTargetLabels + Domain; XML actions/visibility/NodeRef/whole collection counts/window/lease allocation are explicit host fixtures. No actual dispatch.");
        Files.write(output,(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);System.out.println(result.toString());
    }
}
