package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/** Pure parser regression using original retained DTO data and explicit
 * mutations. No live Android, installed identity, lease, dispatch or SDK. */
final class NativeXiaomiImageModalHostTest {
    private static final NativeAppGoal GOAL=NativeAppGoal.parse(ActualXiaomiImageModalFixture.OWNER,NativeAppGoal.XIAOMI_PACKAGE);
    private static final NativeAppEvidence.Frame ACTUAL=ActualXiaomiImageModalFixture.frame();
    private static final List<String> names=new ArrayList<String>();
    private static int checks;
    private interface Test {void run() throws Exception;}
    private interface EditNode {void edit(N node);}
    private interface EditFrame {void edit(F frame);}
    private static void check(boolean value,String reason){checks++;if(!value)throw new AssertionError(reason);}
    private static void one(String name,Test body)throws Exception{
        if(names.contains(name))throw new AssertionError("duplicate case");body.run();names.add(name);
    }
    private static void rejects(Test body,String why)throws Exception{
        checks++;try{body.run();}catch(IllegalArgumentException expected){return;}throw new AssertionError(why);
    }
    private static NativeXiaomiProductPage.Page page(NativeAppEvidence.Frame f){return NativeXiaomiProductPage.inspect(GOAL,f);}
    private static void noAuthority(NativeXiaomiProductPage.Page p){
        check(p.clickIds.isEmpty()&&p.editValues.isEmpty()&&p.purposes.isEmpty(),"no node action targets");
        check(p.quote==null,"no quote from unlabeled image");
        check(Boolean.FALSE.equals(p.evidence().get("dispatch_authority"))
                &&Boolean.FALSE.equals(p.evidence().get("task_completion_authority"))
                &&Boolean.FALSE.equals(p.evidence().get("order_submitted")),"no dispatch, completion or purchase authority");
    }
    private static void modal(NativeAppEvidence.Frame f){
        NativeXiaomiProductPage.Page p=page(f);check("image_modal".equals(p.phase),"inset image shape recognized");
        check(p.frame==f,"same actual Frame object retained");
        check(p.missing.equals(Collections.singletonList("image_modal_content_unclassified")),"semantics remain unknown");noAuthority(p);
    }
    private static void notModal(NativeAppEvidence.Frame f){
        NativeXiaomiProductPage.Page p=page(f);check(!"image_modal".equals(p.phase),"mutation must not become modal capability");noAuthority(p);
    }
    private static final class N {
        String id,pkg,cls,vid,text,desc,path,parent,signature,label;
        int left,top,right,bottom;boolean enabled,password,clickable,editable,scrollable;
        Boolean selected,checkable,checked;Set<String> directions;
        N(NativeAppEvidence.Node n){
            id=n.id;pkg=n.packageName;cls=n.className;vid=n.viewId;text=n.text;desc=n.description;
            path=n.path;parent=n.parentClass;signature=n.signature;label=n.label;
            left=n.left;top=n.top;right=n.right;bottom=n.bottom;enabled=n.enabled;password=n.password;
            clickable=n.clickable;editable=n.editable;scrollable=n.scrollable;
            selected=n.selected;checkable=n.checkable;checked=n.checked;directions=n.scrollDirections;
        }
        NativeAppEvidence.Node build(){return new NativeAppEvidence.Node(id,pkg,cls,vid,text,desc,path,parent,signature,label,
                left,top,right,bottom,enabled,password,clickable,editable,scrollable,selected,checkable,checked,directions);}
    }
    private static final class F {
        String owner=ACTUAL.ownerSha,pkg=ACTUAL.packageName;
        int display=ACTUAL.displayId,window=ACTUAL.windowId,width=ACTUAL.width,height=ACTUAL.height;
        int left=ACTUAL.left,top=ACTUAL.top,right=ACTUAL.right,bottom=ACTUAL.bottom,type=ACTUAL.windowType;
        boolean complete=ACTUAL.collectionComplete,truncated=ACTUAL.nodesTruncated,metadata=ACTUAL.metadataObserved;
        List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>(ACTUAL.nodes);
        NativeAppEvidence.Frame build(){return new NativeAppEvidence.Frame(ACTUAL.taskId,owner,ACTUAL.targetSha,
                ACTUAL.authorizationSha,ACTUAL.selectionSha,ACTUAL.observationId,pkg,ACTUAL.generation,
                ACTUAL.treeSha,ACTUAL.stateSha,ACTUAL.screenshotSha,ACTUAL.sourceRecordSha,ACTUAL.completionFrameSha,
                display,window,ACTUAL.rotation,width,height,left,top,right,bottom,ACTUAL.capturedElapsedMs,
                truncated,complete,nodes,type,metadata);}
    }
    private static NativeAppEvidence.Frame change(EditFrame edit){F f=new F();edit.edit(f);return f.build();}
    private static NativeAppEvidence.Frame node(int at,EditNode edit){return change(f->{N n=new N(f.nodes.get(at));edit.edit(n);f.nodes.set(at,n.build());});}
    private static void output(String destination)throws Exception{
        StringBuilder s=new StringBuilder("{\"cases\":").append(names.size()).append(",\"checks\":").append(checks).append(",\"names\":[");
        for(int i=0;i<names.size();i++){if(i>0)s.append(',');s.append('"').append(names.get(i)).append('"');}
        s.append("],\"host_only\":true,\"business_verified\":false}\n");
        Files.write(Paths.get(destination),s.toString().getBytes(StandardCharsets.UTF_8));System.out.print(s.toString());
    }
    public static void main(String[] args)throws Exception{
        if(args.length<1||args.length>2)throw new IllegalArgumentException("CASES destination [legacy]");
        if(args.length==2){
            if(!"legacy".equals(args[1]))throw new IllegalArgumentException("legacy mode");
            one("original_b95f_actual_image_modal_was_unrecognized",()->{
                NativeXiaomiProductPage.Page p=page(ACTUAL);check("unrecognized_native_page".equals(p.phase),"old source reproduces blocker");noAuthority(p);
            });output(args[0]);return;
        }
        one("actual_saved_frame_classifies_shape_without_semantic_or_action_authority",()->modal(ACTUAL));
        one("actual_retained_identity_and_geometry_are_replayed",()->{
            check(ACTUAL.sourceRecordSha.equals(ActualXiaomiImageModalFixture.ORIGINAL_SHA),"original raw record SHA");
            check(ACTUAL.ownerSha.equals(GOAL.ownerSha256)&&ACTUAL.nodes.size()==2,"exact OWNER and retained count");
            check(ACTUAL.left==216&&ACTUAL.top==333&&ACTUAL.right==504&&ACTUAL.bottom==947,"actual original bounds");
            check(ACTUAL.nodes.get(0).signature.equals("946adfc4bf863ceb41dfa3acff45132939d7eda01220ecb49043b1f074891451"),"actual original NodeRef");
        });
        one("window_display_ids_and_scale_are_not_hardcoded",()->modal(change(f->{
            f.display=9;f.window=703;f.width*=2;f.height*=2;f.left*=2;f.top*=2;f.right*=2;f.bottom*=2;
            for(int i=0;i<f.nodes.size();i++){N n=new N(f.nodes.get(i));n.left*=2;n.top*=2;n.right*=2;n.bottom*=2;f.nodes.set(i,n.build());}
        })));
        one("node_order_and_node_ids_are_not_position_selectors",()->modal(change(f->{
            Collections.reverse(f.nodes);for(int i=0;i<f.nodes.size();i++){N n=new N(f.nodes.get(i));n.id="n"+(71+i);f.nodes.set(i,n.build());}
        })));
        one("wrong_immutable_owner_is_rejected",()->rejects(()->page(change(f->f.owner=NativeAppEvidence.hash("different owner"))),"wrong owner must throw"));
        one("non_xiaomi_goal_is_rejected",()->rejects(()->NativeXiaomiProductPage.inspect(
                NativeAppGoal.parse("查一下2026年11月17日北京到上海的单程机票，1名成人",NativeAppGoal.CTRIP_PACKAGE),ACTUAL),"foreign goal must throw"));
        one("foreign_node_package_is_unavailable",()->notModal(node(0,n->n.pkg="ctrip.android.view")));
        one("non_application_window_is_unavailable",()->notModal(change(f->f.type=2)));
        one("unknown_window_metadata_is_unavailable",()->notModal(change(f->f.metadata=false)));
        one("incomplete_collection_is_unavailable",()->notModal(change(f->f.complete=false)));
        one("truncated_collection_is_unavailable",()->notModal(change(f->f.truncated=true)));
        one("fullscreen_or_screen_touching_bounds_are_not_inset",()->{
            notModal(change(f->{f.left=0;f.top=0;f.right=f.width;f.bottom=f.height;}));
            notModal(change(f->f.left=0));notModal(change(f->f.top=0));notModal(change(f->f.right=f.width));notModal(change(f->f.bottom=f.height));
        });
        one("missing_or_extra_retained_node_rejects_modal",()->{
            notModal(change(f->f.nodes.remove(1)));
            notModal(change(f->{N n=new N(f.nodes.get(1));n.id="n2";n.path="0/2";f.nodes.add(n.build());}));
        });
        one("privacy_consent_login_text_and_description_never_match",()->{
            for(final String label:Arrays.asList("隐私政策","同意","登录","Privacy policy","Consent","Sign in")){
                notModal(node(0,n->n.text=label));notModal(node(1,n->n.desc=label));
            }
        });
        one("derived_label_or_resource_id_rejects_modal",()->{
            notModal(node(0,n->n.label="同意隐私政策"));notModal(node(1,n->n.vid="com.xiaomi.shop:id/close"));
        });
        one("whitespace_is_observed_content_not_empty",()->notModal(node(0,n->n.text=" ")));
        one("native_child_paths_must_be_exact_observed_siblings",()->{
            notModal(node(1,n->n.path="0/2"));notModal(node(0,n->{n.path=null;n.parent=null;}));
        });
        one("parent_class_must_be_same_frame_layout",()->notModal(node(0,n->n.parent="android.view.ViewGroup")));
        one("missing_node_reference_is_rejected",()->notModal(node(0,n->n.signature=null)));
        one("other_widget_class_is_rejected",()->notModal(node(0,n->n.cls="android.widget.TextView")));
        one("disabled_nonclickable_editable_password_or_scroll_node_is_rejected",()->{
            notModal(node(0,n->n.enabled=false));notModal(node(1,n->n.clickable=false));notModal(node(0,n->n.editable=true));
            notModal(node(1,n->n.password=true));notModal(node(0,n->n.scrollable=true));notModal(node(1,n->n.directions=Collections.singleton("down")));
        });
        one("selection_tuple_must_be_observed_and_all_false",()->{
            notModal(node(0,n->{n.selected=null;n.checkable=null;n.checked=null;}));notModal(node(0,n->n.selected=true));
            notModal(node(1,n->n.checkable=true));notModal(node(1,n->n.checked=true));
        });
        one("top_image_must_match_actual_frame_edges",()->{
            notModal(node(0,n->n.left++));notModal(node(0,n->n.top++));notModal(node(0,n->n.right--));
        });
        one("lower_image_must_be_square_and_centered",()->{
            notModal(node(1,n->n.right--));notModal(node(1,n->{n.left++;n.right++;}));
        });
        one("image_gap_must_be_positive_and_bounded",()->{
            notModal(node(0,n->n.bottom=845));notModal(node(0,n->n.bottom=846));notModal(node(0,n->n.bottom=742));
        });
        one("lower_image_must_match_frame_bottom",()->notModal(node(1,n->{n.top--;n.bottom--;})));
        one("image_with_bounds_outside_window_is_not_usable",()->notModal(node(0,n->n.left--)));
        one("both_image_width_and_height_must_exceed_lower_image",()->{
            notModal(change(f->{f.right=318;N n=new N(f.nodes.get(0));n.right=318;f.nodes.set(0,n.build());
                N lower=new N(f.nodes.get(1));lower.left=216;lower.right=318;f.nodes.set(1,lower.build());}));
            notModal(node(0,n->n.bottom=n.top+102));
        });
        one("unrelated_unknown_page_keeps_original_unrecognized_phase",()->{
            NativeXiaomiProductPage.Page p=page(node(0,n->n.text="unknown content"));
            check("unrecognized_native_page".equals(p.phase),"no generic unknown Back classification");noAuthority(p);
        });
        output(args[0]);
    }
    private NativeXiaomiImageModalHostTest(){}
}
