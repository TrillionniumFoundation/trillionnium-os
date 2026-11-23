package org.trillionnium.hepta.local;

import java.util.*;

/** Actual observations are positives; all altered frames below are labelled negatives. */
public final class NotesNonScrollEditorHostTest {
    private static int checks;
    private static final List<String> names=new ArrayList<String>();
    private static void check(boolean value,String reason){checks++;if(!value)throw new AssertionError(reason);}
    private static void test(String name,Runnable body){body.run();names.add(name);}
    private static NotesCompletionEvidence.Frame frame(int index){return CurrentCompletionBridge.copy(CapturedNotesFixtures.get(index));}
    private static NotesCompletionEvidence.Installed installed(){
        Map<String,String> hashes=new LinkedHashMap<String,String>();hashes.put("base",NotesCompletionEvidence.OBSERVED_BASE_APK_SHA256);
        return new NotesCompletionEvidence.Installed(NotesCompletionEvidence.NOTES,10382,hashes);
    }
    private static NotesCompletionEvidence.Node edit(NotesCompletionEvidence.Node n,String key,Object value){
        return new NotesCompletionEvidence.Node(
            "id".equals(key)?(String)value:n.id,"package".equals(key)?(String)value:n.packageName,
            "text".equals(key)?(String)value:n.text,n.label,n.viewId,"input_sha".equals(key)?(String)value:n.inputTextSha256,
            "bounds".equals(key)?(int[])value:n.bounds(),"editable".equals(key)?(Boolean)value:n.editable,n.clickable,
            "scrollable".equals(key)?(Boolean)value:n.scrollable,"enabled".equals(key)?(Boolean)value:n.enabled,
            "password".equals(key)?(Boolean)value:n.password,n.childText,"node_sha".equals(key)?(String)value:n.observedAppTreeSignature,
            "class".equals(key)?(String)value:n.className,"path".equals(key)?(String)value:n.nativeTreePath);
    }
    private static NotesCompletionEvidence.Frame withNodes(NotesCompletionEvidence.Frame f,List<NotesCompletionEvidence.Node> n){
        return new NotesCompletionEvidence.Frame(f.observationId,f.packageName,f.windowId,f.displayId,
            f.backgroundGeneration,f.windowType,f.metadataObserved,f.nodesTruncated,n);
    }
    private static NotesCompletionEvidence.Frame mutate(NotesCompletionEvidence.Frame f,String id,String key,Object value){
        List<NotesCompletionEvidence.Node> n=new ArrayList<NotesCompletionEvidence.Node>();
        for(NotesCompletionEvidence.Node node:f.nodes)n.add(id.equals(node.id)?edit(node,key,value):node);
        return withNodes(f,n);
    }
    private static NotesCompletionEvidence.Frame add(NotesCompletionEvidence.Frame f,NotesCompletionEvidence.Node n){
        List<NotesCompletionEvidence.Node> all=new ArrayList<NotesCompletionEvidence.Node>(f.nodes);all.add(n);return withNodes(f,all);
    }
    private static NotesCompletionEvidence.Node node(NotesCompletionEvidence.Frame f,String id){
        for(NotesCompletionEvidence.Node n:f.nodes)if(id.equals(n.id))return n;throw new AssertionError("missing actual node");
    }
    private static void denied(NotesCompletionEvidence.Frame f,String reason){denied(f,CapturedNotesFixtures.BODIES[0],installed(),reason);}
    private static void denied(NotesCompletionEvidence.Frame f,String body,NotesCompletionEvidence.Installed i,String reason){
        NotesCompletionEvidence.BodyEvidence e=NotesCompletionEvidence.editor(f,body,i);
        check(!e.matched,"mutated fixture must be rejected");check(reason.equals(e.missing),"wrong refusal: "+e.missing);
        check(!e.persistentBytesVerified,"predicate must not claim persistent storage");
    }
    private static void accepted(NotesCompletionEvidence.Frame f,String body,String rule){
        NotesCompletionEvidence.BodyEvidence e=NotesCompletionEvidence.editor(f,body,installed());
        check(e.matched,"real body should be admitted: "+e.missing);check(rule.equals(e.matchRule),"body rule changed");
        check("n10".equals(e.nodeId),"must bind original editable");
        check(ObservedImeEnter.hash(body).equals(e.bodySha256),"complete OWNER body hash");
        check(ObservedImeEnter.hash(node(f,"n10").text).equals(e.rawTextSha256),"complete raw body hash");
        check(!e.persistentBytesVerified,"editor admission is not save/reopen proof");
    }
    private static String lf(int count){StringBuilder b=new StringBuilder();while(count-->0)b.append('\n');return b.toString();}
    private static NotesCompletionEvidence.Frame text(String raw){
        return mutate(mutate(frame(0),"n10","text",raw),"n10","input_sha",ObservedImeEnter.hash(raw));
    }
    private static void altered(String name,String id,String key,Object value,String reason){
        test(name,()->denied(mutate(frame(0),id,key,value),reason));
    }
    public static void main(String[] args){
        for(int i=0;i<4;i++){final int at=i;test("actual_v67_frame_"+(i+1)+"_full_body_40lf",()->{
            NotesCompletionEvidence.Frame f=frame(at);accepted(f,CapturedNotesFixtures.BODIES[at],"body_plus_observed_40_lf");
            check(!node(f,"n4").scrollable,"real non-scroll state");
            check(node(f,"n10").nativeTreePath.startsWith(node(f,"n4").nativeTreePath+"/"),"actual ancestor path");
        });}
        test("actual_v66_scrollable_editor_retained",()->{
            NotesCompletionEvidence.Frame f=frame(4);check(node(f,"n4").scrollable,"actual old scroll state");
            accepted(f,CapturedNotesFixtures.BODIES[4],"body_plus_observed_40_lf");
        });
        test("legacy_scrollable_constructor_needs_no_new_metadata",()->{
            NotesCompletionEvidence.Frame f=frame(4);List<NotesCompletionEvidence.Node> all=new ArrayList<NotesCompletionEvidence.Node>();
            for(NotesCompletionEvidence.Node n:f.nodes)all.add(new NotesCompletionEvidence.Node(n.id,n.packageName,n.text,n.label,n.viewId,n.inputTextSha256,
                n.bounds(),n.editable,n.clickable,n.scrollable,n.enabled,n.password,n.childText,n.observedAppTreeSignature));
            accepted(withNodes(f,all),CapturedNotesFixtures.BODIES[4],"body_plus_observed_40_lf");
        });
        test("nonscroll_raw_exact_body_retained",()->accepted(text(CapturedNotesFixtures.BODIES[0]),CapturedNotesFixtures.BODIES[0],"raw_exact"));
        test("actual_controller_copies_same_frame_metadata",()->{
            PhoneObservation p=CapturedNotesFixtures.get(0);NotesCompletionEvidence.Frame f=CurrentCompletionBridge.copy(p);
            check(f.nodes.size()==p.nodes.size(),"all retained nodes copied");check(f.observationId.equals(p.id),"same observation");
            check(f.windowId==p.windowId&&f.displayId==p.windowMetadata.displayId,"same window/display");
            check(f.backgroundGeneration.equals(p.backgroundGeneration),"same generation");
            for(int i=0;i<p.nodes.size();i++){
                PhoneObservation.Node n=p.nodes.get(i);NotesCompletionEvidence.Node c=f.nodes.get(i);
                check(c.id.equals(n.id)&&c.className.equals(n.className)&&c.nativeTreePath.equals(n.nativeTreePath),"actual metadata pass-through");
                check(c.observedAppTreeSignature.equals(n.observedAppTreeSignature),"same actual node signature");
            }
        });
        test("editor_evidence_cannot_become_saved_list_evidence",()->{
            NotesCompletionEvidence.ListEvidence e=NotesCompletionEvidence.list(frame(0),CapturedNotesFixtures.BODIES[0]);
            check(!e.matched&&"editor_present_not_note_list".equals(e.missing),"no save/list/reopen authorization from editor body");
        });
        test("missing_actual_ancestor_rejected",()->{
            List<NotesCompletionEvidence.Node> n=new ArrayList<NotesCompletionEvidence.Node>(frame(0).nodes);
            n.removeIf(x->"n4".equals(x.id));denied(withNodes(frame(0),n),"unique_observed_NoteEditor_context_required");
        });
        altered("wrong_context_class_rejected","n4","class","android.widget.TextView","unique_observed_NoteEditor_context_required");
        altered("missing_context_path_rejected","n4","path",null,"unique_observed_NoteEditor_context_required");
        altered("context_missing_actual_signature_rejected","n4","node_sha",null,"unique_observed_NoteEditor_context_required");
        altered("context_noncanonical_path_rejected","n4","path","0/01/0","unique_observed_NoteEditor_context_required");
        altered("wrong_editor_class_rejected","n10","class","android.webkit.WebView","non_scroll_editor_requires_actual_webview_ancestor");
        altered("missing_editor_path_rejected","n10","path",null,"non_scroll_editor_requires_actual_webview_ancestor");
        altered("editor_same_path_is_not_descendant","n10","path","0/1/0","non_scroll_editor_requires_actual_webview_ancestor");
        altered("path_prefix_without_segment_rejected","n10","path","0/1/00/0","non_scroll_editor_requires_actual_webview_ancestor");
        altered("valid_sibling_path_rejected","n10","path","0/2/0/0","non_scroll_editor_requires_actual_webview_ancestor");
        altered("editor_missing_actual_signature_rejected","n10","node_sha",null,"non_scroll_editor_requires_actual_webview_ancestor");
        test("two_NoteEditor_labels_ambiguous",()->{
            NotesCompletionEvidence.Node extra=edit(edit(node(frame(0),"n4"),"id","n90"),"path","0/3");
            denied(add(frame(0),extra),"unique_observed_NoteEditor_context_required");
        });
        test("duplicate_ancestor_position_rejected",()->{
            NotesCompletionEvidence.Node extra=edit(edit(node(frame(0),"n0"),"id","n90"),"path","0/1/0");
            denied(add(frame(0),extra),"non_scroll_editor_requires_actual_webview_ancestor");
        });
        test("duplicate_editor_position_rejected",()->{
            NotesCompletionEvidence.Node extra=edit(edit(node(frame(0),"n0"),"id","n90"),"path","0/1/0/0/0/0");
            denied(add(frame(0),extra),"non_scroll_editor_requires_actual_webview_ancestor");
        });
        test("two_editables_ambiguous",()->denied(add(frame(0),edit(node(frame(0),"n10"),"id","n90")),"unique_enabled_nonpassword_editable_required"));
        altered("foreign_package_context_rejected","n4","package","com.example.other","unique_observed_NoteEditor_context_required");
        altered("disabled_context_rejected","n4","enabled",false,"unique_observed_NoteEditor_context_required");
        altered("password_context_rejected","n4","password",true,"unique_observed_NoteEditor_context_required");
        altered("disabled_editor_rejected","n10","enabled",false,"unique_enabled_nonpassword_editable_required");
        altered("password_editor_rejected","n10","password",true,"unique_enabled_nonpassword_editable_required");
        altered("outside_same_frame_geometry_rejected","n10","bounds",new int[]{60,180,1164,2671},"editable_outside_observed_editor_bounds");
        altered("empty_editor_geometry_rejected","n10","bounds",new int[]{60,181,60,2671},"editable_outside_observed_editor_bounds");
        test("wrong_OWNER_body_rejected",()->denied(frame(0),CapturedNotesFixtures.BODIES[0]+"X",installed(),"observed_body_differs_from_supported_forms"));
        test("different_full_raw_text_rejected",()->denied(text(CapturedNotesFixtures.BODIES[0]+"X"),"observed_body_differs_from_supported_forms"));
        altered("complete_input_SHA_mismatch_rejected","n10","input_sha",ObservedImeEnter.hash("wrong"),"complete_input_sha_does_not_match_observed_text");
        test("39LF_not_40_rejected",()->denied(text(CapturedNotesFixtures.BODIES[0]+lf(39)),"observed_body_differs_from_supported_forms"));
        test("41LF_not_40_rejected",()->denied(text(CapturedNotesFixtures.BODIES[0]+lf(41)),"observed_body_differs_from_supported_forms"));
        test("40LF_wrong_installed_APK_rejected",()->{
            Map<String,String> h=new LinkedHashMap<String,String>(installed().apkHashes);h.put("base",ObservedImeEnter.hash("another apk"));
            denied(frame(0),CapturedNotesFixtures.BODIES[0],new NotesCompletionEvidence.Installed(NotesCompletionEvidence.NOTES,10382,h),"forty_lf_form_requires_exact_observed_single_base_apk");
        });
        test("40LF_split_APK_rejected",()->{
            Map<String,String> h=new LinkedHashMap<String,String>(installed().apkHashes);h.put("split:extra",ObservedImeEnter.hash("split"));
            denied(frame(0),CapturedNotesFixtures.BODIES[0],new NotesCompletionEvidence.Installed(NotesCompletionEvidence.NOTES,10382,h),"forty_lf_form_requires_exact_observed_single_base_apk");
        });
        test("incomplete_observation_rejected",()->{
            NotesCompletionEvidence.Frame f=frame(0);denied(new NotesCompletionEvidence.Frame(f.observationId,f.packageName,f.windowId,f.displayId,f.backgroundGeneration,f.windowType,true,true,f.nodes),"complete_bounded_observed_nodes_required");
        });
        test("unknown_window_metadata_rejected",()->{
            NotesCompletionEvidence.Frame f=frame(0);denied(new NotesCompletionEvidence.Frame(f.observationId,f.packageName,f.windowId,f.displayId,f.backgroundGeneration,f.windowType,false,false,f.nodes),"observed_application_window_metadata_required");
        });
        test("nonapplication_window_rejected",()->{
            NotesCompletionEvidence.Frame f=frame(0);denied(new NotesCompletionEvidence.Frame(f.observationId,f.packageName,f.windowId,f.displayId,f.backgroundGeneration,2,true,false,f.nodes),"observed_application_window_metadata_required");
        });
        test("background_generation_missing_rejected",()->{
            NotesCompletionEvidence.Frame f=frame(0);denied(new NotesCompletionEvidence.Frame(f.observationId,f.packageName,f.windowId,f.displayId,null,f.windowType,true,false,f.nodes),"display_and_background_generation_must_match");
        });
        test("foreign_frame_package_rejected",()->{
            NotesCompletionEvidence.Frame f=frame(0);denied(new NotesCompletionEvidence.Frame(f.observationId,"com.example.other",f.windowId,f.displayId,f.backgroundGeneration,f.windowType,true,false,f.nodes),"actual_notes_observation_identity_required");
        });
        test("duplicate_node_ID_rejected",()->denied(add(frame(0),node(frame(0),"n0")),"unique_actual_node_ids_required"));
        test("missing_installed_identity_rejected",()->denied(frame(0),CapturedNotesFixtures.BODIES[0],null,"actual_installed_notes_identity_required"));
        test("legacy_two_scrollable_contexts_still_rejected",()->{
            NotesCompletionEvidence.Frame f=frame(4);denied(add(f,edit(node(f,"n4"),"id","n90")),CapturedNotesFixtures.BODIES[4],installed(),"unique_observed_NoteEditor_context_required");
        });
        StringBuilder out=new StringBuilder("{\"schema\":\"hepta.notes-nonscroll-editor-host.v1\",\"all_pass\":true,\"cases\":").append(names.size()).append(",\"assertions\":").append(checks).append(",\"case_names\":[");
        for(int i=0;i<names.size();i++){if(i>0)out.append(',');out.append('"').append(names.get(i)).append('"');}
        System.out.println(out.append("],\"actual_current_frame_replays\":4,\"actual_legacy_frame_replays\":1,\"phone_execution\":false,\"persistent_bytes_verified\":false}"));
    }
}
