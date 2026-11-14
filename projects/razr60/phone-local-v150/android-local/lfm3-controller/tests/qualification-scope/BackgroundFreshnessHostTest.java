package org.trillionnium.hepta.local;

import android.graphics.Rect;
import android.os.SystemClock;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityWindowInfo;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.*;
import org.json.JSONObject;
import static org.trillionnium.hepta.local.QualificationScopeHostTest.*;

/** Actual snapshot/dispatcher/controller methods, with synthetic Android nodes and model IO only. */
final class BackgroundFreshnessHostTest {
    static final int DISPLAY=6;
    static final String RUN="dddddddddddddddddddddddddddddddd";
    static final class GraphSetup {
        final BackgroundObservationFixture fixture=new BackgroundObservationFixture();
        final AccessibilityNodeInfo root=new AccessibilityNodeInfo(SETTINGS,7),child=new AccessibilityNodeInfo(SETTINGS,7);
        GraphSetup(){
            fixture.background=BackgroundSession.fixture("snapshot-only",DISPLAY,Collections.singleton(SETTINGS));
            root.text="container";root.clickable=false;root.viewId="synthetic:id/root";
            root.bounds=new android.graphics.Rect(0,0,1080,2400);root.window.display=DISPLAY;root.window.root=root;
            child.text="old";child.viewId="synthetic:id/field";child.editable=true;child.window.display=DISPLAY;
            root.children.add(child);fixture.windows.add(root.window);
            fixture.foreground=new AccessibilityNodeInfo(FOREIGN[0],99);
        }
        PhoneObservation capture(){return fixture.snapshot();}
    }
    static PhoneObservation.Node field(PhoneObservation value,String id){
        for(PhoneObservation.Node row:value.nodes)if(id.equals(row.viewId))return row;
        throw new AssertionError("missing synthetic node "+id);
    }
    static void freshnessFailure(Runnable action){
        try{action.run();throw new AssertionError("expected snapshot freshness refusal");}
        catch(IllegalStateException changed){check(changed.getMessage().startsWith("stale:"),"explicit transient snapshot failure: "+changed);}
    }
    static void identityFailure(Runnable action){
        try{action.run();throw new AssertionError("expected snapshot identity refusal");}
        catch(IllegalStateException changed){check(!changed.getMessage().startsWith("stale:"),"identity must stay terminal");}
    }
    static void budgetFailure(Runnable action){
        try{action.run();throw new AssertionError("expected read budget refusal");}
        catch(IllegalStateException stopped){check("synthetic read deadline".equals(stopped.getMessage()),"deadline must not be swallowed as a missing label/frame");}
    }
    static void snapshots()throws Exception{
        test("background_snapshot_refreshes_root_before_metadata_and_children_before_text",()->{
            GraphSetup s=new GraphSetup();s.root.onRefresh=()->s.root.className="FreshRoot";s.child.onRefresh=()->s.child.text="fresh";
            PhoneObservation value=s.capture();
            check("FreshRoot".equals(value.windowMetadata.rootClass)&&"fresh".equals(field(value,"synthetic:id/field").text),"actual graph must publish refreshed data");
            check(s.root.refreshes==1&&s.child.refreshes==1&&s.fixture.foregroundReads==0,"refresh root and each visited child, no main-display read");
        });
        test("background_snapshot_old_and_fresh_field_produce_distinct_tree_identity",()->{
            GraphSetup s=new GraphSetup();PhoneObservation before=s.capture();s.child.onRefresh=()->s.child.text="fresh";PhoneObservation after=s.capture();
            check(!before.treeSha256.equals(after.treeSha256)&&!before.state.appTreeSha256.equals(after.state.appTreeSha256),"fresh body changes both graph and app identity");
            check("old".equals(field(before,"synthetic:id/field").text),"published prior observation remains immutable");
        });
        test("background_snapshot_failed_root_refresh_is_transient_without_partial_frame",()->{
            GraphSetup s=new GraphSetup();s.root.refreshResult=false;freshnessFailure(s::capture);
            check(s.root.recycles==1&&s.child.refreshes==0&&s.fixture.foregroundReads==0,"failed root is released and no other display consulted");
        });
        test("background_snapshot_failed_child_refresh_releases_partial_graph",()->{
            GraphSetup s=new GraphSetup();s.child.refreshResult=false;freshnessFailure(s::capture);
            check(s.root.recycles>=2&&s.child.recycles==1,"both traversal references and captured graph are released");
        });
        test("background_snapshot_missing_child_is_transient",()->{
            GraphSetup s=new GraphSetup();s.root.children.set(0,null);freshnessFailure(s::capture);check(s.fixture.foregroundReads==0,"no display fallback");
        });
        test("background_snapshot_refreshes_noninteractive_descendant_label_before_parent_identity",()->{
            GraphSetup s=new GraphSetup();s.root.text="";s.root.clickable=true;s.root.actionOverride=Collections.singletonList(new AccessibilityNodeInfo.AccessibilityAction(AccessibilityNodeInfo.ACTION_CLICK));
            s.child.editable=false;s.child.clickable=false;s.child.actionOverride=Collections.emptyList();s.child.onRefresh=()->s.child.text="fresh label";
            PhoneObservation value=s.capture();check("fresh label".equals(field(value,"synthetic:id/root").childText.text),"parent label cannot retain cached child text");
        });
        test("background_snapshot_failed_label_child_refresh_cannot_be_suppressed_as_empty_label",()->{
            GraphSetup s=new GraphSetup();s.root.text="";s.root.clickable=true;
            s.child.editable=false;s.child.clickable=false;s.child.actionOverride=Collections.emptyList();s.child.refreshResult=false;
            freshnessFailure(s::capture);
        });
        test("background_snapshot_refreshed_foreign_root_is_terminal",()->{
            GraphSetup s=new GraphSetup();s.root.onRefresh=()->s.root.pkg=FOREIGN[0];identityFailure(s::capture);check(s.fixture.foregroundReads==0,"no fallback");
        });
        test("background_snapshot_wrong_display_and_ime_roots_are_never_traversed",()->{
            GraphSetup s=new GraphSetup();AccessibilityNodeInfo foreign=new AccessibilityNodeInfo(FOREIGN[0],99);foreign.window.root=foreign;foreign.window.layer=999;
            AccessibilityNodeInfo ime=new AccessibilityNodeInfo("synthetic.ime",8);ime.window.root=ime;ime.window.display=DISPLAY;ime.window.type=AccessibilityWindowInfo.TYPE_INPUT_METHOD;ime.window.layer=999;
            s.fixture.windows.add(foreign.window);s.fixture.windows.add(ime.window);s.capture();
            check(foreign.refreshes==0&&ime.refreshes==0&&s.fixture.foregroundReads==0,"selected immutable display application only");
        });
        test("background_snapshot_refresh_work_retains_production_traversal_bound",()->{
            GraphSetup s=new GraphSetup();s.root.children.clear();
            for(int i=0;i<1600;i++){AccessibilityNodeInfo child=new AccessibilityNodeInfo(SETTINGS,7);child.clickable=false;child.window.display=DISPLAY;s.root.children.add(child);}
            PhoneObservation value=s.capture();int refreshed=s.root.refreshes;for(AccessibilityNodeInfo child:s.root.children)refreshed+=child.refreshes;
            check(value.collectionStats!=null&&value.collectionStats.visitLimit==1536,"actual declared traversal limit is archived");
            check(value.nodesTruncated&&refreshed==1536&&s.root.children.get(1535).refreshes==0,"no refresh outside the explicit v50 bound");
            check(value.collectionStats.visited==1536&&value.collectionStats.childSlotsOmitted==65
                    &&value.collectionStats.pending==0&&value.collectionStats.limitReasons.equals(Collections.singletonList("traversal_limit")),
                    "record the exact acquisition-budget reason without inventing an omitted descendant count");
        });
        test("foreground_snapshot_retains_existing_refresh_behavior",()->{
            GraphSetup s=new GraphSetup();s.fixture.background=null;s.fixture.foreground=s.root;s.root.window.display=0;s.child.window.display=0;s.capture();
            check(s.fixture.foregroundReads==1&&s.root.refreshes==0&&s.child.refreshes==0,"background fix does not change foreground sampler");
        });
        test("observation_budget_after_root_acquisition_releases_root",()->{
            GraphSetup s=new GraphSetup();final boolean[] acquired={false};final int[] checks={0};
            s.root.onRefresh=()->acquired[0]=true;
            budgetFailure(()->s.fixture.budgetedSnapshot(()->{if(acquired[0]&&++checks[0]==2)throw new IllegalStateException("synthetic read deadline");}));
            check(s.root.recycles==1&&s.child.refreshes==0,"root acquired before graph metadata is still released on budget expiry");
        });
        test("observation_budget_during_child_refresh_releases_partial_graph",()->{
            GraphSetup s=new GraphSetup();final boolean[] expired={false};s.child.onRefresh=()->expired[0]=true;
            budgetFailure(()->s.fixture.budgetedSnapshot(()->{if(expired[0])throw new IllegalStateException("synthetic read deadline");}));
            check(s.root.recycles>=2&&s.child.recycles==1,"cancelled traversal releases captured root and child ownership");
        });
        test("observation_budget_in_label_collector_is_not_suppressed",()->{
            GraphSetup s=new GraphSetup();s.root.text="";s.root.clickable=true;
            s.child.editable=false;s.child.clickable=false;s.child.actionOverride=Collections.emptyList();
            final boolean[] expired={false};s.child.onRefresh=()->expired[0]=true;
            budgetFailure(()->s.fixture.budgetedSnapshot(()->{if(expired[0])throw new IllegalStateException("synthetic read deadline");}));
            check(s.child.recycles==1&&s.fixture.foregroundReads==0,"label helper cannot turn cancelled background work into an empty fresh label");
        });
        test("foreground_observation_budget_after_root_acquisition_releases_root",()->{
            GraphSetup s=new GraphSetup();s.fixture.background=null;s.fixture.foreground=s.root;s.root.window.display=0;
            budgetFailure(()->s.fixture.budgetedSnapshot(()->{if(s.fixture.foregroundReads>0)throw new IllegalStateException("synthetic read deadline");}));
            check(s.root.recycles==1&&s.root.refreshes==0,"foreground root remains owned even when expiry precedes metadata");
        });
    }
    private static final String NOTES_LONG_BODY="Hepta261eStopR3_20261113_一在本机记录本次取消验证正文，二检查背景任务已停止，三保留真实运行证据。";
    private static String repeated(char value,int count){char[] chars=new char[count];Arrays.fill(chars,value);return new String(chars);}
    private static GraphSetup notesGraph(String raw){
        GraphSetup s=new GraphSetup();
        s.fixture.background=BackgroundSession.fixture("snapshot-only",DISPLAY,Collections.singleton(NotesCompletionEvidence.NOTES));
        s.root.pkg=NotesCompletionEvidence.NOTES;s.root.className="android.webkit.WebView";s.root.text="NoteEditor";s.root.scrollable=true;
        s.child.pkg=NotesCompletionEvidence.NOTES;s.child.className="android.widget.EditText";s.child.text=raw;
        return s;
    }
    private static NotesCompletionEvidence.Frame notesFrame(PhoneObservation observation)throws Exception{
        java.lang.reflect.Method bridge=LocalTaskController.class.getDeclaredMethod("completionFrame",PhoneObservation.class);
        bridge.setAccessible(true);return (NotesCompletionEvidence.Frame)bridge.invoke(null,observation);
    }
    private static NotesCompletionEvidence.Installed notesIdentity(){
        // Explicit synthetic identity metadata for the unchanged pinned provider rule.
        return new NotesCompletionEvidence.Installed(NotesCompletionEvidence.NOTES,10382,
                Collections.singletonMap("base",NotesCompletionEvidence.OBSERVED_BASE_APK_SHA256));
    }
    private static NotesCompletionEvidence.Frame replaceEditor(NotesCompletionEvidence.Frame frame,String text,String hash){
        List<NotesCompletionEvidence.Node> rows=new ArrayList<NotesCompletionEvidence.Node>();
        for(NotesCompletionEvidence.Node n:frame.nodes)rows.add(!n.editable?n:
                new NotesCompletionEvidence.Node(n.id,n.packageName,text,n.label,n.viewId,hash,n.bounds(),
                        n.editable,n.clickable,n.scrollable,n.enabled,n.password,n.childText,n.observedAppTreeSignature));
        return new NotesCompletionEvidence.Frame(frame.observationId,frame.packageName,frame.windowId,frame.displayId,
                frame.backgroundGeneration,frame.windowType,frame.metadataObserved,frame.nodesTruncated,rows);
    }
    static void notesTextCapture()throws Exception{
        test("notes_raw_capture_preserves_hash_bound_actual_61_plus_40_shape",()->{
            String raw=NOTES_LONG_BODY+repeated('\n',40);GraphSetup s=notesGraph(raw);PhoneObservation o=s.capture();
            PhoneObservation.Node n=field(o,"synthetic:id/field");
            // The full string is reconstructed as a synthetic input; its hash is
            // the native input hash from the retained v61 NoCoex sample, not an
            // assertion that the old collector saved those untruncated bytes.
            check(NOTES_LONG_BODY.length()==61&&raw.length()==101
                    &&"90ef53f73367891a1eb865b56455f56938771d8bd23423b4649c295d4099e40b".equals(ObservedImeEnter.hash(raw)),
                    "constructed input matches actual native full-input SHA");
            check(raw.equals(n.text)&&ObservedImeEnter.hash(raw).equals(n.inputTextSha256),"actual graph retains the complete native string and its independent hash");
            NotesCompletionEvidence.BodyEvidence e=NotesCompletionEvidence.editor(notesFrame(o),NOTES_LONG_BODY,notesIdentity());
            check(e.matched&&!e.rawExact&&e.trailingLfCount==40&&!e.persistentBytesVerified,"unchanged exact provider rule verifies the complete captured body, not storage");
        });
        test("notes_raw_capture_covers_maximum_94_body_plus_40_lf",()->{
            String body=repeated('甲',94),raw=body+repeated('\n',40);GraphSetup s=notesGraph(raw);
            PhoneObservation o=s.capture();check(raw.length()==134&&raw.equals(field(o,"synthetic:id/field").text),"full supported 134 UTF16 raw evidence");
            check(NotesCompletionEvidence.editor(notesFrame(o),body,notesIdentity()).matched,"maximum supported body passes unchanged strict provider");
        });
        test("notes_truncated_ellipsis_remains_rejected",()->{
            String raw=NOTES_LONG_BODY+repeated('\n',40);NotesCompletionEvidence.Frame f=notesFrame(notesGraph(raw).capture());
            String old=raw.substring(0,96)+"…";
            check("86043be633ebce513774534b6a05afbed9897bf0eb8350af9b066dde5a583efc".equals(ObservedImeEnter.hash(old)),"retained actual v61 truncated text SHA");
            NotesCompletionEvidence.BodyEvidence e=NotesCompletionEvidence.editor(replaceEditor(f,old,ObservedImeEnter.hash(raw)),NOTES_LONG_BODY,notesIdentity());
            check(!e.matched&&"complete_input_sha_does_not_match_observed_text".equals(e.missing),"ellipsis cannot stand for omitted raw bytes");
        });
        test("notes_appended_character_remains_rejected",()->{
            String raw=NOTES_LONG_BODY+repeated('\n',40)+"X";NotesCompletionEvidence.Frame f=notesFrame(notesGraph(raw).capture());
            check(!NotesCompletionEvidence.editor(f,NOTES_LONG_BODY,notesIdentity()).matched,"complete raw extra character is not trimmed away");
        });
        test("notes_wrong_lf_count_remains_rejected",()->{
            for(int count:new int[]{39,41}){
                String raw=NOTES_LONG_BODY+repeated('\n',count);
                check(!NotesCompletionEvidence.editor(notesFrame(notesGraph(raw).capture()),NOTES_LONG_BODY,notesIdentity()).matched,"only exact40LF provider form accepted");
            }
        });
        test("notes_hash_mismatch_and_label_only_remain_rejected",()->{
            String raw=NOTES_LONG_BODY+repeated('\n',40);NotesCompletionEvidence.Frame f=notesFrame(notesGraph(raw).capture());
            check(!NotesCompletionEvidence.editor(replaceEditor(f,raw,ObservedImeEnter.hash("different native input")),NOTES_LONG_BODY,notesIdentity()).matched,"full raw SHA remains mandatory");
            check(!NotesCompletionEvidence.editor(replaceEditor(f,"",ObservedImeEnter.hash("")),NOTES_LONG_BODY,notesIdentity()).matched,"existing display label cannot replace missing native text");
        });
        test("notes_raw_capture_over_bound_remains_incomplete",()->{
            String body=repeated('甲',94),raw=body+repeated('\n',40)+"X";PhoneObservation o=notesGraph(raw).capture();
            check(field(o,"synthetic:id/field").text.length()==135&&field(o,"synthetic:id/field").text.endsWith("…"),"one explicit ellipsis after134-unit evidence cap");
            check(!NotesCompletionEvidence.editor(notesFrame(o),body,notesIdentity()).matched,"over-bound raw text cannot pass full-input hash");
        });
        test("non_notes_raw_text_retains_original_96_bound",()->{
            GraphSetup s=new GraphSetup();s.child.text=repeated('甲',134);PhoneObservation o=s.capture();
            check(field(o,"synthetic:id/field").text.equals(repeated('甲',96)+"…"),"unrelated app raw capture unchanged");
        });
        test("notes_larger_per_node_evidence_retains_global_payload_bound",()->{
            GraphSetup s=notesGraph(repeated('甲',94)+repeated('\n',40));s.root.children.clear();
            for(int i=0;i<60;i++){
                AccessibilityNodeInfo n=new AccessibilityNodeInfo(NotesCompletionEvidence.NOTES,7);
                n.text=s.child.text;n.editable=true;n.window.display=DISPLAY;n.viewId="synthetic:id/field"+i;s.root.children.add(n);
            }
            PhoneObservation o=s.capture();JSONObject c=o.toJson().getJSONObject("collection");
            check(o.nodesTruncated&&c.getInt("text_utf16_exclusive_limit")==6144&&c.getInt("retained_text_utf16")<6144
                    &&c.getInt("nodes_omitted_by_text_limit")>0,"original global text cap still refuses overflowing evidence");
        });
    }
    static final class DispatchSetup implements AutoCloseable {
        final Env env=new Env(false);final HeptaAccessibilityService service=env.service;final BackgroundSession background;
        DispatchSetup()throws Exception{
            env.bind(null);background=BackgroundSession.fixture(env.task,DISPLAY,new LinkedHashSet<String>(Arrays.asList(SETTINGS,SEARCH)));
            service.bindBackgroundSession(env.task,background);service.root.window.display=DISPLAY;service.node.window.display=DISPLAY;capture();
        }
        void capture(){service.observe(env.task,env.dir.toFile(),()->false,Long.MAX_VALUE,new HeptaAccessibilityService.ObservationCallback(){
            public void onObservation(PhoneObservation value){}public void onError(String error){throw new AssertionError(error);}});}
        ActionDecision action(String kind)throws Exception{return ActionDecision.parse(raw(service.current,kind),ActionDecision.IME_ACTION_SCHEMA);}
        HeptaAccessibilityService.ActionOutcome run(ActionDecision action){
            PhoneObservation observed=service.current;ObservedTargetLabels targets=ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,observed.id,observed.packageName,
                    Collections.singletonMap("n0",ObservedTargetLabels.project(observed.nodes.get(0).label())));
            final HeptaAccessibilityService.ActionOutcome[] reply={null};service.perform(env.task,observed,action,targets,service.taskAuthorization,RUN,()->false,value->reply[0]=value);
            service.awaitWorkers();
            check(reply[0]!=null,"bounded actual worker result");return reply[0];
        }
        public void close(){background.close();env.close();}
    }
    static String raw(PhoneObservation observed,String kind)throws Exception{
        JSONObject value=new JSONObject().put("reason","依据本次观察决定下一步").put("action",kind).put("observation_id",observed.id).put("package",observed.packageName);
        if("type".equals(kind)||"click".equals(kind)||"scroll".equals(kind)||"submit".equals(kind))
            value.put("node_label",ObservedTargetLabels.project(observed.nodes.get(0).label())).put("node_id","n0");
        if("type".equals(kind))value.put("text","replacement");if("scroll".equals(kind))value.put("direction","forward");
        if("done".equals(kind))value.put("status","partial").put("summary","synthetic model ended; no business success claim");
        return value.toString();
    }
    static void stale(DispatchSetup s,HeptaAccessibilityService.ActionOutcome result)throws Exception{
        check(!result.accepted&&!result.dispatched&&result.stale&&s.service.effects()==0,"freshness refusal has zero dispatch and requests new inference");
        check(!result.qualificationScope.getBoolean("scope_refused")&&!s.env.bound.restricted(),"stale does not poison original scope");
    }
    static void terminal(DispatchSetup s,HeptaAccessibilityService.ActionOutcome result){
        check(!result.accepted&&!result.dispatched&&!result.stale&&s.service.effects()==0,"identity/authority failure stays terminal with zero effects");
    }
    static void dispatch()throws Exception{
        for(String kind:new String[]{"click","type","scroll","submit"})test("background_"+kind+"_content_change_is_stale_not_scope_refusal",()->{try(DispatchSetup s=new DispatchSetup()){
            ActionDecision action=s.action(kind);s.service.node.onRefresh=()->s.service.node.text="changed";stale(s,s.run(action));
        }});
        test("background_missing_ref_is_terminal",()->{try(DispatchSetup s=new DispatchSetup()){
            ActionDecision action=ActionDecision.parse(new JSONObject(raw(s.service.current,"click")).put("node_id","n999").toString(),ActionDecision.IME_ACTION_SCHEMA);terminal(s,s.run(action));
        }});
        test("background_invalid_label_stays_terminal_before_stale_node_refresh",()->{try(DispatchSetup s=new DispatchSetup()){
            ActionDecision action=ActionDecision.parse(new JSONObject(raw(s.service.current,"type")).put("node_label","forged").toString(),ActionDecision.IME_ACTION_SCHEMA);
            s.service.node.onRefresh=()->s.service.node.text="changed";terminal(s,s.run(action));check(s.service.node.refreshes==0,"invalid pair is rejected before freshness branch");
        }});
        test("background_failed_node_refresh_is_stale_without_dispatch",()->{try(DispatchSetup s=new DispatchSetup()){
            s.service.node.refreshResult=false;stale(s,s.run(s.action("click")));
        }});
        for(String changed:new String[]{"foreign_package","other_allowed_package","window","window_object","display","type"})test("background_identity_"+changed+"_never_becomes_stale",()->{try(DispatchSetup s=new DispatchSetup()){
            s.service.node.onRefresh=()->{
                s.service.node.text="changed";
                if("foreign_package".equals(changed))s.service.node.pkg=FOREIGN[0];
                if("other_allowed_package".equals(changed))s.service.node.pkg=SEARCH;
                if("window".equals(changed))s.service.node.windowId=8;
                if("window_object".equals(changed))s.service.node.window.id=8;
                if("display".equals(changed))s.service.node.window.display=0;
                if("type".equals(changed))s.service.node.window.type=AccessibilityWindowInfo.TYPE_INPUT_METHOD;
            };terminal(s,s.run(s.action("type")));
        }});
        test("background_retired_during_refresh_is_terminal_even_when_content_changed",()->{try(DispatchSetup s=new DispatchSetup()){
            s.service.node.onRefresh=()->{s.background.close();s.service.node.text="changed";};terminal(s,s.run(s.action("click")));
        }});
        test("background_new_scope_file_is_terminal_before_refresh",()->{try(DispatchSetup s=new DispatchSetup()){
            ActionDecision action=s.action("click");s.env.writeConfig();s.service.node.onRefresh=()->s.service.node.text="changed";
            terminal(s,s.run(action));check(s.service.node.refreshes==0,"scope identity is checked first");
        }});
        test("background_final_predispatch_change_does_not_replay_old_action",()->{try(DispatchSetup s=new DispatchSetup()){
            // First refresh is initial background check, second is core validation,
            // third is the final immediately-before-effect check in this fixture.
            s.service.node.onRefresh=()->{if(s.service.node.refreshes==3)s.service.node.text="changed at final gate";};
            stale(s,s.run(s.action("click")));check(s.service.node.refreshes==3,"exercise final gate, not first check");
        }});
        test("background_fresh_type_is_exact_replacement_without_implicit_submit",()->{try(DispatchSetup s=new DispatchSetup()){
            HeptaAccessibilityService.ActionOutcome result=s.run(s.action("type"));
            check(result.accepted&&result.dispatched&&!result.stale&&s.service.effects()==1,"one permitted fresh type");
            check("replacement".equals(s.service.node.text)&&s.service.node.lastAction==AccessibilityNodeInfo.ACTION_SET_TEXT,"whole field replacement only");
        }});
        test("background_consumed_submit_stale_during_journal_is_terminal_not_retry",()->{try(DispatchSetup s=new DispatchSetup()){
            s.service.node.imePresent=true;s.service.node.imeLabel="搜索";
            SubmitAttemptGuard ledger=new SubmitAttemptGuard(s.env.task,attempt->s.service.node.text="changed during durable journal");
            s.service.bindSubmitAttempts(s.env.task,ledger);s.capture();String input=s.service.current.nodes.get(0).inputTextSha256;
            HeptaAccessibilityService.ActionOutcome result=s.run(s.action("submit"));terminal(s,result);
            check(result.imeSubmit!=null&&result.imeSubmit.getBoolean("attempt_consumed")&&!result.imeSubmit.getBoolean("automatic_retry_allowed"),"consumed stale is never reusable");
            check(!ledger.available(SETTINGS,input),"consumption survives zero platform effect");
        }});
    }
    static void controller(boolean continuous)throws Exception{
        try(Env e=new Env(false)){
            BackgroundSession.controllerDisplay=DISPLAY;e.service.root.window.display=DISPLAY;e.service.node.window.display=DISPLAY;
            final List<String> observations=new ArrayList<String>(),prompts=new ArrayList<String>();final int[] calls={0};
            LocalInference model=new LocalInference(){
                public LocalRuntimeConfig configuration(){return e.runtime;}
                public TaskCleanup endTask(){return TaskCleanup.noWorker();}
                public Handle generate(String prompt,String system,File image,DecisionGrammar grammar,int max,long timeout,Callback callback){
                    try{
                        int step=++calls[0];observations.add(e.service.current.id);prompts.add(prompt);
                        String answer=raw(e.service.current,continuous||step==1?"click":"done");
                        if(continuous||step==1)e.service.node.onRefresh=()->{e.service.node.onRefresh=null;e.service.node.text="fresh observation "+step;};
                        callback.onSuccess(answer,String.format(Locale.ROOT,"%032x",step));return ()->{};
                    }catch(Exception error){throw new IllegalStateException(error);}
                }
            };
            e.controller=new LocalTaskController(e.service,model);final LocalTaskController.TaskResult[] result={null};CountDownLatch completed=new CountDownLatch(1);
            String owner="在设置应用检查当前页面，依据新观察执行。";
            BackgroundTaskTarget target=BackgroundTaskTarget.resolveExplicitSelection(owner,SETTINGS,Collections.singleton(SETTINGS));
            BackgroundSession.Selection selection=new BackgroundSession.Selection(target);
            TaskAuthorization authorization=TaskAuthorization.parse(owner).forExecutionSelection(selection);
            check(e.controller.start(owner,null,authorization,selection,new LocalTaskController.Listener(){
                public void onState(String state){}public void onFinished(LocalTaskController.TaskResult value){result[0]=value;completed.countDown();}}),"ordinary background controller starts");
            check(completed.await(10,TimeUnit.SECONDS),"controller terminates");
            check(e.service.effects()==0&&result[0].cleanupKnown&&!result[0].modelReportedSuccess,"no stale action, automatic replay, or synthetic success");
            check(new HashSet<String>(observations).size()==calls[0],"every retry invokes model with a genuinely new observation id");
            JSONObject rejected=new JSONObject(new String(Files.readAllBytes(result[0].evidenceDirectory.toPath().resolve("step-01-action.json")),StandardCharsets.UTF_8));
            check(rejected.getBoolean("stale")&&!rejected.getBoolean("dispatched")&&!rejected.getJSONObject("qualification_scope").getBoolean("scope_refused"),"actual task receipt preserves retry reason without scope poison");
            if(continuous)check(calls[0]==3&&result[0].steps==3&&"failed".equals(result[0].status)&&result[0].summary.contains("连续变化"),"existing two-retry ceiling is unchanged");
            else check(calls[0]==2&&result[0].steps==2&&prompts.get(1).contains("fresh observation 1")&&prompts.get(1).contains("action_rejected"),"second inference sees new body and prior rejection, never a re-issued old action");
        }finally{BackgroundSession.controllerDisplay=-1;}
    }

    private static List<PhoneObservation.Node> readinessRows(String body,boolean ready){
        List<PhoneObservation.Node> out=new ArrayList<PhoneObservation.Node>();
        out.add(new PhoneObservation.Node("n0",NotesCompletionEvidence.NOTES,"android.webkit.WebView","","NoteEditor","",
                new Rect(10,200,1000,1800),false,false,true,true,false,false,ObservedChildText.notApplicable(),
                ObservedScrollActions.UNKNOWN,ObservedImeEnter.UNKNOWN,null,false));
        if(ready)out.add(new PhoneObservation.Node("n1",NotesCompletionEvidence.NOTES,"android.widget.EditText","",""+body,"",
                new Rect(20,300,900,600),false,true,false,true,false,false,ObservedChildText.notApplicable(),
                ObservedScrollActions.UNKNOWN,ObservedImeEnter.UNKNOWN,ObservedImeEnter.hash(body),false));
        return out;
    }
    private static Object readinessField(Object value,String name)throws Exception{
        java.lang.reflect.Field f=value.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(value);
    }
    @SuppressWarnings("unchecked")
    private static void readinessControllerCase(String mode)throws Exception{
        final String pkg=NotesCompletionEvidence.NOTES,body="HostReadiness261e",owner="记一下，"+body;
        try(Env e=new Env(false)){
            BackgroundSession bg=null;
            try{
                android.content.pm.PackageInfo info=new android.content.pm.PackageInfo();info.packageName=pkg;info.version=104;
                info.applicationInfo=new android.content.pm.ApplicationInfo();info.applicationInfo.packageName=pkg;info.applicationInfo.uid=10382;
                java.nio.file.Path apk=e.dir.resolve("installed/notes-readiness.apk");
                QualificationScopeHostTest.write(apk,"synthetic Notes APK, not phone bytes".getBytes(StandardCharsets.UTF_8),0644);
                info.applicationInfo.sourceDir=apk.toString();e.pm.packages.put(pkg,info);
                e.service.prepare(pkg);e.service.root.window.display=DISPLAY;e.service.node=null;
                check(e.service.acquireTask(e.task,()->{}),"readiness synthetic lease acquired");
                e.bound=QualificationScopeConfig.capture(e.service,e.task,null,e.runtime);e.service.bindQualificationScope(e.task,e.bound);
                TaskAuthorization authorization=TaskAuthorization.parse(owner);TaskAuthorization.Gate auth=e.service.bindTaskAuthorization(e.task,authorization);
                bg=BackgroundSession.fixture(e.task,DISPLAY,Collections.singleton(pkg));e.service.bindBackgroundSession(e.task,bg);
                QualificationScopeConfig.CompletionInstalledIdentity installed=QualificationScopeConfig.CompletionInstalledIdentity.captureNotes(e.service);
                TaskCompletionGate completion=new TaskCompletionGate(e.task,owner,authorization);
                completion.bindInstalled(new NotesCompletionEvidence.Installed(installed.packageName,installed.uid,installed.apkHashes));
                final int[] providerCalls={0};
                e.service.observationRows=()->readinessRows(body,mode.equals("immediate")||(!mode.equals("never")&&++providerCalls[0]>1));
                e.service.observe(e.task,e.dir.toFile(),()->false,SystemClock.elapsedRealtime()+10000,new HeptaAccessibilityService.ObservationCallback(){
                    public void onObservation(PhoneObservation o){}public void onError(String why){throw new AssertionError(why);}
                });
                final PhoneObservation initial=e.service.current;
                java.lang.reflect.Method bridge=LocalTaskController.class.getDeclaredMethod("completionFrame",PhoneObservation.class);bridge.setAccessible(true);
                NotesCompletionEvidence.Frame first=(NotesCompletionEvidence.Frame)bridge.invoke(null,initial);
                NotesCompletionEvidence.Frame before=new NotesCompletionEvidence.Frame("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",pkg,3,DISPLAY,bg.generation,1,true,false,Collections.<NotesCompletionEvidence.Node>emptyList());
                String run="dddddddddddddddddddddddddddddddd";
                ActionDecision parent=ActionDecision.parse(new JSONObject().put("reason","synthetic host accepted create")
                        .put("action","notes.create").put("app_label","Moto").put("package",pkg).put("observation_id",before.observationId)
                        .put("text",body).toString(),ActionDecision.FIXED_INTENT_ACTION_SCHEMA);
                Map<String,Object> target=new LinkedHashMap<String,Object>();
                org.trillionnium.hepta.background.FixedIntentTools.Profile profile=org.trillionnium.hepta.background.FixedIntentTools.forAction("notes.create");
                target.put("package",pkg);target.put("component",pkg+"/"+profile.className);target.put("action","notes.create");
                target.put("app_label","Moto");target.put("target_uid",10382);
                for(String key:new String[]{"exported","activity_enabled","application_enabled","declared_intent_filter_matched","ordinary_caller_permission_checked"})target.put(key,true);
                Map<String,Object> fixed=new LinkedHashMap<String,Object>();
                fixed.put("schema","hepta.fixed-intent-result.v1");fixed.put("task_id",e.task);fixed.put("model_run_id",run);
                fixed.put("observation_id",before.observationId);fixed.put("source_package",pkg);fixed.put("source_window_id",before.windowId);
                fixed.put("display_id",DISPLAY);fixed.put("background_generation",bg.generation);fixed.put("action","notes.create");
                for(String key:new String[]{"attempt_consumed","dispatch_attempted","api_accepted"})fixed.put(key,true);
                fixed.put("automatic_retry_allowed",false);fixed.put("result","launch_accepted");fixed.put("payload_sha256",ObservedImeEnter.hash(body));
                fixed.put("attempt_ordinal",1);fixed.put("attempt_id",ObservedImeEnter.hash(e.task+"|1|notes.create|"+ObservedImeEnter.hash(body)));fixed.put("target",target);
                completion.action(1,run,parent,true,true,false,before,first,fixed);
                check(completion.notesPhase(first).launchProved,"strict synthetic parent receipt is actually admitted");
                e.controller=new LocalTaskController(e.service,new QualificationScopeHostTest.CountingModel(e,"done",pkg,null));
                java.nio.file.Path dir=Files.createDirectory(e.dir.resolve("readiness-case"));
                byte[] firstBytes=initial.toJson().toString(2).getBytes(StandardCharsets.UTF_8);
                QualificationScopeHostTest.write(dir.resolve("step-01-after.json"),firstBytes,0600);
                int observationsBefore=e.service.observations;
                if(mode.equals("window"))e.service.cacheClearHook=()->{e.service.root.windowId=8;e.service.root.window.id=8;};
                if(mode.equals("duplicate"))e.service.cacheClearHook=()->e.service.observations--;
                if(mode.equals("changed-apk"))e.service.cacheClearHook=()->{try{QualificationScopeHostTest.write(apk,"changed synthetic APK".getBytes(StandardCharsets.UTF_8),0644);}catch(Exception bad){throw new IllegalStateException(bad);}};
                if(mode.equals("cancel"))e.service.cacheClearHook=()->{try{
                    java.lang.reflect.Field cancelled=LocalTaskController.class.getDeclaredField("cancelled");cancelled.setAccessible(true);
                    ((java.util.concurrent.atomic.AtomicBoolean)cancelled.get(e.controller)).set(true);
                }catch(Exception bad){throw new IllegalStateException(bad);}};
                if(mode.equals("cache-false"))e.service.cacheClearResult=false;
                if(mode.equals("sdk32"))android.os.Build.VERSION.SDK_INT=32;
                long deadline=mode.equals("expired")?SystemClock.elapsedRealtime()-1:SystemClock.elapsedRealtime()+15000;
                java.lang.reflect.Method method=LocalTaskController.class.getDeclaredMethod("awaitNotesCreatedEditor",String.class,File.class,int.class,String.class,
                        TaskAuthorization.Gate.class,TaskCompletionGate.class,QualificationScopeConfig.CompletionInstalledIdentity.class,PhoneObservation.class,long.class);
                method.setAccessible(true);Object result=method.invoke(e.controller,e.task,dir.toFile(),1,run,auth,completion,installed,initial,deadline);
                Exception error=(Exception)readinessField(result,"error");
                List<NotesCreateWorkflow.Observation> reads=(List<NotesCreateWorkflow.Observation>)readinessField(result,"reads");
                JSONObject receipt=new JSONObject(new String(Files.readAllBytes(dir.resolve((String)readinessField(result,"receiptFile"))),StandardCharsets.UTF_8));
                boolean success=mode.equals("immediate")||mode.equals("delayed")||mode.equals("cache-false")||mode.equals("sdk32");
                check((error==null)==success&&receipt.getBoolean("body_verified")==success,"actual helper result follows only observed body and current fences: "+mode);
                check(java.util.Arrays.equals(firstBytes,Files.readAllBytes(dir.resolve("step-01-after.json"))),"actual first-after bytes are never overwritten");
                check(e.service.effects()==0&&receipt.getInt("model_requests")==0&&receipt.getInt("app_actions")==0,"readiness dispatches no app/model effect");
                check(reads.size()<=4&&e.service.observations-observationsBefore<=3,"real helper enforces four observations total");
                check(e.service.cacheClears==(mode.equals("immediate")||mode.equals("expired")||mode.equals("sdk32")?0:1),"at most one actual client-cache IO call");
                check(!completion.controllerWorkflowReady((NotesCompletionEvidence.Frame)bridge.invoke(null,(PhoneObservation)readinessField(result,"observation"))),
                        "readiness alone never proves save/list/reopen");
                if(mode.equals("window")||mode.equals("duplicate")){
                    org.json.JSONArray samples=receipt.getJSONArray("samples");check(samples.length()==2,"rejected returned frame stays in actual samples");
                    JSONObject rejected=samples.getJSONObject(1);
                    check(!rejected.getBoolean("validation_accepted")&&receipt.getString("last_observation_file").equals(rejected.getString("observation_file")),
                            "failure receipt points to the rejected raw observation");
                    JSONObject archived=new JSONObject(new String(Files.readAllBytes(dir.resolve(rejected.getString("observation_file"))),StandardCharsets.UTF_8));
                    check(archived.getString("observation_id").equals(rejected.getString("observation_id"))
                            &&archived.getInt("window_id")==rejected.getInt("window_id"),"foreign or repeated raw frame is actually retained before refusal");
                }
                if(mode.equals("never"))check(reads.size()==4&&!receipt.getBoolean("body_verified"),"missing subtree stops at the fixed read bound");
                if(success&&!mode.equals("immediate"))check(reads.size()==2,"a newly complete body stops further reads");
                if(mode.equals("cancel")||mode.equals("changed-apk"))check(e.service.observations==observationsBefore,"cancellation or installed change after reset causes no new read");
                if(mode.equals("sdk32"))check(!receipt.getJSONObject("client_cache_reset").getBoolean("api33_supported"),"unsupported cache API is explicit, never emulated");
                if(mode.equals("cache-false"))check(!receipt.getJSONObject("client_cache_reset").getBoolean("clear_cache_returned"),"false cache return is retained; later actual body decides");
            }finally{android.os.Build.VERSION.SDK_INT=33;if(bg!=null)bg.close();}
        }
    }
    private static void readinessController()throws Exception{
        for(final String mode:new String[]{"immediate","delayed","never","window","duplicate","changed-apk","cancel","expired","cache-false","sdk32"})
            test("notes_created_editor_actual_controller_readiness_"+mode,()->readinessControllerCase(mode));
    }
    static void run()throws Exception{
        readinessController();
        snapshots();notesTextCapture();dispatch();
        test("background_controller_stale_reobserves_and_calls_model_before_next_action",()->controller(false));
        test("background_controller_continuous_stale_stops_after_existing_two_retries",()->controller(true));
    }
}
