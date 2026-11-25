package org.trillionnium.hepta.local;

import android.graphics.Rect;
import android.net.LocalSocket;
import android.os.SystemClock;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import org.json.JSONObject;
import org.trillionnium.hepta.background.WindowOwnership;

/** Actual complete Phone/adapter/Frame/Session/Domain/Guard consumers. The
 * BackgroundSession socket/display/clock and complete censuses are explicit
 * synthetic host inputs. No Android BFS, live node, platform effect, model,
 * installed phone or business-success qualification is claimed by this gate. */
public final class NativeFormHistoryConsumersHostTest {
    static final long START=1000000L;
    static final String OWNER=NativeProfileIdentityHostTest.FLIGHT;
    static final List<String> names=new ArrayList<String>();
    static final List<Map<String,Object>> results=new ArrayList<Map<String,Object>>();
    static int assertions;
    interface Work {void run()throws Exception;}
    static void check(boolean yes,String why){assertions++;if(!yes)throw new AssertionError(why);}
    static void denied(Work body,String fragment)throws Exception {
        boolean refused=false;
        try{body.run();}
        catch(IllegalArgumentException|IllegalStateException|IOException|ActionDecision.InvalidActionException e){
            refused=true;check(e.getMessage()!=null&&(fragment==null||e.getMessage().contains(fragment)),"wrong refusal: "+e);
        }
        check(refused,"expected actual consumer refusal");
    }
    static void one(String name,Work body){
        if(names.contains(name))throw new AssertionError("duplicate case");
        LocalSocket.reset();SystemClock.now=START;names.add(name);
        Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name);
        int before=assertions;
        try{body.run();row.put("passed",true);}
        catch(Throwable error){row.put("passed",false);row.put("error",error.toString());
            java.io.StringWriter stack=new java.io.StringWriter();error.printStackTrace(new java.io.PrintWriter(stack));row.put("stack",stack.toString());}
        row.put("assertions",assertions-before);results.add(row);
    }
    static String id(){return UUID.randomUUID().toString().replace("-","");}
    static String hash(String value){return NativeAppEvidence.hash(value);}
    static Map<String,Object> map(){return new TreeMap<String,Object>();}
    static Map<String,Object> obj(Object value){
        if(!(value instanceof Map))throw new AssertionError("explicit test object expected");
        Map<String,Object> out=map();for(Map.Entry<?,?> e:((Map<?,?>)value).entrySet())out.put((String)e.getKey(),e.getValue());return out;
    }
    static Map<String,Object> mark(long events,long content){Map<String,Object> out=map();
        out.put("events",events);out.put("unknown",0L);out.put("content",content);out.put("boundary",2L);return out;}
    static String fullSignature(String path){String base=hash("synthetic-original-node:"+path);
        return ObservedImeEnter.ABSENT.bindFreshness(ObservedScrollActions.observed(Collections.<String>emptyList())
                .bindFreshness(ObservedChildText.notApplicable().bind(base)),false,null);}
    static NativeActionSnapshotCheckHostTest.Fixture form(){
        NativeActionSnapshotCheckHostTest.Fixture raw=NativeActionSnapshotCheckHostTest.form(NativeActionSnapshotCheck.YEAR);
        for(Map<String,Object> row:raw.nodes.values()){
            row.put("scroll_actions",ObservedScrollActions.observed(Collections.<String>emptyList()).fingerprintInput());
            row.put("ime_enter",ObservedImeEnter.ABSENT.fingerprintInput());
            row.put("ref_signature_sha256",hash(fullSignature((String)row.get("path"))));
        }return raw;
    }
    static final class Fixture implements AutoCloseable {
        final NativeProfileIdentityHostTest.Env env;
        final TaskAuthorization authority;final TaskAuthorization.Gate gate;
        final NativeAppSession task;final String selectionSha,token=UUID.randomUUID().toString();
        final List<Map<String,Object>> journal=new ArrayList<Map<String,Object>>();
        int verifies,sequence;
        Fixture()throws Exception{this(OWNER);}
        Fixture(String owner)throws Exception{
            env=new NativeProfileIdentityHostTest.Env(NativeProfileIdentityHostTest.ctrip(),owner);env.active();
            authority=TaskAuthorization.parse(owner).forExecutionSelection(env.session.selection);
            gate=authority.bind(NativeProfileIdentityHostTest.TASK);
            selectionSha=NativeAppObservation.selectionSha(env.session.selection);
            task=new NativeAppSession(NativeProfileIdentityHostTest.TASK,gate,env.session.selection,
                    new NativeAppEvidence.Installed(env.target),selectionSha,env.session.generation,env.session.displayId(),
                    ()->{verifies++;},(name,value)->journal.add(NativeAppEvidence.immutableMap(value)));
        }
        WindowOwnership window(long at)throws Exception{
            SystemClock.now=at;
            // Authenticated transport is the existing explicit host IO port;
            // the actual verifier registers the returned object for later copy.
            LocalSocket.responder=raw->{
                JSONObject request=ProfileClientPort.decode(raw),response=env.reply(raw,env.target,true);
                if("window".equals(request.getString("op"))){
                    WindowOwnership proof=new WindowOwnership(env.target,env.session.generation,env.session.displayId(),
                            request.getInt("window_id"),request.getInt("task_id"),1200,token,UUID.randomUUID().toString(),
                            env.target.profile.userId,env.target.profile.serial,env.target.fullUid,SystemClock.now,SystemClock.now+1000);
                    response.put("window_ownership_wire",proof.wire());
                }
                return ProfileClientPort.frame(response.toString().getBytes(StandardCharsets.UTF_8));
            };
            return env.session.verifyProfileWindow(96,1234,()->false,at+4000);
        }
        ObservedWindowMetadata metadata(){return ObservedWindowMetadata.observed(new int[]{0,0,1224,2992},"android.widget.FrameLayout",
                1,env.session.displayId(),new int[]{0,0,1224,2992},"explicit synthetic Ctrip consumer window");}
        Map<String,Object> reported(){
            Map<String,Object> row=map();row.put("window_id",96);row.put("display_id",env.session.displayId());
            row.put("type",1);row.put("layer",1);row.put("bounds",Arrays.asList(0,0,1224,2992));row.put("focused",true);row.put("active",true);
            Map<String,Object> out=map();out.put("display_id",env.session.displayId());out.put("target_window_id",96);out.put("target_layer",1);
            out.put("windows",Collections.singletonList(row));out.put("other_window_roots_traversed",false);out.put("unreported_windows_excluded",false);return out;
        }
        Map<String,Object> windowFacts(){
            Map<String,Object> out=map();out.put("metadata",metadata().bindFreshness(""));out.put("package",env.target.packageName);
            out.put("window_id",96);out.put("display_id",env.session.displayId());out.put("rotation",0);
            out.put("width",1224);out.put("height",2992);out.put("left",0);out.put("top",0);out.put("right",1224);out.put("bottom",2992);return out;
        }
        Pack history()throws Exception{return new Pack(this,START+(sequence++*1000),true,true);}
        Pack equalAx()throws Exception{return new Pack(this,START+(sequence++*1000),false,false);}
        public void close()throws IOException{env.close();}
    }
    static final class Pack {
        final Fixture owner;final long start,captured;final String observation=id(),tree,state;
        final NativeActionSnapshotCheckHostTest.Fixture original,second;
        final boolean recordedPurposeFixture;
        final WindowOwnership firstWindow,secondWindow;
        final Map<String,Object> binding,first,after,receipt,metadata;
        final ObservationCaptureEvidence capture;
        final List<PhoneObservation.Node> nodes;
        final PhoneObservation observed;final NotesCompletionEvidence.Frame completion;final NativeAppEvidence.Frame frame;
        Pack(Fixture owner,long start,boolean history,boolean change)throws Exception{
            this(owner,start,history,change,null,null);
        }
        /** Explicit host-only complete-census injection for the purpose-geometry gate.
         * The original constructor and all existing fixture behavior are unchanged. */
        Pack(Fixture owner,long start,boolean history,boolean change,
                NativeActionSnapshotCheckHostTest.Fixture recordedFirst,NativeActionSnapshotCheckHostTest.Fixture recordedSecond)throws Exception{
            this.owner=owner;this.start=start;captured=start+100;
            recordedPurposeFixture=recordedFirst!=null;
            if((recordedFirst==null)!=(recordedSecond==null))throw new IllegalArgumentException("both recorded host censuses required");
            original=recordedFirst==null?form():recordedFirst.copy();second=recordedSecond==null?original.copy():recordedSecond.copy();
            if(change&&recordedSecond==null)NativeActionSnapshotCheckHostTest.changedText(second,"0/0/7/0","22w人围观");
            firstWindow=owner.window(start+60);secondWindow=owner.window(start+160);
            tree=NativeAppEvidence.fingerprint(original.nodes);state=hash(tree+"|synthetic hidden IME");
            binding=map();binding.put("task_id",owner.task.taskId);binding.put("owner_sha256",owner.task.goal.ownerSha256);
            binding.put("execution_target_sha256",owner.task.target.targetSha256);binding.put("task_authorization_sha256",owner.authority.sha256);
            binding.put("actual_selection_sha256",owner.selectionSha);binding.put("native_goal_sha256",owner.task.goal.contractSha256);
            binding.put("observation_id",observation);binding.put("package",owner.env.target.packageName);
            binding.put("background_generation",owner.env.session.generation);binding.put("app_tree_sha256",tree);binding.put("observation_state_sha256",state);
            binding.put("display_id",owner.env.session.displayId());binding.put("window_id",96);binding.put("rotation",0);
            binding.put("width",1224);binding.put("height",2992);binding.put("left",0);binding.put("top",0);binding.put("right",1224);binding.put("bottom",2992);
            binding.put("captured_elapsed_ms",captured);binding.put("profile_window",firstWindow.evidence());
            binding.put("profile_action_identity",NativeAppEvidence.profileActionIdentity(firstWindow));binding.put("original_census_captured_elapsed_ms",start+80);
            first=census(original,firstWindow,start+10,start+90,start+80,tree,state);
            String otherTree=change?NativeAppEvidence.fingerprint(second.nodes):tree,otherState=change?hash(otherTree+"|synthetic hidden IME"):state;
            after=census(second,secondWindow,start+150,start+190,start+180,otherTree,otherState);
            receipt=map();receipt.put("schema",history?"hepta.native-ax-form-history.v1":"hepta.native-ax-capture.v1");
            receipt.put("kind",history?ObservationCaptureEvidence.NATIVE_AX_FORM_HISTORY:ObservationCaptureEvidence.NATIVE_AX);
            for(String key:Arrays.asList("visual_model","screenshot_present","publication_refreshes_capture_age","grants_action_authority","business_completion_verified"))receipt.put(key,false);
            receipt.put("binding",binding);receipt.put("first",first);receipt.put("second",after);
            receipt.put("request_started_elapsed_ms",start);receipt.put("request_deadline_elapsed_ms",start+12000);
            receipt.put("sealed_elapsed_ms",start+200);receipt.put("capture_watermark",mark(5,3));
            receipt.put("second_start_watermark",mark(6,4));receipt.put("second_completed_watermark",mark(7,5));
            receipt.put("complete_census_endpoint_frozen",true);receipt.put("complete_census_endpoint_elapsed_ms",start+190);
            if(history){
                Map<String,Object> proof=map();proof.put("phase",NativeCtripFlightPage.FORM);proof.put("installed_set_sha256",owner.task.installed.apkSetSha256);
                proof.put("provider_version_code",NativeCtripFlightPage.VERSION_CODE);proof.put("provider_base_apk_sha256",NativeCtripFlightPage.BASE_APK_SHA256);
                proof.put("comparison",NativeCtripFormObservation.compareAxCensuses(first,after,binding,owner.task.installed.apkSetSha256));
                receipt.put("form_history",proof);receipt.put("historical_form_planning_only",true);receipt.put("published_pair_is_current_tree_claimed",false);
            }
            byte[] encoded=history?ObservationCaptureEvidence.nativeAxFormHistoryBytes(receipt):ObservationCaptureEvidence.nativeAxBytes(receipt);
            Path file=owner.env.directory.resolve(observation+"-native-ax.json");
            Files.write(file,encoded,StandardOpenOption.CREATE_NEW);Files.setPosixFilePermissions(file,PosixFilePermissions.fromString("rw-------"));
            byte[] actual=Files.readAllBytes(file);check(Arrays.equals(actual,encoded),"actual private receipt readback differs");
            capture=history?ObservationCaptureEvidence.fromSealedNativeAxFormHistory(receipt,actual,ObservationCaptureEvidence.hash(actual))
                    :ObservationCaptureEvidence.fromSealedNativeAx(receipt,actual,ObservationCaptureEvidence.hash(actual));
            metadata=new TreeMap<String,Object>(capture.evidence());metadata.put("schema",capture.metadataSchema());
            metadata.put("mode",history?"complete_native_ax_form_history":"complete_native_ax");
            metadata.put("capture_requested_elapsed_ms",captured);metadata.put("published_elapsed_ms",start+250);
            metadata.put("publication_event_watermark",mark(8,6));metadata.put("events_after_complete_census_admitted",history);
            metadata.put("post_census_events_use","historical_form_planning_only");metadata.put("publication_window_matched",true);
            nodes=phoneNodes(original);
            observed=phone(metadata,capture,captured,null,null,nodes);
            completion=completion(nodes,observation,owner.env.session.generation,owner.env.session.displayId());
            Path record=owner.env.directory.resolve(observation+"-phone.json");
            Files.write(record,(observed.toEvidenceJson().toString()+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
            SystemClock.now=start+250;
            frame=NativeAppObservation.copy(owner.task.taskId,owner.gate,owner.env.session,observed,completion,
                    ObservationCaptureEvidence.hash(Files.readAllBytes(record)));
        }
        Map<String,Object> census(NativeActionSnapshotCheckHostTest.Fixture f,WindowOwnership profile,long readStart,long readEnd,long censusAt,String graph,String stateHash){
            Map<String,Object> identity=new TreeMap<String,Object>(binding);
            for(String key:Arrays.asList("observation_id","captured_elapsed_ms","profile_window","profile_action_identity","original_census_captured_elapsed_ms"))identity.remove(key);
            identity.put("app_tree_sha256",graph);identity.put("observation_state_sha256",stateHash);
            Map<String,Object> out=map();out.put("identity",identity);out.put("window",owner.windowFacts());out.put("reported_windows",owner.reported());
            out.put("profile_window",profile.evidence());out.put("profile_owner",NativeAppEvidence.profileActionIdentity(profile));out.put("ime_visibility","hidden");
            out.put("complete",true);out.put("truncated",false);out.put("visited",f.nodes.size());out.put("pending",0);
            out.put("node_budget_omissions",0);out.put("text_budget_omissions",0);out.put("child_slots_omitted",0L);
            out.put("read_started_elapsed_ms",readStart);out.put("read_completed_elapsed_ms",readEnd);out.put("census_captured_elapsed_ms",censusAt);
            out.put("nodes",new ArrayList<Map<String,Object>>(f.nodes.values()));return out;
        }
        List<PhoneObservation.Node> phoneNodes(NativeActionSnapshotCheckHostTest.Fixture f){
            List<PhoneObservation.Node> result=new ArrayList<PhoneObservation.Node>();int index=0;
            for(Map<String,Object> row:f.nodes.values()){
                if(recordedPurposeFixture&&(!Boolean.TRUE.equals(row.get("visible"))
                        ||!(Boolean.TRUE.equals(row.get("clickable"))||Boolean.TRUE.equals(row.get("editable"))
                        ||Boolean.TRUE.equals(row.get("scrollable"))||!((String)row.get("text")).isEmpty()
                        ||!((String)row.get("description")).isEmpty())))continue;
                List<?> b=(List<?>)row.get("bounds");
                result.add(new PhoneObservation.Node("n"+index++,(String)row.get("package"),(String)row.get("class"),(String)row.get("view_id"),
                        (String)row.get("text"),(String)row.get("description"),new Rect((Integer)b.get(0),(Integer)b.get(1),(Integer)b.get(2),(Integer)b.get(3)),
                        (Boolean)row.get("clickable"),(Boolean)row.get("editable"),(Boolean)row.get("scrollable"),(Boolean)row.get("enabled"),
                        (Boolean)row.get("focused"),(Boolean)row.get("password"),ObservedChildText.notApplicable(),
                        ObservedScrollActions.observed(Collections.<String>emptyList()),ObservedImeEnter.ABSENT,null,false,
                        (String)row.get("ref_signature_sha256"),(String)row.get("path"),(String)row.get("parent_class"),
                        (Boolean)row.get("selected"),(Boolean)row.get("checkable"),(Boolean)row.get("checked")));
            }return result;
        }
        PhoneObservation phone(Map<String,Object> meta,ObservationCaptureEvidence proof,long clock,java.io.File image,String screen,List<PhoneObservation.Node> phoneNodes)throws Exception{
            PhoneObservation.CollectionStats stats=new PhoneObservation.CollectionStats(1536,512,6144,original.nodes.size(),phoneNodes.size(),200,0,0,0,0L,80L);
            return new PhoneObservation(observation,owner.env.target.packageName,clock,1224,2992,0,96,new Rect(0,0,1224,2992),image,screen,state,
                    new ObservationState(tree,ImeVisibility.HIDDEN),owner.metadata(),false,phoneNodes,owner.env.session.generation,
                    owner.env.target.packageName,Collections.singletonList(owner.env.target.packageName),stats,owner.env.session.selection.json(),
                    owner.task.goal.ownerSha256,meta,firstWindow,proof);
        }
        NativeAppEvidence.Frame frameWith(List<NativeAppEvidence.Node> observedNodes,ObservationCaptureEvidence proof,String screen){
            return new NativeAppEvidence.Frame(frame.taskId,frame.ownerSha,frame.targetSha,frame.authorizationSha,frame.selectionSha,
                    frame.observationId,frame.packageName,frame.generation,frame.treeSha,frame.stateSha,screen,frame.sourceRecordSha,
                    frame.completionFrameSha,frame.displayId,frame.windowId,frame.rotation,frame.width,frame.height,
                    frame.left,frame.top,frame.right,frame.bottom,frame.capturedElapsedMs,false,true,observedNodes,1,true,frame.profileWindow,proof);
        }
        NativeAppEvidence.Node path(String path){for(NativeAppEvidence.Node node:frame.nodes)if(path.equals(node.path))return node;throw new AssertionError("fixture path");}
        NativeActionSnapshotCheck.Snapshot snapshot(NativeActionSnapshotCheckHostTest.Fixture f,long at){
            NativeActionSnapshotCheckHostTest.Fixture raw=f.copy();
            raw.env.put("task_id",owner.task.taskId);raw.env.put("owner_sha256",owner.task.goal.ownerSha256);
            raw.env.put("target_sha256",owner.task.target.targetSha256);raw.env.put("authorization_sha256",owner.authority.sha256);
            raw.env.put("selection_sha256",owner.selectionSha);raw.env.put("goal_sha256",owner.task.goal.contractSha256);
            raw.env.put("installed_set_sha256",owner.task.installed.apkSetSha256);raw.env.put("origin_observation_id",observation);
            raw.env.put("background_generation",owner.env.session.generation);raw.env.put("display_id",owner.env.session.displayId());
            raw.env.put("window_metadata_sha256",hash(owner.metadata().bindFreshness("")));
            raw.env.put("reported_windows_sha256",NativeAppEvidence.fingerprint(owner.reported()));raw.env.put("captured_elapsed_ms",at);
            raw.env.putAll(NativeAppEvidence.profileActionIdentity(firstWindow));return raw.snapshot();
        }
    }
    static NotesCompletionEvidence.Frame completion(List<PhoneObservation.Node> nodes,String observation,String generation,int display){
        List<NotesCompletionEvidence.Node> values=new ArrayList<NotesCompletionEvidence.Node>();
        for(PhoneObservation.Node n:nodes)values.add(new NotesCompletionEvidence.Node(n.id,n.packageName,n.text,n.label(),n.viewId,null,
                new int[]{n.bounds.left,n.bounds.top,n.bounds.right,n.bounds.bottom},n.editable,n.clickable,n.scrollable,n.enabled,n.password,n.childText,n.observedAppTreeSignature));
        return new NotesCompletionEvidence.Frame(observation,NativeAppGoal.CTRIP_PACKAGE,96,display,generation,1,true,false,values);
    }
    static ActionDecision action(Pack p,String type,String status,String nodeId)throws Exception{
        JSONObject out=new JSONObject().put("action",type).put("package",p.frame.packageName).put("observation_id",p.frame.observationId);
        if(nodeId!=null)out.put("node_id",nodeId).put("node_label",p.frame.byId.get(nodeId).label);
        if("done".equals(type))out.put("status",status).put("summary","explicit synthetic noncompletion");
        if("wait".equals(type))out.put("duration_ms",100);
        if("type".equals(type))out.put("text","synthetic forbidden edit");
        return ActionDecision.parse(out.toString(),ActionDecision.IME_ACTION_SCHEMA);
    }
    static NativeAppDomain manual(Pack p,String phase,String purpose,String path,boolean back,Map<String,Object> result){
        String target=p.path(path).id;
        return new NativeAppDomain(p.frame,phase,Collections.singleton(target),Collections.<String,String>emptyMap(),
                Collections.singletonMap(target,purpose),back,Collections.<String,Object>emptyMap(),result,Collections.<String>emptyList());
    }
    static NativeAppSession.ActionGuard dateGuard(Fixture f,Pack p,String run)throws Exception{
        f.task.observed(p.frame);ActionDecision click=action(p,"click",null,p.path("0/0/2/5").id);
        f.task.beforeModelAction(1,click,run,p.start+300);
        return f.task.actionGuard(click,run,p.observation,p.start+310,p.start+8310);
    }
    public static void main(String[] args)throws Exception{
        Path output=Paths.get(args[0]);NativeProfileIdentityHostTest.workspace=Paths.get(args[1]);Files.createDirectories(NativeProfileIdentityHostTest.workspace);
        one("actual_history_phone_copy_frame_session_form_chain",()->{try(Fixture f=new Fixture()){
            Pack p=f.history();f.task.observed(p.frame);NativeAppDomain d=f.task.domain();
            check(ObservationCaptureEvidence.NATIVE_AX_FORM_HISTORY.equals(p.observed.captureKind),"Phone must preserve distinct actual kind");
            check(p.observed.captureKind.equals(p.frame.captureKind)&&p.frame.capture==p.capture,"adapter must preserve typed source");
            check(p.frame.capturedElapsedMs==p.start+100,"original A capture clock");
            check(NativeCtripFlightPage.FORM.equals(d.phase)&&!d.resultReady,"history is FORM only");
            check(d.clickIds.equals(Collections.singleton(p.path("0/0/2/5").id)),"only original date proposal before year proof");
            check(Boolean.TRUE.equals(d.promptEvidence().get("historical_form_planning_only"))&&Boolean.FALSE.equals(d.promptEvidence().get("published_pair_is_current_tree_claimed")),"history prompt facts");
            check(p.observed.screenshot==null&&p.frame.screenshotSha==null,"no fabricated pixels");
        }});
        one("history_retains_different_complete_trees_and_late_content_without_current_claim",()->{try(Fixture f=new Fixture()){
            Pack p=f.history();Map<String,Object> h=p.capture.formHistoryEvidence();
            check(Boolean.FALSE.equals(h.get("whole_graph_equal"))&&((Integer)h.get("changed_path_count"))==1,"actual synthetic complete pair change retained");
            check(Boolean.TRUE.equals(p.metadata.get("events_after_complete_census_admitted")),"actual late content recorded");
            check(Boolean.FALSE.equals(h.get("grants_action_authority"))&&Boolean.FALSE.equals(h.get("business_completion_verified")),"pair cannot grant");
        }});
        one("history_publication_current_tree_claim_is_refused",()->{try(Fixture f=new Fixture()){Pack p=f.history();Map<String,Object> bad=new TreeMap<String,Object>(p.metadata);bad.put("published_pair_is_current_tree_claimed",true);denied(()->p.phone(bad,p.capture,p.captured,null,null,p.nodes),"cannot claim");}});
        one("history_publication_kind_alias_is_refused",()->{try(Fixture f=new Fixture()){Pack p=f.history();Map<String,Object> bad=new TreeMap<String,Object>(p.metadata);bad.put("kind",ObservationCaptureEvidence.NATIVE_AX);denied(()->p.phone(bad,p.capture,p.captured,null,null,p.nodes),"metadata differs");}});
        one("history_original_capture_clock_cannot_be_refreshed",()->{try(Fixture f=new Fixture()){Pack p=f.history();denied(()->p.phone(p.metadata,p.capture,p.start+250,null,null,p.nodes),"captured_elapsed_ms");}});
        one("history_pixel_claim_is_refused",()->{try(Fixture f=new Fixture()){Pack p=f.history();denied(()->p.phone(p.metadata,p.capture,p.captured,f.env.directory.resolve("fake.png").toFile(),hash("fake"),p.nodes),"no pixels");}});
        one("history_and_ordinary_ax_have_distinct_source_identity",()->{try(Fixture f=new Fixture()){
            Pack p=f.history(),ax=f.equalAx();check(p.frame.sameCapture(p.capture,null)&&p.frame.sameSource(p.frame),"own source");
            check(!p.capture.sameSource(ax.capture)&&!p.frame.sameCapture(ax.capture,null)&&!p.frame.sameSource(ax.frame),"distinct typed source");
            check(!p.frame.sameCapture(null,null),"two missing screenshots are not a source");
        }});
        one("history_receipt_cannot_be_passed_to_old_equal_ax_factory",()->{try(Fixture f=new Fixture()){Pack p=f.history();byte[] bytes=ObservationCaptureEvidence.nativeAxFormHistoryBytes(p.receipt);denied(()->ObservationCaptureEvidence.fromSealedNativeAx(p.receipt,bytes,ObservationCaptureEvidence.hash(bytes)),"kind/schema");}});
        one("history_frame_cannot_rebind_selection_or_task_identity",()->{try(Fixture f=new Fixture()){Pack p=f.history();Map<String,Object> wrong=map();wrong.put("actual_selection_sha256",hash("different"));denied(()->p.capture.requireBinding(wrong),"actual_selection_sha256");wrong.clear();wrong.put("task_id",id());denied(()->p.capture.requireBinding(wrong),"task_id");}});
        one("same_value_different_selection_authority_cannot_copy_history",()->{try(Fixture f=new Fixture()){Pack p=f.history();
            BackgroundSession.Selection different=new BackgroundSession.Selection(f.env.session.selection.taskTarget);
            TaskAuthorization.Gate gate=TaskAuthorization.parse(OWNER).forExecutionSelection(different).bind(f.task.taskId);
            denied(()->NativeAppObservation.copy(f.task.taskId,gate,f.env.session,p.observed,p.completion,p.frame.sourceRecordSha),null);
        }});
        one("history_domain_rejects_result_payload",()->{try(Fixture f=new Fixture()){Pack p=f.history();denied(()->manual(p,NativeCtripFlightPage.FORM,NativeActionSnapshotCheck.YEAR,"0/0/2/5",false,Collections.<String,Object>singletonMap("synthetic",true)),"planning-only");}});
        one("history_domain_rejects_other_phase_and_back",()->{try(Fixture f=new Fixture()){Pack p=f.history();denied(()->manual(p,NativeCtripFlightPage.RESULTS,NativeActionSnapshotCheck.YEAR,"0/0/2/5",false,null),"planning-only");denied(()->manual(p,NativeCtripFlightPage.FORM,NativeActionSnapshotCheck.YEAR,"0/0/2/5",true,null),"planning-only");}});
        one("history_domain_rejects_generic_click_purpose",()->{try(Fixture f=new Fixture()){Pack p=f.history();denied(()->manual(p,NativeCtripFlightPage.FORM,"generic_click","0/0/2/5",false,null),"only inspected date/query");}});
        one("history_domain_refuses_recommendation_target",()->{try(Fixture f=new Fixture()){Pack p=f.history();denied(()->p.capture.requireFormHistoryTarget("0/0/7/0"),"unrelated target");}});
        one("history_session_rejects_calendar_or_results_projection_before_progress",()->{try(Fixture f=new Fixture()){Pack p=f.history();denied(()->f.task.observed(p.frameWith(Collections.<NativeAppEvidence.Node>emptyList(),p.capture,null)),"cannot become");check(f.task.acceptSuccess(1,id(),p.completion,true)==null,"no completion side effect");}});
        one("history_never_readies_or_accepts_success",()->{try(Fixture f=new Fixture()){Pack p=f.history();f.task.observed(p.frame);check(!f.task.ready(p.completion),"not ready");check(f.task.acceptSuccess(1,id(),p.completion,true)==null,"no success");denied(()->f.task.domain().requireCurrent(action(p,"done","success",null)),"not verified");}});
        one("history_wait_uses_original_non_effect_null_guard",()->{try(Fixture f=new Fixture()){Pack p=f.history();f.task.observed(p.frame);ActionDecision a=action(p,"wait",null,null);String run=id();f.task.beforeModelAction(1,a,run,p.start+300);check(f.task.actionGuard(a,run,p.observation,p.start+310,p.start+8310)==null,"wait creates no effect guard");}});
        one("history_done_failure_uses_original_non_effect_null_guard",()->{try(Fixture f=new Fixture()){Pack p=f.history();f.task.observed(p.frame);ActionDecision a=action(p,"done","failure",null);String run=id();f.task.beforeModelAction(1,a,run,p.start+300);check(f.task.actionGuard(a,run,p.observation,p.start+310,p.start+8310)==null,"failure creates no effect guard");}});
        one("history_done_partial_uses_original_non_effect_null_guard",()->{try(Fixture f=new Fixture()){Pack p=f.history();f.task.observed(p.frame);ActionDecision a=action(p,"done","partial",null);String run=id();f.task.beforeModelAction(1,a,run,p.start+300);check(f.task.actionGuard(a,run,p.observation,p.start+310,p.start+8310)==null,"partial creates no effect guard");}});
        one("history_query_before_calendar_roundtrip_is_refused",()->{try(Fixture f=new Fixture()){Pack p=f.history();f.task.observed(p.frame);denied(()->f.task.beforeModelAction(1,action(p,"click",null,p.path("0/0/2/13").id),id(),p.start+300),"target not");}});
        one("history_real_date_guard_is_once_claimed_and_keeps_eight_second_budget",()->{try(Fixture f=new Fixture()){Pack p=f.history();String run=id();NativeAppSession.ActionGuard g=dateGuard(f,p,run);g.requireOpen(g.action,run,p.start+320);g.verifyInstalled();int verified=f.verifies;check(verified>=3,"real verifier reused");
            g.claim(g.action,run,p.start+330);g.requireClaimed();denied(()->g.claim(g.action,run,p.start+331),"second effect");
            check(g.deadline-g.issued==8000&&g.frame==p.frame&&g.targetNode==p.path("0/0/2/5"),"original guard source and budget");
        }});
        one("history_real_guard_expiry_refuses_claim",()->{try(Fixture f=new Fixture()){Pack p=f.history();String run=id();NativeAppSession.ActionGuard g=dateGuard(f,p,run);denied(()->g.claim(g.action,run,g.deadline),"closed");}});
        one("history_equal_pair_comparator_and_protected_change_refusal",()->{try(Fixture f=new Fixture()){Pack p=f.history();String run=id();NativeAppSession.ActionGuard g=dateGuard(f,p,run);
            NativeActionSnapshotCheck.Intent intent=g.intent(fullSignature("0/0/2/5"));
            NativeActionSnapshotCheck.Snapshot first=p.snapshot(p.original,p.start+80),fresh=p.snapshot(p.original,p.start+340);
            Map<String,Object> proof=NativeActionSnapshotCheck.compare(intent,first,fresh,p.start+350);
            check(Boolean.FALSE.equals(proof.get("grants_dispatch")),"even equal full compare gives no dispatch");
            NativeActionSnapshotCheckHostTest.Fixture changed=p.original.copy();NativeActionSnapshotCheckHostTest.changedText(changed,"0/0/2/1","南京");
            denied(()->NativeActionSnapshotCheck.compare(intent,first,p.snapshot(changed,p.start+340),p.start+350),null);
            check(((Integer)g.evidence().get("state"))==0,"pure comparison cannot claim");
        }});
        one("history_guard_needs_same_model_run_action_and_single_reservation",()->{try(Fixture f=new Fixture()){Pack p=f.history();String run=id();NativeAppSession.ActionGuard g=dateGuard(f,p,run);
            denied(()->g.requireOpen(g.action,id(),p.start+320),"replaced");
            denied(()->f.task.actionGuard(g.action,run,p.observation,p.start+311,p.start+8311),"one original");
        }});
        boolean all=true;for(Map<String,Object> r:results)if(!Boolean.TRUE.equals(r.get("passed")))all=false;
        Map<String,Object> report=map();report.put("schema","hepta.native-form-history-consumers-host.v1");report.put("all_pass",all);
        report.put("cases",names.size());report.put("assertions",assertions);report.put("case_names",names);report.put("results",results);
        report.put("phone_operations",0);report.put("android_producer_tested",false);report.put("platform_effect_tested",false);report.put("business_verified",false);
        report.put("boundary","Complete actual PhoneObservation, NativeAppObservation.copy, Frame, managed NativeAppSession, Domain and original ActionGuard/NAS comparator. Full synthetic census/window/profile/socket inputs and private receipt bytes; no Android BFS, service effect/validate execution, model call or phone success.");
        Files.write(output,(new JSONObject(report).toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println(new JSONObject(report).toString());if(!all)System.exit(1);
    }
}
