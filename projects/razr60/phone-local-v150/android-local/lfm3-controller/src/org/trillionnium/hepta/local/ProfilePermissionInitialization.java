package org.trillionnium.hepta.local;

import org.trillionnium.hepta.background.PermissionWindowObservation;
import org.trillionnium.hepta.background.ProfilePermissionTransient;
import org.trillionnium.hepta.background.ProfileTarget;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Pure owner-bound initialization policy. This is deliberately not an agent tool.
 * The only effect it can request is the live, ordinary PermissionController deny
 * button. It cannot grant, deny-and-never-ask, press Back, inject coordinates,
 * run a command, change a profile, or turn a PC window into a business frame.
 *
 * Platform integration must read real accessibility nodes on the owned display,
 * corroborate their task through PermissionWindowObservation, and call Dispatch.enter with a
 * fresh complete observation immediately before ACTION_CLICK on its returned
 * node. Source and host tests alone do not qualify that Android adapter.
 */
public final class ProfilePermissionInitialization {
    public static final String SCHEMA="hepta.profile-permission-initialization.v1";
    public static final String PREFIX=ProfilePermissionTransient.PACKAGE+":id/";
    public static final String MESSAGE=PREFIX+"permission_message";
    public static final String DENY=PREFIX+"permission_deny_button";
    public static final String ONE_TIME=PREFIX+"permission_allow_one_time_button";
    public static final String FINE=PREFIX+"permission_location_accuracy_radio_fine";
    public static final String COARSE=PREFIX+"permission_location_accuracy_radio_coarse";
    public static final long MAX_SESSION_MS=12000;
    private static final int MAX_NODES=128,MAX_TEXT_BYTES=16384,MAX_WINDOWS=16;
    private static final Set<String> BUTTON_IDS=Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
            DENY,ONE_TIME,PREFIX+"permission_allow_button",PREFIX+"permission_allow_foreground_only_button",
            PREFIX+"permission_allow_always_button",PREFIX+"permission_deny_and_dont_ask_again_button",
            PREFIX+"permission_allow_selected_button",PREFIX+"permission_allow_all_button",
            PREFIX+"permission_dont_allow_more_selected_button",PREFIX+"permission_no_upgrade_button")));
    private ProfilePermissionInitialization(){}

    public static final class Refusal extends Exception {
        private static final long serialVersionUID=1L;
        public final String code;
        Refusal(String code){super(code);this.code=code;}
    }
    private static void need(boolean ok,String code)throws Refusal{if(!ok)throw new Refusal(code);}
    private static boolean hash(String value){return value!=null&&value.matches("[0-9a-f]{64}");}
    private static String text(String value){return value==null?"":value;}
    private static String sha(String value){
        try{byte[] bytes=MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder out=new StringBuilder();for(byte b:bytes)out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return out.toString();
        }catch(java.security.NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
    }
    private static void field(StringBuilder out,String value){String s=text(value);out.append(s.length()).append(':').append(s);}

    /** The handle must be the actual retained accessibility node identity, not a
     * resource name, coordinate, path, JSON token or model-selected string. */
    public static final class Node {
        public final Object handle;
        public final String packageName,resourceId,className,label,contentDescription,bounds;
        public final int windowId;
        public final boolean visible,enabled,clickable,actionClick,checkable,checked;
        public Node(Object handle,String pkg,int window,String resource,String klass,String label,String description,
                String bounds,boolean visible,boolean enabled,boolean clickable,boolean actionClick,boolean checkable,boolean checked){
            this.handle=handle;packageName=pkg;windowId=window;resourceId=text(resource);className=text(klass);
            this.label=text(label);contentDescription=text(description);this.bounds=text(bounds);this.visible=visible;
            this.enabled=enabled;this.clickable=clickable;this.actionClick=actionClick;this.checkable=checkable;this.checked=checked;
        }
        private String data(){StringBuilder b=new StringBuilder();for(String s:Arrays.asList(packageName,resourceId,className,label,contentDescription,bounds))field(b,s);
            return b.append('|').append(windowId).append('|').append(visible).append('|').append(enabled).append('|')
                    .append(clickable).append('|').append(actionClick).append('|').append(checkable).append('|').append(checked).toString();}
    }
    /** Complete actual interactive-window census for the owned display. An
     * underlying target-App window is allowed only in the same owned leaf and
     * below the active PC window. Other system or accessibility overlays refuse. */
    public static final class Window {
        public final int id,display,task,type,layer;
        public final String packageName;
        public final boolean active,focused;
        public Window(int id,int display,int task,int type,int layer,String pkg,boolean active,boolean focused){
            this.id=id;this.display=display;this.task=task;this.type=type;this.layer=layer;
            packageName=pkg;this.active=active;this.focused=focused;
        }
        private String data(){return id+":"+display+":"+task+":"+type+":"+layer+":"+packageName+":"+active+":"+focused;}
    }
    /** Snapshot facts come from a dedicated platform adapter, never an LLM.
     * physicalIdentities always contains complete identity/focus/recents audit
     * fingerprints for displays 0 and 1. V1 freezes them; authenticated public
     * V2 compares its additional owned-scope projection. Partial reads refuse. */
    public static final class Snapshot {
        public final PermissionWindowObservation identity;
        public final long started,finished;
        public final List<Node> nodes;
        public final List<Window> windows;
        public final Map<Integer,String> physicalIdentities;
        public final String fingerprint,message;
        private final Node deny;
        private final boolean locationControls;
        public Snapshot(PermissionWindowObservation identity,long started,long finished,boolean complete,List<Node> nodes,
                List<Window> windows,Map<Integer,String> physicalIdentities)throws Exception{
            need(identity!=null&&complete&&started>=0&&finished>=started,"PERMISSION_UI_INCOMPLETE");
            identity.requireFresh(finished);
            need(identity.displayId>1,"PERMISSION_PHYSICAL_DISPLAY_FORBIDDEN");
            need(nodes!=null&&!nodes.isEmpty()&&nodes.size()<=MAX_NODES,"PERMISSION_NODE_BOUND");
            need(windows!=null&&!windows.isEmpty()&&windows.size()<=MAX_WINDOWS,"PERMISSION_WINDOW_BOUND");
            need(physicalIdentities!=null&&physicalIdentities.keySet().equals(new HashSet<Integer>(Arrays.asList(0,1))),"PERMISSION_PHYSICAL_FENCE_INCOMPLETE");
            for(String digest:physicalIdentities.values())need(hash(digest),"PERMISSION_PHYSICAL_FENCE_INVALID");
            need(identity.physicalIdentities.equals(physicalIdentities),"PERMISSION_PHYSICAL_FENCE_NOT_BROKER_READBACK");
            this.identity=identity;this.started=started;this.finished=finished;
            this.physicalIdentities=Collections.unmodifiableMap(new LinkedHashMap<Integer,String>(physicalIdentities));
            this.nodes=Collections.unmodifiableList(new ArrayList<Node>(nodes));
            this.windows=Collections.unmodifiableList(new ArrayList<Window>(windows));
            Set<Integer> windowIds=new HashSet<Integer>();Window pc=null;
            for(Window w:this.windows){
                need(w!=null&&w.id>=0&&windowIds.add(w.id)&&w.display==identity.displayId&&w.task==identity.taskId&&w.type==1,
                        "PERMISSION_WINDOW_IDENTITY_CHANGED");
                if(w.id==identity.windowId){need(ProfilePermissionTransient.PACKAGE.equals(w.packageName)&&w.focused,"PERMISSION_PC_WINDOW_NOT_FOCUSED");pc=w;}
                else need(identity.target.packageName.equals(w.packageName)&&!w.active&&!w.focused,"PERMISSION_FOREIGN_WINDOW");
            }
            need(pc!=null,"PERMISSION_PC_WINDOW_MISSING");
            for(Window w:this.windows)if(w!=pc)need(w.layer<pc.layer,"PERMISSION_PC_WINDOW_OCCLUDED");
            Set<Object> handles=new HashSet<Object>();Set<String> visibleIds=new HashSet<String>();
            Node request=null,denial=null,fine=null,coarse=null;int bytes=0;StringBuilder raw=new StringBuilder();
            for(Node n:this.nodes){
                need(n!=null&&n.handle!=null&&handles.add(n.handle)&&ProfilePermissionTransient.PACKAGE.equals(n.packageName)
                        &&n.windowId==identity.windowId,"PERMISSION_NODE_IDENTITY_CHANGED");
                bytes+=n.data().getBytes(StandardCharsets.UTF_8).length;need(bytes<=MAX_TEXT_BYTES,"PERMISSION_TEXT_BOUND");
                field(raw,n.data());
                if(!n.visible)continue;
                if(MESSAGE.equals(n.resourceId)||BUTTON_IDS.contains(n.resourceId)||FINE.equals(n.resourceId)||COARSE.equals(n.resourceId))
                    need(visibleIds.add(n.resourceId),"PERMISSION_VISIBLE_ROLE_AMBIGUOUS");
                if(MESSAGE.equals(n.resourceId))request=n;
                if(DENY.equals(n.resourceId))denial=n;
                if(FINE.equals(n.resourceId))fine=n;
                if(COARSE.equals(n.resourceId))coarse=n;
            }
            need(request!=null&&!request.label.isEmpty()&&!request.clickable&&!request.actionClick,"PERMISSION_REQUEST_MESSAGE_MISSING");
            for(Window w:this.windows)field(raw,w.data());
            fingerprint=sha(raw.toString());message=request.label;deny=denial;
            // Structural location evidence only. Unknown text is displayed literally;
            // it is never classified by a model or a substring such as "location".
            locationControls=fine!=null&&coarse!=null&&fine.checkable&&coarse.checkable&&fine.checked!=coarse.checked;
        }
        private void requireDeny()throws Refusal{
            need(deny!=null&&deny.visible&&deny.enabled&&deny.clickable&&deny.actionClick&&!deny.label.isEmpty(),"PERMISSION_ORDINARY_DENY_UNAVAILABLE");
        }
        private boolean sameDialog(Snapshot other){
            if(other==null||!identity.sameRequest(other.identity)||!fingerprint.equals(other.fingerprint)
                    ||!identity.samePhysicalScope(other.identity)||nodes.size()!=other.nodes.size())return false;
            for(int i=0;i<nodes.size();i++)if(!Objects.equals(nodes.get(i).handle,other.nodes.get(i).handle))return false;
            return true;
        }
    }
    public static final class Preview {
        public final String message,classification,fingerprint;
        public final List<Map<String,Object>> visibleOptions;
        public final boolean optionalForExplicitRoute,actualPermissionNamesAvailable=false;
        private final Snapshot snapshot;
        private PublicationReceipt publication;
        private Preview(Snapshot snapshot){
            this.snapshot=snapshot;message=snapshot.message;fingerprint=snapshot.fingerprint;
            optionalForExplicitRoute=snapshot.locationControls;
            classification=optionalForExplicitRoute?"location_controls_observed":"unresolved_visible_permission_request";
            List<Map<String,Object>> options=new ArrayList<Map<String,Object>>();
            for(Node n:snapshot.nodes)if(n.visible&&BUTTON_IDS.contains(n.resourceId)){
                Map<String,Object> option=new LinkedHashMap<String,Object>();option.put("resource_id",n.resourceId);option.put("visible_label",n.label);
                option.put("enabled",n.enabled);option.put("input_supported",DENY.equals(n.resourceId)&&n.clickable&&n.actionClick);
                option.put("grant_supported",false);options.add(Collections.unmodifiableMap(option));
            }
            visibleOptions=Collections.unmodifiableList(options);
        }
        public Map<String,Object> evidence(){
            Map<String,Object> e=new LinkedHashMap<String,Object>();e.put("schema",SCHEMA);e.put("visible_request",message);
            e.put("classification",classification);e.put("actual_android_permission_names_available",false);
            e.put("visible_options",visibleOptions);e.put("ui_fingerprint",fingerprint);
            e.put("identity",snapshot.identity.evidence());e.put("sent_to_business_model",false);
            e.put("visible_pixels_verified",false);e.put("publication",publication==null?null:publication.evidence());
            e.put("business_observation_allowed",false);e.put("serialized_evidence_is_authority",false);
            return Collections.unmodifiableMap(e);
        }
    }
    /** The implementation must consult the live authenticated RPC object registry. */
    public interface ReadProvenance { void require(PermissionWindowObservation observation,long now)throws Exception; }
    /** Synchronous durable state publication, not proof that an Activity was
     * opened, focused, rendered or seen by the user. No screen may be awakened. */
    public interface StatePublisher { PublicationReceipt publish(Preview preview)throws Exception; }
    public static final class PublicationReceipt {
        private final Preview preview;
        public final long publishedElapsedMs;
        public final String durableSha256;
        public final boolean statePublished,visiblePixelsVerified=false;
        public PublicationReceipt(Preview preview,long publishedElapsedMs,String durableSha256,boolean statePublished){
            this.preview=preview;this.publishedElapsedMs=publishedElapsedMs;this.durableSha256=durableSha256;this.statePublished=statePublished;
        }
        private void require(Preview wanted,long now)throws Refusal{
            need(preview==wanted&&statePublished&&hash(durableSha256)&&publishedElapsedMs>=wanted.snapshot.finished
                    &&publishedElapsedMs<=now,"PERMISSION_STATE_PUBLICATION_UNVERIFIED");
        }
        public Map<String,Object> evidence(){
            Map<String,Object> e=new LinkedHashMap<String,Object>();e.put("durable_sha256",durableSha256);
            e.put("published_elapsed_ms",publishedElapsedMs);e.put("state_published",statePublished);
            e.put("visible_pixels_verified",false);e.put("serialized_evidence_is_authority",false);return Collections.unmodifiableMap(e);
        }
    }
    /** Live provenance from the actual current ordinary owner button callback.
     * The adapter must retain the choice object and retire it on focus loss,
     * Activity stop, cancellation, task/session change or preview replacement.
     * A boolean, serialized event or business-model decision cannot supply it. */
    public interface OwnerDenyChoice { void requireCurrent(Preview preview,long now)throws Exception; }
    public interface Journal {
        /** Must durably create an attempt record before returning. A failed write
         * prevents the platform callback; no uncertain attempt is replayed. */
        void reserve(Map<String,Object> attempt)throws Exception;
        void complete(Map<String,Object> result)throws Exception;
    }
    public interface Platform {
        long now();
        boolean cancelled();
        Snapshot observe()throws Exception;
        /** Only call ACTION_CLICK on the live node returned by enter(). No
         * coordinate/parent/Back/shell fallback, alternate node, or retry. */
        boolean clickOrdinaryDeny(Dispatch dispatch)throws Exception;
    }
    public static final class Receipt {
        public final boolean inputEntered,apiAccepted;
        public final boolean continuationAuthorized=false,permissionGrantVerified=false,businessCompleted=false;
        private final Map<String,Object> evidence;
        private Receipt(boolean entered,boolean accepted,String source,Preview preview){
            inputEntered=entered;apiAccepted=accepted;Map<String,Object> e=new LinkedHashMap<String,Object>();
            e.put("schema",SCHEMA);e.put("source",source);e.put("ui_fingerprint",preview.fingerprint);
            e.put("input_entered",entered);e.put("api_accepted",accepted);e.put("permission_grant_verified",false);
            e.put("business_completed",false);e.put("continuation_authorized",false);e.put("automatic_retry",false);
            evidence=Collections.unmodifiableMap(e);
        }
        public Map<String,Object> evidence(){return evidence;}
    }
    /** This separate token exists only after owner policy, publication, fresh
     * complete observation and durable reservation. The old transient proof
     * continues to report permission_input_allowed=false. */
    public static final class Dispatch {
        private final Session session;private final Snapshot expected;private final Platform platform;
        private final Preview preview;private final OwnerDenyChoice ownerChoice;
        private boolean entered;
        private Dispatch(Session session,Snapshot expected,Platform platform,Preview preview,OwnerDenyChoice ownerChoice){
            this.session=session;this.expected=expected;this.platform=platform;this.preview=preview;this.ownerChoice=ownerChoice;
        }
        public Node enter(Snapshot immediatelyBeforeInput)throws Exception{
            synchronized(session){
                session.guard(platform);need(session.state==State.DISPATCHING&&!entered,"PERMISSION_DISPATCH_ALREADY_CONSUMED");
                session.requireSnapshot(immediatelyBeforeInput,platform.now());
                need(expected.sameDialog(immediatelyBeforeInput),"PERMISSION_DIALOG_CHANGED_BEFORE_INPUT");
                if(ownerChoice!=null)ownerChoice.requireCurrent(preview,platform.now());
                // Provenance and choice checks can themselves wait on a Binder
                // read. Cancellation/deadline must be checked after they return.
                session.guard(platform);
                immediatelyBeforeInput.requireDeny();entered=true;return immediatelyBeforeInput.deny;
            }
        }
    }
    private enum State { READY, PUBLISHING, PREVIEWED, RESERVING, DISPATCHING, FINISHED, REFUSED, UNKNOWN }
    public static final class Session {
        private final NativeAppGoal ownerGoal;private final PermissionWindowObservation owner;
        private final Map<Integer,String> physicalBaseline;private final long started,deadline;
        private final ReadProvenance provenance;
        private State state=State.READY;private Preview current;
        /** The already-authorized literal owner query is the only task policy
         * input. An instruction parsed from screen/model output is not accepted
         * by the integration contract; there is no model-choice parameter. */
        public Session(NativeAppGoal originalOwnerGoal,String originalTaskOwnerSha256,PermissionWindowObservation owner,Map<Integer,String> physicalBaseline,
                long now,long originalDeadline,ReadProvenance provenance)throws Exception{
            need(originalOwnerGoal!=null&&owner!=null&&NativeAppGoal.FLIGHT_RESULTS.equals(originalOwnerGoal.kind)
                    &&ProfileTarget.CTRIP.equals(originalOwnerGoal.packageName)&&originalOwnerGoal.packageName.equals(owner.target.packageName)
                    &&originalOwnerGoal.fromCity!=null&&originalOwnerGoal.toCity!=null&&!originalOwnerGoal.fromCity.equals(originalOwnerGoal.toCity),
                    "PERMISSION_OWNER_QUERY_UNSUPPORTED");
            // Integration supplies BackgroundSession.ownerSha256 from the original
            // durable owner record, never a digest computed from PC/model text.
            need(hash(originalTaskOwnerSha256)&&originalTaskOwnerSha256.equals(originalOwnerGoal.ownerSha256),
                    "PERMISSION_ORIGINAL_OWNER_CHANGED");
            need(now>=0&&originalDeadline>now&&now<=Long.MAX_VALUE-MAX_SESSION_MS,"PERMISSION_INITIALIZATION_DEADLINE");
            need(provenance!=null,"PERMISSION_LIVE_PROVENANCE_REQUIRED");provenance.require(owner,now);this.provenance=provenance;
            owner.requireFresh(now);need(owner.displayId>1,"PERMISSION_PHYSICAL_DISPLAY_FORBIDDEN");
            need(physicalBaseline!=null&&physicalBaseline.keySet().equals(new HashSet<Integer>(Arrays.asList(0,1))),"PERMISSION_PHYSICAL_FENCE_INCOMPLETE");
            for(String digest:physicalBaseline.values())need(hash(digest),"PERMISSION_PHYSICAL_FENCE_INVALID");
            need(owner.physicalIdentities.equals(physicalBaseline),"PERMISSION_PHYSICAL_DISPLAY_CHANGED");
            ownerGoal=originalOwnerGoal;this.owner=owner;this.physicalBaseline=Collections.unmodifiableMap(new LinkedHashMap<Integer,String>(physicalBaseline));
            started=now;deadline=Math.min(originalDeadline,now+MAX_SESSION_MS);
        }
        private void guard(Platform platform)throws Exception{
            need(platform!=null&&!platform.cancelled(),"PERMISSION_INITIALIZATION_CANCELLED");
            long now=platform.now();need(now>=started&&now<deadline,"PERMISSION_INITIALIZATION_DEADLINE");
        }
        private void requireSnapshot(Snapshot snapshot,long now)throws Exception{
            need(snapshot!=null&&snapshot.finished>=snapshot.started&&snapshot.started>=0&&snapshot.finished<=now&&now-snapshot.started<=ProfilePermissionTransient.MAX_AGE_MS
                    &&snapshot.identity.observedElapsedMs>=snapshot.started,"PERMISSION_UI_TIME_INVALID");
            provenance.require(snapshot.identity,now);snapshot.identity.requireFresh(now);
            need(owner.sameOwnedTask(snapshot.identity),"PERMISSION_OWNED_TASK_CHANGED");
            need(owner.samePhysicalScope(snapshot.identity),"PERMISSION_PHYSICAL_DISPLAY_CHANGED");
        }
        public synchronized Preview publish(Snapshot snapshot,StatePublisher publisher,Platform platform)throws Exception{
            guard(platform);need(state==State.READY&&publisher!=null,"PERMISSION_PREVIEW_NOT_AVAILABLE");
            requireSnapshot(snapshot,platform.now());Preview preview=new Preview(snapshot);state=State.PUBLISHING;
            try{PublicationReceipt receipt=publisher.publish(preview);guard(platform);
                need(receipt!=null,"PERMISSION_STATE_PUBLICATION_UNVERIFIED");receipt.require(preview,platform.now());
                preview.publication=receipt;current=preview;state=State.PREVIEWED;return preview;}
            catch(Exception failure){state=State.REFUSED;throw failure;}
        }
        /** Normal visible owner UI callback only. Even an explicit owner cannot
         * select an allow/one-time/never-ask node through this API. */
        public synchronized Receipt denyFromOwnerUi(Preview preview,OwnerDenyChoice ownerChoice,Platform platform,Journal journal)throws Exception{
            need(ownerChoice!=null,"PERMISSION_VISIBLE_OWNER_CHOICE_REQUIRED");
            return deny(preview,platform,journal,"owner_visible_deny",ownerChoice);
        }
        /** A specified-city flight query does not require location. Automatic
         * denial needs the real system's precise/coarse controls; text, model
         * confidence, app rationale and a supplied permission name do not suffice. */
        public synchronized Receipt denyOptionalLocationForExplicitRoute(Preview preview,Platform platform,Journal journal)throws Exception{
            need(preview!=null&&preview.optionalForExplicitRoute,"PERMISSION_OPTIONAL_GROUP_UNPROVEN");
            return deny(preview,platform,journal,"owner_explicit_route_optional_location_deny",null);
        }
        private Receipt deny(Preview preview,Platform platform,Journal journal,String source,OwnerDenyChoice ownerChoice)throws Exception{
            guard(platform);need(state==State.PREVIEWED&&current==preview&&preview.publication!=null&&journal!=null,"PERMISSION_OWNER_PREVIEW_MISMATCH");
            if(ownerChoice!=null)ownerChoice.requireCurrent(preview,platform.now());
            Snapshot live=platform.observe();guard(platform);requireSnapshot(live,platform.now());
            need(preview.snapshot.sameDialog(live),"PERMISSION_DIALOG_CHANGED_SINCE_PREVIEW");live.requireDeny();
            Map<String,Object> attempt=new LinkedHashMap<String,Object>();attempt.put("schema",SCHEMA);attempt.put("source",source);
            attempt.put("owner_sha256",ownerGoal.ownerSha256);attempt.put("owner_goal_sha256",ownerGoal.contractSha256);
            attempt.put("generation",owner.generation);attempt.put("target_sha256",owner.target.sha256);
            attempt.put("display_id",live.identity.displayId);attempt.put("window_id",live.identity.windowId);attempt.put("task_id",live.identity.taskId);
            attempt.put("request_activity",live.identity.activityRecord);attempt.put("request_result_to",live.identity.resultToActivityRecord);
            attempt.put("ui_fingerprint",live.fingerprint);attempt.put("resource_id",DENY);attempt.put("visible_request",live.message);
            attempt.put("visible_options",preview.visibleOptions);attempt.put("permission_grant_allowed",false);
            attempt.put("state_publication",preview.publication.evidence());attempt.put("visible_pixels_verified",false);
            attempt.put("owner_visible_choice_required",ownerChoice!=null);
            attempt.put("automatic_retry",false);attempt.put("business_model_decision",false);attempt.put("deadline_elapsed_ms",deadline);
            if(ownerChoice!=null)ownerChoice.requireCurrent(preview,platform.now());state=State.RESERVING;
            try{journal.reserve(Collections.unmodifiableMap(attempt));}
            catch(Exception failedWrite){state=State.UNKNOWN;throw failedWrite;}
            Dispatch dispatch=new Dispatch(this,live,platform,preview,ownerChoice);state=State.DISPATCHING;
            try{
                guard(platform);boolean accepted=platform.clickOrdinaryDeny(dispatch);
                need(dispatch.entered,"PERMISSION_PLATFORM_DID_NOT_ENTER_GUARD");
                Receipt result=new Receipt(true,accepted,source,preview);journal.complete(result.evidence());state=State.FINISHED;return result;
            }catch(Exception uncertain){state=State.UNKNOWN;throw uncertain;}
        }
        /** True after the single attempt, including journal/input uncertainty.
         * The caller must use existing ordinary cleanup; this class cannot retire
         * a lease or authorize a business continuation. */
        public synchronized boolean attemptedOrUnknown(){return state==State.RESERVING||state==State.DISPATCHING||state==State.FINISHED||state==State.UNKNOWN;}
    }
}
