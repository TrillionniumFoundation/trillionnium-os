package org.trillionnium.hepta.local;

import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.json.JSONArray;
import org.json.JSONObject;

/** Actual persisted planning receipt. This type cannot be passed as a
 * PhoneObservation, executable native Frame, image, or completion candidate. */
final class NativeSearchPlanning {
    static final String KIND="native_ax_planning",SCHEMA="hepta.native-search-planning.v1",ICON_SCHEMA="hepta.native-search-icon-planning.v1";
    static final int MAX_BYTES=2*1024*1024;
    final String id,packageName,receiptSha256,kind=KIND;
    final NativeActionSnapshotCheck.Snapshot first,second;
    final NativeSearchRole role;
    final boolean fullTreeEqual;
    final Timing timing;
    final long capturedElapsed,completedElapsed,persistedElapsed;
    final int receiptBytes;
    final Map<String,Object> binding;
    final CaptureContext context;
    final Map<String,Object> publication;
    final long publishedElapsed;

    static final long INITIAL_READ_LIMIT_MS=30000;
    static final long NAVIGATION_LIMIT_MS=24000;
    static final long FINAL_CENSUS_MAX_AGE_MS=8000;
    static long navigationDeadline(long started,long chainDeadline){
        need(started>=0&&chainDeadline>started,"live original navigation chain required");
        return started+Math.min(chainDeadline-started,NAVIGATION_LIMIT_MS);
    }
    static long initialReadDeadline(long started,long chainDeadline){
        need(started>=0&&chainDeadline>=0,"original elapsed planning deadlines required");
        long end=started>Long.MAX_VALUE-INITIAL_READ_LIMIT_MS?Long.MAX_VALUE:started+INITIAL_READ_LIMIT_MS;
        return Math.min(chainDeadline,end);
    }
    static long samplingDeadline(long started,long deadline){
        // A shorter caller still owns its original read window. Reserve the last
        // two seconds of the longer preparation window for persistence/publication.
        if(deadline-started>12000)return deadline-2000;
        return deadline-started>10000?started+10000:deadline;
    }
    static final class Timing {
        final long requestStarted,requestDeadline,aReadStarted,aReadCompleted,aCensusCaptured,
                bReadStarted,bReadCompleted,bCensusCaptured,sealedElapsed;
        Timing(long requestStarted,long requestDeadline,long aReadStarted,long aReadCompleted,long aCensusCaptured,
                long bReadStarted,long bReadCompleted,long bCensusCaptured,long sealedElapsed){
            this(requestStarted,requestDeadline,aReadStarted,aReadCompleted,aCensusCaptured,bReadStarted,bReadCompleted,bCensusCaptured,sealedElapsed,false);
        }
        Timing(long requestStarted,long requestDeadline,long aReadStarted,long aReadCompleted,long aCensusCaptured,
                long bReadStarted,long bReadCompleted,long bCensusCaptured,long sealedElapsed,boolean completingInFlightPair){
            need(requestStarted>=0&&requestDeadline>requestStarted&&requestDeadline-requestStarted<=INITIAL_READ_LIMIT_MS,"bounded original native planning request");
            need(requestStarted<=aReadStarted&&aReadStarted<=aCensusCaptured&&aCensusCaptured<=aReadCompleted
                    &&aReadCompleted<=bReadStarted&&bReadStarted<=bCensusCaptured&&bCensusCaptured<=bReadCompleted
                    &&bReadCompleted<=sealedElapsed&&sealedElapsed<requestDeadline,"actual read/census/seal clock order");
            need((bReadCompleted<samplingDeadline(requestStarted,requestDeadline)||(completingInFlightPair&&bReadStarted<samplingDeadline(requestStarted,requestDeadline)))
                    &&bCensusCaptured-aCensusCaptured>=200,"both reads must start within the settle window and remain separated");
            this.requestStarted=requestStarted;this.requestDeadline=requestDeadline;this.aReadStarted=aReadStarted;
            this.aReadCompleted=aReadCompleted;this.aCensusCaptured=aCensusCaptured;this.bReadStarted=bReadStarted;
            this.bReadCompleted=bReadCompleted;this.bCensusCaptured=bCensusCaptured;this.sealedElapsed=sealedElapsed;
        }
        Map<String,Object> evidence(){Map<String,Object> e=new LinkedHashMap<String,Object>();
            e.put("request_started_elapsed_ms",requestStarted);e.put("request_deadline_elapsed_ms",requestDeadline);
            e.put("first_read_started_elapsed_ms",aReadStarted);e.put("first_read_completed_elapsed_ms",aReadCompleted);e.put("first_census_captured_elapsed_ms",aCensusCaptured);
            e.put("second_read_started_elapsed_ms",bReadStarted);e.put("second_read_completed_elapsed_ms",bReadCompleted);e.put("second_census_captured_elapsed_ms",bCensusCaptured);
            e.put("sealed_elapsed_ms",sealedElapsed);return NativeAppEvidence.immutableMap(e);}
        static Timing read(Map<String,Object> e){need(e.keySet().equals(NativeActionSnapshotCheck.keys("request_started_elapsed_ms,request_deadline_elapsed_ms,first_read_started_elapsed_ms,first_read_completed_elapsed_ms,first_census_captured_elapsed_ms,second_read_started_elapsed_ms,second_read_completed_elapsed_ms,second_census_captured_elapsed_ms,sealed_elapsed_ms")),"exact timing fields");
            return new Timing(number(e,"request_started_elapsed_ms"),number(e,"request_deadline_elapsed_ms"),number(e,"first_read_started_elapsed_ms"),number(e,"first_read_completed_elapsed_ms"),number(e,"first_census_captured_elapsed_ms"),number(e,"second_read_started_elapsed_ms"),number(e,"second_read_completed_elapsed_ms"),number(e,"second_census_captured_elapsed_ms"),number(e,"sealed_elapsed_ms"),true);}
    }

    static final class EventMark {
        final long events,unknown,content,boundary;
        EventMark(long events,long unknown,long content,long boundary){
            need(events>=0&&unknown>=0&&content>=0&&boundary>=0&&unknown<=events
                    &&content<=events&&boundary<=events-content,"actual event counter structure");
            this.events=events;this.unknown=unknown;this.content=content;this.boundary=boundary;
        }
        boolean monotonicSince(EventMark old){return old!=null&&events>=old.events&&unknown>=old.unknown
                &&content>=old.content&&boundary>=old.boundary&&unknown-old.unknown<=events-old.events
                &&content-old.content<=events-old.events&&boundary-old.boundary<=events-old.events-(content-old.content);}
        boolean contentOnlySince(EventMark before){
            return monotonicSince(before)&&unknown==before.unknown&&boundary==before.boundary
                    &&events-before.events==content-before.content;
        }
        Map<String,Object> evidence(){Map<String,Object> e=new LinkedHashMap<String,Object>();e.put("events",events);e.put("unknown",unknown);
            e.put("content",content);e.put("boundary",boundary);e.put("untyped",events-content-boundary);return NativeAppEvidence.immutableMap(e);}
        static EventMark read(Map<String,Object> e){need(e.keySet().equals(NativeActionSnapshotCheck.keys("events,unknown,content,boundary,untyped")),"exact actual event fields");
            EventMark out=new EventMark(number(e,"events"),number(e,"unknown"),number(e,"content"),number(e,"boundary"));
            need(number(e,"untyped")==out.events-out.content-out.boundary,"derived untyped count differs");return out;}
    }
    /** Window facts and event history are copied from the actual two reads.
     * Counter equality is never substituted for complete ownership evidence. */
    static final class CaptureContext {
        final Map<String,Object> firstWindowFacts,secondWindowFacts;
        final EventMark aBefore,aAfter,bBefore,bAfter,sealed;
        CaptureContext(Map<String,Object> first,Map<String,Object> second,EventMark aBefore,EventMark aAfter,
                EventMark bBefore,EventMark bAfter,EventMark sealed){
            need(first!=null&&second!=null&&aBefore!=null&&aAfter!=null&&bBefore!=null&&bAfter!=null&&sealed!=null,"actual full source context required");
            firstWindowFacts=NativeAppEvidence.immutableMap(first);secondWindowFacts=NativeAppEvidence.immutableMap(second);
            this.aBefore=aBefore;this.aAfter=aAfter;this.bBefore=bBefore;this.bAfter=bAfter;this.sealed=sealed;
            need(aAfter.monotonicSince(aBefore)&&bBefore.monotonicSince(aAfter)&&bAfter.monotonicSince(bBefore)&&sealed.monotonicSince(bAfter),"actual source event order");
        }
        void require(NativeActionSnapshotCheck.Snapshot a,NativeActionSnapshotCheck.Snapshot b,Timing timing){
            validateWindowFacts(a,firstWindowFacts,timing.aCensusCaptured);validateWindowFacts(b,secondWindowFacts,timing.bCensusCaptured);
            need(sameWindowFacts(firstWindowFacts,secondWindowFacts),"actual two-census window/owner facts differ");
        }
        Map<String,Object> evidence(){Map<String,Object> e=new LinkedHashMap<String,Object>();e.put("first_window_facts",firstWindowFacts);e.put("second_window_facts",secondWindowFacts);
            e.put("first_before",aBefore.evidence());e.put("first_after",aAfter.evidence());e.put("second_before",bBefore.evidence());e.put("second_after",bAfter.evidence());
            e.put("sealed",sealed.evidence());e.put("event_neutrality_claimed",false);return NativeAppEvidence.immutableMap(e);}
        static CaptureContext read(Map<String,Object> e){need(e.keySet().equals(NativeActionSnapshotCheck.keys("first_window_facts,second_window_facts,first_before,first_after,second_before,second_after,sealed,event_neutrality_claimed"))
                    &&Boolean.FALSE.equals(e.get("event_neutrality_claimed")),"exact source facts, no event neutrality claim");
            return new CaptureContext(object(e,"first_window_facts"),object(e,"second_window_facts"),EventMark.read(object(e,"first_before")),EventMark.read(object(e,"first_after")),
                    EventMark.read(object(e,"second_before")),EventMark.read(object(e,"second_after")),EventMark.read(object(e,"sealed")));}
    }

    static final class WindowCheck {
        final Map<String,Object> facts;final long started,completed;final EventMark before,after;
        WindowCheck(Map<String,Object> facts,long started,long completed,EventMark before,EventMark after){
            need(facts!=null&&started>=0&&completed>=started&&before!=null&&after!=null&&after.monotonicSince(before),"actual worker window check interval/watermarks required");
            this.facts=NativeAppEvidence.immutableMap(facts);this.started=started;this.completed=completed;this.before=before;this.after=after;
        }
        Map<String,Object> evidence(){Map<String,Object> e=new LinkedHashMap<String,Object>();e.put("started_elapsed_ms",started);e.put("completed_elapsed_ms",completed);
            e.put("before",before.evidence());e.put("after",after.evidence());e.put("window_facts",facts);return NativeAppEvidence.immutableMap(e);}
    }

    private static void requireBinding(Map<String,Object> e){
        need(e.keySet().equals(NativeActionSnapshotCheck.keys("task_id,owner_sha256,target_sha256,authorization_sha256,selection_sha256,installed_set_sha256,goal_sha256,background_generation,package,display_id,profile_target_sha256,profile_user_id,profile_user_serial,profile_full_uid")),"complete exact profile Session binding required");
        need(NativeAppEvidence.id(string(e,"task_id"))&&NativeAppEvidence.backgroundGeneration(string(e,"background_generation"))
                &&NativeAppGoal.XIAOMI_PACKAGE.equals(e.get("package")),"Session task/generation/package binding");
        for(String key:Arrays.asList("owner_sha256","target_sha256","authorization_sha256","selection_sha256","installed_set_sha256","goal_sha256","profile_target_sha256"))
            need(NativeAppEvidence.sha(string(e,key)),"Session hash "+key);
        long user=integer(e,"profile_user_id"),uid=integer(e,"profile_full_uid");
        need(integer(e,"display_id")>0&&user>0&&user<=21473&&number(e,"profile_user_serial")>0&&uid/100000==user
                &&uid%100000>=10000&&uid%100000<90000,"actual background/profile/UID identity");
    }
    private static void validateWindowFacts(NativeActionSnapshotCheck.Snapshot census,Map<String,Object> source,long at){
        need(source!=null&&source.keySet().equals(NativeActionSnapshotCheck.keys("window,reported_windows,profile_window,ime_visibility"))
                &&"hidden".equals(source.get("ime_visibility"))&&source.get("ime_visibility").equals(census.env.get("ime_visibility")),"complete actual source window/IME facts");
        Map<String,Object> window=object(source,"window"),reported=object(source,"reported_windows"),owner=object(source,"profile_window");
        need(window.keySet().equals(NativeActionSnapshotCheck.keys("metadata,package,window_id,display_id,rotation,left,top,right,bottom,width,height")),"complete original window fields");
        need(NativeActionSnapshotCheck.hash(string(window,"metadata")).equals(census.env.get("window_metadata_sha256"))
                &&NativeAppEvidence.fingerprint(reported).equals(census.env.get("reported_windows_sha256")),"actual window facts do not match census hashes");
        for(String key:Arrays.asList("package","window_id","display_id","rotation","width","height"))need(equalValue(window.get(key),census.env.get(key)),"actual window envelope differs: "+key);
        need(equal(Arrays.asList(integer(window,"left"),integer(window,"top"),integer(window,"right"),integer(window,"bottom")),census.env.get("root_bounds")),"actual window root geometry differs");
        need(reported.keySet().equals(NativeActionSnapshotCheck.keys("display_id,target_window_id,target_layer,windows,other_window_roots_traversed,unreported_windows_excluded"))
                &&Boolean.FALSE.equals(reported.get("other_window_roots_traversed"))&&Boolean.FALSE.equals(reported.get("unreported_windows_excluded"))
                &&equalValue(reported.get("display_id"),census.env.get("display_id"))&&equalValue(reported.get("target_window_id"),census.env.get("window_id"))
                &&reported.get("windows") instanceof List,"actual complete reported window source");
        List<?> rows=(List<?>)reported.get("windows");need(!rows.isEmpty()&&rows.size()<=64,"reported window cap");
        java.util.Set<Integer> ids=new java.util.TreeSet<Integer>();Map<String,Object> target=null;
        for(Object value:rows){need(value instanceof Map,"actual window row");Map<String,Object> row=cast(value);
            need(row.keySet().equals(NativeActionSnapshotCheck.keys("window_id,display_id,type,layer,bounds,focused,active"))
                    &&row.get("focused") instanceof Boolean&&row.get("active") instanceof Boolean,"complete actual window row fields");
            int id=integer(row,"window_id"),type=integer(row,"type"),layer=integer(row,"layer");
            need(id>=0&&ids.add(id)&&type>0&&type!=2&&layer>=0&&equalValue(row.get("display_id"),census.env.get("display_id")),"reported foreign/IME/duplicate window");
            rect(row.get("bounds"));if(equalValue(row.get("window_id"),census.env.get("window_id")))target=row;
        }
        need(target!=null&&integer(target,"type")==1&&integer(target,"layer")==integer(reported,"target_layer"),"actual reported target window missing");
        List<Integer> root=rect(census.env.get("root_bounds")),targetBounds=rect(target.get("bounds"));need(contains(targetBounds,root),"actual target window does not contain root");
        for(Object value:rows){Map<String,Object> row=cast(value);if(row!=target&&integer(row,"layer")>=integer(target,"layer"))
            need(!intersects(rect(row.get("bounds")),root),"reported window covers owned root");}
        need(owner.keySet().equals(NativeActionSnapshotCheck.keys("schema,source,generation,target_identity_sha256,proof_id,task_token_id,display_id,window_id,task_id,parent_task_id,user_id,user_serial,full_uid,observed_elapsed_ms,expires_elapsed_ms,proof_sha256,serialized_token_is_authority,grants_action_authority"))
                &&"hepta.profile-window-ownership.v1".equals(owner.get("schema"))&&"observed_accessibility_task_id_and_fresh_privileged_leaf".equals(owner.get("source"))
                &&Boolean.FALSE.equals(owner.get("serialized_token_is_authority"))&&Boolean.FALSE.equals(owner.get("grants_action_authority")),"actual profile window source required");
        String[][] keys={{"generation","background_generation"},{"target_identity_sha256","profile_target_sha256"},{"task_token_id","profile_task_token_id"},
            {"display_id","display_id"},{"window_id","window_id"},{"task_id","profile_task_id"},{"parent_task_id","profile_parent_task_id"},
            {"user_id","profile_user_id"},{"user_serial","profile_user_serial"},{"full_uid","profile_full_uid"}};
        for(String[] key:keys)need(equalValue(owner.get(key[0]),census.env.get(key[1])),"actual profile source differs: "+key[0]);
        long observed=number(owner,"observed_elapsed_ms"),expires=number(owner,"expires_elapsed_ms");
        need(observed>=0&&observed<=at&&at<expires&&expires-observed<=10000&&NativeAppEvidence.backgroundGeneration(string(owner,"proof_id"))
                &&NativeAppEvidence.sha(string(owner,"proof_sha256")),"actual profile proof clock/identity differs");
    }
    private static boolean sameWindowFacts(Map<String,Object> a,Map<String,Object> b){
        for(String k:Arrays.asList("window","reported_windows","ime_visibility"))if(!equalValue(a.get(k),b.get(k)))return false;
        Map<String,Object> x=new TreeMap<String,Object>(object(a,"profile_window")),y=new TreeMap<String,Object>(object(b,"profile_window"));
        for(String k:Arrays.asList("proof_id","proof_sha256","observed_elapsed_ms","expires_elapsed_ms")){x.remove(k);y.remove(k);}return equal(x,y);
    }
    private static int integer(Map<String,Object> e,String k){Object v=e.get(k);need(v instanceof Integer,"exact integer "+k);return (Integer)v;}
    @SuppressWarnings("unchecked") private static List<Integer> rect(Object o){need(o instanceof List&&((List<?>)o).size()==4,"complete actual rectangle");
        for(Object n:(List<?>)o)need(n instanceof Integer,"integer rectangle coordinates");List<Integer> r=(List<Integer>)o;need(r.get(0)<r.get(2)&&r.get(1)<r.get(3),"positive actual window rectangle");return r;}
    private static boolean contains(List<Integer> a,List<Integer> b){return a.get(0)<=b.get(0)&&a.get(1)<=b.get(1)&&a.get(2)>=b.get(2)&&a.get(3)>=b.get(3);}
    private static boolean intersects(List<Integer> a,List<Integer> b){return Math.max(a.get(0),b.get(0))<Math.min(a.get(2),b.get(2))&&Math.max(a.get(1),b.get(1))<Math.min(a.get(3),b.get(3));}

    /** Called before private create-only persistence; neither return value nor
     * encoding time grants observation freshness or an effect capability. */
    static byte[] encode(String id,NativeActionSnapshotCheck.Snapshot a,NativeActionSnapshotCheck.Snapshot b,
            Map<String,Object> binding,Timing timing,CaptureContext context)throws Exception{
        return encode(id,a,b,binding,timing,context,false);
    }
    static byte[] encodeIcon(String id,NativeActionSnapshotCheck.Snapshot a,NativeActionSnapshotCheck.Snapshot b,
            Map<String,Object> binding,Timing timing,CaptureContext context)throws Exception{
        return encode(id,a,b,binding,timing,context,true);
    }
    private static byte[] encode(String id,NativeActionSnapshotCheck.Snapshot a,NativeActionSnapshotCheck.Snapshot b,
            Map<String,Object> binding,Timing timing,CaptureContext context,boolean icon)throws Exception{
        need(context!=null,"actual source context required");context.require(a,b,timing);
        NativeSearchRole role=checked(id,a,b,binding,timing,context,icon);
        Map<String,Object> e=new LinkedHashMap<String,Object>();e.put("schema",icon?ICON_SCHEMA:SCHEMA);e.put("capture_kind",KIND);
        e.put("observation_id",id);e.put("package",NativeAppGoal.XIAOMI_PACKAGE);e.put("binding",binding);e.put("timing",timing.evidence());
        e.put("first",snapshot(a));e.put("second",snapshot(b));e.put("role",role.evidence());e.put("source_context",context.evidence());
        e.put("full_tree_equal",role.fullTreeEqual);e.put("planning_only",true);e.put("screenshot_observed",false);
        e.put("screenshot_sha256",null);e.put("generic_action_authority",false);e.put("completion_authority",false);
        byte[] bytes=json(e).toString().getBytes(StandardCharsets.UTF_8);need(bytes.length<=MAX_BYTES,"complete planning receipt byte cap");return bytes;
    }

    /** Only bytes read back from the private fsynced file may enter here. The
     * expected identity is the same Session's immutable host-independent value,
     * never supplied by a model. Persisted/callback clocks stay outside the
     * original encoded census timestamps. */
    static NativeSearchPlanning fromSealedBytes(byte[] actual,String expectedEncodedSha,Map<String,Object> expectedBinding,long persistedElapsed)throws Exception{
        need(actual!=null&&actual.length>0&&actual.length<=MAX_BYTES,"actual bounded receipt bytes required");
        byte[] owned=actual.clone();need(NativeAppEvidence.sha(expectedEncodedSha)&&expectedEncodedSha.equals(hash(owned)),"actual readback bytes differ from this encoded request");String text=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(owned)).toString();
        Map<String,Object> e=map(new JSONObject(text));
        need(e.keySet().equals(NativeActionSnapshotCheck.keys("schema,capture_kind,observation_id,package,binding,timing,first,second,role,source_context,full_tree_equal,planning_only,screenshot_observed,screenshot_sha256,generic_action_authority,completion_authority")),"exact planning receipt fields");
        boolean icon=ICON_SCHEMA.equals(e.get("schema"));
        need((icon||SCHEMA.equals(e.get("schema")))&&KIND.equals(e.get("capture_kind"))&&NativeAppGoal.XIAOMI_PACKAGE.equals(e.get("package"))
                &&Boolean.TRUE.equals(e.get("planning_only"))&&Boolean.FALSE.equals(e.get("screenshot_observed"))&&e.get("screenshot_sha256")==null
                &&Boolean.FALSE.equals(e.get("generic_action_authority"))&&Boolean.FALSE.equals(e.get("completion_authority")),"planning kind cannot acquire pixel/action/completion authority");
        Map<String,Object> binding=object(e,"binding");need(equal(binding,expectedBinding),"receipt belongs to another Session identity");
        Timing timing=Timing.read(object(e,"timing"));NativeActionSnapshotCheck.Snapshot a=readSnapshot(object(e,"first")),b=readSnapshot(object(e,"second"));
        CaptureContext context=CaptureContext.read(object(e,"source_context"));context.require(a,b,timing);
        String id=string(e,"observation_id");NativeSearchRole role=checked(id,a,b,binding,timing,context,icon);
        need(equal(role.evidence(),object(e,"role"))&&Boolean.valueOf(role.fullTreeEqual).equals(e.get("full_tree_equal")),"actual complete role/tree claims differ");
        need(timing.sealedElapsed<=persistedElapsed&&persistedElapsed<timing.requestDeadline,"original persistence deadline exceeded");
        return new NativeSearchPlanning(id,owned,a,b,role,binding,timing,context,persistedElapsed);
    }
    private NativeSearchPlanning(String id,byte[] bytes,NativeActionSnapshotCheck.Snapshot a,NativeActionSnapshotCheck.Snapshot b,
            NativeSearchRole role,Map<String,Object> binding,Timing timing,CaptureContext context,long persisted){
        this.id=id;packageName=NativeAppGoal.XIAOMI_PACKAGE;receiptSha256=hash(bytes);receiptBytes=bytes.length;
        first=a;second=b;this.role=role;fullTreeEqual=role.fullTreeEqual;this.binding=NativeAppEvidence.immutableMap(binding);
        this.timing=timing;this.context=context;capturedElapsed=timing.bCensusCaptured;completedElapsed=timing.bReadCompleted;persistedElapsed=persisted;publication=null;publishedElapsed=-1;
    }
    /** Publication is a small immutable envelope over the already decoded
     * core. It records actual late content events without pretending that B is
     * a current full tree; the new tool still requires a complete fresh C/D. */
    NativeSearchPlanning published(long now,EventMark watermark,WindowCheck check){
        need(publication==null&&watermark!=null&&now>=persistedElapsed&&now<timing.requestDeadline
                &&now-capturedElapsed<=2000,"original capture age/publication deadline exceeded");
        need(check!=null&&persistedElapsed<=check.started&&check.completed<=now&&check.before.monotonicSince(context.sealed)
                &&watermark.monotonicSince(check.after),"actual late window check/event order differs");
        Map<String,Object> currentWindowFacts=check.facts;validateWindowFacts(second,currentWindowFacts,now);
        need(sameWindowFacts(context.secondWindowFacts,currentWindowFacts),"publication window/owner facts changed");
        Map<String,Object> e=new LinkedHashMap<String,Object>();e.put("schema","hepta.native-search-planning-publication.v1");
        e.put("receipt_sha256",receiptSha256);e.put("published_elapsed_ms",now);e.put("watermark",watermark.evidence());
        e.put("worker_window_check",check.evidence());e.put("current_window_facts",currentWindowFacts);e.put("late_content_events",watermark.content-context.sealed.content);
        e.put("late_boundary_events",watermark.boundary-context.sealed.boundary);e.put("late_unknown_events",watermark.unknown-context.sealed.unknown);
        e.put("late_untyped_events",watermark.events-context.sealed.events-(watermark.content-context.sealed.content)-(watermark.boundary-context.sealed.boundary));
        e.put("planning_as_of_B",true);e.put("no_event_neutrality_claim",true);
        e.put("current_full_tree_claimed",false);e.put("capture_clock_refreshed",false);e.put("fresh_effect_census_required",true);
        return new NativeSearchPlanning(this,now,NativeAppEvidence.immutableMap(e));
    }
    private NativeSearchPlanning(NativeSearchPlanning original,long now,Map<String,Object> publication){
        id=original.id;packageName=original.packageName;receiptSha256=original.receiptSha256;receiptBytes=original.receiptBytes;
        first=original.first;second=original.second;role=original.role;fullTreeEqual=original.fullTreeEqual;binding=original.binding;
        timing=original.timing;context=original.context;capturedElapsed=original.capturedElapsed;completedElapsed=original.completedElapsed;
        persistedElapsed=original.persistedElapsed;publishedElapsed=now;this.publication=publication;
    }
    private static NativeSearchRole checked(String id,NativeActionSnapshotCheck.Snapshot a,NativeActionSnapshotCheck.Snapshot b,
            Map<String,Object> binding,Timing timing,CaptureContext context,boolean icon){
        need(NativeAppEvidence.id(id)&&a!=null&&b!=null&&binding!=null&&timing!=null,"actual planning identity/timing required");
        requireBinding(binding);
        need(id.equals(a.env.get("origin_observation_id"))&&id.equals(b.env.get("origin_observation_id")),"census observation ID differs");
        for(Map.Entry<String,Object> e:binding.entrySet())need(a.env.containsKey(e.getKey())&&b.env.containsKey(e.getKey())
                &&equalValue(e.getValue(),a.env.get(e.getKey()))&&equalValue(e.getValue(),b.env.get(e.getKey())),"census Session binding differs: "+e.getKey());
        need(number(a.env,"captured_elapsed_ms")==timing.aCensusCaptured&&number(b.env,"captured_elapsed_ms")==timing.bCensusCaptured,"census time was refreshed");
        EventMark before=context.aBefore,after=context.sealed;
        boolean contentOnly=after.contentOnlySince(before);
        NativeSearchRole role=icon?NativeSearchRole.iconPair(a,b,contentOnly):
                contentOnly?NativeSearchRole.compareForPlanning(a,b):NativeSearchRole.compare(a,b);
        if(timing.bReadCompleted>=samplingDeadline(timing.requestStarted,timing.requestDeadline))
            need(contentOnly&&role.fullPageSwap,"only a fully classified in-flight banner pair can use the publication margin");
        return role;
    }
    Map<String,Object> evidence(){Map<String,Object> e=new LinkedHashMap<String,Object>();e.put("schema",role.iconAction?ICON_SCHEMA:SCHEMA);e.put("capture_kind",KIND);
        e.put("observation_id",id);e.put("package",packageName);e.put("receipt_sha256",receiptSha256);e.put("receipt_bytes",receiptBytes);
        e.put("timing",timing.evidence());e.put("source_context",context.evidence());e.put("persisted_elapsed_ms",persistedElapsed);e.put("publication",publication);e.put("binding",binding);e.put("role",role.evidence());
        e.put("planning_only",true);e.put("full_tree_equal",fullTreeEqual);e.put("screenshot_observed",false);e.put("screenshot_sha256",null);
        e.put("generic_action_authority",false);e.put("completion_authority",false);return NativeAppEvidence.immutableMap(e);}
    static Map<String,Object> snapshot(NativeActionSnapshotCheck.Snapshot s){Map<String,Object> e=new LinkedHashMap<String,Object>();e.put("envelope",s.env);
        List<Map<String,Object>> rows=new ArrayList<Map<String,Object>>();for(NativeActionSnapshotCheck.Node n:s.nodes.values())rows.add(n.v);e.put("nodes",rows);return e;}
    @SuppressWarnings("unchecked") static NativeActionSnapshotCheck.Snapshot readSnapshot(Map<String,Object> e){
        need(e.keySet().equals(NativeActionSnapshotCheck.keys("envelope,nodes"))&&e.get("nodes") instanceof List,"complete exact census fields");
        List<NativeActionSnapshotCheck.Node> rows=new ArrayList<NativeActionSnapshotCheck.Node>();for(Object row:(List<?>)e.get("nodes")){
            need(row instanceof Map,"complete node object");rows.add(new NativeActionSnapshotCheck.Node((Map<String,Object>)row));}
        return new NativeActionSnapshotCheck.Snapshot(object(e,"envelope"),rows);
    }
    static JSONObject json(Map<String,Object> e)throws Exception{JSONObject out=new JSONObject();for(Map.Entry<String,Object> row:e.entrySet())out.put(row.getKey(),jsonValue(row.getValue()));return out;}
    private static Object jsonValue(Object v)throws Exception{if(v==null)return JSONObject.NULL;if(v instanceof Map)return json(cast(v));
        if(v instanceof Iterable){JSONArray out=new JSONArray();for(Object x:(Iterable<?>)v)out.put(jsonValue(x));return out;}return v;}
    static Map<String,Object> map(JSONObject o)throws Exception{Map<String,Object> out=new TreeMap<String,Object>();Iterator<String> keys=o.keys();while(keys.hasNext()){String k=keys.next();out.put(k,value(o.get(k),0));}return out;}
    private static Object value(Object v,int depth)throws Exception{need(depth<16,"receipt nesting bound");if(v==JSONObject.NULL)return null;
        if(v instanceof JSONObject){Map<String,Object> out=new TreeMap<String,Object>();Iterator<String> keys=((JSONObject)v).keys();while(keys.hasNext()){String k=keys.next();out.put(k,value(((JSONObject)v).get(k),depth+1));}return out;}
        if(v instanceof JSONArray){List<Object> out=new ArrayList<Object>();for(int i=0;i<((JSONArray)v).length();i++)out.add(value(((JSONArray)v).get(i),depth+1));return out;}
        need(v instanceof String||v instanceof Boolean||v instanceof Integer||v instanceof Long,"exact receipt scalar type");return v;}
    @SuppressWarnings("unchecked") private static Map<String,Object> cast(Object v){return (Map<String,Object>)v;}
    private static Map<String,Object> object(Map<String,Object> e,String k){Object v=e.get(k);need(v instanceof Map,"object "+k);return cast(v);}
    private static String string(Map<String,Object> e,String k){Object v=e.get(k);need(v instanceof String,"string "+k);return (String)v;}
    private static long number(Map<String,Object> e,String k){Object v=e.get(k);need(v instanceof Integer||v instanceof Long,"integer clock "+k);return ((Number)v).longValue();}
    static boolean equal(Object a,Object b){return a!=null&&b!=null&&NativeAppEvidence.fingerprint(a).equals(NativeAppEvidence.fingerprint(b));}
    private static boolean equalValue(Object a,Object b){return a==null?b==null:b!=null&&equal(a,b);}
    private static String hash(byte[] bytes){try{StringBuilder s=new StringBuilder(64);for(byte b:MessageDigest.getInstance("SHA-256").digest(bytes))s.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return s.toString();}catch(Exception e){throw new IllegalStateException(e);}}
    private static void need(boolean yes,String why){if(!yes)throw new IllegalArgumentException("native search planning: "+why);}
}
