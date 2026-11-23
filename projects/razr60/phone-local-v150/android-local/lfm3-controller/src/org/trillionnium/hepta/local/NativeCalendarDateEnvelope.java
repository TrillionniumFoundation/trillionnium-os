package org.trillionnium.hepta.local;

import java.io.File;
import java.time.LocalDate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.WindowOwnership;

/** Original pixels and observed calendar facts for a separate protocol proposal.
 * This is data binding, NOT a Session Offer, current dispatch permit or date proof.
 * The future producer must additionally bind the actual NativeAppSession/Gate.
 */
final class NativeCalendarDateEnvelope {
    static final long FRESH_CAPTURE_MS=2000L;
    final NativeAppGoal goal;
    final NativeAppEvidence.Frame facts;
    final LocalInference.CurrentFrame image;
    final ProfileTarget profile;
    final NativeCalendarDateIntent.Rect monthRegion;
    final String pngSha256,ownerEvidenceSha256;
    final LocalDate observedMonth;
    private final File originalPath;

    private NativeCalendarDateEnvelope(NativeAppGoal goal,NativeAppEvidence.Frame facts,
            LocalInference.CurrentFrame image,ProfileTarget profile,NativeCalendarDateIntent.Rect region,
            String pngSha,String ownerEvidenceSha,LocalDate month,File path){
        this.goal=goal;this.facts=facts;this.image=image;this.profile=profile;monthRegion=region;
        pngSha256=pngSha;ownerEvidenceSha256=ownerEvidenceSha;observedMonth=month;originalPath=path;
    }

    /** Actual private readback, actual CurrentFrame callback and exact complete
     * pixel Frame are mandatory. A hash-only or caller-provided byte array is not accepted.
     * This initial protocol module is deliberately not called by production yet.
     */
    static NativeCalendarDateEnvelope capture(NativeAppGoal goal,NativeAppEvidence.Frame facts,
            LocalInference.CurrentFrame image,ProfileTarget profile,LocalRuntimeConfig runtime,NativeCalendarDateProtocol.Clock clock)throws Exception{
        need(clock!=null,"actual elapsed-realtime clock required");long now=clock.elapsedRealtime();
        need(runtime!=null&&runtime.profile==ModelProfile.GUI_OWL_4B&&!runtime.visualObservationOnly
                &&"npu".equals(runtime.compute)&&runtime.contextTokens==8192&&runtime.threads==4,
                "only the explicit GUI-Owl tools configuration can produce this proposal");
        need(NativeCtripFlightPage.supported(goal)&&goal.departureDate!=null&&facts!=null&&image!=null&&profile!=null,
                "same supported literal flight goal, pixel frame and selected profile required");
        need(profile.versionCode==NativeCtripFlightPage.VERSION_CODE&&profile.apkHashes.size()==1
                &&NativeCtripFlightPage.BASE_APK_SHA256.equals(profile.apkHashes.get("base")),"pinned installed-provider identity required");
        need(facts.capture==null&&ObservationCaptureEvidence.PIXELS.equals(facts.captureKind)
                &&facts.collectionComplete&&!facts.nodesTruncated&&facts.metadataObserved&&facts.windowType==1,
                "a complete original pixel application observation is required");
        need(goal.packageName.equals(profile.packageName)&&goal.packageName.equals(facts.packageName)
                &&goal.ownerSha256.equals(facts.ownerSha)&&goal.ownerSha256.equals(image.ownerSha256)
                &&facts.taskId.equals(image.taskId)&&facts.observationId.equals(image.observationId)
                &&facts.generation.equals(image.backgroundGeneration)&&facts.packageName.equals(image.packageName)
                &&facts.screenshotSha.equals(image.imageSha256)&&facts.displayId==image.displayId
                &&facts.windowId==image.windowId&&facts.rotation==image.rotation
                &&facts.width==image.width&&facts.height==image.height&&facts.capturedElapsedMs==image.capturedElapsedMillis,
                "CurrentFrame and original native pixel facts differ");
        need(goal.ownerSha256.equals(MobiMindContract.sha(image.taskOwnerEvidence())),
                "CurrentFrame original OWNER bytes differ from the immutable goal");
        need(facts.left>=0&&facts.top>=0&&facts.right<=image.width&&facts.bottom<=image.height,
                "window must be inside original unscaled screenshot");
        requireFresh(facts,profile,now);
        NativeCtripFlightPage.Page page=NativeCtripFlightPage.inspect(goal,facts);
        need(NativeCtripFlightPage.CALENDAR.equals(page.phase)&&page.calendarYearHeadersAdmitted()
                &&page.form==null&&page.quotes.isEmpty(),"actual bounded native calendar required");
        NativeAppEvidence.Node list=null;
        for(NativeAppEvidence.Node n:facts.nodes)if("ctrip.android.view:id/calendar_list".equals(n.viewId)){
            need(list==null,"one original calendar list required");list=n;
        }
        need(list!=null&&facts.usable(list)&&"android.widget.ListView".equals(list.className)
                &&list.enabled&&list.scrollable&&!list.editable&&!list.password,
                "actual enabled calendar list is required");
        int monthTop=-1,monthBottom=list.bottom,seen=0;
        LocalDate month=goal.departureDate.withDayOfMonth(1);
        for(Map<String,Object> header:page.calendarMonths){
            NativeAppEvidence.Node headerNode=facts.byId.get(header.get("node_id"));
            need(headerNode!=null&&headerNode.path!=null&&list.path!=null
                    &&headerNode.path.startsWith(list.path+"/")&&headerNode.within(list),
                    "actual month title must belong to the same calendar list");
            int year=integer(header.get("year")),number=integer(header.get("month"));
            int[] bounds=bounds(header.get("bounds"));
            LocalDate observed=LocalDate.of(year,number,1);
            if(observed.equals(month)){
                seen++;monthTop=Math.max(list.top,bounds[3]);
                Object sticky=header.get("sticky_header_pair");
                if(sticky instanceof Map){
                    Object h=((Map<?,?>)sticky).get("sticky_header");
                    need(h instanceof Map,"actual sticky-header evidence required");
                    monthTop=Math.max(monthTop,bounds(((Map<?,?>)h).get("bounds"))[3]);
                }
            }
        }
        need(seen==1,"requested year and month must be uniquely observed, never inferred");
        for(Map<String,Object> header:page.calendarMonths){
            LocalDate observed=LocalDate.of(integer(header.get("year")),integer(header.get("month")),1);
            int[] bounds=bounds(header.get("bounds"));
            if(!observed.equals(month)){
                need(bounds[3]<=monthTop||bounds[1]>monthTop,"another month header overlaps the target-month start");
                // The basic provider does not prove month-title ordering. Any
                // later visible header ends this month region, including an
                // unexpected earlier/same-year header below it.
                if(bounds[1]>monthTop)monthBottom=Math.min(monthBottom,bounds[1]);
            }
        }
        need(monthTop<monthBottom,"requested visible month region is empty");
        NativeCalendarDateIntent.Rect region=new NativeCalendarDateIntent.Rect(list.left,monthTop,list.right,monthBottom);
        image.requireCurrent();
        MobiMindPrivateFiles.Read read=MobiMindPrivateFiles.read(image.image,8*1024*1024,true);
        String actual=MobiMindContract.sha(read.bytes);
        need(actual.equals(image.imageSha256),"actual private PNG bytes differ from the CurrentFrame hash");
        int[] geometry=UiVenusInputContract.png(read.bytes);
        need(geometry[0]==image.width&&geometry[1]==image.height,"original PNG geometry differs");
        read.unchangedPath();image.requireCurrent();requireFresh(facts,profile,clock.elapsedRealtime());
        return new NativeCalendarDateEnvelope(goal,facts,image,profile,region,actual,
                MobiMindContract.sha(image.taskOwnerEvidence()),month,image.image.getCanonicalFile());
    }

    void requireUnchangedOriginal()throws Exception{
        image.requireCurrent();
        need(originalPath.equals(image.image.getCanonicalFile()),"original screenshot path changed");
        MobiMindPrivateFiles.Read read=MobiMindPrivateFiles.read(originalPath,8*1024*1024,true);
        need(pngSha256.equals(MobiMindContract.sha(read.bytes)),"sealed screenshot bytes changed");
        read.unchangedPath();image.requireCurrent();
    }
    void requireFreshReplacement(NativeCalendarDateEnvelope current,long modelCompleted,NativeCalendarDateProtocol.Clock clock)throws Exception{
        need(clock!=null,"actual elapsed-realtime clock required");
        need(current!=null&&current!=this&&current.goal==goal&&current.profile.same(profile),"same original goal/profile objects required");
        NativeAppEvidence.Frame a=facts,b=current.facts;
        need(a.taskId.equals(b.taskId)&&a.ownerSha.equals(b.ownerSha)&&a.targetSha.equals(b.targetSha)
                &&a.authorizationSha.equals(b.authorizationSha)&&a.selectionSha.equals(b.selectionSha)
                &&a.packageName.equals(b.packageName)&&a.generation.equals(b.generation)
                &&a.displayId==b.displayId&&a.windowId==b.windowId&&a.rotation==b.rotation
                &&a.width==b.width&&a.height==b.height&&a.left==b.left&&a.top==b.top&&a.right==b.right&&a.bottom==b.bottom
                &&NativeAppEvidence.sameProfileOwner(a.profileWindow,b.profileWindow),"fresh frame identity changed");
        need(!a.observationId.equals(b.observationId)&&!a.sourceRecordSha.equals(b.sourceRecordSha)
                &&!originalPath.equals(current.originalPath)&&b.capturedElapsedMs>a.capturedElapsedMs
                &&b.capturedElapsedMs>=modelCompleted,"fresh recapture after the model is mandatory; no old pixels relabelled");
        need(pngSha256.equals(current.pngSha256)&&a.treeSha.equals(b.treeSha)&&a.stateSha.equals(b.stateSha)
                &&monthRegion.same(current.monthRegion)&&observedMonth.equals(current.observedMonth),
                "strict first protocol requires identical newly captured pixels, complete tree and calendar geometry");
        requireFresh(b,current.profile,clock.elapsedRealtime());current.requireUnchangedOriginal();
        requireFresh(b,current.profile,clock.elapsedRealtime());
    }
    Map<String,Object> evidence(){
        Map<String,Object> e=new LinkedHashMap<String,Object>();e.put("schema","hepta.native-calendar-pixel-envelope.v1");
        e.put("goal_sha256",goal.contractSha256);e.put("date",goal.departureDate.toString());e.put("source_frame",facts.evidence());
        e.put("screen_sha256",pngSha256);e.put("task_owner_evidence_sha256",ownerEvidenceSha256);
        e.put("observed_calendar_month",observedMonth.toString());e.put("month_region",monthRegion.evidence());
        e.put("png_header_and_hash_verified",true);e.put("png_decode_verified_by_this_protocol",false);
        e.put("model_cell_semantics_verified",false);e.put("grants_dispatch_authority",false);return NativeAppEvidence.immutableMap(e);
    }
    private static void requireFresh(NativeAppEvidence.Frame f,ProfileTarget profile,long now){
        need(now>=f.capturedElapsedMs&&now-f.capturedElapsedMs<=FRESH_CAPTURE_MS,"fresh capture age exceeds the original two-second bound");
        NativeAppEvidence.requireProfileTarget(profile,f.profileWindow);WindowOwnership window=f.profileWindow;
        need(window!=null,"actual full-UID profile window missing");
        window.requireMatches(profile,f.generation,f.displayId,f.windowId,window.taskId,now);
    }
    private static int integer(Object v){need(v instanceof Integer,"canonical integer month fact required");return ((Integer)v).intValue();}
    private static int[] bounds(Object v){need(v instanceof List&&((List<?>)v).size()==4,"actual header bounds required");
        List<?> b=(List<?>)v;return new int[]{integer(b.get(0)),integer(b.get(1)),integer(b.get(2)),integer(b.get(3))};}
    private static void need(boolean ok,String why){if(!ok)throw new IllegalArgumentException(why);}
}
