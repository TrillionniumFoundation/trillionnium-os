package org.trillionnium.hepta.local;

import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import org.json.JSONObject;

/** Finite task-private fixture artifacts. This reader has no action, model,
 * configuration, control-session, recovery-journal or resume interface. */
final class NativeOrderPreviewManualFiles {
    static final String DIRECTORY="manual-order-preview";
    private final File directory;
    private final NativeAppSession.ManualFixture fixture;
    final NativeOrderPreviewManual.Ready ready;
    private final Map<String,MobiMindPrivateFiles.Read> originals=new LinkedHashMap<String,MobiMindPrivateFiles.Read>();
    private final Set<String> written=new TreeSet<String>();
    private NativeOrderPreviewManual.ManualPreviewGuard guard;
    private boolean finished;

    private NativeOrderPreviewManualFiles(File directory,NativeAppSession.ManualFixture fixture,
            NativeOrderPreviewManual.Ready ready){
        this.directory=directory;this.fixture=fixture;this.ready=ready;
    }
    static NativeOrderPreviewManualFiles publish(File taskDirectory,NativeAppSession.ManualFixture fixture,
            PhoneObservation observed,NativeActionSnapshotCheck.Snapshot census,String controllerBuildSha,long now)throws Exception{
        fixture.requireCurrent(now);requireDirectory(taskDirectory);
        need(observed!=null&&census!=null&&fixture.before.observationId.equals(observed.id)
                &&observed.id.equals(census.env.get("origin_observation_id"))
                &&observed.screenshot!=null&&observed.screenshot.getParentFile().equals(taskDirectory)
                &&observed.screenshotSha256!=null,"actual visual frame/census/PNG required");
        File originalFrame=new File(taskDirectory,"native-app-frame-"+observed.id+".json");
        MobiMindPrivateFiles.Read frame=MobiMindPrivateFiles.read(originalFrame,2*1024*1024,true);
        need(Arrays.equals(frame.bytes,observed.toEvidenceJson().toString(2).getBytes(StandardCharsets.UTF_8))
                &&fixture.before.sourceRecordSha.equals(NativeOrderPreviewManual.sha256(frame.bytes)),"original saved frame differs");
        MobiMindPrivateFiles.Read png=MobiMindPrivateFiles.read(observed.screenshot,16*1024*1024,true);
        need(observed.screenshotSha256.equals(NativeOrderPreviewManual.sha256(png.bytes)),"original PNG bytes differ");
        requirePng(png.bytes,observed.width,observed.height);
        byte[] full=NativeOrderPreviewManual.json(NativeOrderPreviewManual.censusEvidence(census));
        need(full.length<=4*1024*1024,"bounded full census required");
        File directory=MobiMindPrivateFiles.directory(new File(taskDirectory,DIRECTORY),true);
        List<NativeOrderPreviewManual.Artifact> artifacts=new ArrayList<NativeOrderPreviewManual.Artifact>();
        artifacts.add(artifact("before-census.json",full));
        artifacts.add(artifact("before-frame.json",frame.bytes));
        artifacts.add(artifact("before.png",png.bytes));
        String readyId=UUID.randomUUID().toString().replace("-","");
        String nonce=UUID.randomUUID().toString().replace("-","")+UUID.randomUUID().toString().replace("-","");
        NativeOrderPreviewManual.Ready ready=new NativeOrderPreviewManual.Ready(fixture.owner,census,
                fixture.binding(controllerBuildSha),artifacts,readyId,nonce,now,fixture.taskDeadline,fixture.leaseDeadline);
        NativeOrderPreviewManualFiles files=new NativeOrderPreviewManualFiles(directory,fixture,ready);
        files.write("before-census.json",full);files.write("before-frame.json",frame.bytes);files.write("before.png",png.bytes);
        files.write("ready.json",ready.bytes());
        frame.unchangedPath();png.unchangedPath();fixture.requireCurrent(android.os.SystemClock.elapsedRealtime());
        Map<String,Object> marker=NativeOrderPreviewManual.map();
        marker.put("schema","hepta.order-preview.manual-fixture-publication.v1");marker.put("ready_sha256",ready.sha256);
        marker.put("ready_bytes",Long.valueOf(ready.bytes().length));marker.put("task_id",ready.taskId);
        marker.put("complete_originals",true);marker.put("grants_dispatch",false);
        files.write("published.json",NativeOrderPreviewManual.json(marker));
        files.requireMembership();return files;
    }
    /** A publisher writes/readbacks request.json first, and create-only publishes
     * its exact hash/length marker last. A partial request file is never consumed. */
    NativeOrderPreviewManual.ManualPreviewGuard consumeIfPublished(long now)throws Exception{
        need(!finished&&guard==null,"manual request phase already ended");fixture.requireCurrent(now);
        requireMembership();
        File markerPath=new File(directory,"request-published.json");
        if(!MobiMindPrivateFiles.exists(markerPath))return null;
        MobiMindPrivateFiles.Read marker=MobiMindPrivateFiles.read(markerPath,1024,true);
        JSONObject value=WebEvidenceJson.parse(strictUtf8(marker.bytes),1024);
        WebEvidenceJson.keys(value,NativeOrderPreviewManual.keys("schema,request_sha256,request_bytes"));
        need("hepta.order-preview.manual-fixture-request-publication.v1".equals(WebEvidenceJson.text(value,"schema")),
                "manual request publication schema differs");
        long bytes=WebEvidenceJson.number(value,"request_bytes");
        String sha=WebEvidenceJson.text(value,"request_sha256");
        need(bytes>0&&bytes<=NativeOrderPreviewManual.REQUEST_MAX&&NativeOrderPreviewManual.sha(sha),"request marker shape differs");
        MobiMindPrivateFiles.Read request=MobiMindPrivateFiles.read(new File(directory,"request.json"),
                NativeOrderPreviewManual.REQUEST_MAX,true);
        need(bytes==request.bytes.length&&sha.equals(NativeOrderPreviewManual.sha256(request.bytes)),"request publication differs");
        NativeOrderPreviewManual.Request parsed=NativeOrderPreviewManual.Request.parse(request.bytes);
        for(Map.Entry<String,MobiMindPrivateFiles.Read> entry:originals.entrySet()){
            MobiMindPrivateFiles.Read current=MobiMindPrivateFiles.read(new File(directory,entry.getKey()),16*1024*1024,true);
            entry.getValue().unchangedPath();need(Arrays.equals(entry.getValue().bytes,current.bytes),"READY original changed");
            current.unchangedPath();
        }
        marker.unchangedPath();request.unchangedPath();fixture.requireCurrent(android.os.SystemClock.elapsedRealtime());
        guard=ready.consume(parsed,android.os.SystemClock.elapsedRealtime());
        originals.put("request.json",request);originals.put("request-published.json",marker);
        written.add("request.json");written.add("request-published.json");
        Map<String,Object> consumed=NativeOrderPreviewManual.map();
        consumed.put("schema","hepta.order-preview.manual-fixture-consumption.v1");
        consumed.put("task_id",ready.taskId);consumed.put("ready_sha256",ready.sha256);
        consumed.put("request_id",parsed.requestId);consumed.put("request_sha256",parsed.sha256);
        consumed.put("consumed_elapsed_ms",Long.valueOf(guard.consumedElapsed));
        consumed.put("request_consumed",true);consumed.put("dispatch_claimed",false);
        consumed.put("platform_call_entered",false);consumed.put("origin","owner_manual_fixture");
        // Memory consumption happens first; a failed/unknown durable write never
        // permits retry, action dispatch, request replacement or claim deletion.
        write("request-consumed.json",NativeOrderPreviewManual.json(consumed));
        write("refusal.json",NativeOrderPreviewManual.json(guard.refuseUnbound(android.os.SystemClock.elapsedRealtime())));
        marker.unchangedPath();request.unchangedPath();requireMembership();return guard;
    }
    /** A real observation after the refused request, never a fabricated effect
     * result. Unknown provider pages can be preserved without Session.observed. */
    void archiveAfterRefusal(PhoneObservation observed,NativeActionSnapshotCheck.Snapshot census)throws Exception{
        need(!finished&&guard!=null&&observed!=null&&census!=null,"one actual post-request observation required");
        fixture.requireCurrent(android.os.SystemClock.elapsedRealtime());
        need(!fixture.before.observationId.equals(observed.id)
                &&observed.id.equals(census.env.get("origin_observation_id"))
                &&observed.capturedElapsedMillis>=guard.consumedElapsed&&observed.screenshot!=null,
                "new real observation after request consumption required");
        for(String key:NativeActionSnapshotCheck.PROFILE_AUTHORITY){
            if("origin_observation_id".equals(key))continue;
            need(ready.census.env.get(key).equals(census.env.get(key)),"post-request identity differs: "+key);
        }
        MobiMindPrivateFiles.Read png=MobiMindPrivateFiles.read(observed.screenshot,16*1024*1024,true);
        need(observed.screenshotSha256.equals(NativeOrderPreviewManual.sha256(png.bytes)),"post-request PNG bytes differ");
        requirePng(png.bytes,observed.width,observed.height);
        write("after-census.json",NativeOrderPreviewManual.json(NativeOrderPreviewManual.censusEvidence(census)));
        write("after-frame.json",observed.toEvidenceJson().toString(2).getBytes(StandardCharsets.UTF_8));
        write("after.png",png.bytes);png.unchangedPath();
        Map<String,Object> fact=NativeOrderPreviewManual.map();fact.put("schema","hepta.order-preview.manual-fixture-after.v1");
        fact.put("observation_id",observed.id);fact.put("census_sha256",census.sha);
        fact.put("observed_after_request",true);fact.put("navigation_entered",false);fact.put("navigation_effect",false);
        fact.put("page_provider_acceptance_claimed",false);fact.put("business_success",false);
        write("after.json",NativeOrderPreviewManual.json(fact));requireMembership();
    }
    void finish(String reason,long now)throws Exception{
        need(!finished,"manual fixture terminal already written");finished=true;
        Map<String,Object> value=NativeOrderPreviewManual.map();value.put("schema","hepta.order-preview.manual-fixture-terminal.v1");
        value.put("task_id",ready.taskId);value.put("ready_sha256",ready.sha256);value.put("status","partial");
        value.put("reason",reason);value.put("finished_elapsed_ms",Long.valueOf(now));
        value.put("manual_fixture",true);value.put("request_consumed",guard!=null);
        value.put("actual_after_observation_archived",written.contains("after.json"));
        value.put("this_navigation_has_model_proposal",false);value.put("dispatch_claimed",false);
        value.put("platform_call_entered",false);value.put("effect",false);value.put("automatic_continuation",false);
        value.put("business_success",false);value.put("order_submitted",false);value.put("payment_attempted",false);
        value.put("cleanup_result_supplied_by_original_controller_finally",true);
        value.put("cleanup_known",null);write("partial.json",NativeOrderPreviewManual.json(value));requireMembership();
    }
    private void write(String leaf,byte[] bytes)throws Exception{
        need(!written.contains(leaf)&&bytes!=null&&bytes.length>0&&bytes.length<=16*1024*1024,"bounded new fixture artifact required");
        File path=new File(directory,leaf);MobiMindPrivateFiles.writeNew(path,bytes);
        MobiMindPrivateFiles.Read actual=MobiMindPrivateFiles.read(path,16*1024*1024,true);
        need(Arrays.equals(bytes,actual.bytes),"fixture artifact readback differs");actual.unchangedPath();
        originals.put(leaf,actual);written.add(leaf);
    }
    private void requireMembership()throws Exception{
        requireDirectory(directory);String[] actual=directory.list();need(actual!=null,"fixture directory unreadable");
        Set<String> names=new TreeSet<String>(Arrays.asList(actual));
        Set<String> expected=new TreeSet<String>(written);
        if(names.contains("request.json"))expected.add("request.json");
        if(names.contains("request-published.json"))expected.add("request-published.json");
        need(names.equals(expected)&&(!names.contains("request-published.json")||names.contains("request.json")),
                "unexpected or incomplete fixture directory member");
        for(MobiMindPrivateFiles.Read original:originals.values())original.unchangedPath();
    }
    private static void requireDirectory(File directory)throws Exception{
        need(directory.getAbsoluteFile().equals(directory.getCanonicalFile()),"canonical task directory required");
        StructStat stat=Os.lstat(directory.getPath());
        need(OsConstants.S_ISDIR(stat.st_mode)&&stat.st_uid==android.os.Process.myUid()&&(stat.st_mode&0777)==0700,
                "private same-UID directory required");
    }
    private static NativeOrderPreviewManual.Artifact artifact(String leaf,byte[] raw){
        return new NativeOrderPreviewManual.Artifact(leaf,raw.length,NativeOrderPreviewManual.sha256(raw));
    }
    private static String strictUtf8(byte[] raw)throws Exception{
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(raw)).toString();
    }
    private static void requirePng(byte[] bytes,int width,int height){
        byte[] magic={(byte)137,80,78,71,13,10,26,10};
        need(bytes.length>=33&&Arrays.equals(magic,Arrays.copyOfRange(bytes,0,8))
                &&bytes[12]=='I'&&bytes[13]=='H'&&bytes[14]=='D'&&bytes[15]=='R'
                &&java.nio.ByteBuffer.wrap(bytes,16,4).getInt()==width
                &&java.nio.ByteBuffer.wrap(bytes,20,4).getInt()==height,"actual complete-size PNG header required");
    }
    private static void need(boolean value,String reason){NativeOrderPreviewManual.need(value,reason);}
}
