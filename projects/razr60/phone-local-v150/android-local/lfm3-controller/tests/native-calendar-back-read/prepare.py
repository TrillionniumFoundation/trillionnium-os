"""Narrow test-only bridge. Production members are inserted verbatim.
Existing 132 cases remain intact. Synthetic SDK/observer delivery never claims Phone proof."""
from pathlib import Path
import hashlib,json
PKG=Path('src/org/trillionnium/hepta/local')
HERE=Path(__file__).resolve().parent

def need(b,why):
    if not b:raise RuntimeError(why)
def change(s,before,after,edits,name):
    need(s.count(before)==1,'unique test port: '+name)
    edits.append(dict(name=name,before=before,after=after))
    return s.replace(before,after,1)

def extend_other_generated(source,out,extractor,common):
    controller=(source/PKG/'LocalTaskController.java').read_text()
    added=extractor.body(controller,'    private static java.util.Map<String,Object> nativeCalendarBackExecution(')
    original=extractor.body(controller,'    private static java.util.Map<String,Object> nativeQueryExecution(')
    records=[]
    for p in sorted((out/'generated').rglob('*.java')):
        t=p.read_text()
        if 'calendarBackAwait(' not in t:continue
        if added in t:continue
        need(t.count(original)==1,'real projection in generated await fixture: '+str(p))
        result=t.replace(original,original+'\n'+added,1)
        need(result.replace('\n'+added,'',1)==t,'additional real helper inverse')
        added_import=False
        if 'import org.json.JSONArray;' not in result and 'import org.json.*;' not in result:
            need(result.count('import org.json.JSONObject;')==1,'known actual JSON import port')
            result=result.replace('import org.json.JSONObject;','import org.json.JSONObject;\nimport org.json.JSONArray;',1);added_import=True
        p.write_text(result)
        records.append(dict(added_json_array_import=added_import,path=str(p),before_sha256=common.sha(t.encode()),after_sha256=common.sha(result.encode()),
            helper_sha256=common.sha(added.encode()),helper_verbatim=True))
    return records

def extend_template(source,text,extractor,controller,out,common):
    original=text;edits=[]
    def replace(b,a,name):
        nonlocal text
        text=change(text,b,a,edits,name)
    replace('NativeAppSession.PostEffectReadPermit postEffectPermit;',
            'NativeAppSession.PostActionReadAccess postEffectPermit;','generic private request type')
    replace('NativeAppSession.PostEffectReadPermit permit,\n                String id,Object authorization',
            'NativeAppSession.PostActionReadAccess permit,\n                String id,Object authorization','generic observer private type')
    replace('            final org.trillionnium.hepta.background.WindowOwnership profileWindow=null; // Legacy user0 fixture; no profile proof producer.',
            '            org.trillionnium.hepta.background.WindowOwnership profileWindow; // Explicit host profile IO; actual AX producer is separately exercised.',
            'profile identity carrier only')
    proof_anchor=extractor.body((source/PKG/'HeptaAccessibilityService.java').read_text(),
        '    static final class PostEffectObservationRetryProof {')
    port='''
        /** Test-only opaque producer carrier. The real Service proof and Controller
         * consumer execute here; actual AX worker/window/drain are a separate gate. */
        private static final class PostEffectSamplingRetry {
            final Map<String,Object> axReadIdentity;
            PostEffectSamplingRetry(boolean typed){axReadIdentity=typed?Collections.<String,Object>singletonMap("synthetic_sdk_port",true):null;}
        }
'''
    replace(proof_anchor,port+proof_anchor,'explicit synthetic producer type')
    helper=extractor.body(controller,'    private static java.util.Map<String,Object> nativeCalendarBackExecution(')
    projection=extractor.body(controller,'    private static java.util.Map<String,Object> nativeQueryExecution(')
    replace(projection,projection+'\n'+helper,'actual BACK callback projection')
    replace('    boolean postFixture,failPostOutcome;','    boolean postFixture,failPostOutcome;','unchanged declaration accounting')
    replace('        boolean actionClaim=true,actionDrain=true,actionCallbackCurrent=true,actionAccepted=true;',
        '        boolean actionClaim=true,actionDrain=true,actionCallbackCurrent=true,actionAccepted=true;\n'
        '        String backFault,backReadFault;int pendingReadWorks;','BACK-only endpoint fault controls')
    replace('            performCalls++;lastGuard=guard;',
        '            if(host.backFixture!=null){performBack(id,observed,action,authorization,run,deadline,guard,cancellation,callback);return;}\n'
        '            performCalls++;lastGuard=guard;','independent BACK endpoint')
    back_perform='''
        void performBack(String id,PhoneObservation observed,ActionDecision action,TaskAuthorization.Gate authorization,
                String run,long deadline,NativeAppSession.ActionGuard guard,Cancellation cancellation,ActionCallback callback)throws Exception{
            performCalls++;lastGuard=guard;
            yes(id.equals(host.currentTaskId)&&observed==host.before&&action==host.backFixture.action
                    &&authorization==host.authorization&&run.equals(host.backFixture.run)&&guard==null,
                    "BACK endpoint receives exact original identity with no OPEN guard");
            long queued=SystemClock.elapsedRealtime();
            yes(deadline==queued+8000L,"same original action deadline");
            executionState=new ActionExecutionState(NativeActionBridgeHost.id("back-operation:"+id),id,run,observed.id,
                authorization.authorization.sha256,observed.nativeFrame.windowId,observed.nativeFrame.displayId,
                observed.nativeFrame.generation,queued,deadline,()->SystemClock.elapsedRealtime());
            ActionExecutionState.Slot slot=new ActionExecutionState.Slot();
            yes(slot.acquire(executionState),"actual serial state slot");pendingAction=true;
            org.trillionnium.hepta.background.WindowOwnership window=host.backFixture.window(observed.nativeFrame.windowId,queued+454);
            clock(queued+586);executionState.enterEffect(false,true);syntheticEffectEntries++;
            clock(queued+778);
            if(!"not-returned".equals(backFault))executionState.effectReturned(Boolean.valueOf(actionAccepted));
            if(actionDrain){clock(queued+1132);executionState.drained();slot.release(executionState);pendingAction=slot.pending();
                executionState.publish(false,actionCallbackCurrent);}
            Map<String,Object> raw=executionState.evidence();
            if(window!=null)raw.put("live_profile_before_effect",window.evidence());
            JSONObject wire=new JSONObject(NativeQueryReservationHostTest.serviceJson(raw).toString());
            if("missing-profile".equals(backFault))wire.remove("live_profile_before_effect");
            if("bad-profile".equals(backFault))wire.getJSONObject("live_profile_before_effect").put("full_uid",1010999);
            if("wrong-operation".equals(backFault))wire.put("operation_id","invalid-operation");
            JSONArray phases=wire.getJSONArray("phases");
            if("duplicate-phase".equals(backFault))phases.put(new JSONObject().put("phase","effect_returned").put("elapsed_ms",queued+778));
            if("missing-return-phase".equals(backFault)){
                JSONArray changed=new JSONArray();for(int i=0;i<phases.length();i++)if(!"effect_returned".equals(phases.getJSONObject(i).getString("phase")))changed.put(phases.get(i));
                wire.put("phases",changed);
            }
            if("phases-extra-key".equals(backFault))phases.getJSONObject(0).put("unknown",true);
            if(beforeActionCallback!=null)beforeActionCallback.run();
            callback.onResult(new ActionOutcome(actionAccepted,true,false,wire));
        }
'''
    replace('        PhoneObservation postFresh()throws Exception{',back_perform+'\n        PhoneObservation postFresh()throws Exception{\n'
        '            if(host.backFixture!=null){latest=new PhoneObservation(host.backFixture.frame(false,SystemClock.elapsedRealtime()-10L,3008));return latest;}',
        'BACK actual state endpoint and fresh complete AX construction')
    replace('            long started=SystemClock.elapsedRealtime();\n            yes(deadline<=taskDeadline',
        '            long started=SystemClock.elapsedRealtime();\n            if(host.backFixture!=null)yes(pendingReadWorks==0,"old read worker is drained before submission");\n'
        '            yes(deadline<=taskDeadline','explicit serial read IO boundary')
    replace('                postCalls++;host.events.add("post_effect_read_submitted");firstDeadline=deadline;firstCancellation=cancel;firstCallback=callback;',
        '                postCalls++;host.events.add("post_effect_read_submitted");firstDeadline=deadline;firstCancellation=cancel;firstCallback=callback;\n'
        '                if(host.backFixture!=null)pendingReadWorks=1;',
        'first read active IO')
    replace('                ObservationRequest request=new ObservationRequest();\n                request.taskId="task".equals(proofMutation)?NativeActionBridgeHost.id("foreign-post-task"):id;',
        '                if(host.backFixture!=null){\n'
        '                    if(!"worker-live".equals(backReadFault))pendingReadWorks=0;\n'
        '                    if("ordinary".equals(backReadFault)||"identity".equals(backReadFault)||"hard".equals(backReadFault)||"worker-live".equals(backReadFault)){\n'
        '                        callback.onError("explicit unqualified first AX read");return;}\n'
        '                }\n                ObservationRequest request=new ObservationRequest();\n                request.taskId="task".equals(proofMutation)?NativeActionBridgeHost.id("foreign-post-task"):id;','explicit failure delivery never grants on hard/unknown/undrained')
    replace('request.postEffectNativeTask="native".equals(proofMutation)?host.fixture.session:nativeTask;',
        'request.postEffectNativeTask="native".equals(proofMutation)?(host.backFixture==null?host.fixture.session:null):nativeTask;',
        'foreign Session mutation retains refusal')
    replace('                request.postEffectIdentity.displayId=frame.displayId;',
        '                request.postEffectIdentity.displayId=frame.displayId;\n'
        '                request.postEffectIdentity.profileWindow=frame.profileWindow;',
        'complete profile proof diagnostic carrier')
    replace('                postIssued=new PostEffectObservationRetryProof("service".equals(proofMutation)?new Object():this,request,SystemClock.elapsedRealtime());',
        '                if(host.backFixture==null)postIssued=new PostEffectObservationRetryProof("service".equals(proofMutation)?new Object():this,request,SystemClock.elapsedRealtime());\n'
        '                else postIssued=new PostEffectObservationRetryProof(this,request,SystemClock.elapsedRealtime(),request.postEffectIdentity,\n'
        '                    "native_ax_read_transient_after_entered_action",new PostEffectSamplingRetry(!"sampling".equals(backReadFault)),\n'
        '                    Collections.<String,Object>singletonMap("synthetic_sdk_port",true));',
        'actual private constructor with explicitly synthetic producer handoff')
    replace('postActionOutcome=awaitAction(currentTaskId,before,fixture.action,null,null,authorization,fixture.run,SystemClock.elapsedRealtime()+480000);',
        'postActionOutcome=awaitAction(currentTaskId,before,postAction(),null,null,authorization,postRun(),SystemClock.elapsedRealtime()+480000);',
        'common real await uses selected fixture action')
    replace('activeNativeTask.modelActionOutcome(fixture.action,fixture.run,postActionOutcome.accepted,postActionOutcome.dispatched,',
        'activeNativeTask.modelActionOutcome(postAction(),postRun(),postActionOutcome.accepted,postActionOutcome.dispatched,',
        'common real durable outcome uses selected fixture action')
    replace('return awaitPostEffectNativeObservation(currentTaskId,directory,authorization,deadline,fixture.action,fixture.run,before);',
        'return awaitPostEffectNativeObservation(currentTaskId,directory,authorization,deadline,postAction(),postRun(),before);',
        'common real read uses selected fixture action')
    fragment=(HERE/'CalendarBackCases.fragment').read_text()
    replace('    public static void main(String[] args)throws Exception{',fragment+'\n    public static void main(String[] args)throws Exception{','new BACK cases only')
    replace('Files.createDirectory(outputRoot);cases();','Files.createDirectory(outputRoot);cases();backCases();','old full cases then new cases')
    inverse=text
    for e in reversed(edits):
        need(inverse.count(e['after'])==1,'test inverse unique: '+e['name'])
        inverse=inverse.replace(e['after'],e['before'],1)
    need(inverse==original,'whole original template inverse')
    common.save(out/'BACK-TEST-EXTRACTION.json',dict(schema='hepta.calendar-back-read-test-extraction.v1',
        old_template_sha256=common.sha(original.encode()),compiled_template_sha256=common.sha(text.encode()),
        whole_inverse=True,changes=edits,actual_back_helper_sha256=common.sha(helper.encode()),
        actual_session=True,actual_controller_await_finally=True,actual_ActionExecutionState=True,actual_fsync=True,
        actual_service_proof=True,service_producer_handoff_is_explicit_host_IO=True,
        full_AX_producer_is_separate_gate=True,phone_operations=0,business_completion_verified=False))
    return text
