#!/usr/bin/env python3
"""Run actual Service observation bodies and form helper through synthetic Android IO.
No phone, action, model or business completion is executed or claimed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import runpy
import sys
sys.dont_write_bytecode=True
PKG=Path('src/org/trillionnium/hepta/local')
HERE=Path(__file__).resolve().parent
TEST=Path('tests/native-ctrip-form-observation')
# Historical protected pins remain exact; reviewed AX and sampling successors use strict proof-copy inverses.
BASELINE_BODY_SHA256={'    private static NativeActionSnapshotCheck.Snapshot nativeActionSnapshot(Graph graph,NativeAppSession.ActionGuard guard){': '3c333501044116981cd0522e5f97a693228553c76a8bdd6471f1fce3dd94fae5', '    private void requireNativeActionGuard(String task,PhoneObservation frame,ActionDecision action,ActionWork work)throws Exception{': 'a3a85b9845dd2c954adafa9769e9b6f183ce476916b5dd80b05cbc629ed7261b', '    private NativeResampleSeed nativeSavedGraphSeed(ObservationRequest request,CaptureIdentity identity,Graph graph,': '3f36b20a4e45aff418c90822bf347a76a91c795638a054696eaec6854f11e993', '    private void acceptSample(final ObservationRequest request,Graph graph,String error,long events,long unknownEvents){': '9a0816eff581f9d03e15dcce23c7f5e04896dc47293273bb856ff5470b834218', '    private void sampleObservation(final ObservationRequest request){': '1ce51a7e36ba0af59b43605c09b7066d20476c56cc587f9bdf8f745e298178ec', '    private void acceptScreenshot(ObservationRequest request,ObservationProduct product,boolean retry,String error){': 'd86064ad2a7361af1e3be8e1b601b542d3faa73795b849c742b86397a76d710f', '    private FrozenObservationWindow readFrozenObservationWindow(ObservationRequest request,CaptureIdentity identity){': '9c0d88bffdd13ad27dc78046b3fbf30c1e9665d5e84b09493a726cda38f5198c', '    private boolean nativeObservationRecheckAllowed(ObservationRequest request,Graph graph){': '047494d32858affc85c7c45d21b6740b942f20465dcffe0d19476b65d11806ec', '    private static void requireSameProfileOwner(': 'd7e53c1e6adb723a2f33ee7cb58f426dd7cdf7b35267eafa81f3cb5ce1baf8be'}
BASELINE_FILES={
 'NativeActionSnapshotCheck.java':'d4736f666443118a80340c74bd940009c0e30cf1d3e817e961bd2334f233e500',
 'ObservationStabilityGate.java':'426100c4f31e825c9e0f0c556c8c89d23aa45a40593978cb5fd8d5946a4beeb8',
 'NativeCtripFlightPage.java':'fcce736df40dfc29fe8b2b31e6c37d58e9e820ca075727dd6fd4a05aea1ae3a7',
 'NativeAppGoal.java':'c266f1e3e6ca3d86ad2e8f94c78a4263138822e004b5eab64dafdda5fcb653d5',
}
PORT='''    /** Explicit fail-only port: legacy scheduling fixtures cannot admit scoped form pairs.
     * The dedicated form-observation gate substitutes both actual production helpers. */
    private Map<String,Object> nativeCtripFormPair(ObservationRequest request,CaptureIdentity identity,Graph after){return null;}
'''
# Exact reviewed AX differences are reversed only in proof copies.
# Actual production extraction, current typed guards and legacy cases remain intact.
# Search has a separate actual producer gate. These exact reversals are only
# historical proof copies; current production methods still compile below.
SEARCH_UNBOUND_PORTS='    // No native search Session is bound in these original observer fixtures.\n    // Unexpected binding is refused; these ports cannot create planning or an Offer.\n    private final Object nativeSearchSession=null,activeNativeSearchObservation=null;\n    private void noteNativeSearchEvent(int display,int window,String pkg,boolean content,boolean typed){\n        if(nativeSearchSession!=null||activeNativeSearchObservation!=null)\n            throw new AssertionError("legacy observer cannot route a bound native search event");\n    }\n    private boolean nativeSearchAllowsLegacyObservation(String taskId){\n        return nativeSearchSession==null&&activeNativeSearchObservation==null;\n    }\n'
REVIEWED_SEARCH_NAS_INVERSE=[
    ('            out.facts.put("literal_departure_date",date.text);out.facts.put("year_inferred",false);\n        }else{\n            for(Node n:s.nodes.values())if(n.visible())need(!b(n.v,"editable")&&!"加入购物车".equals(n.text)&&!"立即购买".equals(n.text),"fresh home only, no input/detail phase");\n',
     '            out.facts.put("literal_departure_date",date.text);out.facts.put("year_inferred",false);\n        }else return searchScope(in.purpose,in.path,s);\n        return out;\n    }\n    /** Shared pure SEARCH structure/hint contract. Legacy compare still uses its original full protected roots. */\n    private static Scope searchScope(String purpose,String targetPath,Snapshot s){\n        Scope out=new Scope();\n            for(Node n:s.nodes.values())if(n.visible())need(!b(n.v,"editable")&&!"加入购物车".equals(n.text)&&!"立即购买".equals(n.text),"fresh home only, no input/detail phase");\n'),
    ('                    &&icon.bounds.get(3)<home.bounds.get(1)&&entry.bounds.get(3)<home.bounds.get(1),"same actual selected home/search");\n            need("android.widget.ViewSwitcher".equals(entry.cls)&&entry.click()&&(SEARCH_ICON.equals(in.purpose)?icon.path.equals(in.path):entry.path.equals(in.path))\n                    &&entry.text.isEmpty()&&entry.desc.isEmpty()&&entry.label!=null&&!entry.label.isEmpty()\n',
     '                    &&icon.bounds.get(3)<home.bounds.get(1)&&entry.bounds.get(3)<home.bounds.get(1),"same actual selected home/search");\n            need("android.widget.ViewSwitcher".equals(entry.cls)&&entry.click()&&(SEARCH_ICON.equals(purpose)?icon.path.equals(targetPath):entry.path.equals(targetPath))\n                    &&entry.text.isEmpty()&&entry.desc.isEmpty()&&entry.label!=null&&!entry.label.isEmpty()\n'),
    ('                    &&icon.bounds.get(0)-entry.bounds.get(2)<=Math.max(entry.bounds.get(3)-entry.bounds.get(1),icon.bounds.get(3)-icon.bounds.get(1))\n                    &&Math.min(entry.bounds.get(3),icon.bounds.get(3))>Math.max(entry.bounds.get(1),icon.bounds.get(1)),SEARCH_ICON.equals(in.purpose)?"actual native stable search icon":"actual native query entry, not adjacent search icon");\n            need(container.path.equals(pager.path)||"android.widget.RelativeLayout".equals(container.cls)\n',
     '                    &&icon.bounds.get(0)-entry.bounds.get(2)<=Math.max(entry.bounds.get(3)-entry.bounds.get(1),icon.bounds.get(3)-icon.bounds.get(1))\n                    &&Math.min(entry.bounds.get(3),icon.bounds.get(3))>Math.max(entry.bounds.get(1),icon.bounds.get(1)),SEARCH_ICON.equals(purpose)?"actual native stable search icon":"actual native query entry, not adjacent search icon");\n            need(container.path.equals(pager.path)||"android.widget.RelativeLayout".equals(container.cls)\n'),
    ('            out.facts.put("home",home.v);\n            if(icon.path.equals(in.path)||searchEntryTarget(in,s)){\n                need(icon.text.isEmpty()&&"搜索".equals(icon.label)&&icon.children==0,"exact stable leaf search icon");\n',
     '            out.facts.put("home",home.v);\n            if(icon.path.equals(targetPath)||SEARCH.equals(purpose)){\n                need(icon.text.isEmpty()&&"搜索".equals(icon.label)&&icon.children==0,"exact stable leaf search icon");\n'),
    ('                out.facts.put("entry_hint_term",stableSearchIconTermFacts(term));\n                out.facts.put("navigation_target",searchEntryTarget(in,s)?"same_resource_query_entry":"stable_search_icon_candidate");\n            }else{\n',
     '                out.facts.put("entry_hint_term",stableSearchIconTermFacts(term));\n                out.facts.put("navigation_target",SEARCH.equals(purpose)?"same_resource_query_entry":"stable_search_icon_candidate");\n            }else{\n'),
    ('            out.facts.put("adjacent_search_icon",icon.v);out.protect(s,pager.path);out.protect(s,parent(home.path));\n        }return out;\n    }\n    private static Map<String,Object> roleFacts(Intent in,Snapshot s){Map<String,Object> out=new TreeMap<String,Object>();\n        Set<String> xiaomi=keys("首页,搜索,加入购物车,立即购买,综合,销量,价格,Xiaomi路由器AX3000T,xiaomi路由器ax3000t");\n',
     '            out.facts.put("adjacent_search_icon",icon.v);out.protect(s,pager.path);out.protect(s,parent(home.path));\n        return out;\n    }\n    private static Map<String,Object> roleFacts(Intent in,Snapshot s){return roleFacts(in.purpose,in.pkg,in.path,s);}\n    private static Map<String,Object> roleFacts(String purpose,String pkg,String targetPath,Snapshot s){Map<String,Object> out=new TreeMap<String,Object>();\n        Set<String> xiaomi=keys("首页,搜索,加入购物车,立即购买,综合,销量,价格,Xiaomi路由器AX3000T,xiaomi路由器ax3000t");\n'),
    ('            boolean relevant;\n            if(CTRIP.equals(in.pkg)){String shortId=n.view.startsWith(CP)?n.view.substring(CP.length()):"";\n                relevant=FORM_IDS.contains(shortId)||Arrays.asList(TILE_IDS).contains(shortId)||"calendar_month_title_left_tv".equals(shortId)||"calendar_list".equals(shortId)||ROLES.contains(n.view)||ROLES.contains(n.desc)||"机票".equals(n.text);\n            }else relevant=n.view.equals("com.xiaomi.shop.plugin.homepage:id/main_view_nav_bar_text")||n.view.equals("com.xiaomi.shop.plugin.homepage:id/searchIcon")||n.view.equals("com.xiaomi.shop.plugin.homepage:id/switcher")||xiaomi.contains(n.text)||n.text.startsWith("Xiaomi路由器")||"android.widget.EditText".equals(n.cls)||b(n.v,"editable");\n            if(relevant)out.put(n.path,(searchIconTarget(in,s)||searchEntryTarget(in,s))&&"com.xiaomi.shop.plugin.homepage:id/switcher".equals(n.view)\n                    ?stableHintFacts(n,null):n.v);\n        }return out;\n    }\n',
     '            boolean relevant;\n            if(CTRIP.equals(pkg)){String shortId=n.view.startsWith(CP)?n.view.substring(CP.length()):"";\n                relevant=FORM_IDS.contains(shortId)||Arrays.asList(TILE_IDS).contains(shortId)||"calendar_month_title_left_tv".equals(shortId)||"calendar_list".equals(shortId)||ROLES.contains(n.view)||ROLES.contains(n.desc)||"机票".equals(n.text);\n            }else relevant=n.view.equals("com.xiaomi.shop.plugin.homepage:id/main_view_nav_bar_text")||n.view.equals("com.xiaomi.shop.plugin.homepage:id/searchIcon")||n.view.equals("com.xiaomi.shop.plugin.homepage:id/switcher")||xiaomi.contains(n.text)||n.text.startsWith("Xiaomi路由器")||"android.widget.EditText".equals(n.cls)||b(n.v,"editable");\n            if(relevant)out.put(n.path,((SEARCH_ICON.equals(purpose)||SEARCH.equals(purpose))&&XIAOMI.equals(pkg))&&"com.xiaomi.shop.plugin.homepage:id/switcher".equals(n.view)\n                    ?stableHintFacts(n,null):n.v);\n        }return out;\n    }\n    /** Planning-role facts derived directly from a complete actual census. No old Intent/Frame is fabricated. */\n    static Map<String,Object> searchPlanningRoleFacts(Snapshot snapshot){\n        need(snapshot!=null&&XIAOMI.equals(s(snapshot.env,"package")),"native search planning package");\n        Node entry=oneId(snapshot,"com.xiaomi.shop.plugin.homepage:id/switcher");\n        Scope role=searchScope(SEARCH,entry.path,snapshot);\n        Node icon=oneId(snapshot,"com.xiaomi.shop.plugin.homepage:id/searchIcon");\n        Node home=oneIdText(snapshot,"com.xiaomi.shop.plugin.homepage:id/main_view_nav_bar_text","首页");\n        Map<String,Object> out=new TreeMap<String,Object>();\n        out.put("target_path",entry.path);out.put("hint_path",entry.path+"/0");out.put("term_path",entry.path+"/0/0");\n        out.put("icon_path",icon.path);out.put("home_path",home.path);out.put("navbar_path",parent(home.path));\n        out.put("facts",role.facts);out.put("global_role_facts",roleFacts(SEARCH,XIAOMI,entry.path,snapshot));\n        return freeze(out);\n    }\n'),
]
AX_PORTS='    // Legacy scheduling fakes never bind a text-native model. The AX gate substitutes\n    // the actual production mode admission, worker and publisher at these three ports.\n    private void bindNativeAxObservationRequest(ObservationRequest request){}\n    private boolean nativeTextObservationAllowed(ObservationRequest request,Graph graph){return false;}\n    private void captureNativeAxObservation(ObservationRequest request){throw new AssertionError("legacy fixture cannot enter AX capture");}\n'
REVIEWED_AX_BODY_INVERSE={'    private void requireNativeActionGuard(String task,PhoneObservation frame,ActionDecision action,ActionWork work)throws Exception{': {'sha256': '4ff4399af8965f25601a0c494a97d5101d41d4f5031dc4413dc57cdb2baa5bab',
                                                                                                                                          'current': '||!original.sameCapture(frame.capture,frame.screenshotSha256)||',
                                                                                                                                          'legacy': '||!original.screenshotSha.equals(frame.screenshotSha256)||'},
 '    private void acceptSample(final ObservationRequest request,Graph graph,String error,long events,long unknownEvents){': {'sha256': '9efece9a8d9c103aa6c794911a6eb01cdbdb949567406cbfb435d1341da3285a',
                                                                                                                              'current': 'long '
                                                                                                                                         'screenshotDelay=nativeTextObservationAllowed(request,graph)?0:Math.max(0,400-(now-lastScreenshotAt));',
                                                                                                                              'legacy': 'long '
                                                                                                                                        'screenshotDelay=Math.max(0,400-(now-lastScreenshotAt));'}}
AX_REJECTION_PREFIX='    static Map<String,Object> rejectionEvidence(Intent in,Snapshot old,Snapshot fresh,long comparedAt,\n            String operation,String originalScreen,String originalFrameRecord,String reason){\n        return rejectionEvidence(in,old,fresh,comparedAt,operation,originalScreen,originalFrameRecord,reason,null);\n    }\n    static Map<String,Object> rejectionEvidence(Intent in,Snapshot old,Snapshot fresh,long comparedAt,\n            String operation,String originalScreen,String originalFrameRecord,String reason,ObservationCaptureEvidence capture){\n        need(in!=null&&old!=null&&fresh!=null&&id(operation)&&sha(originalFrameRecord),\n                "same-operation original frame diagnostic binding required");\n        if(capture==null)need(sha(originalScreen),"same-operation original pixel diagnostic binding required");\n        else{\n            need(ObservationCaptureEvidence.NATIVE_AX.equals(capture.kind)&&sha(capture.receiptSha256)&&originalScreen==null,\n                    "same-operation typed AX diagnostic binding required");\n            Map<String,Object> bound=new TreeMap<String,Object>();\n            bound.put("task_id",old.env.get("task_id"));bound.put("owner_sha256",old.env.get("owner_sha256"));\n            bound.put("execution_target_sha256",old.env.get("target_sha256"));\n            bound.put("task_authorization_sha256",old.env.get("authorization_sha256"));\n            bound.put("actual_selection_sha256",old.env.get("selection_sha256"));\n            bound.put("native_goal_sha256",old.env.get("goal_sha256"));bound.put("observation_id",old.env.get("origin_observation_id"));\n            for(String k:Arrays.asList("package","background_generation","display_id","window_id","rotation","width","height"))\n                bound.put(k,old.env.get(k));\n            List<Integer> bounds=rect(old.env.get("root_bounds"));\n            bound.put("left",bounds.get(0));bound.put("top",bounds.get(1));bound.put("right",bounds.get(2));bound.put("bottom",bounds.get(3));\n            // The original census read clock and PhoneObservation capture clock are distinct.\n            bound.put("original_census_captured_elapsed_ms",old.env.get("captured_elapsed_ms"));\n            Map<String,Object> profile=null;\n            if(old.env.containsKey("profile_target_sha256")){\n                profile=new TreeMap<String,Object>();for(String k:PROFILE_IDENTITY)profile.put(k,old.env.get(k));\n            }\n            bound.put("profile_action_identity",profile);capture.requireBinding(bound);\n        }\n'
LEGACY_REJECTION_PREFIX='    static Map<String,Object> rejectionEvidence(Intent in,Snapshot old,Snapshot fresh,long comparedAt,\n            String operation,String originalScreen,String originalFrameRecord,String reason){\n        need(in!=null&&old!=null&&fresh!=null&&id(operation)&&sha(originalScreen)&&sha(originalFrameRecord),\n                "same-operation original frame diagnostic binding required");\n'
AX_REJECTION_METADATA='        out.put("original_capture_kind",capture==null?ObservationCaptureEvidence.PIXELS:ObservationCaptureEvidence.NATIVE_AX);\n        out.put("original_screenshot_observed",capture==null);\n        if(capture!=null)out.put("original_capture",capture.evidence());\n'
JAVA=['NativeXiaomiSearchInputObservation.java', 'ObservationCaptureEvidence.java', 'ObservationDiagnostics.java','ObservationStabilityGate.java','ActionExecutionState.java','TaskCancellationQueue.java',
      'ObservedWindowMetadata.java','ObservationState.java','ImeVisibility.java','NativeActionSnapshotCheck.java',
      'ObservedChildText.java','ObservedTargetLabels.java','ObservedScrollActions.java','ObservedImeEnter.java',
      'NativeAppGoal.java','NativeCtripFormObservation.java']
READ=['HeptaAccessibilityService.java','PhoneObservation.java','NativeAppEvidence.java','NativeCtripFlightPage.java']
PROFILE=Path('src/org/trillionnium/hepta/background')
PROFILE_NAMES=['ProfileIdentity.java','ProfileTarget.java','WindowOwnership.java']
def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
def once(text,old,new):
    if text.count(old)!=1:raise RuntimeError('nonunique fixture boundary: '+old[:100])
    return text.replace(old,new,1)
# Exact reviewed post-effect sampling changes are reversed only in method proof copies.
# acceptSample then follows the existing AX inverse; compiled parts remain current.
REVIEWED_SAMPLING_BODY_INVERSE={
 '    private void acceptSample(final ObservationRequest request,Graph graph,String error,long events,long unknownEvents){': {
  'sha256': '8982b1a2fe3d36a8fb6881ec7db393e37082b5b503f4cebfe2eff4e68271a0c7',
  'predecessor_sha256': '9efece9a8d9c103aa6c794911a6eb01cdbdb949567406cbfb435d1341da3285a',
  'inverse': [
   ('                if(!postEffectObservationOwner(request))request.rejectPostEffectIdentity();',
    '                if(!postEffectObservationOwner(request))request.postEffectIdentityRejected=true;'),
   ('                PostEffectSamplingRetry sampling=result==ObservationStabilityGate.Result.EXPIRED\n                        ?postEffectSamplingCandidate(request,graph,nativeRecheck,now):null;\n                if(sampling!=null){\n                    graph.close();graph=null;failPostEffectObservationAfterReadDrain(request,reason,sampling);\n                }else if(result==ObservationStabilityGate.Result.EXPIRED&&nativeReadRetryCandidate(request,graph)){',
    '                if(result==ObservationStabilityGate.Result.EXPIRED&&nativeReadRetryCandidate(request,graph)){'),
   ('            rememberPostEffectSamplingFrame(request,graph,nativeRecheck,now);\n',
    ''),
  ]},
 '    private void sampleObservation(final ObservationRequest request){': {
  'sha256': '6f0a1bb847e442b84973e4ecfb20d1fc67d08136cc212fa69ec3507cd28267e6',
  'predecessor_sha256': '1ce51a7e36ba0af59b43605c09b7066d20476c56cc587f9bdf8f745e298178ec',
  'inverse': [
   ('                catch(StaleObservation busy){request.note(ObservationDiagnostics.Event.SAMPLE_STALE_ROOT,busy.backgroundChildUnavailable);}',
    '                catch(StaleObservation busy){request.note(ObservationDiagnostics.Event.SAMPLE_STALE_ROOT);}'),
  ]},
}
# Strict proof copy only. Compilation always consumes the actual source Gate.
FORM_SAMPLING_GATE_CURRENT = '2abe6a4074be6c75514755c741d10792e78e80d914e7ae063e1f43ce470d0992'
FORM_SAMPLING_GATE_PREDECESSOR = '426100c4f31e825c9e0f0c556c8c89d23aa45a40593978cb5fd8d5946a4beeb8'
FORM_SAMPLING_GATE_MEMBER = b'    /** Explicit classified pair over two REAL keys. The caller must have compared complete values.\n     * This timing helper grants no action or graph authority and never substitutes a digest. */\n    Result sampleClassifiedPair(long now,FrameKey expectedPrevious,long expectedAt,FrameKey actual,boolean allowed){\n        if(retired||!allowed)return Result.CANCELLED;\n        if(!requestAlive(now,true)||now>=settleDeadline)return Result.EXPIRED;\n        boolean sameWindow=expectedPrevious!=null&&actual!=null&&!expectedPrevious.truncated&&!actual.truncated\n                &&expectedPrevious.packageName.equals(actual.packageName)&&expectedPrevious.windowId==actual.windowId\n                &&expectedPrevious.rotation==actual.rotation&&expectedPrevious.left==actual.left&&expectedPrevious.top==actual.top\n                &&expectedPrevious.right==actual.right&&expectedPrevious.bottom==actual.bottom;\n        if(sameWindow&&previous!=null&&previous.equals(expectedPrevious)&&previousAt==expectedAt\n                &&now>=expectedAt&&now-expectedAt>=SAMPLE_GAP_MS){\n            previous=actual;previousAt=now;return Result.READY;\n        }\n        return Result.WAIT;\n    }\n'

def gate_predecessor(raw):
    actual=hashlib.sha256(raw).hexdigest()
    if actual==FORM_SAMPLING_GATE_PREDECESSOR:return raw
    if actual!=FORM_SAMPLING_GATE_CURRENT:
        raise RuntimeError('unreviewed complete FORM sampling Gate source')
    if raw.count(FORM_SAMPLING_GATE_MEMBER)!=1:
        raise RuntimeError('unique complete classified-pair Gate member required')
    prior=raw.replace(FORM_SAMPLING_GATE_MEMBER,b'',1)
    if hashlib.sha256(prior).hexdigest()!=FORM_SAMPLING_GATE_PREDECESSOR:
        raise RuntimeError('classified-pair Gate must reverse to the complete original source')
    return prior

# Exact current method -> complete 0a8 predecessor for the existing historical
# body proof chain. The real full observation section is extracted above/below
# unchanged; this helper never supplies compiled Java or an execution endpoint.
REVIEWED_COMPLETE_FORM_SAMPLING_BODY_INVERSE = {
    '    private void sampleObservation(final ObservationRequest request){': {
        'current_sha256': '4dda78389010012f907200b4b7c1bbc6d612134edea0cab47912e5f45951cb33',
        'actual_body_anchor': '    private void sampleObservation(final ObservationRequest request){',
        'actual_body_sha256': '4dda78389010012f907200b4b7c1bbc6d612134edea0cab47912e5f45951cb33',
        'predecessor_sha256': '6f0a1bb847e442b84973e4ecfb20d1fc67d08136cc212fa69ec3507cd28267e6',
        'inverse': [
            (
                '        try{observationIo.execute(new Runnable(){public void run(){\n            Graph graph=null;String error=null;final long unknownEvents=request.unknownEvents,events=request.events;\n            CtripFormSampleRead formRead=null;CtripFormSample previous;ObservationEventWatermark formStart;\n            synchronized(request){previous=request.ctripFormSample;formStart=request.eventWatermark();}\n            try{\n                requireObservationWork(request);\n',
                '        try{observationIo.execute(new Runnable(){public void run(){\n            Graph graph=null;String error=null;final long unknownEvents=request.unknownEvents,events=request.events;\n            try{\n                requireObservationWork(request);\n',
            ),
            (
                '                catch(NoActiveWindow busy){request.note(ObservationDiagnostics.Event.SAMPLE_NO_ROOT);}\n                catch(StaleObservation busy){request.note(ObservationDiagnostics.Event.SAMPLE_STALE_ROOT,busy.backgroundChildUnavailable);}\n                // Freeze the real census endpoint before diagnostics or any pure form comparison.\n                final ObservationEventWatermark formEnd;final long formEpoch;\n                synchronized(request){formEnd=request.eventWatermark();formEpoch=request.ctripFormSampleEpoch;}\n                final long formCompletedAt=SystemClock.elapsedRealtime();\n                request.graph("sample_graph",graph);requireObservationWork(request);\n                formRead=readCtripFormSample(request,graph,previous,formStart,formEnd,formCompletedAt,formEpoch);\n            }catch(Exception failure){request.note(ObservationDiagnostics.Event.SAMPLE_ERROR);error="无法读取当前活动窗口："+message(failure);}\n            finally{request.worker(false);observationIoBusy.set(false);}\n            final Graph sampled=graph;final String failure=error;final CtripFormSampleRead sampledForm=formRead;\n            boolean posted=false;\n            try{posted=main.post(new Runnable(){public void run(){acceptSample(request,sampled,failure,events,unknownEvents,sampledForm);}});}\n            finally{if(!posted&&sampled!=null)sampled.close();}\n        }});}catch(RuntimeException unavailable){request.worker(false);observationIoBusy.set(false);failObservation(request,"屏幕观察队列不可用："+message(unavailable));}\n',
                '                catch(NoActiveWindow busy){request.note(ObservationDiagnostics.Event.SAMPLE_NO_ROOT);}\n                catch(StaleObservation busy){request.note(ObservationDiagnostics.Event.SAMPLE_STALE_ROOT,busy.backgroundChildUnavailable);}\n                request.graph("sample_graph",graph);requireObservationWork(request);\n            }catch(Exception failure){request.note(ObservationDiagnostics.Event.SAMPLE_ERROR);error="无法读取当前活动窗口："+message(failure);}\n            finally{request.worker(false);observationIoBusy.set(false);}\n            final Graph sampled=graph;final String failure=error;\n            boolean posted=false;\n            try{posted=main.post(new Runnable(){public void run(){acceptSample(request,sampled,failure,events,unknownEvents);}});}\n            finally{if(!posted&&sampled!=null)sampled.close();}\n        }});}catch(RuntimeException unavailable){request.worker(false);observationIoBusy.set(false);failObservation(request,"屏幕观察队列不可用："+message(unavailable));}\n',
            ),
        ],
    },
    '    private void acceptSample(final ObservationRequest request,Graph graph,String error,long events,long unknownEvents){': {
        'current_sha256': '8520c7c5821ae81eea943c728b6dd9ab4ca72d3d87f2295b808f23a222944102',
        'actual_body_anchor': '    private void acceptSample(final ObservationRequest request,Graph graph,String error,long events,long unknownEvents,CtripFormSampleRead formRead){',
        'actual_body_sha256': '46642366df0dd4ebb11a6f80b2d22641223ad10447153dcfde8e982040598539',
        'predecessor_sha256': '8982b1a2fe3d36a8fb6881ec7db393e37082b5b503f4cebfe2eff4e68271a0c7',
        'inverse': [
            (
                '    private void acceptSample(final ObservationRequest request,Graph graph,String error,long events,long unknownEvents,CtripFormSampleRead formRead){\n        try{\n            if(!observationActive(request))return;\n',
                '    private void acceptSample(final ObservationRequest request,Graph graph,String error,long events,long unknownEvents){\n        try{\n            if(!observationActive(request))return;\n',
            ),
            (
                '                        &&graph.readCompletedElapsedMs>=graph.readStartedElapsedMs;\n                if(!same){\n                    request.resampleSeed=null;request.clearCtripSample("SAMPLE_SEED_RESET");request.gate.resetEvidence();request.nativeSample=false;\n                    if(request.trace!=null)request.trace.reset();nativeSeedDecision(request,"invalidated_before_sample");\n                }else if(!seed.key.equals(frameKey(graph))){\n',
                '                        &&graph.readCompletedElapsedMs>=graph.readStartedElapsedMs;\n                if(!same){\n                    request.resampleSeed=null;request.gate.resetEvidence();request.nativeSample=false;\n                    if(request.trace!=null)request.trace.reset();nativeSeedDecision(request,"invalidated_before_sample");\n                }else if(!seed.key.equals(frameKey(graph))){\n',
            ),
            (
                '                    request.note(ObservationDiagnostics.Event.SAMPLE_EVENT_RECHECKED);\n                }else{\n                    if(graph!=null){graph.close();graph=null;}request.resampleSeed=null;request.clearCtripSample("SAMPLE_EVENT_RESET");request.gate.resetEvidence();nativeRecheck=false;\n                    request.note(ObservationDiagnostics.Event.SAMPLE_EVENT_RESET);if(request.trace!=null)request.trace.reset();\n                }\n            }\n            // Two complete native samples are required; an earlier legacy/incomplete sample cannot seed this path.\n            if(nativeRecheck!=request.nativeSample){request.resampleSeed=null;request.clearCtripSample("SAMPLE_MODE_RESET");request.gate.resetEvidence();if(request.trace!=null)request.trace.reset();}\n            request.nativeSample=nativeRecheck;\n            boolean formCurrent=ctripFormSampleCurrent(request,graph,formRead),classified=false;\n            long now;ObservationStabilityGate.Result result;\n            synchronized(request){\n                request.ctripSamplingProof=null;\n                formCurrent=formCurrent&&formRead.after.epoch==request.ctripFormSampleEpoch\n                        &&request.ctripFormSample==formRead.before\n                        &&sameObservationWatermark(formRead.after.completed,request.eventWatermark());\n                if(!formCurrent)request.clearCtripSample("SAMPLE_CANDIDATE_NOT_CURRENT");\n                now=SystemClock.elapsedRealtime();\n                result=ObservationStabilityGate.Result.WAIT;\n                if(formCurrent&&formRead.before!=null&&formRead.comparison!=null\n                        &&!formRead.before.key.equals(formRead.after.key)){\n                    result=request.gate.sampleClassifiedPair(now,formRead.before.key,formRead.before.acceptedAt,formRead.after.key,true);\n                    classified=result==ObservationStabilityGate.Result.READY;\n                }\n                // WAIT still consumes the actual current key; terminal results never obtain another budget.\n                if(result==ObservationStabilityGate.Result.WAIT)\n                    result=request.gate.sample(now,graph==null?null:frameKey(graph),true);\n                if(formCurrent&&(result==ObservationStabilityGate.Result.WAIT||result==ObservationStabilityGate.Result.READY)){\n                    if(classified||formRead.before==null||!formRead.before.key.equals(formRead.after.key)){\n                        request.ctripFormSample=new CtripFormSample(formRead.after,now);\n                        if(formRead.before==null)recordCtripSampling(request,"SAMPLE_TARGET_BOUND",request.ctripFormSample,null,null);\n                    }\n                    if(classified)request.ctripSamplingProof=ctripSamplingProof(request,formRead,now);\n                }\n            }\n            if(graph==null&&request.trace!=null)request.trace.missingSample();\n            request.note(ObservationDiagnostics.Event.valueOf("SAMPLE_"+result.name()));\n',
                '                    request.note(ObservationDiagnostics.Event.SAMPLE_EVENT_RECHECKED);\n                }else{\n                    if(graph!=null){graph.close();graph=null;}request.resampleSeed=null;request.gate.resetEvidence();nativeRecheck=false;\n                    request.note(ObservationDiagnostics.Event.SAMPLE_EVENT_RESET);if(request.trace!=null)request.trace.reset();\n                }\n            }\n            // Two complete native samples are required; an earlier legacy/incomplete sample cannot seed this path.\n            if(nativeRecheck!=request.nativeSample){request.resampleSeed=null;request.gate.resetEvidence();if(request.trace!=null)request.trace.reset();}\n            request.nativeSample=nativeRecheck;\n            long now=SystemClock.elapsedRealtime();\n            ObservationStabilityGate.Result result=request.gate.sample(now,graph==null?null:frameKey(graph),true);\n            if(graph==null&&request.trace!=null)request.trace.missingSample();\n            request.note(ObservationDiagnostics.Event.valueOf("SAMPLE_"+result.name()));\n',
            ),
            (
                '            }\n            long delay=request.gate.nextSampleDelay(now);\n            if(result==ObservationStabilityGate.Result.READY){\n                // The next read must earn its own pair; a throttled classified READY is not carried forward.\n                synchronized(request){request.ctripSamplingProof=null;}\n                request.note(ObservationDiagnostics.Event.SCREENSHOT_INTERVAL_WAIT);delay=Math.min(delay,screenshotDelay);\n            }\n            request.phase("sample_gap");\n            main.postDelayed(new Runnable(){public void run(){sampleObservation(request);}},delay);\n',
                '            }\n            long delay=request.gate.nextSampleDelay(now);\n            if(result==ObservationStabilityGate.Result.READY){request.note(ObservationDiagnostics.Event.SCREENSHOT_INTERVAL_WAIT);delay=Math.min(delay,screenshotDelay);}\n            request.phase("sample_gap");\n            main.postDelayed(new Runnable(){public void run(){sampleObservation(request);}},delay);\n',
            ),
        ],
    },
    '    private void acceptScreenshot(ObservationRequest request,ObservationProduct product,boolean retry,String error){': {
        'current_sha256': '5490d33aec3dd56908fa02f6de121afd7710479a3137dc0a0e6e127601f35680',
        'actual_body_anchor': '    private void acceptScreenshot(ObservationRequest request,ObservationProduct product,boolean retry,String error){',
        'actual_body_sha256': '5490d33aec3dd56908fa02f6de121afd7710479a3137dc0a0e6e127601f35680',
        'predecessor_sha256': '272b52c9de2479a6569d92999d3f9c71d5876dd15d1bee92e3f61384984f9fd2',
        'inverse': [
            (
                '            request.captured=null;product.bitmap=null;product.published=true;\n            if(request.trace!=null)request.trace.published(observation.id,SystemClock.elapsedRealtime());\n            request.clearCtripSample("SAMPLE_REQUEST_PUBLISHED");request.postEffectChildDiagnostic.finish();request.ctripReadDiagnostic.finish();request.finished=true;request.gate.retire();activeObservation=null;\n            request.callback.onObservation(observation);\n        }catch(Exception failure){failObservation(request,"观察发布失败："+message(failure));}\n',
                '            request.captured=null;product.bitmap=null;product.published=true;\n            if(request.trace!=null)request.trace.published(observation.id,SystemClock.elapsedRealtime());\n            request.postEffectChildDiagnostic.finish();request.ctripReadDiagnostic.finish();request.finished=true;request.gate.retire();activeObservation=null;\n            request.callback.onObservation(observation);\n        }catch(Exception failure){failObservation(request,"观察发布失败："+message(failure));}\n',
            ),
        ],
    },
}

def form_sampling_body_predecessor(service,anchor,raw,h):
    reviewed=REVIEWED_COMPLETE_FORM_SAMPLING_BODY_INVERSE.get(anchor)
    if reviewed is None or h.sha(raw.encode())!=reviewed['current_sha256']:
        return raw,False
    proof=h.body(service,reviewed['actual_body_anchor'])
    if h.sha(proof.encode())!=reviewed['actual_body_sha256']:
        raise RuntimeError('exact complete current FORM sampling producer body required: '+anchor)
    for current,prior in reviewed['inverse']:proof=once(proof,current,prior)
    if h.sha(proof.encode())!=reviewed['predecessor_sha256']:
        raise RuntimeError('FORM sampling body must reverse to the complete 0a8 predecessor: '+anchor)
    return proof,True

def generate(source,output,h):
    service=(source/PKG/'HeptaAccessibilityService.java').read_text()
    evidence=(source/PKG/'NativeAppEvidence.java').read_text()
    phone=(source/PKG/'PhoneObservation.java').read_text()
    page=(source/PKG/'NativeCtripFlightPage.java').read_text()
    template=(source/'tests/observation-pipeline/ObserverPipelineHost.template').read_text()
    child_fixture=source/'tests/native-ctrip-child-identity/protected_fixture.py'
    child_proof=runpy.run_path(str(child_fixture)) if child_fixture.is_file() else None
    proof_template=child_proof['template_predecessor'](template.encode()).decode() if child_proof else template
    if h.sha(proof_template.encode())!='7f78539e600115f929a743b0e36e4399227faaae2701af64ba2482c122634b6f':
        raise RuntimeError('reviewed current observer fixture changed')
    # Proof copy only: compile the current metadata ports with all original scheduling cases.
    png_metadata='        // Unknown pixel color metadata keeps all legacy IO/scheduling fixtures on the original encoder.\n        android.graphics.ColorSpace getColorSpace(){return null;}\n        Config getConfig(){return Config.ARGB_8888;}\n        boolean isMutable(){return false;}\n        boolean hasGainmap(){return false;}\n        int getGenerationId(){return 1;}\n        void getPixels(int[] out,int offset,int stride,int x,int y,int width,int height){\n            throw new AssertionError("legacy fixture has no qualified sRGB pixel plane");\n        }\n'
    pre_png_template=once(proof_template,png_metadata,'')
    if h.sha(pre_png_template.encode())!='1c6df78b51e766282001d5f4b0233efd31a82dc3f04b1182072eaa769aa6a7d2':
        raise RuntimeError('PNG metadata ports must reverse to the complete prior observer fixture')
    # Restore only the exact failure-type proof copy; template stays current for compilation.
    typed_child_port = '''    // Explicit Android read-failure port. Existing one-argument callers remain untyped.
    static final class StaleObservation extends IllegalStateException {
        private static final long serialVersionUID=1L;final boolean backgroundChildUnavailable;
        StaleObservation(String message){this(message,false);}
        StaleObservation(String message,boolean childUnavailable){super(message);backgroundChildUnavailable=childUnavailable;}
    }
'''
    prior_stale_port = '''    static final class StaleObservation extends IllegalStateException {private static final long serialVersionUID=1L;StaleObservation(String message){super(message);}}
'''
    prior_template_sha = '662c99d5b7703907b40d18f55b716c2ab0660abac3d67f556d5b881dfde2a333'
    prior_typed_template = once(pre_png_template,typed_child_port,prior_stale_port)
    if h.sha(prior_typed_template.encode())!=prior_template_sha:
        raise RuntimeError('typed child-failure port must reverse to the complete prior observer fixture')
    # Restore only a proof copy; generated code keeps the actual pending method
    # and the explicit absent-business queue carrier. No recovery can run here.
    business_port="    // Observer-only fixture has no business recovery flight or receipt.\n    // Actual held/drained recovery queues are covered by the dedicated lifecycle gate.\n    static final class PublicProfileBusinessRecoveryClient {\n        private PublicProfileBusinessRecoveryClient(){throw new AssertionError(\"no business recovery authority in observer fixture\");}\n        static boolean workPending(){return false;}\n    }\n"
    legacy_business_template=once(prior_typed_template,business_port,'')
    if h.sha(legacy_business_template.encode())!='1bd38ed61ce94adbb1b85c8ccd099c1b45c268c62c66b3aebca4d574f9ffdc57':
        raise RuntimeError('business queue port must reverse to the complete prior observer fixture')
    legacy_search_template=once(legacy_business_template,SEARCH_UNBOUND_PORTS,'')
    if h.sha(legacy_search_template.encode())!='2fedec818e4fb21c0260580658e225da5cc34443ec8928988f34b80f6cbb9a01':
        raise RuntimeError('unbound search ports must reverse to exact prior AX fixture')
    legacy_template=once(legacy_search_template,AX_PORTS,'')
    if h.sha(legacy_template.encode())!='50b7d239c4e76334894082dd01ecad1a7a207eb1e776f82f9916d3ea1e62de1d':
        raise RuntimeError('AX fail-only ports must reverse to the exact prior fixture')
    if legacy_template.count(PORT)!=1:raise RuntimeError('explicit fail-only old fixture port required')
    if h.sha(legacy_template.replace(PORT,'',1).encode())!='c13a2152891f7f7a4373421b8060f683c1d7d6dd92725bee86081cda9c660799':
        raise RuntimeError('old fixture must differ only by fail-only port; old cases intact')
    parts={
      'observation_callback':h.section(service,'    public interface ObservationCallback','    public interface Cancellation'),
      'diagnostic':h.section(service,'    private String diagnosticTask;','    /** Each observation owns'),
      'acquire':h.section(service,'    public synchronized boolean acquireTask(','    public synchronized void releaseTask('),
      'recovery_idle':h.section(service,'    synchronized boolean recoveryControllerIdle(','    synchronized void retireControllerAfterAcknowledgement('),
      'action_pending':h.section(service,'    boolean actionWorkPending()','    void retireActionWork('),
      'cancellation_pending':h.section(service,'    boolean nativeCancellationWorkPending()','    boolean requestNativeCancellation('),
      'background_lock':h.section(service,'    private boolean locked(BackgroundSession background)','    private int rotation('),
      'observation':h.section(service,'    /** Each observation owns','    synchronized void bindQualificationScope('),
      'form_pair':h.body(service,'    private Map<String,Object> nativeCtripFormPair(ObservationRequest request,CaptureIdentity identity,Graph after){'),
      'form_snapshot':h.body(service,'    private NativeActionSnapshotCheck.Snapshot nativeCtripFormSnapshot(ObservationRequest request,Graph graph,ProfileTarget target){'),
      'ctrip_diagnostic_mark':h.body(service,'    private static List<Long> ctripDiagnosticMark('),
      'ctrip_saved_gate':h.body(service,'    private static Map<String,Object> ctripSavedGraphGate('),
      'ctrip_form_gate':h.body(service,'    private static void recordCtripFormGate('),
      'frozen_factory':h.body(service,'    private static FrozenObservationWindow frozenObservationWindow(Graph graph){'),
      'complete_native':h.body(service,'    private static boolean completeNativeObservationGraph(Graph graph){'),
      'profile_owner':h.body(service,'    private static void requireSameProfileOwner('),
      'collection_stats':h.body(phone,'    public static final class CollectionStats {'),
      'supported_goal':h.body(page,'    static boolean supported(NativeAppGoal goal){')}
    if child_proof is not None:
        parts['child_identity_recheck']=h.body(service,'    private PostEffectChildWindowCheck recheckPostEffectChildWindow(')
        parts['child_window_fingerprint']=h.body(service,'    private static String postEffectChildWindowFingerprint(')
        parts['actual_stale_type']=h.body(service,'    private static final class StaleObservation extends IllegalStateException {')
    evidence_anchors=[
      '    static boolean sameProfileOwner(WindowOwnership a,WindowOwnership b){',
      '    static void requireProfileTarget(ProfileTarget expected,WindowOwnership actual){',
      '    static Map<String,Object> profileActionIdentity(WindowOwnership actual){',
      '    static Map<String,Object> map(){',
      '    static Map<String,Object> immutableMap(Map<String,Object> source){',
      '    private static Object immutableValue(Object value,int depth){',
      '    static void need(boolean yes,String why){',
      '    static String hash(String value){',
      '    static String fingerprint(Object value){',
      '    private static void canonical(StringBuilder out,Object value,int depth){']
    evidence_parts=[h.body(evidence,a) for a in evidence_anchors]
    for i,value in enumerate(evidence_parts):parts['evidence_'+str(i)]=value
    protected={}
    for anchor,expected in BASELINE_BODY_SHA256.items():
        raw=h.body(service,anchor);actual=h.sha(raw.encode())
        proof,form_sampling_inverse=form_sampling_body_predecessor(service,anchor,raw,h)
        if child_proof is not None and anchor=='    private void acceptScreenshot(ObservationRequest request,ObservationProduct product,boolean retry,String error){':
            proof=child_proof['accept_predecessor'](proof.encode()).decode()
        # Reverse only the reviewed Xiaomi original-literal type guard for the
        # historical body proof. Actual production extraction stays current.
        if anchor=='    private void requireNativeActionGuard(String task,PhoneObservation frame,ActionDecision action,ActionWork work)throws Exception{' and actual=='0fbffdc34dc59df1828d928c70c7514d9732d8cb6afedaf2f2c308918a321d01':
            proof=once(proof,'                ||!original.packageName.equals(frame.backgroundBootstrapPackage)\n                ||!(nativeSearchInputGuard(work)?"type".equals(action.action):"click".equals(action.action))\n                ||nativeSearchInputGuard(work)&&(!original.packageName.equals(NativeAppGoal.XIAOMI_PACKAGE)\n                    ||!guard.goal.readsXiaomiProduct()||!NativeAppGoal.PRODUCT_MODEL.equals(guard.goal.productModel)\n                    ||!guard.goal.immutableOwner.substring(guard.goal.modelStartUtf16,guard.goal.modelEndUtf16).equals(action.text)\n                    ||!guard.targetNode.text.isEmpty()||!"0/1".equals(guard.targetNode.path))\n','                ||!original.packageName.equals(frame.backgroundBootstrapPackage)||!"click".equals(action.action)\n')
            if h.sha(proof.encode())!='4ff4399af8965f25601a0c494a97d5101d41d4f5031dc4413dc57cdb2baa5bab':
                raise RuntimeError('empty-input type guard must reverse to exact prior action guard')
        if anchor=='    private void acceptScreenshot(ObservationRequest request,ObservationProduct product,boolean retry,String error){':
            # Proof copy only: exact inverse of the post-capture settle tightening.
            proof=once(proof,'                // A discarded post-navigation screenshot requires a new pair even when it seeds\n                // the first sample. The capture margin cannot admit sampling after settle expiry.\n                long now=SystemClock.elapsedRealtime(),remaining=request.deadline-now;\n                if(request.postEffectController!=null&&(now-request.started>=ObservationStabilityGate.SETTLE_LIMIT_MS\n                        ||remaining<=ObservationStabilityGate.SAMPLE_GAP_MS)){\n                    failObservation(request,"操作后的页面仍在变化，本次观察剩余时间不足以重新采样");return;\n                }\n','                // A discarded post-navigation screenshot requires a new pair even when it seeds\n                // the first sample. Starting another Binder read cannot satisfy a sub-gap budget.\n                long remaining=request.deadline-SystemClock.elapsedRealtime();\n                if(request.postEffectController!=null&&remaining<=ObservationStabilityGate.SAMPLE_GAP_MS){\n                    failObservation(request,"操作后的页面仍在变化，本次观察剩余时间不足以重新采样");return;\n                }\n')
            proof=once(proof,'if((request.postEffectRetrySubmission!=null||request.postEffectController!=null\n                    &&(product.formPair!=null||product.postEncodingFormPair!=null))\n                    &&(!postEffectObservationOwner(request)||request.postEffectIdentityRejected)){','if(request.postEffectRetrySubmission!=null&&(!postEffectObservationOwner(request)||request.postEffectIdentityRejected)){')
            # Reverse both reviewed production deltas on a proof copy. The compiled
            # observer retains both the scoped owner check and the remaining-time guard.
            if h.sha(proof.encode())!='09c4c89c912224ad957f9a53d430999e790fa6d570a16f5b3865f677f5904f9c':
                raise RuntimeError('reviewed form publication must restore exact post-navigation predecessor')
            proof=once(proof,'                // A discarded post-navigation screenshot requires a new pair even when it seeds\n                // the first sample. Starting another Binder read cannot satisfy a sub-gap budget.\n                long remaining=request.deadline-SystemClock.elapsedRealtime();\n                if(request.postEffectController!=null&&remaining<=ObservationStabilityGate.SAMPLE_GAP_MS){\n                    failObservation(request,"操作后的页面仍在变化，本次观察剩余时间不足以重新采样");return;\n                }\n', '')
            if h.sha(proof.encode())!='d86064ad2a7361af1e3be8e1b601b542d3faa73795b849c742b86397a76d710f':raise RuntimeError('historical form publication must restore exact R32 owner check')
        sampling=REVIEWED_SAMPLING_BODY_INVERSE.get(anchor);sampling_inverse=False
        if sampling is not None and h.sha(proof.encode())==sampling['sha256']:
            for revised,prior in sampling['inverse']:proof=once(proof,revised,prior)
            if h.sha(proof.encode())!=sampling['predecessor_sha256']:
                raise RuntimeError('reviewed sampling body must reverse to exact predecessor: '+anchor)
            sampling_inverse=True
        predecessor=h.sha(proof.encode());ax_inverse=predecessor!=expected
        if ax_inverse:
            reviewed=REVIEWED_AX_BODY_INVERSE.get(anchor)
            if reviewed is None or predecessor!=reviewed['sha256']:
                raise RuntimeError('protected reviewed production body changed: '+anchor)
            legacy=once(proof,reviewed['current'],reviewed['legacy'])
            if h.sha(legacy.encode())!=expected:
                raise RuntimeError('reviewed AX body must reverse to exact legacy body: '+anchor)
        protected[anchor]={'bytes':len(raw.encode()),'sha256':actual,'legacy_sha256':expected,
                           'reviewed_ax_inverse_verified':ax_inverse,
                           'reviewed_complete_form_sampling_inverse_verified':form_sampling_inverse,
                           'complete_form_sampling_predecessor_sha256':REVIEWED_COMPLETE_FORM_SAMPLING_BODY_INVERSE[anchor]['predecessor_sha256'] if form_sampling_inverse else None,
                           'reviewed_sampling_inverse_verified':sampling_inverse,
                           'sampling_predecessor_sha256':predecessor if sampling_inverse else None}
    protected_files={}
    readonly_owner_inverse=None;form_sampling_gate_inverse=None
    for name,expected in BASELINE_FILES.items():
        current=(source/PKG/name).read_bytes();actual=h.sha(current)
        if name=='ObservationStabilityGate.java':
            prior=gate_predecessor(current)
            if h.sha(prior)!=expected:raise RuntimeError('complete original Gate proof required')
            protected_files[name]=actual
            form_sampling_gate_inverse={'current_sha256':actual,'predecessor_sha256':h.sha(prior),
                'proof_copy_only':True,'actual_compilation_uses_current_source':True}
            continue
        r32_provider_pins={'NativeActionSnapshotCheck.java': '4b44a759dd41f60c6c693c60d500a83fa8ec83962eb7f6b8d6dd5be95953ad6b', 'NativeCtripFlightPage.java': '78d72c577f42e44754da0856df5f02152f9ba69c40b9b219968d869683539892'}
        if name=='NativeActionSnapshotCheck.java' and actual=='400db829f8b5942d9ad4a43a1bbbc18d96fe2138964482146b8cd08fd63ea593':
            prior=runpy.run_path(str(source/'tests/native-ctrip-form-observation/scope_predecessor.py'))['predecessor'](current)
            prior=runpy.run_path(str(source/'tests/native-xiaomi-query-stability/protected_filled_query.py'))['predecessor'](name,prior)
            proof=runpy.run_path(str(source/'tests/native-search-producer/protected_snapshot.py'))['predecessor'](prior)
            if h.sha(proof)!=r32_provider_pins[name]:raise RuntimeError('complete Ctrip scope inverse to R32')
            protected_files[name]=actual
            continue
        if name=='NativeCtripFlightPage.java' and actual=='8f848806d0761d1ba33c9a1f8030bb2bacb385c7ae534992daa88349705821cb':
            # This added reader is independent of the earlier form observer.
            # Removing its sole block must reproduce every byte of its original provider.
            start=b'        /** Exact displayed fare strip only.'
            end=b'        LocalDate displayedMonthDay('
            if current.count(start)!=1 or current.count(end)!=1:raise RuntimeError('calendar minimum reader boundaries')
            prior=current[:current.index(start)]+current[current.index(end):]
            if h.sha(prior)!=r32_provider_pins[name]:raise RuntimeError('calendar minimum reader must reverse to R32 provider')
            protected_files[name]=actual
            continue
        if name=='NativeAppGoal.java' and actual=='65c87f6254ac109223ddb643f0ef7dd9763c5690414b7ccb8a50e4bc921c6447':
            helper=source/'tests/native-ctrip-readonly-owner/protected_readonly_owner.py'
            if h.sha(helper.read_bytes())!='14a0378f13c0a0cfbb370b0230ec2b58a0ee475f4e88e4031f3a866e9333e353':raise RuntimeError('exact reviewed read-only OWNER inverse helper')
            prior=runpy.run_path(str(helper))['predecessor'](current)
            if len(prior)!=21582 or h.sha(prior)!='9f823e54fee2862e390df6b86d7a2fc9a02d463c073159dc6f38d6c3a31cb5c4':
                raise RuntimeError('complete preceding OWNER source required')
            readonly_owner_inverse={'current_sha256':actual,'predecessor_sha256':h.sha(prior),
                'helper_sha256':'14a0378f13c0a0cfbb370b0230ec2b58a0ee475f4e88e4031f3a866e9333e353','proof_copy_only':True,'actual_compilation_uses_current_source':True}
            protected_files[name]=actual
            continue
        if name=='NativeAppGoal.java' and actual=='9f823e54fee2862e390df6b86d7a2fc9a02d463c073159dc6f38d6c3a31cb5c4':
            # Recognizes an additional Xiaomi owner. The actual Ctrip goal and all
            # the form-observer bodies and original cases compile and run below.
            protected_files[name]=actual
            continue
        if name=='NativeActionSnapshotCheck.java' and actual in ('dbc72e40e410334c9db300308dc0dfec60339a8e4c3018661239c1a959438d05',
                'de5a0bcd74250ce051595bc9200802ad019a99a69babc18dd9ecc229a6e2afac',
                '5e3366ed3d59c94360663058004bcab06fa896f97a120717f90fd8d8f43e33bf',
                'b5bbcc3e74f769c94718de560fa476431d0b726997f48b9c4ad094a997d737b2'):
            predecessor_input=current
            if actual=='b5bbcc3e74f769c94718de560fa476431d0b726997f48b9c4ad094a997d737b2':
                predecessor_input=runpy.run_path(str(source/'tests/native-xiaomi-query-stability/protected_filled_query.py'))['predecessor'](name,current)
            proof=runpy.run_path(str(source/'tests/native-search-producer/protected_snapshot.py'))['predecessor'](predecessor_input)
            if h.sha(proof)!=r32_provider_pins[name]:raise RuntimeError('full prior comparator required')
            protected_files[name]=actual
            continue
        if name in r32_provider_pins and actual==r32_provider_pins[name]:
            protected_files[name]=actual
            continue
        if actual!=expected:
            proof_current=current
            if name=='NativeActionSnapshotCheck.java' and actual=='df7231303bac13507172dd83ebfe36fb17d107390f4aaa40a80ce4cf18263412':
                # Proof copy only: exact typed-history diagnostic changes. The
                # unchanged current source and all original cases compile below.
                proof=current.decode()
                inverse=[
                    ('need(capture.nativeText()&&sha(capture.receiptSha256)&&originalScreen==null,',
                     'need(ObservationCaptureEvidence.NATIVE_AX.equals(capture.kind)&&sha(capture.receiptSha256)&&originalScreen==null,'),
                    ('out.put("original_capture_kind",capture==null?ObservationCaptureEvidence.PIXELS:capture.kind);',
                     'out.put("original_capture_kind",capture==null?ObservationCaptureEvidence.PIXELS:ObservationCaptureEvidence.NATIVE_AX);')]
                for revised,prior in inverse:proof=once(proof,revised,prior)
                proof_current=proof.encode()
                if h.sha(proof_current)!='829bbcb2b7ad39c37acfde5493fcf5195acaaa7e461327d915f656a5b90fc25c':
                    raise RuntimeError('typed-history diagnostics must reverse to complete prior search file')
            if name!='NativeActionSnapshotCheck.java' or h.sha(proof_current)!='829bbcb2b7ad39c37acfde5493fcf5195acaaa7e461327d915f656a5b90fc25c':
                raise RuntimeError('protected production file changed: '+name)
            legacy_search=proof_current.decode()
            for prior,revised in REVIEWED_SEARCH_NAS_INVERSE:
                legacy_search=once(legacy_search,revised,prior)
            if h.sha(legacy_search.encode())!='1d2278784b70f4e57857f8a2cdc89d8e5d2471726e68f57b1d75a659f47a24c1':
                raise RuntimeError('reviewed pure search extraction must reverse to exact prior AX file')
            legacy=once(legacy_search,AX_REJECTION_PREFIX,LEGACY_REJECTION_PREFIX)
            legacy=once(legacy,AX_REJECTION_METADATA,'')
            if h.sha(legacy.encode())!=expected:
                raise RuntimeError('typed AX rejection evidence must reverse to exact legacy file')
        protected_files[name]=actual
    compiled_parts,calendar_boundary=h.calendar_observer_legacy_parts(service,parts,retain_ctrip_sampling=True)
    for name in ('observation_callback','diagnostic','acquire','recovery_idle','action_pending','cancellation_pending','background_lock','observation'):
        template=once(template,'{{'+name+'}}',compiled_parts[name])
    template=once(template,'            long transitionDeadline(){requireCurrent();return transition;}',
                  '            String fixtureOrigin; String originalObservationId(){requireCurrent();if(fixtureOrigin==null)throw new IllegalStateException("missing prior entered fixture frame");return fixtureOrigin;} Map<String,Object> evidence(){return Collections.<String,Object>singletonMap("original_observation_id",originalObservationId());}\n            long transitionDeadline(){requireCurrent();return transition;}')
    main=h.body(template,'    public static void main(String[] args)throws Exception{')
    template=once(template,main,BRIDGE)
    template=once(template,'import java.util.*;','import java.util.*;\nimport java.security.NoSuchAlgorithmException;\nimport org.json.JSONArray;\nimport org.json.JSONException;\nimport org.trillionnium.hepta.background.ProfileIdentity;\nimport org.trillionnium.hepta.background.ProfileTarget;\nimport org.trillionnium.hepta.background.WindowOwnership;')
    template=once(template,h.body(template,'    static final class WindowOwnership {'),'')
    template=once(template,h.body(template,'    static final class NativeAppEvidence {'),'    static final class NativeAppEvidence {\n'+'\n'.join(evidence_parts)+'\n    }')
    template=once(template,h.body(template,'    static void requireSameProfileOwner('),parts['profile_owner'])
    template=once(template,'    static final class NativeAppGoal {String ownerSha256,packageName;}','')
    constants=[]
    for marker in ('    static final String PACKAGE=','    static final long VERSION_CODE=','    static final String BASE_APK_SHA256='):
        lines=[line for line in page.splitlines() if line.startswith(marker)]
        if len(lines)!=1:raise RuntimeError('actual provider constant boundary')
        constants.extend(lines)
    parts['provider_constants']='\n'.join(constants)
    template=once(template,'    interface GraphBudget {void check();}',
                  '    interface GraphBudget {void check();}\n    static final class NativeCtripFlightPage {\n'+'\n'.join(constants)+'\n'+parts['supported_goal']+'\n    }\n    static final class ProfileOwnershipViolation extends IllegalStateException {private static final long serialVersionUID=1L;ProfileOwnershipViolation(String message){super(message);}}')
    template=once(template,'    static final class SystemClock {static volatile long now=1000;static long elapsedRealtime(){return now;}}',
                  '    static final class SystemClock {static volatile long now=1000;static volatile Runnable nextElapsedHook;static long elapsedRealtime(){Runnable hook=nextElapsedHook;if(hook!=null){nextElapsedHook=null;hook.run();}return now;}}')
    template=once(template,'        boolean explicitSelection;String route,ownerSha256,packageName;','        boolean explicitSelection;String route,ownerSha256,packageName,targetSha256;')
    template=once(template,'    static final class Selection {BackgroundTaskTarget taskTarget;String initialPackage;List<String> allowedPackages;}',
                  '    static final class Selection {BackgroundTaskTarget taskTarget;String initialPackage,sha;List<String> allowedPackages;}')
    template=once(template,'        final int display;boolean closed;final String taskId;String ownerSha256,generation;',
                  '        final int display;boolean closed;final String taskId;String ownerSha256,generation;ProfileTarget profile;')
    template=once(template,'        Object profileTarget(){return null;} // Explicit scheduling fixture has no profile selection.',
                  '        ProfileTarget profileTarget(){return profile;} // Synthetic target value; production identity predicates execute.')
    template=once(template,'        final Object state=new Object(),windowMetadata=new Object(),rows=new Object(),collectionStats=new Object();',
                  '        ObservationState state;ObservedWindowMetadata windowMetadata;PhoneObservation.CollectionStats collectionStats;\n        final List<PhoneObservation.Node> rows=new ArrayList<PhoneObservation.Node>();final Map<String,NodeRef> refs=new HashMap<String,NodeRef>();')
    template=once(template,'        final String backgroundBootstrapPackage="fixture.notes";final List<String> backgroundAllowedPackages=Collections.singletonList("fixture.notes");',
                  '        String backgroundBootstrapPackage="fixture.notes";List<String> backgroundAllowedPackages=Collections.singletonList("fixture.notes");')
    template=once(template,'        long readStartedElapsedMs,readCompletedElapsedMs;',
                  '        long readStartedElapsedMs,readCompletedElapsedMs,nativeActionCapturedAt;\n        List<NativeActionSnapshotCheck.Node> nativeActionNodes;Map<String,Object> nativeActionWindows;int nativeActionWidth,nativeActionHeight;\n        String nativeActionTaskId,nativeActionAuthorizationSha,nativeActionSelectionSha,nativeActionTargetSha,nativeActionGoalSha;')
    template=once(template,'        int getWidth(){return 1080;}int getHeight(){return 2400;}','        int getWidth(){return 1224;}int getHeight(){return 2992;}')
    template=once(template,'    static final class PhoneObservation {','    static final class PhoneObservation {\n'+parts['collection_stats']+'''
        static final class Node {
            String id,packageName,nativeTreePath,observedAppTreeSignature;boolean selectionStateObserved=true;
            Node(String id,String pkg,String path,String signature){this.id=id;packageName=pkg;nativeTreePath=path;observedAppTreeSignature=signature;}
        }
''')
    template=once(template,'            if(profile!=null)throw new AssertionError("legacy observer cannot publish profile authority");',
                  '            // Profile is a synthetic value carrier here, not a phone ownership assertion.')
    template=once(template,'        expect(!isMain(),"hash on main");if(hashHook!=null)hashHook.run();MessageDigest digest=MessageDigest.getInstance("SHA-256");\n        digest.update(Files.readAllBytes(file.toPath()));return Arrays.toString(digest.digest());',
                  '        expect(!isMain(),"hash on main");\n        if(file.getName().endsWith("-form-history.json")){if(formHistoryHashHook!=null)formHistoryHashHook.run();}\n        else if(hashHook!=null)hashHook.run();return sha(Files.readAllBytes(file.toPath()));')

    template=once(template,'        JSONObject(String raw){throw new AssertionError("observer scheduling fixture cannot construct Selection provenance");}',
                  '        JSONObject(){value=new org.json.JSONObject();}\n        JSONObject put(String key,Object object)throws JSONException{value.put(key,object);return this;}\n        JSONObject(String raw)throws JSONException{value=new org.json.JSONObject(raw);}')
    template=once(template,'    Object taskScope,taskAuthorization,taskNotesPhase,taskCalculatorInput,taskSubmitAttempts,taskFixedIntentAttempts,appDiscovery;Runnable stopListener;',
                  '    Object taskScope,taskNotesPhase,taskCalculatorInput,taskSubmitAttempts,taskFixedIntentAttempts,appDiscovery;Runnable stopListener;\n    AuthorizationGate taskAuthorization;')
    template=once(template,'try{if(readHook!=null)readHook.read(graph,n);budget.check();graph.readCompletedElapsedMs=SystemClock.now;return graph;}',
                  'try{if(readHook!=null)readHook.read(graph,n);budget.check();graph.readCompletedElapsedMs=SystemClock.now;\n            Runnable after=afterReadHook;if(after!=null){afterReadHook=null;SystemClock.nextElapsedHook=after;}return graph;}')
    if child_proof is None or 'DIAGNOSTIC_PORTS' not in child_proof:raise RuntimeError('exact coherent diagnostic template proof required')
    template=once(template,child_proof['DIAGNOSTIC_PORTS'],'')
    template=once(template,'    private Map<String,Object> nativeCtripFormPair(ObservationRequest request,CaptureIdentity identity,Graph after){return null;}',
                  '\n'.join(parts[k] for k in ('form_pair','form_snapshot','ctrip_diagnostic_mark','ctrip_saved_gate','ctrip_form_gate')))
    template=once(template,'    private static FrozenObservationWindow frozenObservationWindow(Graph graph){return null;}',
                  parts['frozen_factory']+'\n'+parts['complete_native'])
    fake=h.body(template,'    private FrozenObservationWindow readFrozenObservationWindow(ObservationRequest request,CaptureIdentity identity){')
    template=once(template,fake,'''    private FrozenObservationWindow readFrozenObservationWindow(ObservationRequest request,CaptureIdentity identity){
        expect(!isMain(),"identity Android IO on main");windowChecks.incrementAndGet();
        if(windowHook!=null)windowHook.run();requireObservationWork(request);
        requireTaskAuthorization(request.taskId,taskAuthorization);return windowValue;
    }''')
    template=once(template,'        expect(owns(task)&&authorization!=null&&authorization==taskAuthorization,"retired fixture authorization");',
                  '        if(!owns(task)||!authorizationReady||authorization==null||authorization!=taskAuthorization)throw new IllegalStateException("retired fixture authorization");')
    if child_proof is not None:
        template=once(template,child_proof['PORT'],parts['child_identity_recheck']+'\n'+parts['child_window_fingerprint']+'\n')
        template=once(template,typed_child_port,parts['actual_stale_type']+'\n')
    if '{{' in template:raise RuntimeError('unfilled host fixture')
    for name,raw in parts.items():
        if name=='provider_constants':continue
        compiled_raw=compiled_parts.get(name,raw)
        if template.count(compiled_raw)!=1:raise RuntimeError('actual production body or explicit calendar type boundary was altered or duplicated: '+name)
    h.write(output/'ObserverPipelineHost.java',template)
    return {'schema':'hepta.ctrip-form-observer-extraction.v1',
            'typed_child_port_inverse':{'current_complete_sha256':'1c6df78b51e766282001d5f4b0233efd31a82dc3f04b1182072eaa769aa6a7d2',
                'prior_complete_sha256':prior_template_sha,'exact_current_block_sha256':h.sha(typed_child_port.encode()),
                'proof_copy_only':True,'actual_compilation_uses_current_template':True},
            'production_bodies_verbatim':not calendar_boundary['calendar_producer_excluded'],
            'original_observer_methods_and_hooks_verbatim':True,'calendar_legacy_boundary':calendar_boundary,
            'parts':{name:{'bytes':len(raw.encode()),'sha256':h.sha(raw.encode())} for name,raw in parts.items()},
            'protected_production_bodies':protected,'protected_files':protected_files,
            'child_identity_fixture_proof':h.meta(child_fixture) if child_proof is not None else None,
            'readonly_owner_inverse':readonly_owner_inverse,
            'complete_form_sampling_gate_inverse':form_sampling_gate_inverse,
            'protected_legacy_files':BASELINE_FILES,'current_ax_fail_only_ports_preserved':True,
            'legacy_fixture_only_fail_closed_port':True,'initial_current_frame_created_by_actual_observer':True,
            'pair_snapshot_uses_actual_full_node_and_snapshot_classes':True,
            'actual_profile_value_types_compiled':True,'actual_owner_parser_compiled':True,
            'boundary':'Actual observer, both scoped helpers, completeness predicate, pure comparator, profile value types and owner parser. Android graph/window/authorization/selection/pixels/clock are explicit synthetic endpoints. No actual device, action or business evidence.',
            'phone_execution':False,'model_executed':False,'business_completion_verified':False}
def main():
    ap=argparse.ArgumentParser()
    for arg in ('source','output','java-home','json-jar'):ap.add_argument('--'+arg,type=Path,required=True)
    a=ap.parse_args();source=a.source.resolve();output=a.output.absolute();output.mkdir(parents=True,exist_ok=False)
    h=module(source/'tests/observation-diagnostics/run_host.py','form_observer_helpers')
    jdk=a.java_home.resolve();java=jdk/'bin/java';javac=jdk/'bin/javac';jar=a.json_jar.resolve()
    tools=[java,javac,jdk/'lib/modules',jdk/'lib/ct.sym',jar]
    if not all(path.is_file() for path in tools):raise RuntimeError('JDK17 and JSON closure required')
    if jar.stat().st_size!=78332 or h.sha(jar.read_bytes())!='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed':
        raise RuntimeError('pinned JSON jar required')
    inputs=[source/PKG/n for n in JAVA+READ]+[source/PROFILE/n for n in PROFILE_NAMES]
    inputs += [source/TEST/n for n in ('ObserverIntegrationHostTest.java','run_observer_host.py','FormPairHostTest.java','scope_predecessor.py','form-region-nodes.json')]
    inputs += [source/'tests/native-action-integration/NativeActionSnapshotCheckHostTest.java',
               source/'tests/observation-pipeline/ObserverPipelineHost.template',source/'tests/observation-diagnostics/run_host.py']
    inputs += [source/'tests/native-xiaomi-query-stability/protected_filled_query.py']
    inputs += [source/'tests/native-ctrip-readonly-owner/protected_readonly_owner.py']
    inputs += h.png_sources(source)
    before=[h.meta(p) for p in inputs];tools_before=[h.meta(p) for p in tools]
    report={'schema':'hepta.ctrip-form-observer-host.v1','all_pass':False,'stages':[],
            'source_root':str(source),'source_inputs':before,'tools_before':tools_before,
            'compiler_contract':'JDK17 --release 8 -encoding UTF-8 -Xlint:all -Werror',
            'phone_execution':False,'phone_operations':0,'android_execution':False,'model_executed':False,
            'sdk_loaded':False,'business_completion_verified':False}
    try:
        generated=output/'generated';generated.mkdir();h.save(output/'EXTRACTION.json',generate(source,generated,h))
        classes=output/'classes';classes.mkdir()
        compiled=[source/PKG/n for n in JAVA]+[source/PROFILE/n for n in PROFILE_NAMES]
        compiled += [source/'tests/native-action-integration/NativeActionSnapshotCheckHostTest.java',
                     source/TEST/'FormPairHostTest.java',source/TEST/'ObserverIntegrationHostTest.java',generated/'ObserverPipelineHost.java']
        compiled += h.png_sources(source)
        report['stages'].append(h.stage('compile',[str(javac),'--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-cp',str(jar),'-d',str(classes)]+[str(p) for p in compiled],output))
        if report['stages'][-1]['exit_code']!=0:raise RuntimeError('actual observer extraction compilation failed')
        report['stages'].append(h.stage('observer-cases',[str(java),'-Dhepta.ctrip.form.fixture='+str(source/TEST/'form-region-nodes.json'),'-cp',str(classes)+os.pathsep+str(jar),
                'org.trillionnium.hepta.local.ObserverIntegrationHostTest',str(output/'CASES.json')],output))
        if report['stages'][-1]['exit_code']!=0:raise RuntimeError('actual observer integration cases failed')
        cases=json.loads((output/'CASES.json').read_text())
        if cases['all_pass'] is not True or cases['cases']!=len(cases['case_names']) or len(set(cases['case_names']))!=cases['cases']:
            raise RuntimeError('complete unique case accounting required')
        report.update(all_pass=True,cases=cases,case_file=h.meta(output/'CASES.json'),extraction_file=h.meta(output/'EXTRACTION.json'),
                generated_files={p.name:h.meta(p) for p in generated.glob('*.java')})
    except Exception as error:report['error']={'type':type(error).__name__,'message':str(error)}
    finally:
        report['source_inputs_after']=[h.meta(p) for p in inputs];report['tools_after']=[h.meta(p) for p in tools]
        report['inputs_unchanged']=before==report['source_inputs_after'];report['tools_unchanged']=tools_before==report['tools_after']
        report['all_pass']=report['all_pass'] and report['inputs_unchanged'] and report['tools_unchanged']
        h.save(output/'RESULT.json',report)
    print(json.dumps({'all_pass':report['all_pass'],'result':h.meta(output/'RESULT.json')},sort_keys=True))
    return 0 if report['all_pass'] else 1
BRIDGE = r'''
    // Explicit host-only Graph/selection/clock endpoints for actual observer code.
    static final String TEST_TASK=NativeActionSnapshotCheckHostTest.ID;
    static final String TEST_GENERATION=NativeActionSnapshotCheckHostTest.UUID;
    static final String TEST_TOKEN="22222222-3333-4444-5555-666666666666";
    static final String TEST_SHA=NativeActionSnapshotCheckHostTest.H;
    static final class AuthorizationValue {String sha256=TEST_SHA;}
    static final class AuthorizationGate {final AuthorizationValue authorization=new AuthorizationValue();}
    static final class NativeAppObservation {
        static String selectionSha(Selection selection)throws Exception{
            if(live!=null&&live.selectionCheckedFailure)throw new Exception("synthetic checked selection failure");
            Runnable hook=live==null?null:live.selectionHook;
            if(hook!=null){live.selectionHook=null;hook.run();}
            return selection.sha;
        }
    }
    static final class NodeRef {String appTreeSignature;NodeRef(String value){appTreeSignature=value;}}
    volatile Runnable selectionHook,afterReadHook,windowHook,formHistoryHashHook;
    volatile boolean selectionCheckedFailure;
    volatile FrozenObservationWindow windowValue;
    final AtomicInteger windowChecks=new AtomicInteger();
    boolean authorizationReady=true;
    static ProfileTarget target(String pkg,long version,String base){
        return new ProfileTarget(new ProfileIdentity(10,7L,0,ProfileIdentity.MANAGED),1012345,pkg,pkg+"/SyntheticActivity",
                version,Collections.singletonMap("base",base),Collections.singleton(TEST_SHA));
    }
    static WindowOwnership owned(ProfileTarget target,int window,String token){
        return new WindowOwnership(target,TEST_GENERATION,15,window,500,499,token,
                "33333333-4444-5555-6666-777777777777",target.profile.userId,target.profile.serial,target.fullUid,
                SystemClock.now,SystemClock.now+9000);
    }
    static Map<String,Object> windows(){
        Map<String,Object> row=new LinkedHashMap<String,Object>();
        row.put("window_id",96);row.put("display_id",15);row.put("type",1);row.put("layer",2);
        row.put("bounds",Arrays.asList(0,0,1224,2992));row.put("focused",true);row.put("active",true);
        Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("display_id",15);out.put("target_window_id",96);out.put("target_layer",2);
        out.put("windows",Collections.singletonList(row));out.put("other_window_roots_traversed",false);
        out.put("unreported_windows_excluded",false);return NativeAppEvidence.immutableMap(out);
    }
    static PhoneObservation.CollectionStats counters(Graph g,int visited,int pending,int nodeOmitted,long childOmitted){
        return new PhoneObservation.CollectionStats(1536,512,32768,visited,g.rows.size(),100,
                pending,nodeOmitted,0,childOmitted,1);
    }
    static void populate(ObserverPipelineHost f,Graph g,NativeActionSnapshotCheckHostTest.Fixture values,String scenario,int ordinal){
        BackgroundSession bg=f.taskBackground;BackgroundTaskTarget task=bg.selection.taskTarget;
        g.packageName=task.packageName;g.windowId=96;g.rotation=0;
        g.backgroundGeneration=bg.generation;g.backgroundOwnerSha=bg.ownerSha256;
        g.backgroundSelectionRaw="{\"fixture\":\"synthetic_managed_form_selection\"}";
        g.backgroundBootstrapPackage=task.packageName;g.backgroundAllowedPackages=bg.selection.allowedPackages;
        g.bounds.left=0;g.bounds.top=0;g.bounds.right=1224;g.bounds.bottom=2992;
        g.state=new ObservationState(TEST_SHA,ImeVisibility.HIDDEN);
        g.windowMetadata=ObservedWindowMetadata.observed(new int[]{0,0,1224,2992},"android.widget.FrameLayout",1,15,new int[]{0,0,1224,2992},g.packageName);
        g.nativeActionNodes=new ArrayList<NativeActionSnapshotCheck.Node>();
        int k=0;for(Map<String,Object> original:values.nodes.values()){
            Map<String,Object> raw=new TreeMap<String,Object>(original);raw.put("package",g.packageName);
            NativeActionSnapshotCheck.Node row=new NativeActionSnapshotCheck.Node(raw);g.nativeActionNodes.add(row);
            String id="n"+k++;String signature=NativeActionSnapshotCheck.hash("synthetic-complete-retained:"+row.path);
            g.rows.add(new PhoneObservation.Node(id,g.packageName,row.path,signature));g.refs.put(id,new NodeRef(signature));
        }
        g.collectionStats=counters(g,g.nativeActionNodes.size(),0,0,0);
        g.nativeActionWindows=windows();g.nativeActionWidth=1224;g.nativeActionHeight=2992;
        g.nativeActionTaskId=f.lease;g.nativeActionAuthorizationSha=f.taskAuthorization.authorization.sha256;
        g.nativeActionSelectionSha=bg.selection.sha;g.nativeActionTargetSha=task.targetSha256;
        g.nativeActionGoalSha=task.nativeGoal.contractSha256;g.nativeActionCapturedAt=SystemClock.now;
        g.profileWindow=bg.profile==null?null:owned(bg.profile,g.windowId,TEST_TOKEN);
        g.digest=ordinal==6&&!"unchanged_pair_keeps_legacy_mode".equals(scenario)?"changed-form":"original-form";
        if(ordinal==6){
            if("protected_form_change".equals(scenario)){
                replaceNode(g,"0/0/2/5","text","11月18日周三");
            }else if("missing_child".equals(scenario)){
                for(int i=0;i<g.nativeActionNodes.size();i++)if("0/0/7/0".equals(g.nativeActionNodes.get(i).path)){g.nativeActionNodes.remove(i);break;}
                g.collectionStats=counters(g,g.nativeActionNodes.size(),0,0,0);
            }else if("visited_count_mismatch".equals(scenario)){
                g.collectionStats=counters(g,g.nativeActionNodes.size()+1,0,0,0);
            }else if("known_target_event_during_census".equals(scenario))f.noteObservationEvent(15);
            else if("unrelated_display_event".equals(scenario))f.noteObservationEvent(0);
            else if("unknown_event_during_census".equals(scenario))f.noteObservationEvent(-1);
            else if("known_event_after_census_return".equals(scenario))f.afterReadHook=()->f.noteObservationEvent(15);
            else if("known_event_in_snapshot_adapter".equals(scenario))f.selectionHook=()->f.noteObservationEvent(15);
            else if("selection_checked_exception".equals(scenario))f.selectionCheckedFailure=true;
            else if("unknown_event_in_snapshot_adapter".equals(scenario))f.selectionHook=()->f.noteObservationEvent(-1);
            else if("authorization_replaced".equals(scenario))f.taskAuthorization=new AuthorizationGate();
            else if("lease_retired".equals(scenario))bg.closed=true;
            else if("cancelled".equals(scenario))f.cancelled.set(true);
            else if("original_deadline_expired".equals(scenario))SystemClock.now=f.activeObservation.deadline;
            else if("node_omission".equals(scenario))g.collectionStats=counters(g,g.nativeActionNodes.size(),0,1,0);
            else if("child_omission".equals(scenario))g.collectionStats=counters(g,g.nativeActionNodes.size(),0,0,1);
            else if("ime_visible".equals(scenario))g.state=new ObservationState(TEST_SHA,ImeVisibility.VISIBLE);
            else if("missing_profile_proof".equals(scenario))g.profileWindow=null;
            else if("profile_token_replaced".equals(scenario))g.profileWindow=owned(bg.profile,96,"44444444-5555-6666-7777-888888888888");
            else if("window_id_replaced".equals(scenario))g.windowId=97;
            else if("generation_replaced".equals(scenario))g.backgroundGeneration="55555555-6666-7777-8888-999999999999";
            else if("owner_hash_replaced".equals(scenario))g.backgroundOwnerSha=NativeActionSnapshotCheckHostTest.repeat('c',64);
            else if("census_task_replaced".equals(scenario))g.nativeActionTaskId=NativeActionSnapshotCheckHostTest.repeat('d',32);
            else if("census_target_replaced".equals(scenario))g.nativeActionTargetSha=NativeActionSnapshotCheckHostTest.repeat('d',64);
            else if("census_authorization_replaced".equals(scenario))g.nativeActionAuthorizationSha=NativeActionSnapshotCheckHostTest.repeat('d',64);
            else if("census_selection_replaced".equals(scenario))g.nativeActionSelectionSha=NativeActionSnapshotCheckHostTest.repeat('d',64);
            else if("census_goal_replaced".equals(scenario))g.nativeActionGoalSha=NativeActionSnapshotCheckHostTest.repeat('d',64);
            else if("native_nodes_missing".equals(scenario))g.nativeActionNodes=null;
            else if("census_time_predates_request".equals(scenario))g.nativeActionCapturedAt=f.activeObservation.started-1;
            else if("read_before_replaced".equals(scenario))f.current=null;
        }
        g.nativeObservationComplete=completeNativeObservationGraph(g);
        if(ordinal==6&&"partial_native_census".equals(scenario)){g.truncated=true;g.nativeObservationComplete=false;}
        if(ordinal==2||ordinal==5)f.windowValue=frozenObservationWindow(g);
    }
    static void replaceNode(Graph g,String path,String key,Object value){
        for(int i=0;i<g.nativeActionNodes.size();i++){
            NativeActionSnapshotCheck.Node node=g.nativeActionNodes.get(i);
            if(path.equals(node.path)){Map<String,Object> raw=new TreeMap<String,Object>(node.v);raw.put(key,value);
                g.nativeActionNodes.set(i,new NativeActionSnapshotCheck.Node(raw));return;}
        }throw new AssertionError("synthetic mutation node absent");
    }
    static NativeActionSnapshotCheckHostTest.Fixture regionFixture(boolean after)throws Exception{
        org.json.JSONObject input=new org.json.JSONObject(new String(Files.readAllBytes(Paths.get(System.getProperty("hepta.ctrip.form.fixture"))),StandardCharsets.UTF_8));
        org.json.JSONArray rows=input.getJSONArray(after?"after":"before");
        NativeActionSnapshotCheckHostTest.Fixture value=FormPairHostTest.managedForm();value.nodes.clear();
        for(int i=0;i<rows.length();i++){Map<String,Object> node=rows.getJSONObject(i).toMap();value.nodes.put((String)node.get("path"),node);}
        return value;
    }
    static ObserverPipelineHost formFixture(final String scenario)throws Exception{
        ObserverPipelineHost f=new ObserverPipelineHost();f.lease=TEST_TASK;f.taskAuthorization=new AuthorizationGate();
        String pkg="xiaomi_scope".equals(scenario)?NativeAppGoal.XIAOMI_PACKAGE:NativeAppGoal.CTRIP_PACKAGE;
        String owner=NativeAppGoal.XIAOMI_PACKAGE.equals(pkg)?"在小米商城查询小米路由器AX3000T的价格":
                "unsupported_owner_goal".equals(scenario)?"在携程查询2026年11月17日上海到北京的单程机票，1位成人。":
                "在携程查询2026年11月17日北京到上海的单程机票，1位成人。";
        NativeAppGoal goal=NativeAppGoal.parse(owner,pkg);expect(goal!=null,"synthetic recognized owner");
        BackgroundSession bg=new BackgroundSession(15);bg.ownerSha256=goal.ownerSha256;bg.generation=TEST_GENERATION;
        if(!"ordinary_user0_scope".equals(scenario))bg.profile=target(pkg,
                "unsupported_installed_version".equals(scenario)?1780:NativeCtripFlightPage.VERSION_CODE,
                "unsupported_base_apk".equals(scenario)?NativeActionSnapshotCheckHostTest.repeat('c',64):NativeCtripFlightPage.BASE_APK_SHA256);
        BackgroundTaskTarget task=new BackgroundTaskTarget();task.route=BackgroundTaskTarget.NATIVE_APP;task.explicitSelection=true;
        task.ownerSha256=bg.ownerSha256;task.packageName=pkg;task.nativeGoal=goal;task.targetSha256=TEST_SHA;
        bg.selection.taskTarget=task;bg.selection.initialPackage=pkg;bg.selection.allowedPackages=Collections.singletonList(pkg);bg.selection.sha=TEST_SHA;
        f.taskBackground=bg;
        final boolean region=scenario.startsWith("post_region");
        final NativeActionSnapshotCheckHostTest.Fixture before=region?regionFixture(false):FormPairHostTest.managedForm();
        final NativeActionSnapshotCheckHostTest.Fixture after=region?regionFixture(true):FormPairHostTest.changedForm(before);
        boolean post=scenario.startsWith("post_")||scenario.equals("ordinary_late_change");
        boolean late=scenario.startsWith("post_late")||scenario.equals("ordinary_late_change");
        f.readHook=(graph,n)->{
            int changeAt=late?7:6;
            boolean changed=(region?n>=6:n==changeAt)&&!"unchanged_pair_keeps_legacy_mode".equals(scenario);
            populate(f,graph,changed?after:before,post?"post_fixture":scenario,n);
            if(post){
                graph.digest=changed?"changed-form":"original-form";
                if(region&&n==7){
                    if(scenario.endsWith("c_unknown"))f.noteObservationEvent(-1);
                    if(scenario.endsWith("c_boundary"))f.noteObservationEvent(15,96,NativeAppGoal.CTRIP_PACKAGE,false);
                    if(scenario.endsWith("c_after"))f.afterReadHook=()->f.noteObservationEvent(15,96,NativeAppGoal.CTRIP_PACKAGE,true);
                    if(scenario.endsWith("c_date"))replaceNode(graph,"0/0/2/5","text","11月27日后天");
                    if(scenario.endsWith("c_overlap")){replaceNode(graph,"0/6","visible",true);replaceNode(graph,"0/6","bounds",Arrays.asList(79,793,415,937));}
                    if(scenario.endsWith("c_deadline"))SystemClock.now=f.activeObservation.deadline;
                }
                if(region&&(scenario.endsWith("margin")||scenario.endsWith("encode_expiry"))){
                    if(n==5)SystemClock.now=f.activeObservation.started+9959;
                    if(n==6)SystemClock.now=f.activeObservation.started+11374;
                }
                if(changed){
                    if(scenario.endsWith("protected"))replaceNode(graph,"0/0/2/5","text","11月18日周三");
                    if(scenario.endsWith("omitted"))graph.collectionStats=counters(graph,graph.nativeActionNodes.size(),0,1,0);
                    if(scenario.endsWith("foreign"))graph.backgroundOwnerSha=NativeActionSnapshotCheckHostTest.repeat('d',64);
                    if(scenario.endsWith("untyped"))f.noteObservationEvent(-1);
                    if(scenario.endsWith("other_window"))f.noteObservationEvent(15,97,NativeAppGoal.CTRIP_PACKAGE,false);
                }
            }
        };
        return f;
    }
    NativeAppSession.PostEffectReadPermit submitted;
    void beginFormRead(){
        ObservationCallback callback=new ObservationCallback(){
            public void onObservation(PhoneObservation value){expect(isMain(),"publication off main");delivered.add(value);}
            public void onError(String error){expect(isMain(),"error off main");errors.add(error);}
        };
        long deadline=ObservationStabilityGate.requestDeadline(SystemClock.now,SystemClock.now+100000);
        if(submitted==null)observe(lease,directory,()->cancelled.get(),deadline,callback);
        else observePostEffectNative(ownedController,submitted.owner,submitted,lease,taskAuthorization,taskBackground,directory,
                ()->cancelled.get(),deadline,SystemClock.now+100000,callback,null);
        main.drain();
    }
    ObservationRequest captureFormRead()throws Exception{
        beginFormRead();ObservationRequest r=activeObservation;expect(r!=null,"read admitted");
        awaitSample();SystemClock.now+=200;
        main.drainUntil(()->pendingScreenshot!=null);
        await(()->pendingScreenshot!=null||(reads.get()%3>=2&&!observationIoBusy.get()&&observationIo.active.get()==0),"second complete sample");
        main.drainUntil(()->pendingScreenshot!=null);expect(pendingScreenshot!=null,"capture admitted");return r;
    }
    static FrozenObservationWindow changedWindow(FrozenObservationWindow w){
        return new FrozenObservationWindow(w.packageName,w.windowId,w.displayId,w.rotation,w.left,w.top,w.right,w.bottom,w.width,w.height,
                w.metadata+"changed",w.windows,w.profileWindow);
    }
    static Map<String,Object> exerciseFormScenario(final String scenario)throws Exception{
        mainThread=Thread.currentThread();expect(!observationIoBusy.get()&&observationIo.active.get()==0,"prior worker drain");
        SystemClock.now=1000;SystemClock.nextElapsedHook=null;Bitmap.made.clear();Bitmap.copyHook=null;Bitmap.encodeHook=null;Bitmap.streamHook=null;
        observationIo.reject=false;WebFlightSession.unreleased=false;
        ObserverPipelineHost f=formFixture(scenario);Map<String,Object> out=new LinkedHashMap<String,Object>();
        try{
            f.captureFormRead();f.finish();expect(f.delivered.size()==1,"actual initial complete pair must publish: "+f.errors);
            PhoneObservation before=f.current;int filesBefore=f.directory.list((parent,name)->name.endsWith(".png")).length,readsBefore=f.reads.get(),windowsBefore=f.windowChecks.get();
            f.delivered.clear();f.errors.clear();f.pendingScreenshot=null;SystemClock.now+=400;
            if("encoding_delay_keeps_original_capture_age".equals(scenario))Bitmap.encodeHook=()->SystemClock.now+=600;
            if("known_event_during_publication_check".equals(scenario))f.windowHook=()->f.noteObservationEvent(15);
            if("unknown_event_during_publication_check".equals(scenario))f.windowHook=()->f.noteObservationEvent(-1);
            if("publication_window_replaced".equals(scenario))f.windowHook=()->f.windowValue=changedWindow(f.windowValue);
            if(scenario.startsWith("post_")){
                f.ownedController=new LocalTaskController();
                f.submitted=new NativeAppSession.PostEffectReadPermit(new NativeAppSession(),f.taskAuthorization,f.lease,
                        f.taskBackground.selection,f.taskBackground.generation,15,SystemClock.now+15000);
                f.submitted.fixtureOrigin=before.id;
            }
            if(scenario.startsWith("post_late")||scenario.equals("ordinary_late_change")||scenario.equals("post_early_event_after_pair"))
                Bitmap.encodeHook=()->f.noteObservationEvent(15,96,NativeAppGoal.CTRIP_PACKAGE,true);
            if(scenario.equals("post_region_content")||scenario.contains("post_region_c_"))
                Bitmap.encodeHook=()->f.noteObservationEvent(15,96,NativeAppGoal.CTRIP_PACKAGE,true);
            if(scenario.equals("post_region_margin"))Bitmap.encodeHook=()->SystemClock.now+=200; // explicitly synthetic new encoding cost
            if(scenario.equals("post_region_encode_expiry"))Bitmap.encodeHook=()->SystemClock.now+=700;
            if(scenario.equals("post_region_proof_unknown"))f.formHistoryHashHook=()->f.noteObservationEvent(-1);
            if(scenario.equals("post_region_proof_content"))f.formHistoryHashHook=()->f.noteObservationEvent(15,96,NativeAppGoal.CTRIP_PACKAGE,true);
            if(scenario.equals("post_region_proof_corrupt"))f.formHistoryHashHook=()->{
                try{File[] files=f.directory.listFiles((parent,name)->name.endsWith("-form-history.json"));
                    Files.write(files[0].toPath(),"corrupted".getBytes(StandardCharsets.UTF_8));
                }catch(Exception failure){throw new AssertionError(failure);}
            };
            ObservationRequest request=f.captureFormRead();long captureAt=f.lastScreenshotAt;
            await(()->!observationIoBusy.get()&&observationIo.active.get()==0,"after-capture worker drain");
            if("post_late_retired".equals(scenario))f.submitted.valid=false;
            if("post_late_after_completion".equals(scenario))f.noteObservationEvent(15,96,NativeAppGoal.CTRIP_PACKAGE,true);
            if("known_event_after_publication_check".equals(scenario))f.noteObservationEvent(15);
            if("unknown_event_after_publication_check".equals(scenario))f.noteObservationEvent(-1);
            f.main.drain();
            out.put("original_frame_id",before.id);
            out.put("scenario",scenario);out.put("publications",f.delivered.size());out.put("errors",new ArrayList<String>(f.errors));
            out.put("original_deadline_preserved",request.deadline==request.started+12000);
            out.put("new_full_reads",f.reads.get()-readsBefore);out.put("new_window_checks",f.windowChecks.get()-windowsBefore);
            out.put("new_png_files",f.directory.list((parent,name)->name.endsWith(".png")).length-filesBefore);
            out.put("original_observation_retained",f.current==before||"read_before_replaced".equals(scenario)&&f.current==null);
            out.put("actual_capture_requested_at",captureAt);
            out.put("captured_at",f.delivered.isEmpty()?-1L:f.delivered.get(0).capturedElapsedMillis);
            if(!f.delivered.isEmpty()){
                Map<String,Object> capture=f.delivered.get(0).captureEvidence;
                out.put("capture_evidence",capture);
                out.put("capture_evidence_bytes",new org.json.JSONObject(capture).toString().getBytes(StandardCharsets.UTF_8).length);
                File[] histories=f.directory.listFiles((parent,name)->name.endsWith("-form-history.json"));
                out.put("full_form_artifact_count",histories.length);
                if(histories.length==1){
                    byte[] raw=Files.readAllBytes(histories[0].toPath());
                    out.put("full_form_artifact_sha256",sha(raw));out.put("full_form_artifact_bytes",raw.length);
                    out.put("full_form_artifact",new org.json.JSONObject(new String(raw,StandardCharsets.UTF_8)).toMap());
                }
            }
            out.put("no_action_work",!f.actionWorkPending()&&!f.nativeCancellationWorkPending());
        }finally{
            SystemClock.nextElapsedHook=null;f.selectionHook=null;f.afterReadHook=null;f.windowHook=null;
            // If this one endpoint intentionally cleared current, the retained
            // graph/bitmap still belong to the fixture and dispose closes them.
            f.dispose();
        }
        boolean graphs=true;for(Graph graph:f.graphs)graphs&=graph.closed;
        boolean bitmaps=true;for(Bitmap bitmap:Bitmap.made)bitmaps&=bitmap.recycled;
        boolean buffers=true;for(ScreenshotResult shot:f.shots)buffers&=shot.buffer.closes==1;
        out.put("all_graphs_closed",graphs);out.put("all_bitmaps_recycled",bitmaps);out.put("all_buffers_closed",buffers);
        out.put("workers_drained",!observationIoBusy.get()&&observationIo.active.get()==0&&observationIo.uncaught.get()==0);
        return out;
    }
    public static void main(String[] args)throws Exception{ObserverIntegrationHostTest.main(args);}
'''

if __name__=='__main__':raise SystemExit(main())
