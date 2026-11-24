#!/usr/bin/env python3
"""Actual Session/Guard and verbatim Service input path over explicit Android IO.

Reuses the old action fixture without editing it. The new generated profile and
ACTION_SET_TEXT endpoints are synthetic; no phone/business result is claimed.
"""
import argparse,hashlib,importlib.util,json,os,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
PKG=Path('src/org/trillionnium/hepta/local')
TEST=Path('tests/native-xiaomi-search-input-bridge')
def load(p,n):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def sha(b):return hashlib.sha256(b).hexdigest()
def meta(p):
 p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=sha(b),mode=p.stat().st_mode&0o777)
def once(s,a,b):
 if s.count(a)!=1:raise RuntimeError('one reviewed port anchor required: '+a[:120])
 return s.replace(a,b,1)
def generate(source,out,action):
 action.generate(source,out)
 extractor=load(source/'tests/observation-diagnostics/run_host.py','input_bridge_extract')
 service=(source/PKG/'HeptaAccessibilityService.java').read_text()
 p=out/'NativeActionBridgeHost.java';s=p.read_text()
 selected=extractor.section(service,'            NodeRef reference=graph.refs.get(action.nodeId);','            boolean accepted;')
 typed=extractor.section(service,'                if(!node.isEditable()||!hasAction(node,AccessibilityNodeInfo.ACTION_SET_TEXT))',
                         '            }else if("submit".equals(action.action)){')
 wrapper='''    void typeBranch(final String taskId,final PhoneObservation expected,final ActionDecision action,final ActionWork work)throws Exception{
        if(!"type".equals(action.action))throw new AssertionError("only extracted type branch");
        final Graph graph=work.graph;final Cancellation cancel=work.cancel;
        final QualificationScopeConfig.Bound dispatchScope=work.scope;
        final TaskAuthorization.Gate authorization=work.authorization;final String modelRunId=work.state.modelRunId;
        final ActionCallback callback=outcome->{callbackAccepted=outcome.accepted;};
'''+selected+'''        boolean accepted;
'''+typed+'''    }
'''
 s=once(s,'    // MORE_DECLARATIONS',wrapper+(source/TEST/'InputActionCases.fragment').read_text())
 s=once(s,'boolean refresh=true;int obtained,recycled,effects;',
           'NativeActionBridgeHost inputOwner;boolean refresh=true;int refreshes,obtained,recycled,effects;')
 s=once(s,'boolean refresh(){if(data.beforeRefresh!=null)', 'boolean refresh(){data.refreshes++;if(data.beforeRefresh!=null)')
 s=once(s,'CharSequence getText(){return s("text");}',
           'CharSequence getText(){return data.inputOwner!=null&&b("editable")&&s("text").isEmpty()&&value("input_sha256")==null?null:s("text");}')
 s=once(s,'        static final int ACTION_CLICK=16,',
           '        static final String ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE="host_original_set_text";\n        static final int ACTION_CLICK=16,')
 endpoint='''        boolean performAction(int action,Bundle args){
            NativeActionBridgeHost owner=data.inputOwner;
            if(owner==null||!owner.inputMode||action!=ACTION_SET_TEXT)throw new AssertionError("explicit input endpoint only");
            owner.inputEffectReference=this;owner.inputEffectData=data;data.effects++;
            if(owner.apiAccepts)data.values.put("text",args.getCharSequence(ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE).toString());
            return owner.apiAccepts;
        }
'''
 s=once(s,'        @Override public boolean equals(Object o){return o instanceof AccessibilityNodeInfo',
           endpoint+'        @Override public boolean equals(Object o){return o instanceof AccessibilityNodeInfo')
 s=once(s,'        private void requireLegacyOnly(){', '''        private void requireLegacyOnly(){
            if(fixtureOwner.inputMode){
                if(selection==null||selection.profileTarget!=fixtureOwner.inputTarget||!selection.independentProfileDisplay)
                    throw new StaleObservation("explicit input profile selection changed");
                return;
            }''')
 s=once(s,'            throw new AssertionError("legacy action fixture has no historical profile RPC proof");',
           '            if(fixtureOwner.inputMode){fixtureOwner.requireInputProfile(this,proof,window,task,captured);return;}\n            throw new AssertionError("legacy action fixture has no historical profile RPC proof");')
 s=once(s,'    AccessibilityNodeInfo selectedRoot(BackgroundSession selected,GraphBudget budget){',
           '    AccessibilityNodeInfo selectedRoot(BackgroundSession selected,GraphBudget budget){\n        if(inputMode){selected.requireActive();checkReadBudget(budget);return new AccessibilityNodeInfo(fixture.data.get("0"));}')
 s=once(s,'    void requireActualProfileTask(BackgroundSession selected,PhoneObservation frame,AccessibilityWindowInfo window){',
           '    void requireActualProfileTask(BackgroundSession selected,PhoneObservation frame,AccessibilityWindowInfo window){\n        if(inputMode){requireInputProfile(selected,frame.profileWindow,window.id,1234,frame.capturedElapsedMillis);return;}')
 s=once(s,'    WindowOwnership readProfileWindow(AccessibilityNodeInfo root,BackgroundSession selected,GraphBudget budget){',
           '    WindowOwnership readProfileWindow(AccessibilityNodeInfo root,BackgroundSession selected,GraphBudget budget){\n        if(inputMode){checkReadBudget(budget);selected.requireActive();if(root.getWindowId()!=96||!root.getPackageName().equals(inputTarget.packageName))throw new StaleObservation("actual profile root changed");return inputProfileWindow();}')
 s=once(s,'return action==AccessibilityNodeInfo.ACTION_CLICK&&n.b("action_click");',
           'return action==AccessibilityNodeInfo.ACTION_SET_TEXT&&n.data.inputOwner!=null&&n.isEditable()||action==AccessibilityNodeInfo.ACTION_CLICK&&n.b("action_click");')
 s=once(s,'        // FIXTURE_METHODS',INPUT_CONSTRUCTOR)
 s=once(s,'            for(String path:values.nodes.keySet())if(!"0".equals(path)){',
           '''            if(inputMode)for(NodeData d:data.values()){d.inputOwner=service;d.scrollOverride=inputScroll((String)d.values.get("scroll_actions"));}
            for(String path:values.nodes.keySet())if(!"0".equals(path)){''')
 s=once(s,'            g.digest=hash(new JSONObject(values.nodes).toString());',
           '            if(inputMode)g.profileWindow=inputProfileWindow();\n            g.digest=hash(new JSONObject(values.nodes).toString());')
 s=once(s,'            g.nativeObservationComplete=true;finishNativeActionCensus(g,budget);return g;',
           '            g.nativeObservationComplete=true;finishNativeActionCensus(g,budget);if(inputMode)inputFrameGraph=g;return g;')
 s=once(s,'        NativeAppEvidence.Frame frame(List<NativeAppEvidence.Node> nodes,String tree)throws Exception{',
           '        NativeAppEvidence.Frame frame(List<NativeAppEvidence.Node> nodes,String tree)throws Exception{\n            if(inputMode)return inputFrame(this,nodes,tree);')
 s=once(s,'            current.capture=frame.capture;', '            current.profileWindow=frame.profileWindow;current.capture=frame.capture;')
 s=once(s,'        int effects(){return data.get(raw.target).effects;}', '''        boolean dispatchInput()throws Exception{
            String refusal=validate(task,current,action,null,()->cancelled,work);inputRefusal=refusal;
            if(refusal!=null)return false;typeBranch(task,current,action,work);return true;
        }
        int effects(){return data.get(raw.target).effects;}''')
 p.write_text(s)
 return dict(actual_selected_refresh_sha256=sha(selected.encode()),actual_type_body_sha256=sha(typed.encode()),
             type_body_verbatim=True,actual_final_checker_and_target_chain_verbatim=True,
             actual_session_and_private_guard=True,android_profile_and_node_io='explicit synthetic endpoints',
             original_action_fixture_edited=False,generated=meta(p))

INPUT_CONSTRUCTOR='''        // Additional constructor only. Old fixture constructors and cases stay intact.
        Fixture(JSONObject recording,String label)throws Exception{
            actualJournalDirectory=null;fixture=this;inputMode=true;purpose=NativeActionSnapshotCheck.SET_QUERY;
            task=id("input-task:"+label);run=id("input-model:"+label);owner="在小米商城查一下小米AX3000T的售价";
            JSONObject files=recording.getJSONObject("source_files");
            JSONObject published=new JSONObject(files.getJSONObject("a57e1dedb06a4e739823379bd472f953-native-ax.json").getString("raw_utf8"));
            JSONObject failed=new JSONObject(files.getJSONObject("failed-native-census.json").getString("raw_utf8"));
            raw=inputRaw(published.getJSONObject("first"));
            inputTarget=new ProfileTarget(new org.trillionnium.hepta.background.ProfileIdentity(10,20L,0,
                    org.trillionnium.hepta.background.ProfileIdentity.MANAGED),1010111,raw.pkg,raw.pkg+"/com.xiaomi.shop2.activity.MainActivity",20261010L,
                    Collections.singletonMap("base",NativeXiaomiSearchInputObservation.BASE_APK_SHA256),Collections.singleton(hash("synthetic-signer")));
            BackgroundTaskTarget target=BackgroundTaskTarget.resolveExplicitSelection(owner,raw.pkg,Collections.singleton(raw.pkg),inputTarget);
            selection=new org.trillionnium.hepta.local.BackgroundSession.Selection(target,true);
            authorization=TaskAuthorization.parse(owner).forExecutionSelection(selection);gate=authorization.bind(task);
            background=new BackgroundSession(service);background.taskId=task;background.generation=NativeAppProviderHostTest.GENERATION;
            background.ownerSha256=target.ownerSha256;background.selection=selection;taskAuthorization=gate;
            windowRows.add(new AccessibilityWindowInfo());SystemClock.now=1000;inputWindow=inputProfileWindow();
            session=new NativeAppSession(task,gate,selection,new NativeAppEvidence.Installed(inputTarget),
                    NativeAppObservation.selectionSha(selection),background.generation,7,
                    ()->{if(!installedCurrent)throw new IllegalStateException("host installed change");events.add("installed");},
                    (leaf,value)->{Map<String,Object> e=NativeAppEvidence.map();e.put("leaf",leaf);e.put("value",NativeAppEvidence.immutableMap(value));journal.add(e);});
            observeGraph(raw);String selected=null;
            for(Map.Entry<String,String> e:session.domain().purposes.entrySet())if(purpose.equals(e.getValue()))selected=e.getKey();
            if(selected==null)throw new AssertionError("actual input provider did not admit input: "+session.domain().evidence());
            action=ActionDecision.parse(new JSONObject().put("action","type").put("package",raw.pkg).put("observation_id",frame.observationId)
                    .put("node_id",selected).put("node_label",frame.byId.get(selected).label).put("text","AX3000T").toString(),ActionDecision.IME_ACTION_SCHEMA);
            SystemClock.now+=10;step=1;gate.check(action,run);session.beforeModelAction(step,action,run,SystemClock.now);
            NativeAppSession.ActionGuard guard=session.actionGuard(action,run,frame.observationId,SystemClock.now,SystemClock.now+8000);
            if(guard==null)throw new AssertionError("actual original input guard required");
            work=new ActionWork(task,current,run,scope,gate,background,()->cancelled,currentGraph.copyForAction(action.nodeId,null),null,SystemClock.now,SystemClock.now+8000,guard);
            work.phase("worker_started");fresh=inputRaw(new JSONObject().put("nodes",failed.getJSONObject("before").getJSONArray("native_nodes")));
            SystemClock.now+=10;events.clear();
        }
'''
def main():
 ap=argparse.ArgumentParser()
 for k in ('source','output','java-home','json-jar'):ap.add_argument('--'+k,type=Path,required=True)
 a=ap.parse_args();source=a.source.resolve();out=a.output.resolve();jdk=a.java_home.resolve();jar=a.json_jar.resolve()
 if out.exists() or source in out.parents:raise RuntimeError('fresh outside-source output required')
 out.mkdir(mode=0o700);action=load(source/'tests/native-action-integration/run_host.py','input_bridge_base')
 report=dict(schema='hepta.native-empty-input-actual-action-bridge-host.v1',all_pass=False,stages=[],phone_operations=0,android_execution=False,model_executed=False,business_completion_verified=False)
 try:
  gen=out/'generated';gen.mkdir();report['extraction']=generate(source,gen,action)
  paths,boundary=action.sources(source,out);report['base_closure']=boundary
  main_java=gen/'InputBridgeMain.java'
  main_java.write_text('''package org.trillionnium.hepta.local;
final class InputBridgeMain {public static void main(String[] a)throws Exception{
 NativeActionBridgeHost.inputCases(java.nio.file.Paths.get(a[0]));
 IntegrationChecks.finish(java.nio.file.Paths.get(a[1]),"hepta.empty-input-action-bridge-cases.v1",
 "Actual Session/Guard and verbatim Service validate/final-census/original-node-chain/type bodies over explicit Android node/profile/clock/effect ports; no phone/business qualification.");
}}\n''');paths.append(main_java)
  fixture=source/'tests/native-xiaomi-search-input/real-censuses.json'
  tracked=list(dict.fromkeys(paths+[source/PKG/'HeptaAccessibilityService.java',source/PKG/'LocalTaskController.java',source/TEST/'run_host.py',source/TEST/'InputActionCases.fragment',fixture]))
  before=[meta(p) for p in tracked];tools=[meta(p) for p in (jdk/'bin/java',jdk/'bin/javac',jdk/'lib/modules',jdk/'lib/ct.sym',jar)]
  report.update(inputs_before=before,tools_before=tools)
  if tools[-1]['sha256']!=action.JSON_SHA:raise RuntimeError('JSON jar pin')
  classes=out/'classes';classes.mkdir();args=out/'javac.args';args.write_text('\n'.join('"'+str(p)+'"' for p in paths)+'\n')
  env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
  for k in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH'):env.pop(k,None)
  commands=[('compile',[jdk/'bin/javac','--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-cp',jar,'-d',classes,'@'+str(args)]),
            ('cases',[jdk/'bin/java','-ea','-cp',str(classes)+':'+str(jar),'org.trillionnium.hepta.local.InputBridgeMain',source,out/'CASES.json'])]
  for name,argv in commands:
   begin=time.monotonic()
   with (out/(name+'.stdout')).open('xb') as stdout,(out/(name+'.stderr')).open('xb') as stderr:
    r=subprocess.run(list(map(str,argv)),cwd=out,env=env,stdout=stdout,stderr=stderr,timeout=180)
   report['stages'].append(dict(name=name,exit_code=r.returncode,seconds=time.monotonic()-begin,stdout=meta(out/(name+'.stdout')),stderr=meta(out/(name+'.stderr'))))
   if r.returncode:raise RuntimeError('actual input bridge '+name+' failed')
  report['cases']=json.loads((out/'CASES.json').read_text());report['all_pass']=report['cases']['all_pass']
  report['inputs_after']=[meta(p) for p in tracked];report['inputs_unchanged']=before==report['inputs_after']
  report['tools_unchanged']=tools==[meta(x['path']) for x in tools]
  report['all_pass'] &= report['inputs_unchanged'] and report['tools_unchanged']
 except Exception as e:report['error']=dict(type=type(e).__name__,message=str(e))
 (out/'RESULT.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps(dict(all_pass=report['all_pass'],error=report.get('error'),result=meta(out/'RESULT.json'))))
 return 0 if report['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
