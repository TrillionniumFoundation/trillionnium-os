#!/usr/bin/env python3
"""Actual Session and verbatim Service bridge methods with explicit host IO.

One compiler invocation, retained pure matrix, then actual integration cases.
Android APIs, traversal, clock, installed app and effects remain host endpoints;
no phone, model, business, pixel or platform-dispatch success is claimed.
"""
import argparse, hashlib, importlib.util, json, os, subprocess, sys, time
from pathlib import Path

PKG=Path('src/org/trillionnium/hepta/local')
TEST=Path('tests/native-action-integration')
JSON_SHA='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
METHODS={
 'snapshot_node':'    private static NativeActionSnapshotCheck.Node snapshotNativeActionNode(',
 'windows':'    private Map<String,Object> readNativeActionWindows(',
 'begin_census':'    private void beginNativeActionCensus(',
 'collect_node':'    private static void collectNativeActionNode(',
 'finish_census':'    private void finishNativeActionCensus(',
 'guard':'    private void requireNativeActionGuard(',
 'snapshot':'    private static NativeActionSnapshotCheck.Snapshot nativeActionSnapshot(',
 'compare':'    private Map<String,Object> compareNativeAction(',
 'final_check':'    private void finalNativeActionCheck(',
 'live_chain':'    private void refreshNativeActionTargetChain(',
 'validate':'    private String validate(',
 'graph_for_action':'    private Graph graphForAction(',
 'action_check':'    private static void actionCheck(',
 'action_phase':'    private static void actionPhase(',
 'enter_effect':'    private static void enterActionEffect(',
 'effect_returned':'    private static void actionEffectReturned(',
 'refresh':'    private boolean refreshActionNode(',
 'base_signature':'    private static String baseNodeSignature(',
 'node_signature':'    private static String nodeSignature(',
 'input_hash':'    private static String inputTextHash('}

def sha(raw):return hashlib.sha256(raw).hexdigest()
def need(ok,why):
    if not ok:raise RuntimeError(why)
def meta(path):
    path=Path(path).absolute();raw=path.read_bytes()
    return {'path':str(path),'bytes':len(raw),'sha256':sha(raw),'mode':path.stat().st_mode&0o777}
def write(path,raw):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    if isinstance(raw,str):raw=raw.encode('utf-8')
    with path.open('xb') as stream:stream.write(raw)
def save(path,value):write(path,json.dumps(value,ensure_ascii=False,indent=2,sort_keys=True)+'\n')
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
def inventory(source):
    rows={}
    for path in sorted(source.rglob('*')):
        need(not path.is_symlink(),'source symlink')
        if path.is_file() and '__pycache__' not in path.parts:
            m=meta(path);rows[str(path.relative_to(source))]={k:m[k] for k in ('bytes','sha256','mode')}
    return rows
def replace(text,marker,value):
    need(text.count(marker)==1,'nonunique marker: '+marker);return text.replace(marker,value,1)

def generate(source,out):
    extraction=load(source/'tests/observation-diagnostics/run_host.py','integration_original_extractor')
    body=extraction.body;section=extraction.section
    service=(source/PKG/'HeptaAccessibilityService.java').read_text()
    controller=(source/PKG/'LocalTaskController.java').read_text()
    anchors={
      'same_window':'        boolean sameWindow(Graph other){',
      'copy_for_action':'        Graph copyForAction(String nodeId,WebRegionNativeBridge region){',
      'close_graph':'        void close(){for(NodeRef n:refs.values())n.node.recycle();refs.clear();}',
      'node_ref':'    private static final class NodeRef {',
      'action_work':'    private final class ActionWork {'}
    parts={key:body(service,value) for key,value in anchors.items()}
    parts['selected_refresh']=section(service,'            NodeRef reference=graph.refs.get(action.nodeId);','            boolean accepted;')
    parts['click_branch']=body(service,'            if("click".equals(action.action)){')
    text=(source/TEST/'NativeActionBridgeHost.template').read_text()
    for key,value in parts.items():text=replace(text,'{{'+key+'}}',value)
    methods={}
    for name,signature in METHODS.items():methods[name]=body(service,signature)
    text=replace(text,'    // ACTUAL_METHODS','\n'.join(methods.values()))
    text=replace(text,'{{bridge_cases}}',(source/TEST/'BridgeCases.fragment').read_text())
    need('{{' not in text,'unfilled bridge template');write(out/'NativeActionBridgeHost.java',text)
    original=(source/'tests/native-app-provider/NativeXiaomiModalSessionHostTest.java').read_text()
    main=body(original,'    public static void main(String[] args)throws Exception{')
    projection=replace(original,main,(source/TEST/'XiaomiGuardCases.fragment').read_text())
    projection=replace(projection,'class NativeXiaomiModalSessionHostTest','class XiaomiActionGuardHost')
    projection=replace(projection,'private NativeXiaomiModalSessionHostTest(){}','private XiaomiActionGuardHost(){}')
    write(out/'XiaomiActionGuardHost.java',projection)
    write(out/'android/util/DisplayMetrics.java','package android.util; public final class DisplayMetrics { public int widthPixels,heightPixels; }\n')
    return service,controller,parts,methods,original,main

def sources(source,out):
    query=load(source/'tests/web-flight/run_query_host_tests.py','integration_query_closure')
    bg=load(source/'tests/background-session/prepare_fixture.py','integration_background_fixture')
    bgfiles,bgrecord=bg.prepare(source,out/'platform-fixture')
    bgfiles=[p for p in bgfiles if not(p.parent.name=='json' and p.parent.parent.name=='org') and 'terminal' not in p.parts]
    paths=[source/p for p in query.PURE_PATHS if p not in ('tests/web-flight/WebFlightQueryHostTest.java','tests/native-app/legacy-boundary/NativeAppSession.java')]+bgfiles
    names=['PromptActionDomain','NativeAppEvidence','NativeAppDomain','NativeAppSession','NativeAppObservation',
      'NativeCtripFlightPage','NativeXiaomiProductPage','NativeActionSnapshotCheck','ActionExecutionState',
      'ObservationDiagnostics','ActionPolicy','PersistentActionPolicy']
    paths += [source/PKG/(name+'.java') for name in names]
    paths += [source/'tests/native-app-fixtures/NativeXmlFixture.java',
      source/'tests/native-app-provider/NativeAppProviderHostTest.java',
      source/'tests/native-app-provider/NativeResourceHomeHostTest.java',
      source/'tests/native-xiaomi-image-modal/ActualXiaomiImageModalFixture.java']
    paths += [source/TEST/(name+'.java') for name in ['IntegrationChecks','NativeActionSessionHostTest',
        'NativeActionSnapshotCheckHostTest','NativeActionIntegrationHostTest']]
    paths += sorted((out/'generated').rglob('*.java'))
    if not any(str(p).endswith('/android/util/Log.java') for p in paths):
        log=out/'generated/android/util/Log.java'
        write(log,'package android.util; public final class Log { public static int i(String tag,String text){return 0;} }\n');paths.append(log)
    paths=list(dict.fromkeys(p.resolve() for p in paths))
    for path in paths:need(path.is_file(),'missing actual compile source: '+str(path))
    return paths,bgrecord

def stage(name,argv,out,env):
    begin=time.monotonic_ns()
    with (out/(name+'.stdout')).open('xb') as stdout,(out/(name+'.stderr')).open('xb') as stderr:
        run=subprocess.run(list(map(str,argv)),cwd=out,env=env,stdout=stdout,stderr=stderr,timeout=150,check=False)
    return {'name':name,'argv':list(map(str,argv)),'exit_code':run.returncode,'elapsed_ns':time.monotonic_ns()-begin,
      'stdout':meta(out/(name+'.stdout')),'stderr':meta(out/(name+'.stderr'))}

def main():
    parser=argparse.ArgumentParser()
    for name in ('source','output','java-home','json-jar'):parser.add_argument('--'+name,required=True,type=Path)
    args=parser.parse_args();source=args.source.resolve();out=args.output.absolute();jdk=args.java_home.resolve();jar=args.json_jar.resolve()
    need(source.is_dir() and not out.exists() and source not in out.parents,'fresh output outside source required')
    toolpaths=[jdk/'bin/java',jdk/'bin/javac',jdk/'lib/modules',jdk/'lib/ct.sym',jar]
    need(all(p.is_file() for p in toolpaths),'full JDK17 and JSON tools required')
    need(jar.stat().st_size==78332 and sha(jar.read_bytes())==JSON_SHA,'pinned JSON jar required')
    before=inventory(source);tools_before=[meta(p) for p in toolpaths];out.mkdir(parents=True,mode=0o700)
    env=dict(os.environ);env['PYTHONDONTWRITEBYTECODE']='1';sys.dont_write_bytecode=True
    for key in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH'):env.pop(key,None)
    report={'schema':'hepta.native-action-integration-host-gate.v1','all_pass':False,'stages':[],
      'inputs_before':before,'tools_before':tools_before,'phone_operations':0,'android_execution':False,
      'model_executed':False,'business_completion_verified':False,'platform_dispatch_executed':False,
      'compiler_contract':'JDK17 --release8; complete actual Session plus verbatim bridge; explicit host IO'}
    try:
        generated=out/'generated';generated.mkdir()
        service,controller,parts,methods,xiaomi,oldmain=generate(source,generated)
        paths,bgrecord=sources(source,out)
        modal=source/'tests/native-xiaomi-image-modal'
        modal_record=load(modal/'run_host.py','integration_modal_fixture').fixture(modal)
        record={'schema':'hepta.native-action-integration-extraction.v1','bodies_verbatim':True,
          'source_files':{name:meta(source/PKG/(name+'.java')) for name in ('HeptaAccessibilityService','LocalTaskController','NativeAppSession','NativeActionSnapshotCheck')},
          'methods':{name:{'bytes':len(value.encode()),'sha256':sha(value.encode())} for name,value in {**parts,**methods}.items()},
          'xiaomi_original_harness':meta(source/'tests/native-app-provider/NativeXiaomiModalSessionHostTest.java'),
          'xiaomi_only_main_and_outer_name_changed':True,'xiaomi_old_main_sha256':sha(oldmain.encode()),
          'background_fixture':bgrecord,'actual_image_fixture':modal_record,
          'boundary':'Session/authorization/provider classes and Service extracted bodies are actual. Complete census rows, Android APIs, traversal, clock, installed verifier and performAction are explicit synthetic host endpoints. No PhoneObservation screenshot is fabricated as device proof.'}
        save(out/'EXTRACTION.json',record)
        report['compile_inputs']=[meta(p) for p in paths]
        classes=out/'classes';classes.mkdir()
        commands=[('compile',[jdk/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all,-options','-Werror','-cp',jar,'-d',classes,*paths]),
          ('pure-cases',[jdk/'bin/java','-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.NativeActionSnapshotCheckHostTest',out/'PURE-CASES.json']),
          ('integration-cases',[jdk/'bin/java','-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.NativeActionIntegrationHostTest',source,out/'CASES.json',out/'private'])]
        for name,command in commands:
            result=stage(name,command,out,env);report['stages'].append(result)
            need(result['exit_code']==0,'actual stage failed: '+name)
        pure=json.loads((out/'PURE-CASES.json').read_text());cases=json.loads((out/'CASES.json').read_text())
        need(pure['schema']=='hepta.native-action-snapshot-candidate-host.v1' and pure['all_pass'] is True and pure['cases']==76 and pure['assertions']==157 and len(set(pure['names']))==76,'original complete pure matrix required')
        need(cases['schema']=='hepta.native-action-integration-host.v1' and cases['all_pass'] is True and cases['cases']==len(cases['case_names'])==len(set(cases['case_names'])) and cases['assertions']>0,'actual complete unique integration cases required')
        report.update(cases=cases,pure=pure,cases_file=meta(out/'CASES.json'),pure_cases_file=meta(out/'PURE-CASES.json'),extraction_file=meta(out/'EXTRACTION.json'),
            generated_files={str(p.relative_to(generated)):meta(p) for p in sorted(generated.rglob('*.java'))},all_pass=True)
    except Exception as error:report['error']={'type':type(error).__name__,'message':str(error)}
    finally:
        report['inputs_after']=inventory(source);report['tools_after']=[meta(p) for p in toolpaths]
        report['inputs_unchanged']=report['inputs_after']==before;report['tools_unchanged']=report['tools_after']==tools_before
        report['all_pass']=report['all_pass'] and report['inputs_unchanged'] and report['tools_unchanged'];save(out/'RESULT.json',report)
    print(json.dumps({'all_pass':report['all_pass'],'result':meta(out/'RESULT.json'),'error':report.get('error')}))
    return 0 if report['all_pass'] else 1

if __name__=='__main__':raise SystemExit(main())
