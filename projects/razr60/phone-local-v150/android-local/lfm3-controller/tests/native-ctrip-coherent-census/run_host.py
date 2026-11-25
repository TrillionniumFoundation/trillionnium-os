#!/usr/bin/env python3
"""Actual captured-label and Ctrip observer methods over complete private nodes.
No Android/phone execution or historical missing-watermark reconstruction.
"""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import traceback
sys.dont_write_bytecode=True
PKG=Path('src/org/trillionnium/hepta/local')
TEST=Path('tests/native-ctrip-coherent-census')
PROTECTED = {'src/org/trillionnium/hepta/local/NativeActionSnapshotCheck.java': '400db829f8b5942d9ad4a43a1bbbc18d96fe2138964482146b8cd08fd63ea593', 'src/org/trillionnium/hepta/local/NativeCtripFormObservation.java': 'ff884b8cafe28330262e8ff27423eaf34553faed3556984a3d188876ccef02ad', 'src/org/trillionnium/hepta/local/ObservationStabilityGate.java': '426100c4f31e825c9e0f0c556c8c89d23aa45a40593978cb5fd8d5946a4beeb8', 'tests/native-ctrip-form-observation/ObserverIntegrationHostTest.java': '1ce3bf2711df668fa04c219f792b360fd10471e40f13a2a833a9d48c0299d8e2', 'tests/native-ctrip-form-observation/FormPairHostTest.java': '9874629b7c95bdbeef2942712aab6974b8cb366e32690d149624d85d0cb7e757'}

def need(value,message):
    if not value:raise RuntimeError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def meta(path):
    p=Path(path);st=p.lstat();need(stat.S_ISREG(st.st_mode) and not p.is_symlink(),'regular input '+str(p))
    raw=p.read_bytes()
    return {'path':str(p.resolve()),'bytes':len(raw),'sha256':sha(raw),'mode':format(stat.S_IMODE(st.st_mode),'04o')}
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x',encoding='utf-8') as out:json.dump(value,out,ensure_ascii=False,indent=2,sort_keys=True);out.write('\n')
    path.chmod(0o644)
def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def inventory(root):
    rows=[]
    for p in sorted(root.rglob('*')):
        need(not p.is_symlink(),'source symlink is not a complete pinned input')
        if p.is_file():
            r=meta(p);r['relative']=str(p.relative_to(root));rows.append(r)
    return rows
def once(raw,old,new):
    need(raw.count(old)==1,'one exact host fixture substitution: '+old[:100]);return raw.replace(old,new,1)
def prepare(source,out):
    h=module(source/'tests/observation-diagnostics/run_host.py','coherent_observer_extractor')
    bridge=module(source/'tests/native-ctrip-form-observation/run_observer_host.py','coherent_form_bridge')
    old=module(source/'tests/native-ctrip-child-identity/run_host.py','coherent_old_case_inventory')
    service=(source/PKG/'HeptaAccessibilityService.java').read_text()
    generated=out/'generated';generated.mkdir(parents=True)
    extraction=bridge.generate(source,generated,h)
    host=generated/'ObserverPipelineHost.java';raw=host.read_text()
    need(raw.endswith('}\n'),'complete generated observer class')
    original_generated=meta(host)
    raw=once(raw,'List<NativeActionSnapshotCheck.Node> nativeActionNodes;Map<String,Object> nativeActionWindows;',
             'List<NativeActionSnapshotCheck.Node> nativeActionNodes,nativeActionBuilding;Map<String,Object> nativeActionWindows;')
    extra={a:h.body(service,a) for a in [
        '    private boolean capturedCtripLabelsAllowed(',
        '    private static void checkReadBudget(',
    ]}
    fragment=source/TEST/'CtripCoherentCases.fragment'
    raw=raw[:-2]+'\n'.join(extra.values())+fragment.read_text()+'\n}\n'
    host.write_text(raw);host.chmod(0o644)
    methods=[]
    for anchor in [
        '    private void processScreenshot(',
        '    private void acceptScreenshot(ObservationRequest request,ObservationProduct product,boolean retry,String error){',
        '    private Map<String,Object> nativeCtripFormPair(ObservationRequest request,CaptureIdentity identity,Graph after){',
        '    private NativeActionSnapshotCheck.Snapshot nativeCtripFormSnapshot(ObservationRequest request,Graph graph,ProfileTarget target){',
        '    private static final class CtripReadDiagnostic {',
        '    private static List<Long> ctripDiagnosticMark(',
        '    private static Map<String,Object> ctripSavedGraphGate(',
        '    private static void recordCtripFormGate(',
        '    private boolean capturedCtripLabelsAllowed(',
    ]:
        body=h.body(service,anchor);need(raw.count(body)==1,'actual production method compiled once: '+anchor)
        methods.append({'anchor':anchor,'bytes':len(body.encode()),'sha256':sha(body.encode())})
    evidence=(source/PKG/'NativeAppEvidence.java').read_text()
    parts={
        'phone_node':h.body((source/PKG/'PhoneObservation.java').read_text(),'    public static final class Node {'),
        'close_graph':h.body(service,'        void close(){for(NodeRef n:refs.values())n.node.recycle();refs.clear();}'),
        'evidence_sha':h.body(evidence,'    static boolean sha('),
        'evidence_hash':h.body(evidence,'    static String hash('),
        'stale':h.body(service,'    private static final class StaleObservation extends IllegalStateException {'),
        'graph_budget':h.body(service,'    private interface GraphBudget {'),
        'label_fact':h.body(service,'    private static final class NativeSearchLabelFact {'),
        'captured_labels':h.body(service,'    private static final class NativeSearchCapturedLabels {'),
        'node_ref':h.body(service,'    private static final class NodeRef {'),
        'capture_fact':h.body(service,'    private static NativeSearchLabelFact captureNativeSearchLabelFact('),
        'apply_labels':h.body(service,'    private int applyNativeSearchCapturedLabels('),
        'recycle_references':h.body(service,'    private static void recycleNativeSearchLabelReferences('),
        'base_signature':h.body(service,'    private static String baseNodeSignature('),
        'has_action':h.body(service,'    private static boolean hasAction('),
        'check_budget':h.body(service,'    private static void checkReadBudget('),
    }
    adapter=(source/TEST/'CapturedCtripLabelHost.template').read_text()
    for name,body in parts.items():adapter=once(adapter,'{{'+name+'}}',body)
    need('{{' not in adapter,'complete captured label extraction')
    for name,body in parts.items():need(adapter.count(body)==1,'actual captured member once '+name)
    adapter_path=generated/'CapturedCtripLabelHost.java';adapter_path.write_text(adapter);adapter_path.chmod(0o644)
    extraction['coherent_census']={
        'original_generated':original_generated,'generated':meta(host),'fixture':meta(fragment),
        'actual_observer_methods':methods,'captured_adapter_generated':meta(adapter_path),
        'captured_adapter_template':meta(source/TEST/'CapturedCtripLabelHost.template'),
        'actual_captured_members':{name:{'bytes':len(body.encode()),'sha256':sha(body.encode())} for name,body in parts.items()},
        'android_bfs_read_graph_execution':False,'android_getters_synthetic':True,
        'missing_input_type_long_click_and_unrecorded_actions_synthetic':True,
        'owner_clock_event_watermark_context_synthetic':True,'archive_nodes_unchanged':True,
        'no_phone_or_action_authority':True}
    save(out/'EXTRACTION.json',extraction)
    compiled=[source/PKG/n for n in bridge.JAVA]+[source/bridge.PROFILE/n for n in bridge.PROFILE_NAMES]
    compiled += [source/'tests/native-action-integration/NativeActionSnapshotCheckHostTest.java',
        source/bridge.TEST/'FormPairHostTest.java',source/bridge.TEST/'ObserverIntegrationHostTest.java',
        source/TEST/'CtripCoherentHostTest.java',host,adapter_path]
    compiled += h.png_sources(source)
    need(len(set(map(str,compiled)))==len(compiled),'complete distinct compile input set')
    source_inputs=[source/PKG/'HeptaAccessibilityService.java',source/PKG/'PhoneObservation.java',source/PKG/'NativeAppEvidence.java',
        source/'tests/observation-pipeline/ObserverPipelineHost.template',
        source/'tests/native-ctrip-child-identity/protected_fixture.py',
        source/'tests/native-ctrip-child-identity/run_host.py',
        source/'tests/native-ctrip-form-observation/run_observer_host.py',
        source/'tests/observation-diagnostics/run_host.py',
        source/'tests/native-ctrip-form-observation/form-region-nodes.json',
        source/TEST/'run_host.py',source/TEST/'CtripCoherentHostTest.java',source/TEST/'CtripCoherentCases.fragment',
        source/TEST/'CapturedCtripLabelHost.template']
    return h,compiled,source_inputs,old.LEGACY_CASES
def cases(path,expected_count,expected_names=None):
    value=json.loads(path.read_text());need(value.get('all_pass') is True,'actual case report all_pass')
    names=value.get('case_names');need(isinstance(names,list) and len(names)==len(set(names))==expected_count,'exact unique case count')
    need(value.get('cases')==expected_count,'declared case count')
    if expected_names is not None:need(set(names)==set(expected_names),'all original unique case names preserved')
    return {'report':meta(path),'cases':value['cases'],'assertions':value['assertions'],'case_names':names}
def main():
    ap=argparse.ArgumentParser()
    for name in ('source','output','java-home','json-jar','actual-pair'):ap.add_argument('--'+name,type=Path,required=True)
    ap.add_argument('--actual-pair-sha256',required=True);ap.add_argument('--actual-pair-bytes',type=int,required=True)
    a=ap.parse_args();source=a.source.resolve();out=a.output.absolute();out.mkdir(parents=True,exist_ok=False)
    jar=a.json_jar.resolve();jdk=a.java_home.resolve();pair=a.actual_pair.resolve()
    pair_before=meta(pair);need((pair_before['bytes'],pair_before['sha256'])==(a.actual_pair_bytes,a.actual_pair_sha256),'exact externally pinned complete actual pair')
    need((jar.stat().st_size,sha(jar.read_bytes()))==(78332,'3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'),'original JSON tool')
    for relative,expected in PROTECTED.items():need(sha((source/relative).read_bytes())==expected,'unchanged complete original rule/legacy case file '+relative)
    tools=[jdk/'bin/java',jdk/'bin/javac',jdk/'lib/modules',jdk/'lib/ct.sym',jar]
    before=inventory(source);tool_before=[meta(p) for p in tools]
    save(out/'SOURCE-INVENTORY-BEFORE.json',before)
    report={'schema':'hepta.ctrip-coherent-census-host.v1','all_pass':False,'source_root':str(source),
        'source_inventory_before':meta(out/'SOURCE-INVENTORY-BEFORE.json'),'tools_before':tool_before,
        'private_pair':pair_before,'stages':[],'phone_operations':0,
        'historical_event_watermarks_or_capture_clock_reconstructed':False,'android_bfs_execution':False,
        'actual_75395_failure_predicate_reconstructed':False,'business_completion_claimed':False,
        'declared_new_cases':43,'declared_legacy_observer_cases':68,'legacy_child_41_executed':False}
    try:
        h,compiled,source_inputs,legacy=prepare(source,out)
        report['compile_inputs']=[meta(p) for p in compiled];report['source_inputs']=[meta(p) for p in source_inputs]
        report['extraction']=meta(out/'EXTRACTION.json')
        classes=out/'classes';classes.mkdir()
        command=[str(jdk/'bin/javac'),'--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-cp',str(jar),'-d',str(classes)]+list(map(str,compiled))
        step=h.stage('compile',command,out);report['stages'].append(step);need(step['exit_code']==0,'actual strict compilation')
        common=[str(jdk/'bin/java'),'-ea','-Dhepta.ctrip.form.fixture='+str(source/'tests/native-ctrip-form-observation/form-region-nodes.json'),
            '-Dhepta.ctrip.coherent.actual='+str(pair),'-cp',str(classes)+os.pathsep+str(jar)]
        new=out/'CASES.json'
        step=h.stage('coherent-census-cases',common+['org.trillionnium.hepta.local.CtripCoherentHostTest',str(new)],out)
        report['stages'].append(step)
        if new.is_file():report['new_case_report']=meta(new)
        need(step['exit_code']==0,'actual coherent census cases')
        report['new_cases']=cases(new,43)
        old=out/'LEGACY-CASES.json';step=h.stage('legacy-observer-cases',common+['org.trillionnium.hepta.local.ObserverIntegrationHostTest',str(old)],out)
        report['stages'].append(step);need(step['exit_code']==0,'original 68 observer cases')
        report['legacy_cases']=cases(old,68,legacy)
        report['all_pass']=True
    except Exception as failure:
        report['error']={'type':type(failure).__name__,'message':str(failure),'traceback':traceback.format_exc()}
    finally:
        after=inventory(source);save(out/'SOURCE-INVENTORY-AFTER.json',after)
        report['source_inventory_after']=meta(out/'SOURCE-INVENTORY-AFTER.json');report['source_unchanged']=after==before
        report['tools_after']=[meta(p) for p in tools];report['private_pair_after']=meta(pair)
        report['all_pass']=report['all_pass'] and after==before and report['tools_after']==tool_before and report['private_pair_after']==pair_before
        save(out/'RESULT.json',report)
    print(json.dumps({'all_pass':report['all_pass'],'report':meta(out/'RESULT.json'),'error':report.get('error')},ensure_ascii=False))
    return 0 if report['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
