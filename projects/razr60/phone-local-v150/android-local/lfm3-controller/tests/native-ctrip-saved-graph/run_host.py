#!/usr/bin/env python3
"""Actual original/current Service publication with complete private archived node pairs.
All Android graph, image, clock, event and owner endpoints are explicit host fixtures.
No phone operation, historical event reconstruction or business success is claimed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import traceback
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
PKG=Path('src/org/trillionnium/hepta/local')
TEST=Path('tests/native-ctrip-saved-graph')
BASE_SERVICE_SHA='dd6dd99063e7294b6b6bdf030973a2fc27ee3403f5644c9caba43160e7760b53'
BASE_DIAGNOSTIC_SHA='208b1a7d008beb093d30dad04c4c5c4db2f860142ac26136c04891e80dbe3a9b'
BASE_CASES=['actual_280_complete_pair','content_during_census']
CANDIDATE_CASES=['actual_280_complete_pair', 'content_during_census', 'unrelated_display_during_census', 'unsealed_boundary_pair', 'unknown_during_encode', 'boundary_during_encode', 'untyped_counter_increment', 'unknown_during_census', 'boundary_during_census', 'content_after_census_endpoint', 'content_during_comparison', 'unknown_during_comparison', 'content_during_history_persist', 'unknown_during_history_persist', 'content_before_publication', 'unknown_before_publication', 'boundary_before_publication', 'wrong_current', 'missing_read_identity', 'rejected_read_identity', 'no_read_before', 'initial_mode', 'lease_closed', 'authorization_replaced', 'cancelled', 'deadline_reached', 'protected_date_changed', 'protected_ancestor_changed', 'window_changed', 'owner_changed', 'generation_changed', 'profile_token_changed', 'profile_missing', 'omitted_census', 'missing_node', 'target_changed', 'goal_changed', 'ime_visible', 'capture_clock_before_request']
LEGACY_CASES=['post_region_early', 'post_region_content', 'post_region_margin', 'post_early_classified', 'post_late_classified', 'classified_complete_pair', 'known_target_event_during_census', 'unrelated_display_event', 'encoding_delay_keeps_original_capture_age', 'unchanged_pair_keeps_legacy_mode', 'post_region_c_unknown', 'post_region_c_boundary', 'post_region_c_after', 'post_region_c_date', 'post_region_c_overlap', 'post_region_c_deadline', 'post_region_encode_expiry', 'post_region_proof_unknown', 'post_region_proof_content', 'post_region_proof_corrupt', 'post_late_retired', 'post_late_after_completion', 'post_late_protected', 'post_late_foreign', 'post_late_untyped', 'post_late_other_window', 'post_late_omitted', 'post_early_event_after_pair', 'ordinary_late_change', 'protected_form_change', 'missing_child', 'visited_count_mismatch', 'selection_checked_exception', 'known_event_after_census_return', 'known_event_in_snapshot_adapter', 'unknown_event_during_census', 'unknown_event_in_snapshot_adapter', 'known_event_during_publication_check', 'unknown_event_during_publication_check', 'known_event_after_publication_check', 'unknown_event_after_publication_check', 'authorization_replaced', 'lease_retired', 'cancelled', 'original_deadline_expired', 'partial_native_census', 'node_omission', 'child_omission', 'ime_visible', 'missing_profile_proof', 'profile_token_replaced', 'window_id_replaced', 'generation_replaced', 'owner_hash_replaced', 'census_task_replaced', 'census_target_replaced', 'census_authorization_replaced', 'census_selection_replaced', 'census_goal_replaced', 'native_nodes_missing', 'census_time_predates_request', 'unsupported_installed_version', 'unsupported_base_apk', 'unsupported_owner_goal', 'ordinary_user0_scope', 'xiaomi_scope', 'publication_window_replaced', 'read_before_replaced']
VERBATIM_ANCHORS=[
 '    private void processScreenshot(',
 '    private void acceptScreenshot(ObservationRequest request,ObservationProduct product,boolean retry,String error){',
 '    private Map<String,Object> nativeCtripFormPair(ObservationRequest request,CaptureIdentity identity,Graph after){',
 '    private NativeActionSnapshotCheck.Snapshot nativeCtripFormSnapshot(ObservationRequest request,Graph graph,ProfileTarget target){',
 '    private void persistCtripFormHistory(ObservationRequest request,ObservationProduct product)throws Exception{',
]
def need(ok,why):
    if not ok:raise RuntimeError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def meta(p):
    p=Path(p).resolve();raw=p.read_bytes()
    return {'path':str(p),'bytes':len(raw),'sha256':sha(raw)}
def save(p,v):
    with Path(p).open('x',encoding='utf-8') as f:
        f.write(json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
def module(p,name):
    spec=importlib.util.spec_from_file_location(name,p);v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v);return v
def inventory(root):
    out=[]
    for p in sorted(root.rglob('*')):
        if p.is_symlink():raise RuntimeError('source symlink not allowed')
        if p.is_file():
            v=meta(p);v['relative_path']=str(p.relative_to(root));v['mode']=oct(p.stat().st_mode&0o777);out.append(v)
    return out
def case_check(p,names):
    v=json.loads(p.read_text())
    need(v.get('all_pass') is True and v.get('cases')==len(names),'complete case count')
    need(len(set(v.get('case_names',[])))==len(names) and set(v['case_names'])==set(names),'exact declared cases')
    return v
def prepare_compile(root,out,author_source,jdk,jar,report,phase):
    bridge=module(root/'tests/native-ctrip-form-observation/run_observer_host.py','saved_bridge_'+phase)
    h=module(root/'tests/observation-diagnostics/run_host.py','saved_helpers_'+phase)
    generated=out/'generated';generated.mkdir(parents=True)
    extraction=bridge.generate(root,generated,h)
    gen=generated/'ObserverPipelineHost.java';before=gen.read_bytes()
    fragment=author_source/TEST/'SavedGraphCases.fragment'
    raw=before.decode();need(raw.endswith('}\n'),'complete generated class')
    revised=raw[:-2]+fragment.read_text()+'\n}\n'
    gen.write_text(revised)
    actual_service=(root/PKG/'HeptaAccessibilityService.java').read_text()
    methods=[]
    for anchor in VERBATIM_ANCHORS:
        body=h.body(actual_service,anchor)
        need(revised.count(body)==1,'complete actual production method exactly once: '+anchor)
        methods.append({'anchor':anchor,'bytes':len(body.encode()),'sha256':sha(body.encode())})
    extraction['saved_graph_adapter']={
        'schema':'hepta.ctrip-saved-graph-host-adapter.v1',
        'original_generated':{'bytes':len(before),'sha256':sha(before)},
        'generated':meta(gen),'fragment':meta(fragment),
        'actual_methods_compiled_verbatim':methods,
        'only_appended_host_fixture_methods':True,'production_methods_unchanged':True,
        'synthetic_android_io_profile_lease_clock_events':True,
        'historical_capture_clock_reconstructed':False,'historical_event_watermarks_reconstructed':False,
    }
    save(out/'EXTRACTION.json',extraction)
    classes=out/'classes';classes.mkdir()
    compiled=[root/PKG/n for n in bridge.JAVA]+[root/bridge.PROFILE/n for n in bridge.PROFILE_NAMES]
    compiled += [root/'tests/native-action-integration/NativeActionSnapshotCheckHostTest.java',
                 root/bridge.TEST/'FormPairHostTest.java',root/bridge.TEST/'ObserverIntegrationHostTest.java',
                 author_source/TEST/'SavedGraphHostTest.java',gen]
    compiled += h.png_sources(root)
    need(len(set(map(str,compiled)))==len(compiled),'unique complete compilation input set')
    command=[str(jdk/'bin/javac'),'--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-cp',str(jar),'-d',str(classes)]+[str(p) for p in compiled]
    one={'phase':phase,'source_root':str(root),'compile_inputs':[meta(p) for p in compiled],
         'extraction':meta(out/'EXTRACTION.json'),'generated':meta(gen),'stages':[]}
    report['executions'].append(one)
    s=h.stage('compile',command,out);one['stages'].append(s);need(s['exit_code']==0,phase+' actual compilation')
    return classes,h,one
def main():
    ap=argparse.ArgumentParser()
    for key in ('source','base-source','output','java-home','json-jar','actual-pair'):ap.add_argument('--'+key,type=Path,required=True)
    a=ap.parse_args();source=a.source.resolve();base=a.base_source.resolve();out=a.output.absolute()
    out.mkdir(parents=True,exist_ok=False)
    jdk=a.java_home.resolve();jar=a.json_jar.resolve();pair=a.actual_pair.resolve()
    need(sha((base/PKG/'HeptaAccessibilityService.java').read_bytes())==BASE_SERVICE_SHA,'exact original cc22 Service')
    need(sha((base/PKG/'ObservationDiagnostics.java').read_bytes())==BASE_DIAGNOSTIC_SHA,'exact original cc22 diagnostics')
    need(jar.stat().st_size==78332 and sha(jar.read_bytes())=='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed','original pinned JSON tool')
    tools=[jdk/'bin/java',jdk/'bin/javac',jdk/'lib/modules',jdk/'lib/ct.sym',jar]
    tool_before=[meta(p) for p in tools];pair_before=meta(pair)
    before=inventory(source);base_before=inventory(base)
    save(out/'SOURCE-INVENTORY-BEFORE.json',before);save(out/'BASE-INVENTORY-BEFORE.json',base_before)
    report={'schema':'hepta.ctrip-saved-graph-host.v1','all_pass':False,'source_root':str(source),
            'base_source_root':str(base),'tools_before':tool_before,'private_actual_pair':pair_before,
            'source_inventory_before':meta(out/'SOURCE-INVENTORY-BEFORE.json'),
            'base_inventory_before':meta(out/'BASE-INVENTORY-BEFORE.json'),'executions':[],
            'phone_operations':0,'android_execution':False,'actual_failure_branch_proved':False,
            'historical_event_watermarks_reconstructed':False,'historical_capture_clock_reconstructed':False,
            'actual_65b5_success_claimed':False,'business_completion_verified':False}
    try:
        for phase,root in [('baseline',base),('candidate',source)]:
            phase_out=out/phase;phase_out.mkdir()
            classes,h,one=prepare_compile(root,phase_out,source,jdk,jar,report,phase)
            common=[str(jdk/'bin/java'),'-Dhepta.ctrip.form.fixture='+str(root/'tests/native-ctrip-form-observation/form-region-nodes.json'),
                    '-Dhepta.ctrip.saved.pair='+str(pair),'-cp',str(classes)+os.pathsep+str(jar)]
            cases=phase_out/'CASES.json'
            s=h.stage('saved-graph-cases',common+['org.trillionnium.hepta.local.SavedGraphHostTest',str(cases),phase],phase_out)
            one['stages'].append(s);need(s['exit_code']==0,phase+' actual saved-graph cases')
            v=case_check(cases,BASE_CASES if phase=='baseline' else CANDIDATE_CASES)
            one['cases']={'report':meta(cases),'count':v['cases'],'assertions':v['assertions'],'names':v['case_names']}
            if phase=='candidate':
                legacy=phase_out/'LEGACY-CASES.json'
                s=h.stage('legacy-observer-cases',common+['org.trillionnium.hepta.local.ObserverIntegrationHostTest',str(legacy)],phase_out)
                one['stages'].append(s);need(s['exit_code']==0,'all original observer cases')
                v=case_check(legacy,LEGACY_CASES)
                one['legacy_cases']={'report':meta(legacy),'count':v['cases'],'assertions':v['assertions'],'names':v['case_names'],
                    'all_original_names_retained':True,'changed_expected_case':'ordinary_late_change',
                    'reason':'New authorized ordinary sealed post-encoding history publication; all publication/resource/identity assertions retained.'}
        report['all_pass']=True
    except Exception as error:
        report['error']={'type':type(error).__name__,'message':str(error),'traceback':traceback.format_exc()}
    finally:
        after=inventory(source);base_after=inventory(base)
        save(out/'SOURCE-INVENTORY-AFTER.json',after);save(out/'BASE-INVENTORY-AFTER.json',base_after)
        report['source_inventory_after']=meta(out/'SOURCE-INVENTORY-AFTER.json')
        report['base_inventory_after']=meta(out/'BASE-INVENTORY-AFTER.json')
        report['source_unchanged']=after==before;report['base_unchanged']=base_after==base_before
        report['tools_after']=[meta(p) for p in tools];report['private_actual_pair_after']=meta(pair)
        report['all_pass']=report['all_pass'] and after==before and base_after==base_before and report['tools_after']==tool_before and report['private_actual_pair_after']==pair_before
        save(out/'RESULT.json',report)
    print(json.dumps({'all_pass':report['all_pass'],'report':meta(out/'RESULT.json'),'error':report.get('error')},ensure_ascii=False))
    return 0 if report['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
