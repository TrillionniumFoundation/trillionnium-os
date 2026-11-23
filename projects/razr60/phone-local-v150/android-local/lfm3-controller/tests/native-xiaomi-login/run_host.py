#!/usr/bin/env python3
"""Synthetic portable native login, real Session and verbatim currentness guards.

All Android endpoints, later frames, model callbacks and receipts are host
fixtures. No phone, model, login, credential, consent or return click runs.
"""
import argparse, hashlib, importlib.util, json, os, re, sys
from pathlib import Path

PKG=Path('src/org/trillionnium/hepta/local')
TEST=Path('tests/native-xiaomi-login')
BASE_PROVIDER_SHA='c0f04ceeaf56758db268b619ad2fb4e12a0c0d70c99c1523a9964471a0681805'
BASE_MANIFEST_SHA='147df7d1e1f184abdb7e26f6502737b91f0a631adb3f353f7d25a84701fb7acf'
JSON_SHA='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module);return module

def fixture(source,generated,c):
    root=source/TEST/'fixtures';prov=json.loads((root/'PROVENANCE.json').read_text())
    for row in prov['files']:
        actual=c.meta(root/row['file']);c.need(all(actual[k]==row[k] for k in ('bytes','sha256')),'portable fixture bytes changed')
    o=json.loads((root/'synthetic-observation.json').read_text());page=json.loads((root/'synthetic-page.json').read_text())
    binding=json.loads((root/'synthetic-binding.json').read_text());m=page['frame'];owner=prov['owner']
    c.need(prov['schema']=='hepta.native-xiaomi-login-portable-fixtures.v1' and prov['phone_receipts_included'] is False and prov['device_observation_claimed'] is False,'explicit portable provenance')
    c.need(all(v['fixture_kind']=='synthetic_portable_host_fixture' and v['is_phone_receipt'] is False for v in (o,page,binding)),'only explicitly synthetic fixture inputs')
    c.need(binding['installed_app']['uid']==12345 and m['captured_elapsed_ms']==1000 and m['background_generation']=='00000000-0000-4000-8000-000000000071','synthetic UID, clock and lease')
    c.need(o['screen_width']==720 and o['screen_height']==1600,'portable normalized geometry')
    c.need(m['phone_observation_record_sha256']==c.meta(root/'synthetic-observation.json')['sha256'],'portable exact-byte frame linkage')
    c.need(m['owner_sha256']==binding['owner_sha256']==prov['owner_sha256']==c.sha(owner.encode()),'exact owner linkage')
    c.need(m['task_id']==prov['task_id']==binding['task_id'],'synthetic task linkage')
    c.need(m['observation_id']==o['observation_id']==prov['observation_id']=='10418d9e69c27340cb37c9353c35cd1d','synthetic login observation')
    c.need(m['retained_nodes']==len(o['nodes'])==13 and m['window_id']==71 and m['display_id']==7,'synthetic graph/window')
    c.need(page['baseline_expected_phase']=='unrecognized_native_page','declared baseline failure phase')
    k=o['collection'];c.need(k['visited_nodes']==16 and k['retained_nodes']==13 and k['retained_text_utf16']==76,'declared synthetic collector counters')
    c.need(k['pending_nodes_at_stop']==k['child_slots_omitted_by_traversal_limit']==k['nodes_omitted_by_node_limit']==k['nodes_omitted_by_text_limit']==0,'complete traversal')
    c.need(not o['nodes_truncated'] and k['truncation_reasons']==[] and m['actual_collection_complete'],'complete synthetic frame')
    q=lambda v:json.dumps(v,ensure_ascii=False)
    def boolean(v):
        c.need(type(v) is bool,'declared fixture boolean');return str(v).lower()
    rows=[]
    for n in o['nodes']:
        c.need(n['scroll_directions']==[] and n['native_selection_state']['observed'] is True,'declared scroll/selection tuple')
        t=n['native_tree_position'];s=n['native_selection_state'];text=n.get('text','');desc=n.get('description','');label=text if text.strip() else desc
        if not label:c.need(n['id']=='n9' and n.get('child_text_status')=='empty' and n.get('child_text_sources_complete') is True,'explicit empty checkbox label')
        values=[q(n['id']),q(n['package']),q(n['class_name']),q(n.get('view_id','')),q(text),q(desc),q(t['path']),q(t['parent_class']),q(n['node_app_tree_sha256']),q(label)]
        values+=list(map(str,n['bounds']))+[boolean(n.get('enabled',True)),boolean(n.get('password',False)),boolean(n.get('clickable',False)),boolean(n.get('editable',False)),boolean(n.get('scrollable',False))]
        values+=['Boolean.'+str(s[key]).upper() for key in ('selected','checkable','checked')]+['Collections.<String>emptySet()']
        rows.append('        nodes.add(new NativeAppEvidence.Node('+','.join(values)+'));')
    fields=('task_id','owner_sha256','execution_target_sha256','task_authorization_sha256','actual_selection_sha256','observation_id','package','background_generation','app_tree_sha256','observation_state_sha256','screen_sha256','phone_observation_record_sha256','completion_frame_sha256')
    args=','.join(q(m[key]) for key in fields)+','+','.join(map(str,[m['display_id'],m['window_id'],o['rotation'],o['screen_width'],o['screen_height']]+o['window']['bounds']))+','+str(m['captured_elapsed_ms'])+'L,false,true,nodes,1,true'
    java='package org.trillionnium.hepta.local;\nimport java.util.ArrayList;\nimport java.util.Collections;\nimport java.util.List;\nfinal class SyntheticXiaomiNativeLoginFixture {\n'
    java+='    static final String OWNER='+q(owner)+';\n    static NativeAppEvidence.Frame frame(){\n        List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>();\n'
    java+='\n'.join(rows)+'\n        return new NativeAppEvidence.Frame('+args+');\n    }\n}\n'
    c.write(generated/'SyntheticXiaomiNativeLoginFixture.java',java)
    return dict(synthetic_frame=c.meta(root/'synthetic-observation.json'),synthetic_page=c.meta(root/'synthetic-page.json'),synthetic_binding=c.meta(root/'synthetic-binding.json'),synthetic_portable_fixture=True,phone_receipt_included=False,device_observation_claimed=False,live_android_adapter_executed=False,defaults_source='Explicit portable Node DTO: absent enabled=true; password/editable/scrollable false; text/description/view_id empty. Literal public UI labels; synthetic unchecked checkbox has explicit empty complete child-text record.')

BASELINE_PROBE='''package org.trillionnium.hepta.local;
import java.util.Collections;
final class NativeLoginBaselineProbe {
 public static void main(String[] args) {
  NativeXiaomiProductPage.Page p=NativeXiaomiProductPage.inspect(NativeAppGoal.parse(SyntheticXiaomiNativeLoginFixture.OWNER,NativeAppGoal.XIAOMI_PACKAGE),SyntheticXiaomiNativeLoginFixture.frame());
  System.out.println("baseline_phase="+p.phase+" baseline_click_ids="+p.clickIds);
  if(!"native_login".equals(p.phase)||!p.clickIds.equals(Collections.singleton("n0")))throw new AssertionError("login return capability absent from compiled baseline");
 }
}
'''

def main():
    p=argparse.ArgumentParser()
    for n in ('source','output','java-home','json-jar'):p.add_argument('--'+n,required=True,type=Path)
    p.add_argument('--previous-source',type=Path);a=p.parse_args()
    source=a.source.resolve();out=a.output.absolute();jdk=a.java_home.resolve();jar=a.json_jar.resolve();sys.dont_write_bytecode=True
    c=load(source/'tests/native-xiaomi-home-loading/run_host.py','login_existing_host_utilities')
    c.need(source.is_dir() and not out.exists() and source not in out.parents,'fresh output outside source required')
    tools=[jdk/'bin/java',jdk/'bin/javac',jdk/'lib/modules',jdk/'lib/ct.sym',jar]
    c.need(all(t.is_file() for t in tools),'full JDK17 and JSON jar required');c.need(jar.stat().st_size==78332 and c.sha(jar.read_bytes())==JSON_SHA,'pinned JSON jar')
    paths_before=c.source_inputs(source)
    if a.previous_source:
        old=a.previous_source.resolve();c.need(c.sha((old/PKG/'NativeXiaomiProductPage.java').read_bytes())==BASE_PROVIDER_SHA,'exact c8a1 baseline provider')
        c.need(c.sha((old/'SOURCE-MANIFEST.json').read_bytes())==BASE_MANIFEST_SHA,'exact c8a1 baseline manifest')
        paths_before += [old/PKG/(n+'.java') for n in ('NativeAppGoal','NativeAppEvidence','NativeXiaomiProductPage')]+[old/'SOURCE-MANIFEST.json']
    paths_before+=tools;before=[c.meta(t) for t in paths_before];out.mkdir(parents=True,mode=0o700)
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
    for k in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH'):env.pop(k,None)
    report=dict(schema='hepta.native-xiaomi-login-host-gate.v1',all_pass=False,input_before=before,steps=[],phone_operations=0,android_execution=False,model_executed=False,business_completion_verified=False,platform_dispatch_executed=False)
    try:
        integration=load(source/'tests/native-action-integration/run_host.py','login_existing_compile_closure')
        extraction=load(source/'tests/observation-diagnostics/run_host.py','login_existing_body_extractor')
        generated=out/'generated';generated.mkdir();integration.generate(source,generated);portable=fixture(source,generated,c)
        harness_path=source/'tests/native-app-provider/NativeXiaomiModalSessionHostTest.java';harness=harness_path.read_text()
        old_main=extraction.body(harness,'    public static void main(String[] args)throws Exception{')
        projected=c.replace(harness,old_main,(source/TEST/'LoginSessionCases.fragment').read_text())
        projected=c.replace(projected,'class NativeXiaomiModalSessionHostTest','class NativeLoginSessionHost')
        projected=c.replace(projected,'private NativeXiaomiModalSessionHostTest(){}','private NativeLoginSessionHost(){}')
        projected=c.replace(projected,'private static final String OWNER=ActualXiaomiImageModalFixture.OWNER;','private static final String OWNER=SyntheticXiaomiNativeLoginFixture.OWNER;')
        projected=c.replace(projected,'String run;boolean installedCurrent=true;','String run;boolean installedCurrent=true,failOutcomeJournal;')
        projected,uid_count=re.subn(r'new NativeAppEvidence\.Installed\(PACKAGE,\d+,','new NativeAppEvidence.Installed(PACKAGE,12345,',projected)
        c.need(uid_count==1,'one installed UID fixture must be projected')
        old_write='                        Map<String,Object> record=NativeAppEvidence.map();record.put("leaf",leaf);'
        projected=c.replace(projected,old_write,'                        if(failOutcomeJournal&&leaf.startsWith("native-app-outcome-"))throw new IllegalStateException("synthetic outcome journal failure");\n'+old_write)
        controller_path=source/PKG/'LocalTaskController.java';controller=controller_path.read_text()
        projection=extraction.body(controller,'    private static java.util.Map<String,Object> nativeQueryExecution(JSONObject raw)throws Exception{')
        c.need(controller.count('nativeQueryExecution(outcome.actionExecution)')==1,'actual outcome-to-projection call must remain connected')
        end=projected.rfind('\n}')
        c.need(end>=0 and projected[end:].strip()=='}','complete generated session class')
        projected=projected[:end]+'\n'+projection+projected[end:]
        c.write(generated/'NativeLoginSessionHost.java',projected)
        window_path=source/'tests/native-xiaomi-home-loading/LoadingWindowBridgeHost.template';template=window_path.read_text()
        template=c.replace(template,extraction.body(template,'    public static void main(String[] args)throws Exception {'),(source/TEST/'LoginWindowCases.fragment').read_text())
        c.need('LoadingWindowBridgeHost' in template,'original window fixture class');template=template.replace('LoadingWindowBridgeHost','LoginWindowBridgeHost')
        service=(source/PKG/'HeptaAccessibilityService.java').read_text();methods={n:extraction.body(service,sig) for n,sig in c.METHODS.items()}
        c.write(generated/'LoginWindowBridgeHost.java',c.replace(template,'    // ACTUAL_METHODS','\n'.join(methods.values())))
        compile_paths,bg_record=integration.sources(source,out)
        record=dict(schema='hepta.native-xiaomi-login-extraction.v1',bodies_verbatim=True,methods={n:dict(bytes=len(v.encode()),sha256=c.sha(v.encode())) for n,v in methods.items()},service_source=c.meta(source/PKG/'HeptaAccessibilityService.java'),controller_projection=dict(source=c.meta(controller_path),bytes=len(projection.encode()),sha256=c.sha(projection.encode()),verbatim=True,outcome_call_occurrences=controller.count('nativeQueryExecution(outcome.actionExecution)')),portable_fixture=portable,original_session_harness=c.meta(harness_path),original_main_sha256=c.sha(old_main.encode()),original_window_harness=c.meta(window_path),harness_changes=['case fragments','outer class names','public example owner','synthetic installed UID','explicit host journal-failure flag','verbatim Controller action-execution projection'],production_sources=[c.meta(source/PKG/(n+'.java')) for n in ('NativeAppSession','NativeAppDomain','NativeXiaomiProductPage','LocalTaskController')],background_fixture=bg_record,boundary='Actual production parser/Session/Domain/grammar/TCG, verbatim Controller receipt projection and scope/background bodies; portable public UI shape, identities, hashes, Android endpoints, model callbacks, receipts and later frames are explicitly synthetic host fixtures.')
        c.save(out/'EXTRACTION.json',record);report['compile_inputs']=[c.meta(t) for t in compile_paths];classes=out/'classes';classes.mkdir()
        cp=str(classes)+os.pathsep+str(jar);flags=['--release','8','-encoding','UTF-8','-proc:none','-Xlint:all,-options','-Werror','-cp',jar]
        commands=[('compile',[jdk/'bin/javac',*flags,'-d',classes,*compile_paths]),('session-cases',[jdk/'bin/java','-cp',cp,'org.trillionnium.hepta.local.NativeLoginSessionHost',source/'tests/native-xiaomi-product/fixtures',out/'SESSION-CASES.json']),('window-cases',[jdk/'bin/java','-cp',cp,'org.trillionnium.hepta.local.LoginWindowBridgeHost',out/'WINDOW-CASES.json'])]
        for name,argv in commands:
            result=c.stage(name,argv,out,env);report['steps'].append(result);c.need(result['exit_code']==0,'actual stage failed: '+name)
        parts=[json.loads((out/leaf).read_text()) for leaf in ('SESSION-CASES.json','WINDOW-CASES.json')];names=[n for part in parts for n in part['case_names']]
        c.need(all(part['all_pass'] and part['cases']==len(part['case_names']) for part in parts) and len(names)==len(set(names)),'complete unique cases')
        cases=dict(schema='hepta.native-xiaomi-login-host.v1',all_pass=True,cases=len(names),assertions=sum(part['assertions'] for part in parts),case_names=names,phone_operations=0,android_execution=False,model_executed=False,business_completion_verified=False,groups=parts);c.save(out/'CASES.json',cases)
        if a.previous_source:
            previous=out/'previous-generated';previous.mkdir();fixture(source,previous,c);c.write(previous/'NativeLoginBaselineProbe.java',BASELINE_PROBE)
            old_classes=out/'previous-classes';old_classes.mkdir();old_paths=[old/PKG/(n+'.java') for n in ('NativeAppGoal','NativeAppEvidence','NativeXiaomiProductPage')]+sorted(previous.glob('*.java'))
            compiled=c.stage('previous-compile',[jdk/'bin/javac',*flags,'-d',old_classes,*old_paths],out,env);report['steps'].append(compiled);c.need(compiled['exit_code']==0,'baseline must compile before negative control')
            failed=c.stage('previous-required-capability',[jdk/'bin/java','-cp',str(old_classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.NativeLoginBaselineProbe'],out,env);report['steps'].append(failed)
            c.need(failed['exit_code']!=0 and 'baseline_phase=unrecognized_native_page baseline_click_ids=[]' in Path(failed['stdout']['path']).read_text() and 'login return capability absent from compiled baseline' in Path(failed['stderr']['path']).read_text(),'actual baseline capability failure required')
            report['baseline_negative_control']=dict(expected_failure_observed=True,compiled_actual_baseline=True,provider=c.meta(old/PKG/'NativeXiaomiProductPage.java'),result=failed)
        report.update(cases=cases,cases_file=c.meta(out/'CASES.json'),case_records={leaf:c.meta(out/leaf) for leaf in ('SESSION-CASES.json','WINDOW-CASES.json')},extraction_file=c.meta(out/'EXTRACTION.json'),generated_files={str(t.relative_to(generated)):c.meta(t) for t in sorted(generated.rglob('*.java'))},all_pass=True)
    except Exception as error:report['error']=dict(type=type(error).__name__,message=str(error))
    finally:
        report['input_after']=[c.meta(t) for t in paths_before];report['inputs_unchanged']=report['input_after']==before
        report['all_pass']=report['all_pass'] and report['inputs_unchanged'];c.save(out/'RESULT.json',report)
    print(json.dumps(dict(all_pass=report['all_pass'],result=c.meta(out/'RESULT.json'),error=report.get('error'))));return 0 if report['all_pass'] else 1

if __name__=='__main__':raise SystemExit(main())
