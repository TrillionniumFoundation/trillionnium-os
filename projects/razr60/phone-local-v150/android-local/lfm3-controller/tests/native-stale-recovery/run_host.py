#!/usr/bin/env python3
"""Actual stale recovery host regression; no phone, model or Android execution."""
import argparse, json, os, re, sys
from pathlib import Path
PKG=Path('src/org/trillionnium/hepta/local')
TEST=Path('tests/native-stale-recovery')
OLD_MANIFEST='0059535d09e9a24ea972dabb32a8886565142597f0397a7984cf256dfc2d5912'
OLD_PRODUCTION={
 'NativeAppSession.java':'edf54f921343bbcada686eeb9cdbd3254f260c9a93572367021a49afa8bb5eaf',
 'LocalTaskController.java':'d8903e5e58a2343ed2c725065a8ca8edc2ec8d51ab1c98601eabce05ee19a5e2',
 'NativeActionSnapshotCheck.java':'e2fc5ccc057216b79d9931145bc681b9cf089a6437a986061120f620dd943c79',
 'HeptaAccessibilityService.java':'8238e460b3d63bb52e952072191eb4267ddf7e5456b17771cb701658001f0cfa'}
def need(value,reason):
    if not value:raise RuntimeError(reason)
def generate(code,tests,out,common):
    integration=common.module(code/'tests/native-action-integration/run_host.py','stale_integration')
    extractor=common.module(code/'tests/observation-diagnostics/run_host.py','stale_extractor')
    generated=out/'generated';generated.mkdir()
    service,controller,parts,methods,original,main=integration.generate(code,generated)
    receipt=extractor.body(service,'    private static JSONObject actionDiagnosticEvidence(ActionWork work){')
    terminal=extractor.body(service,'    JSONObject actionExecutionEvidence(String taskId){')
    projection=extractor.body(controller,'    private static java.util.Map<String,Object> nativeQueryExecution(JSONObject raw)throws Exception{')
    start=controller.index('                if(activeNativeTask!=null)activeNativeTask.modelActionOutcome(')
    call=controller[start:controller.index(';',start)+1]
    need(call.count('nativeQueryExecution(outcome.actionExecution)')==1,'actual outcome forwards Service projection once')
    prompt=re.search(r'(?ms)^    private static final String SYSTEM\s*=.*?;\s*$',controller)
    need(prompt is not None,'actual system prompt declaration');actual_prompt=prompt.group(0).rstrip()
    fragment=(tests/TEST/'RecoveryCases.fragment').read_text(encoding='utf-8')
    bridge_path=generated/'NativeActionBridgeHost.java';bridge=bridge_path.read_text(encoding='utf-8')
    extra='    private ActionExecutionState lastActionExecution;\n'+receipt+'\n'+terminal+'\n'+fragment
    need(bridge.count('    // TEST_CASES')==1,'unique bridge injection site')
    bridge_path.write_text(bridge.replace('    // TEST_CASES',extra,1),encoding='utf-8')
    common.write(generated/'NativeStaleProjectionBridge.java',
        'package org.trillionnium.hepta.local;\nimport org.json.JSONObject;\nfinal class NativeStaleProjectionBridge {\n'+projection+
        '\nstatic java.util.Map<String,Object> project(JSONObject value)throws Exception{return nativeQueryExecution(value);}\n}\n')
    common.write(generated/'NativeQueryControllerBridge.java',
        'package org.trillionnium.hepta.local;\nfinal class NativeQueryControllerBridge {\n'+
        'static java.util.Map<String,Object> project(org.json.JSONObject value)throws Exception{return NativeStaleProjectionBridge.project(value);}\n}\n')
    common.write(generated/'NativeStalePromptBridge.java',
        'package org.trillionnium.hepta.local;\nfinal class NativeStalePromptBridge {\n'+actual_prompt+
        '\nstatic String value(){return SYSTEM;}\n}\n')
    paths,bg=integration.sources(code,out)
    paths += [tests/TEST/'NativeStaleRecoveryHostTest.java',tests/'tests/native-query-reservation/NativeQueryReservationHostTest.java']
    paths=list(dict.fromkeys(p.resolve() for p in paths))
    extracted=dict(methods);extracted.update(parts)
    extracted.update(action_receipt=receipt,terminal_execution=terminal,controller_projection=projection,system_prompt=actual_prompt)
    extraction={
      'schema':'hepta.native-stale-recovery-extraction.v1','bodies_verbatim':True,
      'service_source':common.meta(code/PKG/'HeptaAccessibilityService.java'),
      'controller_source':common.meta(code/PKG/'LocalTaskController.java'),
      'methods':{k:{'bytes':len(v.encode('utf-8')),'sha256':common.sha(v.encode('utf-8'))} for k,v in extracted.items()},
      'actual_controller_call':call,'actual_controller_call_sha256':common.sha(call.encode('utf-8')),
      'case_fragment':common.meta(tests/TEST/'RecoveryCases.fragment'),'background_fixture':bg,
      'boundary':'Actual Session, ActionExecutionState, comparator and verbatim Service methods; synthetic host Android graph, model decisions, clock, installed package and journal. No Android, phone, model or business pass.'}
    common.save(out/'EXTRACTION.json',extraction)
    return paths,extraction

def main():
    parser=argparse.ArgumentParser()
    for key in ('source','output','java-home','json-jar'):parser.add_argument('--'+key,required=True,type=Path)
    parser.add_argument('--previous-source',type=Path)
    args=parser.parse_args();source=args.source.resolve();out=args.output.absolute();jdk=args.java_home.resolve();jar=args.json_jar.resolve()
    need(source.is_dir() and not out.exists() and source not in out.parents,'fresh output outside source')
    sys.dont_write_bytecode=True
    import importlib.util
    spec=importlib.util.spec_from_file_location('stale_common',source/'tests/native-query-reservation/run_host.py')
    common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
    tools=[jdk/'bin/java',jdk/'bin/javac',jdk/'lib/modules',jdk/'lib/ct.sym',jar]
    need(all(p.is_file() for p in tools),'full JDK17 and pinned JSON jar')
    need(jar.stat().st_size==78332 and common.sha(jar.read_bytes())==common.JSON_SHA,'exact JSON dependency')
    inputs=common.source_files(source)+tools
    previous=args.previous_source.resolve() if args.previous_source else None
    if previous:
        need(common.sha((previous/'SOURCE-MANIFEST.json').read_bytes())==OLD_MANIFEST,'exact R16 baseline manifest')
        for name,digest in OLD_PRODUCTION.items():need(common.sha((previous/PKG/name).read_bytes())==digest,'exact old production '+name)
        inputs+=common.source_files(previous)
    before=[common.meta(p) for p in inputs];out.mkdir(parents=True,mode=0o700)
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
    for key in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH'):env.pop(key,None)
    report={'schema':'hepta.native-stale-recovery-host-gate.v1','all_pass':False,'input_before':before,'steps':[],
      'phone_operations':0,'android_execution':False,'model_executed':False,'business_completion_verified':False,'platform_dispatch_executed':False}
    try:
        paths,extraction=generate(source,source,out,common)
        classes=out/'classes';classes.mkdir()
        flags=['--release','8','-encoding','UTF-8','-proc:none','-Xlint:all,-options','-Werror','-cp',jar]
        report['compile_inputs']=[common.meta(p) for p in paths]
        for name,argv in [('compile',[jdk/'bin/javac',*flags,'-d',classes,*paths]),
          ('recovery-cases',[jdk/'bin/java','-cp',str(classes)+os.pathsep+str(jar),
            'org.trillionnium.hepta.local.NativeStaleRecoveryHostTest',source,out/'RECOVERY-CASES.json'])]:
            result=common.stage(name,argv,out,env);report['steps'].append(result)
            need(result['exit_code']==0,'actual stage failed: '+name)
        cases=json.loads((out/'RECOVERY-CASES.json').read_text(encoding='utf-8'))
        need(cases['all_pass'] and cases['cases']==len(cases['case_names'])==len(set(cases['case_names'])) and cases['assertions']>0,
             'complete unique real case records')
        recovery_cases=cases
        result=common.stage('census-budget',[sys.executable,source/TEST/'run_budget.py',
          '--component',source,'--output',out/'budget','--java-home',jdk,'--json-jar',jar],out,env)
        report['steps'].append(result);need(result['exit_code']==0,'actual census budget probe failed')
        budget=json.loads((out/'budget/RESULT.json').read_text(encoding='utf-8'));b=budget['runtime']
        need(budget['all_pass'] and budget['source_inputs_unchanged'] and b['all_pass'] and
          b['diagnostic_count']==20 and b['compact_census_bytes_each']==262144 and
          b['projection_census_added_bytes']==0 and b['prompt_census_absent'] and b['result_session_census_absent'],
          'actual maximum twenty-census projection and terminal IO checks')
        budget_cases=dict(b,cases=1,case_names=['twenty_maximum_censuses_actual_projection_prompt_and_terminal_io'],case_assertions=[b['assertions']])
        common.save(out/'BUDGET-CASES.json',budget_cases)
        cases=dict(recovery_cases,cases=recovery_cases['cases']+1,assertions=recovery_cases['assertions']+b['assertions'],
          case_names=recovery_cases['case_names']+budget_cases['case_names'],case_assertions=recovery_cases['case_assertions']+[b['assertions']],
          groups={'recovery':recovery_cases,'census_budget':budget_cases})
        common.save(out/'CASES.json',cases);report['budget_result']=common.meta(out/'budget/RESULT.json')
        report['extra_files']={str(p.relative_to(out)):common.meta(p) for p in sorted((out/'budget').rglob('*'))
          if p.is_file() and 'classes' not in p.parts and p.suffix!='.java'}
        if previous:
            oldout=out/'previous';oldout.mkdir();oldpaths,oldextraction=generate(previous,source,oldout,common)
            oldclasses=oldout/'classes';oldclasses.mkdir()
            oldreport={'compile_inputs':[common.meta(p) for p in oldpaths],'steps':[],
                       'extraction_file':common.meta(oldout/'EXTRACTION.json')}
            report['previous']=oldreport
            result=common.stage('previous-compile',[jdk/'bin/javac',*flags,'-d',oldclasses,*oldpaths],out,env)
            oldreport['steps'].append(result);need(result['exit_code']==0,'actual R16 parent compiles before regression')
            for mode,needle in [('old-context','fresh current native domain must describe proven pre-effect stale recovery'),
                                ('old-diagnostic','actual rejected Service comparison must retain complete two-tree diagnostic')]:
                name='previous-'+mode
                result=common.stage(name,[jdk/'bin/java','-cp',str(oldclasses)+os.pathsep+str(jar),
                  'org.trillionnium.hepta.local.NativeStaleRecoveryHostTest',previous,oldout/(mode+'-CASES.json'),mode],out,env)
                oldreport['steps'].append(result)
                need(result['exit_code']==1 and needle in (out/(name+'.stderr')).read_text(encoding='utf-8'),
                     'exact old production runtime failure: '+mode)
            oldreport['both_runtime_failures_reproduced']=True
        report.update(all_pass=True,cases=cases,cases_file=common.meta(out/'CASES.json'),
          case_records={name:common.meta(out/name) for name in ('RECOVERY-CASES.json','BUDGET-CASES.json')},extraction_file=common.meta(out/'EXTRACTION.json'),
          generated_files={str(p.relative_to(out)):common.meta(p) for folder in ('generated','budget')
            for p in sorted((out/folder).rglob('*.java'))})
    except Exception as error:report['error']={'type':type(error).__name__,'message':str(error)}
    finally:
        report['input_after']=[common.meta(p) for p in inputs];report['inputs_unchanged']=before==report['input_after']
        report['all_pass']=report['all_pass'] and report['inputs_unchanged'];common.save(out/'RESULT.json',report)
    print(json.dumps({'all_pass':report['all_pass'],'cases':report.get('cases'),'error':report.get('error'),'result':str(out/'RESULT.json')}))
    return 0 if report['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
