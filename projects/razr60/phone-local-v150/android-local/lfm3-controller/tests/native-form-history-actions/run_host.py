#!/usr/bin/env python3
"""Verbatim HA validate and click-branch control flow, explicit instrumented ports.
Companion actual Phone/Session/Guard/comparator tests own receipt validity and
one-use authority. This gate proves required calls/order, not platform effects.
"""
import argparse,hashlib,importlib.util,json,os,subprocess,sys,time
from pathlib import Path
def sha(raw):return hashlib.sha256(raw).hexdigest()
def meta(path):
    p=Path(path).resolve();raw=p.read_bytes()
    return {'path':str(p),'bytes':len(raw),'sha256':sha(raw),'mode':p.stat().st_mode&0o777}
def need(ok,why):
    if not ok:raise RuntimeError(why)
def write(path,value):
    p=Path(path);p.parent.mkdir(parents=True,exist_ok=True)
    if isinstance(value,str):value=value.encode('utf-8')
    with p.open('xb') as stream:stream.write(value)
def save(path,value):write(path,json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
def main():
    parser=argparse.ArgumentParser()
    for name in ('source','output','java-home'):parser.add_argument('--'+name,required=True,type=Path)
    args=parser.parse_args();source=args.source.resolve();out=args.output.absolute();jdk=args.java_home.resolve()
    need(source.is_dir() and not out.exists() and source not in out.parents,'fresh external output required')
    own=Path(__file__).resolve().parent
    service=source/'src/org/trillionnium/hepta/local/HeptaAccessibilityService.java'
    extractor=source/'tests/observation-diagnostics/run_host.py'
    template=own/'NativeFormHistoryActionHost.template'
    year_fixture=own/'86b343-departure-year-refusals.json'
    goal=source/'src/org/trillionnium/hepta/local/NativeAppGoal.java'
    snapshot=source/'src/org/trillionnium/hepta/local/NativeActionSnapshotCheck.java'
    inputs=[service,extractor,Path(__file__).resolve(),template,year_fixture,goal,snapshot]
    tools=[jdk/'bin/javac',jdk/'bin/java',jdk/'lib/modules',jdk/'lib/ct.sym']
    before=[meta(p) for p in inputs];tool_before=[meta(p) for p in tools]
    out.mkdir(parents=True,mode=0o700)
    report={'schema':'hepta.native-form-history-actions-host.v1','all_pass':False,'stages':[],
      'inputs_before':before,'tools_before':tool_before,'android_execution':False,'phone_operations':0,
      'business_completion_verified':False,'real_comparator_executed':False,'real_guard_executed':False,
      'scope':'Verbatim HA validate/click and query helpers with actual NativeAppGoal and purpose constants; Android IO, captures, graph facts, comparison, claim and effects remain explicit instrumented ports.'}
    env=dict(os.environ);env['PYTHONDONTWRITEBYTECODE']='1';sys.dont_write_bytecode=True
    for key in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH'):env.pop(key,None)
    try:
        spec=importlib.util.spec_from_file_location('history_actual_extractor',extractor);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        raw=service.read_text(encoding='utf-8')
        methods={'form_purpose_guard':module.body(raw,'    private static boolean nativeFormPurposeGuard(ActionWork work){'),
                 'product_query_guard':module.body(raw,'    private static boolean nativeProductQueryGuard(ActionWork work){'),
                 'query_budget':module.body(raw,'    private final class QueryGraphBudget implements GraphBudget {'),
                 'query_read':module.body(raw,'    private Graph readNativeActionGraph('),
                 'validate':module.body(raw,'    private String validate('),
                 'click_branch':module.body(raw,'            if("click".equals(action.action)){')}
        constants=[line for line in snapshot.read_text(encoding='utf-8').splitlines() if line.startswith('    static final String OPEN=')]
        need(len(constants)==1 and 'SUBMIT_QUERY="submit_product_query"' in constants[0],'one actual purpose declaration required')
        text=template.read_text(encoding='utf-8')
        need(text.count('{{purpose_constants}}')==1,'one actual purpose declaration marker')
        text=text.replace('{{purpose_constants}}',constants[0],1)
        for key,value in methods.items():
            marker='{{'+key+'}}';need(text.count(marker)==1,'one method marker');text=text.replace(marker,value,1)
        need('{{' not in text,'no unresolved method markers')
        generated=out/'generated/org/trillionnium/hepta/local/NativeFormHistoryActionHost.java'
        write(generated,text)
        report['extraction']={'source':meta(service),'methods':{k:{'bytes':len(v.encode('utf-8')),'sha256':sha(v.encode('utf-8'))} for k,v in methods.items()},
          'bodies_verbatim':True,'generated':meta(generated),'production_methods_rewritten':False,
          'actual_goal_class':meta(goal),'purpose_constants_source':meta(snapshot),
          'purpose_constants':{'bytes':len(constants[0].encode('utf-8')),'sha256':sha(constants[0].encode('utf-8'))},
          'query_helper_stubbed':False,'new_query_authority_qualified':False,
          'form_purpose_helper_stubbed':False,'new_form_purpose_qualification_executed':False}
        tool_port=out/'generated/org/trillionnium/hepta/background/FixedIntentTools.java'
        write(tool_port,'package org.trillionnium.hepta.background; public final class FixedIntentTools { private FixedIntentTools(){} public static boolean isTool(String action){ if("click".equals(action)||"back".equals(action)||"wait".equals(action)||"done".equals(action))return false; throw new AssertionError("FixedIntentTools protocol outside this control-flow gate"); } }\n')
        report['instrumented_tool_classifier_port']={'source':meta(tool_port),'boundary':'Only four tested non-tool action labels return false; every other action throws. No FixedIntentTools route is qualified.'}
        fixture=own/'d1e685-query-refusals.json';rows=json.loads(fixture.read_bytes())['operations']
        need(hashlib.sha256(fixture.read_bytes()).hexdigest()=='919429962fb09dfb9cb4925db28c920600030e683a034309d993224f00cd2572','recorded d1e685 operation receipt projection changed')
        for row in rows:
            need(row['purpose']=='query_observed_form' and row['capture_kind']=='native_ax_form_history'
                 and row['model_proposal']=='click' and row['view_id']=='ctrip.android.view:id/bt_submit_inquire'
                 and row['guard_state']==0 and row['stale'] and row['worker_drained'] and not row['accepted']
                 and not row['dispatched'] and not row['effect_entered'] and row['original_failure_path'] is None,
                 'recorded historical refusal with unknown descendant required')
        counts=[row['phase_names'].count('graph_read') for row in rows];need(counts==[2,1,2],'recorded three failing graph stages changed')
        report['recorded_refusals']=meta(fixture)
        need(sha(year_fixture.read_bytes())=='ee385d37512221fa85363aa87702265ec409d3fb74c836b27b233ad21a70c975','recorded 86b343 projection changed')
        year_rows=json.loads(year_fixture.read_text())['operations']
        year_args=[]
        for row in year_rows:
            need(row['purpose']=='inspect_departure_year' and row['capture_kind']=='native_ax_form_history'
                 and row['model_proposal']=='click' and row['node_id']=='n33' and row['view_id']=='ctrip.android.view:id/tv_depart_date'
                 and row['target_position']['path']=='0/0/2/5' and row['protected_subtrees']==['0/0/2']
                 and row['guard_state']==0 and row['worker_drained'] and row['stale']
                 and not row['dispatched'] and not row['accepted'] and not row['effect_entered']
                 and row['original_failure_path'] is None,'recorded typed year operation, selected target and unknown failing descendant required')
            phases=row['phase_names'];last=len(phases)-1-phases[::-1].index('graph_read')
            start=row['offsets_ms'][last];duration=row['offsets_ms'][phases.index('worker_drained')]-start
            year_args.append((phases.count('graph_read'),start,duration,row['deadline_offset_ms']))
        need([v[0] for v in year_args]==[2,1,1] and all(0<v[2]<v[3]-v[1] for v in year_args),'recorded year stages and timing')
        report['recorded_year_refusals']=meta(year_fixture)
        report['year_scenario_offsets']=year_args
        classes=out/'classes';classes.mkdir()
        commands=[('compile',[jdk/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all','-Werror','-d',classes,goal,generated,tool_port]),
          ('cases',[jdk/'bin/java','-cp',classes,'org.trillionnium.hepta.local.NativeFormHistoryActionHost',out/'CASES.json',','.join(str(n) for n in counts),','.join('/'.join(map(str,row)) for row in year_args)])]
        for name,argv in commands:
            start=time.monotonic_ns()
            with (out/(name+'.stdout')).open('xb') as stdout,(out/(name+'.stderr')).open('xb') as stderr:
                r=subprocess.run(list(map(str,argv)),cwd=out,env=env,stdout=stdout,stderr=stderr,timeout=120,check=False)
            report['stages'].append({'name':name,'argv':list(map(str,argv)),'exit_code':r.returncode,'elapsed_ns':time.monotonic_ns()-start,
                'stdout':meta(out/(name+'.stdout')),'stderr':meta(out/(name+'.stderr'))})
            need(r.returncode==0,'actual '+name+' failed')
        cases=json.loads((out/'CASES.json').read_text(encoding='utf-8'))
        need(cases['all_pass'] is True and cases['cases']==44 and len(set(cases['case_names']))==44,'expected all control-flow cases')
        need(cases['real_comparator_executed'] is False and cases['real_guard_executed'] is False and cases['effects_are_instrumented_ports'] is True,'explicit test boundary')
        report.update(cases=cases,cases_file=meta(out/'CASES.json'),all_pass=True)
    except Exception as error:report['error']={'type':type(error).__name__,'message':str(error)}
    finally:
        report['inputs_after']=[meta(p) for p in inputs];report['tools_after']=[meta(p) for p in tools]
        report['inputs_unchanged']=report['inputs_after']==before;report['tools_unchanged']=report['tools_after']==tool_before
        report['all_pass']=report['all_pass'] and report['inputs_unchanged'] and report['tools_unchanged']
        save(out/'RESULT.json',report)
    print(json.dumps({'all_pass':report['all_pass'],'result':meta(out/'RESULT.json'),'error':report.get('error')},ensure_ascii=False))
    return 0 if report['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
