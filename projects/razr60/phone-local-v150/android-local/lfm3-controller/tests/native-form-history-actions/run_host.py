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
    inputs=[service,extractor,Path(__file__).resolve(),template]
    tools=[jdk/'bin/javac',jdk/'bin/java',jdk/'lib/modules',jdk/'lib/ct.sym']
    before=[meta(p) for p in inputs];tool_before=[meta(p) for p in tools]
    out.mkdir(parents=True,mode=0o700)
    report={'schema':'hepta.native-form-history-actions-host.v1','all_pass':False,'stages':[],
      'inputs_before':before,'tools_before':tool_before,'android_execution':False,'phone_operations':0,
      'business_completion_verified':False,'real_comparator_executed':False,'real_guard_executed':False,
      'scope':'Two exact HA method bodies; all Android IO, captures, graph facts, comparison, claim and effects are explicit instrumented ports.'}
    env=dict(os.environ);env['PYTHONDONTWRITEBYTECODE']='1';sys.dont_write_bytecode=True
    for key in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH'):env.pop(key,None)
    try:
        spec=importlib.util.spec_from_file_location('history_actual_extractor',extractor);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        raw=service.read_text(encoding='utf-8')
        methods={'validate':module.body(raw,'    private String validate('),
                 'click_branch':module.body(raw,'            if("click".equals(action.action)){')}
        text=template.read_text(encoding='utf-8')
        for key,value in methods.items():
            marker='{{'+key+'}}';need(text.count(marker)==1,'one method marker');text=text.replace(marker,value,1)
        need('{{' not in text,'no unresolved method markers')
        generated=out/'generated/org/trillionnium/hepta/local/NativeFormHistoryActionHost.java'
        write(generated,text)
        report['extraction']={'source':meta(service),'methods':{k:{'bytes':len(v.encode('utf-8')),'sha256':sha(v.encode('utf-8'))} for k,v in methods.items()},
          'bodies_verbatim':True,'generated':meta(generated),'production_methods_rewritten':False}
        tool_port=out/'generated/org/trillionnium/hepta/background/FixedIntentTools.java'
        write(tool_port,'package org.trillionnium.hepta.background; public final class FixedIntentTools { private FixedIntentTools(){} public static boolean isTool(String action){ if("click".equals(action)||"back".equals(action)||"wait".equals(action)||"done".equals(action))return false; throw new AssertionError("FixedIntentTools protocol outside this control-flow gate"); } }\n')
        report['instrumented_tool_classifier_port']={'source':meta(tool_port),'boundary':'Only four tested non-tool action labels return false; every other action throws. No FixedIntentTools route is qualified.'}
        classes=out/'classes';classes.mkdir()
        commands=[('compile',[jdk/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all','-Werror','-d',classes,generated,tool_port]),
          ('cases',[jdk/'bin/java','-cp',classes,'org.trillionnium.hepta.local.NativeFormHistoryActionHost',out/'CASES.json'])]
        for name,argv in commands:
            start=time.monotonic_ns()
            with (out/(name+'.stdout')).open('xb') as stdout,(out/(name+'.stderr')).open('xb') as stderr:
                r=subprocess.run(list(map(str,argv)),cwd=out,env=env,stdout=stdout,stderr=stderr,timeout=120,check=False)
            report['stages'].append({'name':name,'argv':list(map(str,argv)),'exit_code':r.returncode,'elapsed_ns':time.monotonic_ns()-start,
                'stdout':meta(out/(name+'.stdout')),'stderr':meta(out/(name+'.stderr'))})
            need(r.returncode==0,'actual '+name+' failed')
        cases=json.loads((out/'CASES.json').read_text(encoding='utf-8'))
        need(cases['all_pass'] is True and cases['cases']==13 and len(set(cases['case_names']))==13,'all 13 distinct control-flow cases required')
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
