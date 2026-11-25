#!/usr/bin/env python3
"""Host-only Request consumer checks using explicit private input mappings.
No archive fixture is embedded in this repository and no phone is contacted.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

JSON_SHA='941cc2fe5b1e42c30ceeeb25578e589a137094d5eccf84d67196eca9c29e5cdb'
MAIN='org.trillionnium.hepta.local.NotesHistoryDiagnosticConsumerHostTest'

def need(ok,why):
    if not ok:raise RuntimeError(why)

def raw(path):
    p=Path(path);a=p.lstat()
    need(p.is_absolute() and p.resolve()==p and stat.S_ISREG(a.st_mode) and a.st_nlink==1,'regular unaliased file required')
    b=p.read_bytes();z=p.lstat()
    need((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)
         and len(b)==a.st_size,'input changed while read')
    return b

def ref(path):
    b=raw(path);return dict(path=str(path),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())

def put(path,value):
    b=value if isinstance(value,bytes) else (json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
    with Path(path).open('xb') as f:f.write(b)
    os.chmod(path,0o600)
    return ref(path)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('source','output','java-home','android-json-jar','dependency-classes','private-input-map','producer-inputs'):
        p.add_argument('--'+key,required=True)
    a=p.parse_args()
    source=Path(a.source);out=Path(a.output);jdk=Path(a.java_home);jar=Path(a.android_json_jar);deps=Path(a.dependency_classes)
    mapping=Path(a.private_input_map);producer=Path(a.producer_inputs)
    for path in (source,out,jdk,jar,deps,mapping,producer):
        need(path.is_absolute() and path.resolve()==path,'absolute unaliased paths required')
    need(not out.exists() and source.is_dir() and deps.is_dir(),'new output and existing source/dependencies required')
    test=Path(__file__).resolve().with_name('NotesHistoryDiagnosticConsumerHostTest.java')
    production=source/'src/org/trillionnium/hepta/background/PublicPersonalNotesAbsenceRecovery.java'
    rows=json.loads(raw(mapping))['rows'];pm=json.loads(raw(producer))
    need(len(rows)==24 and len({r['role'] for r in rows})==24,'actual 23 originals plus current control required')
    need(pm['schema']=='hepta.notes-diagnostic-consumer-inputs.v1' and pm['producer_terminals_host_derived'] is True,'explicit producer schema')
    all_inputs=[Path(__file__).resolve(),test,production,mapping,producer]
    for row in rows:
        r=ref(Path(row['host_path']));need(r['bytes']==row['bytes'] and r['sha256']==row['sha256'],'private original mismatch');all_inputs.append(Path(row['host_path']))
    for k in ('normal','max','omitted'):
        r=ref(Path(pm[k]['path']));need(r==pm[k],'producer reference changed');all_inputs.append(Path(pm[k]['path']))
    before=[ref(p) for p in all_inputs]
    dependency_before=[ref(p) for p in sorted(deps.rglob('*.class'))]
    need(dependency_before and (deps/'org/trillionnium/hepta/local/PublicPersonalNotesRecoveryClient.class').is_file(),'actual compiled client dependency required')
    tools={k:ref(v) for k,v in [('java',jdk/'bin/java'),('javac',jdk/'bin/javac'),('modules',jdk/'lib/modules'),('json',jar)]}
    need(tools['json']['sha256']==JSON_SHA,'exact Android16 host JSON implementation required')
    env=dict(os.environ)
    for k in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH'):env.pop(k,None)
    out.mkdir(mode=0o700,parents=True);classes=out/'classes';classes.mkdir(mode=0o700)
    cp=os.pathsep.join(map(str,(jar,deps)));runtime_cp=os.pathsep.join(map(str,(classes,jar,deps)));stages=[]
    def run(label,argv):
        put(out/(label+'.command.json'),argv)
        r=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,env=env,timeout=180)
        row=dict(label=label,argv=argv,exit_code=r.returncode,stdout=put(out/(label+'.stdout'),r.stdout),stderr=put(out/(label+'.stderr'),r.stderr))
        stages.append(row);put(out/(label+'.result.json'),row)
        need(r.returncode==0 and r.stderr==b'','host command failed: '+label)
        return r.stdout
    result=dict(schema='hepta.notes-history-diagnostic-consumer-gate.v1',all_pass=False,phone_operations=0,
        current_absence_proven=False,app_recovery_completed=False,input_before=before,tools=tools,
        producer_terminals_host_derived=True,startup_current_control_host_derived=True)
    try:
        run('compile',[str(jdk/'bin/javac'),'--release','8','-Xlint:all,-options','-Werror','-encoding','UTF-8','-proc:none','-cp',cp,'-d',str(classes),str(production),str(test)])
        actual=json.loads(run('consumer',[str(jdk/'bin/java'),'-cp',runtime_cp,MAIN,str(mapping),str(producer)]))
        need(actual['schema']=='hepta.notes-history-diagnostic-consumer-host.v1' and actual['all_pass'] is True
            and actual['cases']==14 and actual['phone_operations']==0 and actual['current_absence_proven'] is False
            and actual['business_success_claimed'] is False and actual['normal_worker_generation_validator'] is True,
            'consumer proof shape differs')
        after=[ref(p) for p in all_inputs];dependency_after=[ref(p) for p in sorted(deps.rglob('*.class'))]
        need(before==after and dependency_before==dependency_after,'source/private input/dependency changed')
        result.update(all_pass=True,actual_summary=actual,input_after=after,inputs_unchanged=True,
            dependency_before=dependency_before,dependency_after=dependency_after,dependencies_unchanged=True,
            compiled_classes=[ref(p) for p in sorted(classes.rglob('*.class'))],stages=stages,
            startup_archive_provenance_not_claimed=True)
    except BaseException as error:
        result.update(error=type(error).__name__+': '+str(error),stages=stages)
        report=put(out/'RESULT.json',result);print(json.dumps(dict(all_pass=False,result=report,error=result['error'])));raise
    report=put(out/'RESULT.json',result)
    print(json.dumps(dict(all_pass=True,cases=actual['cases'],assertions=actual['assertions'],
        max_bundle_bytes=max(r['raw_bundle_bytes'] for r in actual['metrics']),
        max_wire_chars=max(r['wire_chars'] for r in actual['metrics']),
        max_command_bytes=max(r['complete_command_bytes'] for r in actual['metrics']),result=report,phone_operations=0)))
    return 0

if __name__=='__main__':raise SystemExit(main())
