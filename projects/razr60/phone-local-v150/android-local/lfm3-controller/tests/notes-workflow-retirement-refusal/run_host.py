#!/usr/bin/env python3
"""Compile and verify the strict v7 request with explicitly supplied private originals.
This host test does not contact a phone, perform cleanup, or establish current absence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

ANDROID_JSON_SHA='941cc2fe5b1e42c30ceeeb25578e589a137094d5eccf84d67196eca9c29e5cdb'
MAIN='org.trillionnium.hepta.local.NotesWorkflowRetirementRefusalHostTest'
LEGACY_MAIN='org.trillionnium.hepta.local.ActualCancelledNotesVerifier'


def need(ok,why):
    if not ok:raise RuntimeError(why)


def regular(path):
    path=Path(path)
    a=path.lstat()
    need(path.is_absolute() and path.resolve()==path and stat.S_ISREG(a.st_mode) and a.st_nlink==1,
         'unaliased regular input required: '+str(path))
    raw=path.read_bytes();b=path.lstat()
    fields=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(fields(a)==fields(b) and len(raw)==a.st_size,'input changed while read')
    return raw


def ref(path):
    path=Path(path);raw=regular(path)
    return dict(path=str(path),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def put(path,raw):
    if not isinstance(raw,bytes):raw=(json.dumps(raw,indent=2,ensure_ascii=False)+'\n').encode()
    with Path(path).open('xb') as stream:stream.write(raw)
    os.chmod(path,0o600)


def input_refs(path):
    manifest=json.loads(regular(path));rows=manifest['rows']
    need(manifest['schema']=='hepta.actual-private-original-input-map.v1' and len(rows)==24,
         'explicit actual 23 originals plus current-control map required')
    need(len({r['role'] for r in rows})==24,'duplicate private input role')
    result={}
    for row in rows:
        actual=ref(row['host_path'])
        need(actual['bytes']==row['bytes'] and actual['sha256']==row['sha256'],'private original changed: '+row['role'])
        result[row['role']]=actual
    return result


def run(out,label,argv,env):
    put(out/(label+'.command.json'),argv)
    completed=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,env=env,timeout=180)
    put(out/(label+'.stdout'),completed.stdout);put(out/(label+'.stderr'),completed.stderr)
    row=dict(argv=argv,exit_code=completed.returncode,stdout=ref(out/(label+'.stdout')),stderr=ref(out/(label+'.stderr')))
    put(out/(label+'.result.json'),row)
    need(completed.returncode==0 and completed.stderr==b'','host subprocess failed: '+label)
    return completed.stdout,row


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--java-home',required=True)
    parser.add_argument('--android-json-jar',required=True)
    parser.add_argument('--dependency-classes',required=True)
    parser.add_argument('--private-input-map',required=True)
    parser.add_argument('--legacy-v6-archive')
    parser.add_argument('--legacy-v6-classes')
    args=parser.parse_args()
    source=Path(args.source);out=Path(args.output);jdk=Path(args.java_home)
    jar=Path(args.android_json_jar);deps=Path(args.dependency_classes);inputs=Path(args.private_input_map)
    for path in (source,out,jdk,jar,deps,inputs):
        need(path.is_absolute() and path.resolve()==path,'absolute unaliased explicit path required')
    need(source.is_dir() and deps.is_dir() and not out.exists(),'existing source/dependencies and new output required')
    need(bool(args.legacy_v6_archive)==bool(args.legacy_v6_classes),'legacy archive and classes must be supplied together')
    jar_ref=ref(jar);need(jar_ref['sha256']==ANDROID_JSON_SHA,'reviewed Android16 host JSON implementation required')
    before=input_refs(inputs);input_map_ref=ref(inputs)
    production=source/'src/org/trillionnium/hepta/background/PublicPersonalNotesAbsenceRecovery.java'
    test=source/'tests/notes-workflow-retirement-refusal/NotesWorkflowRetirementRefusalHostTest.java'
    source_refs=[ref(production),ref(test)]
    dep_names=[
      'org/trillionnium/hepta/local/PublicPersonalNotesRecoveryClient.class',
      'org/trillionnium/hepta/background/WorkerGenerationProof.class']
    dependencies=[]
    for name in dep_names:
        path=deps/name
        if path.is_file():dependencies.append(ref(path))
    need(any(row['path'].endswith('/PublicPersonalNotesRecoveryClient.class') for row in dependencies),
         'actual compiled recovery client dependency required')
    env=dict(os.environ)
    for key in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH'):
        env.pop(key,None)
    out.mkdir(mode=0o700,parents=True)
    classes=out/'classes';classes.mkdir(mode=0o700)
    compile_cp=os.pathsep.join(map(str,(jar,deps)))
    runtime_cp=os.pathsep.join(map(str,(classes,jar,deps)))
    javac=str(jdk/'bin/javac');java=str(jdk/'bin/java')
    probe=out/'AndroidJsonOrigin.java'
    put(probe,b'import org.json.JSONObject;\npublic final class AndroidJsonOrigin {\n public static void main(String[] args)throws Exception {\n  String s=new JSONObject("{\\"z\\":1,\\"a\\":2}").toString();\n  if(!s.equals("{\\"z\\":1,\\"a\\":2}"))throw new IllegalStateException("Android JSON order differs");\n  System.out.println(new java.io.File(JSONObject.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getCanonicalPath());\n }\n}\n')
    _,compile_row=run(out,'compile',[javac,'--release','8','-Xlint:all,-options','-Werror',
        '-encoding','UTF-8','-proc:none','-cp',compile_cp,'-d',str(classes),str(production),str(test),str(probe)],env)
    origin,origin_row=run(out,'json-origin',[java,'-cp',runtime_cp,'AndroidJsonOrigin'],env)
    need(origin.decode().strip()==str(jar),'actual JSONObject class did not load from reviewed Android jar')
    stdout,test_row=run(out,'test',[java,'-cp',runtime_cp,MAIN,str(inputs),str(out/'mutation-scratch')],env)
    actual=json.loads(stdout)
    need(actual['schema']=='hepta.notes-workflow-retirement-refusal-host.v1' and actual['all_pass'] is True
         and actual['request_roundtrip_exact'] is True and actual['normal_model_generation_validator_passed'] is True
         and actual['phone_operations']==0 and actual['current_absence_proven'] is False
         and actual['business_success_claimed'] is False,'strict v7 actual-input host test failed')
    legacy=None
    if args.legacy_v6_archive:
        archive=Path(args.legacy_v6_archive);legacy_classes=Path(args.legacy_v6_classes)
        need(archive.is_absolute() and archive.resolve()==archive and archive.is_dir()
             and legacy_classes.is_absolute() and legacy_classes.resolve()==legacy_classes and legacy_classes.is_dir(),
             'explicit actual old archive/classes required')
        legacy_verifier=ref(legacy_classes/'org/trillionnium/hepta/local/ActualCancelledNotesVerifier.class')
        legacy_cp=os.pathsep.join(map(str,(classes,jar,legacy_classes)))
        stdout,legacy_row=run(out,'old-v6',[java,'-cp',legacy_cp,LEGACY_MAIN,str(archive),
            str(out/'OLD-V6-REAL-RECEIPT-REVALIDATED.json')],env)
        old=json.loads(stdout)
        need(old['all_pass'] is True and old['actual_production_request_and_proof_validated'] is True
             and old['actual_worker_generation_proof_validated'] is True and old['phone_operations']==0
             and old['historical_model_exit_code']==143 and old['historical_business_success'] is False,
             'old real cancelled receipt regression failed')
        legacy=dict(result=ref(out/'OLD-V6-REAL-RECEIPT-REVALIDATED.json'),summary=old,
                    actual_legacy_verifier_class=legacy_verifier,command=legacy_row)
    need(before==input_refs(inputs) and input_map_ref==ref(inputs)
         and source_refs==[ref(production),ref(test)] and jar_ref==ref(jar),'actual host originals changed during verification')
    report=dict(schema='hepta.notes-workflow-retirement-refusal-runner.v1',all_pass=True,
        source_root=str(source),sources=source_refs,private_input_map=input_map_ref,private_originals=before,
        compile=compile_row,json_origin=origin_row,test=test_row,actual_summary=actual,
        android_json_jar=jar_ref,actual_json_class_origin=str(jar),dependency_classes=str(deps),
        dependency_class_refs=dependencies,old_v6_actual_receipt=legacy,
        old_v6_actual_receipt_tested=legacy is not None,all_original_bytes_unchanged=True,
        compiled_classes=[ref(p) for p in sorted(classes.rglob('*.class'))],
        phone_operations=0,current_absence_proven=False,app_recovery_completed=False)
    put(out/'HOST-VERIFIED.json',report)
    print(json.dumps(dict(all_pass=True,cases=actual['cases'],assertions=actual['assertions'],
        actual_wire_chars=actual['wire_chars'],old_v6_actual_receipt_tested=legacy is not None,
        result=ref(out/'HOST-VERIFIED.json'),phone_operations=0)))
    return 0


if __name__=='__main__':raise SystemExit(main())
