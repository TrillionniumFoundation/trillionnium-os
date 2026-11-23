#!/usr/bin/env python3
"""Actual Owner GBNF emission plus independent recognition; no Android/SDK/phone."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[2])
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--release8',action='store_true')
    args=parser.parse_args();source=args.source.resolve();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    # Compile the actual dependency closure of this grammar task. Unrelated
    # process/session classes remain in the unchanged comprehensive host gate.
    names=('BackgroundTaskTarget','NativeAppGoal','NotesOwnerIntent','TaskAuthorization','ActionDecision','DecisionGrammar','ObservedTargetLabels',
           'ObservedAppLabels','ObservedScrollActions','ObservedImeEnter','AppCatalogueRanker','MobiMindContract','MobiMindPins')
    inputs=[source/'src/org/trillionnium/hepta/local'/(name+'.java') for name in names]
    inputs += [source/'src/org/trillionnium/hepta/background'/(name+'.java') for name in ('FixedIntentTools','FixedIntentTarget','ProfileIdentity','ProfileTarget')]
    inputs += [source/'src/org/trillionnium/hepta/local/web'/(name+'.java') for name in ('WebFlightGoal','WebShoppingGoal')]
    inputs.append(source/'tests/owner-grammar/OwnerGrammarHostTest.java')
    port_spec=importlib.util.spec_from_file_location('old_search_pure',source/'tests/native-app/legacy-boundary/prepare_search_pure.py')
    legacy_search=importlib.util.module_from_spec(port_spec);port_spec.loader.exec_module(legacy_search);inputs=legacy_search.add(source,inputs)
    pins={str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    for p in (source/'tests/owner-grammar/test_owner_grammar.py',source/'tests/action-grammar/gbnf_recognizer.py',
              source/'tests/native-app/legacy-boundary/prepare_search_pure.py',
              source/'src/org/trillionnium/hepta/local/NativeCalendarDateIntent.java',Path(__file__).resolve()):
        pins[str(p.relative_to(source))]=hashlib.sha256(p.read_bytes()).hexdigest()
    # This old pure Owner grammar gate has no Android NativeAppSession.
    # Only supply the new Calendar type shape: all constructors/endpoints refuse.
    # The actual MobiMindContract and Pins above remain production compiler inputs.
    constants='    static final String SCHEMA="hepta.native-calendar-select-date.v1",ACTION="calendar.select_date";'
    intent_source=source/'src/org/trillionnium/hepta/local/NativeCalendarDateIntent.java'
    if intent_source.read_text().splitlines().count(constants)!=1:
        raise RuntimeError('Actual calendar schema/action constants differ')
    port_dir=out/'calendar-legacy-types';port_dir.mkdir()
    calendar_ports={
        'NativeAppSession.java':"""package org.trillionnium.hepta.local;
final class NativeAppSession {
 private NativeAppSession(){throw unavailable();}
 static final class CalendarFacts {
  final String observationId=null,packageName=null;
  private CalendarFacts(){throw unavailable();}
 }
 static final class CalendarSource {
  final CalendarFacts facts=null;
  private CalendarSource(){throw unavailable();}
 }
 static final class CalendarGrammar {
  final String grammar=null,grammarSha256=null;
  private CalendarGrammar(){throw unavailable();}
 }
 static final class CalendarOffer {
  final CalendarSource source=null;final CalendarGrammar protocol=null;
  private CalendarOffer(){throw unavailable();}
  void claimGrammar(TaskAuthorization.Frame owner)throws Exception{throw unavailable();}
  void close(){throw unavailable();}
 }
 private static UnsupportedOperationException unavailable(){
  return new UnsupportedOperationException("Calendar model/session capability is not executed by this legacy pure Owner gate");
 }
}
""",
        'NativeCalendarDateIntent.java':"""package org.trillionnium.hepta.local;
final class NativeCalendarDateIntent {
"""+constants+"""
 private NativeCalendarDateIntent(){throw new UnsupportedOperationException("Calendar intent is not executed by this legacy pure Owner gate");}
}
"""}
    for name,body in calendar_ports.items():
        if any(p.name==name for p in inputs):raise RuntimeError('Calendar boundary would duplicate a compiler input')
        target=port_dir/name;target.write_text(body);inputs.append(target)
    generated_pins={str(port_dir/name):hashlib.sha256((port_dir/name).read_bytes()).hexdigest() for name in calendar_ports}
    classes=out/'classes';classes.mkdir();fixtures=out/'grammars';fixtures.mkdir()
    compiler=[shutil.which('javac')] if shutil.which('javac') else ['java','-m','jdk.compiler/com.sun.tools.javac.Main']
    lint='-Xlint:all' if args.release8 else '-Xlint:all,-options'
    stages=[('compile',compiler+(['--release','8'] if args.release8 else ['-source','8','-target','8'])+
             ['-encoding','UTF-8',lint,'-Werror','-d',str(classes),*map(str,inputs)]),
            ('emit',['java','-cp',str(classes),'org.trillionnium.hepta.local.OwnerGrammarHostTest',str(fixtures)]),
            ('recognize',[sys.executable,'-B',str(source/'tests/owner-grammar/test_owner_grammar.py'),str(fixtures)])]
    result={'schema':'hepta.owner-grammar-host-validation.v1','source_inputs':pins,'stages':[],
            'phone_actions':0,'android_runtime':False,'model_inference':False,
            'compiler_contract':'Java 8 API release' if args.release8 else 'Java21 supplemental syntax/class8; no Java8 API claim','passed':False}
    result['generated_calendar_type_inputs']=generated_pins
    result['calendar_boundary']={'private_throwing_constructors':True,'all_endpoints_refuse':True,
        'actual_calendar_session_executed':False,'actual_calendar_intent_executed':False,
        'actual_hash_dependency_compiled':True,'shared_legacy_session_modified':False}
    for name,argv in stages:
        start=time.monotonic();r=subprocess.run(argv,text=True,capture_output=True,timeout=90)
        (out/(name+'.stdout')).write_text(r.stdout);(out/(name+'.stderr')).write_text(r.stderr)
        result['stages'].append({'name':name,'argv':argv,'exit_code':r.returncode,'elapsed_seconds':time.monotonic()-start})
        if r.returncode:break
    result['passed']=len(result['stages'])==len(stages) and all(x['exit_code']==0 for x in result['stages'])
    if any(hashlib.sha256((source/n).read_bytes()).hexdigest()!=h for n,h in pins.items()):raise RuntimeError('source changed during tests')
    if any(hashlib.sha256(Path(p).read_bytes()).hexdigest()!=h for p,h in generated_pins.items()):
        raise RuntimeError('generated Calendar boundary changed during tests')
    (out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ('passed','compiler_contract','stages')}));return 0 if result['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
