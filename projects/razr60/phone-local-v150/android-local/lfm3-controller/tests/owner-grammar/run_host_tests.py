#!/usr/bin/env python3
"""Actual Owner GBNF emission plus independent recognition; no Android/SDK/phone."""
import argparse
import hashlib
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
    names=('NotesOwnerIntent','TaskAuthorization','ActionDecision','DecisionGrammar','ObservedTargetLabels',
           'ObservedAppLabels','ObservedScrollActions','ObservedImeEnter','AppCatalogueRanker')
    inputs=[source/'src/org/trillionnium/hepta/local'/(name+'.java') for name in names]
    inputs += [source/'src/org/trillionnium/hepta/background'/(name+'.java') for name in ('FixedIntentTools','FixedIntentTarget')]
    inputs.append(source/'tests/owner-grammar/OwnerGrammarHostTest.java')
    pins={str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    for p in (source/'tests/owner-grammar/test_owner_grammar.py',source/'tests/action-grammar/gbnf_recognizer.py'):
        pins[str(p.relative_to(source))]=hashlib.sha256(p.read_bytes()).hexdigest()
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
    for name,argv in stages:
        start=time.monotonic();r=subprocess.run(argv,text=True,capture_output=True,timeout=90)
        (out/(name+'.stdout')).write_text(r.stdout);(out/(name+'.stderr')).write_text(r.stderr)
        result['stages'].append({'name':name,'exit_code':r.returncode,'elapsed_seconds':time.monotonic()-start})
        if r.returncode:break
    result['passed']=len(result['stages'])==len(stages) and all(x['exit_code']==0 for x in result['stages'])
    if any(hashlib.sha256((source/n).read_bytes()).hexdigest()!=h for n,h in pins.items()):raise RuntimeError('source changed during tests')
    (out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ('passed','compiler_contract','stages')}));return 0 if result['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
