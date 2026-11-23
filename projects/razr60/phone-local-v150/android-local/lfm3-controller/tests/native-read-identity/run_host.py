#!/usr/bin/env python3
"""Verify exact identity outputs and optionally measure the production Java liveness check."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

def main():
    ap=argparse.ArgumentParser()
    for name in ('source','output','java-home','json-jar'):
        ap.add_argument('--'+name,type=Path,required=True)
    ap.add_argument('--parent-source',type=Path)
    ap.add_argument('--measure',action='store_true')
    args=ap.parse_args()
    here=Path(__file__).resolve().parent
    out=args.output.resolve()
    out.mkdir(parents=True,exist_ok=False)
    jdk=args.java_home.resolve()
    jar=args.json_jar.resolve()
    measured={}
    sources=[('current',args.source.resolve())]
    if args.parent_source:sources.insert(0,('parent',args.parent_source.resolve()))
    for label,source in sources:
        work=out/label
        work.mkdir()
        suite=work/'session'
        def run(argv,tag):
            result=subprocess.run([str(x) for x in argv],cwd=work,capture_output=True,timeout=240)
            (work/(tag+'.stdout')).write_bytes(result.stdout)
            (work/(tag+'.stderr')).write_bytes(result.stderr)
            if result.returncode:raise RuntimeError(label+' '+tag+' failed')
            return result.stdout
        run([sys.executable,'-B',source/'tests/native-search-session/run_host.py','--source',source,
             '--output',suite,'--java-home',jdk,'--json-jar',jar],'session')
        cp=os.pathsep.join(map(str,(suite/'classes',jar)))
        run([jdk/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all','-Werror',
             '-cp',cp,'-d',work,here/'NativeReadIdentityHostTest.java'],'compile')
        argv=[jdk/'bin/java','-Xms128m','-Xmx256m','-cp',str(work)+os.pathsep+cp,
              'org.trillionnium.hepta.local.NativeReadIdentityHostTest',work/'fixture']
        if args.measure:argv.append('measure')
        measured[label]=json.loads(run(argv,'identity'))
    current=measured['current']
    assert current['all_pass'] and current['assertions']>540 and current['phone_operations']==0
    equality=['profile_sha','wire','installed_apk_set_sha','owner_sha','selection_sha','goal_sha','target_sha','authorization_sha']
    if len(sources)>1:
        assert all(current[n]==measured['parent'][n] for n in equality)
    result={'all_pass':True,'assertions':current['assertions'],'checks_compared':equality if len(sources)>1 else [],
            'synthetic_android_io':True,'real_android_timing':False,'phone_operations':0,'timings':{}}
    for name,value in measured.items():
        result['timings'][name]={k:v for k,v in value.items() if k.startswith('ns_')}
    (out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))
if __name__=='__main__':main()
