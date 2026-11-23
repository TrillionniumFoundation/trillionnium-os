#!/usr/bin/env python3
"""Compile and execute diagnostic stage timing without a phone or model."""
import argparse, hashlib, json, shutil, subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def pin(path):
    raw=path.read_bytes()
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--cxx',default=shutil.which('c++'));a=p.parse_args()
    out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    names=['native/stage-clock.h','tests/stage-clock-test.cpp','tools/test_stage_clock.py']
    before={name:pin(ROOT/name) for name in names}
    report={'schema':'hepta.vlm.stage-clock-host.v1','passed':False,'sources':before,
            'phone_contacted':False,'model_inference_performed':False,'commands':[]}
    try:
        if not a.cxx:raise ValueError('existing C++17 compiler required')
        commands=[('compile',[a.cxx,'-std=c++17','-O2','-Wall','-Wextra','-Werror','-pedantic',
                    '-I'+str(ROOT/'native'),ROOT/'tests/stage-clock-test.cpp','-o',out/'stage-clock-test']),
                  ('execute',[out/'stage-clock-test'])]
        for name,argv in commands:
            r=subprocess.run(list(map(str,argv)),capture_output=True,timeout=60)
            (out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr)
            report['commands'].append({'name':name,'argv':list(map(str,argv)),'exit_code':r.returncode,
                'stdout':pin(out/(name+'.stdout')),'stderr':pin(out/(name+'.stderr'))})
            if r.returncode:raise RuntimeError(name+' failed')
        report['result']=json.loads(r.stdout)
        if report['result'].get('passed') is not True or report['result'].get('checks')!=6:raise ValueError('stage clock test incomplete')
        report['sources_unchanged']=before=={name:pin(ROOT/name) for name in names}
        if not report['sources_unchanged']:raise ValueError('source changed')
        report['passed']=True
    except Exception as error:report['error']=str(error)
    finally:
        (out/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({'passed':report['passed'],'result':report.get('result'),'error':report.get('error')}))
    return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
