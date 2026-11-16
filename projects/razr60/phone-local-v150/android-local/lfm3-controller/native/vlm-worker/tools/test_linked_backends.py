#!/usr/bin/env python3
"""Test the actual production selection helper against a non-plugin host registry."""
from pathlib import Path
import argparse,hashlib,json,re,shutil,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]

def pin(path):
    b=path.read_bytes()
    return {'path':str(path),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--cxx',default=shutil.which('c++'))
    a=p.parse_args();out=a.out.resolve()
    if not a.cxx or out.exists() or out==ROOT or ROOT in out.parents:
        raise ValueError('host compiler and new output outside source required')
    if sys.platform not in ('linux','darwin'):raise ValueError('Linux/macOS host required')
    out.mkdir(parents=True,mode=0o700)
    paths=[ROOT/'native/linked-backends.h',ROOT/'native/vlm-worker.cpp',
        ROOT/'tests/linked-backends-fixture.cpp',ROOT/'tests/linked-backends-test.cpp',
        ROOT/'vendor/llama/ggml-backend.h',Path(__file__).resolve()]
    before={str(x.relative_to(ROOT)):pin(x) for x in paths}
    receipt={'schema':'hepta.vlm.linked-backend-host-run.v1','sources':before,'commands':[],
        'passed':False,'phone_contacted':False,'model_inference_performed':False}
    def run(argv,name):
        r=subprocess.run(list(map(str,argv)),capture_output=True,timeout=60)
        (out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr)
        receipt['commands'].append({'argv':list(map(str,argv)),'exit_code':r.returncode,
            'stdout':pin(out/(name+'.stdout')),'stderr':pin(out/(name+'.stderr'))})
        if r.returncode:raise RuntimeError(name+' failed')
        return r.stdout
    try:
        source=(ROOT/'native/vlm-worker.cpp').read_text()
        helper=(ROOT/'native/linked-backends.h').read_text()
        forbidden=r'\bggml_backend_(?:load|load_all|load_all_from_path|register|init_best|cpu_reg)\s*\('
        if re.search(forbidden,source+'\n'+helper):raise ValueError('plugin load, manual registration or fallback call introduced')
        if source.index('hepta_vlm::require_linked_backends()')>=source.index('BackendLifecycle backend_lifecycle;'):
            raise ValueError('linked registration must precede llama backend initialization')
        fixture=out/('liblinked-backend-fixture.dylib' if sys.platform=='darwin' else 'liblinked-backend-fixture.so')
        shared=['-dynamiclib','-Wl,-install_name,@rpath/'+fixture.name] if sys.platform=='darwin' else ['-shared','-fPIC']
        rpath='@loader_path' if sys.platform=='darwin' else '$ORIGIN'
        common=[a.cxx,'-std=c++17','-O2','-Wall','-Wextra','-Werror','-pedantic',
            '-I'+str(ROOT/'vendor/llama'),'-I'+str(ROOT/'native')]
        run([*common,*shared,ROOT/'tests/linked-backends-fixture.cpp','-o',fixture],'compile-fixture')
        executable=out/'linked-backends-test'
        extra=['-ldl'] if sys.platform=='linux' else []
        run([*common,ROOT/'tests/linked-backends-test.cpp','-L'+str(out),'-llinked-backend-fixture',
            '-Wl,-rpath,'+rpath,*extra,'-o',executable],'compile-test')
        result=json.loads(run([executable,fixture],'execute-test'))
        if result.get('passed') is not True or result.get('checks')!=23 or result.get('rejection_cases')!=13:
            raise ValueError('linked-backend test result differs')
        receipt['result']=result
        receipt['sources_unchanged']=all(pin(ROOT/name)==value for name,value in before.items())
        if not receipt['sources_unchanged']:raise ValueError('source changed during test')
        receipt['passed']=True
    except Exception as e:receipt['error']=str(e)
    finally:
        (out/'RESULT.json').write_text(json.dumps(receipt,indent=2)+'\n')
        print(json.dumps({'passed':receipt['passed'],'result':receipt.get('result'),'error':receipt.get('error')}))
    return 0 if receipt['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
