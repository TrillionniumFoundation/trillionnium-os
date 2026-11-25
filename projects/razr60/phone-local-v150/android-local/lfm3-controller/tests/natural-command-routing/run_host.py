#!/usr/bin/env python3
"""Finite route/UI contract checks over exact production code.
No Android/model/business qualification. The existing automatic-target compiler
ports are reused verbatim; no private phone history or old preference is loaded.
"""
import argparse, hashlib, importlib.util, json, os, subprocess, sys, time
from pathlib import Path
sys.dont_write_bytecode = True

PRODUCTION = (
    'src/org/trillionnium/hepta/local/BackgroundAutoTargetResolver.java',
    'src/org/trillionnium/hepta/local/MainActivity.java',
    'src/org/trillionnium/hepta/local/OwnerExplicitAppRoute.java',
)
UNCHANGED = (
    'src/org/trillionnium/hepta/local/TaskCompletionGate.java',
    'src/org/trillionnium/hepta/local/DecisionGrammar.java',
    'src/org/trillionnium/hepta/local/TaskAuthorization.java',
    'src/org/trillionnium/hepta/local/BackgroundTaskTarget.java',
    'src/org/trillionnium/hepta/local/BackgroundAutoTargetPreferences.java',
    'src/org/trillionnium/hepta/local/LocalTaskController.java',
)
def need(ok, why):
    if not ok:
        raise RuntimeError(why)
def ref(path):
    path = Path(path)
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
def write(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
def load(path):
    spec = importlib.util.spec_from_file_location('existing_auto_route_prepare', path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value
def view_source(base, overlay, view):
    # Exact Java/Python source copies satisfy the original compiler root guard.
    # Other project files remain links, never generated/writable input paths.
    # No device history/model bytes or external directory is copied/followed.
    view.mkdir()
    for directory, dirs, files in os.walk(base, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in ('.git', '__pycache__') and not (Path(directory)/d).is_symlink())
        relative = Path(directory).relative_to(base)
        target = view / relative
        target.mkdir(parents=True, exist_ok=True)
        for name in sorted(files):
            p = Path(directory)/name
            if p.is_symlink() or name.endswith('.pyc') or name.startswith('.hepta-lock-'):
                continue
            need(p.is_file(), 'regular source file required')
            if p.suffix in ('.java', '.py'):
                write(target/name, p.read_bytes())
            else:
                os.symlink(str(p), str(target/name))
    for item in sorted(overlay.rglob('*')):
        if not item.is_file():
            continue
        rel = str(item.relative_to(overlay))
        dest = view/rel
        if dest.exists() or dest.is_symlink():
            need(dest.is_file(), 'source overlay must replace only a file')
            dest.unlink()
        dest.parent.mkdir(parents=True, exist_ok=True)
        write(dest, (overlay/rel).read_bytes())
def main():
    parser = argparse.ArgumentParser()
    for name in ('source', 'overlay', 'output', 'java-home', 'json-jar'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    base, overlay, out, jdk, jar = (getattr(args, n).resolve() for n in ('source','overlay','output','java_home','json_jar'))
    need(base.is_dir() and overlay.is_dir() and not out.exists(), 'existing base/overlay and new output required')
    need(base not in out.parents and overlay not in out.parents, 'output must be outside source inputs')
    need(ref(jar)['sha256'] == '3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed', 'fixed JSON jar required')
    expected = set(PRODUCTION) | {'tests/native-auto-target/run_host.py', 'tests/natural-command-routing/NaturalCommandRoutingHostTest.java', 'tests/natural-command-routing/run_host.py'}
    actual = {str(p.relative_to(overlay)) for p in overlay.rglob('*') if p.is_file()}
    need(actual == expected, 'closed public overlay')
    out.mkdir(parents=True)
    inputs = [overlay/p for p in sorted(expected)] + [base/p for p in UNCHANGED] + [
        base/'tests/native-auto-target/run_host.py', base/'tests/native-auto-target/host_ports.py',
        base/'tests/background-session/prepare_fixture.py', base/'tests/web-flight/run_query_host_tests.py', jar]
    before = [ref(p) for p in inputs]
    report = {'schema':'hepta.natural-command-routing-host.v1','all_pass':False,
              'base_source':str(base), 'overlay':str(overlay), 'inputs_before':before,
              'stages':[], 'phone_operations':0, 'android_runtime':False,
              'model_inference':False, 'business_verified':False, 'private_phone_history_used':False}
    env = dict(os.environ, PATH=str(jdk/'bin')+':'+os.environ.get('PATH',''), PYTHONDONTWRITEBYTECODE='1')
    for key in ('CLASSPATH','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS'):
        env.pop(key, None)
    def run(name, argv):
        start=time.monotonic()
        value=subprocess.run(list(map(str,argv)),cwd=out,env=env,capture_output=True,timeout=100)
        write(out/(name+'.stdout'),value.stdout);write(out/(name+'.stderr'),value.stderr)
        report['stages'].append({'name':name,'argv':list(map(str,argv)),'exit_code':value.returncode,
            'elapsed_seconds':time.monotonic()-start,'stdout':ref(out/(name+'.stdout')),'stderr':ref(out/(name+'.stderr'))})
        need(value.returncode==0, name+' failed; original stdout/stderr retained')
    try:
        view=out/'source-view';view_source(base,overlay,view)
        existing=load(overlay/'tests/native-auto-target/run_host.py')
        compiler_inputs, metadata=existing.prepare(view,out)
        need((view/PRODUCTION[2]).resolve() in [Path(p).resolve() for p in compiler_inputs], 'existing compiler closure includes the actual new route source')
        compiler_inputs += [overlay/'tests/natural-command-routing/NaturalCommandRoutingHostTest.java']
        compiler_inputs=list(dict.fromkeys(Path(p).resolve() for p in compiler_inputs))
        report['extraction']=metadata
        report['source_bindings_before']=[]
        origins=[]
        for compiled in compiler_inputs:
            if view in compiled.parents:
                rel=compiled.relative_to(view)
                original=overlay/rel if (overlay/rel).is_file() else base/rel
                need(compiled.read_bytes()==original.read_bytes(), 'materialized full source differs from its original')
                origins.append(original)
                report['source_bindings_before'].append({'compiled':ref(compiled),'original':ref(original)})
        report['source_originals_before']=[ref(p) for p in origins]
        report['compile_inputs_before']=[ref(p) for p in compiler_inputs]
        classes=out/'classes';classes.mkdir();empty=out/'empty-sourcepath';empty.mkdir()
        run('compile',[jdk/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all,-options','-Werror',
                       '-sourcepath',empty,'-cp',jar,'-d',classes,*compiler_inputs])
        run('cases',[jdk/'bin/java','-Dhepta.fixture.host_uid='+str(os.getuid()),'-cp',str(classes)+os.pathsep+str(jar),
                     'org.trillionnium.hepta.local.NaturalCommandRoutingHostTest',out/'cases'])
        cases=json.loads((out/'cases/RESULT.json').read_text())
        report['cases']=cases
        need(cases['all_pass'],'finite route contract cases must pass')
        report['compile_inputs_after']=[ref(p) for p in compiler_inputs]
        need(report['compile_inputs_before']==report['compile_inputs_after'],'compiled sources changed')
        report['source_originals_after']=[ref(p) for p in origins]
        need(report['source_originals_before']==report['source_originals_after'],'original source dependencies changed')
        report['all_pass']=True
    except Exception as error:
        report['error']=type(error).__name__+': '+str(error)
    finally:
        report['inputs_after']=[ref(p) for p in inputs]
        report['inputs_unchanged']=report['inputs_before']==report['inputs_after']
        report['all_pass']=report['all_pass'] and report['inputs_unchanged']
        write(out/'RESULT.json',(json.dumps(report,ensure_ascii=False,indent=2)+'\n').encode())
        print(json.dumps({'all_pass':report['all_pass'],'error':report.get('error'),'result':ref(out/'RESULT.json')},ensure_ascii=False))
    return 0 if report['all_pass'] else 1
if __name__=='__main__':
    raise SystemExit(main())
