#!/usr/bin/env python3
"""Compile actual C pin producer; trace policy inputs to the d125 metadata archive."""
import argparse,hashlib,json,os,pathlib,subprocess,time
ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCE_SHA='6215ce406e841f6cc9504327ea5db9c157ad59f9603414a8aa587316cc3e0e74'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def ref(path):return {'path':str(path),'bytes':path.stat().st_size,'sha256':sha(path)}
def need(ok,why):
    if not ok:raise ValueError(why)
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=pathlib.Path,required=True);ap.add_argument('--actual-metadata',type=pathlib.Path);ap.add_argument('--require-runtime-io',action='store_true');a=ap.parse_args()
    out=a.out.resolve();need(not out.exists()and ROOT not in out.parents,'fresh output outside source required');out.mkdir(parents=True)
    fixture=ROOT/'tests/runtime-pins/d125-installed-runtime-metadata.json';value=json.loads(fixture.read_text())
    need(value['schema']=='hepta.vlm.runtime-pin-metadata-fixture.v1'and value['source']['sha256']==SOURCE_SHA,'actual metadata fixture source differs')
    row=value['first_runtime'];need(row['file']=='libllama.so'and row['observed_before']==row['observed_after'],'first runtime actual metadata differs')
    actual_ref=None
    if a.actual_metadata is not None:
        b=a.actual_metadata.read_bytes();need(len(b)==30517 and hashlib.sha256(b).hexdigest()==SOURCE_SHA,'actual phone metadata original changed')
        actual=json.loads(b);need(actual['complete']is True and actual['task_id']=='d125b831f0e44893a0a98df612ea876e'
           and actual['libraries'][0]==row and actual['current_task_control_result_owner_unchanged']is True,'fixture is not this actual phone metadata')
        actual_ref=ref(a.actual_metadata)
    native=ROOT/'native';source_paths=[ROOT/'tests/runtime-pin-test.c',fixture,pathlib.Path(__file__),*sorted(native.glob('*'))]
    inputs=[ref(p)for p in source_paths if p.is_file()];cc=os.environ.get('CC','cc');exe=out/'runtime-pin-test'
    compile_argv=[cc,'-std=c11','-O2','-Wall','-Wextra','-Werror',str(ROOT/'tests/runtime-pin-test.c'),'-o',str(exe)]
    started=time.monotonic();p=subprocess.run(compile_argv,capture_output=True,timeout=90)
    (out/'compile.stdout').write_bytes(p.stdout);(out/'compile.stderr').write_bytes(p.stderr);need(p.returncode==0,'production C test compile failed: '+p.stderr.decode()[-3000:])
    st=row['observed_before'];keys=('device','inode','mode','uid','gid','nlink','bytes','mtime_seconds','ctime_seconds')
    argv=[str(exe)]+[str(st[k])for k in keys];p=subprocess.run(argv,capture_output=True,timeout=60)
    (out/'run.stdout').write_bytes(p.stdout);(out/'run.stderr').write_bytes(p.stderr);need(p.returncode==0,'production C cases failed: '+p.stderr.decode()[-3000:])
    result=json.loads(p.stdout);need(result['passed']is True and result['policy_cases']==17 and result['io_cases']in(4,12),'native case membership differs')
    if a.require_runtime_io:need(result['runtime_real_file_io_verified']is True and result['io_cases']==12,'actual runtime owner/IO could not be verified on this host')
    need(all(ref(pathlib.Path(r['path']))==r for r in inputs),'producer input changed during test')
    report={'schema':'hepta.vlm.runtime-pin-host-run.v1','passed':True,'source_inputs':inputs,'actual_phone_metadata':actual_ref,
      'actual_phone_metadata_replayed':actual_ref is not None,'metadata_policy_is_struct_replay':True,'runtime_file_io_is_actual_os':result['runtime_real_file_io_verified'],
      'compile_argv':compile_argv,'run_argv':argv,'result':result,'elapsed_seconds':time.monotonic()-started,'phone_contacted':False,'model_inference_performed':False}
    target=out/'RESULT.json';target.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':True,'result':ref(target),'checks':result}))
if __name__=='__main__':main()
