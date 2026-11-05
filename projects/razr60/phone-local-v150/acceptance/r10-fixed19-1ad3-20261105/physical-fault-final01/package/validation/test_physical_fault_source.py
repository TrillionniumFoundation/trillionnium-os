#!/usr/bin/env python3
"""Portable local source/interface checks. Never invokes phone, SSH or fault actor."""
import argparse,ast,base64,copy,gzip,hashlib,json,os,re,shlex,subprocess,sys,time,types
from pathlib import Path


def sha(raw):return hashlib.sha256(raw).hexdigest()
def enc(v):return (json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
def need(v,s):
    if not v:raise AssertionError(s)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--package',type=Path,required=True);p.add_argument('--manifest-sha256',required=True)
    p.add_argument('--out',type=Path,required=True);args=p.parse_args()
    root=args.package.resolve();out=args.out.resolve();out.mkdir(mode=0o700)
    mfraw=(root/'SOURCE-MANIFEST.json').read_bytes();need(sha(mfraw)==args.manifest_sha256,'manifest input pin')
    mf=json.loads(mfraw);files={}
    for row in mf['files']:
        name=row['path'];raw=(root/name).read_bytes()
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'source member '+name);files[name]=raw
    results=[]
    def check(name,fn):
        try:
            detail=fn();results.append({'name':name,'passed':True,'detail':detail})
        except BaseException as e:
            results.append({'name':name,'passed':False,'error_type':type(e).__name__,'detail':str(e)})
    def rejected(fn,contains=None):
        try:fn()
        except (ValueError,AssertionError,TypeError) as e:
            if contains is not None:need(contains in str(e),'unexpected rejection: '+str(e))
            return type(e).__name__+': '+str(e)
        raise AssertionError('invalid input was accepted')
    def load(name):
        m=types.ModuleType(name);m.__file__=str(root/'source'/(name+'.py'));sys.modules[name]=m
        exec(compile(files['source/'+name+'.py'],m.__file__,'exec'),m.__dict__);return m
    S=load('physical_fault_common');O=load('fault_originals');P=load('fault_projections')
    V=load('verify_physical_fault');R=load('run_physical_fault_once');W=load('watch_physical_fault_once')
    F=load('freeze_physical_fault');C=load('owned_capture')
    def parse39():
        names=[n for n in files if n.endswith('.py')]
        for name in names:ast.parse(files[name],feature_version=(3,9))
        return {'parsed_python_files':len(names)}
    check('all pinned Python sources parse with Python 3.9 grammar',parse39)
    def exact_capture():
        need((len(files['source/owned_capture.py']),sha(files['source/owned_capture.py']))==S.CAPTURE_PIN,
             'original repaired capture changed')
        return {'source_sha256':S.CAPTURE_PIN[1]}
    check('reused owned capture is exact reviewed f12a source',exact_capture)
    defaults=['run_physical_fault_once','verify_fault_once','watch_physical_fault_once','capture_fault_phone',
              'capture_fault_p4','prepare_physical_fault','freeze_physical_fault','p4_fault_dispatch_once']
    for name in defaults:
        def preview(name=name):
            argv=[sys.executable,'-I','-B',str(root/'source'/(name+'.py'))]
            if name=='p4_fault_dispatch_once':argv+=['--case-root','/nonexistent-source-check','--self-sha256','0'*64]
            result=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=5)
            (out/(name+'.preview.stdout')).write_bytes(result.stdout);(out/(name+'.preview.stderr')).write_bytes(result.stderr)
            need(result.returncode==0 and result.stderr==b'','default entry did not return cleanly')
            value=json.loads(result.stdout);need('PREVIEW' in value['state'],'default entry not preview')
            need(value.get('phone_calls',value.get('phone_reads',0))==0,'default preview claims phone activity')
            return {'returncode':result.returncode,'state':value['state']}
        check('default '+name+' performs no case execution',preview)
    for name,flag in [('run_physical_fault_once','--execute-once'),('verify_fault_once','--execute-verify-once'),
                      ('prepare_physical_fault','--prepare-host-only')]:
        def gate(name=name,flag=flag):
            argv=[sys.executable,'-I','-B',str(root/'source'/(name+'.py')),
                  '--source-manifest-sha256',args.manifest_sha256,flag]
            result=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=5)
            (out/(name+'.unfrozen.stdout')).write_bytes(result.stdout);(out/(name+'.unfrozen.stderr')).write_bytes(result.stderr)
            need(result.returncode!=0 and b'future_actual_fault_dependencies_are_unfrozen' in result.stderr,
                 'unfrozen entry reached case path or accepted missing dependencies')
            return {'returncode':result.returncode,'rejected_before_missing_case_path':True}
        check('unfrozen '+name+' refuses before private case input',gate)
    def watcher_gate():
        return rejected(lambda:W.execute(b'not-json',b'not-source',{}),'future_actual_fault_dependencies_are_unfrozen')
    check('unfrozen watcher refuses before owner or installed paths',watcher_gate)
    def whitelist():
        need(S.CASE_IDS==W.CASE_IDS==('NEG-04','NEG-05','NEG-07'),'fixed independent whitelist')
        return rejected(lambda:W.validate_plan({'schema':'hepta.physical-fault.watch-plan.v1','case_id':'NEG-08'}),
                        'fixed_fault_watch_plan_fields')
    check('CPU cancellation cases cannot enter this separate fault watch',whitelist)
    # These are source-only wire fixtures. No recipe below is executed.
    baseline=json.loads(files['reference/fault-package.original.json'])
    sibling=root.parent
    external=Path(__file__).resolve().parents[2]/'downstream_review_cache/fault-signal-r10-r1-operator-final05'
    operator={}
    for row in baseline['runtime_sources']:
        name=row['path'];candidate=root/'validation/operator-source-fixture'/name
        path=candidate if candidate.exists() else external/name
        body=path.read_bytes();need(len(body)==row['bytes'] and sha(body)==row['sha256'],'operator source fixture pin')
        operator[name]=body
    bundle={'manifest_b64':S.b64(files['reference/fault-package.original.json']),
            'sources':{name:S.b64(body) for name,body in operator.items()}}
    nonce='a'*32;plan=S.enc({'nonce':nonce,'source_only_fixture':True,'text':'中文🙂\n第二行'})
    def recipe_roundtrip():
        stage,ref=S.operator_stage_request(bundle,nonce)
        watch=S.source_request(files['source/watch_physical_fault_once.py'],plan,'watch',ref)
        capture=S.source_request(files['source/capture_fault_phone.py'],plan,'capture')
        rows={}
        for name,request in [('operator_stage',stage),('watch',watch),('capture',capture)]:
            command=shlex.split(request['command']);need(command[-2]=='-c','one fixed python recipe')
            code=command[-1];tree=ast.parse(code);compile(tree,'<source-only-wire>','exec')
            compressed=[n.args[0].value for n in ast.walk(tree) if isinstance(n,ast.Call) and
                isinstance(n.func,ast.Attribute) and n.func.attr=='b64decode' and n.args and
                isinstance(n.args[0],ast.Constant) and isinstance(n.args[0].value,str)]
            need(len(compressed)==1,'one static bounded packed envelope')
            body=gzip.decompress(base64.b64decode(compressed[0],validate=True));need(len(body)<=262144,'wire unpack cap')
            value=json.loads(body)
            if name=='operator_stage':need(body==S.operator_bundle_bytes(bundle),'static operator exact UTF8 roundtrip')
            else:
                need(value['source_utf8'].encode()==files['source/'+('watch_physical_fault_once.py' if name=='watch' else 'capture_fault_phone.py')]
                    and value['plan_utf8'].encode()==plan,'source/Chinese emoji/newline plan exact UTF8 roundtrip')
            wire=len(('shell,v2,raw:/debug_ramdisk/su -c '+shlex.quote(request['command'])).encode())
            need(wire<65536,'unchanged wire cap');rows[name]={'wire_bytes':wire,'unpacked_bytes':len(body)}
        return rows
    check('three exact staged UTF8 envelopes fit original wire and unpack caps',recipe_roundtrip)
    check('oversized phone source rejected before recipe',lambda:rejected(
        lambda:S.source_request(b'x'*65537,plan,'capture'),'bounded_exact_phone_source_and_plan'))
    check('foreign P4 archive path rejected before any read',lambda:rejected(
        lambda:S.p4_archive_chunk_program({'path':'/tmp/foreign.tar.gz','bytes':1,'sha256':'0'*64},0),
        'fixed_bounded_P4_archive_chunk'))
    def source_budget():
        p=out/'OVER-BUDGET-SYNTHETIC-MANIFEST.json'
        raw=S.enc({'files':[{'path':'must-not-be-read','bytes':32*1024*1024+1,'sha256':'0'*64}]})
        p.write_bytes(raw)
        return rejected(lambda:S.load_members(S.Originals(),S.desc(p,raw)), 'complete_source_package_32MiB_budget')
    check('source package capacity rejected before opening oversized member',source_budget)
    def api_imports():
        api=V.load_apis({'admitted':{'operator_sources':operator},'files':files},types.SimpleNamespace(Path=Path))
        P.business_api({'raw_sources':{'business':files['reference/collect_business_evidence.original.py']}},types.SimpleNamespace(Path=Path))
        need(callable(api.model.verify_cleanup) and callable(api.cleanup.assess_original),'original pure projections absent')
        return {'effect_functions_called':0,'pinned_pure_API_loads':True}
    check('original ledger model business and decoder projections load without effects',api_imports)
    def rewrite_utf8():
        raw='# 中文🙂\nFINAL_DEPENDENCIES = None\nUNCHANGED = "✅"\n'.encode()
        v={'schema':'SYNTHETIC-NOT-ACTUAL','sha256':'1'*64};changed=F.rewrite(raw,{'FINAL_DEPENDENCIES':v})
        need(F.rewrite(changed,{'FINAL_DEPENDENCIES':None})==raw,'UTF8 byte offsets changed other source')
        for name in ('physical_fault_common','watch_physical_fault_once','capture_fault_phone','capture_fault_p4'):
            body=files['source/'+name+'.py'];result=F.rewrite(body,{'FINAL_DEPENDENCIES':v})
            need(F.rewrite(result,{'FINAL_DEPENDENCIES':None})==body,'reviewed whole-byte inverse '+name)
        return {'changed_slots_per_source':1,'actual_dependencies_claimed':False}
    check('source freezing changes only exact UTF8 AST RHS and is wholly reversible',rewrite_utf8)
    def fd_replacement():
        d=out/'created-inode-race';d.mkdir();target=d/'new-output';retained=d/'original-inode';real=F.os.fsync;hit=[]
        def injected(fd):
            real(fd)
            if not hit and target.exists() and os.fstat(fd).st_ino==target.stat().st_ino:
                hit.append(True);target.rename(retained);target.write_bytes(b'created-original')
        F.os.fsync=injected
        try:detail=rejected(lambda:F.created(S,target,b'created-original'),'new_output_inode_or_bytes_replaced')
        finally:F.os.fsync=real
        need(hit and retained.read_bytes()==target.read_bytes(),'same-byte replacement fixture did not occur')
        return {'rejection':detail,'same_bytes_different_inode_rejected':True}
    check('source output receipt refuses same-byte pathname replacement',fd_replacement)
    def async_adapter():
        base=out/'async-adapter';base.mkdir();owner=C.OwnedCapture(base/'capture')
        argv=[sys.executable,'-I','-B','-c','import os;os.write(1,b"complete-new-adapter\\n")']
        started=owner.execute_process('async-interface',argv,5,async_start=True)
        body=R.finish_async(C,owner,'async-interface',started)
        need(body==b'complete-new-adapter\n' and owner.close_owned_host_outputs()=={'stream_cleanup_errors':[],'host_children':[]},
             'new adapter did not join actual local child and reader')
        records={k:S.desc(base/'capture/async-interface'/leaf,(base/'capture/async-interface'/leaf).read_bytes()) for k,leaf in
            [('intent','INTENT.json'),('child','CHILD.json'),('result','RESULT.json'),('stdout','stdout.original'),
             ('stderr','stderr.original'),('output_capture','OUTPUT-CAPTURE.json')]};records['stdin']=None
        need(O.host_phase(S.Originals(),records,'async-interface',argv,5,None)==body,
             'independent unchanged phase parser rejects actual adapter evidence')
        return {'actual_local_child_joined':True,'stdout_and_stderr_EOF':True,'phone_calls':0,'physical_case_pass':False}
    check('new async adapter actual local child accepted by exact capture parser',async_adapter)
    def single_actor():
        tree=ast.parse(files['source/watch_physical_fault_once.py'])
        calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
               and isinstance(n.func.value,ast.Name) and n.func.value.id=='actor' and n.func.attr=='execute']
        need(len(calls)==1,'more than one actor dispatch callsite')
        core=ast.parse(files['source/verify_physical_fault.py'])
        need(not any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr in
            ('Popen','run','pidfd_send_signal','kill','killpg','create_connection') for n in ast.walk(core)),
            'independent core has active process/socket/signal call')
        return {'single_actor_callsite':True,'independent_core_effect_calls':0}
    check('one actor callsite and no process socket or signal call in independent core',single_actor)
    passed=all(r['passed'] for r in results)
    report={'schema':'hepta.physical-fault.host-source-interface-checks.v1','state':'PASS' if passed else 'FAIL',
        'source_manifest':{'path':str(root/'SOURCE-MANIFEST.json'),'bytes':len(mfraw),'sha256':sha(mfraw)},
        'checks':results,'passed':sum(r['passed'] for r in results),'total':len(results),
        'local_subprocesses_only':True,'phone_calls':0,'SSH_calls':0,'fault_actor_invocations':0,
        'actual_physical_cases_passed':0,'whole_case_pass':False,
        'limitations':['No actual physical integration or phone phase was run.','Synthetic wire fixtures are not READY or actual adoption.']}
    (out/'RESULT.json').write_bytes(enc(report));print(json.dumps({'state':report['state'],'passed':report['passed'],
        'total':len(results),'report':str(out/'RESULT.json'),'physical_cases_passed':0},sort_keys=True))
    return 0 if passed else 1


if __name__=='__main__':raise SystemExit(main())
