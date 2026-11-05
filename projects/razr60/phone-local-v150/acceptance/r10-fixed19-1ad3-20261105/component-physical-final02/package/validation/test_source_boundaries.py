#!/usr/bin/env python3
"""Local host checks only. Synthetic geometry never counts as physical evidence."""
import argparse
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time
import types
import zlib

sys.dont_write_bytecode=True


def load(path,name):
    body=path.read_bytes();m=types.ModuleType(name);m.__file__=str(path)
    exec(compile(body,str(path),'exec'),m.__dict__)
    return m


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--production-cache',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args();root=Path(__file__).resolve().parent.parent
    out=args.out.resolve();os.umask(0o077);out.mkdir(mode=0o700)
    S=load(root/'source/physical_component_common.py','tested_physical_common')
    V=load(root/'source/verify_physical_component.py','tested_physical_verifier')
    C=load(root/'source/owned_capture.py','tested_owned_capture')
    rows=[]
    def check(name,condition):
        if not condition:raise AssertionError(name)
        rows.append({'name':name,'passed':True})
    def reject(name,fn):
        try:fn()
        except (ValueError,AssertionError,TypeError,KeyError) as error:
            rows.append({'name':name,'passed':True,'rejection':str(error)[:200]});return
        raise AssertionError('must reject: '+name)
    source={p.name:p.read_bytes() for p in args.production_cache.glob('*.py')}
    pins=json.loads((root/'reference/production-pins.json').read_bytes())
    check('all exact current production15 sources match supplied cache',
        len(source)==15 and set(source)==set(pins) and {n:S.sha(b) for n,b in source.items()}==pins)
    originals=ast.parse((root/'reference/capture_transport0374.original.py').read_bytes())
    candidate=ast.parse((root/'source/owned_capture.py').read_bytes())
    derivation=json.loads((root/'validation/CAPTURE-DERIVATION.json').read_bytes())
    check('donor is the reviewed 0374 bytes',S.sha((root/'reference/capture_transport0374.original.py').read_bytes())
        ==derivation['donor_sha256'])
    def definitions(tree):return {n.name:n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
    a,b=definitions(originals),definitions(candidate)
    ac,bc=definitions(a['Chain']),definitions(b['OwnedCapture'])
    check('every extracted function and method AST is unchanged',all(ast.dump(a[n],include_attributes=False)
        ==ast.dump(b[n],include_attributes=False) for n in derivation['unchanged_function_bodies'])
        and all(ast.dump(ac[n],include_attributes=False)==ast.dump(bc[n],include_attributes=False)
            for n in derivation['unchanged_method_bodies']))
    for path in sorted((root/'source').glob('*.py')):compile(path.read_bytes(),str(path),'exec')
    check('all executable candidate source parses',True)
    context=(root/'reference/component_source_context.original.py').read_bytes()
    context_text=context.decode();context_nodes={n.targets[0].id:n for n in ast.parse(context).body
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)}
    allowed={'MATERIALIZER','CONSUMER','CONSUMER_PIN','READINESS_PIN','RUNTIME_SHA','POLICY_SHA','ADOPTION_SHA'}
    def context_with_paths(materializer,consumer):
        text=context_text
        for name,value in (('MATERIALIZER',materializer),('CONSUMER',consumer)):
            old=ast.get_source_segment(context_text,context_nodes[name].value)
            assert text.count(old)==1;text=text.replace(old,value,1)
        return text.encode()
    mac_context=context_with_paths("B/'scoped-acceptance-v150-r10-r1-readiness-r9/operator/materialize_case_r10.py'",
        "B/'r10-boundary-consumers-final-r8/source/release_boundaries.py'")
    S.verify_literal_increment(mac_context,context,allowed,{'MATERIALIZER','CONSUMER'})
    check('actual Mac finalizer B slash path expressions are accepted unchanged',True)
    absolute_context=context_with_paths("Path('/synthetic/source/materialize_case_r10.py')",
        "Path('/synthetic/source/release_boundaries.py')")
    S.verify_literal_increment(absolute_context,context,allowed,{'MATERIALIZER','CONSUMER'})
    check('explicit literal Path expressions remain supported',True)
    dynamic=context_with_paths("Path(__import__('os').getcwd())","B/'reviewed/consumer.py'")
    reject('dynamic dependency path expression is refused',lambda:S.verify_literal_increment(
        dynamic,context,allowed,{'MATERIALIZER','CONSUMER'}))
    reject('non-slot executable drift is refused',lambda:S.verify_literal_increment(
        mac_context+b'\nUNREVIEWED_EXECUTABLE_DRIFT=True\n',context,allowed,{'MATERIALIZER','CONSUMER'}))
    admitted={'release':{'source':source},'release_path':str(args.production_cache.resolve())}
    with S.actual_modules(admitted) as modules:
        nonce='7'*32
        obs=modules['phone_observation_tools'];guards=modules['phone_task_guards'];local=modules['phone_local_tools']
        viewport="DisplayViewport{type=INTERNAL, valid=true, isActive=true, displayId=0, uniqueId='local:"+obs.PHYSICAL_DISPLAY+"', orientation=0, logicalFrame=Rect(0, 0 - 1224, 2992), physicalFrame=Rect(0, 0 - 1224, 2992)}"
        page=('Display: mDisplayId=0\nmTopFocusedDisplayId=0\nmCurrentFocus=Window{synthetic u0 org.example.fixture/.Activity}\n'
            'mFocusedApp=ActivityRecord{synthetic u0 org.example.fixture/.Activity}\nisKeyguardShowing=false\n'
            'topResumedActivity=ActivityRecord{synthetic u0 org.example.fixture/.Activity}\n')
        binpath=out/'stub-bin';binpath.mkdir(mode=0o700)
        stub=binpath/'dumpsys'
        stub.write_text('#!'+sys.executable+'\nimport os,sys\n'
            "if sys.argv[1]=='display': print('mViewports=['+os.environ['FIXTURE_VIEWPORT']+']')\n"
            "elif sys.argv[1]=='window': print('\\n'.join(x for x in os.environ['FIXTURE_PAGE'].splitlines() if not x.startswith('topResumedActivity=')))\n"
            "elif sys.argv[1]=='activity': print('\\n'.join(x for x in os.environ['FIXTURE_PAGE'].splitlines() if x.startswith('topResumedActivity=')))\n")
        stub.chmod(0o700)
        marker='HOST_FIXTURE_GUARD_CONTINUED'
        guard=local.current_viewport_guard()
        check('physical guard is the actual focused-input precondition',
            local.PhoneLocalTools._focus_input_precondition(None)==guard)
        mapped=[]
        mapper=obs.PhoneTools(out/'synthetic-direct-mapping',lambda path,value:mapped.append((str(path),value)))
        identity={'schema':'hepta.operator-direct-component-identity.v1','case_id':'COMP-01',
            'label':'comp01-host-synthetic','nonce':nonce,'request_sha256':S.sha(b'synthetic owner')}
        mapper.bind(identity);call_id='comp01-return-'+nonce
        decision={'call_id':call_id,'tool':'phone.return_hepta','argv':[],'command':''}
        wire=mapper.map(decision);token=mapper.calls[call_id]['capture_id']
        check('actual direct mapper records exactly one reviewed launch shell',len(mapped)==1 and len(mapper.calls)==1
            and wire==['-s',obs.SERIAL,'shell',guards.return_command(mapper._serial_guard(),token)]
            and wire[-1].count('am start -W -n ')==1 and 'input -d ' not in wire[-1])
        def production_reject(name,fn,reason):
            try:fn()
            except modules['provider_openai_compatible'].ProviderError as error:
                check(name,reason in str(error));return
            raise AssertionError('production parser did not reject: '+name)
        production_reject('the same component call ID cannot be mapped twice',lambda:mapper.map(decision),'already mapped')
        hepta_page=page.replace('org.example.fixture/.Activity',guards.HEPTA_FULL_COMPONENT)
        returned={'schema':'hepta.return-receipt.v149.1','operation_id':token,'launch_exit_code':0,
            'launch_b64':S.b64(('Status: ok\nActivity: '+guards.HEPTA_FULL_COMPONENT+'\n').encode()),
            'page_b64':S.b64(hepta_page.encode()),'viewport_b64':S.b64(viewport.encode())}
        observed,actual_vp=guards.verify_return(returned,token);obs.validate_viewport(actual_vp)
        check('synthetic typed return control proves launch and actual focus as separate fields',
            observed['component']==guards.HEPTA_FULL_COMPONENT)
        only_launch=dict(returned,page_b64=S.b64(page.encode()))
        production_reject('launch success cannot substitute for HEPTA focus',
            lambda:guards.verify_return(only_launch,token),'not the actual focused')
        failed_launch=dict(returned,launch_exit_code=1)
        production_reject('HEPTA focus cannot erase the failed launch exit',
            lambda:guards.verify_return(failed_launch,token),'launch exit status differs')
        env=dict(os.environ,PATH=str(binpath)+':/usr/bin:/bin',FIXTURE_PAGE=page)
        synthetic_guards=[('portrait',viewport,0),('rotation',viewport.replace('orientation=0','orientation=1'),68),
            ('external',viewport.replace('displayId=0','displayId=1').replace('type=INTERNAL','type=EXTERNAL'),68)]
        for name,vp,wanted in synthetic_guards:
            env['FIXTURE_VIEWPORT']=vp
            proc=subprocess.run(['/bin/sh','-c',guard+"printf '%s\\n' "+marker],env=env,
                capture_output=True,timeout=3,check=False)
            check('real production guard on synthetic '+name+' rejects before continuation' if wanted else
                'real production guard admits the synthetic portrait control',
                proc.returncode==wanted and proc.stderr==b'' and proc.stdout==(b'' if wanted else (marker+'\n').encode()))
            (out/('synthetic-guard-'+name+'.json')).write_bytes(S.enc({'kind':'host_synthetic_geometry_only',
                'returncode':proc.returncode,'stdout':proc.stdout.decode(),'stderr':proc.stderr.decode(),
                'input_commands':0,'phone_calls':0,'physical_case_passed':False}))
        def png(w,h):
            def chunk(kind,body):return struct.pack('>I',len(body))+kind+body+struct.pack('>I',zlib.crc32(kind+body)&0xffffffff)
            return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',w,h,8,2,0,0,0)) \
                +chunk(b'IDAT',zlib.compress((b'\0'+b'\0'*(w*3))*h))+chunk(b'IEND',b'')
        image=png(1224,2992)
        def envelope(phase,rotation=0):
            vp=viewport.replace('orientation=0','orientation='+str(rotation));negative=phase=='rotate-negative'
            return {'schema':'hepta.physical-component.rotation-observation.v1','nonce':nonce,'phase':phase,
                'boot_id':S.BOOT,'stay_on':'3','accelerometer_rotation':'0','user_rotation':str(rotation),
                'set_accelerometer_rc':-1 if phase=='portrait-baseline' else 0,
                'set_user_rotation_rc':-1 if phase=='portrait-baseline' else 0,
                'guard_rc':68 if negative else 0,
                'guard_stdout_b64':S.b64(b'' if negative else ('hepta_guard_admitted_'+nonce+'_'+phase+'\n').encode()),
                'guard_stderr_b64':'','page_before_b64':S.b64(page.encode()),'page_after_b64':S.b64(page.encode()),
                'page_guard_after_b64':S.b64(page.encode()),'viewport_before_b64':S.b64(vp.encode()),
                'viewport_after_b64':S.b64(vp.encode()),'viewport_guard_after_b64':S.b64(vp.encode()),
                'fingerprint_b64':S.b64(b'host.synthetic.fixture'),
                'png_bytes':len(image),'png_sha256':S.sha(image),'png_base64':S.b64(image)}
        base=envelope('portrait-baseline');baseline=S.parse_physical(modules,S.enc(base),nonce,'portrait-baseline')
        neg=envelope('rotate-negative',1);S.parse_physical(modules,S.enc(neg),nonce,'rotate-negative')
        restored=envelope('restore-positive');S.parse_physical(modules,S.enc(restored),nonce,'restore-positive')
        check('three clearly synthetic receipt shapes parse with actual production parsers',True)
        mutations=[('setting-only rotation without observed physical orientation',lambda x:x.update(viewport_before_b64=base['viewport_before_b64'],
            viewport_after_b64=base['viewport_after_b64'],viewport_guard_after_b64=base['viewport_guard_after_b64'])),
            ('continuation marker after a reported rejection',lambda x:x.update(guard_stdout_b64=S.b64(b'forged continuation'))),
            ('focus changed after the guard',lambda x:x.update(page_guard_after_b64=S.b64(page.replace('org.example.fixture','org.other').encode()))),
            ('screenshot hash changed',lambda x:x.update(png_sha256='0'*64)),
            ('stale nonce',lambda x:x.update(nonce='8'*32)),
            ('nonzero settings result',lambda x:x.update(set_user_rotation_rc=1))]
        for name,mutate in mutations:
            value=copy.deepcopy(neg);mutate(value)
            reject(name,lambda value=value:S.parse_physical(modules,S.enc(value),nonce,'rotate-negative'))
        bad=bytearray(image);bad[-1]^=1
        reject('PNG CRC corruption is rejected',lambda:S.png_info(bytes(bad)))
        requests={}
        for phase in ('portrait-baseline','rotate-negative','restore-positive'):
            req,recipe=S.physical_request(modules,nonce,phase,None if phase=='portrait-baseline' else baseline)
            syntax=subprocess.run(['/bin/sh','-n','-c',req['command']],capture_output=True,timeout=3)
            check(phase+' exact command syntax and no input/launch recipe',syntax.returncode==0 and syntax.stderr==b''
                and recipe['input_commands']==0 and 'input -d ' not in req['command'] and 'am start' not in req['command']
                and req['timeout_seconds']==20 and len(('shell,v2,raw:/debug_ramdisk/su -c '+__import__('shlex').quote(req['command'])).encode())<65536)
            requests[phase]={'bytes':len(req['command'].encode()),'sha256':S.sha(req['command'].encode())}
        check('exact old settings, not a guessed positive baseline, determine restoration',
            'settings put system accelerometer_rotation 0;' in S.physical_request(modules,nonce,'restore-positive',baseline)[0]['command']
            and 'settings put system user_rotation 0;' in S.physical_request(modules,nonce,'restore-positive',baseline)[0]['command'])
        reject('oversized ADB request fails before dispatch',lambda:S.request('x'*65536,20))
        reject('out-of-budget phone timeout fails before dispatch',lambda:S.request('printf ok',21))
    capture_root=out/'capture';owner=C.OwnedCapture(capture_root)
    argv=[sys.executable,'-I','-B','-c',"import sys;assert sys.stdin.buffer.read()==b'original-input';print('actual-owned-child')"]
    actual=owner.execute_process('bounded-original',argv,3,input_raw=b'original-input')
    checked=V.capture(S,S.Originals(),capture_root/'bounded-original','bounded-original',argv,b'original-input',3)
    check('real host child join plus both EOF/inode capture independently verifies',actual==checked['stdout']==b'actual-owned-child\n'
        and owner.close_owned_host_outputs()=={'stream_cleanup_errors':[],'host_children':[]})
    actual_dir=capture_root/'bounded-original'
    for name,filename,mutate in [
        ('missing stdout EOF','OUTPUT-CAPTURE.json',lambda v:v.update(stdout_eof=False)),
        ('replaced output inode','OUTPUT-CAPTURE.json',lambda v:v['files']['stdout']['metadata'].update(st_ino=0)),
        ('rebound CHILD intent','CHILD.json',lambda v:v.update(source_intent_sha256='0'*64)),
        ('incomplete captured bytes','OUTPUT-CAPTURE.json',lambda v:v['captured']['stdout'].update(sha256='0'*64))]:
        target=out/('mutation-'+str(len(rows)));shutil.copytree(actual_dir,target)
        path=target/filename;value=json.loads(path.read_bytes());mutate(value);path.write_bytes(S.enc(value))
        reject(name,lambda target=target:V.capture(S,S.Originals(),target,'bounded-original',argv,b'original-input',3,actual_dir))
    for name,extra in [('run_physical_component_once.py',[]),('verify_physical_component.py',[]),
        ('restore_existing_rotation_once.py',[]),('p4_component_dispatch_once.py',
            ['--case-root','/does/not/exist','--self-sha256','0'*64])]:
        proc=subprocess.run([sys.executable,'-I','-B',str(root/'source'/name)]+extra,capture_output=True,timeout=3)
        preview=json.loads(proc.stdout)
        check(name+' default preview reads no supplied inputs and starts no phone',
            proc.returncode==0 and proc.stderr==b'' and preview['phone_calls']==0)
    report={'schema':'hepta.physical-component.source-validation.v1',
        'state':'LOCAL_SOURCE_BOUNDARIES_PASSED_NOT_PHYSICAL_ACCEPTANCE','checks':rows,'checks_count':len(rows),
        'source_files':{p.name:{'bytes':len(p.read_bytes()),'sha256':S.sha(p.read_bytes())}
            for p in sorted((root/'source').glob('*.py'))},'synthetic_recipe_wires':requests,
        'actual_phone_calls':0,'actual_mac_calls':0,'real_model_requests':0,'native_submissions':0,
        'synthetic_geometry_explicitly_not_physical':True,'COMP01_pass':False,'NEG03_physical_pass':False,
        'remaining_actual_gates':['actual sealed runtime/adoption generation','fresh actual ready binding',
            'fresh same-generation six-axis NEG03 fixture','explicit owner request and new supplied nonce',
            'actual phone phases and independent closure']}
    (out/'TEST-RESULT.json').write_bytes(S.enc(report));print(json.dumps({'state':report['state'],
        'checks':len(rows),'result':str(out/'TEST-RESULT.json'),'physical_case_passed':False},sort_keys=True))


if __name__=='__main__':main()
