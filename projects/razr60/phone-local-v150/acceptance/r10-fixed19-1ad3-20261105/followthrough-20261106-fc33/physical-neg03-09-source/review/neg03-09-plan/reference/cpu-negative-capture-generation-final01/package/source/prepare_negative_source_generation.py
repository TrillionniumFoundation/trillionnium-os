#!/usr/bin/env python3
"""Prepare exactly two explicit source bindings; never run source generation or phone."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

sys.dont_write_bytecode=True
B=Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def need(ok,message):
    if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def enc(value):return (json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode()
def strict(raw):
    def pairs(rows):
        result={}
        for key,value in rows:
            need(key not in result,'duplicate JSON key');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def meta(info):return tuple(getattr(info,k) for k in META)
def path(value):
    need(type(value) is str and value.startswith('/') and '\0' not in value and
         all(x not in ('','.','..') for x in value[1:].split('/')),'canonical absolute input path')
    result=Path(value);need(str(result)==value,'canonical path spelling');return result
def desc(name,raw):return {'path':str(name),'bytes':len(raw),'sha256':sha(raw)}
def read(row,maximum=131072):
    need(type(row) is dict and set(row)=={'path','bytes','sha256'} and type(row['bytes']) is int
        and 0<row['bytes']<=maximum and re.fullmatch('[0-9a-f]{64}',row['sha256']),'bounded exact3 input')
    target=path(row['path']);need(target.resolve(strict=True)==target,'input symlink rejected')
    fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and
            before.st_size==row['bytes'],'input regular single-link size')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(row['bytes']+1)
        need(desc(target,raw)==row and meta(before)==meta(os.fstat(fd))==meta(target.lstat()),
             'input bytes or identity changed')
        return raw
    finally:os.close(fd)
def sync(directory):
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)
def put(target,raw):
    need(target.parent.resolve(strict=True)==target.parent,'output parent must be canonical')
    fd=os.open(target,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        created=os.fstat(fd);remaining=memoryview(raw)
        while remaining:
            n=os.write(fd,remaining);need(n>0,'short output write');remaining=remaining[n:]
        os.fsync(fd);os.lseek(fd,0,os.SEEK_SET)
        with os.fdopen(fd,'rb',closefd=False) as stream:observed=stream.read(len(raw)+1)
        final=os.fstat(fd);need(observed==raw and final.st_ino==created.st_ino and
            final.st_dev==created.st_dev and final.st_nlink==1 and
            meta(final)==meta(target.lstat()),'output created inode and exact bytes required')
        sync(target.parent);need(meta(os.fstat(fd))==meta(target.lstat()),'output replaced at persistence')
    finally:os.close(fd)
    return desc(target,raw)
def bootstrap(mf_sha):
    root=Path(__file__).resolve(strict=True).parent.parent;mf=root/'SOURCE-MANIFEST.json'
    need(type(mf_sha) is str and re.fullmatch('[0-9a-f]{64}',mf_sha),'candidate manifest SHA required')
    mfrow={'path':str(mf),'bytes':mf.stat().st_size,'sha256':mf_sha};mfraw=read(mfrow,65536)
    value=strict(mfraw);rows=value.get('files')
    need(value.get('schema')=='hepta.r10.cpu-negative-capture-generator-source-package.v1' and
         type(rows) is list and 1<=len(rows)<=128,'bounded candidate source package')
    files={};total=0
    for row in rows:
        name=row['path'];need(type(name) is str and not name.startswith('/') and
            all(x not in ('','.','..') for x in name.split('/')) and name not in files,'exact unique relative member')
        total+=row['bytes'];need(total<=32*1024*1024,'unchanged whole source bundle32MiB bound')
        files[name]=read(dict(row,path=str(root/name)),131072)
    source=files['source/derive_negative_operator_sources.py']
    need(files['source/prepare_negative_source_generation.py']==Path(__file__).read_bytes(),'executing preparer source pin')
    generator=types.ModuleType('reviewed_cpu_capture_generator');generator.__file__=str(root/'source/derive_negative_operator_sources.py')
    exec(compile(source,generator.__file__,'exec'),generator.__dict__)
    need(generator.FINALIZATION is None and generator.ROOT_CAPTURE_MANIFEST is None,'candidate must retain both unbound gates')
    return root,files,source,generator,mfrow
def prepare(generator,source,value):
    need(type(value) is dict and set(value)=={'schema','out','finalization','root_capture_manifest'} and
         value['schema']=='hepta.r10.cpu-negative-capture-source-binding-inputs.v1','explicit binding input fields')
    out=path(value['out']);need(out.parent==B and re.fullmatch('property-r8-negative-capture-bound-[A-Za-z0-9_-]{1,48}',out.name),
        'new explicit bounded source-binding namespace')
    generator.FINALIZATION=value['finalization'];generator.ROOT_CAPTURE_MANIFEST=value['root_capture_manifest']
    frozen=generator.finalization();root=generator.capture_manifest_pin()
    bound,edits=generator.changed_source(source,[('FINALIZATION',None,repr(frozen)),
        ('ROOT_CAPTURE_MANIFEST',None,repr(root))])
    need(generator.inverse(bound,edits,source),'exact two source RHS inverse')
    return out,bound,edits
def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-manifest-sha256');parser.add_argument('--inputs');parser.add_argument('--inputs-sha256')
    parser.add_argument('--prepare-host-only',action='store_true');args=parser.parse_args(argv)
    if not args.prepare_host_only:
        print(enc({'state':'SOURCE_PREVIEW_NO_ORIGINAL_READ_NO_GENERATION','phone_calls':0,
            'native_cases':0,'physical_case_pass':False}).decode(),end='');return 0
    root,files,source,G,mfrow=bootstrap(args.source_manifest_sha256)
    ip=path(args.inputs);row={'path':str(ip),'bytes':ip.stat().st_size,'sha256':args.inputs_sha256}
    input_raw=read(row,65536);value=strict(input_raw);out,bound,edits=prepare(G,source,value)
    need(out.parent.resolve(strict=True)==out.parent,'source binding parent must be canonical')
    try:out.lstat()
    except FileNotFoundError:pass
    else:raise ValueError('source binding output already exists')
    observed=G.Originals();parents=G.parent_packages(observed);binding=G.actual_dependencies(observed,G.FINALIZATION)
    packages,proof,patches=G.derive_packages(parents,binding)
    capture=G.capture_dependencies(observed,binding)
    closure,closure_proof,closure_patch=G.derive_capture_closure(packages,binding,capture)
    packages['closure']=closure
    need(set(packages)==set(G.OUTPUTS) and len(packages)==7,'exact six original packages plus one closure')
    for target in (G.OUT,*G.OUTPUTS.values()):
        need(target.parent==B and target.parent.resolve(strict=True)==target.parent,'original fixed private output namespace')
        try:target.lstat()
        except FileNotFoundError:pass
        else:raise ValueError('source generation output already exists: '+str(target))
    observed.recheck();read(mfrow,65536)
    need(read(row,65536)==input_raw,'binding input final readback')
    out.mkdir(mode=0o700);sync(out.parent);(out/'source').mkdir(mode=0o700);sync(out)
    source_path=out/'source/derive_negative_operator_sources.py';source_row=put(source_path,bound)
    entry=['/usr/bin/python3','-I','-B',str(source_path),'--source-sha256',source_row['sha256'],
        '--execute-source-generation-once']
    result={'schema':'hepta.r10.cpu-negative-capture-source-binding-result.v1',
        'state':'ACTUAL_SOURCE_RELATIONSHIPS_PREFLIGHTED_GENERATION_NOT_EXECUTED',
        'candidate_manifest':mfrow,'source':source_row,'input':row,
        'root_capture_manifest':value['root_capture_manifest'],'two_RHS_only':edits,
        'predicted_package_manifests':{kind:desc(G.OUTPUTS[kind]/next(n for n in bodies if n in
            ('SOURCE-MANIFEST.json','MANIFEST.json')),bodies[next(n for n in bodies if n in
            ('SOURCE-MANIFEST.json','MANIFEST.json'))]) for kind,bodies in packages.items()},
        'execute_argv':entry,'actual_generation_executed':False,'phone_calls':0,'new_nonces':0,
        'physical_case_pass':False,'automatic_execution':False,'automatic_retry':False}
    outputs={'source/derive_negative_operator_sources.py':bound,
        'BINDING-INPUT.original.json':input_raw,'CANDIDATE-GENERATOR.original.py':source,
        'SOURCE-DEPENDENCIES.json':enc(binding),'CAPTURE-CLOSURE-PROOF.preview.json':enc(closure_proof),
        'ORIGINAL-INPUTS.json':enc({'files':list(observed.rows.values()),'directories':list(observed.directories.values())}),
        'RESULT.json':enc(result)}
    for name,body in outputs.items():
        if name!='source/derive_negative_operator_sources.py':put(out/name,body)
    observed.recheck()
    mf=put(out/'SOURCE-MANIFEST.json',enc({'schema':'hepta.r10.cpu-negative-capture-source-binding.v1',
        'files':[dict(path=n,bytes=len(b),sha256=sha(b)) for n,b in sorted(outputs.items())],
        'source':source_row,'physical_case_pass':False,'phone_calls':0}))
    print(enc({'state':result['state'],'source_manifest':mf,'result':desc(out/'RESULT.json',outputs['RESULT.json']),
        'execute_argv':entry,'phone_calls':0,'actual_generation_executed':False}).decode(),end='');return 0
if __name__=='__main__':raise SystemExit(main())
