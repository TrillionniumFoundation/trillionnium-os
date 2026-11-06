#!/usr/bin/env python3
"""Bind one complete actual input to one reviewed constructor; host publication only.

The explicit CLI three-field input identity is supplied by the root controller.
All JSON templates retain None and are rejected until actual originals exist.
This tool writes a separate bound source and a request; it never dispatches it.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import types

B = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
PACKAGE_ROOT = B + '/followthrough-fc33-install-build-controller01'
SOURCES = {
 'component_build': {'path': PACKAGE_ROOT+'/source/derive_component_build_inputs_UNBOUND.py',
  'bytes':34048,'sha256':'766f6b933b4982088925669f327e0c7c2d03855b8c3f140052d7fbfd088d1b5f'},
 'release_install_stage': {'path': PACKAGE_ROOT+'/source/derive_release_install_stages_UNBOUND.py',
  'bytes':64682,'sha256':'60c6d2e84216798037133199882c5d34101808eb9035a741c64f22d6aa3fbece'},
}
SCHEMA='hepta.fc33.actual-constructor-input-binding.v1'

def need(ok,reason):
    if not ok:raise ValueError(reason)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def strict(raw):
    need(type(raw)is bytes and len(raw)<=4*1024*1024,'bounded complete actual binding input')
    def pairs(rows):
        value={}
        for key,item in rows:
            need(key not in value,'duplicate binding input key');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite binding input'))

def no_unknown(value):
    need(value is not None,'UNBOUND_ACTUAL_CONSTRUCTOR_BINDING_NO_IO')
    if type(value)is dict:
        for item in value.values():no_unknown(item)
    elif type(value)is list:
        for item in value:no_unknown(item)

def descriptor(row):
    need(type(row)is dict and set(row)=={'path','bytes','sha256'}
         and type(row['path'])is str and type(row['bytes'])is int and 0<row['bytes']<=4*1024*1024
         and type(row['sha256'])is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),
         'exact typed actual host descriptor')
    p=PurePosixPath(row['path'])
    need(p.is_absolute()and str(p)==row['path']and '..'not in p.parts
         and not any(c in row['path']for c in '\0\r\n\t')and PurePosixPath(B)in p.parents,
         'exact actual project host pathname')
    return row

def prepare_controller_binding(raw, *, input_descriptor, read_pinned):
    descriptor(input_descriptor)
    need(type(raw)is bytes and pin(raw)=={k:input_descriptor[k]for k in ('bytes','sha256')},
         'complete explicitly selected binding input bytes')
    value=strict(raw)
    need(type(value)is dict and set(value)=={'schema','constructor','actual_inputs','output_root',
         'execution_idempotency_key','execution_timeout_seconds'}and value['schema']==SCHEMA,
         'closed actual constructor binding contract')
    no_unknown(value)
    need(value['constructor']in SOURCES,'one reviewed construction entry')
    descriptor(value['actual_inputs'])
    out=PurePosixPath(value['output_root'])
    need(type(value['output_root'])is str and str(out)==value['output_root']and out.parent==PurePosixPath(B)
         and not any(c in value['output_root']for c in '\0\r\n\t'),'one fresh explicit binding output namespace')
    need(type(value['execution_idempotency_key'])is str
         and re.fullmatch('[A-Za-z0-9_-]{1,110}',value['execution_idempotency_key'])
         and type(value['execution_timeout_seconds'])is int and 1<=value['execution_timeout_seconds']<=300,
         'one finite explicitly selected host construction request')
    observed={}
    def read(row):
        descriptor(row);body=read_pinned(dict(row))
        need(type(body)is bytes and pin(body)=={k:row[k]for k in ('bytes','sha256')},'whole pinned original source/input')
        key=row['path']
        if key in observed:need(observed[key]==(row,body),'same original source/input bytes')
        else:observed[key]=(dict(row),body)
        return body
    actual_raw=read(value['actual_inputs']);actual=strict(actual_raw);no_unknown(actual)
    def load(row,name):
        body=read(row);module=types.ModuleType(name);module.__file__=row['path']
        exec(compile(body,row['path'],'exec'),module.__dict__);return module,body
    S,stage_raw=load(SOURCES['release_install_stage'],'reviewed_host_stage_constructor')
    H,component_raw=load(SOURCES['component_build'],'reviewed_host_component_constructor')
    expected_schema=H.SCHEMA if value['constructor']=='component_build'else S.SCHEMA
    need(type(actual)is dict and actual.get('schema')==expected_schema,'actual input belongs to selected constructor')
    if value['constructor']=='component_build':
        H.exact(actual,('schema','case_results','output_root','build_output_root','build_idempotency_key','build_timeout_seconds'),
                'complete actual component construction input')
        H.exact(actual['case_results'],('NEG-01','NEG-02'),'both actual new closed cases')
        for row in actual['case_results'].values():H.descriptor(row)
    else:
        H.exact(actual,('schema','stage','output_root','actual'),'complete actual stage input')
        need(actual['stage']in S.STAGES,'one implemented construction stage')
    source_row=SOURCES[value['constructor']]
    parent=component_raw if value['constructor']=='component_build'else stage_raw
    bound,proof=S.bind_none(parent,{'FROZEN_INPUTS':value['actual_inputs']})
    name='source/'+('derive_component_build_inputs_BOUND.py'if value['constructor']=='component_build'
                   else'derive_release_install_stage_BOUND.py')
    bound_row=H.located(out/name,bound)
    request=dict(host='mac',executable='/usr/bin/python3',
        args=['-I','-B',bound_row['path'],'--publish-host-inputs-once'],
        idempotency_key=value['execution_idempotency_key'],timeout_seconds=value['execution_timeout_seconds'])
    files={name:bound,'reference/UNBOUND-CONSTRUCTOR.original.py':parent,
           'reference/ACTUAL-CONSTRUCTION-INPUTS.original.json':actual_raw,
           'reference/BINDING-INPUTS.original.json':raw,'reference/COMPLETE-SOURCE-INVERSE.json':H.encoded(proof),
           'requests/EXECUTE-CONSTRUCTOR.json':H.encoded(request)}
    for row,body in observed.values():need(read_pinned(row)==body,'all actual source/input originals rechecked')
    report=dict(schema='hepta.fc33.actual-constructor-binding-result.v1',
        state='EXACT_INPUT_LITERAL_BOUND_CONSTRUCTION_REQUEST_NOT_DISPATCHED',
        source=source_row,bound_source=bound_row,actual_inputs=value['actual_inputs'],binding_input=input_descriptor,
        complete_source_inverse=proof,execution_request=H.located(out/'requests/EXECUTE-CONSTRUCTOR.json',H.encoded(request)),
        phone_calls=0,actor_dispatches=0,BUILD_executed=False,actual_install=None,actual_READY=None,
        files=[H.located(out/n,b)for n,b in sorted(files.items())])
    files['DERIVATION.json']=H.encoded(report)
    return dict(files=files,report=report,output_root=str(out),publisher=H.publish_material)

def read_host(row):
    descriptor(row);p=Path(row['path'])
    need(p.resolve(strict=True)==p,'actual host original without symlink ancestors')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    def meta(s):return [getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size==row['bytes'],'complete regular host original')
        with os.fdopen(fd,'rb',closefd=False)as stream:
            raw=stream.read(row['bytes']+1);need(stream.read(1)==b'','complete host original EOF')
        need(meta(before)==meta(os.fstat(fd))==meta(p.lstat())
             and pin(raw)=={k:row[k]for k in('bytes','sha256')},'host original full9/byte bookends')
        return raw
    finally:os.close(fd)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs',required=True);parser.add_argument('--inputs-bytes',type=int,required=True)
    parser.add_argument('--inputs-sha256',required=True);args=parser.parse_args()
    row=dict(path=args.inputs,bytes=args.inputs_bytes,sha256=args.inputs_sha256)
    result=prepare_controller_binding(read_host(row),input_descriptor=row,read_pinned=read_host)
    output=Path(result['output_root']);need(output.parent.resolve(strict=True)==output.parent,'actual host output parent')
    result['publisher'](output,result['files'])
    terminal=dict(path=str(output/'DERIVATION.json'),**pin(result['files']['DERIVATION.json']))
    need(read_host(terminal)==result['files']['DERIVATION.json'],'complete bound-source publication readback')
    print(json.dumps(dict(state=result['report']['state'],derivation=terminal,
        execution_request=result['report']['execution_request'],phone_calls=0,actor_dispatches=0),sort_keys=True))

if __name__=='__main__':main()
