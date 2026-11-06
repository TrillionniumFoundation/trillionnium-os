#!/usr/bin/env python3
"""Read-only actual E2E source archive verification; no task execution."""
import ast
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import types
import zlib

ROOT=Path(__file__).resolve().parent
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def need(ok,why):
    if not ok:raise ValueError(why)
def read(name):return (ROOT/name).read_bytes()
def literal(raw,name):
    rows=[n for n in ast.parse(raw).body if isinstance(n,ast.Assign)and len(n.targets)==1
          and isinstance(n.targets[0],ast.Name)and n.targets[0].id==name]
    need(len(rows)==1,'one exact original source literal '+name)
    return ast.literal_eval(rows[0].value)
def inverse(raw,name,expected,replacement):
    rows=[n for n in ast.parse(raw).body if isinstance(n,ast.Assign)and len(n.targets)==1
          and isinstance(n.targets[0],ast.Name)and n.targets[0].id==name]
    need(len(rows)==1,'one exact original source literal')
    node=rows[0].value
    need(json.dumps(ast.literal_eval(node),sort_keys=True)==json.dumps(expected,sort_keys=True),
         'exact typed actual literal before inverse')
    lines=raw.splitlines(keepends=True)
    start=sum(len(line)for line in lines[:node.lineno-1])+node.col_offset
    end=sum(len(line)for line in lines[:node.end_lineno-1])+node.end_col_offset
    return raw[:start]+repr(replacement).encode()+raw[end:]

def main():
    helper=read('reference/verify_host_controller_originals.py')
    need(pin(helper)=={'bytes':16570,'sha256':'be2b96db92bb456a798c3f8be6c1425a81e3afeadf782940bd695cf4cb3c714a'},'reviewed original controller reader')
    module=types.ModuleType('actual_controller_reader');module.__file__=str(ROOT/'reference/verify_host_controller_originals.py')
    exec(compile(helper,module.__file__,'exec'),module.__dict__)
    record=json.loads(read('PUBLICATION-CONTROLLER.original.json'))
    job,status,outputs=module.controller(record,code=0,complete=True)
    need(job['id']=='1a1b204a568-fc05-7c0c'and len(outputs['stdout'])==385 and outputs['stderr']==b'',
         'actual successful original E2E source publication')
    need(record['request']['stdin'].encode()==read('reference/SOURCE-ENTRY-GUARD.original.py'),
         'complete original submitted source guard')
    binding_source=read('reference/bind_e2e_sources_r5.original.py')
    need(pin(binding_source)=={'bytes':18012,'sha256':'a39fbab2020e357bbd5a146e15af96b76f847fcd83b54a2fd60dfc6430e5e3a1'}
         and pin(binding_source)['sha256']in record['request']['stdin'],'exact reviewed actual source entry')
    published=json.loads(outputs['stdout'])
    observation=json.loads(read('READ-CONTROLLER.original.json'))
    observed_job,unused,streams=module.controller(observation,code=0,complete=True)
    need(observed_job['id']=='1a1b23d619a-fc05-7d1b'and len(observation['reads'])==33
         and streams['stdout']==read('ORIGINAL-TRANSFER.stdout.json')and streams['stderr']==b''
         and observation['request']['stdin'].encode()==read('observe_bound_e2e_sources.py'),
         'actual independent complete read-only source observation')
    transfer=json.loads(streams['stdout'])
    decoder=zlib.decompressobj();body=decoder.decompress(base64.b64decode(transfer['raw_zlib_base64'],validate=True),4*1024*1024+1)
    need(len(body)<=4*1024*1024 and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
         and body==read('PUBLISHED-E2E-ORIGINALS.json')and pin(body)==transfer['uncompressed']
         and transfer['all_observation_fds_closed']is True,'complete original transfer hash and EOF')
    value=json.loads(body);group=value['groups'][0]
    need(len(value['groups'])==1 and value['file_count']==group['file_count']==49
         and value['file_bytes']==group['file_bytes']==2234976
         and value['all_original_files_read_to_EOF']is True
         and value['all_directory_and_file_full9_bookended']is True,'exact complete source observation scope')
    full={};names=set();meta=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    for row in group['files']:
        raw=read('actual/'+row['relative_path']);m=row['metadata']
        need(raw==row['text'].encode()and pin(raw)=={k:row[k]for k in ('bytes','sha256')}and row['eof']is True,
             'whole actual source original preserved')
        need(set(m)==set(meta)and all(type(m[k])is int for k in meta)and stat.S_ISREG(m['st_mode'])
             and stat.S_IMODE(m['st_mode'])==0o600 and m['st_nlink']==1 and m['st_size']==len(raw),'actual complete full9')
        full[row['path']]=raw;names.add(row['relative_path'])
    binding_raw=read('actual/BINDING.json');binding=json.loads(binding_raw)
    need(pin(binding_raw)=={k:published['result'][k]for k in ('bytes','sha256')}
         and full[published['result']['path']]==binding_raw
         and {row['path']for row in binding['files']}|{published['result']['path']}==set(full),
         'actual publication and complete49 member set')
    need(binding['state']=='SOURCE_BOUND_TASK_EXECUTION_UNBOUND'
         and all(binding[k]is None for k in ('actual_BUILD','actual_READY','actual_context','actual_native_scope','actual_request'))
         and all(type(binding[k])is int and binding[k]==0 for k in ('phone_calls','model_requests','native_dispatches','new_nonces','fixed19_credit'))
         and binding['historical_pass_inherited']is False,'source publication grants no task or installation qualification')
    for row in binding['files']:need(pin(full[row['path']])=={k:row[k]for k in ('bytes','sha256')},'all terminal source pins')
    for directory in group['directories']:
        parent=PurePosixPath(directory['relative_path']);expected=set()
        for name in names:
            path=PurePosixPath(name)
            try:parts=path.relative_to(parent).parts
            except ValueError:continue
            if parts:expected.add(parts[0])
        need(directory['names']==sorted(expected),'actual held-directory names contain all and only declared source files')
    for prefix,manifest_name,count in [('collector-package','MANIFEST.json',7),('operator-chain','SOURCE-MANIFEST.json',6),('shared','SHARED-MATERIALS.json',17)]:
        manifest=json.loads(read('actual/'+prefix+'/'+manifest_name))
        need(len(manifest['files'])==count,'source child manifest exact count')
        for row in manifest['files']:
            need(pin(read('actual/'+prefix+'/'+row['path']))=={k:row[k]for k in ('bytes','sha256')},'source child manifest full bytes')
    parent=json.loads(read('actual/reference/CANDIDATE-SOURCES.original.json'))
    parent_rows={row['path']:row for row in parent['files']};inverses=[]
    targets=[('operator-chain/root_acceptance_r10.py','READINESS_SHA',pin(read('actual/reference/readiness.source.original.py'))['sha256'],None,
              {k:parent_rows['operator-chain-template/root_acceptance_r10.py'][k]for k in ('bytes','sha256')}),
             ('source/run_fixed19_e2e_root_once.py','OPERATOR_MANIFEST_PIN',pin(read('actual/operator-chain/SOURCE-MANIFEST.json')),None,
              {k:parent_rows['coordinator/run_fixed19_e2e_root_once_UNBOUND.py'][k]for k in ('bytes','sha256')}),
             ('reference/release_boundaries.source.original.py','PACKAGE_SHA',pin(read('actual/reference/RUNTIME-MANIFEST.original.json'))['sha256'],None,
              literal(binding_source,'CONSUMER_TEMPLATE_PIN')),
             ('reference/readiness.source.original.py','BOUNDARY_CONSUMER_SHA256',pin(read('actual/reference/release_boundaries.source.original.py'))['sha256'],
              literal(binding_source,'OLD_CONSUMER_SHA'),literal(binding_source,'READINESS_PARENT_PIN'))]
    for path,name,before,after,expected in targets:
        raw=read('actual/'+path);back=inverse(raw,name,before,after)
        need(pin(back)==expected,'complete source literal inverse '+path)
        inverses.append(dict(path=path,actual=pin(raw),parent=expected))
    selected_inputs=literal(binding_source,'FROZEN_INPUTS')
    input_raw=read('actual/BINDING-INPUTS.json')
    need(json.dumps(json.loads(input_raw),sort_keys=True)==json.dumps(selected_inputs,sort_keys=True)
         ==json.dumps(binding['inputs'],sort_keys=True),
         'complete actual binding input equals the source-bound literal object')
    result=dict(schema='hepta.fc33.actual-e2e-source-archive-verification.v1',
        state='ACTUAL_E2E_SOURCE_PUBLICATION_AND_COMPLETE_49_ORIGINALS_VERIFIED',
        publication_job=job['id'],read_only_observation_job=observed_job['id'],source_file_count=49,source_file_bytes=2234976,
        complete_actual_read_pages=33,all_actual_streams_complete_durable_and_EOF=True,
        all_original_full9_and_exact_directory_sets_verified=True,source_inverse_count=4,source_inverses=inverses,
        current_collector_members=7,current_operator_members=6,current_shared_members=17,
        actual_BUILD=None,actual_install=None,actual_READY=None,actual_business_task_run=False,
        phone_calls_by_archive=0,new_controls_executed=0,fixed19_credit=0)
    print(json.dumps(result,sort_keys=True,indent=2))

if __name__=='__main__':main()
