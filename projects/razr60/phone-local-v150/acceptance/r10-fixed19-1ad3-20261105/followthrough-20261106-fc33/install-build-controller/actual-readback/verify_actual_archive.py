#!/usr/bin/env python3
"""Verify existing actual controller-source originals, without rerunning source controls."""
import ast
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import types
import zlib

ROOT=Path(__file__).resolve().parent
PACKAGE=ROOT.parent
def need(ok,why):
    if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(name):return (ROOT/name).read_bytes()

def main():
    helper=(PACKAGE/'verify_host_controller_originals.py').read_bytes()
    need(pin(helper)=={'bytes':16570,'sha256':'be2b96db92bb456a798c3f8be6c1425a81e3afeadf782940bd695cf4cb3c714a'},'exact controller reader')
    M=types.ModuleType('actual_controller_archive');M.__file__=str(PACKAGE/'verify_host_controller_originals.py')
    exec(compile(helper,M.__file__,'exec'),M.__dict__)
    publication=json.loads((PACKAGE/'publication/ROOT-ACTUAL-PUBLICATION-CONTROLLER.original.json').read_bytes())
    job,status,output=M.controller(publication,code=0,complete=True)
    need(job['id']=='1a1b25d70f9-fc05-7db5'and len(output['stdout'])==808 and output['stderr']==b'',
         'actual once-only source publication original')
    publisher=(PACKAGE/'publication/publish_controller_source_package_once.py').read_bytes()
    need(publication['request']['stdin'].encode()==publisher
         and pin(publisher)=={'bytes':308748,'sha256':'755135e1cbe32296171b372ef4aa8809128b64d90ae598570ef8fba69870ee3d'},
         'complete actual reviewed publisher stdin')
    published=json.loads(output['stdout'])
    record=json.loads(read('READ-CONTROLLER.original.json'))
    observation,unused,streams=M.controller(record,code=0,complete=True)
    need(observation['id']=='1a1b25f8f91-fc05-7dc2'and len(record['reads'])==4
         and streams['stdout']==read('ORIGINAL-TRANSFER.stdout.json')and streams['stderr']==b''
         and record['request']['stdin'].encode()==read('observe_controller_source_originals.py'),
         'complete actual readonly transport and original observation source')
    transfer=json.loads(streams['stdout'])
    z=zlib.decompressobj();raw=z.decompress(base64.b64decode(transfer['raw_zlib_base64'],validate=True),4*1024*1024+1)
    need(z.eof and not z.unused_data and not z.unconsumed_tail and raw==read('PUBLISHED-CONTROLLER-ORIGINALS.json')
         and pin(raw)==transfer['uncompressed']and transfer['all_observation_fds_closed']is True,
         'whole raw source observation with hash and EOF')
    value=json.loads(raw);need(value['file_count']==27 and len(value['groups'])==1,'exact complete actual source package')
    group=value['groups'][0];all_files={};names=set()
    expected_payload=json.loads((PACKAGE/'publication/PAYLOAD.original.json').read_bytes())
    metadata=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    for row in group['files']:
        body=read('actual/'+row['relative_path']);m=row['metadata']
        need(row['eof']is True and body==row['text'].encode()
             and pin(body)=={k:row[k]for k in ('bytes','sha256')}
             and body==base64.b64decode(expected_payload[row['relative_path']],validate=True),
             'actual file equals expected complete reviewed source payload')
        need(set(m)==set(metadata)and all(type(m[k])is int for k in metadata)
             and stat.S_ISREG(m['st_mode'])and stat.S_IMODE(m['st_mode'])==0o600
             and m['st_nlink']==1 and m['st_size']==len(body),'actual file full9')
        all_files[row['path']]=body;names.add(row['relative_path'])
    need(names==set(expected_payload)and len(names)==27,'all and only27 source files')
    terminal=json.loads(read('actual/DERIVATION.json'))
    need(read('actual/DERIVATION.json')==(PACKAGE/'publication/DERIVATION.expected.json').read_bytes()
         and {r['path']for r in terminal['files']}|{published['derivation']['path']}==set(all_files)
         and pin(all_files[published['derivation']['path']])=={k:published['derivation'][k]for k in ('bytes','sha256')}
         and pin(all_files[published['source_package']['path']])=={k:published['source_package'][k]for k in ('bytes','sha256')},
         'actual terminal and source manifest precisely match publication stdout and payload')
    for directory in group['directories']:
        parent=PurePosixPath(directory['relative_path']);expected=set()
        if str(parent)=='.':expected.update(('originals','source','requests','reference'))
        for name in names:
            path=PurePosixPath(name)
            if path.parent==parent:expected.add(path.name)
        need(directory['names']==sorted(expected),'exact actual directory names including empty owned directories')
    slots=[]
    for name,slot in (('derive_component_build_inputs_UNBOUND.py','FROZEN_INPUTS'),
                      ('derive_release_install_stages_UNBOUND.py','FROZEN_INPUTS'),
                      ('observe_p4_install_phase_UNBOUND.py','FROZEN_SPEC')):
        ns=[n for n in ast.parse(read('actual/source/'+name)).body if isinstance(n,ast.Assign)
            and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)and n.targets[0].id==slot]
        need(len(ns)==1 and ast.literal_eval(ns[0].value)is None,'actual source slot remains None')
        slots.append(name+':'+slot)
    package=json.loads(read('actual/SOURCE-PACKAGE.json'))
    need(len(package['sources'])==5 and all(package[k]is None for k in
         ('actual_new_NEG01','actual_new_NEG02','actual_BUILD','actual_install','actual_READY')),
         'actual source package does not manufacture execution identities')
    need(value['all_original_files_read_to_EOF']is True and value['all_directory_and_file_full9_bookended']is True,
         'all originals were fully bookended')
    result=dict(schema='hepta.fc33.actual-controller-source-archive-verification.v1',
        state='ACTUAL_27_CONTROLLER_SOURCE_ORIGINALS_VERIFIED_EXECUTION_UNBOUND',
        publication_job=job['id'],observation_job=observation['id'],actual_file_count=27,actual_source_count=5,
        actual_file_bytes=value['file_bytes'],complete_read_pages=4,original_full9_and_membership_verified=True,
        all_actual_original_bytes_equal_prepared_payload=True,actual_source_slots_None=slots,
        source_controls_rerun=0,actual_BUILD=None,actual_install=None,actual_READY=None,
        phone_calls=0,actor_dispatches=0,fixed19_credit=0)
    print(json.dumps(result,sort_keys=True,indent=2))

if __name__=='__main__':main()
