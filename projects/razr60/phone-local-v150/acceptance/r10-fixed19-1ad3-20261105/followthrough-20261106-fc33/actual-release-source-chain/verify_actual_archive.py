#!/usr/bin/env python3
"""Read-only revalidation of the actual 8+21 host source originals and carriers."""
import ast
import base64
import hashlib
import json
from pathlib import Path
import stat
import types
import zlib

ROOT = Path(__file__).resolve().parent


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def check(ok, why):
    if not ok:
        raise ValueError(why)


def read(name):
    return (ROOT/name).read_bytes()


def main():
    helper = read('reference/verify_host_controller_originals.py')
    check(pin(helper) == {'bytes':16570,'sha256':'be2b96db92bb456a798c3f8be6c1425a81e3afeadf782940bd695cf4cb3c714a'}, 'exact original controller reader')
    module = types.ModuleType('reviewed_actual_controller_reader')
    module.__file__ = str(ROOT/'reference/verify_host_controller_originals.py')
    exec(compile(helper,module.__file__,'exec'),module.__dict__)
    publication = json.loads(read('evidence/publication-controller.original.json'))
    job, status, streams = module.controller(publication, code=0, complete=True)
    check(job['id']=='1a1b1ff0f2e-fc05-7bef' and len(streams['stdout'])==2051 and streams['stderr']==b'', 'actual successful source publication original')
    check(pin(publication['request']['stdin'].encode()) == {'bytes':141651,'sha256':'477bb8c20d4868428761e403456e9c8b333b72607c8ff51aac404b2429dda342'}, 'exact source publisher v2 submitted')
    published = json.loads(streams['stdout'])
    observation = json.loads(read('evidence/original-read-controller.original.json'))
    observed_job, observed_status, output = module.controller(observation, code=0, complete=True)
    check(observed_job['id']=='1a1b205a071-fc05-7c0f' and len(observation['reads'])==24
          and output['stdout']==read('evidence/original-transfer.stdout.original.json')
          and output['stderr']==b'' and observation['request']['stdin'].encode()==read('observe_published_sources.py'), 'actual full original observation transport')
    transfer = json.loads(output['stdout'])
    compressed = base64.b64decode(transfer['raw_zlib_base64'],validate=True)
    decoder = zlib.decompressobj(); complete = decoder.decompress(compressed,4*1024*1024+1)
    check(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
          and pin(complete)==transfer['uncompressed'] and complete==read('evidence/PUBLISHED-SOURCE-ORIGINALS.original.json'), 'full original transfer hash and EOF')
    value = json.loads(complete); copied = json.loads(read('COPY-MAP.json'))
    check(value['file_count']==29 and value['file_bytes']==1272413
          and value['all_original_files_read_to_EOF'] is True and value['all_directory_and_file_full9_bookended'] is True
          and transfer['all_observation_fds_closed'] is True, 'original complete source observation scope')
    full = {}; metadata_names=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    for group in value['groups']:
        check(group['file_count']==(8 if group['tag']=='binding' else 21), 'exact two source namespaces')
        names = set()
        for row in group['files']:
            original = row['text'].encode(); name=group['tag']+'/'+row['relative_path']; local=read(name)
            check(row['eof'] is True and local==original and pin(local)=={k:row[k]for k in ('bytes','sha256')}, 'whole original local source copy')
            metadata=row['metadata']
            check(set(metadata)==set(metadata_names) and all(type(metadata[k])is int for k in metadata_names)
                  and stat.S_ISREG(metadata['st_mode']) and stat.S_IMODE(metadata['st_mode'])==0o600
                  and metadata['st_nlink']==1 and metadata['st_size']==len(local), 'actual original file full9')
            names.add(row['relative_path']);full[row['path']]=original
        terminal=json.loads(read(group['tag']+'/DERIVATION.json'))
        check({r['path']for r in terminal['files']}|{group['terminal']['path']}=={r['path']for r in group['files']}, 'terminal exact complete member list')
        for directory in group['directories']:
            parent=directory['relative_path']; expected=set()
            for name in names:
                relative=Path(name)
                parts=relative.parts if parent=='' else relative.relative_to(parent).parts if Path(parent) in relative.parents else ()
                if parts:expected.add(parts[0])
            check(directory['names']==sorted(expected), 'actual directory names exactly cover published files')
        for row in terminal['files']:
            check(pin(full[row['path']])=={k:row[k]for k in ('bytes','sha256')}, 'terminal raw source pin')
    check(len(full)==len(copied['files'])==29, 'all copies present once')
    for row in copied['files']:
        check(full[row['original']['path']]==read(row['group']+'/'+row['relative_path'])
              and pin(full[row['original']['path']])=={k:row['copy'][k]for k in ('bytes','sha256')}, 'complete explicit original/copy map')
    for key in ('binding_receipt','derivation','consumer','readiness','source_binding'):
        row=published[key];check(pin(full[row['path']])=={k:row[k]for k in ('bytes','sha256')}, 'actual publisher stdout binds actual readback '+key)
    inverses=[]
    proof=json.loads(read('binding/BINDING-PROOF.json'))
    changes=[('binding/source/release_boundaries.py',proof['consumer_change']),
             ('binding/source/derive_reviewed_release_sources_BOUND.py',proof['constructor_change'])]
    changes += [('derived/'+name,row)for name,row in json.loads(read('derived/SOURCE-CHANGES.json')).items()]
    for name,row in changes:
        body=read(name);check(pin(body)==row['candidate'] and row['complete_inverse']is True,'exact source candidate change pin')
        for change in reversed(row['changes']):
            before,after=change['before'].encode(),change['after'].encode()
            check(body.count(after)==1,'exact unique inverse source span');body=body.replace(after,before,1)
        check(pin(body)==row['parent'],'full source byte inverse pin')
        inverses.append({'source':name,'parent':row['parent'],'candidate':row['candidate']})
    slots=[]
    for name in ('verify_install_start_ready_UNBOUND.py','verify_install_retention_UNBOUND.py','install_retention_protocol_UNBOUND.py'):
        tree=ast.parse(read('derived/source/'+name))
        for node in tree.body:
            if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id.startswith('FROZEN_'):
                check(ast.literal_eval(node.value)is None,'unknown actual execution slot remains None')
                slots.append(name+':'+node.targets[0].id)
    result={'schema':'hepta.fc33.actual-source-archive-verification.v1',
        'state':'ACTUAL_SOURCE_PUBLICATION_AND_COMPLETE_29_ORIGINALS_VERIFIED',
        'publication_job':job['id'],'read_only_observation_job':observed_job['id'],
        'source_file_count':29,'source_file_bytes':1272413,'complete_actual_read_pages':24,
        'all_actual_streams_complete_durable_and_EOF':True,'all_original_full9_and_exact_directory_sets_verified':True,
        'full_source_inverse_count':len(inverses),'source_inverses':inverses,'actual_execution_slots_None':slots,
        'phone_calls_by_archive':0,'new_controls_executed':0,'actual_BUILD':None,'actual_install':None,'actual_READY':None,
        'current_case_qualified':False,'fixed19_credit':0}
    print(json.dumps(result,sort_keys=True,indent=2))


if __name__=='__main__':
    main()
