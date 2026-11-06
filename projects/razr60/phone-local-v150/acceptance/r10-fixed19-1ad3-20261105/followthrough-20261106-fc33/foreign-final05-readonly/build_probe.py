#!/usr/bin/env python3
"""Host-only exact source construction. Does not dispatch or execute the probe."""
from pathlib import Path
import ast
import base64
import hashlib
import json
import shlex
import zlib

D = Path(__file__).resolve().parent
R = D.parent/'R5-stage-parent-diagnosis01'
F = R/'foreign-final05'
def sha(b): return hashlib.sha256(b).hexdigest()
def encoded(v): return (json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
def read_json(p): return json.loads(p.read_bytes())
def pin(p):
    b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
def put(name,raw):
    p=D/name
    if p.exists():
        assert p.read_bytes()==raw, 'create-only output differs: '+name
    else:
        with p.open('xb') as s:s.write(raw)

donor = (F/'LIFECYCLE-CAUSE-COLLECTOR.original.py').read_bytes()
assert len(donor)==25720 and sha(donor)=='199a4005e8b1b6618f82261a8ebeea508fa305acb85db565174e4687a5791e60'
full = ast.parse(donor);text=donor.decode();nodes={n.name:n for n in full.body if isinstance(n,ast.FunctionDef)}
names=['need','sha','encoded','strict','metadata','parent_fd','stat_identity','generation','check_time',
       'read_fd','blob','absent_or_error','directory','proc_bytes','complete_row','inspect_pid']
helpers='\n\n'.join(ast.get_source_segment(text,nodes[n]) for n in names)+'\n\n'
lease=read_json(F/'cause-originals/LEASE.json');manifest=read_json(F/'cause-originals/package/MANIFEST.json')
mapping=read_json(F/'cause-originals/ORIGINAL-MAP.json')
boundary=read_json(D.parent/'R5-agent-late/history-inputs/NEG01-BOUNDARY.original.json')
summary=read_json(R/'CURRENT44-EXISTING-SUMMARY.original.json')
indices=read_json(R/'FOREIGN-P4-EXISTING-INDEX.original.json')
scope_home='/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/'+lease['label']
android_home='/proc/1/root'+lease['android_journal'].rsplit('/executor',1)[0]
transport=[]
for suffix in ('-copy-material','-copy-stage-source'):
    result=next(r['result'] for r in indices['rows'] if r['directory'].endswith(suffix))
    value=json.loads(result['stdout'])
    transport.append(value['target'])
    transport.append({'path':value['source'],'bytes':value['target']['bytes'],'sha256':value['target']['sha256'],
                      'metadata':value['source_metadata']})
known={k:{x:v[x] for x in ('bytes','sha256','metadata','selinux_raw_b64')} for k,v in mapping.items()}
inputs={'schema':'hepta.fc33.failed-final05-readonly-inputs.v1','lease':lease,
    'runtime_files':manifest['files'],'baseline':boundary['inventory'],
    'boundary':lease['prior_boundary'],'baseline_roots':summary['roots'],
    'foreign_server_lock':known[android_home+'/executor/server.lock'],
    'known_originals':known,'transport':transport,
    'archive_path':transport[0]['path'],
    'role_identities':{'supervisor':[29207,29207,29207,32401303],'sidecar':[30384,30384,30384,32404591]},
    'parent_paths':['/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1',
                    '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1',
                    '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-staging-r10-r1',
                    '/proc/1/root/data/local/tmp/hepta-phone-local-v150-r1'],
    'inspect_absence_names':['provider.SPAWN-INTENT.json','provider.SPAWNED.json','provider.barrier.json',
        'provider.ADMIT.json','provider.TERM-INTENT.json','provider.JOINED.json','provider.stdout','provider.stderr',
        'SIDECAR-HEALTH.original.json','BOUND-CONTRACT.json','PROVIDER-HEALTH.original.json','READY.json',
        'CONNECTION-ACCEPTED.json','ACCEPTED.json','PROVIDER-ENDED.json','ROOT-SETUP-PLAN.json'],
    'historical_sender_original':pin(F/'sender-execute/stdout.original'),
    'historical_root_failure':pin(F/'ROOT-FAILURE.json'),
    'original_cause_operation':pin(F/'LIFECYCLE-CAUSE-OPERATION.original.json'),
    'original_cause_packet':pin(F/'LIFECYCLE-CAUSE-PACKET.original.json')}
assert len(inputs['runtime_files'])==37 and len(inputs['baseline_roots'])==44
inputraw=encoded(inputs);put('INPUTS.json',inputraw)
header='''#!/usr/bin/env python3
"""One exact failed final05 scope: read-only preservation, never cleanup/qualification."""
import base64
import errno
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import sys
import tarfile
import time
import zlib

'''
header+='INPUTS_RAW = '+repr(inputraw)+'\nINPUTS_SHA = '+repr(sha(inputraw))+'\n'
header+='INPUTS = json.loads(INPUTS_RAW)\nassert hashlib.sha256(INPUTS_RAW).hexdigest() == INPUTS_SHA\n'
header+='BOOT = '+repr(lease['boot_id'])+'\nLABEL = '+repr(lease['label'])+'\nNONCE = '+repr(lease['nonce'])+'\n'
header+='LEASE_SHA = '+repr(sha((F/'cause-originals/LEASE.json').read_bytes()))+'\nPACKAGE_SHA = '+repr(sha((F/'cause-originals/package/MANIFEST.json').read_bytes()))+'\n'
header+='SCOPE_HOME = Path('+repr(scope_home)+')\nANDROID_HOME = Path('+repr(android_home)+')\n'
header+="ANDROID = Path('/proc/1/root')\nJOURNAL = ANDROID_HOME/'executor'\nFIXTURE = ANDROID/'data/local/tmp'/('hepta-native-guard-'+NONCE)\n"
header+='BASELINE_FILE_BYTES = 44353573\nMAX_FILE = 16*1024*1024\nMAX_READ_BYTES = 160*1024*1024\nMAX_BLOB_BYTES = 16*1024*1024\nMAX_PRIVATE_TREE_BYTES = 16*1024*1024\nMAX_PACKET = 32*1024*1024\nMAX_OUTPUT = 8*1024*1024\nMAX_SECONDS = 45\nMAX_ENTRIES = 30000\nMAX_PIDS = 4096\nCENSUS_SECONDS = 2\nSTATE = None\n\n'
raw=(header+helpers+(D/'probe_extension.py').read_text()).encode()
compile(raw,'<fresh-final05-readonly>','exec')
put('SOURCE.py',raw)
compressed=zlib.compress(raw,9)
payload="import base64,hashlib,zlib\ndata=base64.b64decode(%r,validate=True)\nassert len(data)==%d and hashlib.sha256(data).hexdigest()==%r\ndecoder=zlib.decompressobj()\nraw=decoder.decompress(data,%d)\nassert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail\nassert len(raw)==%d and hashlib.sha256(raw).hexdigest()==%r\nexec(compile(raw,'<fc33-final05-readonly>','exec'),{'__name__':'__main__'})\n"%(base64.b64encode(compressed).decode(),len(compressed),sha(compressed),len(raw)+1,len(raw),sha(raw))
original_command=(F/'LIFECYCLE-CAUSE-COMMAND.original.sh').read_text()
outer=shlex.split(original_command);assert outer[:2]==['/debug_ramdisk/su','-c']
inner=shlex.split(outer[2]);assert inner[-2]=='-c' and inner[-5:-2]==['/usr/bin/python3','-I','-B']
command=shlex.join(outer[:2]+[shlex.join(inner[:-1]+[payload])])+'\n'
request=encoded({'kind':'shell','root':True,'timeout_seconds':70,'command':command})
assert len(command.encode())<=65535 and len(request)<=65535
put('PHONE-REQUEST.json',request)
put('PHONE-COMMAND.sh',command.encode())
limitations=[
 'No deletion, cleanup admission, source-parent qualification or new case credit is granted.',
 'No historical failed cmdline bytes, exact failing PID sample, supervisor wait status, or provider nonexistence over all past time can be reconstructed.',
 'Current proc/census/kernel signal-zero results apply only to the two fresh windows and exact recorded identities.',
 'All37 runtime and61 staged members are read as bytes, not imported or executed.',
 'Historical sender0/draft restore and child wait remain separate exact originals; this phone probe cannot prove current host draft state or host controller termination.',
 'No fixture/claim/action record plus unchanged44 inventory is scoped negative evidence; it is not by itself a universal zero-effect assertion.',
 'Any concurrent change, held lock, unknown I/O, new active group, deadline, truncation or cap failure leaves UNKNOWN and no automatic replay.'
]
review={'schema':'hepta.fc33.failed-final05-readonly-plan.v1','state':'SOURCE_READY_FOR_ROOT_REVIEW_NOT_DISPATCHED',
 'source':pin(D/'SOURCE.py'),'inputs':pin(D/'INPUTS.json'),'request':pin(D/'PHONE-REQUEST.json'),
 'command':pin(D/'PHONE-COMMAND.sh'),'donor':pin(F/'LIFECYCLE-CAUSE-COLLECTOR.original.py'),
 'helper_functions_copied_verbatim':names,'extension':pin(D/'probe_extension.py'),
 'transport_environment':'exact argv from previously executed lifecycle-cause01, payload only replaced',
 'proposed_operation_label':'ng-fc33-final05-failed-scope-readonly01',
 'proposed_idempotency_key':'fc33-final05-failed-scope-readonly01',
 'p4_request_path':'/home/alex/razr60-local-model-v150/requests/ng-fc33-final05-failed-scope-readonly01.json',
 'phone_actor':{'path':'/home/alex/razr60-local-model-v150/ops/phone_once.py','bytes':5652,
                 'sha256':'179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'},
 'observed_baseline':{'roots':44,'entries':3823,'files':3495,'file_bytes_hashed_each_window':44353573,
                      'lock_aliases':26,'lock_inode_groups':14},
 'private_scope':{'stage_members':61,'runtime_files':37,'known_role_originals':len(known),
   'lock_aliases_with_foreign':28,'lock_inode_groups_with_foreign':15,
   'read_roots':[scope_home,android_home+'/executor','/proc/1/root/data/local/tmp/hepta-native-guard-'+lease['nonce']]},
 'bounds':{'phone_source_bytes':len(raw),'compressed_source_bytes':len(compressed),'wire_command_bytes':len(command.encode()),
  'wire_request_bytes':len(request),'wire_cap':65535,'stdout_cap':8*1024*1024,'raw_packet_cap':32*1024*1024,
  'read_budget':160*1024*1024,'unique_preserved_original_budget':16*1024*1024,'deadline_seconds':45,'actor_timeout_seconds':70},
 'signal_queries':{'known_groups':[29207,30384],'windows':2,'syscall':'os.kill(-pgid,0)','required_errno':'ESRCH',
  'maximum_nonzero_signals_to_other_processes':0},
 'phone_calls_executed_by_builder':0,'model_requests':0,'native_dispatches':0,'deletion_authorized':False,
 'actual_publish':None,'actual_dispatch':None,'actual_result':None,'remaining_conditions':limitations}
put('MANIFEST.json',encoded(review))
print(json.dumps({'source':review['source'],'inputs':review['inputs'],'request':review['request'],'bounds':review['bounds']}))
