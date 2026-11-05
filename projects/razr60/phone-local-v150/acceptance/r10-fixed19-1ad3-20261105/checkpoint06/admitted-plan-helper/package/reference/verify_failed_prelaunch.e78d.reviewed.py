#!/usr/bin/env python3
"""Independently reconcile two original failed prelaunch attempts, never qualify them.

Pure verification consumes exact original bytes through read_pinned.  The CLI
writes a fresh admission only after every required original and current gate
has passed.  No phone, process, source-generation, signal or nonce operation is
available here.  Missing current publication or external09 evidence rejects.
"""
import argparse
import ast
import base64
import hashlib
import io
import json
import lzma
import math
import os
from pathlib import Path
import re
import shlex
import stat
import tarfile
import zlib

B='/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
PHONE='/var/lib/trillionnium/owner-open/phone-local-v150'
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
LABELS=('root-r10-neg01-20261105-09','root-r10-neg01-1ad3-01')
ACTUAL08={'bytes':9373,'metadata':[65086,153711,33152,0,0,1,9373,1793853757339925229,1793853757339925229],
 'path':PHONE+'/native-guard-boundaries-r10-r1/2b0b103ee6de7a422064b9571266bf5d.json',
 'sha256':'eca941303197228ebe03561e612bfe41eb0518c590ff21253444db25a11adc10'}
RUNTIME=(16808,'67dc40470b8ecb1e10cb57f8953a3d0b6db309b45079216eb24cd65f0760107c')
COMBINATION=(4702,'54b1d9aef4c16ebc0989b3e13345238bfbd4e400e5bfc9a97e27648a2385057e')
SENDER=(40952,'aafd40345c6dc35b7b7d34ab8b04c860ebf17d326d842ed733d0404cd0a051ad')
READY=(18666,'f3b83e55a07edd370946c40cec8694f310c9713082604646d264b625e7314d99')
OLD_SENDER=(40788,'5ab04019e94adb989e9909ae3a9aa10db0689de62821ec549db8beb3ec4d0281')
STAGE_TEMPLATE=(20268,'fdfa661921d8f5a80bae3f7ac07812c666188625a9e23b7951df8f4b8b1048ac')
GLOBAL_SOURCE=(17039,'118d821b2007c41b6cea23ced070452c7376aa31b2829c7c4fb91e6724c0c5ba')
ACTOR_1AD3=(82841,'4e470e5a3c255c80c93fe8d3f3b7940d084cda7d9429ab06bb2735e3c05502cd')
ACTOR_EXTERNAL09=(82909,'34c1534d5985bd643c74361a5009b980e5684d6f1373b2e34eed7fcbde283e04')
# Exact reviewed source for the actual two-attempt current publication and
# selected-state observation; a different source is never an implicit waiver.
CURRENT_PUBLICATION_SOURCE_TEMPLATE=(13192,'1956c026152ff82a9c3065388139c8782c55c5788afa9cfeacfef054651f18ed')
PHONE_ACTOR_SHA='179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'
# These are the four actual, retained controller stdin programs. They are
# parsed as data, never imported. Trusted controller receipts remain the
# execution-origin evidence; no stdin digest reconstruction is claimed.
READONLY_LAUNCHERS={
 STAGE_TEMPLATE[1]:((51692,'a6823b2544c19dbf38aaa178298ba61d8271dd4e4fe28775b5c7a5763f370ae7'),
  '1a1ab32d7b6-fc05-4b5b','fixed19-root-1ad3-neg01-stage-read01'),
 'a460562d2217bcbbd167ac6a4ae2e38d4713da05dee8b57337ff4ce3eceb37be':
  ((48346,'8c30eda635a93396d5e7ed46cf4a1ef6900d6f19c80a47b6a9c573622e9ea9b7'),
   '1a1ab5f2e9d-fc05-4d0f','fixed19-root-1ad3-external09-stage-read01'),
 GLOBAL_SOURCE[1]:((41213,'046e6ca126c5c5bb204301a9d44f833e3051d5844ec4d118495d30194202ab26'),
  '1a1ab559f85-fc05-4cb3','fixed19-root-1ad3-neg01-retired-read02'),
 CURRENT_PUBLICATION_SOURCE_TEMPLATE[1]:
  ((33230,'1593b08bc5bea4b7f0b8d213296376cfe9b7962fb9734a30696dd5beff25f668'),
   '1a1ab5cfe76-fc05-4d02','fixed19-root-1ad3-failed-prelaunch-current-read01')}
MAX_FILE=16*1024*1024
MAX_READSET=32*1024*1024
MAX_ARCHIVE_PLAIN=16*1024*1024
MAX_INPUT=1024*1024
HASH=re.compile('[0-9a-f]{64}\\Z')
NONCE=re.compile('[0-9a-f]{32}\\Z')
PHASES=('prepare-material','host-stage-material','phone-push-material','phone-copy-material',
        'phone-push-stage-source','phone-copy-stage-source','phone-stage','sender-preview','sender-prepared')
ATTEMPT_FIELDS={'label','root_plan','root_failure','chain_intent','prepared','component_archive',
 'sender_inventory','sender_archive_xz','sender_result','sender_actor','sender_execute_intent','sender_child',
 'mac_sender_absence','stage_observation'}
OBSERVATION_FIELDS={'source','launcher_source','controller_start','controller_status','controller_read','launcher_result',
 'joined','phone_intent','phone_result','phone_stdout'}

def need(ok,why):
    if not ok:raise ValueError(why)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def encoded(value):
    return (json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()

def strict(raw):
    def pairs(rows):
        value={}
        for key,item in rows:
            need(key not in value,'duplicate JSON key');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))

def exact(value,fields,why):
    need(type(value) is dict and set(value)==set(fields),why)

def bare(raw):return {'bytes':len(raw),'sha256':sha(raw)}

def identity(raw):return (len(raw),sha(raw))

def descriptor(value):
    exact(value,('path','bytes','sha256'),'exact3 original descriptor required')
    p=Path(value['path']) if type(value['path']) is str else Path('.')
    need(p.is_absolute() and str(p)==value['path'] and '..' not in p.parts
         and type(value['bytes']) is int and 0<=value['bytes']<=MAX_FILE
         and type(value['sha256']) is str and HASH.fullmatch(value['sha256']),
         'bounded canonical original descriptor required')
    return value

class Originals:
    def __init__(self,callback):
        need(callable(callback),'read_pinned callback required');self.callback=callback;self.rows={};self.total=0
    def read(self,row,maximum=MAX_FILE,expected=None):
        row=descriptor(row);need(row['bytes']<=maximum,'original per-role budget')
        if row['path'] in self.rows:need(self.rows[row['path']]==row,'one path has conflicting original identities')
        else:
            self.total+=row['bytes'];need(self.total<=MAX_READSET and len(self.rows)<256,'bounded proof readset')
            self.rows[row['path']]=dict(row)
        raw=self.callback(row)
        need(type(raw) is bytes and bare(raw)=={k:row[k] for k in ('bytes','sha256')},'original bytes differ')
        if expected is not None:need(identity(raw)==expected,'reviewed exact source/original differs')
        return raw
    def value(self,row,maximum=MAX_FILE,expected=None):return strict(self.read(row,maximum,expected))
    def recheck(self):
        for row in list(self.rows.values()):self.read(row,row['bytes'])

def unpack(raw,kind):
    if kind=='gzip':decoder=zlib.decompressobj(16+zlib.MAX_WBITS)
    elif kind=='xz':decoder=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=64*1024*1024)
    else:raise ValueError('fixed archive codec required')
    if kind=='gzip':plain=decoder.decompress(raw,MAX_ARCHIVE_PLAIN+1)
    else:plain=decoder.decompress(raw,max_length=MAX_ARCHIVE_PLAIN+1)
    need(len(plain)<=MAX_ARCHIVE_PLAIN and decoder.eof and not decoder.unused_data,
         'one complete bounded archive compression stream required')
    if kind=='gzip':need(not decoder.unconsumed_tail,'unconsumed compressed suffix')
    files={};total=0
    with tarfile.open(fileobj=io.BytesIO(plain),mode='r:') as archive:
        for member in archive:
            p=Path(member.name)
            need(member.isfile() and not member.issparse() and not member.pax_headers
                 and not p.is_absolute() and '..' not in p.parts and str(p)==member.name
                 and member.name not in files and 0<=member.size<=MAX_FILE and len(files)<1024,
                 'bounded unique regular archive member required')
            with archive.extractfile(member) as stream:body=stream.read(member.size+1)
            need(len(body)==member.size,'archive member size differs')
            total+=len(body);need(total<=MAX_ARCHIVE_PLAIN,'archive body total exceeded')
            files[member.name]=body
        need(not plain[archive.offset:].strip(b'\0'),'nonzero bytes after tar end')
    return files

def literals(raw):
    result={}
    for node in ast.parse(raw).body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            name=node.targets[0].id
            try:value=ast.literal_eval(node.value)
            except (ValueError,TypeError):continue
            need(name not in result,'duplicate top-level literal binding');result[name]=value
    return result

def replace_literal_source(raw,replacements):
    """Replace only exact top-level RHS byte spans, keeping every other byte."""
    text=raw.decode();lines=text.splitlines(keepends=True);offsets=[];pos=0
    for line in lines:offsets.append(pos);pos+=len(line.encode())
    spans={}
    for n in ast.parse(raw).body:
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name):
            name=n.targets[0].id
            if name in replacements:
                need(name not in spans,'one literal binding required')
                spans[name]=(offsets[n.value.lineno-1]+n.value.col_offset,
                             offsets[n.value.end_lineno-1]+n.value.end_col_offset)
    need(set(spans)==set(replacements),'literal binding slot missing')
    for name,(start,end) in sorted(spans.items(),key=lambda row:row[1][0],reverse=True):
        raw=raw[:start]+replacements[name]+raw[end:]
    return raw

def controller(value):
    # Some retained responses are the exact Promise.allSettled wrapper.
    # Unwrap only its successful two-field form, never a rejected result.
    if type(value) is dict and 'status' in value:
        exact(value,('status','value'),'exact settled controller receipt required')
        need(value['status']=='fulfilled','controller request was not fulfilled')
        value=value['value']
    if type(value) is dict and 'content' in value:
        need(value.get('isError') is not True,'controller tool error cannot prove completion')
        structured=value.get('structuredContent')
        if type(structured) is dict and structured:return structured
        blocks=[x for x in value['content'] if type(x) is dict and x.get('type')=='text']
        need(len(blocks)==1,'one complete original controller response required')
        return strict(blocks[0]['text'])
    need(type(value) is dict,'controller response object required');return value

def completed_controller(O,record):
    start=controller(O.value(record['controller_start'],MAX_INPUT))
    status=controller(O.value(record['controller_status'],MAX_INPUT))
    read=controller(O.value(record['controller_read'],MAX_INPUT))
    job=start['job']
    need(job['host']=='pocket4' and job['executable']=='/usr/bin/python3'
         and job['args']==['-I','-B','-'] and job['id']==status['job_id']==read['job_id'],
         'actual Pocket4 controller identity differs')
    need(status['state']=='succeeded' and status['exit_code']==0 and not status['timed_out']
         and not status['cancelled'] and status['output_complete'] is True and status['output_durable'] is True
         and status['terminal_publication_confirmed'] is True
         and all(x is False for x in status['log_truncated'].values())
         and all(x is None for x in status['log_errors'].values())
         and all(x is True for x in status['log_synced'].values()),'complete durable controller terminal required')
    streams={}
    for name in ('stdout','stderr'):
        row=read[name];body=bytes.fromhex(row['bytes_hex'])
        need(row['offset']==0 and row['eof'] is True and row['size']==row['next_offset']==len(body)
             and status['log_bytes'][name]['seen']==status['log_bytes'][name]['stored']==len(body)
             and row['text'].encode()==body,'complete original controller stream differs')
        streams[name]=body
    need(streams['stderr']==b'','controller stderr is not empty')
    records=[strict(line) for line in streams['stdout'].splitlines()]
    result_raw=O.read(record['launcher_result'],65536)
    matches=[x for x in records if type(x) is dict and type(x.get('result')) is dict
             and {k:x['result'][k] for k in ('bytes','sha256')}==bare(result_raw)]
    need(len(matches)==1 and matches[0]['actor_returncode']==matches[0]['phone_returncode']==0,
         'controller terminal stdout does not name the successful native collector result')
    # Native rc is separately required below. A successful collector is never
    # accepted as proof that the original phone verification succeeded.
    return {'job_id':job['id'],'created_unix_ms':job['created_unix_ms'],'terminal_unix_ms':status['at_unix_ms'],
            'launcher_result_original':descriptor(matches[0]['result'])}

def phone_observation(O,record,source_expected=None):
    exact(record,OBSERVATION_FIELDS,'complete native observation originals required')
    source=O.read(record['source'],262144,source_expected)
    need(sha(source) in READONLY_LAUNCHERS,'one of the four actual read-only observations is required')
    launcher_pin,job_id,out_name=READONLY_LAUNCHERS[sha(source)]
    launcher=O.read(record['launcher_source'],262144,launcher_pin)
    bound=literals(launcher)
    control=completed_controller(O,record)
    need(control['job_id']==job_id and bound['PROBE']==source
        and control['launcher_result_original']['path']=='/home/alex/razr60-local-model-v150/'+out_name+'/RESULT.json',
        'retained controller job, actual launcher and original result namespace differ')
    joined=O.value(record['joined'],16384);need(joined['wait_returned'] is True and joined['returncode']==0
        and joined['signals_sent']==0,'read-only observer actor did not join normally')
    intent=O.value(record['phone_intent'],MAX_INPUT);native=O.value(record['phone_result'],8*1024*1024)
    stdout=O.read(record['phone_stdout'],MAX_INPUT);result=O.value(record['launcher_result'],65536)
    need(native['schema']=='hepta.phone-local.operator-result.v150.1'
         and intent['schema']=='hepta.phone-local.operator-intent.v150.1'
         and native['label']==intent['label'] and native['status']=='command_exited'
         and native['model_decision'] is False and native['native_task_result'] is False,
         'actual read-only native wrapper shape differs')
    request=intent['request'];exact(request,('kind','root','timeout_seconds','command'),'one shell request required')
    request_raw=(json.dumps(request,sort_keys=True,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode()
    need(bound['REQ']==request and bound['LABEL']==intent['label']
         and intent['request_sha256']==sha(request_raw) and intent['automatic_replay'] is False,
         'actual launcher request bytes and native intent differ')
    need(request['kind']=='shell' and request['root'] is True and type(request['timeout_seconds']) is int
         and 1<=request['timeout_seconds']<=210,'bounded Root read-only request required')
    outer=shlex.split(native['phone']['command'])
    need(outer==['/debug_ramdisk/su','-c',request['command']],'native command differs from original request')
    expected=['/data/adb/magisk/busybox','env','-i','PATH=/usr/bin:/bin:/usr/libexec/trillionnium',
      'PYTHONHOME=/usr','PYTHONDONTWRITEBYTECODE=1',
      'LD_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu/android:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu',
      'LANG=C.UTF-8','LC_ALL=C.UTF-8','TMPDIR=/var/lib/trillionnium/owner-open/tmp','NO_COLOR=1','TERM=dumb',
      '/data/adb/magisk/busybox','chroot','/data/trillionnium/owner-open/root','/usr/bin/python3','-I','-B','-c',source.decode()]
    prefix=' '.join(expected[:-2]);command=request['command']
    if command==prefix+' -c '+shlex.quote(source.decode()):
        encoding={'kind':'exact_shell_quoted_c_argument','program_bytes':len(source),'program_sha256':sha(source)}
    else:
        # The actual 118d launcher used a literal quoted heredoc and retained
        # one extra terminal LF before its delimiter. Bind that exact payload
        # separately; do not pretend its byte hash equals the source file.
        match=re.fullmatch(re.escape(prefix)+r" - <<'([A-Z][A-Z0-9_]{0,63})'\n([\s\S]*)",command)
        need(match is not None,'unreviewed native source transport grammar')
        marker,body=match.groups();need(marker not in source.decode().splitlines()
            and body==source.decode()+'\n'+marker,'literal heredoc payload differs beyond one explicit final LF')
        payload=source+b'\n'
        encoding={'kind':'literal_quoted_heredoc_with_one_terminal_LF','delimiter':marker,
                  'program_bytes':len(payload),'program_sha256':sha(payload),'added_terminal_LF_bytes':1}
    need(native['phone']['rc']==0 and native['phone']['stderr']==''
         and native['phone']['stdout'].encode()==stdout,'source-bound actual native call did not succeed')
    need(result['actor_returncode']==result['phone_returncode']==0
         and result['phone_status']=='command_exited' and result['source_sha256']==sha(source)
         and {k:result['phone_stdout'][k] for k in ('bytes','sha256')}==bare(stdout)
         and result['signals_sent']==0 and result['automatic_retry'] is False and result['case_pass'] is False
         and result['native_boundary_created'] is False,'native collector crosslink differs')
    need({k:result['phone_originals']['intent.json'][k] for k in ('bytes','sha256')}==bare(O.read(record['phone_intent']))
         and {k:result['phone_originals']['result.json'][k] for k in ('bytes','sha256')}==bare(O.read(record['phone_result'])),
         'native original manifest crosslink differs')
    control['source_transport']=encoding
    control['retained_launcher_source']=bare(launcher)
    control['launcher_pinned_phone_actor_sha256']=PHONE_ACTOR_SHA
    control['execution_origin']='TRUSTED_RETAINED_CONTROLLER_TOOL_RECEIPTS'
    control['controller_stdin_digest_recomputed']=False
    return strict(stdout),source,control

def material(O,attempt):
    label=attempt['label'];prepared=O.value(attempt['prepared'],65536)
    archive=O.read(attempt['component_archive'],MAX_FILE)
    need(bare(archive)==prepared['archive'] and prepared['label']==label
         and prepared['case_id']=='NEG-01' and prepared['package_sha256']==RUNTIME[1]
         and prepared['component_qualified'] is False and prepared['business_qualified'] is False,
         'actual material original differs')
    files=unpack(archive,'gzip');need(len(files)==prepared['archive_members']==56,'actual staged archive closed set differs')
    lease_raw=files['LEASE.json'];lease=strict(lease_raw);contract_raw=files['sender-contract.json'];contract=strict(contract_raw)
    nonce=lease['nonce'];need(type(nonce) is str and NONCE.fullmatch(nonce),'actual failed nonce required')
    need(lease['label']==label and lease['boot_id']==BOOT and lease['prior_boundary']==ACTUAL08
         and lease['case_id']=='NEG-01' and lease['package_sha256']==RUNTIME[1]
         and identity(files['inputs/COMBINATION.json'])==COMBINATION
         and identity(files['package/MANIFEST.json'])==RUNTIME
         and prepared['nonce']==nonce and prepared['lease']==bare(lease_raw)
         and prepared['combination']==bare(files['inputs/COMBINATION.json'])
         and prepared['owner_request_sha256']==sha(files['owner-request.txt'])==lease['owner_request_sha256'],
         'lease, current policy combination and actual08 binding differ')
    need(contract['nonce']==nonce and contract['label']==label and contract['boot_id']==BOOT
         and contract['lease_sha256']==sha(lease_raw) and contract['owner_request_sha256']==lease['owner_request_sha256']
         and contract['package_sha256']==RUNTIME[1] and contract['combination_sha256']==COMBINATION[1]
         and contract['expires_unix_ms']==lease['expires_unix_ms']
         and sha(contract_raw)==prepared['sender_contract_sha256'],'actual sender contract differs')
    manifest=strict(files['package/MANIFEST.json']);need(len(manifest['files'])==32,'runtime32 required')
    for row in manifest['files']:
        need(bare(files['package/'+row['path']])=={k:row[k] for k in ('bytes','sha256')},'runtime member byte identity differs')
    return prepared,files,lease,contract

def root_failure(O,attempt,prepared,lease):
    failure=O.value(attempt['root_failure'],MAX_INPUT);plan=O.value(attempt['root_plan'],MAX_INPUT)
    chain=O.value(attempt['chain_intent'],16384);label=attempt['label'];case_root=B+'/native-guard-root-chains-r10-r1/'+label
    need(failure['state']=='FAILED_OR_UNKNOWN_ORIGINALS_PRESERVED_NO_AUTOMATIC_CONTINUATION'
         and failure['detail']=='same lease exhausted; no extension/restart' and failure['root_fixture_attempts']==[]
         and failure['component_qualified'] is False and failure['business_qualified'] is False
         and failure['send_again'] is False and failure['new_identity_retry'] is False
         and failure['signals_sent_by_coordinator']==0 and failure['policy_changes']==0 and failure['model_requests']==0,
         'only the actual prelaunch 510-gate failures may be reconciled')
    need(chain['label']==plan['label']==label and chain['nonce']==plan['nonce']==lease['nonce']
         and chain['lease_expires_unix_ms']==lease['expires_unix_ms'] and plan['out']==case_root
         and plan['boot_id']==BOOT and plan['case_id']=='NEG-01'
         and plan['prior_boundary_original']['sha256']==ACTUAL08['sha256'],'original Root plan/chain differs')
    need(bare(O.read(plan['prior_boundary_original']))=={k:ACTUAL08[k] for k in ('bytes','sha256')}
         and O.value(plan['prior_boundary_descriptor'],16384)==ACTUAL08,'actual08 retained original descriptor differs')
    steps=failure['steps'];need([x['phase'] for x in steps]==list(PHASES),'actual failure prefix changed or launch was reached')
    prefix={}
    for step in steps:
        need(step['state']=='ORIGINAL_HOST_CHILD_JOINED' and step['returncode']==0 and step['automatic_retry'] is False,
             'original prelaunch step did not join normally')
        for stream in ('stdout','stderr'):
            row=step[stream];need(row['path']==case_root+'/'+step['phase']+'/'+stream+'.original','Root prefix original namespace differs')
            prefix[step['phase']+'/'+stream]=O.read(row)
            if stream=='stderr':need(prefix[step['phase']+'/'+stream]==b'','prelaunch stderr differs')
    if label==LABELS[1]:
        cleanup=failure['host_cleanup'];need(cleanup['stream_cleanup_errors']==[] and len(cleanup['host_children'])==1,
                                             'original failed host cleanup changed')
        child=cleanup['host_children'][0];capture=child['output_capture']
        need(child['state']=='OWNED_HOST_CHILD_NOT_JOINED_NO_SIGNAL_OR_RETRY'
             and child['returncode'] is None and child['signals_sent']==0 and capture['child_wait_returned'] is False
             and capture['prefix_only_or_unknown'] is True and capture['stdout_eof'] is False and capture['stderr_eof'] is False
             and capture['remote_terminal_or_cleanup_proven'] is False,'original missing join/EOF must remain unmodified')
        for stream in ('stdout','stderr'):
            row=capture['files'][stream]
            O.read({k:row[k] for k in ('path','bytes','sha256')})
    return failure,plan,prefix

def actor_source_relation(raw,reference,ready,files,contract,label):
    actor=literals(raw);old=literals(reference)
    common=bare(files['package/source/component_common.py']);life=bare(files['package/source/component_lifecycle.py'])
    home=PHONE+'/native-guard-r10-r1/'+label
    binding={'schema':'hepta.native-guard.sender-binding.v1','contract':contract,
      'contract_sha256':sha(files['sender-contract.json']),'contract_bytes':len(files['sender-contract.json']),
      'contract_original_b64':base64.b64encode(files['sender-contract.json']).decode(),
      'source_sha256':sha(files['package/source/component_listener.py']),'common_pin':common,'lifecycle_pin':life,
      'phone_home':home,'phone_contract_path':home+'/sender-contract.json','phone_ready_path':home+'/READY.json',
      'phone_source_path':home+'/package/source/component_listener.py'}
    need(actor['component_binding']==binding,'generated actor complete readiness binding differs')
    ready_tree=ast.parse(ready);fn=next(n for n in ready_tree.body if isinstance(n,ast.FunctionDef) and n.name=='validate_ready_observation')
    validator=''.join(ready.decode().splitlines(keepends=True)[fn.lineno-1:fn.end_lineno])
    probe=literals(ready)['PHONE_SOURCE'].replace('__BOUND__',repr(actor['component_binding'])).replace('__VALIDATOR__',validator)
    need(actor['COMPONENT_READY_PROBE_SOURCE']==probe,'generated readiness code differs from the exact f3b8 generator')
    # The pinned original actor's executable body is retained in full. Only
    # these case/draft data RHS and the literal case label in original UI temp
    # names may differ. No candidate code is imported or executed here.
    names=('label','preserved_draft','component_binding','COMPONENT_READY_PROBE_SOURCE','expected','out')
    replacements={}
    for n in ast.parse(reference).body:
        if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id in names:
            replacements[n.targets[0].id]=ast.get_source_segment(reference.decode(),n.value).encode()
    out=next(n.value for n in ast.parse(raw).body if isinstance(n,ast.Assign)
             and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='out')
    need(isinstance(out,ast.Call) and isinstance(out.func,ast.Name) and out.func.id=='Path'
         and len(out.args)==1 and not out.keywords
         and ast.literal_eval(out.args[0])=='/home/alex/codex-hepta-natural-'+label+'-root-v150',
         'actual actor output namespace differs')
    normalized=replace_literal_source(raw,replacements).replace(label.encode(),old['label'].encode())
    need(normalized==reference,'actual actor differs outside the reviewed case-data generation slots')
    return actor

def sender_originals(O,attempt,prepared,files,lease,contract,prefix,sources,plan):
    label=attempt['label'];owner=lease['owner_request_sha256'];nonce=lease['nonce']
    raw=O.read(attempt['sender_actor'],262144,ACTOR_1AD3 if label==LABELS[1] else ACTOR_EXTERNAL09)
    actor=actor_source_relation(raw,sources['actor_reference'],sources['ready'],files,contract,label)
    need(actor['label']==label and actor['reset_probe'] is False and actor['evidence_mode']=='component'
         and actor['expected'].encode()==files['owner-request.txt'] and actor['component_binding']['contract']==contract
         and actor['component_binding']['contract_original_b64']==base64.b64encode(files['sender-contract.json']).decode()
         and actor['component_binding']['contract_sha256']==sha(files['sender-contract.json'])
         and actor['component_binding']['phone_home']==PHONE+'/native-guard-r10-r1/'+label,
         'actual generated actor data bindings differ')
    # Exact generation evidence: original preview pinned the same full actor,
    # and the actual execute argv used the reviewed aafd sender with this plan.
    preview=strict(prefix['sender-preview/stdout'])
    need(preview['state']=='BUILT_ONLY_NO_PHONE' and preview['actor_sha256']==sha(raw)
         and preview['phone_calls']==preview['send_attempts']==0 and preview['evidence_root_mode']=='component',
         'original actor preview differs from the actual actor bytes')
    execute=O.value(attempt['sender_execute_intent'],65536);argv=execute['argv']
    expected_argv=['/usr/bin/python3','-I','-B',B+'/send_new_native_guard_task_r10_r4.py',label,
      plan['request']['path'],plan['previous']['path'],'--preserved-draft',plan['preserved_draft']['path'],
      '--retirement-resolution',plan['sender_retirement_resolution']['path'],'--evidence-root','component',
      '--component-contract',prepared['sender_contract_path'],'--component-package',plan['package']['path'],
      '--component-package-sha256',RUNTIME[1],'--execute-once']
    need(argv==expected_argv
         and execute['maximum_starts']==1 and execute['maximum_wait_seconds']==600
         and execute['automatic_retry'] is False,'actual aafd sender invocation differs')
    child=O.value(attempt['sender_child'],65536);pid=child['pid'];need(type(pid) is int and pid>1
        and child['pgid']==child['sid']==pid and child['maximum_starts']==1
        and child['source_intent_sha256']==sha(O.read(attempt['sender_execute_intent'])),
        'actual sender child identity/intent crosslink differs')
    previous=O.value(plan['previous'],65536, (1428,'9133e2511a66a809be647cb8bb49e3afb351825db5e465f75b1f2f0b6d9d88f4'))
    need(actor['previous_identity']==previous['identity'] and actor['previous_digest']==previous['request_sha256']
         and O.read(plan['request'],16000)==files['owner-request.txt'],'actual sender previous/request original differs')
    preservation=O.value(plan['preserved_draft'],16384)
    need(base64.b64decode(preservation['exact_utf8_b64'],validate=True)==actor['preserved_draft'].encode(),
         'Root-supplied draft preservation differs from actual generated actor')
    resolution=O.read(plan['sender_retirement_resolution'],MAX_INPUT)
    need(sha(resolution)==actor['retirement_binding']['resolution_sha256'],'actual retirement resolution original differs')
    inventory_raw=O.read(attempt['sender_inventory'],MAX_INPUT);inventory=strict(inventory_raw)
    root='/home/alex/codex-hepta-natural-'+label+'-root-v150'
    if label==LABELS[1]:
        need(identity(inventory_raw)==(51164,'6ddc71d0373be9e293fb1b32548160929936def2a47ca8b36b788bc0c75fe42d')
             and inventory['state']=='READ_ONLY_EXISTING_ORIGINAL_SENDER_INVENTORY' and inventory['exists'] is True
             and inventory['path']==root and inventory['file_count']==len(inventory['files'])==170,
             'complete original 1ad3 sender inventory required')
    else:
        need(identity(inventory_raw)==(84711,'73473cba24df67139f10d26d209729b7852f52da39915e8ccfcc404f26b32998')
             and inventory['schema']=='hepta.fixed19.readonly-original-sender-inventory.v2'
             and inventory['state']=='EXACT_CLOSED_SENDER_ORIGINAL_SET_READ_WITH_FULL9_BOOKENDS'
             and inventory['source']==root and inventory['label']==label
             and inventory['source_file_count']==len(inventory['files'])==170
             and inventory['all_fd_and_named_full9_equal'] is True and inventory['closed_set_bookend_equal'] is True
             and inventory['source_bytes']==5366983 and inventory['send_named_records_present']==[],
             'complete original external09 sender inventory required')
    expected={}
    for row in inventory['files']:
        name=row['relative_path'];need(type(name) is str and str(Path(name))==name and not Path(name).is_absolute()
            and '..' not in Path(name).parts and name not in expected and row['path']==root+'/'+name,
            'sender original name/namespace differs')
        expected[name]={k:row[k] for k in ('bytes','sha256')}
    packed=unpack(O.read(attempt['sender_archive_xz'],MAX_FILE),'xz')
    need(set(packed)=={'sender-originals/'+name for name in expected}|{'P4-SENDER-INVENTORY.original.json'}
         and packed['P4-SENDER-INVENTORY.original.json']==inventory_raw,'sender archive closed set differs')
    originals={name:packed['sender-originals/'+name] for name in expected}
    for name,body in originals.items():need(bare(body)==expected[name],'sender archive member pin differs')
    need(not any(name.startswith('SEND') for name in originals),'Send evidence exists; prelaunch reconciliation is inapplicable')
    val=lambda name:strict(originals[name])
    marker=val('COMPONENT-PREPARED-NO-SEND.json')
    need(marker['state']=='PREPARED_NO_SEND' and marker['nonce']==nonce and marker['owner_request_sha256']==owner
         and marker['contract_sha256']==sha(files['sender-contract.json']) and marker['send_attempt_count']==0
         and marker['provider_started_by_sender'] is False,'actual sender marker differs')
    waits=sorted(name for name in originals if name.startswith('COMPONENT-READY-'))
    need(1<=len(waits)<=512 and waits==['COMPONENT-READY-%04d.original-read.json'%n for n in range(1,len(waits)+1)],
         'complete ordered ready observations required')
    previous=marker['prepared_monotonic_ns']
    for name in waits:
        observation=val(name);wire=observation['original_wire_receipt']
        need(observation['read_only'] is True and observation['socket_connections']==observation['service_launches']==0
             and wire['rc']==0 and wire['stderr']=='','ready read was not a successful no-action observation')
        answer=strict(wire['stdout'])
        need(answer==observation['observation']=={'state':'waiting_for_ready','contract_sha256':sha(files['sender-contract.json']),
          'nonce':nonce,'owner_request_sha256':owner,'claim_absent':True,'ended_absent':True},'ready/claim/ended state differs')
        need(previous<=observation['read_start_monotonic_ns']<=observation['read_end_monotonic_ns']
             <marker['pre_send_deadline_monotonic_ns'],'ready observation clock/order differs')
        previous=observation['read_end_monotonic_ns']
    need(val('ACTOR-FAILURE.json')=={'error_type':'RuntimeError',
      'error':'Component rendezvous deadline elapsed; zero Send, no provider restart','automatic_send_retry':False},
      'actual actor failure cause differs')
    host=O.value(attempt['sender_result'],65536);need(set(host)=={'rc','stdout','stderr'} and host['rc']==2
        and host['stderr']=='' and len(host['stdout'].splitlines())==1,'original aafd subprocess receipt is not a normal rc2 terminal')
    terminal=strict(host['stdout'])
    need(terminal['state']=='PRE_SEND_OR_ACTOR_FAILURE' and terminal['out']==root and terminal['prompt_sha256']==owner
         and terminal['send_attempt_count']==0 and terminal['automatic_replay'] is False
         and terminal['business_success_verified'] is False
         and terminal['draft_restore']=={'state':'ORIGINAL_DRAFT_RESTORED','restore_attempts':1,'original_draft_submitted':False},
         'original sender terminal does not establish no-Send and restoration')
    draft=val('PRESERVED-USER-DRAFT.json');text=draft['exact_text'].encode()
    need(text==actor['preserved_draft'].encode() and sha(text)==draft['utf8_sha256']
         and draft['submitted_original_draft'] is False and text!=files['owner-request.txt'],'preserved exact draft differs')
    restore=val('PRESERVED-DRAFT-RESTORE.original.json');need(restore['rc']==0 and restore['stderr']=='','restore wire failed')
    readback=strict(restore['stdout'])
    need(readback['status']=='set_verified' and readback['effect_state']=='observed_exact_requested_text'
         and readback['before_utf8_sha256']==owner
         and readback['requested_utf8_sha256']==readback['after_utf8_sha256']==sha(text)
         and base64.b64decode(readback['readback_text_b64'],validate=True)==text
         and readback['own_automation_disconnected'] is True,'public exact draft readback differs')
    final=val('DRAFT-RESTORE-RESULT.json')
    need(final['state']=='ORIGINAL_DRAFT_RESTORED' and final['utf8_sha256']==sha(text)
         and final['restore_attempts']==1 and final['original_draft_submitted'] is False,'restoration terminal differs')
    need(originals['FINAL-PRE-SEND-SELECTED.original-read.json']==originals['RESTORE-SELECTED.original-read.json']
         ==originals['RESTORE-SELECTED-FINAL.original-read.json']
         and originals['FINAL-PRE-SEND-RETIREMENT.original-read.json']==originals['RESTORE-GLOBAL-GATE.original-read.json'],
         'original selection/retirement CAS changed during sender')
    absence=O.value(attempt['mac_sender_absence'],65536,
        (620,'8d2e1fc9e990da7d4d017de20f3888b27cebb848a4faa5a9a0334c2d9b09d24b') if label==LABELS[1]
        else (2665,'7bb689ae585b084a564047d163254168d06ce20e191811a5be2dca87943bff7f'))
    need(absence['schema']==('hepta.fixed19.failed-sender-readonly-process-observation.v1' if label==LABELS[1]
                             else 'hepta.fixed19.failed-sender-readonly-process-observation.v2') and absence['label']==label
         and absence['original_sender_pid']==absence['original_pgid']==pid and len(absence['observations'])==2
         and absence['signals_sent']==0 and absence['original_parent_join_proven'] is False
         and absence['original_capture_eof_repaired'] is False,'original Mac sender process observations differ')
    for row in absence['observations']:
        need(row['ps_returncode']==0 and row['matching_process_count']==0
             and row['owned_pid_or_group_or_exact_label_rows']==[],'sender process/group remains or absence unknown')
        if label==LABELS[1]:need(row['ps_stderr']=='','original 1ad3 process observation stderr differs')
        else:
            O.read(absence['collector_source'],65536,
                (9498,'85697ae603d99469b414025457a09bdc1052f1910410fbcd4641321de60ab740'))
            need(row['ps_argv']==['/bin/ps','-axo','pid=,ppid=,pgid=,sess=,lstart=,command=']
                 and O.read(row['stderr'])==b'','actual external09 ps argv/stderr differs')
            matches=[]
            for line in O.read(row['stdout'],MAX_INPUT).decode().splitlines():
                columns=line.split(None,9);need(len(columns)==10,'complete original ps row required')
                if columns[0]==str(pid) or columns[2]==str(pid) or label in columns[9]:matches.append(line)
            need(matches==[],'raw ps still contains the sender PID/group/label')
    if label==LABELS[1]:
        need(len(originals)==170 and sum(map(len,originals.values()))==5362795 and len(waits)==142
             and identity(raw)==ACTOR_1AD3,'the already observed 1ad3 originals must stay exact')
    return {'sender_original_files':len(originals),'sender_original_bytes':sum(map(len,originals.values())),
      'ready_wait_originals':len(waits),'send_attempt_count':0,'draft_restored_exactly':True,
      'mac_sender_absence_observations':2,'original_parent_join_retrofitted':False,'original_capture_eof_retrofitted':False,
      'p4_actor_terminal_from_original_aafd_subprocess_run_receipt':True,
      'selected_wire_original':bare(originals['RESTORE-SELECTED-FINAL.original-read.json']),
      'selected_client_bytes':base64.b64decode(''.join(val('RESTORE-SELECTED-FINAL.original-read.json')['stdout'].split()),validate=True)},actor

def stage_observation(O,attempt,prepared,files,lease,template,prefix):
    stage,source,control=phone_observation(O,attempt['stage_observation'])
    stage_wrapper=strict(prefix['phone-stage/stdout'])
    need(stage_wrapper['actor_rc']==0 and stage_wrapper['wrapper']['phone']['rc']==0
         and stage_wrapper['wrapper']['phone']['stderr']=='','original phone stage wrapper differs')
    stage_original=stage_wrapper['wrapper']['phone']['stdout'].encode()
    need(stage['stage_complete']==bare(stage_original),'observed STAGE-COMPLETE differs from actual original stage receipt')
    bindings=literals(source)
    names=('LABEL','NONCE','LEASE_PIN','ARCHIVE_PIN','STAGE_PIN','LEASE_EXPIRES_UNIX_MS')
    expected={'LABEL':attempt['label'],'NONCE':lease['nonce'],'LEASE_PIN':tuple(prepared['lease'][k] for k in ('bytes','sha256')),
        'PACKAGE_PIN':RUNTIME,'ARCHIVE_PIN':tuple(prepared['archive'][k] for k in ('bytes','sha256')),
        'STAGE_PIN':tuple(stage['stage_complete'][k] for k in ('bytes','sha256')),'LEASE_EXPIRES_UNIX_MS':lease['expires_unix_ms']}
    need(all(bindings[name]==expected[name] for name in names),'stage-only observer changed actual binding')
    # Canonical RHS spelling is fixed by the supplied reviewed template.
    replacements={}
    for node in ast.parse(template).body:
        if isinstance(node,ast.Assign) and isinstance(node.targets[0],ast.Name) and node.targets[0].id in names:
            replacements[node.targets[0].id]=ast.get_source_segment(template.decode(),node.value).encode()
    need(replace_literal_source(source,replacements)==template,'stage observer changed more than its exact binding literals')
    need(stage['state']=='EXACT_STAGED_TREE_RETAINED_NO_LAUNCH_ARTIFACTS_OBSERVED'
         and stage['label']==attempt['label'] and stage['nonce']==lease['nonce'] and stage['boot_id']==BOOT
         and stage['lease']==bare(files['LEASE.json']) and stage['lease_expired'] is True
         and stage['exact_current_file_count']==57 and stage['exact_current_directory_count']==9
         and stage['full9_named_fd_and_canonical_path_bookends'] is True,'exact failed private stage not proven')
    absent_node=next(n.value for n in ast.parse(template).body if isinstance(n,ast.Assign)
        and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='ABSENT')
    need(isinstance(absent_node,ast.Tuple) and len(absent_node.elts)==29
        and ast.dump(absent_node.elts[-1])==ast.dump(ast.parse("'claims/'+NONCE+'.json'",mode='eval').body),
        'reviewed fixed stage absence expression differs')
    expected_absent=[ast.literal_eval(n) for n in absent_node.elts[:-1]]+['claims/'+lease['nonce']+'.json']
    need(set(stage['explicit_absence'])==set(expected_absent)
         and all(v=='ENOENT_AT_HELD_PARENT_BEFORE_AND_AFTER_READSET' for v in stage['explicit_absence'].values()),
         'all launch/acceptance absences must be observed')
    need(set(stage['files'])==set(files)|{'STAGE-COMPLETE.json'},'observed private file closed set differs')
    for name,body in files.items():
        row=stage['files'][name];need({k:row[k] for k in ('bytes','sha256')}==bare(body)
            and type(row['metadata']) is list and len(row['metadata'])==9,'private stage original bytes/full9 differ')
    need(stage['journal']['empty'] is True and stage['journal']['exact_original_seed_metadata'] is True
         and stage['journal']['both_views_equal'] is True and stage['failed_predecessor_closed_here'] is False
         and stage['native_boundary_created'] is False and stage['process_starts']==stage['signals_sent']==0,
         'stage-only observer scope or original executor seed differs')
    return {'files':57,'directories':9,'explicit_launch_absences':29,'empty_original_journal_seed':True,
            'controller':control}

def global_verification(O,record):
    value,source,control=phone_observation(O,record,GLOBAL_SOURCE)
    need(value['schema']=='hepta.native-guard.expired-lease-readonly-verification.v1'
         and value['state']=='ACTUAL08_ORIGINAL_GLOBAL_VERIFICATION_RETURNED_AND_LOCK_RELEASED'
         and value['label']==LABELS[1] and value['nonce']=='7c74b84aefb177d15f746fa7eae29d54'
         and value['boot_id']==BOOT and value['actual_last_native_boundary']==ACTUAL08
         and value['original_verify_retired_callsite_entered']==value['original_verify_retired_returned']==1
         and value['original_verifier_returned'] is True and value['original_verification_complete'] is True
         and value['failure'] is None and value['profiling_enabled'] is False and value['tracing_enabled'] is False,
         'new uninstrumented original global verification did not complete')
    elapsed=value['original_call_wall_seconds'];need(type(elapsed) in (int,float) and math.isfinite(elapsed)
        and 0<=elapsed<180 and value['post_return_elapsed_limit_seconds']==180
        and value['self_deadline_installed'] is False,'global post-return observation limit differs')
    cleanup=value['owned_verifier_lock_cleanup']
    need(cleanup['complete'] is True and cleanup['errors']==[] and cleanup['new_FDs_remaining']==[]
         and len(cleanup['closed'])==1 and all(cleanup['closed'][0][k] is True for k in
             ('returned_by_verifier','matches_bootstrap_lock','readonly','close_returned','observed_EBADF')),
         'original successful verifier lock was not actually released')
    retired=value['original_result'];late=retired['explicit_late_boundary_verification']
    need(retired['old_journal_lock_held_without_writing'] is True
         and late['state']=='EXACT_CLOSED_CUMULATIVE_ORIGINALS_UNCHANGED' and late['previous_boundary']==ACTUAL08
         and late['phone_tool_calls']==late['model_requests']==late['signals']==late['writes']==0,
         'original actual08 cumulative chain/current inventory/groups/endpoints gate differs')
    need(value['failed_prelaunch_predecessor_closed_here'] is False and value['component_qualified'] is False,
         'global observation cannot itself claim a failed-prelaunch closure')
    return {'source':bare(source),'controller':control,'original_call_wall_seconds':elapsed,
            'actual08_original_global_verification_complete':True,'owned_lock_released':True}

def current_publication(O,record,attempt_summaries,selected,global_result):
    value,source,control=phone_observation(O,record,CURRENT_PUBLICATION_SOURCE_TEMPLATE)
    need(value['schema']=='hepta.native-guard.failed-prelaunch-current-observation.v1'
         and value['state']=='TWO_FAILED_NONCES_UNPUBLISHED_SELECTED_ORIGINAL_UNCHANGED'
         and value['boot_id']==BOOT and value['last_real_native_boundary']==ACTUAL08
         and value['full9_readset_canonical_recheck_complete'] is True,
         'current nonce-publication/selected observation did not complete')
    expected=[{'label':a['label'],'nonce':a['nonce'],'owner_request_sha256':a['owner_request_sha256'],
               'lease_expires_unix_ms':a['lease_expires_unix_ms']} for a in attempt_summaries]
    need(value['attempts']==expected and control['created_unix_ms']>=global_result['controller']['terminal_unix_ms']
         and value['observed_unix_ms']>=max(a['lease_expires_unix_ms'] for a in expected),
         'current observation was not taken after these expired attempts and the complete global verification')
    selected_value=value['selected']
    need(selected_value['bytes']==len(selected) and selected_value['sha256']==sha(selected)
         and selected_value['pending_absent'] is True and selected_value['matches_original_actor_final_readback'] is True,
         'current selected bytes differ from both original sender CAS readbacks')
    publication_paths={PHONE+'/native-guard-boundaries-r10-r1/'+a['nonce']+suffix
                       for a in expected for suffix in ('','.json')}
    absent=value['explicit_absence']
    need(publication_paths<=set(absent) and all(absent[p]['state']=='ENOENT_AT_HELD_PARENT_AND_CANONICAL_REOPEN'
          for p in publication_paths),'both failed nonce boundary file/directory absences are required')
    pending=str(Path(selected_value['file']).parent/'owner-client-session-v1.pending')
    need(pending in absent and absent[pending]['state']=='ENOENT_AT_HELD_PARENT_AND_CANONICAL_REOPEN',
         'current selected pending leaf absence missing')
    provider=value['provider']
    need(provider['provider_match_count']==0 and provider['matches']==[] and 1<=provider['run_count']<=512
         and provider['native_journal_hash_chain_claimed'] is False,'a failed owner is published or provider absence unknown')
    roots={PHONE+'/provider-state/evidence',PHONE+'/component-probe-r6/evidence'}
    need(roots<=set(value['directories']),'both current provider roots must be present')
    observed_paths=set()
    for row in provider['files']:
        path=row['path'];need(path not in observed_paths and Path(path).name=='provider-in.jsonl'
            and str(Path(path).parent.parent) in roots,'provider input scope or uniqueness differs')
        observed_paths.add(path);original=value['files'][path]
        need({k:original[k] for k in ('bytes','sha256')}=={k:row[k] for k in ('bytes','sha256')}
             and len(original['metadata'])==9,'provider full original descriptor differs')
    for path in provider['missing_original_provider_input_paths']:
        need(path not in observed_paths and path in absent and str(Path(path).parent.parent) in roots,
             'missing provider input must have an explicit absence original')
        observed_paths.add(path)
    expected_paths=set()
    for root in roots:
        for name in value['directories'][root]['names']:
            if root.endswith('/provider-state/evidence') and name in ('action-ledger','claims'):continue
            need(re.fullmatch(r'[0-9]{8}-[0-9]{6}-[0-9a-f]{32}',name),'provider directory name differs')
            expected_paths.add(root+'/'+name+'/provider-in.jsonl')
    need(observed_paths==expected_paths,'provider input observation is not the complete closed run set')
    need(value['failed_prelaunch_closed_here'] is False and value['native_boundary_created'] is False
         and value['component_qualified'] is False and value['business_qualified'] is False
         and value['phone_writes']==value['process_starts']==value['signals_sent']==value['socket_connections']==0,
         'current observer exceeded its read-only scope')
    return {'source':bare(source),'controller':control,'two_failed_nonce_publications_absent':True,
      'two_failed_owner_provider_starts_absent':True,'selected_original':bare(selected),
      'selected_pending_absent':True,'full9_scoped_readset_rechecked':True}

def assemble_failed_prelaunch(inputs,read_pinned):
    exact(inputs,('schema','sources','attempts','global_retirement','current_observation'),
          'all failed-prelaunch input groups are required')
    need(inputs['schema']=='hepta.native-guard.failed-prelaunch-admission-inputs.v1','admission inputs schema differs')
    exact(inputs['sources'],('sender','ready','old_sender','stage_template','actor_reference'),'reviewed source set differs')
    need(type(inputs['attempts']) is list and [a.get('label') for a in inputs['attempts']]==list(LABELS),
         'both original failed attempts are required, in original order')
    need(inputs['global_retirement'] is not None and inputs['current_observation'] is not None,
         'actual full global and current publication/selected originals are mandatory')
    O=Originals(read_pinned);sources={}
    for name,pin in [('sender',SENDER),('ready',READY),('old_sender',OLD_SENDER),('stage_template',STAGE_TEMPLATE),('actor_reference',ACTOR_1AD3)]:
        sources[name]=O.read(inputs['sources'][name],262144,pin)
    summaries=[];selected=None;nonces=[];last_expiry=0
    for attempt in inputs['attempts']:
        exact(attempt,ATTEMPT_FIELDS,'complete failed-attempt original set required')
        prepared,files,lease,contract=material(O,attempt)
        need(lease['nonce'] not in nonces and lease['expires_unix_ms']>last_expiry,'failed attempt nonce/order differs')
        nonces.append(lease['nonce']);last_expiry=lease['expires_unix_ms']
        failure,plan,prefix=root_failure(O,attempt,prepared,lease)
        sender,actor=sender_originals(O,attempt,prepared,files,lease,contract,prefix,sources,plan)
        candidate=sender.pop('selected_client_bytes')
        if selected is None:selected=candidate
        else:need(candidate==selected,'selected original client state changed between failed attempts')
        stage=stage_observation(O,attempt,prepared,files,lease,sources['stage_template'],prefix)
        summaries.append({'label':attempt['label'],'nonce':lease['nonce'],'lease':bare(files['LEASE.json']),
            'owner_request_sha256':lease['owner_request_sha256'],'lease_expires_unix_ms':lease['expires_unix_ms'],'original_case_failed':True,
            'root_prelaunch_failure_preserved':True,'sender':sender,'private_stage':stage})
    global_result=global_verification(O,inputs['global_retirement'])
    current=current_publication(O,inputs['current_observation'],summaries,selected,global_result)
    O.recheck()
    result={'schema':'hepta.native-guard.failed-prelaunch-admission.v1',
      'state':'TWO_FAILED_PRELAUNCH_ATTEMPTS_RECONCILED_LAST_NATIVE08_UNCHANGED','boot_id':BOOT,
      'last_real_native_boundary':ACTUAL08,'failed_prelaunch_labels':list(LABELS),'failed_prelaunch_nonces':nonces,
      'nonce_reuse_forbidden':True,'attempts':summaries,'global_retirement':global_result,'current_observation':current,
      'inputs':inputs,'verification_originals':sorted(O.rows.values(),key=lambda row:row['path']),
      'native_boundary_created':False,'component_qualified':False,'business_qualified':False,'whole_cases_passed':0,
      'original_parent_join_retrofitted':False,'original_capture_eof_retrofitted':False,
      'phone_calls_by_assembler':0,'automatic_retry_authorized_here':False}
    need(len(encoded(result))<=MAX_INPUT,'admission output exceeds one MiB')
    return result

def verify_failed_prelaunch_admission(value,read_pinned):
    need(type(value) is dict and type(value.get('inputs')) is dict,'complete original-backed admission required')
    recomputed=assemble_failed_prelaunch(value['inputs'],read_pinned)
    need(encoded(value)==encoded(recomputed),'admission fields or consumed original set differ')
    return {key:recomputed[key] for key in ('schema','state','boot_id','last_real_native_boundary',
        'failed_prelaunch_labels','failed_prelaunch_nonces','nonce_reuse_forbidden',
        'native_boundary_created','component_qualified','business_qualified')}

def local_read(row):
    descriptor(row);p=Path(row['path']);need(p.parent.resolve(strict=True)==p.parent,'canonical original parents required')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1
            and before.st_size==row['bytes'],'regular single-link exact-size original required')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(row['bytes']+1)
        keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        meta=lambda s:tuple(getattr(s,k) for k in keys)
        need(meta(before)==meta(os.fstat(fd))==meta(p.lstat()) and len(raw)==row['bytes'] and sha(raw)==row['sha256'],
             'local original changed while read')
        return raw
    finally:os.close(fd)

def main():
    p=argparse.ArgumentParser();p.add_argument('--inputs-desc',required=True);p.add_argument('--out',required=True)
    p.add_argument('--assemble-host-only-once',action='store_true',required=True);args=p.parse_args()
    inputs=strict(local_read(strict(args.inputs_desc)))
    result=assemble_failed_prelaunch(inputs,local_read)
    out=Path(args.out);need(out.is_absolute() and str(out)==args.out and out.parent.resolve(strict=True)==out.parent,
                            'canonical create-only admission path required')
    raw=encoded(result);fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb',closefd=False) as stream:stream.write(raw);stream.flush();os.fsync(fd)
    finally:os.close(fd)
    parent=os.open(out.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(parent)
    finally:os.close(parent)
    row={'path':str(out),**bare(raw)};need(local_read(row)==raw,'created admission readback differs')
    print(json.dumps({'admission':row,'state':result['state'],'component_qualified':False},sort_keys=True))

if __name__=='__main__':main()
