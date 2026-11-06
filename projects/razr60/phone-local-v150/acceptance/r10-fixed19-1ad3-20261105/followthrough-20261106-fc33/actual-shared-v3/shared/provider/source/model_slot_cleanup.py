#!/usr/bin/env python3
"""Candidate: passive cleanup of one original request; no POST or action API.

All new filesystem verification and persistence run in a read-only observer
process. Parent-side nonblocking pipes and pidfd control have a six-second
monotonic deadline. An unjoined worker or scheduler overrun remains UNKNOWN.
"""
import base64
import ctypes
import json
import signal
import subprocess
import sys
import errno
import hashlib
import os
from pathlib import Path
import re
import selectors
import socket
import stat
import time
from phone_local_http_worker import strict_json, endpoint_parts, private_api_key

CLEANUP_SECONDS = 6.0
OBSERVATION_SECONDS = 5.0
MAX_GETS = 12
MAX_BODY = 65536
MAX_HEADER = 8192
IDENTITY_FIELDS = {'schema', 'boot_id', 'pid', 'pgid', 'sid', 'start_ticks'}


def require(value, message):
    if not value:
        raise ValueError(message)


def private_bytes(path, limit=65536):
    path = Path(path)
    require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent,
            'private input canonical path required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        a = os.fstat(fd)
        require(stat.S_ISREG(a.st_mode) and a.st_uid == 0 and a.st_gid == 0 and
                a.st_nlink == 1 and stat.S_IMODE(a.st_mode) == 0o600 and a.st_size <= limit,
                'private input ownership/mode/size differs')
        raw = os.read(fd, limit + 1)
        b, n = os.fstat(fd), path.lstat()
        fields = ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
        require(len(raw) == a.st_size and all(getattr(a,x)==getattr(b,x)==getattr(n,x)
                for x in fields), 'private input changed')
        return raw
    finally:
        os.close(fd)


def load_binding(path):
    value = strict_json(private_bytes(path))
    require(isinstance(value, dict) and set(value) == {
        'schema','server_identity','model_claim','model_claim_sha256',
        'server_binary_sha256','server_domain','endpoint'
    } and value['schema'] == 'hepta.model-cleanup-binding.v1', 'cleanup binding schema differs')
    ident = value['server_identity']
    require(isinstance(ident, dict) and set(ident) == IDENTITY_FIELDS and
            ident['schema'] == 'hepta.llama-server-identity.v1' and
            re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',ident['boot_id']) and
            all(type(ident[x]) is int and ident[x] > 0 for x in ('pid','pgid','sid','start_ticks')) and
            ident['pid'] == ident['pgid'] == ident['sid'], 'server role identity differs')
    for key in ('model_claim_sha256','server_binary_sha256'):
        require(isinstance(value[key], str) and re.fullmatch(r'[0-9a-f]{64}',value[key]), 'binding SHA invalid')
    require(isinstance(value['server_domain'],str) and 0 < len(value['server_domain']) <= 128 and
            '\x00' not in value['server_domain'] and '\n' not in value['server_domain'], 'domain binding absent')
    endpoint_parts(value['endpoint'])
    return value


def security_domain_matches(raw, domain):
    """Accept the exact kernel context with at most its one ABI terminator."""
    if (not isinstance(domain, str) or not 0 < len(domain) <= 128 or
            domain[0] == ' ' or domain[-1] == ' ' or
            any(not 32 <= ord(char) <= 126 for char in domain)):
        return False
    expected = domain.encode('ascii')
    return raw in (expected, expected + b'\x00', expected + b'\n')


def verify_identity(binding, hash_binary=False):
    expect = binding['server_identity']
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(boot == expect['boot_id'], 'server boot changed')
    raw_claim = private_bytes(binding['model_claim'],128)
    require(hashlib.sha256(raw_claim).hexdigest() == binding['model_claim_sha256'],
            'model role claim changed')
    require(raw_claim.decode().strip() == ':'.join(str(expect[x])
            for x in ('pid','pgid','sid','start_ticks')), 'role claim identity differs')
    proc = Path('/proc')/str(expect['pid'])
    def current():
        raw=(proc/'stat').read_text()
        parts=raw[raw.rfind(') ')+2:].split()
        require(len(parts)>=20 and parts[0] != 'Z', 'model process absent/zombie')
        actual={'schema':'hepta.llama-server-identity.v1','boot_id':boot,
                'pid':int(raw.split(' ',1)[0]),'pgid':int(parts[2]),
                'sid':int(parts[3]),'start_ticks':int(parts[19])}
        require(actual == expect, 'model process identity changed')
        return actual
    before=current()
    status=(proc/'status').read_text().splitlines()
    uid=next(row for row in status if row.startswith('Uid:')).split()[1:]
    gid=next(row for row in status if row.startswith('Gid:')).split()[1:]
    require(uid == ['0']*4 and gid == ['0']*4, 'model owner changed')
    require(security_domain_matches((proc/'attr/current').read_bytes(), binding['server_domain']),
            'model domain changed')
    if hash_binary:
        digest=hashlib.sha256();total=0
        with (proc/'exe').open('rb') as stream:
            for block in iter(lambda: stream.read(1024*1024),b''):
                total+=len(block);require(total<=32*1024*1024,'model binary size bound')
                digest.update(block)
        require(digest.hexdigest() == binding['server_binary_sha256'], 'model executable changed')
    require(current() == before, 'model identity changed during read')
    return before


def admission_identity(binding, config, slot_before):
    require(binding['endpoint'] == config['endpoint'], 'bound endpoint differs')
    identity=verify_identity(binding,hash_binary=True)
    slot=slot_before.get('slot',{})
    advertised=slot.get('hepta_server',{})
    require(slot_before.get('observed') is True and slot_before.get('idle') is True and
            advertised.get('schema') == 'hepta.llama-server-receipts.v2' and
            advertised.get('enabled') is True and advertised.get('journal_ok') is True and
            advertised.get('identity') == identity, 'server receipt capability/identity not admitted')
    return identity


def get_json(config, path, deadline):
    """Exactly one GET with a total deadline; no redirect, retry, DNS, or POST."""
    hostname,port,_=endpoint_parts(config['endpoint'])
    require(path == '/slots' or re.fullmatch(r'/hepta/requests/[0-9a-f]{32}',path),
            'read-only original receipt path required')
    key=private_api_key(config['api_key_file'])
    host_header=('['+hostname+']') if ':' in hostname else hostname
    request=('GET '+path+' HTTP/1.1\r\nHost: '+host_header+':'+str(port)+
             '\r\nAuthorization: Bearer '+key+'\r\nConnection: close\r\n\r\n').encode('ascii')
    begin=time.monotonic()
    row={'method':'GET','path':path,'automatic_retry':False,'redirect_followed':False,
         'complete':False,'http_status':None,'error':None}
    raw=bytearray();body=None;value=None
    connection=socket.socket(socket.AF_INET6 if ':' in hostname else socket.AF_INET,socket.SOCK_STREAM)
    connection.setblocking(False)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(connection,selectors.EVENT_WRITE)
            def wait(event):
                selector.modify(connection,event)
                left=deadline-time.monotonic()
                if left<=0 or not selector.select(left):
                    raise TimeoutError('shared observation deadline')
                require(time.monotonic()<deadline,'shared observation deadline passed')
            result=connection.connect_ex((hostname,port))
            require(result in {0,errno.EINPROGRESS,errno.EWOULDBLOCK,errno.EALREADY},'loopback connect failed')
            wait(selectors.EVENT_WRITE)
            require(connection.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)==0,'loopback socket error')
            sent=0
            while sent<len(request):
                wait(selectors.EVENT_WRITE)
                try:n=connection.send(request[sent:])
                except BlockingIOError:continue
                require(n>0,'GET write closed');sent+=n
            header_end=None;length=None
            while True:
                wait(selectors.EVENT_READ)
                try:chunk=connection.recv(16384)
                except BlockingIOError:continue
                require(bool(chunk),'HTTP stream ended before complete bounded body')
                raw.extend(chunk);require(len(raw)<=MAX_HEADER+MAX_BODY,'GET response bound')
                if header_end is None:
                    index=raw.find(b'\r\n\r\n')
                    if index<0:
                        require(len(raw)<=MAX_HEADER,'HTTP header bound');continue
                    header_end=index+4;require(header_end<=MAX_HEADER,'HTTP header bound')
                    lines=bytes(raw[:index]).decode('iso-8859-1').split('\r\n')
                    match=re.fullmatch(r'HTTP/1\.[01] ([0-9]{3})(?: .*)?',lines[0])
                    require(match is not None,'HTTP status framing')
                    row['http_status']=int(match.group(1));headers={}
                    for line in lines[1:]:
                        require(':' in line and not line.startswith((' ','\t')),'HTTP header framing')
                        name,text=line.split(':',1);name=name.lower()
                        require(name not in headers,'duplicate response header')
                        headers[name]=text.strip()
                    require('transfer-encoding' not in headers and
                            re.fullmatch(r'[0-9]+',headers.get('content-length','')),
                            'unbounded/chunked HTTP body not accepted')
                    length=int(headers['content-length']);require(length<=MAX_BODY,'HTTP body bound')
                if header_end is not None and len(raw)>=header_end+length:
                    require(len(raw)==header_end+length,'unexpected trailing HTTP bytes')
                    body=bytes(raw[header_end:]);row['complete']=True
                    row['body_sha256']=hashlib.sha256(body).hexdigest()
                    row['body_bytes']=len(body)
                    if row['http_status']==200:
                        value=strict_json(body)
                    break
    except (OSError,ValueError,UnicodeError,TimeoutError) as error:
        row['error']=type(error).__name__+':'+str(error)[:192]
    finally:
        connection.close()
    row['elapsed_seconds']=time.monotonic()-begin
    row['raw_http_response_b64']=base64.b64encode(bytes(raw)).decode()
    row['raw_http_response_sha256']=hashlib.sha256(raw).hexdigest()
    return value,row


def validate_original_records(request_id,identity,receipt,request_sha256,request_bytes):
    require(receipt.get('original_records_validated') is True and
            receipt.get('request_sha256')==request_sha256 and
            receipt.get('request_bytes')==request_bytes,
            'server original body digest/read-back unconfirmed')
    pins=receipt.get('records');originals=receipt.get('original_records')
    require(isinstance(pins,list) and isinstance(originals,list) and
            2<=len(pins)<=12 and len(originals)==len(pins),'original record inventory differs')
    allowed={'accepted-body.bin','accepted.json','slot-bound.json','model-final-text.bin',
             'model-final-tokens.json','model-final-metadata.json','model-error.json',
             'slot-released.json','cancel-processed.json'}
    expected={};decoded={}
    for row in pins:
        require(isinstance(row,dict) and row.get('name') in allowed and row['name'] not in expected and
                type(row.get('bytes')) is int and 0<=row['bytes']<=2*1024*1024 and
                isinstance(row.get('sha256'),str) and re.fullmatch(r'[0-9a-f]{64}',row['sha256']),
                'original record pin invalid')
        expected[row['name']]=row
    seen=set()
    for row in originals:
        require(isinstance(row,dict) and row.get('name') in expected and row['name'] not in seen,
                'original bytes repeated or unindexed')
        name=row['name'];seen.add(name);pin=expected[name]
        require(row.get('bytes')==pin['bytes'] and row.get('sha256')==pin['sha256'],
                'original file pin differs')
        if name.endswith('.json'):
            require(row.get('raw_included') is True and isinstance(row.get('raw_utf8'),str),
                    'original event bytes absent')
            raw=row['raw_utf8'].encode('utf-8')
            require(len(raw)==pin['bytes'] and hashlib.sha256(raw).hexdigest()==pin['sha256'],
                    'original event byte digest differs')
            event=strict_json(raw);decoded[name]=event
            if name!='model-final-tokens.json':
                require(isinstance(event,dict) and event.get('schema')=='hepta.llama-request-event.v1' and
                        event.get('request_id')==request_id and event.get('task_id')==receipt.get('task_id') and
                        event.get('server_identity')==identity and event.get('request_sha256')==request_sha256,
                        'original event request/task/server/body ownership differs')
                if name!='accepted.json':
                    require(event.get('slot_id')==receipt.get('slot_id'),'original event slot differs')
        else:
            require(row.get('raw_included') is False,'binary original framing differs')
    body=expected.get('accepted-body.bin',{})
    accepted=decoded.get('accepted.json',{})
    require(body.get('sha256')==request_sha256 and body.get('bytes')==request_bytes and
            accepted.get('event')=='accepted_before_queue' and accepted.get('slot_id')==-1 and
            accepted.get('details',{}).get('request_sha256')==request_sha256 and
            accepted.get('details',{}).get('request_bytes')==request_bytes,
            'original wire body admission record differs')
    bound=decoded.get('slot-bound.json')
    if bound:
        require(bound.get('event')=='assigned_original_slot' and
                bound.get('details',{}).get('slot_id')==receipt.get('slot_id'),'original slot binding differs')
    released=decoded.get('slot-released.json')
    if released:
        require(released.get('event')=='slot_state_idle_after_original_release' and
                released.get('details',{}).get('idle_at_release') is True,'original release bytes differ')
    final=decoded.get('model-final-metadata.json')
    if final:
        details=final.get('details',{})
        require(final.get('event')=='producer_nonstream_final_result' and
                details.get('http_delivery_observed') is False and
                details.get('raw_text_sha256')==expected.get('model-final-text.bin',{}).get('sha256') and
                details.get('raw_tokens_sha256')==expected.get('model-final-tokens.json',{}).get('sha256'),
                'original late producer content references differ')
    return decoded


def assess_original(request_id, expected_identity, receipt, slots, request_sha256, request_bytes):
    require(isinstance(receipt,dict) and
            receipt.get('schema')=='hepta.llama-request-receipt.v2' and
            receipt.get('request_id')==request_id and
            receipt.get('server_identity')==expected_identity and
            receipt.get('accepted_durable') is True and receipt.get('journal_ok') is True,
            'original accepted receipt identity/health unresolved')
    originals=validate_original_records(request_id,expected_identity,receipt,request_sha256,request_bytes)
    task=receipt.get('task_id');slot_id=receipt.get('slot_id')
    require(type(task) is int and task>=0 and receipt.get('bound') is True and
            type(slot_id) is int and slot_id>=0,'original task-to-slot ownership unresolved')
    require(isinstance(slots,list) and len(slots)==1 and isinstance(slots[0],dict),
            'single original slot not observed')
    slot=slots[0];server=slot.get('hepta_server',{});owner=slot.get('hepta_owner',{})
    require(server.get('enabled') is True and server.get('journal_ok') is True and
            server.get('identity')==expected_identity,'slot server identity changed')
    require(type(slot.get('id')) is int and type(slot.get('id_task')) is int and
            slot.get('id')==slot_id and slot.get('id_task')==task and
            isinstance(owner,dict) and owner.get('request_id')==request_id and
            owner.get('task_id')==task and owner.get('slot_id')==slot_id and
            owner.get('server_identity')==expected_identity and owner.get('journal_ok') is True,
            'current slot is not the original mapped task')
    require(type(slot.get('is_processing')) is bool,'slot processing state unreadable')
    terminal=receipt.get('state')
    done=(receipt.get('terminal_durable') is True and
          receipt.get('slot_release_observed') is True and
          owner.get('terminal_durable') is True and
          owner.get('slot_release_observed') is True and
          owner.get('state')==terminal and slot['is_processing'] is False)
    if not done:
        return {'admitted':False,'state':'ORIGINAL_STILL_RUNNING_OR_RELEASE_PENDING'}
    required={'accepted.json','slot-bound.json','slot-released.json'}
    names={x.get('name') for x in receipt.get('records',[]) if isinstance(x,dict)}
    if terminal=='completed':
        require(receipt.get('raw_terminal_preserved') is True,'late completion original not preserved')
        required|={'model-final-text.bin','model-final-tokens.json','model-final-metadata.json'}
    elif terminal=='cancelled':
        cancel=originals.get('cancel-processed.json',{})
        require(receipt.get('server_cancel_applied') is True and
                cancel.get('event')=='actual_cancel_task_processed' and
                cancel.get('details',{}).get('server_cancel_applied') is True,
                'actual cancellation original unacknowledged')
        required.add('cancel-processed.json')
    elif terminal=='failed':
        error=originals.get('model-error.json',{})
        fields=error.get('details',{})
        error_codes={'invalid_request_error':400,'authentication_error':401,
            'not_found_error':404,'server_error':500,'permission_error':403,
            'not_supported_error':501,'unavailable_error':503,'exceed_context_size_error':400}
        require(error.get('event')=='producer_error' and isinstance(fields,dict) and
                isinstance(fields.get('type'),str) and fields['type'] in error_codes and
                type(fields.get('code')) is int and fields['code']==error_codes[fields['type']] and
                isinstance(fields.get('message'),str) and bool(fields['message']),
                'original producer error event/fields absent or inconsistent')
        required.add('model-error.json')
    else:
        raise ValueError('original model terminal is unknown/conflicting')
    require(required<=names,'original terminal record references incomplete')
    return {'admitted':True,'state':'ORIGINAL_TERMINAL_RELEASE_AND_IDLE_OBSERVED',
            'original_model_terminal':terminal,
            'server_cancel_acknowledged':receipt.get('server_cancel_applied') is True,
            'original_task_id':task,'original_slot_id':slot_id,
            'native_cancellation_unchanged':True,'late_output_dispatched':False}


def drain_original(config,binding,request_id,run_dir,round_number,request_sha256,request_bytes,record):
    """Read original local receipts before GET; never consumes a model decision."""
    start=time.monotonic();deadline=start+OBSERVATION_SECONDS
    summary={'schema':'hepta.model-passive-cleanup.v1','request_id':request_id,
             'cleanup_budget_seconds':CLEANUP_SECONDS,'observation_budget_seconds':OBSERVATION_SECONDS,
             'request_sha256':request_sha256,'request_bytes':request_bytes,'admitted':False,'state':'UNKNOWN',
             'get_count':0,'post_count':0,'new_model_requests':0,'decision_count':0,'tool_count':0,
             'automatic_retry':False,'record_io_seconds':0.0,'observations':[],
             'client_exit_is_server_cancel_proof':False}
    prefix=Path(run_dir)/('local-%02d'%round_number)
    last_slot={'observed':False,'idle':False,'inference_cleanup':'unknown','automatic_retry':False}
    def persist(name,row):
        before=time.monotonic();record(prefix.with_suffix('.'+name+'.json'),row)
        summary['record_io_seconds']+=time.monotonic()-before
    try:
        require(re.fullmatch(r'[0-9a-f]{32}',request_id) is not None,'original request id invalid')
        expected=verify_identity(binding,hash_binary=True)
        require(config['endpoint']==binding['endpoint'],'bound endpoint differs')
        summary['server_identity']=expected
        originals={};original_values={}
        for kind in ('images','worker-result','spawned','joined','request-identity'):
            raw=private_bytes(prefix.with_suffix('.'+kind+'.json'))
            originals[kind]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
            value=strict_json(raw);original_values[kind]=value
            if kind=='joined':
                require(value.get('child_wait_returned') is True and
                        value.get('dedicated_process_group_absent') is True,
                        'original HTTP worker not joined/absent')
            elif kind=='spawned':
                require(value.get('actual_spawn') is True and type(value.get('pid')) is int and
                        value.get('process_group')==value['pid'],'original client spawn identity differs')
            else:
                require(value.get('request_id')==request_id,'original local request ownership differs')
        require(original_values['joined'].get('pid')==original_values['spawned']['pid'],
                'original join is not the original client')
        require(type(original_values['worker-result'].get('returncode')) is int and
                original_values['worker-result'].get('request_sha256')==request_sha256 and
                original_values['worker-result'].get('client_exit_is_server_cancel_proof') is False,
                'original client terminal/body digest differs')
        require(original_values['request-identity'].get('request_sha256')==request_sha256 and
                original_values['request-identity'].get('request_bytes')==request_bytes,
                'original wire request identity differs')
        summary['original_local_receipts']=originals
        for cycle in range(1,7):
            require(time.monotonic()<deadline,'cleanup deadline exhausted before read')
            verify_identity(binding)
            pair=[]
            for path in ('/hepta/requests/'+request_id,'/slots'):
                require(summary['get_count']<MAX_GETS,'GET observation count exhausted')
                value,row=get_json(config,path,min(deadline,time.monotonic()+.75))
                summary['get_count']+=1;row['cycle']=cycle
                persist('cleanup-observe-%02d'%summary['get_count'],row)
                pair.append((value,row))
                require(row['complete'] is True and row['http_status']==200 and row['error'] is None,
                        'original receipt/slot HTTP observation unresolved')
            receipt,slots=pair[0][0],pair[1][0]
            verify_identity(binding)
            slot=slots[0] if isinstance(slots,list) and len(slots)==1 and isinstance(slots[0],dict) else {}
            last_slot={'observed':type(slot.get('is_processing')) is bool,
                       'idle':slot.get('is_processing') is False,'slot':slot,
                       'response_sha256':pair[1][1].get('body_sha256'),'automatic_retry':False}
            assessment=assess_original(request_id,expected,receipt,slots,request_sha256,request_bytes)
            summary['observations'].append({'cycle':cycle,'assessment':assessment,
                'server_journal_io_us':receipt.get('journal_io_us'),
                'server_journal_fsync_us':receipt.get('journal_fsync_us'),
                'server_journal_fsync_calls':receipt.get('journal_fsync_calls')})
            if assessment['admitted']:
                verify_identity(binding,hash_binary=True)
                require(time.monotonic()<=deadline,'cleanup budget exceeded at final identity gate')
                summary.update(assessment);break
            wait_until=min(deadline,start+cycle)
            if time.monotonic()<wait_until:
                time.sleep(wait_until-time.monotonic())
    except Exception as error:
        summary.update(admitted=False,state='UNKNOWN',error=type(error).__name__+':'+str(error)[:256])
    summary['elapsed_seconds']=time.monotonic()-start
    summary['deadline_exceeded']=summary['elapsed_seconds']>OBSERVATION_SECONDS
    if summary['deadline_exceeded']:
        summary.update(admitted=False,state='UNKNOWN')
    summary['last_slot_observation']=last_slot
    return summary


def write_observer_json(path,value):
    raw=(json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n').encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb',closefd=False) as stream:
            stream.write(raw);stream.flush();os.fsync(fd)
    finally:os.close(fd)
    directory=os.open(Path(path).parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory)
    finally:os.close(directory)
    return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def observer_worker():
    raw=sys.stdin.buffer.read(16385)
    require(len(raw)<=16384,'observer input bound')
    payload=strict_json(raw)
    require(isinstance(payload,dict) and set(payload)=={
        'schema','parent_pid','binding_path','config','request_id','request_sha256',
        'request_bytes','run_dir','round_number','expected_identity','binding_sha256'
    } and payload['schema']=='hepta.cleanup-observer-input.v1','observer schema')
    require(type(payload['parent_pid']) is int and os.getppid()==payload['parent_pid'],
            'observer parent changed before admission')
    # No independent session/group; existing provider-group retirement includes
    # this read-only child. Never signal the model/server or provider group.
    libc=ctypes.CDLL(None,use_errno=True)
    require(libc.prctl(1,int(signal.SIGKILL),0,0,0)==0,'observer parent-death guard unavailable')
    require(os.getppid()==payload['parent_pid'],'observer parent changed during guard')
    stat_raw=Path('/proc/self/stat').read_text()
    fields=stat_raw[stat_raw.rfind(') ')+2:].split()
    started={'kind':'observer_started','pid':os.getpid(),'pgid':os.getpgrp(),
             'sid':os.getsid(0),'start_ticks':int(fields[19]),'parent_pid':os.getppid(),
             'read_only_network':True,'post_count':0}
    print(json.dumps(started,separators=(',',':')),flush=True)
    run=Path(payload['run_dir'])
    require(run.is_absolute() and run.resolve(strict=True)==run,'observer run path differs')
    st=run.stat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and st.st_gid==0 and
            stat.S_IMODE(st.st_mode)==0o700,'observer run ownership differs')
    prefix=run/('local-%02d'%payload['round_number'])
    write_observer_json(prefix.with_suffix('.cleanup-observer-started.json'),started)
    try:
        require(hashlib.sha256(private_bytes(payload['binding_path'])).hexdigest()==payload['binding_sha256'],
                'startup binding bytes changed')
        binding=load_binding(payload['binding_path'])
        require(binding['server_identity']==payload['expected_identity'],
                'cleanup cannot switch to a new server identity')
        result=drain_original(payload['config'],binding,payload['request_id'],run,
            payload['round_number'],payload['request_sha256'],payload['request_bytes'],write_observer_json)
    except Exception as error:
        result={'schema':'hepta.model-passive-cleanup.v1','request_id':payload['request_id'],
                'request_sha256':payload['request_sha256'],'admitted':False,'state':'UNKNOWN',
                'error':type(error).__name__+':'+str(error)[:192],
                'post_count':0,'new_model_requests':0,'decision_count':0,'tool_count':0,
                'last_slot_observation':{'observed':False,'idle':False,'inference_cleanup':'unknown'}}
    ref=write_observer_json(prefix.with_suffix('.cleanup-observer-result.json'),result)
    print(json.dumps({'kind':'observer_result','result':result,'result_ref':ref},
                     ensure_ascii=False,separators=(',',':')),flush=True)
    return 0


def bounded_observer(config,binding_path,binding_sha256,expected_identity,
                     request_id,request_sha256,request_bytes,run_dir,round_number,on_owned):
    """Parent control only: no file reads, file writes, hashing files, or fsync.

    Nonblocking pipe traffic and pidfd signalling share a six-second deadline.
    A missing real waitpid/join means UNKNOWN even if a partial result said idle.
    The caller stores the controller receipt in its existing slot-after record.
    """
    start=time.monotonic();end=start+CLEANUP_SECONDS
    evidence={'schema':'hepta.cleanup-observer-controller.v1','request_id':request_id,
        'request_sha256':request_sha256,'cleanup_budget_seconds':CLEANUP_SECONDS,
        'observation_budget_seconds':OBSERVATION_SECONDS,'admitted':False,'state':'UNKNOWN',
        'signals':[],'pidfd_opened':False,'waitpid_join_returned':False,
        'observer_returncode':None,'observer_may_still_exist':False,
        'post_count':0,'new_model_requests':0,'decision_count':0,'tool_count':0,
        'last_slot_observation':{'observed':False,'idle':False,'inference_cleanup':'unknown'}}
    payload={'schema':'hepta.cleanup-observer-input.v1','parent_pid':os.getpid(),
             'binding_path':str(binding_path),'config':{
                 'endpoint':config['endpoint'],'api_key_file':config['api_key_file']},
             'request_id':request_id,'request_sha256':request_sha256,
             'request_bytes':request_bytes,'run_dir':str(run_dir),'round_number':round_number,
             'expected_identity':expected_identity,'binding_sha256':binding_sha256}
    wire=json.dumps(payload,separators=(',',':')).encode()
    output={'stdout':bytearray(),'stderr':bytearray()}
    process=None;pidfd=None;selector=None
    try:
        require(hasattr(os,'pidfd_open') and hasattr(signal,'pidfd_send_signal'),'pidfd control unavailable')
        require(len(wire)<=16384,'observer control input bound')
        process=subprocess.Popen([sys.executable,'-B',str(Path(__file__)),'--observer-worker'],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            start_new_session=False,bufsize=0,close_fds=True)
        on_owned(process)
        evidence['observer_pid']=process.pid
        # Child has not been reaped, so this pidfd cannot name a reused PID.
        pidfd=os.pidfd_open(process.pid,0);evidence['pidfd_opened']=True
        selector=selectors.DefaultSelector()
        for stream,name in ((process.stdin,'stdin'),(process.stdout,'stdout'),(process.stderr,'stderr')):
            os.set_blocking(stream.fileno(),False)
            selector.register(stream,selectors.EVENT_WRITE if name=='stdin' else selectors.EVENT_READ,name)
        sent=0;term=False;kill=False
        while time.monotonic()<end:
            elapsed=time.monotonic()-start
            if not term and elapsed>=5.25 and process.poll() is None:
                try:signal.pidfd_send_signal(pidfd,signal.SIGTERM,None,0)
                except ProcessLookupError:pass
                evidence['signals'].append({'signal':'SIGTERM','elapsed_seconds':elapsed});term=True
            if not kill and elapsed>=5.5 and process.poll() is None:
                try:signal.pidfd_send_signal(pidfd,signal.SIGKILL,None,0)
                except ProcessLookupError:pass
                evidence['signals'].append({'signal':'SIGKILL','elapsed_seconds':elapsed});kill=True
            for event,_ in selector.select(max(0,min(.01,end-time.monotonic()))):
                stream=event.fileobj;name=event.data
                if name=='stdin':
                    try:n=os.write(stream.fileno(),wire[sent:])
                    except BrokenPipeError:n=0;sent=len(wire)
                    except BlockingIOError:continue
                    sent+=n
                    if sent>=len(wire):
                        selector.unregister(stream);stream.close()
                else:
                    try:chunk=os.read(stream.fileno(),65536)
                    except BlockingIOError:continue
                    if not chunk:
                        selector.unregister(stream);stream.close()
                    else:
                        output[name].extend(chunk)
                        require(len(output[name])<=196608,'observer stream bound')
            if process.poll() is not None and not selector.get_map():
                break
        # poll/wait(0) never grants more time; retain the original process if not joined.
        code=process.poll()
        if code is not None:
            evidence['observer_returncode']=process.wait(timeout=0)
            evidence['waitpid_join_returned']=True
            on_owned(None)
        else:
            evidence['observer_may_still_exist']=True
        if evidence['waitpid_join_returned'] and evidence['observer_returncode']==0:
            require(not output['stderr'],'observer stderr is not empty')
            lines=bytes(output['stdout']).splitlines()
            require(len(lines)==2,'observer complete terminal frames absent')
            hello,done=(strict_json(line) for line in lines)
            require(hello.get('kind')=='observer_started' and hello.get('pid')==process.pid and
                    hello.get('parent_pid')==os.getpid(),'observer actual identity differs')
            require(done.get('kind')=='observer_result' and
                    done.get('result',{}).get('request_id')==request_id and
                    done.get('result',{}).get('request_sha256')==request_sha256,
                    'observer original request result differs')
            result=done['result'];ref=done['result_ref']
            expected_raw=(json.dumps(result,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n').encode()
            require(ref.get('bytes')==len(expected_raw) and
                    ref.get('sha256')==hashlib.sha256(expected_raw).hexdigest(),
                    'observer durable result byte pin differs')
            evidence.update(observer_identity=hello,observer_result_ref=ref,
                observer_result=result,last_slot_observation=result['last_slot_observation'])
            if result.get('admitted') is True:
                require(result.get('server_identity')==expected_identity,'observer server identity differs')
            if result.get('admitted') is True and not evidence['signals'] and time.monotonic()<=end:
                evidence.update(admitted=True,state='ORIGINAL_CLEANUP_VERIFIED_AND_OBSERVER_JOINED')
    except Exception as error:
        evidence['error']=type(error).__name__+':'+str(error)[:192]
        # Still address only this owned observer; never the inference server.
        if process is not None and pidfd is not None and process.poll() is None:
            try:signal.pidfd_send_signal(pidfd,signal.SIGKILL,None,0)
            except ProcessLookupError:pass
            evidence['signals'].append({'signal':'SIGKILL','reason':'observer_failure',
                                        'elapsed_seconds':time.monotonic()-start})
            while process.poll() is None and time.monotonic()<end:
                time.sleep(min(.01,max(0,end-time.monotonic())))
        if process is not None and process.poll() is not None:
            evidence['observer_returncode']=process.wait(timeout=0)
            evidence['waitpid_join_returned']=True;on_owned(None)
        elif process is not None:
            evidence['observer_may_still_exist']=True
    finally:
        if selector is not None:selector.close()
        if process is not None:
            for stream in (process.stdin,process.stdout,process.stderr):
                if stream is not None and not stream.closed:stream.close()
        if pidfd is not None:os.close(pidfd)
    # Include bounded output encoding/hashing before the final admission deadline.
    # This is the cleanup controller only: pre-POST admission I/O and the caller's
    # existing slot-after durable commit remain outside this six-second window.
    tail_start=time.monotonic()
    evidence['stdout_b64']=base64.b64encode(output['stdout']).decode()
    evidence['stderr_b64']=base64.b64encode(output['stderr']).decode()
    evidence['stdout_sha256']=hashlib.sha256(output['stdout']).hexdigest()
    evidence['stderr_sha256']=hashlib.sha256(output['stderr']).hexdigest()
    evidence['bounded_output_processing_seconds']=time.monotonic()-tail_start
    evidence['elapsed_seconds']=time.monotonic()-start
    evidence['deadline_exceeded']=evidence['elapsed_seconds']>CLEANUP_SECONDS
    if evidence['deadline_exceeded'] or not evidence['waitpid_join_returned']:
        evidence.update(admitted=False,state='UNKNOWN')
    return evidence


if __name__=='__main__':
    require(sys.argv[1:]==['--observer-worker'],'observer accepts only the owned once mode')
    raise SystemExit(observer_worker())
