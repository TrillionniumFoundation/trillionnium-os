#!/usr/bin/env python3
"""One reviewed physical fault on one exact newly accepted native task.

Default preview is host-only. Execution is root-only and consumes a durable
request-keyed intent before observation. Only the exact carrier pidfd receives
TERM (NEG04/05), or the exact r6 worker pidfd receives STOP (NEG07). Original r6
timeout cleanup remains responsible for the stopped worker. No retry, follow-up
CONT, provider request, dispatch, Cancel, service or broker signal is performed.
"""
import argparse
import base64
import errno
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import select
import selectors
import shlex
import signal
import stat
import subprocess
import sys
import time
import types

BASE = Path('/var/lib/trillionnium/owner-open/phone-local-v150')
ANDROID = Path('/proc/1/root')
KEYS = ('session_id','profile_id','task_id','turn_id','turn_stream_id')
EXECUTOR = '/data/local/tmp/hepta-phone-executor-v150-r6/bin/phone-tool-sidecar-r6'
EXECUTOR_SHA = '8595f99cf8d0f39ec2a45f85f1250745c158ea504d2d0520cd83791f28bdb976'
WORKER = '/data/local/tmp/hepta-phone-executor-v150-r6/bin/phone-tool-worker-r6'
WORKER_SHA = '49fb74f8798194c63d5e510c0ed81604d64a55e1df84822d9457ae4110cab6da'
WORKER_DOMAIN = 'u:r:trillionnium_owner_open_phone_worker:s0'
EXECUTOR_DOMAIN = 'u:r:trillionnium_owner_open_phone_executor:s0'
BUSYBOX = '/data/adb/magisk/busybox'
STOCK_SHELL = '/system/bin/sh'
STOCK_SHELL_SHA = '4395a80cb88e3fa7a26d8fc1c34beea6c8a78c7664cdd3978671a8fb3dfb76ab'
STOCK_BUSYBOX_SHA = '4d60ab3f5a59ebb2ca863f2f514e6924401b581e9b64f602665c008177626651'
STOCK_ORIGINAL_SHA = '5a7bed5c097b1ee4e560c8bd311e8e0f4d66141e4fff3fb76ae5d14e5fb9c841'
PROBES = {
    'org.trillionnium.hepta.controlprobe/org.trillionnium.hepta.controlprobe.VisualChallengeActivity',
    'org.trillionnium.hepta.controlprobe/org.trillionnium.hepta.controlprobe.TextEntryActivity'}
CASE_SIGNALS = {'NEG-04':signal.SIGTERM, 'NEG-05':signal.SIGTERM, 'NEG-07':signal.SIGSTOP}
PROCESS_FIELDS = ('pid','ppid','pgrp','sid','start_ticks','domain','uid','gid','no_new_privs','exe','argv')
carrier = observation = projection = cancel_guards = active = None

def need(value, reason):
    if not value: raise ValueError(reason)

def sha(raw): return hashlib.sha256(raw).hexdigest()

def strict(raw):
    def pairs(items):
        result = {}
        for key,value in items:
            need(key not in result,'duplicate JSON key'); result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))

def encoded(value):
    return (json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()

def source_read(path, maximum=262144):
    path=Path(path)
    need(path.parent.resolve(strict=True)==path.parent,'noncanonical bundle input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=maximum,'bundle input metadata')
        with os.fdopen(fd,'rb',closefd=False) as f: raw=f.read(maximum+1)
        b,n=os.fstat(fd),path.lstat()
        fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        need(len(raw)==a.st_size and all(getattr(a,k)==getattr(b,k)==getattr(n,k) for k in fields),'bundle input changed')
        return raw
    finally: os.close(fd)

def load_bundle(manifest_pin):
    global carrier, observation, projection, cancel_guards, active
    inline=globals().get('_INLINE_BUNDLE')
    if inline is None:
        root=Path(__file__).resolve().parent.parent
        manifest_raw=source_read(root/'MANIFEST.json')
        manifest=strict(manifest_raw)
        bodies={row['path']:source_read(root/row['path']) for row in manifest['runtime_sources']}
    else:
        need(isinstance(inline,dict) and set(inline)=={'manifest_b64','sources'},'inline bundle fields')
        manifest_raw=base64.b64decode(inline['manifest_b64'],validate=True)
        manifest=strict(manifest_raw)
        bodies={name:base64.b64decode(raw,validate=True) for name,raw in inline['sources'].items()}
    need(sha(manifest_raw)==manifest_pin,'reviewed operator manifest differs')
    need(manifest['schema']=='hepta.r10.signal-fault-package.v1','operator schema')
    rows=manifest['runtime_sources']
    allowed={'source/'+name for name in ('signal_fault_once_r10.py','observe_carrier_r10.py',
        'observe_cancel_phase_r10.py','active_runtime_r10.py','cancel_phase.py','native_journal_audit.py',
        'reviewed_page_projection.py','production-pins.json')}
    need(len(rows)==len(allowed) and {r['path'] for r in rows}==set(bodies)==allowed,'exact operator runtime inventory')
    for row in rows:
        raw=bodies[row['path']]
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'operator source bytes differ')
    def module(name):
        m=types.ModuleType(name); m.__file__='pinned-operator/'+name+'.py'
        sys.modules[name]=m
        exec(compile(bodies['source/'+name+'.py'],m.__file__,'exec'),m.__dict__)
        return m
    active=module('active_runtime_r10')
    active._REVIEWED_PRODUCTION_PINS=strict(bodies['source/production-pins.json'])
    cancel_guards=module('cancel_phase')
    carrier=module('observe_carrier_r10')
    projection=module('reviewed_page_projection')
    observation=module('observe_cancel_phase_r10')
    observation._REVIEWED_PRODUCTION_PINS=strict(bodies['source/production-pins.json'])
    observation._REVIEWED_NATIVE_AUDIT_SOURCE=bodies['source/native_journal_audit.py']
    return manifest

def validate_plan(plan):
    fields={'schema','case_id','operation_id','nonce','expected_boot','owner_request_b64',
            'owner_request_sha256','scope','previous_scope','run','roles','release_pins',
            'expected_probe_component','android_shell_exe','android_shell_sha256','busybox_sha256',
            'app_scope','task_template_sha256','runtime_binding'}
    need(isinstance(plan,dict) and set(plan)==fields,'exact plan fields required')
    need(plan['schema']=='hepta.r10.signal-fault-plan.v1' and plan['case_id'] in CASE_SIGNALS,'fixed physical case required')
    need(re.fullmatch('[a-z0-9][a-z0-9-]{5,79}',plan['operation_id']),'operation id')
    need(re.fullmatch('[0-9a-f]{32}',plan['nonce']),'fresh nonce')
    need(re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',plan['expected_boot']),'boot format')
    owner=base64.b64decode(plan['owner_request_b64'],validate=True)
    need(base64.b64encode(owner).decode()==plan['owner_request_b64'] and 20<=len(owner)<=16000 and
         sha(owner)==plan['owner_request_sha256'] and owner.decode().count(plan['nonce'])==1 and b'\0' not in owner,
         'exact owner bytes and single nonce required')
    for name in ('scope','previous_scope'):
        value=plan[name]
        need(isinstance(value,dict) and set(value)==set(KEYS) and
             all(isinstance(v,str) and 0<len(v.encode())<=256 and '\0' not in v for v in value.values()),'scope format')
    need([plan['scope'][k] for k in KEYS[:-1]]!=[plan['previous_scope'][k] for k in KEYS[:-1]],'old semantic task reuse')
    need(re.fullmatch('[0-9]{8}-[0-9]{6}-[0-9a-f]{32}',plan['run']),'run name')
    active.validate_task_expectations(plan,owner)
    roles=plan['roles']
    need(isinstance(roles,dict) and set(roles)=={'supervisor','provider','sidecar','model'},'four actual readiness roles')
    for row in roles.values():
        need(isinstance(row,list) and len(row)==4 and all(type(n) is int and n>1 for n in row)
             and row[0]==row[1]==row[2],'owned readiness role identity')
    need(len({row[0] for row in roles.values()})==4,'readiness roles collide')
    if plan['case_id']=='NEG-04':
        need(all(plan[k] is None for k in ('expected_probe_component','android_shell_exe','android_shell_sha256','busybox_sha256')),
             'pre-dispatch detach has no probe or Android helper action')
    else:
        need(plan['expected_probe_component'] in PROBES,'only the approved disposable probe may be targeted')
        need(plan['android_shell_exe']==STOCK_SHELL and plan['android_shell_sha256']==STOCK_SHELL_SHA,
             'independently sampled exact stock shell resolved path and binary pin required')
        if plan['case_id']=='NEG-05':
            need(plan['busybox_sha256']==STOCK_BUSYBOX_SHA,'independently sampled actual read-only helper binary pin required')
        else: need(plan['busybox_sha256'] is None,'worker stop does not launch a page query')
    return owner

def original(path, maximum=1048576):
    raw,_=carrier.stable(path,maximum,0o600)
    return raw,{'path':str(path),'bytes':len(raw),'sha256':sha(raw),'raw_b64':base64.b64encode(raw).decode()}

def same_process(before, after):
    need(all(before[k]==after[k] for k in PROCESS_FIELDS),'target or parent process generation changed')

def untraced(pid):
    status={row.split(':',1)[0]:row.split(':',1)[1].strip()
            for row in carrier.proc_bytes(pid,'status').decode().splitlines() if ':' in row}
    need(status['TracerPid']=='0','traced process is not an injection target')
    return status

def carrier_binding(plan):
    return {'schema':'hepta.r10.native-carrier-observation-binding.v1','expected_boot':plan['expected_boot'],
            'scope':plan['scope'],'owner_request_sha256':plan['owner_request_sha256'],'run':plan['run'],
            'provider_identity':plan['roles']['provider'],
            'source_seal_sha256':plan['release_pins']['source_seal_sha256'],
            'configuration_sha256':plan['release_pins']['configuration_sha256'],
            'runtime_binding':plan['runtime_binding']}

def task_phase(plan, owner):
    run=BASE/'provider-state/evidence'/plan['run']
    inraw,indesc=original(run/'provider-in.jsonl',4*1024*1024)
    outraw,outdesc=original(run/'provider-out.jsonl',4*1024*1024)
    incoming,outgoing=observation.jlines(inraw),observation.jlines(outraw)
    for rows in (incoming,outgoing):
        need(all(row.get('protocol')==carrier.PROTOCOL and type(row.get('seq')) is int and row['seq']==i
                 for i,row in enumerate(rows)),'provider sequence differs')
    need(incoming and incoming[0]['kind']=='turn.start' and
         {k:incoming[0]['turn'][k] for k in KEYS}==plan['scope'] and
         incoming[0]['turn']['user_input'].encode()==owner,'exact accepted task required')
    need(all(r.get('kind') not in {'turn.complete','turn.cancelled','turn.fail','turn.cancel'}
             for r in incoming+outgoing),'task control or terminal already advanced')
    health=observation.business_marker(run)
    runtime=active.current(plan['runtime_binding'],plan['expected_boot'])
    task_scope=active.contract_originals(run,plan['scope'],owner,plan,runtime['config'])
    native=observation.native_records(plan['scope'])
    need(native['native_request_sha256']==cancel_guards.native_request_digest(plan['scope'],owner)
         and native['native_terminal'] is None and native['cancel_acceptances']==0,'native accepted/control binding differs')
    calls,originals=observation.dispatches(run,plan['scope'],incoming,outgoing)
    tool_results=[r for r in incoming if r['kind']=='tool.result']
    if plan['case_id']=='NEG-04':
        need(calls==[] and tool_results==[],'before-dispatch phase has already ended')
    else:
        need(len(calls)==1 and tool_results==[],'exact first action, before its provider result, required')
        need(calls[0]['semantic_tool']=='phone.open_app' and
             calls[0]['component']==plan['expected_probe_component'],'first action is not the approved probe open')
    need(carrier.stable(run/'provider-in.jsonl',4*1024*1024,0o600)[0]==inraw and
         carrier.stable(run/'provider-out.jsonl',4*1024*1024,0o600)[0]==outraw and
         observation.business_marker(run)==health,'dispatch or business mode advanced during observation')
    need(active.contract_originals(run,plan['scope'],owner,plan,runtime['config'])==task_scope,
         'request-bound v150.3 app-scope originals advanced during phase observation')
    return {'input':indesc,'output':outdesc,'health_contract':health,'task_scope_originals':task_scope,'native':native,
            'calls':calls,'action_originals':originals,'observed_monotonic_ns':time.monotonic_ns()}

def phase_identity(row):
    return {k:row[k] for k in ('input','output','health_contract','task_scope_originals','native','calls','action_originals')}

def sidecar_worker(plan, phase):
    call=phase['calls'][0];action=call['action_id'];run=BASE/'provider-state/evidence'/plan['run']
    semantic_raw,_=original(run/('semantic-'+sha(call['call_id'].encode())+'.json'))
    semantic=strict(semantic_raw);argv=semantic['wire_call']['argv']
    command=base64.b64decode(argv[6],validate=True).decode()
    need(sha(command.encode())==call['command_sha256'] and '\0' not in command and 0<len(command.encode())<=131072,
         'original action command differs')
    timeout=int(argv[8]);need(timeout==60000,'original fixed executor 60-second budget required')
    action_dir=BASE/'executor-r6/actions'/action
    iraw,intent_original=original(action_dir/'intent.json')
    rraw,receipt_original=original(action_dir/'receipt.json')
    intent,receipt=strict(iraw),strict(rraw)
    for row in (intent,receipt):
        need(row.get('version')==1 and row.get('executor_revision')==6 and row.get('action_id')==action and
             row.get('command_sha256')==sha(command.encode()) and row.get('timeout_ms')==timeout and
             row.get('can_redispatch') is False and row.get('peer_uid')==0 and
             row.get('peer_context')=='u:r:trillionnium_owner_open_bootstrap:s0' and
             row.get('executor_context')==EXECUTOR_DOMAIN and row.get('handshake_stage')=='worker_entry_after_exec_transition',
             'original r6 action identity or domain binding differs')
    need(intent['state']=='intent' and intent['terminal'] is False and intent['dispatch_count']==0 and
         intent['server_instance']==receipt['server_instance'] and re.fullmatch('[0-9a-f]{32}',receipt['server_instance']),
         'r6 original intent or server instance differs')
    need(receipt['state']=='running' and receipt['terminal'] is False and receipt['dispatch_count']==1 and
         receipt['effect_started'] is True and receipt['worker_domain_verified'] is True and
         receipt['execution_context']==WORKER_DOMAIN and receipt['execution_credentials_verified'] is True and
         receipt['supplementary_groups_cleared'] is True and receipt['execution_supplementary_group_count']==0 and
         all(receipt.get(k)==2000 for k in ('execution_uid','execution_euid','execution_gid','execution_egid')),
         'exact running post-transition r6 worker required; handshake is not app-effect proof')
    worker=carrier.process(receipt['pid']);parent=carrier.process(worker['ppid'])
    need(carrier.identity(parent)==plan['roles']['sidecar'] and parent['exe']==EXECUTOR and
         parent['domain']==EXECUTOR_DOMAIN and parent['uid']==parent['gid']==[0]*4 and parent['no_new_privs']==0 and
         carrier.process_digest(parent['pid'])==EXECUTOR_SHA,'current sidecar parent differs')
    need(worker['pid']==worker['pgrp']==worker['sid']==receipt['pgid'] and worker['domain']==WORKER_DOMAIN and
         worker['uid']==worker['gid']==[2000]*4 and worker['no_new_privs']==0 and worker['state'] not in ('T','t'),
         'worker generation, dedicated session or credentials differ')
    status=untraced(worker['pid']);untraced(parent['pid'])
    need(status.get('Groups','')=='','worker supplementary groups differ')
    if worker['exe']==WORKER:
        wargv=worker['argv'];need(len(wargv)==7 and wargv[0]==WORKER and wargv[1]=='--started-fd' and
            re.fullmatch('[0-9]+',wargv[2]) and int(wargv[2])>=3 and wargv[3:5]==['--expected-parent',str(parent['pid'])]
            and wargv[5:]==['--command',command] and carrier.process_digest(worker['pid'])==WORKER_SHA,
            'original dedicated worker argv/image differs')
    else:
        need(worker['exe']==plan['android_shell_exe'] and worker['argv']==['/system/bin/sh','-c',command] and
             carrier.process_digest(worker['pid'])==plan['android_shell_sha256'],'stock shell argv/resolved image differs')
    child_fds,parent_fds=carrier.fd_links(worker['pid']),carrier.fd_links(parent['pid'])
    pipes={}
    for fd in (1,2):
        target=child_fds.get(fd,'');need(re.fullmatch(r'pipe:\[[0-9]+\]',target),'worker output is not a pipe')
        peers=sorted(n for n,value in parent_fds.items() if value==target)
        need(peers,'current sidecar does not own worker output peer');pipes[str(fd)]={'pipe':target,'parent_fds':peers}
    need(pipes['1']['pipe']!=pipes['2']['pipe'],'worker stdout/stderr aliased')
    logs={}
    for name in ('stdout.bin','stderr.bin'):
        _raw,wanted=carrier.stable(action_dir/name,4*1024*1024,0o600)
        owners=[]
        for fd in parent_fds:
            try:s=os.stat('/proc/'+str(parent['pid'])+'/fd/'+str(fd))
            except OSError as error:
                if error.errno in (errno.ENOENT,errno.ESRCH):continue
                raise
            if (s.st_dev,s.st_ino)==wanted:owners.append(fd)
        need(owners,'sidecar does not hold the exact action log inode');logs[name]={'inode':list(wanted),'parent_fds':sorted(owners)}
    return {'worker':worker,'sidecar':parent,'pipes':pipes,'logs':logs,'intent':intent_original,
            'receipt':receipt_original,'receipt_value':receipt,'command_sha256':sha(command.encode()),
            'handshake_is_independent_effect_proof':False}

def android_file_sha(path, wanted):
    # /proc/1/root is the single deliberate native-root anchor; every component
    # below it is opened through a held dirfd without following symlinks.
    parts=Path(path).parts;need(parts[0]=='/' and '..' not in parts,'Android pin path')
    fd=os.open(ANDROID,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for part in parts[1:-1]:
            next_fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd);fd=next_fd
        file_fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
        try:
            a=os.fstat(file_fd);need(stat.S_ISREG(a.st_mode) and a.st_uid==0 and a.st_nlink==1 and
                                    not a.st_mode&0o022 and 0<a.st_size<=16*1024*1024,'Android helper metadata')
            h=hashlib.sha256();count=0
            while True:
                data=os.read(file_fd,65536)
                if not data:break
                count+=len(data);need(count<=a.st_size,'Android helper grew');h.update(data)
            b=os.fstat(file_fd);n=os.stat(parts[-1],dir_fd=fd,follow_symlinks=False)
            fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
            need(count==a.st_size and all(getattr(a,k)==getattr(b,k)==getattr(n,k) for k in fields) and h.hexdigest()==wanted,
                 'Android helper source pin changed')
        finally:os.close(file_fd)
    finally:os.close(fd)

def readonly_page(plan,directory):
    android_file_sha(BUSYBOX,plan['busybox_sha256'])
    android_file_sha(plan['android_shell_exe'],plan['android_shell_sha256'])
    marker='HEPTA_R9_FAULT_VIEWPORT_BOUNDARY'
    code=('set -e; [ "$(getprop ro.serialno)" = ZY22LS7WZT ]; '
          '[ "$(cat /proc/sys/kernel/random/boot_id)" = '+shlex.quote(plan['expected_boot'])+' ]; '+
          projection.PAGE_STATE_COMMAND+'; printf "\\n'+marker+'\\n"; dumpsys display | grep "mViewports="')
    argv=[str(ANDROID)+BUSYBOX,'chroot',str(ANDROID),'/system/bin/sh','-c',code]
    put_at(directory,'PAGE-QUERY-INTENT.json',{'schema':'hepta.r9-r2.independent-page-query-intent.v1',
        'argv':argv,'command_sha256':sha(code.encode()),'stock_original_sha256':STOCK_ORIGINAL_SHA,
        'phone_ui_actions':0,'automatic_retry':False})
    began=time.monotonic_ns();child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,env={'PATH':'/system/bin:/system/xbin','LANG':'C'},start_new_session=True)
    buffers={1:bytearray(),2:bytearray()};selector=selectors.DefaultSelector();cleanup=[];rc=None
    selector.register(child.stdout,selectors.EVENT_READ,1);selector.register(child.stderr,selectors.EVENT_READ,2)
    deadline=time.monotonic()+4
    try:
        need(os.getpgid(child.pid)==os.getsid(child.pid)==child.pid,'read-only helper is not owned session')
        while selector.get_map():
            remaining=deadline-time.monotonic();need(remaining>0,'read-only page deadline')
            for key,_ in selector.select(min(remaining,.1)):
                raw=os.read(key.fileobj.fileno(),4096)
                if not raw:selector.unregister(key.fileobj);continue
                buffers[key.data].extend(raw)
                need(len(buffers[key.data])<=32768,'read-only page output bound')
        rc=child.wait(timeout=max(.001,deadline-time.monotonic()))
    except BaseException:
        # This is only the new read-only helper child, whose PID has not been
        # reaped. Its dedicated session cannot be any admitted service role.
        if child.returncode is None:
            for sig in (signal.SIGTERM,signal.SIGKILL):
                try:os.killpg(child.pid,sig);cleanup.append(int(sig))
                except ProcessLookupError:pass
            child.wait(timeout=2)
        raise
    finally:
        selector.close();child.stdout.close();child.stderr.close()
        put_at(directory,'PAGE-QUERY-RESULT.json',{'schema':'hepta.r9-r2.independent-page-query-result.v1',
            'started_monotonic_ns':began,'finished_monotonic_ns':time.monotonic_ns(),
            'original_pid':child.pid,'returncode':child.returncode,
            'stdout_b64':base64.b64encode(bytes(buffers[1])).decode(),
            'stderr_b64':base64.b64encode(bytes(buffers[2])).decode(),
            'cleanup_signals_to_owned_query_group':cleanup,'phone_ui_actions':0,'automatic_retry':False})
    ended=time.monotonic_ns();stdout,stderr=bytes(buffers[1]),bytes(buffers[2])
    need(rc==0 and stderr==b'','independent public page observation failed')
    parts=stdout.decode().split('\n'+marker+'\n');need(len(parts)==2,'independent page boundaries')
    page=projection.page_state(parts[0]);viewport_sha=projection.validate_viewport(parts[1])
    need(page['component']==plan['expected_probe_component'],'approved probe effect not independently observed')
    return {'schema':'hepta.r9-r2.independent-probe-page.v1','source':'new bounded operator read-only Android dumpsys',
        'command_sha256':sha(code.encode()),'started_monotonic_ns':began,'finished_monotonic_ns':ended,
        'stdout_b64':base64.b64encode(stdout).decode(),'stdout_sha256':sha(stdout),'bytes':len(stdout),
        'page':page,'viewport_sha256':viewport_sha,'helper_exit_code':rc,'helper_cleanup_signals':cleanup,
        'numeric_effect_count_claimed':False,'phone_ui_actions':0}

def current_roles(plan):
    active.verify_current(active.current(plan['runtime_binding'],plan['expected_boot']))
    for name,wanted in plan['roles'].items():
        row=carrier.process(wanted[0]);need(carrier.identity(row)==wanted,'readiness role generation changed: '+name)

def pidfd_apply_once(pid, sig, revalidate):
    """Kernel-protected single process action, never a numeric-PID fallback."""
    need(type(pid) is int and pid>1 and sig in (signal.SIGTERM,signal.SIGSTOP),'one bounded process signal required')
    need(hasattr(os,'pidfd_open') and hasattr(signal,'pidfd_send_signal'),'pidfd support is required')
    fd=os.pidfd_open(pid,0)
    try:
        poll=select.poll();poll.register(fd,select.POLLIN|select.POLLHUP|select.POLLERR)
        need(not poll.poll(0),'target exited before held pidfd validation')
        proof=revalidate()
        need(not poll.poll(0),'target exited during final validation')
        started=time.monotonic_ns()
        signal.pidfd_send_signal(fd,sig,None,0)
        returned=time.monotonic_ns()
        return {'target_pid':pid,'signal':int(sig),'syscall_started_monotonic_ns':started,
                'syscall_returned_monotonic_ns':returned,'syscall_returned_zero':True,
                'target_exited_at_return':bool(poll.poll(0)),'final_revalidation':proof}
    finally:os.close(fd)

def put_at(directory,name,value):
    raw=encoded(value);need(len(raw)<=4*1024*1024,'operator evidence byte bound')
    fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    dfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(dfd)
    finally:os.close(dfd)
    return {'path':str(directory/name),'bytes':len(raw),'sha256':sha(raw)}

def begin_intent(plan, manifest_pin):
    root=BASE/'fault-injections-r10-r1'
    need(root.parent.resolve(strict=True)==root.parent,'intent root parent differs')
    try:root.mkdir(mode=0o700)
    except FileExistsError:pass
    s=root.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700
                       and root.resolve(strict=True)==root,'intent root metadata')
    parent_fd=os.open(BASE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(parent_fd)
    finally:os.close(parent_fd)
    directory=root/plan['owner_request_sha256'];directory.mkdir(mode=0o700)
    root_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(root_fd)
    finally:os.close(root_fd)
    put_at(directory,'INTENT.json',{'schema':'hepta.r10.signal-fault-intent.v1','plan':plan,
        'operator_manifest_sha256':manifest_pin,'automatic_retry':False,'created_monotonic_ns':time.monotonic_ns()})
    return directory

def execute(plan, manifest_pin):
    owner=validate_plan(plan)
    need(os.getuid()==os.geteuid()==0 and os.readlink('/proc/1/exe')=='/system/bin/init','native Android root required')
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==plan['expected_boot'],'boot differs')
    need(carrier.proc_bytes(os.getpid(),'attr/current') in (b'u:r:magisk:s0',b'u:r:magisk:s0\0',b'u:r:magisk:s0\n'),
         'operator must use original Magisk root domain')
    directory=begin_intent(plan,manifest_pin);attempted=False
    try:
        with active.verified_runtime(plan['runtime_binding'],plan['expected_boot']):
            current_roles(plan)
            chain=carrier.observe(carrier_binding(plan))
            first=task_phase(plan,owner)
            worker=None;page=None
            if plan['case_id'] in ('NEG-05','NEG-07'):worker=sidecar_worker(plan,first)
            if plan['case_id']=='NEG-05':page=readonly_page(plan,directory)
            target=worker['worker'] if plan['case_id']=='NEG-07' else chain['carrier']
            need(target['pid'] not in {1,os.getpid(),chain['native_parent']['pid'],*[r[0] for r in plan['roles'].values()]},
                 'target is an operator, broker, parent or service role')
            need(target['state'] not in ('T','t'),'pre-stopped target refused')
            untraced(target['pid'])
            preflight={'plan_sha256':sha(encoded(plan)),'chain':chain,'phase':first,'worker':worker,'public_effect':page,
                'active_runtime_originals':active.current(plan['runtime_binding'],plan['expected_boot'])['last_observation']}
            before=put_at(directory,'PRE-SIGNAL.json',preflight)
            def immediate():
                current_roles(plan)
                for name in ('provider','carrier','native_parent'):
                    same_process(chain[name],carrier.process(chain[name]['pid']))
                carrier.revalidate_transport_edges(chain['provider']['pid'],chain['carrier']['pid'],
                    chain['native_parent']['pid'],chain['socket_pair'],chain['pipe_peers'])
                need(carrier.open_original_streams(chain['provider']['pid'],BASE/'provider-state/evidence'/plan['run'])
                     ==chain['original_streams'],'provider original stream ownership changed')
                final=task_phase(plan,owner)
                need(phase_identity(final)==phase_identity(first),'original dispatch/native prefix changed; phase missed')
                claim_key=sha(json.dumps([plan['scope'][k] for k in KEYS[:-1]],separators=(',',':')).encode())
                claim_raw,_=carrier.stable(BASE/'provider-state/evidence/claims'/claim_key,65536,0o600)
                terminal=BASE/'provider-state/evidence'/plan['run']/'terminal.json'
                need(sha(claim_raw)==chain['claim_sha256'] and not terminal.exists() and not terminal.is_symlink(),
                     'consumed claim or terminal changed during final validation')
                if worker is not None:
                    current=sidecar_worker(plan,final)
                    same_process(worker['worker'],current['worker']);same_process(worker['sidecar'],current['sidecar'])
                    need(all(current[k]==worker[k] for k in ('pipes','logs','intent','receipt','command_sha256')),
                         'original worker ownership or receipt changed; phase missed')
                if page is not None:
                    need(0<=time.monotonic_ns()-page['finished_monotonic_ns']<=1000000000,
                         'independent public effect observation is stale')
                need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==plan['expected_boot'] and
                     (ANDROID/'sys/fs/selinux/enforce').read_bytes() in (b'1',b'1\n'),'boot or enforcing changed')
                actual_target=carrier.process(target['pid']);same_process(target,actual_target)
                need(actual_target['state'] not in ('T','t'),'target was stopped during final validation')
                untraced(target['pid'])
                # Repeat transport ownership after the original/native file reads.
                carrier.revalidate_transport_edges(chain['provider']['pid'],chain['carrier']['pid'],
                    chain['native_parent']['pid'],chain['socket_pair'],chain['pipe_peers'])
                return {'final_phase_sha256':sha(encoded(phase_identity(final))),
                        'target_identity':carrier.identity(target),'finished_monotonic_ns':time.monotonic_ns()}
            attempted=True  # Any exception after this point is retained without retry.
            action=pidfd_apply_once(target['pid'],CASE_SIGNALS[plan['case_id']],immediate)
            result={'schema':'hepta.r10.signal-fault-result.v1','state':'ONE_PIDFD_ACTION_RETURNED',
                'case_id':plan['case_id'],'scope':plan['scope'],'owner_request_sha256':plan['owner_request_sha256'],
                'operator_manifest_sha256':manifest_pin,'pre_signal':before,'action':action,
                'automatic_retry':False,'provider_requests':0,'tool_dispatches':0,'phone_ui_actions':0,
                'original_r6_timeout_cleanup_owner':plan['roles']['sidecar'] if plan['case_id']=='NEG-07' else None,
                'physical_case_pass':False,'final_native_counter_cleanup_capture_required':True}
            record=put_at(directory,'RESULT.json',result)
            return {'state':result['state'],'result':record,'physical_case_pass':False}
    except BaseException as error:
        fail={'schema':'hepta.r10.signal-fault-failure.v1','state':'UNKNOWN_NO_RETRY' if attempted else 'NO_ACTION_PREFLIGHT_FAILED',
              'case_id':plan['case_id'],'signal_call_path_entered':attempted,'error_type':type(error).__name__,
              'error':str(error)[:1000],'automatic_retry':False,'physical_case_pass':False}
        put_at(directory,'FAILURE.json',fail)
        raise

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--plan-b64',required=True)
    parser.add_argument('--manifest-sha256',required=True)
    parser.add_argument('--execute-signal-once',action='store_true')
    args=parser.parse_args()
    need(len(args.plan_b64)<=64000 and re.fullmatch('[0-9a-f]{64}',args.manifest_sha256),'bounded plan/manifest')
    plan=strict(base64.b64decode(args.plan_b64,validate=True))
    load_bundle(args.manifest_sha256)
    validate_plan(plan)
    if not args.execute_signal_once:
        print(json.dumps({'state':'HOST_ONLY_PREVIEW','case_id':plan['case_id'],
            'manifest_sha256':args.manifest_sha256,'phone_calls':0,'signals':0,'intent_writes':0,
            'physical_case_pass':False},sort_keys=True));return 0
    def expired(_sig,_frame):raise TimeoutError('bounded single-action operator expired')
    signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,30)
    try:print(json.dumps(execute(plan,args.manifest_sha256),sort_keys=True));return 0
    finally:signal.setitimer(signal.ITIMER_REAL,0)

if __name__=='__main__':sys.exit(main())
