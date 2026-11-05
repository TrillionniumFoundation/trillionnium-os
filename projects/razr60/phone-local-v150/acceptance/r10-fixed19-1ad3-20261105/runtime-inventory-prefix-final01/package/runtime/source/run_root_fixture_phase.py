#!/usr/bin/env python3
"""One P4 parent-owned fixture process; default host preview, no automatic retry.

The actual reviewed fixture source performs the authorized UI phase. This
parent retains a genuine child wait result so an unfinished host actor cannot
be mistaken for a closed phone lifecycle. Timeout leaves an explicit unknown;
it never signals or re-launches the child and cannot qualify safe closure.
"""
import argparse
import base64
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import component_common as C
import root_fixture_once as X
from prepare_component import host_read,write_new

ARGUMENTS=('material','lease-sha256','package-sha256','plan','plan-sha256',
           'bound-contract','bound-contract-sha256','accepted','accepted-sha256')
FIXTURE_PARENTS=Path('/home/alex/codex-hepta-native-guard-fixtures-r10-r1')


def prepare_parent_directory(nonce,phase,out):
    C.need(out==FIXTURE_PARENTS/nonce/phase,'Root fixture parent output left its exact nonce/phase namespace')
    C.need(FIXTURE_PARENTS.parent.resolve(strict=True)==FIXTURE_PARENTS.parent,
           'P4 parent namespace anchor differs')
    for path in (FIXTURE_PARENTS,FIXTURE_PARENTS/nonce):
        try:path.mkdir(mode=0o700)
        except FileExistsError:pass
        st=path.lstat()
        C.need(stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode)==0o700
               and st.st_uid==os.getuid() and st.st_gid==os.getgid()
               and path.resolve(strict=True)==path,'actual private P4 parent namespace differs')
    out.mkdir(mode=0o700)


def proc_stat_original(pid):
    fd=os.open('/proc/%d/stat'%pid,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        C.need(stat.S_ISREG(os.fstat(fd).st_mode),'P4 proc stat type differs')
        raw=os.read(fd,8193);C.need(0<len(raw)<=8192,'P4 proc stat bound')
        return raw
    finally:os.close(fd)


def host_child_identity(child):
    # This is the real P4 host child, never a phone /proc identity. Reading an
    # ancestor-mounted procfs with different local PIDs is a hard refusal.
    C.need(os.readlink('/proc/self')==str(os.getpid()),'P4 native proc self differs')
    first=proc_stat_original(child.pid);before=C.stat_identity(first,child.pid)
    group,session=os.getpgid(child.pid),os.getsid(child.pid)
    second=proc_stat_original(child.pid);after=C.stat_identity(second,child.pid)
    fields=('pid','ppid','pgid','sid','start_ticks')
    C.need(all(before[k]==after[k] for k in fields)
           and after['ppid']==os.getpid() and group==session==child.pid
           and after['pid']==after['pgid']==after['sid']==child.pid,
           'P4 owned fixture child generation or parent differs')
    return {'identity':C.generation(after),'ppid':after['ppid'],
        'proc_self_pid_matches_host':True,'stat_before':{'raw_b64':base64.b64encode(first).decode(),**C.descriptor(first)},
        'stat_after':{'raw_b64':base64.b64encode(second).decode(),**C.descriptor(second)}}


def actor_inventory(path):
    path=Path(path);parent=path.parent
    C.need(parent.resolve(strict=True)==parent,'canonical P4 output parent required')
    parent_fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(parent_fd)
        try:directory=os.stat(path.name,dir_fd=parent_fd,follow_symlinks=False)
        except FileNotFoundError:
            try:os.stat(path.name,dir_fd=parent_fd,follow_symlinks=False)
            except FileNotFoundError:pass
            else:C.need(False,'actor output appeared during absence observation')
            current=parent.lstat()
            C.need((before.st_dev,before.st_ino)==(current.st_dev,current.st_ino),
                   'P4 output parent changed')
            return {'path':str(path),'kind':'absent','absence':'ENOENT',
                'canonical_parent_identity':[before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_gid]},{}
        C.need(stat.S_ISDIR(directory.st_mode) and path.resolve(strict=True)==path,
               'actual actor output directory differs')
        names=sorted(path.iterdir());C.need(len(names)<=512,'actual actor original count bound')
        files={};total=0
        for item in names:
            before_item=item.lstat();raw=host_read(item,16*1024*1024);total+=len(raw)
            C.need(total<=64*1024*1024 and C.metadata(before_item)==C.metadata(item.lstat()),
                   'actual actor output bytes changed or exceeded bound')
            files[item.name]={'path':str(item),'metadata':C.metadata(before_item),**C.descriptor(raw)}
        C.need(C.metadata(directory)==C.metadata(path.lstat())
               and [p.name for p in names]==sorted(p.name for p in path.iterdir()),
               'actual actor original inventory changed')
        return {'path':str(path),'kind':'directory','metadata':C.metadata(directory),
                'names':[p.name for p in names]},files
    finally:os.close(parent_fd)


def run(a):
    os.umask(0o077)
    tree,lease,_combo,_cfg,plan,_commands=X.inputs(a)
    manifest=C.strict(host_read(tree/'package/MANIFEST.json'))
    rows={row['path']:row for row in manifest['files']}
    own='source/run_root_fixture_phase.py';source='source/root_fixture_once.py'
    C.need(rows[own]['sha256']==C.sha(host_read(Path(__file__))),
           'Root phase parent is not this reviewed package source')
    child_entry=tree/'package'/source;child_raw=host_read(child_entry)
    C.need(C.descriptor(child_raw)=={k:rows[source][k] for k in ('bytes','sha256')},
           'actual Root fixture child source differs')
    if not a.execute_root_fixture_phase_once:
        print(C.encoded({'schema':'hepta.native-guard.root-fixture-host-preview.v1',
            'state':'HOST_ONLY_NO_CHILD_OR_PHONE','scope':plan['scope'],'phase':plan['phase'],
            'phase_plan_sha256':a.plan_sha256,'phone_calls':0,'model_requests':0,
            'child_processes_started':0,'automatic_retry':False}).decode(),end='')
        return 0
    out=Path(a.out).absolute();prepare_parent_directory(lease['nonce'],plan['phase'],out)
    child_out=out/'actor'
    argv=['/usr/bin/python3','-I','-B',str(child_entry)]
    for key in ARGUMENTS:argv.extend(['--'+key,str(getattr(a,key.replace('-','_')))])
    argv.extend(['--out',str(child_out),'--execute-root-fixture-phase-once'])
    binding={'scope':plan['scope'],'phase':plan['phase'],'phase_plan_sha256':a.plan_sha256,
        'contract_sha256':plan['contract_sha256'],'lease_sha256':a.lease_sha256,'package_sha256':a.package_sha256,
        'child_entry':{'path':str(child_entry),**C.descriptor(child_raw)},'actor_out':str(child_out),'argv':argv}
    intent={'schema':'hepta.native-guard.root-fixture-host-intent.v1',**binding,
        'maximum_child_starts':1,'automatic_retry':False,'maximum_wait_seconds':240,
        'parent_source_sha256':C.sha(host_read(Path(__file__))), 'phone_actions_owned_by_child_only':True}
    write_new(out/'HOST-INTENT.json',C.encoded(intent))
    stdout=(out/'child.stdout').open('xb');stderr=(out/'child.stderr').open('xb')
    child=None;observed=None;failure=None;started=time.monotonic_ns();rc=None
    try:
        child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,
            start_new_session=True,close_fds=True,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8',
                'LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'})
        try:
            observed=host_child_identity(child)
            write_new(out/'HOST-CHILD.json',C.encoded({'schema':'hepta.native-guard.root-fixture-host-child.v1',
                **binding,**observed,'spawned_pid':child.pid,'parent_pid':os.getpid(),
                'p4_monotonic_observed_ns':time.monotonic_ns()}))
        except BaseException as error:
            failure={'phase':'child_identity','type':type(error).__name__,'detail':str(error)[:512]}
        try:rc=child.wait(timeout=max(.01,240-(time.monotonic_ns()-started)/1e9))
        except subprocess.TimeoutExpired:
            failure={'phase':'wait','type':'TimeoutExpired','detail':'Original actor may still be running; no signal or retry'}
    except BaseException as error:
        failure=failure or {'phase':'spawn_or_observe','type':type(error).__name__,'detail':str(error)[:512]}
    finally:
        stdout.close();stderr.close()
    # A pending actor can keep writing. Do not read those streams or make a
    # completed-file assertion when the original wait has not returned.
    joined=child is not None and type(rc) is int
    group_absence=[];directory=None;actor_files={}
    if joined and observed is not None:
        try:
            group_absence=[C.absent_groups([observed['identity']]),C.absent_groups([observed['identity']])]
            directory,actor_files=actor_inventory(child_out)
        except BaseException as error:
            failure=failure or {'phase':'original_absence_or_inventory','type':type(error).__name__,'detail':str(error)[:512]}
    result={'schema':'hepta.native-guard.root-fixture-host-terminal.v1',**binding,
        'state':'OWNED_ROOT_FIXTURE_CHILD_JOINED' if joined and observed is not None and failure is None else 'ROOT_FIXTURE_HOST_UNKNOWN',
        'child_pid':None if child is None else child.pid,'child_identity':observed,
        'child_wait_returned':joined,'child_returncode':rc,'failure':failure,
        'group_absence_observations':group_absence,'actor_directory':directory,'actor_files':actor_files,
        'p4_started_monotonic_ns':started,'p4_observed_monotonic_ns':time.monotonic_ns(),
        'automatic_retry':False,'signals_sent':0,'model_requests':0,'native_task_submissions':0,
        'parent_source_sha256':C.sha(host_read(Path(__file__))), 'component_qualified':False}
    if joined:
        for key in ('stdout','stderr'):
            path=out/('child.'+key);body=host_read(path,16*1024*1024)
            result[key]={'path':str(path),**C.descriptor(body)}
    write_new(out/'HOST-TERMINAL.json',C.encoded(result))
    print(C.encoded(result).decode(),end='')
    return 0 if joined and observed is not None and failure is None and rc==0 else 70


def main():
    parser=argparse.ArgumentParser()
    for name in (*ARGUMENTS,'out'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--execute-root-fixture-phase-once',action='store_true')
    return run(parser.parse_args())


if __name__=='__main__':raise SystemExit(main())
