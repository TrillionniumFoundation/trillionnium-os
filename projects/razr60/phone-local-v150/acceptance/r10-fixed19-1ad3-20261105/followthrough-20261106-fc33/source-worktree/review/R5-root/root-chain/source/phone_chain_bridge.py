#!/usr/bin/env python3
"""Bound Root bridge: copy a new archive, read actual plans, or export originals.

No UI, policy write, process signal, model request, or service lifecycle call.
The caller separately invokes the frozen component entries for those operations.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

G=Path('/var/lib/trillionnium/owner-open/phone-local-v150')
A=Path('/proc/1/root')
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
PKG = '990c726a1fff139761494cc19cf091deb269201f27ea947dda4a5833e3a72f2a'
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def need(v,s):
    if not v:raise ValueError(s)
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False)+'\n').encode()
def read(p,n=16*1024*1024):
    p=Path(p);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=n,'bounded original')
        with os.fdopen(fd,'rb',closefd=False) as f:b=f.read(n+1)
        z=os.fstat(fd);s=p.lstat();need(len(b)==a.st_size and all(getattr(a,k)==getattr(z,k)==getattr(s,k) for k in META),'unstable original')
    finally:os.close(fd)
    return b,[getattr(a,k) for k in META]
def put(p,b):
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
    fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
def root():
    need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'Root bridge required')
    need(Path('/proc/self/attr/current').read_bytes().rstrip(b'\0\n')==b'u:r:magisk:s0','Root domain')
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==BOOT,'boot')
    need(G.resolve(strict=True)==G and G.stat().st_uid==G.stat().st_gid==0
        and stat.S_IMODE(G.stat().st_mode)==0o700,'canonical private base')
def descriptor(p,include_bytes=True,maximum=16*1024*1024):
    b,m=read(p,maximum);value={'path':str(p),'bytes':len(b),'sha256':sha(b),'metadata':m}
    if include_bytes:value['base64']=base64.b64encode(b).decode()
    return value
def context(label,lease_sha):
    need(re.fullmatch('[a-z0-9][a-z0-9-]{5,55}',label) and re.fullmatch('[0-9a-f]{64}',lease_sha),'explicit label/lease')
    home=G/'native-guard-r10-r1'/label
    b,_=read(home/'LEASE.json');need(sha(b)==lease_sha,'actual lease pin');v=json.loads(b)
    need(v['label']==label and v['boot_id']==BOOT and v['package_sha256']==PKG,'actual lease binding')
    m,_=read(home/'package/MANIFEST.json');need(sha(m)==PKG,'actual package')
    for row in json.loads(m)['files']:
        b,_=read(home/'package'/row['path']);need(len(b)==row['bytes'] and sha(b)==row['sha256'],'package source pin')
    return home,v
def execute(a):
    root();os.umask(0o077)
    if a.operation=='copy-input':
        need(re.fullmatch('[a-z0-9][a-z0-9-]{5,55}',a.label),'label')
        need(re.fullmatch('[0-9a-f]{64}',a.sha256) and type(a.bytes) is int and 0<=a.bytes<=32*1024*1024,'exact transferred file')
        allowed={a.label+'.tar.gz',a.label+'.stage.py',a.label+'.CLOSURE.json',a.label+'.INVENTORY.json'}
        allowed.update(a.label+'-'+p+'.witness.tar.gz' for p in ('setup','before-guard','after-guard'))
        need(a.name in allowed,'explicit one-case staging file')
        # The immutable 179a phone actor admits pushes only below this existing
        # transfer root. Copying into the new GNU namespace does not widen it.
        source=A/'data/local/tmp/hepta-phone-local-v150-r1'/('hepta-native-guard-'+a.name)
        b,m=read(source,32*1024*1024);need(len(b)==a.bytes and sha(b)==a.sha256,'actual pushed bytes')
        target=G/'native-guard-staging-r10-r1'
        try:s=target.lstat()
        except FileNotFoundError:
            target.mkdir(mode=0o700)
            for parent in (target,target.parent):
                fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
            s=target.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700,'private staging root')
        put(target/a.name,b)
        return {'state':'EXACT_INPUT_COPIED_CREATE_ONLY','source':str(source),'source_metadata':m,
            'target':descriptor(target/a.name,False,32*1024*1024),'effects':0}
    home,lease=context(a.label,a.lease_sha256)
    if a.operation=='phase-originals':
        need(a.phase in ('setup','before-guard','after-guard'),'phase')
        target=home/('ROOT-'+a.phase.upper()+'-PLAN.json');deadline=time.monotonic()+(60 if a.phase=='setup' else 25)
        while True:
            try:target.lstat();break
            except FileNotFoundError as e:need(e.errno==2,'plan read error')
            for name in ('LIFECYCLE-FAILURE.json','PROVIDER-ENDED.json','LIFECYCLE-ENDED.json'):
                try:(home/name).lstat()
                except FileNotFoundError:continue
                return {'state':'ORIGINAL_COMPONENT_ENDED_BEFORE_PHASE','phase':a.phase,'original':descriptor(home/name),'effects':0}
            need(time.monotonic()<deadline and time.time_ns()//1000000<lease['expires_unix_ms'],'one bounded original phase wait expired')
            time.sleep(.1)
        rows={name:descriptor(home/name) for name in ('ACCEPTED.json','BOUND-CONTRACT.json',target.name)}
        accepted=json.loads(base64.b64decode(rows['ACCEPTED.json']['base64']));bound=json.loads(base64.b64decode(rows['BOUND-CONTRACT.json']['base64']))
        plan=json.loads(base64.b64decode(rows[target.name]['base64']))
        need(plan['scope']==accepted['scope'] and plan['phase']==a.phase and plan['contract_sha256']==accepted['contract_sha256']
            and bound['lease_sha256']==a.lease_sha256,'actual accepted phase binding')
        return {'state':'ACTUAL_PHASE_ORIGINALS_READ','phase':a.phase,'scope':accepted['scope'],'files':rows,'effects':0}
    if a.operation=='role-end':
        deadline=time.monotonic()+30
        while True:
            try:(home/'LIFECYCLE-ENDED.json').lstat();break
            except FileNotFoundError as e:need(e.errno==2,'role end read error')
            need(time.monotonic()<deadline,'one bounded original role-end wait expired');time.sleep(.1)
        return {'state':'LIFECYCLE_END_ORIGINAL_READ','file':descriptor(home/'LIFECYCLE-ENDED.json'),'effects':0}
    if a.operation=='snapshot-chunk':
        path=G/'native-guard-snapshots-r10-r1'/(a.label+'-capture-01')/'ORIGINALS.tar.gz'
        b,m=read(path,64*1024*1024);need(len(b)==a.bytes and sha(b)==a.sha256,'actual snapshot archive')
        need(type(a.index) is int and 0<=a.index<(len(b)+524287)//524288,'chunk index')
        offset=a.index*524288;raw=b[offset:offset+524288]
        return {'state':'ORIGINAL_SNAPSHOT_CHUNK','archive_sha256':sha(b),'archive_bytes':len(b),'metadata':m,
            'index':a.index,'offset':offset,'bytes':len(raw),'sha256':sha(raw),'base64':base64.b64encode(raw).decode(),'effects':0}
    if a.operation=='boundary-original':
        return {'state':'ORIGINAL_LATE_BOUNDARY_READ','file':descriptor(G/'native-guard-boundaries-r10-r1'/(lease['nonce']+'.json')),'effects':0}
    raise ValueError('unreviewed bridge operation')
def main():
    p=argparse.ArgumentParser();p.add_argument('operation',choices=('copy-input','phase-originals','role-end','snapshot-chunk','boundary-original'))
    p.add_argument('--label',required=True);p.add_argument('--lease-sha256');p.add_argument('--phase');p.add_argument('--name')
    p.add_argument('--sha256');p.add_argument('--bytes',type=int);p.add_argument('--index',type=int)
    p.add_argument('--execute-root-bridge-once',action='store_true');a=p.parse_args()
    if not a.execute_root_bridge_once:print(json.dumps({'state':'PREVIEW_NO_PHONE_READ_OR_WRITE'}));return 0
    print(json.dumps(execute(a),sort_keys=True,separators=(',',':')));return 0
if __name__=='__main__':raise SystemExit(main())
