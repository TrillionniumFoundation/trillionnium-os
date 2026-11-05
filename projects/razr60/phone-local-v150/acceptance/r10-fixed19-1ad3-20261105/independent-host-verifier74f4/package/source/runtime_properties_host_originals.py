#!/usr/bin/env python3
"""Stable host originals and create-only files; no device or subprocess APIs."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import types

VERIFIER_SHA256 = '74f4c89b32b36b074971b247de1951962b45384ef821330b94656d144e512152'
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')

def need(ok,message):
    if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
def metadata(s):return [getattr(s,k) for k in META]

class Originals:
    def __init__(self):self.seen={}
    def read(self,path,expected=None,maximum=32*1024*1024):
        p=Path(path);need(p.is_absolute() and p.resolve(strict=True)==p,'canonical host original required')
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=maximum,'bounded regular host original')
            with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(maximum+1)
            need(len(raw)==a.st_size and metadata(a)==metadata(os.fstat(fd))==metadata(p.lstat()),'host original changed')
        finally:os.close(fd)
        pin={'path':str(p),'bytes':len(raw),'sha256':sha(raw)}
        if expected is not None:need(pin['sha256']==expected,'explicit host original hash differs')
        prior=self.seen.get(str(p));row=(pin,metadata(a))
        need(prior is None or prior==row,'host original changed across reads');self.seen[str(p)]=row
        return raw
    def pinned(self,row):
        need(type(row) is dict and set(row)=={'path','bytes','sha256'} and type(row['bytes']) is int
            and 0<=row['bytes']<=32*1024*1024 and re.fullmatch('[0-9a-f]{64}',row['sha256']),
            'exact original descriptor required')
        raw=self.read(row['path'],row['sha256']);need(len(raw)==row['bytes'],'original size differs');return raw
    def descriptor(self,path,expected=None):
        self.read(path,expected);return self.seen[str(Path(path))][0]
    def recheck(self):
        for pin,meta in list(self.seen.values()):self.pinned(pin)

def verifier(originals):
    need(isinstance(VERIFIER_SHA256,str) and re.fullmatch('[0-9a-f]{64}',VERIFIER_SHA256),
        'actual reviewed runtime-property verifier is not frozen')
    path=Path(__file__).resolve().parent/'policy_runtime_properties_verifier.py'
    raw=originals.read(path,VERIFIER_SHA256,131072)
    module=types.ModuleType('reviewed_runtime_properties_host_verifier');module.__file__=str(path)
    module.__reviewed_source_sha256__=sha(raw);exec(compile(raw,str(path),'exec'),module.__dict__)
    return module

def put_new(path,raw):
    p=Path(path);need(p.is_absolute() and p.parent.resolve(strict=True)==p.parent,'new canonical host destination')
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    need(p.read_bytes()==raw,'create-only original readback differs')
    return {'path':str(p),'bytes':len(raw),'sha256':sha(raw)}
