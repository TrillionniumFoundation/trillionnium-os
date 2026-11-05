#!/usr/bin/env python3
"""Read-only full recomputation of the fixed two-attempt admission on Mac."""
import hashlib
import json
import os
from pathlib import Path
import stat
import types
V = {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/root-fixed19-1ad3-20261105-r1/failed-prelaunch-admission01/source/verify_failed_prelaunch.py', 'bytes': 54893, 'sha256': 'e78defb9c9be3e6cf6a6d3f0616309beef920fa9be87ab594fb36db57b921975'}
A = {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/root-fixed19-1ad3-20261105-r1/failed-prelaunch-admission01/FAILED-PRELAUNCH-ADMISSION.json', 'bytes': 66905, 'sha256': 'e85b3bfed5e4720fdcebca8783c6735a9601d73d903066c6de61917e001bf130'}
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
p=Path(V['path'])
assert p.resolve(strict=True)==p
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
    before=os.fstat(fd)
    assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==V['bytes']
    with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(V['bytes']+1)
    meta=lambda s:tuple(getattr(s,key) for key in META)
    assert meta(before)==meta(os.fstat(fd))==meta(p.lstat())
    assert len(raw)==V['bytes'] and hashlib.sha256(raw).hexdigest()==V['sha256']
finally:os.close(fd)
module=types.ModuleType('reviewed_failed_prelaunch_admission_verify_only')
module.__file__=V['path']
module.__reviewed_source_sha256__=V['sha256']
exec(compile(raw,V['path'],'exec'),module.__dict__)
value=module.strict(module.local_read(A))
summary=module.verify_failed_prelaunch_admission(value,read_pinned=module.local_read)
assert module.local_read(V)==raw
print(json.dumps({'state':'FULL_ACTUAL_FAILED_PRELAUNCH_ADMISSION_RECOMPUTED_FROM_MAC_ORIGINALS',
    'verifier_source':V,'admission_original':A,'verification':summary,
    'original_descriptors_read':len(value['verification_originals']),
    'read_only':True,'phone_calls':0,'newcase_or_nonce_created':False},sort_keys=True))
