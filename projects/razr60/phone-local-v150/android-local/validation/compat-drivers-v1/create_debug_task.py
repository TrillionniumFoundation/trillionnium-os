#!/usr/bin/env python3
"""Prepare a one-use request file. This script never contacts a phone or executes actions."""
import argparse, hashlib, json, os, secrets, time
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('--instruction',required=True)
p.add_argument('--output',type=Path,required=True)
p.add_argument('--now-ms',type=int,default=None)
a=p.parse_args()
if not a.instruction.strip() or len(a.instruction.encode('utf-8'))>1600 or any(s in a.instruction for s in ['\0','<|','<__image__>']):
    p.error('instruction must be nonempty, at most 1600 UTF-8 bytes, and contain no reserved control markers')
nonce=secrets.token_hex(32);now=a.now_ms if a.now_ms is not None else int(time.time()*1000)
record={'schema':'hepta.private-debug-task.v1','nonce':nonce,'instruction':a.instruction,'created_wall_ms':now,'expires_wall_ms':now+600000}
with os.fdopen(os.open(a.output,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb') as out:
    out.write((json.dumps(record,ensure_ascii=False,indent=2)+'\n').encode('utf-8'));out.flush();os.fsync(out.fileno())
print(json.dumps({'path':str(a.output),'nonce':nonce,'nonce_sha256':hashlib.sha256(nonce.encode()).hexdigest(),'expires_wall_ms':record['expires_wall_ms']},indent=2))
