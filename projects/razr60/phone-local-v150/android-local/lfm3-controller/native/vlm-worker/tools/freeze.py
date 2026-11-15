#!/usr/bin/env python3
from pathlib import Path
import hashlib,json,re
root=Path(__file__).resolve().parents[1]
code=(root/'native/vlm-worker.cpp').read_text()
section=code.split('const Pin runtime_pins[] = {',1)[1].split('\n};',1)[0]
runtime=[{'name':name,'bytes':int(size),'sha256':sha} for name,size,sha in re.findall(r'\{"([^"\n]+)",(\d+),"([a-f0-9]{64})"\}',section)]
assert len(runtime)==10
files=[]
for sub in ['native','vendor','tools']:
    for p in sorted((root/sub).rglob('*')):
        if p.is_file() and '__pycache__' not in p.parts:
            b=p.read_bytes();files.append({'path':str(p.relative_to(root)),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
data={'schema':'hepta.vlm.source.v1','llama_source_commit':'19cce6919992fdffd92e0ac152caaf1e2b8f254e',
      'geniex_source_commit':'071f609995470bdb0e0769ab964754adfaab7e47','files':files,'runtime':runtime,
      'actions_dispatched':False,'phone_contacted':False}
(root/'SOURCE.json').write_text(json.dumps(data,indent=2)+'\n')
print(json.dumps({'files':len(files),'source_manifest_sha256':hashlib.sha256((root/'SOURCE.json').read_bytes()).hexdigest()}))
