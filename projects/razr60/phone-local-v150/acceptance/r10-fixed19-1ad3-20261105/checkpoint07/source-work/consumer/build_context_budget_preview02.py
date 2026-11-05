#!/usr/bin/env python3
"""Tighten owned reads and admission-time resource accounting, source only."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

BASE = Path('/workspace/scratch/1ad3d6f55439/epoch_consumer_candidate01')
SOURCE = BASE / 'context-budget-preview01'
TARGET = BASE / 'context-budget-preview02'

def need(ok, reason):
    if not ok:
        raise ValueError(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def once(raw, old, new):
    old, new = old.encode(), new.encode()
    need(raw.count(old) == 1, 'exact source splice differs: ' + old[:100].decode())
    return raw.replace(old, new)

def main():
    need(not TARGET.exists(), 'source candidate already exists')
    parent = json.loads((SOURCE / 'SOURCE-DELTA.json').read_bytes())
    rows = []
    for row in parent['files']:
        p = Path(row['path']); old = p.read_bytes()
        need(len(old) == row['bytes'] and sha(old) == row['sha256'], 'previous whole source differs')
        raw = old
        if p.name == 'release_boundaries.py':
            raw = once(raw,
                'fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)',
                'fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)')
            raw = once(raw,
                '    inputs = {}; originals = {}; observed = {}\n    for name, row in',
                "    inputs = {}; originals = {}; observed = {}; declared = {}\n    decoded_total = sum(file_descriptor(row)['bytes'] for row in (component_input, policy_input))\n    need(decoded_total <= MAX_BUNDLE, 'input originals exceed fixed shared decoded budget')\n    for name, row in")
            raw = once(raw,
                '        for source in descriptors(value):\n            body, identity = read_pinned(source)',
                "        for source in descriptors(value):\n            previous_size = declared.get(source['sha256'])\n            need(previous_size is None or previous_size == source['bytes'],\n                 'same original digest has different declared size')\n            if previous_size is None:\n                decoded_total += source['bytes']\n                need(decoded_total <= MAX_BUNDLE, 'originals exceed one shared decoded budget before reading')\n                declared[source['sha256']] = source['bytes']\n            body, identity = read_pinned(source)")
            raw = once(raw,
                '    """Read-only exact eight bytes/metadata and explicitly adopted policy."""\n    with component_modules',
                '    """Read-only exact eight bytes/metadata and explicitly adopted policy."""\n    need(checked_actual_context(state[\'actual_context\']) == \'phone\',\n         \'current external artifacts require actual phone context\')\n    with component_modules')
        elif p.name == 'make_component_boundary_inputs.py':
            raw = once(raw,
                "    observed = {}; bodies = {}\n\n    def collect(row):\n        raw, identity = h.read_pinned(row)",
                "    observed = {}; bodies = {}; declared = {}; decoded_total = 0\n\n    def collect(row):\n        nonlocal decoded_total\n        h.file_descriptor(row)\n        old_size = declared.get(row['sha256'])\n        need(old_size is None or old_size == row['bytes'], 'original digest declared with different sizes')\n        if old_size is None:\n            decoded_total += row['bytes']\n            need(decoded_total <= h.MAX_BUNDLE, 'complete constructor original pool exceeds fixed decoded budget')\n            declared[row['sha256']] = row['bytes']\n        raw, identity = h.read_pinned(row)")
        ast.parse(raw);compile(raw, '<source-only-' + p.name + '>', 'exec')
        old_lines, new_lines = old.splitlines(keepends=True), raw.splitlines(keepends=True)
        delta = []
        for tag,a,b,c,d in difflib.SequenceMatcher(a=old_lines,b=new_lines,autojunk=False).get_opcodes():
            if tag != 'equal':delta.append({'new_start_line':c,'new_end_line':d,'new_utf8':b''.join(new_lines[c:d]).decode(),'old_utf8':b''.join(old_lines[a:b]).decode()})
        inv = list(new_lines)
        for x in reversed(delta):
            a,b=x['new_start_line'],x['new_end_line'];need(b''.join(inv[a:b]).decode()==x['new_utf8'],'inverse new bytes differ');inv[a:b]=x['old_utf8'].encode().splitlines(keepends=True)
        need(b''.join(inv)==old,'whole source inverse differs')
        dest=TARGET/p.relative_to(SOURCE);dest.parent.mkdir(parents=True,exist_ok=True)
        with dest.open('xb') as f:f.write(raw)
        rows.append({'path':str(dest),'bytes':len(raw),'sha256':sha(raw),'parent':{k:row[k] for k in ('path','bytes','sha256')},'inverse':delta})
    out={'schema':'hepta.epoch.consumer-owned-read-budget-source-preview.v1','state':'SOURCE_ONLY_FULL_EPOCH_INTEGRATION_STILL_REQUIRED','files':rows,
        'all_previous_source_inverses_verified':True,'regular_file_type_checked_after_nonblocking_open':True,
        'constructor_and_bundle_pool_charged_before_new_original_read':True,'phone_context_required_for_live_artifact_reads':True,
        'phone_calls':0,'target_modules_executed':False,'case_credit':False,'runtime_generation_bound':False}
    with (TARGET/'SOURCE-DELTA.json').open('x') as f:json.dump(out,f,sort_keys=True,indent=2);f.write('\n')
    print(json.dumps({'state':out['state'],'files':[{k:r[k] for k in ('path','bytes','sha256')} for r in rows]},indent=2))

if __name__ == '__main__':main()
