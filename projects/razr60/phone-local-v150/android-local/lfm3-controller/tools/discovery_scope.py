"""Strictly reverse the separately reviewed discovery delta for prior scope gates.

Both whole controller hashes and every exact before/after hunk are pinned. This
does not exempt discovery code from review: it keeps the existing deadline-only
reconstruction check valid after layering this independent change.
"""
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def restore_discovery_base(source):
    delta=json.loads((ROOT/'tests/app-discovery/controller-delta.json').read_text())
    if hashlib.sha256(source.encode()).hexdigest()!=delta['candidate_sha256']:
        raise AssertionError('controller differs from reviewed discovery delta')
    for row in delta['hunks']:
        if not row['after'] or source.count(row['after'])!=1:
            raise AssertionError('discovery hunk must match exactly once')
        source=source.replace(row['after'],row['before'],1)
    if hashlib.sha256(source.encode()).hexdigest()!=delta['baseline_sha256']:
        raise AssertionError('discovery reverse does not recover exact baseline')
    return source
