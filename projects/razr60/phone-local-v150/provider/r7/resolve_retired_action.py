#!/usr/bin/env python3
"""Explicit one-case additive retirement resolution. No sockets or effects.

Run only after Root independently reviews original evidence and the frozen
offline verifier binds that review into the pinned final proof. Old native
failure, owner request claim, client claim/result and action intent remain intact.
"""
import argparse
import hashlib
import fcntl
import os
import stat
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent/'source'))
from provider_phone_local import load_local_config
from action_ledger import ActionLedger
from retirement_recovery import (ACTION_ID, EXECUTOR_BINDING, PROOF_SHA256, read_private_proof, validate_proof)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--state', type=Path, required=True)
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--action-id', required=True)
    p.add_argument('--proof', type=Path, required=True)
    p.add_argument('--proof-sha256', required=True)
    p.add_argument('--check-only', action='store_true')
    args = p.parse_args()
    if args.action_id != ACTION_ID or args.proof_sha256 != PROOF_SHA256:
        raise RuntimeError('only the frozen original action and final proof may be resolved')
    config, _digest = load_local_config(args.config)
    if (config['executor']['mode'] != 'phone_local_sidecar'
            or config['executor']['client_path'] != EXECUTOR_BINDING['client_path']
            or config['executor']['client_sha256'] != EXECUTOR_BINDING['client_sha256']):
        raise RuntimeError('future executor binding differs')
    raw = read_private_proof(args.proof)
    if hashlib.sha256(raw).hexdigest() != args.proof_sha256:
        raise RuntimeError('retirement proof raw bytes differ')
    expected_state = Path('/var/lib/trillionnium/owner-open/phone-local-v150/provider-state')
    if args.state != expected_state or args.state.resolve(strict=True) != args.state:
        raise RuntimeError('only the original canonical provider state may be resolved')
    # The resident provider holds this same lock for its whole lifetime.
    # Open the existing file only; never create a substitute admission lock.
    lock = os.open(args.state/'daemon.lock', os.O_RDWR | os.O_NOFOLLOW)
    try:
        info = os.fstat(lock)
        if not (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1):
            raise RuntimeError('original provider daemon lock identity differs')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        ledger = ActionLedger(args.state/'evidence', args.state/'evidence')
        with ledger.exclusive():
            if args.check_only:
                rows = ledger.intents()
                selected = [(value, digest, resolved) for value, digest, resolved in rows
                            if value['action_id'] == args.action_id]
                if (len(selected) != 1 or selected[0][2] is not None
                        or any(value['action_id'] != args.action_id and resolved is None
                               for value, _digest, resolved in rows)):
                    raise RuntimeError('only the one original unresolved action may be reviewed')
                validate_proof(raw, selected[0][0], selected[0][1])
                state, written = 'VALIDATED_FOR_EXPLICIT_RESOLUTION', False
            else:
                resolution = ledger.resolve_retired(args.action_id, raw, EXECUTOR_BINDING)
                state, written = resolution['state'], True
    finally:
        os.close(lock)
    print(json.dumps({'action_id': args.action_id, 'state': state,
                      'retirement_proof_sha256': PROOF_SHA256, 'resolution_written': written,
                      'effects_dispatched': 0, 'executor_inspection_requests': 0,
                      'original_native_task_remains_failed': True, 'original_claims_retained': True,
                      'old_effect_replay_forbidden': True, 'business_verified': False,
                      'future_executor_binding': EXECUTOR_BINDING}, indent=2))
if __name__ == '__main__':
    main()
