#!/usr/bin/env python3
"""Bind a provider to the actual model session after this boot's startup."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent / 'source'))
from model_slot_cleanup import admission_identity, get_json, private_bytes, require, verify_identity
from phone_local_http_worker import strict_json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--config-sha256', required=True)
    parser.add_argument('--model-claim', type=Path, required=True)
    parser.add_argument('--server-sha256', required=True)
    parser.add_argument('--server-domain', required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--require-image-cancel', action='store_true')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'model binding requires the existing root owner')
    for value in (args.config_sha256, args.server_sha256):
        require(re.fullmatch(r'[0-9a-f]{64}', value) is not None, 'expected SHA256 invalid')
    raw_config = private_bytes(args.config)
    require(hashlib.sha256(raw_config).hexdigest() == args.config_sha256, 'configuration changed')
    config = strict_json(raw_config)
    require(isinstance(config, dict), 'configuration object required')
    raw_claim = private_bytes(args.model_claim, 128)
    claim = raw_claim.decode('ascii').strip()
    require(re.fullmatch(r'[1-9][0-9]*(?::[1-9][0-9]*){3}', claim) is not None,
            'model claim identity malformed')
    pid, pgid, sid, start_ticks = map(int, claim.split(':'))
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(pid == pgid == sid, 'model claim is not an owned session')
    identity = {'schema': 'hepta.llama-server-identity.v1', 'boot_id': boot,
                'pid': pid, 'pgid': pgid, 'sid': sid, 'start_ticks': start_ticks}
    binding = {'schema': 'hepta.model-cleanup-binding.v1', 'server_identity': identity,
               'model_claim': str(args.model_claim),
               'model_claim_sha256': hashlib.sha256(raw_claim).hexdigest(),
               'server_binary_sha256': args.server_sha256, 'server_domain': args.server_domain,
               'endpoint': config['endpoint']}
    verify_identity(binding, hash_binary=True)
    directory = args.output_dir
    require(directory.is_absolute() and directory.resolve(strict=True) == directory,
            'binding directory must be canonical')
    info = directory.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and
            stat.S_IMODE(info.st_mode) == 0o700, 'binding directory ownership/mode differs')

    deadline = time.monotonic() + 5.0
    polls = 0
    observed = None
    while time.monotonic() < deadline and polls < 7:
        polls += 1
        slots, receipt = get_json(config, '/slots', min(deadline, time.monotonic() + .75))
        if (receipt.get('complete') is True and receipt.get('http_status') == 200 and
                receipt.get('error') is None and isinstance(slots, list) and len(slots) == 1 and
                isinstance(slots[0], dict) and slots[0].get('is_processing') is False):
            observed = {'observed': True, 'idle': True, 'slot': slots[0]}
            break
        time.sleep(min(.1, max(0.0, deadline - time.monotonic())))
    require(observed is not None, 'one idle receipt-capable model slot not observed')
    admission_identity(binding, config, observed)
    capabilities = observed['slot']['hepta_server'].get('cancel_safe_point', {})
    require(capabilities.get('cpu_decode_abort_callback_installed') is True and
            capabilities.get('compute_and_queue_handoff_required_before_release') is True,
            'CPU cancellation capability missing')
    if args.require_image_cancel:
        require(capabilities.get('image_encode_abort_callback_installed') is True,
                'CPU image cancellation capability missing')
    require(private_bytes(args.model_claim, 128) == raw_claim and
            private_bytes(args.config) == raw_config, 'startup inputs changed')
    verify_identity(binding, hash_binary=True)

    name = f'slot-cleanup-{boot}-{pid}-{start_ticks}.json'
    target = directory / name
    raw = (json.dumps(binding, sort_keys=True, separators=(',', ':')) + '\n').encode()
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        require(private_bytes(target) == raw, 'existing startup binding conflicts')
    else:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    require(private_bytes(target) == raw, 'startup binding readback differs')
    verify_identity(binding)
    print(json.dumps({'schema': 'hepta.model-startup-binding-result.v1', 'state': 'BOUND',
                      'path': str(target), 'sha256': hashlib.sha256(raw).hexdigest(),
                      'server_identity': identity, 'capabilities': capabilities,
                      'read_only_gets': polls, 'model_requests': 0, 'phone_actions': 0}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'Binding refused: {type(error).__name__}: {error}', file=sys.stderr)
        raise SystemExit(2)
