#!/usr/bin/env python3
"""Register an operator-owned one-time task contract; no device/model access.

The exact UTF8 request file must include its fresh nonce once. Use the exact
same bytes in a new UI Send. Admission later binds the generated task/turn IDs.
No existing template or consumed binding is overwritten or removed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent/'source'))
from task_postconditions import (private_directory, validate_template, write_exclusive,
                                 request_hash, require)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--request-file', type=Path, required=True)
    parser.add_argument('--postconditions-file', type=Path, required=True)
    parser.add_argument('--session-id', required=True)
    parser.add_argument('--profile-id', required=True)
    parser.add_argument('--nonce', required=True)
    parser.add_argument('--coverage', choices=['entire_request', 'declared_postconditions_only'],
                        default='declared_postconditions_only')
    args = parser.parse_args()
    state = args.state.absolute()
    private_directory(state)
    raw = args.request_file.read_bytes()
    require(0 < len(raw) <= 512*1024 and b'\0' not in raw, 'request file size or text differs')
    request = raw.decode('utf-8', errors='strict')
    require(request.count(args.nonce) == 1, 'fresh nonce must occur exactly once in the request')
    conditions = json.loads(args.postconditions_file.read_bytes())
    template = {'schema': 'hepta.task-template.v149.1',
                'expected_scope': {'session_id': args.session_id, 'profile_id': args.profile_id},
                'request_sha256': request_hash(request), 'nonce': args.nonce,
                'postconditions': conditions, 'coverage': args.coverage}
    validate_template(template)
    contracts = state/'task-contracts'
    for directory in (contracts, contracts/'templates', contracts/'bindings'):
        directory.mkdir(mode=0o700, exist_ok=True)
        private_directory(directory)
    target = contracts/'templates'/(template['request_sha256']+'.json')
    require(not (contracts/'bindings'/target.name).exists(), 'request nonce already consumed')
    source_sha = write_exclusive(target, template)
    print(json.dumps({'status': 'registered_one_time_request_contract', 'path': str(target),
                      'template_sha256': source_sha, 'request_sha256': template['request_sha256'],
                      'phone_operations': 0, 'model_operations': 0}, ensure_ascii=False))


if __name__ == '__main__':
    main()
