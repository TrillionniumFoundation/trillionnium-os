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
                                 request_hash, require, private_json, app_scope_hash)


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
    parser.add_argument('--template-schema',
                        choices=['hepta.task-template.v149.1', 'hepta.task-template.v150.2',
                                 'hepta.task-template.v150.3'],
                        default='hepta.task-template.v149.1')
    parser.add_argument('--app-scope-file', type=Path,
                        help='Private exact request-bound app subset; required only for v150.3')
    args = parser.parse_args()
    state = args.state.absolute()
    private_directory(state)
    raw = args.request_file.read_bytes()
    require(0 < len(raw) <= 512*1024 and b'\0' not in raw, 'request file size or text differs')
    request = raw.decode('utf-8', errors='strict')
    require(request.count(args.nonce) == 1, 'fresh nonce must occur exactly once in the request')
    conditions = json.loads(args.postconditions_file.read_bytes())
    template = {'schema': args.template_schema,
                'expected_scope': {'session_id': args.session_id, 'profile_id': args.profile_id},
                'request_sha256': request_hash(request), 'nonce': args.nonce,
                'postconditions': conditions, 'coverage': args.coverage}
    scoped = args.template_schema == 'hepta.task-template.v150.3'
    require(scoped == (args.app_scope_file is not None),
            'v150.3 requires an explicit app scope; legacy versions cannot acquire one')
    if scoped:
        selected = private_json(args.app_scope_file.absolute())
        require(selected is not None, 'app scope file absent')
        template['app_scope'] = selected[0]
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
                      'app_scope_sha256': app_scope_hash(template['app_scope']) if scoped else None,
                      'phone_operations': 0, 'model_operations': 0}, ensure_ascii=False))


if __name__ == '__main__':
    main()
