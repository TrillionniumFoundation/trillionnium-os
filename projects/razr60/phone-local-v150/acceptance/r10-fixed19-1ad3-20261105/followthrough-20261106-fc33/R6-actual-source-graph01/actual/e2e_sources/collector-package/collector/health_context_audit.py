"""Rebuild the two-message, zero-tool health request from selected source bytes."""
import importlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

from native_journal_audit import strict_loads
from ledger_prefix_audit import exact, require, sha


def rebuild(snapshot, provider_source, seal, config, request, run, calls):
    require(calls == [], 'health context has native tool calls')
    require(not (run / 'ledger-prefix').exists(), 'health unexpectedly contains business ledger evidence')
    paths = sorted(run.glob('local-*.request.json'))
    require([p.name for p in paths] == ['local-01.request.json'], 'health must contain one original request')
    require(not list(run.glob('local-*.mapping.json')) and not list(run.glob('local-*.model-action.json')),
            'health unexpectedly contains a named-action projection')
    trusted = snapshot.out / 'health-parser-source'
    trusted.mkdir(mode=0o700)
    names = set()
    for row in seal['production_files']:
        relative = Path(row['path'])
        require(len(relative.parts) == 2 and relative.parts[0] == 'source' and relative.suffix == '.py',
                'health source path differs')
        require(relative.stem not in names, 'duplicate health source pin')
        raw = snapshot.read(Path(provider_source) / relative.name)
        require(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'health source bytes differ')
        fd = os.open(trusted / relative.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        names.add(relative.stem)
    require(not names.intersection(sys.modules), 'health parser requires a fresh source namespace')
    before = list(sys.path)
    sys.path.insert(0, str(trusted))
    sys.dont_write_bytecode = True
    try:
        provider = importlib.import_module('provider_phone_local')
        health = importlib.import_module('health_contracts')
        tasks = importlib.import_module('task_postconditions')
        owner = request.decode('utf-8', errors='strict')
        require(owner and '\0' not in owner, 'health owner bytes are invalid')
        require(snapshot.json(run/'task-contract.json')=={'status':'no_trusted_contract','business_verified':False},
                'health cannot acquire a business contract or app-scoped contract')
        _apps,resolved_scope=tasks.resolve_task_apps(None,sha(request),config['approved_apps'])
        require(exact(snapshot.json(run/'task-app-scope.json'),resolved_scope),
                'health legacy task app scope does not match the exact owner/registry')
        messages = [{'role': 'user', 'content': owner}]
        empty = SimpleNamespace(calls={}, verified_facts={}, local_observations={})
        schema = health.final_only_schema(provider.SCHEMA)
        expected = provider.compose_local_messages(messages, messages, empty, {}, [],
                    config['max_prompt_bytes'], decision_schema=schema, health_mode=True)
        expected_format = {'type': 'json_schema', 'json_schema': {
            'name': 'hepta_phone_decision', 'strict': True, 'schema': schema}}
        body = snapshot.json(paths[0])
        require(exact(body['messages'], expected) and exact(body['response_format'], expected_format),
                'health request is not the exact source-derived owner-only prompt and final-only grammar')
        require(len(expected) == 2 and expected[0]['role'] == 'system' and
                expected[1] == {'role': 'user', 'content': owner}, 'selected health source changed its reviewed layout')
        return {1: {'messages': expected, 'response_format': expected_format,
                    'health_no_tools': True, 'health_schema': schema,
                    'task_app_scope':resolved_scope,'request_bound_app_scope_verified':True,
                    'request_sha256': sha(snapshot.read(paths[0])),
                    'source_bound_health_prompt': True}}
    finally:
        sys.path[:] = before
        for name in names:
            module = sys.modules.get(name)
            if module is not None and Path(getattr(module, '__file__', '')).parent == trusted:
                sys.modules.pop(name, None)
