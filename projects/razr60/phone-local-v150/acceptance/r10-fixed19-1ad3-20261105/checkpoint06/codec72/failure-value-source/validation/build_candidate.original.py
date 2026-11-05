#!/usr/bin/env python3
"""Create the fixed local source candidate and three controlled host-shell checks."""
import ast
import datetime
import difflib
import hashlib
import json
from pathlib import Path
import shlex
import subprocess

W = Path('/workspace/scratch/1ad3d6f55439')
OUT = W / 'codec72_failure_value_candidate01'
PLAN = W / 'transport_fix/codec72-source-diagnostic-plan01/DIAGNOSTIC-PLAN.json'
PROD = W / 'current_production_source_cache/phone_observation_tools.py'
PRIVATE = W / 'actual_external_902e_7c907661_01/private-read01/phone-private-originals/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01'
RUNTIME = W / 'runtime_prefix_successor_candidate01/delivery-final01/package/runtime'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enc(obj):
    return (json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


def pin(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def put(name, raw):
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
    assert path.read_bytes() == raw
    return pin(path)


def definitions(raw):
    lines = raw.splitlines(keepends=True)
    result = {}
    for node in ast.parse(raw).body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            if isinstance(node, ast.ClassDef):
                for child in node.body:
                    if isinstance(child, ast.FunctionDef):
                        result[node.name + '.' + child.name] = b''.join(lines[child.lineno - 1:child.end_lineno])
            else:
                result[node.name] = b''.join(lines[node.lineno - 1:node.end_lineno])
    return result


plan_raw = PLAN.read_bytes()
assert sha(plan_raw) == '536977a355032617da5cf857fcd9b9c54f7281c89494064df025c4441e6905d1'
plan = json.loads(plan_raw)
original = PROD.read_bytes()
assert len(original) == 38774 and sha(original) == 'f16c77c1b4509babcea5fc2e8d0a7ae8ab43b3cd58e6640441b44ecd4bccb6df'
before = plan['minimal_candidate']['only_changed_source_literal_before']
after = plan['minimal_candidate']['only_changed_source_literal_after']
assert original.decode().count(before) == 1
candidate = original.decode().replace(before, after).encode()
assert candidate.decode().replace(after, before).encode() == original
assert len(candidate) == plan['minimal_candidate']['derived_bytes']
assert sha(candidate) == plan['minimal_candidate']['derived_sha256']
ast.parse(candidate)
old_defs, new_defs = definitions(original), definitions(candidate)
assert set(old_defs) == set(new_defs)
assert [name for name in old_defs if old_defs[name] != new_defs[name]] == ['PhoneTools.map']
original_command_path = Path(plan['evidence']['actual_capture_command']['path'])
original_command = original_command_path.read_bytes()
assert len(original_command) == 2226 and sha(original_command) == 'a2e8147c79186d5255599bad42ddab99311b4b155415d567594bfb44deea3a17'
old_tail, new_tail = ast.literal_eval(before), ast.literal_eval(after)
assert original_command.decode().count(old_tail) == 1
proposed_command = original_command.decode().replace(old_tail, new_tail).encode()
assert proposed_command.decode().replace(new_tail, old_tail).encode() == original_command
prefix, success_suffix = original_command.decode().split(old_tail)
assert prefix.count('hepta_codec=$(') == 1
old_success_source = original.decode().split(before, 1)[1]
assert candidate.decode().split(after, 1)[1] == old_success_source

OUT.mkdir(mode=0o700)
source_pin = put('source/phone_observation_tools.py', candidate)
reference_pin = put('reference/phone_observation_tools.f16c.original.py', original)
put('reference/capture.a2e814.original-command.txt', original_command)
put('reference/DIAGNOSTIC-PLAN.original.json', plan_raw)
patch = ''.join(difflib.unified_diff(original.decode().splitlines(keepends=True), candidate.decode().splitlines(keepends=True),
                                    fromfile='reference/phone_observation_tools.f16c.original.py', tofile='source/phone_observation_tools.py'))
put('validation/FAILURE-OUTPUT-INCREMENT.patch', patch.encode())
put('validation/PROPOSED-COMMAND-NOT-EXECUTED.txt', proposed_command)
put('validation/build_candidate.original.py', Path(__file__).read_bytes())

# These scripts execute only local shell builtins with fixed synthetic bytes.
# The phone-command prefix (getprop/dumpsys/screencap/app_process) is never run.
cases = [
    ('success_same_envelope', 0, b'{"schema":"host-only-control","status":"encoded"}\n', b''),
    ('failure20_trailing_lf_and_literal_metacharacters', 20,
     b'{"status":"rejected","reason":"host_control","literal":"$(printf UNEXPECTED)"}\n\n\n',
     b'original codec stderr\n'),
    ('failure22_empty_stdout_and_unterminated_stderr', 22, b'', b'original runtime stderr without LF'),
]
checks = []
for name, code, java_stdout, java_stderr in cases:
    synthetic_codec = 'printf %s ' + shlex.quote(java_stdout.decode()) + '; printf %s ' + shlex.quote(java_stderr.decode()) + ' >&2; exit ' + str(code)
    outcomes = {}
    for version, tail in [('original', old_tail), ('candidate', new_tail)]:
        script = "hepta_page_before_b64=SE9TVF9PTkxZ; hepta_page_after_b64=SE9TVF9PTkxZ; hepta_codec=$(" + synthetic_codec + tail + success_suffix
        script_pin = put('validation/host-shell/' + name + '/' + version + '.sh', script.encode())
        result = subprocess.run(['/bin/sh', '-c', script], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=False)
        stdout_pin = put('validation/host-shell/' + name + '/' + version + '.stdout.original', result.stdout)
        stderr_pin = put('validation/host-shell/' + name + '/' + version + '.stderr.original', result.stderr)
        outcomes[version] = {'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr,
                             'script': script_pin, 'stdout_pin': stdout_pin, 'stderr_pin': stderr_pin}
    old_result, new_result = outcomes['original'], outcomes['candidate']
    if code == 0:
        assert (old_result['returncode'], old_result['stdout'], old_result['stderr']) == (new_result['returncode'], new_result['stdout'], new_result['stderr'])
        assert new_result['returncode'] == 0 and b'codec-failure-observation' not in new_result['stderr']
        diagnostic = None
    else:
        assert old_result['returncode'] == new_result['returncode'] == 72
        assert old_result['stdout'] == b'' and old_result['stderr'] == java_stderr
        assert new_result['stdout'] == java_stdout.rstrip(b'\n')
        assert new_result['stderr'].startswith(java_stderr + b'\n')
        diagnostic = json.loads(new_result['stderr'][len(java_stderr) + 1:])
        assert diagnostic == {'schema': 'hepta.codec-failure-observation.v1', 'codec_exit_code': code,
                              'codec_stdout_representation': 'posix_shell_command_substitution_value',
                              'java_stdout_exact': False, 'stderr_has_appended_diagnostic_record': True}
        assert new_result['stderr'].endswith(b'\n')
    checks.append({'case': name, 'passed': True, 'host_only': True, 'codec_stub_exit_code': code,
                   'input_stdout': {'bytes': len(java_stdout), 'sha256': sha(java_stdout)},
                   'input_stderr': {'bytes': len(java_stderr), 'sha256': sha(java_stderr)},
                   'diagnostic_metadata': diagnostic,
                   'outcomes': {key: {k: v for k, v in row.items() if k not in ('stdout', 'stderr')} for key, row in outcomes.items()}})

assert PROD.read_bytes() == original and original_command_path.read_bytes() == original_command
put('validation/HOST-SHELL-CHECKS.json', enc({'schema': 'hepta.codec72.host-shell-semantics-checks.v1',
    'state': 'THREE_CONTROLLED_HOST_SHELL_CHECKS_PASSED', 'checks': checks,
    'actual_subprocesses': 6, 'native_or_android_processes': 0, 'target_module_imports': 0,
    'phone_calls': 0, 'production_changed': False, 'case_pass': False,
    'scope': 'Exact changed shell literal plus original success suffix; phone prefix was never executed. This does not test Android mksh, SELinux, codec, fresh capture, native authorization, or stream limits.'}))
put('DERIVATION.json', enc({'schema': 'hepta.codec72.failure-value-source-derivation.v1',
    'state': 'SOURCE_ONLY_UNSTAGED_NOT_ADMITTED', 'original': reference_pin, 'candidate': source_pin,
    'original_external_path': str(PROD), 'one_source_literal_changed': True,
    'whole_byte_inverse': True, 'only_changed_function': 'PhoneTools.map',
    'other_function_count_byte_identical': len(old_defs) - 1,
    'source_suffix_including_success_envelope_byte_identical': True,
    'actual_command_prefix_and_success_suffix_byte_identical': True,
    'proposed_actual_command_executed': False,
    'stdio_identity': {'stdout': 'shell-captured variable value, no added LF; original command substitution already removed trailing LF',
                       'stderr': 'original stream prefix plus a fixed-schema diagnostic record',
                       'java_stdout_exact': False, 'native_exit_on_codec_failure': 72},
    'future_native_action': None, 'future_nonce': None, 'future_lease': None,
    'new_runtime_or_production_admission': False, 'phone_calls': 0, 'production_changed': False,
    'existing_nonce_or_action_replayed': False, 'case_pass': False}))
print(json.dumps({'candidate_root': str(OUT), 'source': source_pin, 'reference': reference_pin,
                  'controlled_host_checks': 3, 'production_changed': False, 'phone_calls': 0}, indent=2))
