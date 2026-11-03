"""Restricted, observation-bound additions for a phone-local GUI model.

The model never supplies executable shell. Original v149 typed screenshot,
tap, Unicode, public text and return mappings are inherited unchanged.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import xml.etree.ElementTree as ET

from provider_openai_compatible import ProviderError
from retirement_recovery import EXECUTOR_BINDING
from phone_observation_tools import (PhoneTools, SERIAL, PHYSICAL_DISPLAY,
                                    strict_json, native_streams, validate_viewport, sha)
from phone_task_guards import (page_capture, b64_variable, page_state, component,
                               decode_text, public_text_command, verify_public_text)

COMPONENT_RE = re.compile(r'[A-Za-z][A-Za-z0-9_.$]*/(?:\.)?[A-Za-z][A-Za-z0-9_.$]*\Z')
PACKAGE_RE = re.compile(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+\Z')


def require(ok, message):
    if not ok:
        raise ProviderError('[phone_local_tool] ' + message)


def current_viewport_guard():
    """Shell precondition, limited to the same exact v149-qualified geometry."""
    command = "hepta_local_vp=$(dumpsys display | grep 'mViewports='); "
    command += """hepta_local_active=$(printf '%s' "$hepta_local_vp" | grep -o 'DisplayViewport{[^{}]*}' | grep 'isActive=true'); """
    command += """[ "$(printf '%s\n' "$hepta_local_active" | wc -l | tr -d '[:space:]')" = 1 ] || exit 68; """
    for field in ['type=INTERNAL,', 'valid=true,', 'isActive=true,', 'displayId=0,',
                  "uniqueId='local:" + PHYSICAL_DISPLAY + "',", 'orientation=0,',
                  'logicalFrame=Rect(0, 0 - 1224, 2992),',
                  'physicalFrame=Rect(0, 0 - 1224, 2992)']:
        command += 'printf \'%s\' "$hepta_local_active" | grep -F -- ' + shlex.quote(field) + ' >/dev/null || exit 68; '
    command += page_capture('hepta_local_initial_page')
    command += """printf '%s' "$hepta_local_initial_page" | grep -q 'isKeyguardShowing=true' && exit 70; """
    return command


def validate_apps(apps):
    require(isinstance(apps, dict) and 1 <= len(apps) <= 64, 'bounded approved app registry required')
    for alias, value in apps.items():
        require(isinstance(alias, str) and 0 < len(alias.encode()) <= 128 and '\0' not in alias,
                'app alias malformed')
        require(isinstance(value, dict) and set(value) == {'component', 'label'}
                and isinstance(value['component'], str)
                and COMPONENT_RE.fullmatch(value['component'])
                and isinstance(value['label'], str) and 0 < len(value['label'].encode()) <= 128,
                'approved component or label malformed')
    return apps


def validate_executor(executor, *, verify_files=True):
    require(isinstance(executor, dict), 'executor configuration absent')
    require(executor.get('mode') == 'phone_local_sidecar'
            and set(executor) == {'mode', 'python', 'client_path', 'client_sha256', 'timeout_ms'}
            and executor['python'] == '/usr/bin/python3'
            and executor['client_path'] == EXECUTOR_BINDING['client_path']
            and executor['client_sha256'] == EXECUTOR_BINDING['client_sha256']
            and type(executor['timeout_ms']) is int and 1 <= executor['timeout_ms'] <= 60000,
            'phone-local executor configuration differs')
    if verify_files:
        path = Path(executor['client_path'])
        require(path.is_file() and not path.is_symlink()
                and sha(path.read_bytes()) == executor['client_sha256'],
                'phone-local tool client byte pin differs')
    return executor


class PhoneLocalTools(PhoneTools):
    def __init__(self, run_dir, atomic_record, apps, executor):
        super().__init__(run_dir, atomic_record)
        self.apps = validate_apps(apps)
        self.executor = validate_executor(executor)
        self.allowed_packages = {v['component'].split('/')[0] for v in apps.values()}
        self.local_observations = {}

    def _wire_call(self, call_id, shell):
        if self.executor['mode'] == 'adb_legacy':
            return super()._wire_call(call_id, shell)
        validate_executor(self.executor)
        action_id = self._token(call_id)
        argv = [self.executor['python'], self.executor['client_path'], 'execute',
                '--action-id', action_id,
                '--command-b64', base64.b64encode(shell.encode()).decode(),
                '--timeout-ms', str(self.executor['timeout_ms'])]
        return {'call_id': call_id, 'tool': 'shell.exec', 'argv': argv}

    def map(self, decision):
        tool = decision['tool']
        if tool not in {'phone.open_app', 'phone.observe'}:
            return super().map(decision)
        call_id = decision['call_id']
        token = self._token(call_id)
        args, command = decision['argv'], decision['command']
        require(command == '' and len(args) == 1, 'open_app/observe needs one alias/package and empty command')
        record = {'semantic_tool': tool, 'call_id': call_id, 'capture_id': token,
                  'turn': self.binding, 'state': 'model_decision_mapped_not_dispatch_confirmation'}
        if tool == 'phone.open_app':
            require(args[0] in self.apps, 'app is absent from reviewed installed-app registry')
            target = self.apps[args[0]]['component']
            require(target.split('/')[0] != 'org.trillionnium.owneropen',
                    'HEPTA return must use typed phone.return_hepta')
            shell = self._serial_guard() + current_viewport_guard()
            shell += 'hepta_launch=$(am start --display 0 -W -n ' + shlex.quote(target) + ' 2>&1); hepta_launch_rc=$?; '
            shell += page_capture('hepta_open_page')
            shell += "hepta_open_viewport=$(dumpsys display | grep 'mViewports='); "
            for source, dest in [('hepta_launch', 'hepta_launch_b64'),
                                 ('hepta_open_page', 'hepta_page_b64'),
                                 ('hepta_open_viewport', 'hepta_viewport_b64')]:
                shell += b64_variable(source, dest)
            template = ('{"schema":"hepta.local-app-open.v150.1","operation_id":"' + token
                        + '","launch_exit_code":%s,"launch_b64":"%s","page_b64":"%s","viewport_b64":"%s"}\n')
            shell += 'printf ' + shlex.quote(template) + ' "$hepta_launch_rc" "$hepta_launch_b64" "$hepta_page_b64" "$hepta_viewport_b64"; exit "$hepta_launch_rc"'
            record.update(alias=args[0], component=target, package=target.split('/')[0])
        else:
            package = args[0]
            require(isinstance(package, str) and PACKAGE_RE.fullmatch(package)
                    and package in self.allowed_packages
                    and package != 'org.trillionnium.owneropen',
                    'observe requires one approved foreground app package')
            for condition in self.visual_read_constraints:
                if condition['package'] == package:
                    require(any(fact['kind'] == 'visual_tap_executed' and fact['package'] == package
                                for fact in self.verified_facts.values()),
                            'visual contract prohibits pre-tap hierarchy observation')
            path = '/data/local/tmp/hepta-local-observe-' + token + '.xml'
            shell = public_text_command(self._serial_guard(), token, package, path)
            record.update(package=package, source_xml_path=path)
        self.invalidate()
        wire = self._wire_call(call_id, shell)
        record['wire_tool'] = wire['tool']
        record['wire_call'] = wire
        self.atomic_record(self.run_dir / ('semantic-' + sha(call_id.encode()) + '.json'), record)
        self.calls[call_id] = record
        return wire['argv']

    def prepare(self, messages, rendered, round_number):
        output, paths = super().prepare(messages, rendered, round_number)
        updated = []
        for original, projected in zip(messages, output):
            call_id = original.get('tool_call_id')
            call = self.calls.get(call_id)
            if original.get('role') != 'tool' or not call or call['semantic_tool'] not in {'phone.open_app', 'phone.observe'}:
                updated.append(projected)
                continue
            actual = strict_json(original['content'])
            value = strict_json(native_streams(actual, call_id, call.get('wire_tool', 'adb.exec')))
            token = call['capture_id']
            if call['semantic_tool'] == 'phone.open_app':
                require(isinstance(value, dict) and set(value) == {'schema', 'operation_id', 'launch_exit_code',
                        'launch_b64', 'page_b64', 'viewport_b64'}
                        and value['schema'] == 'hepta.local-app-open.v150.1'
                        and value['operation_id'] == token and type(value['launch_exit_code']) is int
                        and value['launch_exit_code'] == 0, 'app launch receipt differs')
                launch = decode_text(value['launch_b64'], 'app launch receipt', 8192)
                require(re.findall(r'^Status:\s*(\S+)\s*$', launch, re.MULTILINE) == ['ok']
                        and not re.search(r'^\s*(?:Error|Exception|SecurityException)\b', launch, re.MULTILINE),
                        'app launch failed')
                activities = re.findall(r'^Activity:\s*(\S+)\s*$', launch, re.MULTILINE)
                require(len(activities) == 1 and component(activities[0]) == component(call['component']),
                        'launch reported another component')
                observed = page_state(decode_text(value['page_b64'], 'app foreground'))
                require(observed['component'] == component(call['component']), 'launched app is not actual foreground')
                validate_viewport(decode_text(value['viewport_b64'], 'app viewport'))
                fact = {'kind': 'app_open_verified', 'call_id': call_id, 'package': call['package'],
                        'component': observed['component'], 'display_id': 0}
            else:
                observed, viewport = verify_public_text(value, token, call['package'], [])
                validate_viewport(viewport)
                root = ET.fromstring(decode_text(value['xml_b64'], 'public UI hierarchy', 196608))
                nodes = []
                for node in root.iter('node'):
                    if node.get('package') != call['package'] or node.get('visible-to-user', 'true') != 'true':
                        continue
                    if node.get('password') == 'true':
                        nodes.append({'class': node.get('class'), 'password': True,
                                      'content_redacted': True})
                        continue
                    fields = {key: node.get(key, '') for key in ['resource-id', 'class', 'text', 'content-desc',
                              'enabled', 'focused', 'focusable', 'clickable', 'long-clickable', 'scrollable', 'bounds']}
                    nodes.append(fields)
                require(len(nodes) <= 96 and len(json.dumps(nodes, ensure_ascii=False).encode()) <= 24576,
                        'complete public UI observation exceeds local model bound; no targets silently omitted')
                fact = {'kind': 'public_ui_observation', 'call_id': call_id, **observed,
                        'nodes': nodes, 'original_result_sha256': sha(original['content'].encode())}
            self.local_observations[call_id] = fact
            reply = strict_json(projected['content'])
            reply['_hepta_verified_local_observation'] = fact
            updated.append({**projected, 'content': json.dumps(reply, ensure_ascii=False, separators=(',', ':'))})
        return updated, paths
