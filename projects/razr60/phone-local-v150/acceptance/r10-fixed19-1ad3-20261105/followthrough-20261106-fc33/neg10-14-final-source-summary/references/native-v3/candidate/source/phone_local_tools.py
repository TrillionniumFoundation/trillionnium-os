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
                                    strict_json, native_streams, native_bound_call, validate_viewport, sha)
from phone_task_guards import (page_capture, b64_variable, page_state, component,
                               decode_text, public_text_command, verify_public_text, app_open_command, verify_app_open)
from task_postconditions import resolve_task_apps

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
        self.task_apps = None
        self.resolved_task_app_scope = None
        self.durable_open_exclusions = frozenset()

    def configure_task_app_scope(self, contract, owner_request_sha256):
        """Bind one trusted request scope before any model or tool activity."""
        require(self.binding is not None and not self.calls
                and getattr(self, 'resolved_task_app_scope', None) is None,
                'task app scope must be configured once before any mapped action')
        if contract is not None:
            require(isinstance(contract, dict) and isinstance(contract.get('contract'), dict)
                    and contract['contract'].get('identity') == {
                        key: self.binding[key] for key in ('session_id', 'profile_id', 'task_id', 'turn_id')},
                    'task app scope contract belongs to another accepted turn')
        self.task_apps, self.resolved_task_app_scope = resolve_task_apps(
            contract, owner_request_sha256, validate_apps(self.apps))
        self.allowed_packages = {v['component'].split('/')[0] for v in self.task_apps.values()}
        self.durable_open_exclusions = frozenset()
        return self.resolved_task_app_scope

    def set_durable_open_exclusions(self, aliases):
        require(getattr(self, 'resolved_task_app_scope', None) is not None
                and isinstance(aliases, (list, tuple))
                and all(isinstance(alias, str) and alias in self.apps for alias in aliases),
                'durable open exclusions require the bound reviewed registry')
        updated = frozenset(aliases)
        require(self.durable_open_exclusions <= updated,
                'durable open exclusions cannot be removed during a turn')
        self.durable_open_exclusions = updated

    def has_explicit_app_scope(self):
        require(getattr(self, 'resolved_task_app_scope', None) is not None
                and isinstance(getattr(self, 'task_apps', None), dict) and self.task_apps,
                'trusted task app scope has not been configured')
        return self.resolved_task_app_scope['mode'] == 'request_bound_explicit_subset'

    def _wire_call(self, call_id, shell):
        if self.executor['mode'] == 'adb_legacy':
            return super()._wire_call(call_id, shell)
        validate_executor(self.executor)
        action_id = self._token(call_id)
        argv = [self.executor['python'], self.executor['client_path'], 'execute',
                '--action-id', action_id,
                '--command-b64', base64.b64encode(shell.encode()).decode(),
                '--timeout-ms', str(self.executor['timeout_ms'])]
        return native_bound_call({'call_id': call_id, 'tool': 'shell.exec', 'argv': argv}, self.binding)

    def _focus_input_precondition(self):
        return current_viewport_guard()

    def map(self, decision):
        tool = decision['tool']
        scoped = self.has_explicit_app_scope()
        if tool in {'phone.focus_input_text', 'phone.read_text_anchor'} or (scoped and tool in {
                'phone.observe', 'phone.input_text', 'phone.read_text'}):
            args = decision['argv']
            require(args and args[0] in self.allowed_packages and args[0] != 'org.trillionnium.owneropen',
                    'typed capability requires a package allowed by this task scope')
        if scoped and tool == 'phone.tap':
            require(self.latest is not None
                    and self.latest.get('observed_page', {}).get('component', '').split('/')[0]
                    in self.allowed_packages,
                    'capture-bound tap is outside the task app package scope')
        if tool == 'phone.focus_input_text':
            require(len(args) == 3, 'focus input requires exact observed editor and old text')
            observations = [v for v in self.local_observations.values()
                            if v.get('kind') == 'public_ui_observation' and v.get('package') == args[0]]
            require(observations, 'focus input requires an original verified public UI observation')
            nodes = [n for n in observations[-1]['nodes'] if n.get('resource-id') == args[1]]
            require(len(nodes) == 1 and nodes[0].get('enabled') == 'true'
                    and nodes[0].get('focusable') == 'true' and nodes[0].get('text') == args[2],
                    'focus input target or old text differs from the last verified public observation')
        if tool not in {'phone.open_app', 'phone.observe'}:
            return super().map(decision)
        call_id = decision['call_id']
        token = self._token(call_id)
        args, command = decision['argv'], decision['command']
        require(command == '' and len(args) == 1, 'open_app/observe needs one alias/package and empty command')
        record = {'semantic_tool': tool, 'call_id': call_id, 'capture_id': token,
                  'turn': self.binding, 'state': 'model_decision_mapped_not_dispatch_confirmation'}
        if tool == 'phone.open_app':
            require(args[0] in self.task_apps, 'app is absent from the request-bound reviewed subset')
            require(args[0] not in self.durable_open_exclusions,
                    'same-turn durable app launch intent cannot be repeated')
            target = self.task_apps[args[0]]['component']
            require(target.split('/')[0] != 'org.trillionnium.owneropen',
                    'HEPTA return must use typed phone.return_hepta')
            shell = app_open_command(self._serial_guard(), target, token, current_viewport_guard())
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
            value = strict_json(native_streams(actual, call_id, call.get('wire_tool', 'adb.exec'), expected_call=call['wire_call'], expected_scope=call['turn']))
            token = call['capture_id']
            if call['semantic_tool'] == 'phone.open_app':
                observed, viewport = verify_app_open(value, token, call['component'])
                validate_viewport(viewport)
                fact = {'kind': 'app_open_verified', 'call_id': call_id, 'package': call['package'],
                        'component': observed['component'], 'display_id': 0,
                        'original_result_sha256': sha(original['content'].encode())}
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
