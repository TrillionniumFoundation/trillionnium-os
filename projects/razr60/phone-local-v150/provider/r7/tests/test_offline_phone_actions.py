#!/usr/bin/env python3
"""Host regressions for actual provider mappings, state admission and guards.

No phone, model or network is used. The exact generated Android shell is run
against four local fake executables. Native IPC/domain qualification remains a
separate device gate; the existing pinned client/worker are not replaced here.
"""
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

SOURCE = Path(os.environ.get('HEPTA_PROVIDER_TEST_SOURCE',
              str(Path(__file__).resolve().parent.parent / 'source')))
sys.path.insert(0, str(SOURCE))
from action_ledger import ActionLedger, fingerprint
from phone_observation_tools import SERIAL, PHYSICAL_DISPLAY, page_state
from phone_local_http_worker import endpoint_parts
from model_health import ModelFailure
from provider_openai_compatible import ProviderError, PROTOCOL
from provider_phone_local import (PhoneLocalAdapter, business_decision_schema,
    mobile_use_schema, normalize_mobile_use, mobile_use_policy, compact_transcript,
    operation_profile, LEGACY_PROFILE, ORDINARY_PROFILE, load_local_config, inspect_single_slot)
from retirement_recovery import EXECUTOR_BINDING
import phone_task_guards
from task_postconditions import evaluate, terminal_fields


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


APPS = {
    'Calculator': {'component': 'com.example.calculator/.Calculator', 'label': 'Calculator'},
    'Calculator alias': {'component': 'com.example.calculator/com.example.calculator.Calculator',
                         'label': 'Same component, another alias'},
    'Calculator history': {'component': 'com.example.calculator/.History', 'label': 'History'},
    'Settings': {'component': 'com.android.settings/.Settings', 'label': 'Settings'},
    'Hepta': {'component': 'org.trillionnium.owneropen/.OwnerOpenShellActivity', 'label': 'Hepta'},
}
EXECUTOR = {'mode': 'phone_local_sidecar', 'python': '/usr/bin/python3',
            'client_path': EXECUTOR_BINDING['client_path'],
            'client_sha256': EXECUTOR_BINDING['client_sha256'], 'timeout_ms': 5000}
VIEWPORT = ("mViewports=[DisplayViewport{type=INTERNAL, valid=true, isActive=true, displayId=0, "
            "uniqueId='local:" + PHYSICAL_DISPLAY + "', orientation=0, "
            "logicalFrame=Rect(0, 0 - 1224, 2992), physicalFrame=Rect(0, 0 - 1224, 2992)}]")
WINDOW = ('Display: mDisplayId=0\nmTopFocusedDisplayId=0\n'
          'mCurrentFocus=Window{a u0 com.example.calculator/.Calculator}\n'
          'mFocusedApp=ActivityRecord{b u0 com.example.calculator/.Calculator t1}\n'
          'isKeyguardShowing=false')
ACTIVITY = 'topResumedActivity=ActivityRecord{c u0 com.example.calculator/.Calculator t1}'
PAGE = WINDOW + '\n' + ACTIVITY
PNG = b'host-fixture screenshot bytes, never a phone capture'
CALL = 'r02_0123456789abcdef'
IMAGE = 'r01_fedcba9876543210'
NEW_ACTIONS = {
    'swipe': {'start_coordinate': [250, 800], 'end_coordinate': [250, 200], 'duration_ms': 400},
    'long_press': {'coordinate': [500, 500], 'duration_ms': 800},
    'back': {},
    'home': {},
}


def native_result(call_id, raw=b'', *, exit_code=0, truncated=False):
    terminal = {'kind': 'exited', 'exit_code': exit_code, 'error': None,
                'output_truncated': truncated, 'stdout_bytes': len(raw), 'stderr_bytes': 0}
    events = [{'kind': 'accepted'}, {'kind': 'started'}]
    if raw:
        events.append({'kind': 'output', 'stream': 'stdout', 'encoding': 'base64',
                       'data': base64.b64encode(raw).decode(), 'byte_count': len(raw)})
    events.append({'kind': 'terminal', 'terminal': terminal})
    return {'protocol': PROTOCOL, 'kind': 'tool.result', 'seq': 1,
            'call_id': call_id, 'status': 'terminal', 'terminal': terminal,
            'events': [{'call_id': call_id, 'tool': 'shell.exec', 'seq': i, 'event': event}
                       for i, event in enumerate(events)]}


def mobile(action, **arguments):
    return {'name': 'mobile_use', 'arguments': {'action': action,
            'summary': 'Host fixture selected action', **arguments}}


def branches(schema):
    return {branch['properties']['tool']['const']: branch['properties']
            for branch in schema['oneOf']}


def fresh_image(binding, **changes):
    value = {'call_id': IMAGE, 'attached_round': 2, 'turn': dict(binding),
             'received_monotonic': time.monotonic(), 'encoded_size': [612, 1496],
             'viewport': VIEWPORT, 'page_state': PAGE, 'page_state_sha256': sha(PAGE.encode()),
             'source_png_sha256': sha(PNG), 'image_sha256': sha(b'host fixture JPEG'),
             'observed_page': page_state(PAGE)}
    value.update(changes)
    return value


class ProviderFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='hepta-offline-source-test-')
        self.root = Path(self.temporary.name)
        self.evidence = self.root / 'evidence'
        self.evidence.mkdir(mode=0o700)
        (self.evidence / 'claims').mkdir(mode=0o700)
        self.counter = 0
        self.adapters = []
        self.owner_requests = {}
        # Only the external file-location check is injected. Mapping, command
        # generation, durable ledger, receive/emit and result parsing are real.
        self.file_pin = mock.patch('phone_local_tools.validate_executor', side_effect=lambda value, **_: value)
        self.file_pin.start()

    def tearDown(self):
        for adapter, writer in self.adapters:
            adapter.frames.close()
            adapter.inputs.close()
            adapter.source.close()
            os.close(writer)
        self.file_pin.stop()
        self.temporary.cleanup()

    def adapter(self, identity=None, request='打开计算器，查看当前页面。', accept=True, profile=None):
        self.counter += 1
        run = self.root / ('run-' + str(self.counter))
        run.mkdir(mode=0o700)
        read_fd, write_fd = os.pipe()
        source = os.fdopen(read_fd, 'rb', buffering=0)
        sink = io.StringIO()
        config = {'approved_apps': copy.deepcopy(APPS), 'executor': dict(EXECUTOR), 'max_prompt_bytes':24576}
        if profile is not None:
            config.update(operation_profile=profile, context_tokens=8192)
        args = types.SimpleNamespace(evidence=self.evidence, contracts=None, timeout=120, local_config=config)
        adapter = PhoneLocalAdapter(args, source, sink, run)
        self.adapters.append((adapter, write_fd))
        self.owner_requests[id(adapter)] = request
        if identity is None:
            identity = {'session_id': 'fixture-session', 'profile_id': 'fixture-profile',
                        'task_id': 'task-' + str(self.counter), 'turn_id': 'turn-' + str(self.counter),
                        'turn_stream_id': 'stream-' + str(self.counter)}
        if accept:
            self.send(adapter, {'protocol': PROTOCOL, 'seq': 0, 'kind': 'turn.start',
                               'turn': {**identity, 'user_input': request}})
            adapter.receive('turn.start', timeout=0)
        return adapter

    def send(self, adapter, value):
        writer = next(writer for item, writer in self.adapters if item is adapter)
        os.write(writer, (json.dumps(value, ensure_ascii=False) + '\n').encode())

    def screen(self, adapter, **changes):
        adapter.round = adapter.phone_tools.round = 2
        adapter.phone_tools.latest = fresh_image(adapter.accepted_identity, **changes)

    def choose(self, adapter, action, call_id=CALL, **fields):
        schema = business_decision_schema(call_id, adapter.round, adapter.phone_tools, APPS, adapter.operation_profile)
        decision = normalize_mobile_use(mobile(action, **fields), schema, call_id)
        adapter._decision(decision, call_id)
        self.bind_host_request(adapter, call_id, schema)
        return adapter.phone_tools.calls[call_id]

    def bind_host_request(self, adapter, call_id, schema):
        """Commit real r9 request bindings for this direct-mapper host fixture.

        No model is invoked by these mapping tests. The fixture supplies the
        explicitly labelled request files that production completion() writes
        before a model call; the real LedgerPrefix and original reserve/emit
        gates remain in use. Full completion ordering is tested separately by
        the native selector/bridge suite.
        """
        prefix = getattr(adapter, 'ledger_prefix', None)
        if prefix is None:
            return  # The public r7 source predates the request-prefix contract.
        number = int(call_id[1:3])
        if prefix.bindings and prefix.bindings[-1]['value']['allowed_call_id'] == call_id:
            return
        self.assertGreater(number, len(prefix.bindings), 'host fixture must advance model round for a new request')
        for current in range(len(prefix.bindings) + 1, number + 1):
            allowed = call_id if current == number else (
                IMAGE if current == 1 else 'r%02d_%016x' % (current, current))
            request_id = allowed[4:] + '0' * 16
            _rows, boundary_sha = prefix.before_request(current, request_id, allowed)
            path = adapter.run_dir / ('local-%02d' % current)
            adapter.atomic_record(path.with_suffix('.open-replay-exclusions.json'), {
                'schema': 'hepta.open-replay-schema-context.v150.1', 'request_id': request_id,
                'round': current, 'ledger_boundary_sha256': boundary_sha, 'excluded': [],
                'authorizes_dispatch': False, 'host_fixture': True})
            adapter.atomic_record(path.with_suffix('.request.json'), {
                'model': 'host-fixture-no-model-invocation', 'host_fixture': True,
                'allowed_call_id': allowed, 'messages': [{'role': 'user',
                    'content': self.owner_requests[id(adapter)]}],
                'response_format': {'type': 'json_schema', 'json_schema': {
                    'schema': mobile_use_schema(schema), 'strict': True}}})
            now = time.monotonic()
            adapter.atomic_record(path.with_suffix('.schema-clock.json'), {
                'schema': 'hepta.business-schema-clock.v150.1', 'request_id': request_id,
                'round': current, 'clock': 'CLOCK_MONOTONIC', 'before': now, 'after': now,
                'latest_image_call_id': IMAGE if current > 1 else None,
                'latest_received_monotonic': None, 'host_fixture': True})
            prefix.bind_request(path)

    def shell(self, record):
        argv = record['wire_call']['argv']
        return base64.b64decode(argv[argv.index('--command-b64') + 1], validate=True).decode()

    def complete(self, adapter, record, raw=b'', **kwargs):
        reply = native_result(record['call_id'], raw, **kwargs)
        messages = [{'role': 'tool', 'tool_call_id': record['call_id'], 'content': json.dumps(reply)}]
        projected, _paths = adapter.phone_tools.prepare(messages, messages, adapter.round + 1)
        return reply, projected

    def app_open_receipt(self, record, component, page):
        """Native receipt fixture for the pinned source's declared revision."""
        receipt = {'schema': 'hepta.local-app-open.v150.1', 'operation_id': record['capture_id'],
                   'launch_exit_code': 0,
                   'launch_b64': base64.b64encode(('Status: ok\nActivity: ' + component + '\n').encode()).decode(),
                   'page_b64': base64.b64encode(page.encode()).decode(),
                   'viewport_b64': base64.b64encode(VIEWPORT.encode()).decode()}
        if hasattr(phone_task_guards, 'APP_OPEN_MAX_OBSERVATIONS'):
            # r9 strengthened app-open proof. Its controlled host fixture must
            # state two stable observations and the fixed launch flags; a v1
            # receipt is deliberately rejected by the production validator.
            receipt.update(schema='hepta.local-app-open.v150.2',
                           launch_flags='NEW_TASK|CLEAR_TOP', observation_attempts=2,
                           observation_stable=True)
        return receipt

    def opened(self, adapter, alias, call_id, round_number):
        adapter.round = round_number
        record = self.choose(adapter, 'open', call_id=call_id, text=alias)
        adapter.emit('tool.call', call=record['wire_call'])
        component = APPS[alias]['component']
        page = PAGE.replace('com.example.calculator/.Calculator', component)
        receipt = self.app_open_receipt(record, component, page)
        result = native_result(call_id, json.dumps(receipt).encode())
        result['seq'] = adapter.in_seq
        self.send(adapter, result)
        original = adapter.receive('tool.result', timeout=0)
        # Recovery must leave this current original response to the typed
        # parser; a process-only inspect cannot replace semantic validation.
        adapter._inspect_pending()
        self.assertFalse(adapter.inspected_actions)
        messages = [{'role':'tool', 'tool_call_id':call_id, 'content':json.dumps(original)}]
        adapter.phone_tools.prepare(messages, messages, round_number + 1)
        adapter.action_ledger.confirm_validated_results(adapter.phone_tools)
        return record

    def confirm_input(self, adapter, record):
        adapter.emit('tool.call', call=record['wire_call'])
        reply = native_result(record['call_id'])
        reply['seq'] = adapter.in_seq
        self.send(adapter, reply)
        original = adapter.receive('tool.result', timeout=0)
        messages = [{'role':'tool', 'tool_call_id':record['call_id'], 'content':json.dumps(original)}]
        adapter.phone_tools.prepare(messages, messages, adapter.round + 1)
        adapter.action_ledger.confirm_validated_results(adapter.phone_tools)


class OpenAndRequestTests(ProviderFixture):
    def test_private_app_open_rejects_old_or_unstable_receipts(self):
        if not hasattr(phone_task_guards, 'APP_OPEN_MAX_OBSERVATIONS'):
            self.skipTest('public r7 source predates stable app-open v2')
        token = 'a' * 32
        component = 'com.example.calculator/.Calculator'
        valid = self.app_open_receipt({'capture_id': token}, component, PAGE)
        phone_task_guards.verify_app_open(valid, token, component)
        variants = [dict(valid, observation_attempts=1), dict(valid, observation_stable=False),
                    dict(valid, launch_flags='NEW_TASK')]
        old = {k: v for k, v in valid.items()
               if k not in {'observation_attempts', 'observation_stable', 'launch_flags'}}
        old['schema'] = 'hepta.local-app-open.v150.1'
        for value in variants + [old]:
            with self.subTest(receipt=value), self.assertRaisesRegex(ProviderError, 'identity or stability differs'):
                phone_task_guards.verify_app_open(value, token, component)

    def test_verified_cross_app_departure_allows_guarded_return_not_permanent_mask(self):
        adapter = self.adapter()
        first = self.opened(adapter, 'Calculator', 'r01_1111111111111111', 1)
        second = self.opened(adapter, 'Settings', 'r02_2222222222222222', 2)
        current = adapter.phone_tools.current_foreground()
        self.assertEqual('com.android.settings/com.android.settings.Settings', current['component'])
        first_time = current['received_monotonic']
        repeated = adapter.phone_tools.remember_foreground(current['call_id'], current['page_state'],
                    current['viewport'], current['original_result_sha256'])
        self.assertEqual(first_time, repeated['received_monotonic'])
        schema = business_decision_schema('r03_3333333333333333', 3, adapter.phone_tools, APPS)
        self.assertIn('Calculator', branches(schema)['phone.open_app']['argv']['items']['enum'])
        third = self.opened(adapter, 'Calculator', 'r03_3333333333333333', 3)
        self.assertEqual(first['capture_id'], third['navigation_reentry']['previous_action_id'])
        self.assertIn('com.android.settings/.Settings', self.shell(third))
        self.assertNotEqual(fingerprint(first), fingerprint(third))
        self.assertEqual(first_time, adapter.phone_tools.foreground_observations[second['call_id']]['received_monotonic'])
        # A second complete A -> B -> A cycle has a new verified navigation
        # epoch; merely changing a call ID or recapturing A never creates it.
        self.opened(adapter, 'Settings', 'r04_4444444444444444', 4)
        fifth = self.opened(adapter, 'Calculator', 'r05_5555555555555555', 5)
        self.assertEqual(third['capture_id'], fifth['navigation_reentry']['previous_action_id'])
        self.assertNotEqual(fingerprint(third), fingerprint(fifth))
        denied = business_decision_schema('r06_6666666666666666', 6, adapter.phone_tools, APPS)
        self.assertNotIn('Calculator', branches(denied)['phone.open_app']['argv']['items']['enum'])
        self.assertEqual(5, len(adapter.action_ledger.intents()))

    def test_no_reentry_on_old_expired_or_unverified_departure(self):
        adapter = self.adapter()
        first = self.opened(adapter, 'Calculator', 'r01_1111111111111111', 1)
        second = self.opened(adapter, 'Settings', 'r02_2222222222222222', 2)
        current = adapter.phone_tools.foreground_observations[second['call_id']]
        current['received_monotonic'] -= 121
        self.assertFalse(adapter.phone_tools.open_app_allowed(APPS['Calculator']['component']))
        current['received_monotonic'] = time.monotonic()
        del adapter.phone_tools.local_observations[first['call_id']]
        self.assertFalse(adapter.phone_tools.open_app_allowed(APPS['Calculator']['component']))

    def test_verified_open_removes_all_component_aliases_but_not_other_activity(self):
        adapter = self.adapter()
        adapter.round = 1
        record = self.choose(adapter, 'open', call_id=IMAGE, text='Calculator')
        adapter.emit('tool.call', call=record['wire_call'])
        receipt = self.app_open_receipt(record, 'com.example.calculator/.Calculator', PAGE)
        reply = native_result(IMAGE, json.dumps(receipt).encode())
        self.send(adapter, reply)
        original = adapter.receive('tool.result', timeout=0)
        messages = [{'role': 'tool', 'tool_call_id': IMAGE, 'content': json.dumps(original)}]
        adapter.phone_tools.prepare(messages, messages, 2)
        adapter.action_ledger.confirm_validated_results(adapter.phone_tools)
        self.assertEqual('app_open_verified', adapter.phone_tools.local_observations[IMAGE]['kind'])
        schema = business_decision_schema(CALL, 2, adapter.phone_tools, APPS)
        aliases = branches(schema)['phone.open_app']['argv']['items']['enum']
        self.assertEqual(['Calculator history', 'Settings'], aliases)
        self.assertIn('phone.screenshot', branches(schema))
        with self.assertRaises(ProviderError):
            normalize_mobile_use(mobile('open', text='Calculator alias'), schema, CALL)
        # A real natural-language request was admitted without a fabricated
        # test contract. Completing it does not claim independent verification.
        self.assertIsNone(adapter.task_contract)
        self.assertIsNone(adapter.health_contract)
        adapter.model_task_status = 'completed'
        adapter.emit('turn.complete', summary='计算器已打开。')
        terminal = json.loads(adapter.sink.getvalue().splitlines()[-1])
        self.assertEqual('turn.complete', terminal['kind'])
        self.assertIn('业务未独立验证', terminal['summary'])
        self.assertFalse(json.loads((adapter.run_dir / 'business-outcome.json').read_text())['business_verified'])

    def test_attempt_is_masked_without_inventing_a_success_receipt(self):
        adapter = self.adapter()
        adapter.round = 1
        self.choose(adapter, 'open', call_id=IMAGE, text='Calculator')
        schema = business_decision_schema(CALL, 2, adapter.phone_tools, APPS)
        self.assertNotIn('Calculator', branches(schema)['phone.open_app']['argv']['items']['enum'])
        self.assertEqual({}, adapter.phone_tools.local_observations)
        self.assertEqual({}, adapter.phone_tools.verified_facts)

    def test_reconnect_cannot_reclaim_old_turn_and_new_request_keeps_old_bytes(self):
        first = self.adapter()
        claims = {p.name: p.read_bytes() for p in (self.evidence / 'claims').iterdir()}
        replacement = self.adapter(accept=False)
        identity = {**first.accepted_identity, 'turn_stream_id': 'replacement-stream'}
        self.send(replacement, {'protocol': PROTOCOL, 'seq': 0, 'kind': 'turn.start',
                               'turn': {**identity, 'user_input': '另一个文本不能使旧请求重放'}})
        with self.assertRaisesRegex(ProviderError, 'already accepted'):
            replacement.receive('turn.start', timeout=0)
        fresh = self.adapter(request='查看设置中的系统版本。')
        self.assertTrue(fresh.claimed)
        self.assertIsNone(fresh.task_contract)
        self.assertNotEqual(first.accepted_identity['task_id'], fresh.accepted_identity['task_id'])
        for name, raw in claims.items():
            self.assertEqual(raw, (self.evidence / 'claims' / name).read_bytes())

    def test_old_unresolved_effect_is_retained_and_still_blocks_new_mutation(self):
        first = self.adapter()
        self.screen(first)
        original = self.choose(first, 'back', screenshot_id=IMAGE)
        first.emit('tool.call', call=original['wire_call'])
        old_path = first.action_ledger.directory / (original['capture_id'] + '.intent.json')
        old_bytes = old_path.read_bytes()
        second = self.adapter(request='一个新的独立请求')
        second.round = 1
        new_record = self.choose(second, 'open', call_id=IMAGE, text='Settings')
        with self.assertRaisesRegex(ProviderError, 'original action is unresolved'):
            second.emit('tool.call', call=new_record['wire_call'])
        self.assertEqual(old_bytes, old_path.read_bytes())
        self.assertFalse(old_path.with_name(original['capture_id'] + '.resolution.json').exists())
        self.assertEqual('', second.sink.getvalue())
        # A fresh read-only request remains distinguishable and can observe;
        # accepting it neither clears uncertainty nor retries the old input.
        # A second model decision is a new round even though the preceding
        # mutation was denied before dispatch by the unresolved-action gate.
        second.round = 2
        shot = self.choose(second, 'screenshot', call_id='r02_aaaaaaaaaaaaaaaa', display_id=0)
        second.emit('tool.call', call=shot['wire_call'])
        self.assertEqual(1, len(second.sink.getvalue().splitlines()))
        self.assertEqual(old_bytes, old_path.read_bytes())


class ActionSchemaTests(ProviderFixture):
    def test_private_request_binding_gate_rejects_an_unbound_direct_action(self):
        adapter = self.adapter()
        if getattr(adapter, 'ledger_prefix', None) is None:
            self.skipTest('public r7 source has no ledger-prefix request binding')
        self.screen(adapter)
        schema = business_decision_schema(CALL, adapter.round, adapter.phone_tools, APPS, adapter.operation_profile)
        decision = normalize_mobile_use(mobile('back', screenshot_id=IMAGE), schema, CALL)
        adapter._decision(decision, CALL)
        record = adapter.phone_tools.calls[CALL]
        with self.assertRaisesRegex(ProviderError, 'no committed request binding'):
            adapter.emit('tool.call', call=record['wire_call'])
        self.assertEqual('', adapter.sink.getvalue())
        self.assertEqual([], adapter.action_ledger.intents())

    def test_only_current_image_offers_new_inputs_and_visual_contract_stays_closed(self):
        adapter = self.adapter()
        for changes in ({}, {'attached_round': 1}, {'received_monotonic': time.monotonic() - 121},
                        {'received_monotonic': time.monotonic() + 100}):
            with self.subTest(changes=changes):
                self.screen(adapter, **changes)
                schema = branches(business_decision_schema(CALL, 2, adapter.phone_tools, APPS))
                for action in NEW_ACTIONS:
                    self.assertEqual(not changes, 'phone.' + action in schema)
        adapter.phone_tools.latest = None
        schema = branches(business_decision_schema(CALL, 2, adapter.phone_tools, APPS))
        self.assertTrue(all('phone.' + action not in schema for action in NEW_ACTIONS))
        self.screen(adapter)
        adapter.phone_tools.visual_read_constraints = [{'package': 'com.example.calculator'}]
        schema = branches(business_decision_schema(CALL, 2, adapter.phone_tools, APPS))
        self.assertIn('phone.tap', schema)
        self.assertTrue(all('phone.' + action not in schema for action in NEW_ACTIONS))
        final = branches(business_decision_schema('r08_0123456789abcdef', 8, adapter.phone_tools, APPS))
        self.assertEqual({'none'}, set(final))

    def test_model_projection_maps_to_fixed_inputs_and_invalidates_image(self):
        expected = {'swipe': 'input -d 0 swipe 306 2392 306 598 400',
                    'long_press': 'input -d 0 swipe 612 1496 612 1496 800',
                    'back': 'input -d 0 keyevent 4', 'home': 'input -d 0 keyevent 3'}
        for action, fields in NEW_ACTIONS.items():
            with self.subTest(action=action):
                adapter = self.adapter()
                self.screen(adapter)
                schema = business_decision_schema(CALL, 2, adapter.phone_tools, APPS)
                self.assertIn(action + '(', mobile_use_policy(mobile_use_schema(schema)))
                record = self.choose(adapter, action, screenshot_id=IMAGE, **fields)
                self.assertTrue(self.shell(record).endswith(expected[action]))
                self.assertTrue(record['exact_pixel_and_focus_guard'])
                self.assertIsNone(adapter.phone_tools.latest)
                with self.assertRaises(ProviderError):
                    adapter.phone_tools.map({'call_id': 'r02_aaaaaaaaaaaaaaaa',
                        'tool': 'phone.back', 'command': '', 'argv': [IMAGE]})

    def test_untrusted_model_fields_cannot_expand_commands_or_bounds(self):
        adapter = self.adapter()
        self.screen(adapter)
        schema = business_decision_schema(CALL, 2, adapter.phone_tools, APPS)
        bad = [mobile('swipe', screenshot_id=IMAGE, start_coordinate=[0, 0],
                      end_coordinate=[1, 1], duration_ms=value) for value in (0, 99, 1501, True, '400')]
        bad += [mobile('long_press', screenshot_id=IMAGE, coordinate=[0, 0], duration_ms=499)]
        bad += [mobile('long_press', screenshot_id=IMAGE, coordinate=point, duration_ms=800)
                for point in ([-1, 0], [1001, 0], [1.5, 0], [True, 0], ['0; id', 0])]
        bad += [mobile('back', screenshot_id=IMAGE, keycode=26),
                mobile('back', screenshot_id='another-image'), mobile('shell', command='id')]
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(ProviderError):
                    normalize_mobile_use(value, schema, CALL)
        self.assertEqual({}, adapter.phone_tools.calls)

    def test_mapper_rejects_cross_turn_stale_locked_rotated_and_tampered_image(self):
        changes = [{'turn': {'task_id': 'foreign'}}, {'attached_round': 1},
                   {'received_monotonic': time.monotonic() - 121},
                   {'received_monotonic': time.monotonic() + 100},
                   {'page_state': PAGE.replace('isKeyguardShowing=false', 'isKeyguardShowing=true')},
                   {'viewport': VIEWPORT.replace('orientation=0', 'orientation=1')},
                   {'source_png_sha256': 'not-a-hash'}, {'page_state_sha256': '0' * 64}]
        for change in changes:
            with self.subTest(change=change):
                adapter = self.adapter()
                self.screen(adapter, **change)
                with self.assertRaises(ProviderError):
                    adapter.phone_tools.map({'call_id': CALL, 'tool': 'phone.back',
                                             'command': '', 'argv': [IMAGE]})
                self.assertEqual({}, adapter.phone_tools.calls)


FAKE_ANDROID = '''#!PYTHON
import json, os, pathlib, sys
root = pathlib.Path(os.environ['HEPTA_FIXTURE_ROOT'])
name = pathlib.Path(sys.argv[0]).name
mode = (root / 'mode').read_text()
if name == 'getprop':
    print((root / 'serial').read_text())
elif name == 'dumpsys':
    part = {'display':'viewport', 'window':'window', 'activity':'activity'}[sys.argv[1]]
    print((root / part).read_text())
elif name == 'screencap':
    if mode == 'capture_failure':
        sys.exit(17)
    path = pathlib.Path(sys.argv[-1])
    assert path.parent == root, 'fixture attempted a nonlocal capture'
    path.write_bytes((root / 'png').read_bytes())
    if mode == 'focus_after_capture':
        (root / 'window').write_text((root / 'window').read_text().replace('.Calculator', '.History'))
    if mode == 'viewport_after_capture':
        (root / 'viewport').write_text((root / 'viewport').read_text().replace('orientation=0', 'orientation=1'))
elif name == 'input':
    with (root / 'input_calls').open('a') as stream:
        stream.write(json.dumps(sys.argv[1:]) + '\\n')
    if mode == 'input_failure':
        sys.exit(43)
elif name == 'am':
    with (root / 'input_calls').open('a') as stream:
        stream.write(json.dumps(['am'] + sys.argv[1:]) + '\\n')
    target = sys.argv[sys.argv.index('-n') + 1]
    previous = (root / 'initial_component').read_text()
    for name in ('window', 'activity'):
        (root / name).write_text((root / name).read_text().replace(previous, target))
    print('Status: ok')
    print('Activity: ' + target)
else:
    raise RuntimeError(name)
'''


class GeneratedGuardTests(ProviderFixture):
    def execute_guard(self, record, mode, initial_component='com.example.calculator/.Calculator'):
        root = self.root / ('android-' + str(self.counter) + '-' + mode)
        root.mkdir()
        binary = root / 'bin'
        binary.mkdir()
        for name in ('getprop', 'dumpsys', 'screencap', 'input', 'am'):
            script = binary / name
            script.write_text(FAKE_ANDROID.replace('#!PYTHON', '#!' + sys.executable))
            script.chmod(0o700)
        for name, value in {'mode': mode, 'serial': SERIAL, 'viewport': VIEWPORT,
                            'window': WINDOW.replace('com.example.calculator/.Calculator', initial_component),
                            'activity': ACTIVITY.replace('com.example.calculator/.Calculator', initial_component),
                            'initial_component': initial_component}.items():
            (root / name).write_text(value)
        (root / 'png').write_bytes(PNG)
        if mode == 'wrong_serial':
            (root / 'serial').write_text('foreign-device')
        if mode == 'rotated':
            (root / 'viewport').write_text(VIEWPORT.replace('orientation=0', 'orientation=1'))
        if mode == 'locked':
            (root / 'window').write_text(WINDOW.replace('isKeyguardShowing=false', 'isKeyguardShowing=true'))
        if mode == 'focus_changed':
            (root / 'window').write_text(WINDOW.replace('.Calculator', '.History'))
        if mode == 'pixels_changed':
            (root / 'png').write_bytes(b'different pixels on the same viewport')
        if mode == 'return_to_target':
            (root / 'window').write_text(WINDOW)
            (root / 'activity').write_text(ACTIVITY)
        local_guard = root / 'guard.png'
        command = self.shell(record)
        if 'guard_png_path' in record:
            command = command.replace(record['guard_png_path'], str(local_guard))
        self.assertNotIn('/data/local/tmp/', command)
        result = subprocess.run(['/bin/sh', '-c', command], capture_output=True, timeout=10,
                    env={**os.environ, 'PATH': str(binary) + os.pathsep + '/usr/bin:/bin',
                         'HEPTA_FIXTURE_ROOT': str(root)})
        calls = (root / 'input_calls').read_text().splitlines() if (root / 'input_calls').exists() else []
        self.assertFalse(local_guard.exists(), 'guard screenshot leaked after completion/failure')
        return result, [json.loads(call) for call in calls]

    def test_exact_generated_scripts_check_guard_before_each_new_input(self):
        expected = {'wrong_serial': 64, 'rotated': 68, 'locked': 70, 'focus_changed': 70,
                    'pixels_changed': 71, 'capture_failure': 67, 'focus_after_capture': 70,
                    'viewport_after_capture': 68}
        for action, fields in {'click': {'coordinate':[500, 500]}, **NEW_ACTIONS}.items():
            adapter = self.adapter()
            self.screen(adapter)
            record = self.choose(adapter, action, screenshot_id=IMAGE, **fields)
            for mode, returncode in expected.items():
                with self.subTest(action=action, mode=mode):
                    result, calls = self.execute_guard(record, mode)
                    self.assertEqual(returncode, result.returncode, result.stderr)
                    self.assertEqual([], calls)
            result, calls = self.execute_guard(record, 'stable')
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(1, len(calls))
            self.assertEqual(['-d', '0'], calls[0][:2])
            self.assertEqual(b'', result.stdout)
            failed, failed_calls = self.execute_guard(record, 'input_failure')
            self.assertEqual(43, failed.returncode)
            self.assertEqual(1, len(failed_calls), 'failed effect was retried')

    def test_cross_app_return_checks_actual_departure_before_launch(self):
        adapter = self.adapter()
        self.opened(adapter, 'Calculator', 'r01_1111111111111111', 1)
        self.opened(adapter, 'Settings', 'r02_2222222222222222', 2)
        adapter.round = 3
        record = self.choose(adapter, 'open', call_id='r03_3333333333333333', text='Calculator')
        result, calls = self.execute_guard(record, 'stable', 'com.android.settings/.Settings')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(1, len(calls))
        expected_launch = ['am', 'start', '--display', '0']
        if hasattr(phone_task_guards, 'APP_OPEN_MAX_OBSERVATIONS'):
            # The r9 v2 contract freezes NEW_TASK|CLEAR_TOP. Keep exact argv
            # validation; do not infer expected flags from generated output.
            expected_launch += ['-f', '0x14000000']
        expected_launch += ['-W', '-n', APPS['Calculator']['component']]
        self.assertEqual(expected_launch, calls[0])
        self.assertEqual(0, json.loads(result.stdout)['launch_exit_code'])
        blocked, calls = self.execute_guard(record, 'return_to_target', 'com.android.settings/.Settings')
        self.assertEqual(70, blocked.returncode)
        self.assertEqual([], calls)


class ReceiptsAndLedgerTests(ProviderFixture):
    def test_real_ui_new_owner_turn_can_repeat_confirmed_effect_in_same_task(self):
        for action, fields in NEW_ACTIONS.items():
            with self.subTest(action=action):
                self.evidence = self.root / ('independent-' + action)
                self.evidence.mkdir(mode=0o700)
                (self.evidence / 'claims').mkdir(mode=0o700)
                first = self.adapter(request='现在执行这个动作。')
                self.screen(first)
                original = self.choose(first, action, screenshot_id=IMAGE, **fields)
                self.confirm_input(first, original)
                first.model_task_status = 'completed'
                first.emit('turn.complete', summary='动作有原始回执。')
                originals = {p.name:p.read_bytes() for p in first.action_ledger.directory.glob('*.json')}
                # Inventing a new turn ID in a provider action is not a new
                # accepted owner request. Only the UI's turn.start can claim it.
                renamed = copy.deepcopy(original)
                renamed.update(capture_id='a' * 32, call_id='r02_aaaaaaaaaaaaaaaa')
                with self.assertRaisesRegex(ProviderError, 'effect already attempted'):
                    first.action_ledger.reserve(renamed, {**first.accepted_identity, 'turn_id':'invented-turn'})
                # Match the installed UI: task_id persists, each explicit Send
                # creates a new turn_id. Repeating the owner's text is valid.
                fresh = self.adapter(identity={**first.accepted_identity,
                    'turn_id':'new-owner-turn', 'turn_stream_id':'new-owner-stream'}, request='现在执行这个动作。')
                self.screen(fresh)
                next_record = self.choose(fresh, action, screenshot_id=IMAGE, **fields)
                self.assertEqual(fingerprint(original), fingerprint(next_record))
                fresh.emit('tool.call', call=next_record['wire_call'])
                self.assertEqual(1, len(fresh.sink.getvalue().splitlines()))
                for name, raw in originals.items():
                    self.assertEqual(raw, (first.action_ledger.directory / name).read_bytes())

    def test_new_turn_cannot_authorize_repeat_with_missing_or_changed_owner_bytes(self):
        first = self.adapter()
        self.screen(first)
        record = self.choose(first, 'back', screenshot_id=IMAGE)
        self.confirm_input(first, record)
        for mode in ('missing', 'changed'):
            with self.subTest(mode=mode):
                fresh = self.adapter(identity={**first.accepted_identity,
                    'turn_id':'owner-turn-' + mode, 'turn_stream_id':'stream-' + mode})
                owner_path = fresh.run_dir / 'accepted-owner-request.json'
                if mode == 'missing':
                    owner_path.unlink()
                else:
                    owner = json.loads(owner_path.read_text())
                    owner['request_utf8_b64'] = base64.b64encode(b'different request').decode()
                    owner_path.write_text(json.dumps(owner))
                self.screen(fresh)
                attempted = self.choose(fresh, 'back', screenshot_id=IMAGE)
                with self.assertRaisesRegex(ProviderError, 'effect already attempted'):
                    fresh.emit('tool.call', call=attempted['wire_call'])
                self.assertEqual('', fresh.sink.getvalue())

    def test_long_owner_request_is_preserved_and_verified_without_truncation(self):
        first = self.adapter()
        self.screen(first)
        original = self.choose(first, 'back', screenshot_id=IMAGE)
        self.confirm_input(first, original)
        text = '返回上一页。' + '这是原始用户的附加说明。' * 700
        fresh = self.adapter(identity={**first.accepted_identity,
            'turn_id':'long-owner-turn', 'turn_stream_id':'long-owner-stream'}, request=text)
        path = fresh.run_dir / 'accepted-owner-request.json'
        self.assertGreater(path.stat().st_size, 16384)
        value = json.loads(path.read_text())
        self.assertEqual(text.encode(), base64.b64decode(value['request_utf8_b64']))
        self.screen(fresh)
        record = self.choose(fresh, 'back', screenshot_id=IMAGE)
        fresh.emit('tool.call', call=record['wire_call'])
        self.assertEqual(1, len(fresh.sink.getvalue().splitlines()))

    def test_new_task_does_not_treat_process_only_inspection_as_typed_success(self):
        first = self.adapter()
        self.screen(first)
        original = self.choose(first, 'back', screenshot_id=IMAGE)
        first.emit('tool.call', call=original['wire_call'])
        intent, digest, _ = first.action_ledger.intents()[0]
        from task_postconditions import write_exclusive
        write_exclusive(first.action_ledger.directory / (intent['action_id'] + '.resolution.json'), {
            'schema':'hepta.action-resolution.v150.1', 'action_id':intent['action_id'],
            'intent_sha256':digest, 'state':'original_sidecar_terminal_independently_inspected',
            'automatic_replay':False, 'business_verified':False})
        fresh = self.adapter(request='新的明确返回指令')
        self.screen(fresh)
        attempted = self.choose(fresh, 'back', screenshot_id=IMAGE)
        with self.assertRaisesRegex(ProviderError, 'effect already attempted'):
            fresh.emit('tool.call', call=attempted['wire_call'])
        self.assertEqual('', fresh.sink.getvalue())

    def test_gestures_require_original_success_receipt_and_do_not_claim_ui_result(self):
        for action, fields in NEW_ACTIONS.items():
            with self.subTest(action=action):
                adapter = self.adapter()
                self.screen(adapter)
                record = self.choose(adapter, action, screenshot_id=IMAGE, **fields)
                for options in ({'exit_code': 1}, {'truncated': True}, {'raw': b'unexpected output'}):
                    with self.assertRaises(ProviderError):
                        self.complete(adapter, record, **options)
                    self.assertEqual({}, adapter.phone_tools.verified_facts)
                original, projected = self.complete(adapter, record)
                fact = adapter.phone_tools.verified_facts[CALL]
                self.assertEqual('screen_action_executed', fact['kind'])
                self.assertEqual('phone.' + action, fact['semantic_tool'])
                self.assertEqual(sha(json.dumps(original).encode()), fact['original_result_sha256'])
                view = compact_transcript(projected, adapter.phone_tools)[0]['content']
                self.assertTrue(view['verified_screen_action']['resulting_screen_requires_observation'])

    def test_new_actions_have_durable_fingerprints_and_cannot_replay_under_new_id(self):
        for action, fields in NEW_ACTIONS.items():
            with self.subTest(action=action):
                # Keep each independent ledger separate; this tests replay of
                # that exact bound effect, not a prior subtest's pending gate.
                adapter = self.adapter()
                ledger_root = self.root / ('ledger-' + str(self.counter))
                ledger_root.mkdir(mode=0o700)
                ledger = ActionLedger(ledger_root, adapter.run_dir)
                self.screen(adapter)
                record = self.choose(adapter, action, screenshot_id=IMAGE, **fields)
                self.assertRegex(fingerprint(record), r'^[0-9a-f]{64}$')
                ledger.reserve(record, adapter.accepted_identity)
                attempted = copy.deepcopy(record)
                attempted.update(capture_id='a' * 32, call_id='r02_aaaaaaaaaaaaaaaa')
                with self.assertRaisesRegex(ProviderError, 'original action is unresolved'):
                    ledger.reserve(attempted, adapter.accepted_identity)
                original, _ = self.complete(adapter, record)
                result_path = adapter.run_dir / ('result-' + sha(CALL.encode()) + '.json')
                result_path.write_text(json.dumps(original))
                ledger.confirm_validated_results(adapter.phone_tools)
                with self.assertRaisesRegex(ProviderError, 'effect already attempted'):
                    ledger.reserve(attempted, adapter.accepted_identity)
                with self.assertRaisesRegex(ProviderError, 'effect already attempted'):
                    ledger.reserve(attempted, {**adapter.accepted_identity, 'task_id': 'new-task', 'turn_id': 'new-turn'})

    def test_cancellation_after_reservation_marks_new_input_not_dispatched(self):
        for action, fields in NEW_ACTIONS.items():
            with self.subTest(action=action):
                adapter = self.adapter()
                self.screen(adapter)
                record = self.choose(adapter, action, screenshot_id=IMAGE, **fields)
                count = 0
                def receive(**_):
                    nonlocal count
                    count += 1
                    if count == 2:
                        adapter.cancelled.set()
                with mock.patch.object(adapter, 'receive', side_effect=receive):
                    adapter.emit('tool.call', call=record['wire_call'])
                self.assertEqual('', adapter.sink.getvalue())
                selected = [row for row in adapter.action_ledger.intents()
                            if row[0]['action_id'] == record['capture_id']]
                self.assertEqual('known_not_dispatched', selected[0][2]['state'])
                self.assertFalse(selected[0][2]['automatic_replay'])


class ProfileTests(ProviderFixture):
    def test_explicit_ordinary_profile_and_legacy_contract_budget_are_distinct(self):
        legacy = self.adapter()
        ordinary = self.adapter(profile=ORDINARY_PROFILE)
        self.assertEqual((7, 8), (legacy.config['max_tool_calls'], legacy.config['max_rounds']))
        self.assertEqual((24, 25), (ordinary.config['max_tool_calls'], ordinary.config['max_rounds']))
        record = json.loads((ordinary.run_dir / 'operation-profile.json').read_text())
        self.assertEqual(ORDINARY_PROFILE, record['selected_profile']['name'])
        self.assertEqual(8192, record['context_tokens'])
        self.assertEqual(24576, record['max_prompt_bytes'])
        self.assertTrue(record['prompt_bytes_are_not_token_count'])
        self.assertEqual(LEGACY_PROFILE, operation_profile({'operation_profile':ORDINARY_PROFILE}, restricted=True)['name'])
        now = time.monotonic()
        self.assertTrue(now < ordinary.session_deadline <= now + 300)
        schema = business_decision_schema('r08_8888888888888888', 8, ordinary.phone_tools, APPS, ordinary.operation_profile)
        self.assertIn('phone.screenshot', branches(schema))
        last = business_decision_schema('r25_5555555555555555', 25, ordinary.phone_tools, APPS, ordinary.operation_profile)
        self.assertEqual({'none'}, set(branches(last)))
        self.assertIn('24 tools and 25 rounds', mobile_use_policy(mobile_use_schema(schema), ordinary.operation_profile))

    def test_registered_contract_forces_original_budget_even_in_ordinary_service(self):
        contract = {'contract':{'postconditions':[], 'coverage':'entire_request'}, 'source_sha256':'a' * 64}
        with mock.patch('provider_codex_host.load_contract', return_value=contract):
            adapter = self.adapter(profile=ORDINARY_PROFILE)
        self.assertEqual(LEGACY_PROFILE, adapter.operation_profile['name'])
        self.assertEqual(393216, adapter.phone_tools.max_turn_image_bytes)
        self.assertEqual('registered_contract_legacy_budget',
                         json.loads((adapter.run_dir / 'operation-profile.json').read_text())['selection_reason'])

    def test_ordinary_image_budget_admits_third_image_but_remains_bounded(self):
        legacy = self.adapter()
        ordinary = self.adapter(profile=ORDINARY_PROFILE)
        for adapter in (legacy, ordinary):
            adapter.round = 3
            adapter.phone_tools.encoded_bytes_used = 2 * 196608
        with self.assertRaisesRegex(ProviderError, 'byte budget exhausted'):
            self.choose(legacy, 'screenshot', call_id='r03_3333333333333333', display_id=0)
        record = self.choose(ordinary, 'screenshot', call_id='r03_3333333333333333', display_id=0)
        self.assertEqual(196608, record['max_image_bytes'])
        self.assertEqual(24 * 196608, ordinary.phone_tools.max_turn_image_bytes)
        ordinary.phone_tools.encoded_bytes_used = ordinary.phone_tools.max_turn_image_bytes - 65535
        with self.assertRaisesRegex(ProviderError, 'byte budget exhausted'):
            self.choose(ordinary, 'screenshot', call_id='r03_aaaaaaaaaaaaaaaa', display_id=0)

    def test_remaining_total_deadline_limits_http_and_native_action(self):
        adapter = self.adapter(profile=ORDINARY_PROFILE)
        self.screen(adapter)
        deadline = time.monotonic() + 0.5
        adapter.session_deadline = adapter.phone_tools.action_deadline = deadline
        self.assertTrue(0.1 <= adapter.remaining_inference_seconds() <= 0.5)
        record = self.choose(adapter, 'back', screenshot_id=IMAGE)
        argv = record['wire_call']['argv']
        self.assertTrue(1 <= int(argv[argv.index('--timeout-ms') + 1]) <= 500)
        adapter.session_deadline = adapter.phone_tools.action_deadline = time.monotonic() - 1
        with self.assertRaises(ModelFailure):
            adapter.remaining_inference_seconds()
        with self.assertRaisesRegex(ProviderError, 'deadline expired'):
            adapter.emit('tool.call', call=record['wire_call'])
        self.assertEqual('', adapter.sink.getvalue())

    def test_new_config_requires_named_profile_and_explicit_context(self):
        key = self.root / 'api.key'
        key.write_text('host-test-key-never-real')
        key.chmod(0o600)
        config = {'schema':'hepta.phone-local-provider.v150.2',
                  'endpoint':'http://127.0.0.1:18087/v1/chat/completions',
                  'api_key_file':str(key), 'model':'host-test-model', 'service_manifest_sha256':'a' * 64,
                  'max_tokens':256, 'max_prompt_bytes':24576, 'approved_apps':APPS,
                  'inference_location':'phone', 'expected_parallel_slots':1, 'executor':EXECUTOR,
                  'operation_profile':ORDINARY_PROFILE, 'context_tokens':8192}
        path = self.root / 'config.json'
        def load(value):
            path.write_text(json.dumps(value)); path.chmod(0o600)
            with mock.patch('provider_phone_local.validate_executor', side_effect=lambda value: value):
                return load_local_config(path)
        selected, _ = load(config)
        self.assertEqual(ORDINARY_PROFILE, selected['operation_profile'])
        for changes in ({'operation_profile':'model-selected-unlimited'}, {'context_tokens':0},
                        {'context_tokens':True}, {'schema':'hepta.phone-local-provider.v150.1'}):
            with self.subTest(changes=changes):
                with self.assertRaises(ProviderError):
                    load({**config, **changes})
        missing = dict(config); del missing['context_tokens']
        with self.assertRaises(ProviderError):
            load(missing)

    def test_configured_context_must_match_actual_server_slot(self):
        config = {'endpoint':'http://127.0.0.1:18087/v1/chat/completions',
                  'api_key_file':'unused-test-path', 'context_tokens':8192}
        for observed, expected in ((8192, True), (4096, False), (None, False)):
            with self.subTest(observed=observed):
                connection = mock.Mock()
                response = connection.getresponse.return_value
                response.status = 200
                response.read.return_value = json.dumps([{'is_processing':False, 'n_ctx':observed}]).encode()
                with mock.patch('provider_phone_local.http.client.HTTPConnection', return_value=connection), \
                     mock.patch('provider_phone_local.private_api_key', return_value='host-test-key'):
                    result = inspect_single_slot(config)
                self.assertEqual(expected, result['observed'])


class RuntimeBoundaryTests(unittest.TestCase):
    def test_source_pins_import_and_reject_tampering(self):
        command = [sys.executable, '-B', '-c', 'import daily_phone_local']
        good = subprocess.run(command, cwd=SOURCE, capture_output=True, timeout=10)
        self.assertEqual(0, good.returncode, good.stderr)
        with tempfile.TemporaryDirectory(prefix='hepta-pin-tamper-') as name:
            target = Path(name)
            for source in SOURCE.glob('*.py'):
                shutil.copyfile(source, target / source.name)
            with (target / 'phone_observation_tools.py').open('a') as stream:
                stream.write('\n# unintended changed source\n')
            bad = subprocess.run(command, cwd=target, capture_output=True, timeout=10)
            self.assertNotEqual(0, bad.returncode)
            self.assertIn(b'protocol source pin differs', bad.stderr)

    def test_phone_model_endpoint_has_no_external_or_proxy_host_fallback(self):
        endpoint_parts('http://127.0.0.1:18087/v1/chat/completions')
        endpoint_parts('http://[::1]:18087/v1/chat/completions')
        for value in ('https://api.openai.com/v1/chat/completions',
                      'http://localhost:18087/v1/chat/completions',
                      'http://192.168.1.2:18087/v1/chat/completions',
                      'http://user:password@127.0.0.1:18087/v1/chat/completions'):
            with self.subTest(endpoint=value):
                with self.assertRaises(Exception):
                    endpoint_parts(value)

    def test_model_claim_alone_never_passes_a_real_postcondition_contract(self):
        no_contract = evaluate(None, [], None, 'completed', 'turn.complete')
        self.assertFalse(no_contract['business_verified'])
        contract = {'contract': {'schema': 'hepta.task-contract.v149.1', 'coverage': 'entire_request', 'postconditions':
                    [{'id': 'return', 'kind': 'foreground_hepta'}]}, 'source_sha256': 'a' * 64}
        outcome = evaluate(contract, [], None, 'completed', 'turn.complete')
        kind, _ = terminal_fields('turn.complete', {'summary': 'Done'}, outcome, True)
        self.assertEqual('turn.fail', kind)
        self.assertFalse(outcome['business_verified'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
