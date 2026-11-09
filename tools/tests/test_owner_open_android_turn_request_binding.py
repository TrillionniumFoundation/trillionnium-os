"""Actual Java request binding/parser, shared vectors also executed by the primary Rust Host."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
JAVA = ROOT / 'android-integration/working-tree/vendor/trillionnium/owner-open/client/src/org/trillionnium/owneropen'
FIXTURE = ROOT / 'apps/trillionnium-owner-open-host/tests/fixtures/android_client_turn_request_digest_v1.json'
HARNESS = r'''
import java.nio.file.*;
import java.util.Collections;
import org.trillionnium.owneropen.*;
public final class TurnBindingHarness {
 public static void main(String[] args) throws Exception {
  String input=Files.readString(Path.of(args[1]));
  if(args[0].equals("invalid-surrogate")) {
   OwnerOpenFrame.turnRequestSha256(args[2],args[3],args[4],"\ud800");
   throw new AssertionError("unpaired surrogate accepted");
  }
  if(args[0].equals("digest")) {
   System.out.println(OwnerOpenFrame.turnRequestSha256(args[2],args[3],args[4],input));
   System.out.println(OwnerOpenFrame.turnStreamId(args[2],args[3],args[4]));
   System.out.println(OwnerOpenFrame.turnInspect(args[2],args[3],args[4],
    OwnerOpenFrame.turnRequestSha256(args[2],args[3],args[4],input),0,256));
  } else {
   OwnerOpenTurnEvidence evidence=OwnerOpenTurnEvidence.parse(input);
   OwnerOpenClientState selected=new OwnerOpenClientState(args[2],args[3],args[4],args[5],Collections.emptyMap());
   System.out.println(evidence==null?"NONE":evidence.kind+":"+evidence.matches(selected)+":"+evidence.completeReadback);
  }
 }
}
'''


class AndroidTurnRequestBindingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('javac') or not shutil.which('java'):
            raise AssertionError('actual Java execution requires a JDK')
        cls.temporary = tempfile.TemporaryDirectory()
        cls.folder = Path(cls.temporary.name)
        harness = cls.folder / 'TurnBindingHarness.java'
        harness.write_text(HARNESS)
        cls.classes = cls.folder / 'classes'
        result = subprocess.run(['javac', '-Xlint:all', '-Werror', '-d', str(cls.classes),
            str(harness), *[str(JAVA / (name + '.java')) for name in
            ('OwnerOpenFrame', 'OwnerOpenTurnEvidence', 'OwnerOpenClientState')]],
            capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise AssertionError(result.stderr)
        cls.vector = json.loads(FIXTURE.read_text())['vectors'][0]

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_java(self, mode, content, digest=None):
        input_file = self.folder / 'input.txt'
        input_file.write_text(content)
        vector = self.vector
        return subprocess.run(['java', '-cp', str(self.classes), 'TurnBindingHarness', mode,
            str(input_file), vector['session_id'], vector['task_id'], vector['turn_id'],
            digest or vector['request_sha256']], capture_output=True, text=True, timeout=10)

    def test_shared_primary_host_vectors_and_existing_inspect_wire(self):
        for vector in json.loads(FIXTURE.read_text())['vectors']:
            with self.subTest(vector=vector['name']):
                # IDs in all shared vectors are deliberately identical.
                result = self.run_java('digest', vector['input_unit'] * vector['repeat'])
                self.assertEqual(result.returncode, 0, result.stderr)
                digest, stream, inspect = result.stdout.split('\n')[:3]
                self.assertEqual(stream, vector['turn_stream_id'])
                self.assertEqual(digest, vector['request_sha256'])
                frame = json.loads(inspect)
                self.assertEqual(frame['kind'], 'turn.inspect')
                self.assertEqual(frame['payload']['request_sha256'], digest)
                self.assertEqual(frame['payload']['inclusive_cursor'], 0)
                self.assertNotIn('broker_epoch', frame['payload'])
                self.assertNotIn('resume_token', frame['payload'])
        self.assertNotEqual(self.run_java('invalid-surrogate', '').returncode, 0)
        for invalid in ('\0', 'x' * 262145):
            with self.subTest(invalid=repr(invalid[:8])):
                self.assertNotEqual(self.run_java('digest', invalid).returncode, 0)

    def envelope(self, kind, payload):
        vector = self.vector
        frame = {'kind': kind, 'session_id': vector['session_id'], 'task_id': vector['task_id'],
                 'turn_id': vector['turn_id'], 'profile_id': 'owner-open', 'payload': payload,
                 'direction': 'host_to_client', 'stream_id': vector['turn_stream_id'], 'turn_stream_id': vector['turn_stream_id'],
                 'event_id': 'fixture-event-' + ('1' if kind == 'turn.end' else '0'), 'seq': 1 if kind == 'turn.end' else 0,
                 'host_seq': 1 if kind == 'turn.end' else 0, 'broker_request_id': 'fixture-explicit-request',
                 'broker_request_sha256': 'c' * 64, 'broker_request_upstream_seq': 7}
        return {'schema': 'org.trillionnium.owner-open.connection-broker-wire.v1',
                'kind': 'result', 'request_id': 'fixture-explicit-request', 'broker_request_id': 'fixture-explicit-request', 'broker_request_kind': 'turn.start' if kind == 'turn.accepted' else 'turn.inspect',
                'automatic_redispatch': False, 'broker_request_sha256': 'c' * 64, 'broker_request_upstream_seq': 7, 'frame': frame}

    def inspect_payload(self):
        digest = self.vector['request_sha256']
        accepted = self.envelope('turn.accepted', {'status': 'accepted', 'turn_request_sha256': digest})['frame']
        terminal = self.envelope('turn.end', {'status': 'completed', 'turn_request_sha256': digest})['frame']
        return {'status': 'found', 'source': 'durable_event_store', 'request_sha256': digest, 'turn_request_sha256': digest,
                'inclusive_cursor': 0, 'next_cursor': 2, 'total_events': 2,
                'complete': True, 'has_more': False, 'frames': [accepted, terminal],
                'side_effects': False, 'automatic_redispatch': False}

    def evidence(self, obj):
        result = self.run_java('evidence', json.dumps(obj, ensure_ascii=False))
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_acceptance_binds_identity_digest_and_is_not_terminal(self):
        accepted = self.envelope('turn.accepted', {'status': 'accepted',
                                'turn_request_sha256': self.vector['request_sha256']})
        self.assertEqual(self.evidence(accepted), 'turn.accepted:true:false')
        accepted['frame']['payload']['turn_request_sha256'] = 'b' * 64
        self.assertEqual(self.evidence(accepted), 'turn.accepted:false:false')
        spoof = {'kind': 'model.message', 'payload': {'text': json.dumps(accepted)}}
        self.assertEqual(self.evidence(spoof), 'NONE')

    def test_complete_zero_cursor_inspection_requires_all_bound_records(self):
        payload = self.inspect_payload()
        self.assertEqual(self.evidence(self.envelope('turn.inspect.result', payload)), 'turn.inspect.result:true:true')
        without_alias = self.inspect_payload()
        del without_alias['turn_request_sha256']
        self.assertEqual(self.evidence(self.envelope('turn.inspect.result', without_alias)), 'turn.inspect.result:true:true')
        for key, value in (('complete', False), ('has_more', True), ('status', 'not_found')):
            modified = self.inspect_payload()
            modified[key] = value
            if key == 'has_more':
                modified['total_events'] = 3
            self.assertEqual(self.evidence(self.envelope('turn.inspect.result', modified)), 'turn.inspect.result:true:false')
        partial = self.inspect_payload()
        partial['frames'][-1]['kind'] = 'model.message'
        self.assertEqual(self.evidence(self.envelope('turn.inspect.result', partial)), 'turn.inspect.result:true:false')

    def test_actual_known_terminal_vocabulary_and_unknown_outcome_hold(self):
        for status in ('completed', 'cancelled', 'provider_failed', 'provider_panicked', 'host_failed',
                       'unknown_after_disconnect', 'unknown_after_journal_failure', 'unexpected'):
            with self.subTest(status=status):
                payload = self.inspect_payload()
                payload['frames'][-1]['payload']['status'] = status
                closed = status in ('completed', 'cancelled', 'provider_failed', 'provider_panicked', 'host_failed')
                self.assertEqual(self.evidence(self.envelope('turn.inspect.result', payload)),
                                 'turn.inspect.result:true:' + str(closed).lower())
        for mutation in ('accepted-status', 'empty-terminal', 'terminal-digest', 'double-terminal',
                         'after-terminal', 'double-accepted', 'context-digest', 'broker-alias'):
            with self.subTest(mutation=mutation):
                payload = self.inspect_payload()
                envelope = self.envelope('turn.inspect.result', payload)
                if mutation == 'accepted-status': payload['frames'][0]['payload']['status'] = 'garbage'
                if mutation == 'empty-terminal': payload['frames'][-1]['payload'] = {}
                if mutation == 'terminal-digest': payload['frames'][-1]['payload']['turn_request_sha256'] = 'b' * 64
                if mutation == 'context-digest': payload['turn_request_sha256'] = 'b' * 64
                if mutation == 'broker-alias': envelope['broker_request_id'] = 'different-request'
                if mutation == 'double-terminal': payload['frames'].append(payload['frames'][-1])
                if mutation == 'after-terminal': payload['frames'].append(payload['frames'][0])
                if mutation == 'double-accepted': payload['frames'].insert(0, payload['frames'][0])
                payload['next_cursor'] = payload['total_events'] = len(payload['frames'])
                self.assertNotEqual(self.run_java('evidence', json.dumps(envelope)).returncode, 0)

    def test_broker_direction_stream_event_identity_and_sequence_conflicts_reject(self):
        for mutation in ('frame-id', 'frame-hash', 'frame-upstream', 'payload-alias', 'outer-direction',
                         'inner-direction', 'outer-stream', 'inner-stream', 'duplicate-event',
                         'missing-event', 'reversed-host-sequence'):
            with self.subTest(mutation=mutation):
                payload = self.inspect_payload()
                envelope = self.envelope('turn.inspect.result', payload)
                frame = envelope['frame']
                if mutation == 'frame-id': frame['broker_request_id'] = 'other'
                if mutation == 'frame-hash': frame['broker_request_sha256'] = 'b' * 64
                if mutation == 'frame-upstream': frame['broker_request_upstream_seq'] = 8
                if mutation == 'payload-alias': payload['broker_request_id'] = 'other'
                if mutation == 'outer-direction': frame['direction'] = 'client_to_host'
                if mutation == 'inner-direction': payload['frames'][0]['direction'] = 'client_to_host'
                if mutation == 'outer-stream': frame['turn_stream_id'] = 'r5-stream-' + 'b' * 64
                if mutation == 'inner-stream': payload['frames'][0]['stream_id'] = 'other'
                if mutation == 'duplicate-event': payload['frames'][-1]['event_id'] = payload['frames'][0]['event_id']
                if mutation == 'missing-event': del payload['frames'][-1]['event_id']
                if mutation == 'reversed-host-sequence': payload['frames'][-1]['host_seq'] = 0
                self.assertNotEqual(self.run_java('evidence', json.dumps(envelope)).returncode, 0)

    def test_type_duplicates_scope_drift_and_bounds_fail_closed(self):
        mutations = [('complete', 1), ('inclusive_cursor', True), ('inclusive_cursor', 1),
                     ('next_cursor', -1), ('total_events', 2**63), ('next_cursor', 2.0),
                     ('source', 'job_runtime_event'), ('side_effects', True), ('automatic_redispatch', True)]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                payload = self.inspect_payload()
                payload[key] = value
                self.assertNotEqual(self.run_java('evidence', json.dumps(self.envelope('turn.inspect.result', payload))).returncode, 0)
        for key in ('turn_id', 'task_id', 'session_id', 'profile_id'):
            payload = self.inspect_payload()
            payload['frames'][0][key] = 'wrong'
            self.assertNotEqual(self.run_java('evidence', json.dumps(self.envelope('turn.inspect.result', payload))).returncode, 0)
        valid = json.dumps(self.envelope('turn.inspect.result', self.inspect_payload()))
        for invalid in (valid.replace('"complete": true', '"complete": true, "complete": true'),
                        valid + '{}', '[[]]', '"' + '\\ud800' + '"', '[' * 34 + '0' + ']' * 34,
                        '{"a":01}', '{"a":NaN}', 'x' * (1024 * 1024)):
            with self.subTest(invalid=invalid[:50]):
                self.assertNotEqual(self.run_java('evidence', invalid).returncode, 0)


if __name__ == '__main__':
    unittest.main()
