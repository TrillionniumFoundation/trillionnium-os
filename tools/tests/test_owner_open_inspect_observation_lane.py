"""Host-only protocol fixtures. No phone, provider, model, or private-state repair."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'owner-open'))
from owner_open_broker_admission_v2 import BrokerAdmissionMixin, inspection_observation_key
from owner_open_broker_common import BrokerError, canonical
from owner_open_broker_mux import ordering_key_for_frame
from test_owner_open_broker_mux_integration import Harness, COMMON, read_line, send

SCOPE = {'session_id':'session-readback','profile_id':'owner-open','task_id':'task-readback',
         'turn_id':'turn-original','turn_stream_id':'stream-original'}

def inspect(kind='turn.inspect',seq=1):
    payload={**SCOPE,'request_sha256':'a'*64,'inclusive_cursor':0,'limit':256}
    if kind=='call.inspect':payload['call_id']='original-call'
    return {'kind':kind,'seq':seq,'direction':'client_to_host','payload':payload}

class ClosedInspectionGrammar(unittest.TestCase):
    def key(self,frame,expected=None,job=None):
        ordinary=ordering_key_for_frame(frame,'client-fixture')
        return inspection_observation_key(frame,expected or frozenset({frame['kind']+'.result','host.error'}),job,ordinary)

    def test_distinct_observation_lane_keeps_original_effect_key_and_preimage(self):
        frame=inspect(); ordinary=ordering_key_for_frame(frame,'a'); observation=self.key(frame)
        self.assertTrue(observation.startswith('observation:v1:'))
        self.assertNotEqual(observation,ordinary)
        cancel={'kind':'turn.cancel','payload':SCOPE}
        self.assertEqual(ordering_key_for_frame(cancel,'b'),ordinary)
        expected=frozenset({'turn.inspect.result','host.error'})
        original=BrokerAdmissionMixin._request_preimage(frame,expected,None,30000,ordinary)
        self.assertEqual(original['ordering_key'],ordinary)
        self.assertNotEqual(hashlib.sha256(canonical(original)).hexdigest(),hashlib.sha256(canonical(
            {**original,'ordering_key':observation})).hexdigest())
        self.assertIsNone(inspection_observation_key(cancel,frozenset({'host.error'}),None,ordinary))
        self.assertTrue(self.key(inspect('call.inspect')).startswith('observation:v1:'))

    def test_arbitrary_effect_payload_or_response_kind_cannot_enter_observation_lane(self):
        for field in ['user_input','command','argv','operation_id','job_id','automatic_redispatch','call_id']:
            frame=inspect();frame['payload'][field]='effect-shaped-field'
            with self.subTest(field=field),self.assertRaises((BrokerError,RuntimeError)):self.key(frame)
        for expected in [frozenset({'tool.result','host.error'}),frozenset({'turn.inspect.result'}),
                         frozenset({'turn.inspect.result','host.error','turn.accepted'})]:
            with self.assertRaises(BrokerError):self.key(inspect(),expected)
        with self.assertRaises(BrokerError):self.key(inspect(),job='job-other')

    def test_missing_digest_scope_alias_and_unbounded_cursor_fail_closed(self):
        for field in ['session_id','profile_id','task_id','turn_id','turn_stream_id','request_sha256']:
            frame=inspect();del frame['payload'][field]
            with self.subTest(field=field),self.assertRaises((BrokerError,RuntimeError)):self.key(frame)
        for field,value in [('inclusive_cursor',True),('inclusive_cursor',-1),('inclusive_cursor',2**64),
                            ('limit',0),('limit',257),('request_sha256','not-a-digest')]:
            frame=inspect();frame['payload'][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(BrokerError):self.key(frame)
        frame=inspect();frame['payload']['stream_id']='other'
        with self.assertRaises((BrokerError,RuntimeError)):self.key(frame)
        frame=inspect();frame['payload']['turn_request_sha256']='b'*64
        with self.assertRaises(BrokerError):self.key(frame)

UPSTREAM = '#!/usr/bin/env python3\n'+COMMON+r'''
handshake()
for line in sys.stdin:
    frame=json.loads(line); remember(frame)
    if frame['kind']=='turn.cancel':
        continue  # Intentional unresolved control fixture, not an actual model cancellation.
    corr=correlation(frame)
    payload={'source':'fixture_readonly','side_effects':False,'automatic_redispatch':False,**corr}
    value={'kind':frame['kind']+'.result','direction':'host_to_client','seq':host_sequence[0],
           'payload':payload,**corr}
    host_sequence[0]+=1
    for name in ('broker_request_id','broker_request_sha256','broker_request_upstream_seq'):
        value[name]=frame[name]
    print(json.dumps(value),flush=True)
'''

class EffectFencePreservedReadback(Harness,unittest.TestCase):
    upstream_source=UPSTREAM

    def test_original_cancel_unknown_is_preserved_while_new_inspect_is_read_only(self):
        sock=self.connect('client-readback')
        try:
            cancel={'kind':'turn.cancel','seq':0,'direction':'client_to_host','payload':SCOPE}
            request={'kind':'request','request_id':'original-cancel','frame':cancel,
                     'expected_kinds':['turn.cancel.accepted','host.error'],'timeout_ms':120}
            send(sock,request)
            unknown=read_line(sock)
            self.assertEqual(unknown['code'],'unknown_after_timeout')
            audit=Path(str(self.descriptor)+'.audit.jsonl')
            oldbytes=audit.read_bytes()
            # Same original request is resolved to the exact retained UNKNOWN,
            # even if a reconnect-local sequence changes. It is never forwarded again.
            duplicate=copy.deepcopy(request);duplicate['frame']['seq']=1
            send(sock,duplicate);self.assertEqual(read_line(sock),unknown)
            frame=inspect(seq=1)
            send(sock,{'kind':'request','request_id':'new-readonly-inspect','frame':frame,
                       'expected_kinds':['turn.inspect.result','host.error'],'timeout_ms':1000})
            result=read_line(sock)
            # The existing broker broadcasts a successfully journalled terminal
            # observation before its exact owner result. Neither is an effect.
            if result['kind']=='observation':
                self.assertEqual(result['frame']['broker_request_id'],'new-readonly-inspect')
                result=read_line(sock)
            self.assertEqual(result['kind'],'result',result)
            self.assertEqual(result['frame']['kind'],'turn.inspect.result')
            self.assertTrue(result['broker_ordering_key'].startswith('observation:v1:'))
            self.assertFalse(result['frame']['payload']['side_effects'])
            self.assertTrue(audit.read_bytes().startswith(oldbytes))
            # A new effect still hits the original unchanged fence.
            nextcancel=copy.deepcopy(request);nextcancel['request_id']='new-cancel';nextcancel['frame']['seq']=2
            send(sock,nextcancel)
            self.assertEqual(read_line(sock)['code'],'ordering_key_uncertain')
            send(sock,duplicate);self.assertEqual(read_line(sock),unknown)
            forwarded=[json.loads(line)['frame'] for line in self.record.read_text().splitlines()]
            self.assertEqual([f['kind'] for f in forwarded],['hello','turn.cancel','turn.inspect'])
        finally:sock.close()

if __name__=='__main__':unittest.main()
