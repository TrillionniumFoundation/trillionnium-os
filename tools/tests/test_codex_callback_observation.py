from __future__ import annotations
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tracemalloc
import unittest

ROOT=Path(__file__).resolve().parents[2]
DIRECTORY=ROOT/'crates/trillionnium-owner-open-provider-jsonl/python'
sys.path.insert(0,str(ROOT/'tools/owner-open'))
if str(DIRECTORY) not in sys.path:sys.path.insert(0,str(DIRECTORY))
SPEC=importlib.util.spec_from_file_location('codex_callback_observation',DIRECTORY/'codex_callback_observation.py')
assert SPEC and SPEC.loader
OBS=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(OBS)


def fixture(payload='YWJj', byte_count=3):
 return {'protocol':'trillionnium.owner-open.provider-jsonl.v1','kind':'tool.result','seq':1,
  'call_id':'call-1','status':'terminal','generation':9,'observation_sha256':'a'*64,
  'terminal':{'kind':'exited','exit_code':7,'stdout_bytes':byte_count,'stderr_bytes':0,'output_truncated':False},
  'registry':{'call_id':'call-1','state':'Terminal','request_sha256':'b'*64},
  'unknown_metadata':{'literal':['  exact\n🙂',False,0]},
  'events':[{'call_id':'call-1','seq':7,'event':{'kind':'output','encoding':'base64','data':payload,'byte_count':byte_count}},
            {'call_id':'call-1','seq':8,'event':{'kind':'terminal','terminal':{'kind':'exited','exit_code':7}}}]}


def raw(value):return json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
def observed(reply):return json.loads(json.loads(reply)['result']['contentItems'][0]['text'])


class CallbackObservationTest(unittest.TestCase):
 def test_small_observations_preserve_all_fields_and_transport_success(self):
  for status in ['terminal','existing','inhibited','unknown','error']:
   with self.subTest(status=status):
    value=fixture();value['status']=status;value['observation_gap']={'domain':'original','unknown':True}
    snapshot=copy.deepcopy(value)
    reply=OBS.native_tool_result_reply('rpc-1',value)
    self.assertEqual(observed(reply),value)
    self.assertEqual(json.loads(reply)['result']['success'],status in ['terminal','existing','inhibited'])
    self.assertEqual(value,snapshot)

 def test_final_envelope_escaping_triggers_gap_before_metadata_loss(self):
  value=fixture('"'*(80*1024),80*1024)
  self.assertLess(len(raw(value)),OBS.MAX_NATIVE_REPLY_BYTES)
  snapshot=copy.deepcopy(value)
  reply=OBS.native_tool_result_reply(20,value)
  self.assertLessEqual(len(reply),OBS.MAX_NATIVE_REPLY_BYTES)
  result=observed(reply)
  for key in ['status','generation','terminal','registry','observation_sha256','unknown_metadata']:
   self.assertEqual(result[key],value[key])
  self.assertEqual(result['events'],[]);self.assertTrue(result['events_truncated'])
  self.assertFalse(result['terminal']['output_truncated'])
  self.assertEqual(result['bridge_observation_gap'],{'domain':'tool_execution_event','call_id':'call-1',
   'first_seq':7,'last_seq':8,'event_count':2,'output_bytes':80*1024,'reason':'native_callback_observation_budget'})
  self.assertEqual(value,snapshot)

 def test_borrowed_large_raw_frame_skips_payload_and_keeps_original_gap(self):
  value=fixture('A'*(2*1024*1024),1572864)
  value['observation_gap']={'domain':'producer_gap','first_seq':1,'last_seq':6,'reason':'unchanged'}
  data=bytearray(raw(value))
  tracemalloc.start()
  try:
   projected=OBS.decode_host_observation(memoryview(data))
   _,peak=tracemalloc.get_traced_memory()
  finally:tracemalloc.stop()
  self.assertLess(peak,2*1024*1024)
  self.assertEqual(projected['events'],[])
  self.assertEqual(projected['observation_gap'],value['observation_gap'])
  self.assertEqual(projected['terminal'],value['terminal'])
  self.assertEqual(projected.bridge_gap['output_bytes'],1572864)
  self.assertEqual(observed(OBS.native_tool_result_reply(20,projected))['bridge_observation_gap'],projected.bridge_gap)

 def test_dense_discarded_event_array_has_global_token_gate_without_dense_dom(self):
  value=fixture('',400000)
  value['events'][0]['event']['bytes']=[0,255]*200000
  data=bytearray(raw(value));del value
  tracemalloc.start()
  try:
   with self.assertRaisesRegex(OBS.ObservationBudgetError,'global value node'):
    OBS.decode_host_observation(data)
   _,peak=tracemalloc.get_traced_memory()
  finally:tracemalloc.stop()
  self.assertLess(peak,2*1024*1024)

 def test_cumulative_nested_key_ownership_is_bounded_before_decode(self):
  value=fixture('A'*(300*1024))
  for i in range(70):value['events'][0]['event']['key-'+str(i)+'K'*16000]=None
  data=raw(value)
  with self.assertRaisesRegex(OBS.ObservationBudgetError,'cumulative key working'):
   OBS.decode_host_observation(data)

 def test_escape_dense_discarded_string_has_cumulative_work_gate(self):
  value=fixture('\\'*140000)
  with self.assertRaisesRegex(OBS.ObservationBudgetError,'cumulative string escape'):
   OBS.decode_host_observation(raw(value))

 def test_numeric_and_unicode_scalar_validation_matches_across_size_boundary(self):
  for padding in ['', 'A'*(300*1024)]:
   good=raw(fixture(padding))
   variants=[good.replace(b'"byte_count":3',b'"byte_count":1e309'),
             good.replace(b'"byte_count":3',b'"byte_count":'+b'9'*129),
             good.replace(b'"data":"',b'"data":"\\ud800',1),
             good.replace(b'"data":"',b'"data":"\\udc00',1),
             good.replace(b'"data":"',b'"data":"\\ud800\\u0041',1)]
   for data in variants:
    with self.subTest(padding=len(padding),data=data[:30]),self.assertRaises(OBS.ObservationBudgetError):
     OBS.decode_host_observation(data)
   paired=good.replace(b'"data":"',b'"data":"\\ud83d\\ude42',1)
   self.assertEqual(OBS.decode_host_observation(paired)['terminal'],fixture()['terminal'])

 def test_producer_bridge_named_metadata_is_preserved_in_separate_content_item(self):
  value=fixture('A'*(300*1024),225*1024);original={'producer':'exact unknown object'}
  value['bridge_observation_gap']=original
  projected=OBS.decode_host_observation(raw(value))
  contents=json.loads(OBS.native_tool_result_reply(20,projected))['result']['contentItems']
  self.assertEqual(len(contents),2)
  self.assertEqual(json.loads(contents[0]['text'])['bridge_observation_gap'],original)
  self.assertEqual(json.loads(contents[1]['text'])['bridge_observation_gap'],projected.bridge_gap)

 def test_missing_unordered_or_cross_call_sequences_never_invent_gap_bounds(self):
  for change in [lambda v:v['events'][0].pop('seq'),
                 lambda v:v['events'][0].update(seq=True),
                 lambda v:v['events'][0].update(seq=-1),
                 lambda v:v['events'][0].update(seq=1<<64),
                 lambda v:v['events'][1].update(seq=7),
                 lambda v:v['events'][1].update(call_id='other-call'),
                 lambda v:v['events'][0]['event'].update(byte_count=True),
                 lambda v:v['events'][0]['event'].update(byte_count=-1)]:
   value=fixture('A'*(300*1024));change(value)
   with self.subTest(value=value['events'][0].get('seq')),self.assertRaises(OBS.ObservationBudgetError):
    OBS.decode_host_observation(raw(value))
   with self.assertRaises(OBS.ObservationBudgetError):OBS.native_tool_result_reply(20,value)

 def test_output_count_overflow_is_explicit_failure(self):
  value=fixture('A'*(300*1024),OBS.U64_MAX)
  value['events'][1]['event']={'kind':'output','byte_count':1,'data':'YQ=='}
  with self.assertRaises(OBS.ObservationBudgetError):OBS.decode_host_observation(raw(value))

 def test_small_frames_use_generic_strict_allocation_gated_decoder(self):
  value=fixture();self.assertEqual(OBS.decode_host_observation(raw(value)),value)
  dense=b'{"kind":"tool.result","call_id":"call-1","unknown":['+b'0,'*40000+b'0]}'
  with self.assertRaises(OBS.ProviderRuntimeError):OBS.decode_host_observation(dense)

 def test_skipped_large_payload_still_rejects_duplicate_and_malformed_json(self):
  good=raw(fixture('A'*(300*1024)))
  variants=[good.replace(b'"encoding":"base64"',b'"encoding":"base64","encoding":"duplicate"'),
            good.replace(b'"byte_count":3',b'"byte_count":03'),
            good.replace(b'"byte_count":3',b'"byte_count":NaN'),
            good.replace(b'"data":"AAA',b'"data":"\xffAA'),
            good.replace(b'"data":"AAA',b'"data":"\x01AA'),
            good.replace(b'"data":"AAA',b'"data":"\\qAA'),
            good+b'{}',good[:-1]+b',}']
  for data in variants:
   with self.subTest(prefix=data[:30]),self.assertRaises(OBS.ProviderRuntimeError):OBS.decode_host_observation(data)

 def test_metadata_and_raw_budget_exhaustion_are_explicit(self):
  value=fixture('A'*(300*1024));value['unknown_metadata']='M'*(300*1024)
  with self.assertRaisesRegex(OBS.ObservationBudgetError,'control metadata'):
   OBS.decode_host_observation(raw(value))
  with self.assertRaisesRegex(OBS.ObservationBudgetError,'control metadata'):
   OBS.native_tool_result_reply(20,value)
  with self.assertRaisesRegex(OBS.ObservationBudgetError,'raw byte budget'):
   OBS.decode_host_observation(raw(fixture()),maximum_raw_bytes=10)

 def test_empty_events_or_whitespace_do_not_invent_truncation(self):
  value=fixture();value['events']=[]
  projected=OBS.decode_host_observation(raw(value)+b' '*OBS.MAX_NATIVE_REPLY_BYTES)
  self.assertIsNone(projected.bridge_gap);self.assertNotIn('events_truncated',projected)
  self.assertEqual(dict(projected),value)
  value.pop('events')
  projected=OBS.decode_host_observation(raw(value)+b' '*OBS.MAX_NATIVE_REPLY_BYTES)
  self.assertEqual(dict(projected),value)

 def test_large_non_tool_frame_and_too_deep_metadata_are_rejected(self):
  value=fixture('A'*(300*1024));value['kind']='turn.start'
  with self.assertRaisesRegex(OBS.ObservationBudgetError,'only tool.result'):
   OBS.decode_host_observation(raw(value))
  data=raw(fixture('A'*(300*1024)))[:-1]+b',"deep":'+b'['*65+b'0'+b']'*65+b'}'
  with self.assertRaisesRegex(OBS.ObservationBudgetError,'nesting'):
   OBS.decode_host_observation(data)

if __name__=='__main__':unittest.main()
