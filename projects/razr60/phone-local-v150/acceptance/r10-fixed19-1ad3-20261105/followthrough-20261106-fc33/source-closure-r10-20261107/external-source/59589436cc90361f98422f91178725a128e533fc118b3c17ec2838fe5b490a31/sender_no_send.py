#!/usr/bin/env python3
"""Pure host audit of the exact diag02 sender failure before Send.

This is an independent non-native verifier. It never calls the frozen sender,
touches a device, creates a native identity, or claims a parent wait receipt.
Private draft/request values and native request digests are compared in memory
and are never included in the result.
"""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import types
import zlib

B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
LABEL = 'root-r10-neg01-7c907661-diag02'
NONCE = '8daaaad6a322963e87973613c1fac762'
F = B/'native-guard-root-chains-r10-r1'/LABEL
HOST = B/'diag02-complete-sender-originals-7c907661-r1'
P4 = '/home/alex/codex-hepta-natural-'+LABEL+'-root-v150'
RUNTIME = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-codec-diagnostic-ff0-01/runtime')
ROOT_CHAIN = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-codec-diagnostic-ff0-01/root-chain')
SCHEMA = 'hepta.native-guard.diag02.sender-no-send-plan.v1'
MAX = 8*1024*1024
HASH = re.compile(r'[0-9a-f]{64}')
EMPTY = hashlib.sha256(b'').hexdigest()
ROOT_PLAN = {'bytes': 4853,
 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag02/ROOT-PLAN.original.json',
 'sha256': '6b61d2f178c3238c6d4a6508e171874ffb3e6811a4f9dc26bb24c2d00e53ac27'}
ROOT_FAILURE = {'bytes': 13590,
 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag02/ROOT-FAILURE.json',
 'sha256': '6fda21d802643191763af4e980eace98160bb49f68e9db509762aecd558701c2'}
INDEX = {'bytes': 12880,
 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/diag02-complete-sender-originals-7c907661-r1/RESULT.json',
 'sha256': 'f2ca35bdc093388f13ca41f23776177cf6b17eb2ff6d9a8fcec3f01a978b1298'}
HOST_CLOSURE = {'bytes': 12880,
 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/diag02-complete-sender-originals-7c907661-r1/RESULT.json',
 'sha256': 'f2ca35bdc093388f13ca41f23776177cf6b17eb2ff6d9a8fcec3f01a978b1298'}
RUNTIME_MANIFEST = {'bytes': 21251,
 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-codec-diagnostic-ff0-01/runtime/MANIFEST.json',
 'sha256': '8e5ba081f1780da2ec73a3c103e7a27f6a0ba4e6e15ceab502fa8221ed410863'}
CHAIN_MANIFEST = {'bytes': 15317,
 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8-codec-diagnostic-ff0-01/root-chain/SOURCE-MANIFEST.json',
 'sha256': '9d5a8b60e0b4570b5c87b5b7219399e482106cff78bddfd89176be9824fc5ded'}
ACTOR = {'bytes': 82969,
 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/root-r10-neg01-7c907661-diag02.actor.py',
 'sha256': 'f86d31190bf3b33068f166bef501bcdc47cdad71771e009830a2cd454ee53eda'}
ONCE = {'bytes': 1182,
 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/root-r10-neg01-7c907661-diag02.local-once.json',
 'sha256': '60a293b1590d6bc1e79b64e1fe3a178092e52ca829262787d35b952fcfa570c9'}
SEND_RESULT = {'bytes': 680,
 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/root-r10-neg01-7c907661-diag02.send-result.json',
 'sha256': '444c0d2549599c3b52c1389f60e314b12a903708b74896a990716c7e7bfec67a'}
EXPORT = {'bytes': 3001971,
 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/diag02-complete-sender-originals-7c907661-r1/P4-EXPORT.original.json',
 'sha256': 'abfc8d3987805930fa163771f8004576029688b1a9b0ea6329107261498d9d55'}
READER = {'bytes': 48950,
 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/read_diag02_complete_sender_7c907661_r1.py',
 'sha256': '9a299c5551121a6789e42a1eab48028a6f69ae33c278ea894a2d90fbf8cb5732'}
DRIVER = {'bytes': 20328,
 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/root-policy-driver-transport-fix-7c907661-r1/candidate02/source/run_runtime_properties_policy_once.py',
 'sha256': '7711a81150f445d7b6fcc1a57633d7e6d5aaad3a60d98b150dad6fef2f20c7d1'}
TRANSPORT = {'bytes': 51032,
 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/root-policy-driver-transport-fix-7c907661-r1/candidate02/reference/run_component_root_once.r4.transport_fixed.py',
 'sha256': 'cb6bd4afb6010c68e2ef1c633dabe1aec61a72a627b85f5ca4c0847c704d2336'}
HOST_INPUT_NAMES = ['CHILD.json',
 'INTENT.json',
 'OUTPUT-CAPTURE.json',
 'actor',
 'once',
 'root-failure',
 'send-result',
 'stderr.original',
 'stdout.original']
PREVIOUS = {'bytes': 1432,
 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag01/ACTUAL-PREVIOUS-INPUT.json',
 'sha256': '0f8cf33cf9e6d92c92a7bf465d65bafe537101bc4ee77b1b8faf79e63d39e1e5'}
OWNED_CHILD_FAILURE = {'bytes': 2857,
 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag02/sender-execute/OWNED-CHILD-FAILURE.json',
 'sha256': '5b088f610f5ae8c90b54d8814deac75e69ef1c48e2428acb745416aea47581ec'}
READY5354_RESULT = {'bytes': 4005,
 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/diag02-ready53-54-existing-p4-originals-7c907661-r1/RESULT.json',
 'sha256': '1c191cafb5a6f8826ce371e6024cedcac41a920066f5ba696511754f806d223e'}
READY5354 = [{'bytes': 35201,
  'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/diag02-ready53-54-existing-p4-originals-7c907661-r1/sender__COMPONENT-READY-0053.original-read.json',
  'sha256': 'd85dd29164c540f88ab578c422106e8eb20e9308f50f08a63f27844b167d4a61'},
 {'bytes': 35130,
  'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/diag02-ready53-54-existing-p4-originals-7c907661-r1/sender__COMPONENT-READY-0054.original-read.json',
  'sha256': '961b323dd8f06b4a3e84a075a65064482a79251293d3cd6f17b172c4314e9c8c'}]
READY54_STDERR = ('Traceback (most recent call last):\n'
 '  File "<string>", line 46, in <module>\n'
 '  File '
 '"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag02/package/source/component_common.py", '
 'line 385, in absent_groups\n'
 "    need(not members, 'owned group/session still observed')\n"
 '  File '
 '"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag02/package/source/component_common.py", '
 'line 47, in need\n'
 '    raise ValueError(reason)\n'
 'ValueError: owned group/session still observed\n')
SENDER_PIN = (40952, 'aafd40345c6dc35b7b7d34ab8b04c860ebf17d326d842ed733d0404cd0a051ad')
DECODER_PIN = (4116, 'a3e619926a4688ebfefd55ad1074cb386240f9828613781b7fd547bcf0c70073')
COORDINATOR_PIN = (72384, '1b0e69e10a51b17405c4db49d7bd08d5f18b1146421de2d36850340bc56669cc')

def need(ok, reason):
    if not ok:
        raise ValueError(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def enc(value):
    return (json.dumps(value,sort_keys=True,ensure_ascii=False,
                       separators=(',',':'),allow_nan=False)+'\n').encode()

def strict(raw):
    def pairs(items):
        result = {}
        for key,value in items:
            need(key not in result,'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError('nonfinite JSON')))

def meta(info):
    return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
            info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]

def descriptor(path, size, digest):
    return {'path':str(path),'bytes':size,'sha256':digest}

# All current exact descriptors are defined together above the pure helpers.

def default_plan():
    return {'schema':SCHEMA,'root_plan':dict(ROOT_PLAN),'sender_index':dict(INDEX),
            'host_sender_closure':dict(HOST_CLOSURE)}

def validate_plan(plan):
    need(type(plan) is dict and set(plan)=={'schema','root_plan','sender_index','host_sender_closure'}
         and plan==default_plan(),'only the fixed original diag02 sender plan is supported')
    return plan

def file_descriptor(row):
    need(type(row) is dict and set(row)=={'path','bytes','sha256'}
         and isinstance(row['path'],str) and Path(row['path']).is_absolute()
         and type(row['bytes']) is int and 0<=row['bytes']<=MAX
         and isinstance(row['sha256'],str) and HASH.fullmatch(row['sha256']),
         'explicit bounded original descriptor required')
    return row

def full_metadata(value, directory=False):
    need(type(value) is list and len(value)==9 and all(type(n) is int for n in value)
         and value[0]>=0 and value[1]>0 and value[3]>=0 and value[4]>=0
         and value[5]>=1 and value[6]>=0
         and (stat.S_ISDIR(value[2]) if directory else stat.S_ISREG(value[2])),
         'original nine-field metadata differs')
    if not directory:
        need(value[5]==1,'single-link original file required')
    return value

def directory_original(originals,path,names,expected_metadata=None):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True)==path,
         'canonical original directory required')
    before=path.lstat()
    need(stat.S_ISDIR(before.st_mode) and not stat.S_ISLNK(before.st_mode),
         'original directory required')
    actual=sorted(os.listdir(path))
    need(actual==sorted(names) and len(actual)==len(set(actual)) and len(actual)<=128,
         'original directory contains missing or additional entries')
    after=path.lstat()
    need(meta(before)==meta(after),'original directory changed during name census')
    if expected_metadata is not None:
        need(meta(before)==full_metadata(expected_metadata,True),
             'original directory no longer matches its recorded metadata')
    record={'metadata':meta(before),'names':actual}
    cache=getattr(originals,'sender_no_send_directories',None)
    if cache is None:
        cache={}; originals.sender_no_send_directories=cache
    need(str(path) not in cache or cache[str(path)]==record,
         'original sender directory changed between audit stages')
    cache[str(path)]=record

def recheck_sender_directories(originals):
    for path,row in dict(getattr(originals,'sender_no_send_directories',{})).items():
        directory_original(originals,path,row['names'],row['metadata'])

def source_top_assignments(raw):
    tree=ast.parse(raw)
    keys={'label','expected','preserved_draft','previous_identity','previous_digest',
          'previous_status','known_all_prior_tools_confirmed','evidence_mode',
          'component_binding','retirement_binding','retirement_prior','reset_probe',
          'COMPONENT_READY_PROBE_SOURCE'}
    values={}
    for node in tree.body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            key=node.targets[0].id
            if key in keys:
                need(key not in values,'generated actor reassigns a bound input')
                values[key]=ast.literal_eval(node.value)
    need(set(values)==keys,'generated actor binding inventory differs')
    return tree,values

def source_send_order(tree):
    rendezvous=[n for n in ast.walk(tree) if isinstance(n,ast.Call)
                and isinstance(n.func,ast.Name) and n.func.id=='wait_component_rendezvous']
    taps=[n for n in ast.walk(tree) if isinstance(n,ast.Call)
          and isinstance(n.func,ast.Name) and n.func.id=='tap'
          and len(n.args)==1 and isinstance(n.args[0],ast.Name) and n.args[0].id=='send']
    def saves(name):
        return [n for n in ast.walk(tree) if isinstance(n,ast.Call)
                and isinstance(n.func,ast.Name) and n.func.id=='save' and n.args
                and isinstance(n.args[0],ast.Constant) and n.args[0].value==name]
    once=saves('SEND.once.json'); intent=saves('SEND.MONOTONIC-INTENT.json')
    need(len(rendezvous)==len(taps)==len(once)==len(intent)==1,
         'unique original rendezvous and Send sites required')
    main=[n for n in tree.body if isinstance(n,ast.Try) and
          n.lineno<rendezvous[0].lineno<taps[0].lineno<=n.end_lineno]
    need(len(main)==1 and rendezvous[0].lineno<once[0].lineno<intent[0].lineno<taps[0].lineno,
         'original Send is not strictly after the component rendezvous')
    branches=[n for n in ast.walk(main[0]) if isinstance(n,ast.If)
              and isinstance(n.test,ast.Compare)
              and ast.unparse(n.test)=='component_binding is not None'
              and any(rendezvous[0] is child for child in ast.walk(n))]
    need(len(branches)==1 and branches[0].end_lineno<once[0].lineno,
         'component rendezvous does not dominate the unique Send path')
    functions={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
    ready=functions['read_component_ready']
    asserts=[n for n in ast.walk(ready) if isinstance(n,ast.Assert)
             and isinstance(n.msg,ast.Constant)
             and n.msg.value=='Fixed component ready observation failed; no Send']
    need(len(asserts)==1 and ast.unparse(asserts[0].test)=="result['rc'] == 0",
         'original ready failure no longer raises before Send')
    return {'unique_send_tap_sites':1,'rendezvous_call_line':rendezvous[0].lineno,
            'send_once_line':once[0].lineno,'send_intent_line':intent[0].lineno,
            'send_tap_line':taps[0].lineno,'ready_nonzero_raises_before_send':True}

def unicode_wire(wire,operation,wanted,allowed_before):
    need(type(wire) is dict and set(wire)=={'command','rc','route','stdout','stderr'}
         and type(wire['rc']) is int and wire['rc']==0 and wire['stderr']==''
         and wire['route']==[5037,'23'],
         'original Unicode input wire did not return zero')
    args=shlex.split(wire['command'])
    prefix=['CLASSPATH=/data/local/tmp/hepta-unicode-v148-r2/input.jar','app_process',
            '/system/bin','org.trillionnium.hepta.input.UnicodeInput','set-text']
    names=['--operation-id','--display','--package','--view-id','--expected-text-b64','--text-b64']
    need(args[:5]==prefix and len(args)==5+2*len(names)
         and args[5::2]==names,'original Unicode command argument shape differs')
    options=dict(zip(args[5::2],args[6::2]))
    def decode(value):
        return b'' if value=='-' else base64.b64decode(value,validate=True)
    before=decode(options['--expected-text-b64'])
    target=decode(options['--text-b64'])
    need(options['--operation-id']==operation and options['--display']=='0'
         and options['--package']=='org.trillionnium.owneropen'
         and options['--view-id']=='org.trillionnium.owneropen:id/ui_prompt'
         and target==wanted and before in allowed_before,
         'original Unicode command did not preserve the exact intended CAS')
    answer=strict(wire['stdout'])
    need(answer.get('schema')=='hepta.focused-unicode-input.v1'
         and answer.get('status') in ('set_verified','already_exact')
         and answer.get('operation_id')==operation and answer.get('display_id')==0
         and answer.get('package')=='org.trillionnium.owneropen'
         and answer.get('view_id')=='org.trillionnium.owneropen:id/ui_prompt'
         and answer.get('own_automation_disconnected') is True
         and answer.get('requested_utf8_sha256')==answer.get('after_utf8_sha256')==sha(wanted)
         and answer.get('before_utf8_sha256')==sha(before)
         and base64.b64decode(answer['readback_text_b64'],validate=True)==wanted,
         'original Unicode independent readback/CAS differs')
    return {'wire_returncode':0,'exact_target_and_readback_equal':True,
            'exact_expected_before_digest_equal':True,
            'own_automation_disconnected':True}

def canonical_retention(value):
    return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()


def literal_source_bindings(raw, keys):
    values={}
    for node in ast.parse(raw).body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            name=node.targets[0].id
            if name in keys:
                need(name not in values,'reviewed source reassigns a fixed binding')
                values[name]=ast.literal_eval(node.value)
    need(set(values)==set(keys),'reviewed source fixed binding set differs')
    return values


def retained_sender_originals(originals, read, idx):
    need(idx['schema']=='hepta.diag02.complete-sender-retention-result.v1'
         and idx['state']=='COMPLETE_ORIGINAL_SENDER_AND_MAC_ABSENCE_RETAINED_NOT_CLOSURE'
         and idx['existing_sender_originals']==82 and idx['retained_sender_bytes']==2224064
         and idx['native_closed'] is False and idx['global_unknown_effect_count'] is None
         and idx['old_sender_wait_claimed'] is False and idx['automatic_retry'] is False
         and idx['component_qualified'] is False and idx['business_qualified'] is False
         and all(type(idx[k]) is int and idx[k]==0 for k in
                 ('phone_calls','native_sends','sender_starts','signals','p4_file_writes'))
         and idx['host_cleanup_complete'] is True
         and idx['host_output_cleanup']=={'host_children':[],'stream_cleanup_errors':[]},
         'fixed complete sender retention is not a successful read-only observation')
    reader_raw=read(READER)
    need(read(descriptor(HOST/'SOURCE.original.py',READER['bytes'],READER['sha256']))==reader_raw,
         'actual retained reader source differs from its exact installed source')
    bindings=literal_source_bindings(reader_raw,{'INPUTS','EXPECTED_DIRECTORY','REMOTE'})
    input_pins=bindings['INPUTS']; expected=bindings['EXPECTED_DIRECTORY']; remote=bindings['REMOTE']
    need(type(input_pins) is dict and set(input_pins)==set(HOST_INPUT_NAMES)
         and type(remote) is str and 0<len(remote.encode('utf-8'))<=262144,
         'fixed reader input or read-only program bindings differ')
    need(type(idx['actual_original_host_inputs']) is dict
         and set(idx['actual_original_host_inputs'])==set(input_pins),
         'all nine original Mac sender inputs are required')
    controls={}
    directory_original(originals,HOST/'host-originals',sorted(input_pins))
    for name in sorted(input_pins):
        row=input_pins[name]; file_descriptor(row)
        bound=idx['actual_original_host_inputs'][name]
        need(set(bound)=={'path','bytes','sha256','metadata'}
             and {k:bound[k] for k in row}==row,'retained original Mac input descriptor differs')
        full_metadata(bound['metadata'])
        need(bound['metadata'][6]==row['bytes'],'original Mac input metadata size differs')
        body=read(row)
        need(meta(Path(row['path']).lstat())==bound['metadata']
             and read(descriptor(HOST/'host-originals'/name,row['bytes'],row['sha256']))==body,
             'original Mac sender input changed or retained copy differs')
        controls[name]=body
    need(input_pins['actor']==ACTOR and input_pins['once']==ONCE
         and input_pins['send-result']==SEND_RESULT and input_pins['root-failure']==ROOT_FAILURE,
         'reader inputs do not bind this exact failed sender')
    intent={'schema':'hepta.diag02.sender-complete-read-intent.v1','original_sender_pid':50521,
            'maximum_remote_reads':1,'maximum_mac_ps_calls':2,'phone_calls':0,'native_sends':0,
            'signals':0,'automatic_retry':False,'input_pins':input_pins,'original_sender_wait_claimed':False}
    raw=canonical_retention(intent)
    need(read(descriptor(HOST/'INTENT.json',len(raw),sha(raw)))==raw,
         'actual one-read/two-census retention intent differs')
    need(idx['p4_export']==EXPORT,'complete P4 raw export descriptor differs')
    export_raw=read(EXPORT); export=strict(export_raw)
    need(export['schema']=='hepta.diag02.complete-existing-sender-export.v1'
         and export['state']=='ALL_EXISTING_SENDER_ORIGINALS_RETAINED_NOT_CLOSURE'
         and export['label']==LABEL and export['nonce']==NONCE
         and export['file_count']==82 and export['total_bytes']==2224064
         and export['all_bytes_and_full9_rechecked'] is True
         and export['complete_names_rechecked'] is True
         and export['native_closed'] is False and export['global_unknown_effect_count'] is None
         and export['business_qualified'] is False and export['component_qualified'] is False
         and all(type(export[k]) is int and export[k]==0 for k in
                 ('phone_calls','native_sends','sender_starts','process_signals','remote_file_writes'))
         and type(export['started_unix_ns']) is int and type(export['finished_unix_ns']) is int
         and 0<export['started_unix_ns']<=export['finished_unix_ns'],
         'original complete P4 export scope or bookends differ')
    need(export['directory_before']==export['directory_after']==
         {k:expected[k] for k in ('path','metadata','names')}
         and expected['path']==P4 and expected['kind']=='directory' and expected['name_bookend_equal'] is True,
         'both complete P4 name and full9 bookends must match the reviewed prior observation')
    full_metadata(expected['metadata'],True)
    names=expected['names']
    need(type(names) is list and len(names)==82 and names==sorted(set(names))
         and all(type(name) is str and Path(name).name==name and name not in ('.','..') for name in names)
         and not any(name.startswith('SEND') or re.fullmatch(r'LATENCY-[0-9]+\.original-read\.json',name)
                     for name in names),'original sender name census contains a Send artifact')
    need(type(export['files']) is list and len(export['files'])==82
         and [row['name'] for row in export['files']]==names
         and set(expected['entries'])==set(names),'all 82 originals and names are required')
    directory_original(originals,HOST/'sender-files',names)
    raws={}
    for row in export['files']:
        name=row['name']
        need(set(row)=={'name','path','bytes','sha256','metadata','base64'}
             and row['path']==P4+'/'+name and expected['entries'][name]['kind']=='file'
             and row['metadata']==expected['entries'][name]['metadata'],
             'P4 original path or full9 differs from the exact reviewed census')
        full_metadata(row['metadata'])
        need(type(row['bytes']) is int and 0<=row['bytes']<=65536
             and row['metadata'][6]==row['bytes'] and type(row['base64']) is str,
             'bounded P4 original size or encoding differs')
        body=base64.b64decode(row['base64'],validate=True)
        need(len(body)==row['bytes'] and sha(body)==row['sha256']
             and base64.b64encode(body).decode('ascii')==row['base64'],
             'complete canonical P4 original byte envelope differs')
        need(read(descriptor(HOST/'sender-files'/name,row['bytes'],row['sha256']))==body,
             'retained Mac copy differs from original P4 bytes')
        raws[name]=body
    need(sum(map(len,raws.values()))==2224064,'all original sender byte totals differ')
    previous_reads=strict(read(READY5354_RESULT))
    need(previous_reads['all_retained_originals_bookended'] is True
         and previous_reads['label']==LABEL and previous_reads['nonce']==NONCE
         and len(previous_reads['files'])==2,'actual5937 complete original reference differs')
    by_name={row['name']:row for row in export['files']}
    for old,row in zip(previous_reads['files'],READY5354):
        file_descriptor(row)
        name=old['name'].removeprefix('sender/')
        need(name in ('COMPONENT-READY-0053.original-read.json','COMPONENT-READY-0054.original-read.json')
             and old['exists'] is True and old['mac_original']==row
             and old['path']==by_name[name]['path'] and old['metadata']==by_name[name]['metadata']
             and (old['bytes'],old['sha256'])==(by_name[name]['bytes'],by_name[name]['sha256'])
             and read(row)==raws[name],'actual5988 final two originals differ from actual5937')
    need([x['name'] for x in previous_reads['files']]==
         ['sender/COMPONENT-READY-0053.original-read.json','sender/COMPONENT-READY-0054.original-read.json'],
         'actual5937 final original ordering differs')
    return raws,names,controls,remote,export_raw


def verify_retention_steps(read, idx, remote, export_raw):
    phases=['mac-sender-absence-00','read-all-existing-diag02-sender','mac-sender-absence-01']
    need(type(idx['steps']) is list and len(idx['steps'])==3
         and [row['phase'] for row in idx['steps']]==phases,
         'all three actual joined retention steps are required')
    transport_raw=read(TRANSPORT)
    ssh=literal_source_bindings(transport_raw,{'SSH'})['SSH']
    need(type(ssh) is list and all(type(arg) is str for arg in ssh),'fixed retained transport SSH binding differs')
    read(DRIVER)
    for index,step in enumerate(idx['steps']):
        phase=phases[index]; d=HOST/phase
        need(set(step)=={'state','phase','pid','returncode','stdout','stderr','automatic_retry'}
             and step['state']=='ORIGINAL_HOST_CHILD_JOINED' and step['automatic_retry'] is False
             and type(step['pid']) is int and step['pid']==(95313,95314,95329)[index]
             and type(step['returncode']) is int and step['returncode']==0,
             'retention child is not the actual independently joined read-only child')
        body=canonical_retention(step)
        need(read(descriptor(d/'RESULT.json',len(body),sha(body)))==body,
             'retention result does not equal the retained joined step')
        need(step['stdout']['path']==str(d/'stdout.original')
             and step['stderr']['path']==str(d/'stderr.original')
             and read(step['stderr'])==b'','retention original stream paths or stderr differ')
        stdout=read(step['stdout'])
        expected={'schema':'hepta.native-guard.root-host-command.v1','phase':phase,
                  'argv':ssh if index==1 else ['/bin/ps','-axo','pid=,ppid=,pgid=,stat='],
                  'stdin_sha256':sha(remote.encode('utf-8')) if index==1 else None,
                  'maximum_starts':1,'maximum_wait_seconds':45 if index==1 else 10,
                  'automatic_retry':False,'signals_on_timeout':False,
                  'deadline_scope':'popen_start_through_actual_join',
                  'input_transport':'retained_readonly_regular_fd_child_reads_within_execution_budget',
                  'hard_bound_on_filesystem_spawn_or_cleanup':False}
        body=canonical_retention(expected)
        need(read(descriptor(d/'INTENT.json',len(body),sha(body)))==body,
             'actual retention process intent differs from the pinned reader and transport')
        if index==1:
            body=remote.encode('utf-8')
            need(read(descriptor(d/'stdin.original',len(body),sha(body)))==body,
                 'retained P4 read-only stdin differs from the exact reviewed reader source')
            wire=strict(stdout)
            need(type(wire) is dict and set(wire)=={'schema','encoding','report_bytes','report_sha256',
                 'gzip_bytes','gzip_sha256','base64'}
                 and wire['schema']=='hepta.diag02.complete-sender-wire.v1'
                 and wire['encoding']=='gzip+base64'
                 and type(wire['report_bytes']) is int and 0<wire['report_bytes']<=MAX
                 and type(wire['gzip_bytes']) is int and 0<wire['gzip_bytes']<=MAX,
                 'bounded original complete-sender wire schema differs')
            packed=base64.b64decode(wire['base64'],validate=True)
            need(len(packed)==wire['gzip_bytes'] and sha(packed)==wire['gzip_sha256']
                 and base64.b64encode(packed).decode('ascii')==wire['base64'],
                 'original complete-sender gzip byte envelope differs')
            decoder=zlib.decompressobj(16+zlib.MAX_WBITS)
            decoded=decoder.decompress(packed,wire['report_bytes']+1)
            need(decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data
                 and len(decoded)==wire['report_bytes'] and sha(decoded)==wire['report_sha256']
                 and decoded==export_raw,'retained raw P4 response differs from the canonical host export')


def verify_original_sender_capture(originals, read, root, controls, host_raw, idx):
    phase=F/'sender-execute'
    names=['CHILD.json','INTENT.json','OUTPUT-CAPTURE.json','OWNED-CHILD-FAILURE.json',
           'stderr.original','stdout.original']
    directory_original(originals,phase,names)
    need(controls['stdout.original']==host_raw and controls['stderr.original']==b'',
         'original sender retained streams differ from actual SSH return receipt')
    child=strict(controls['CHILD.json']);intent=strict(controls['INTENT.json'])
    capture=strict(controls['OUTPUT-CAPTURE.json']);failure=strict(controls['root-failure'])
    need(child['pid']==child['pgid']==child['sid']==50521 and child['maximum_starts']==1
         and child['source_intent_sha256']==sha(controls['INTENT.json']),
         'actual original sender process identity differs')
    expected_argv=['/usr/bin/python3','-I','-B',str(B/'send_new_native_guard_task_r10_r4.py'),
         LABEL,root['request']['path'],root['previous']['path'],'--preserved-draft',
         root['preserved_draft']['path'],'--retirement-resolution',
         root['sender_retirement_resolution']['path'],'--evidence-root','component',
         '--component-contract',str(F/'material/tree/sender-contract.json'),
         '--component-package',RUNTIME_MANIFEST['path'],'--component-package-sha256',
         RUNTIME_MANIFEST['sha256'],'--execute-once']
    need(intent==dict(schema='hepta.native-guard.root-host-command.v1',phase='sender-execute',
         argv=expected_argv,stdin_sha256=None,maximum_starts=1,maximum_wait_seconds=600,
         signals_on_timeout=False,automatic_retry=False,
         deadline_scope='popen_start_through_child_join_pipe_eof_and_output_verification',
         input_transport='retained_readonly_regular_fd_child_reads_within_execution_budget',
         hard_bound_on_filesystem_spawn_or_cleanup=False,output_limit_bytes_per_stream=67108864,
         output_transport='owned_nonblocking_pipe_capture_worker_bounded_memory_main_thread_persistence'),
         'original host sender execution intent differs')
    need(capture==idx['original_output_capture']
         and capture['schema']=='hepta.native-guard.host-output-capture.v1'
         and capture['pid']==50521 and capture['phase']=='sender-execute'
         and capture['source_intent_sha256']==sha(controls['INTENT.json'])
         and capture['child_wait_returned'] is False and capture['child_returncode'] is None
         and capture['child_join_observed_monotonic'] is None
         and capture['prefix_only_or_unknown'] is True
         and capture['remote_terminal_or_cleanup_proven'] is False
         and capture['worker_joined'] is True and capture['stdout_eof'] is True
         and capture['stderr_eof'] is True and capture['signals_sent']==0
         and capture['automatic_retry'] is False,
         'original unjoined sender evidence must remain unjoined and unknown')
    keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    for stream in ('stdout','stderr'):
        row=capture['files'][stream];data=controls[stream+'.original']
        need(row['path']==str(phase/(stream+'.original')) and row['original_created_inode_bound'] is True
             and (row['bytes'],row['sha256'])==(len(data),sha(data))
             and [row['metadata'][key] for key in keys]==
                 idx['actual_original_host_inputs'][stream+'.original']['metadata']
             and capture['captured'][stream]=={'bytes':len(data),'sha256':sha(data)},
             'original sender pipe capture or retained file identity differs')
    owned=strict(read(OWNED_CHILD_FAILURE))
    need(owned=={'state':'OWNED_HOST_CHILD_NOT_JOINED_NO_SIGNAL_OR_RETRY','phase':'sender-execute',
         'pid':50521,'returncode':None,'output_capture':capture,'automatic_retry':False,'signals_sent':0}
         and failure['state']=='FAILED_OR_UNKNOWN_ORIGINALS_PRESERVED_NO_AUTOMATIC_CONTINUATION'
         and failure['host_cleanup']=={'host_children':[owned],'stream_cleanup_errors':[]}
         and failure['send_again'] is False and failure['automatic_retry'] is False,
         'original coordinator failure or owned-child record was rewritten or claimed joined')


def verify_sender_no_send(originals, plan):
    validate_plan(plan)
    source_sha=globals().get('__reviewed_source_sha256__')
    need(isinstance(source_sha,str) and HASH.fullmatch(source_sha),
         'caller must inject the hash of the exact compiled verifier source')
    used={}
    def read(row):
        file_descriptor(row)
        p=Path(row['path'])
        need(p.resolve(strict=True)==p,'noncanonical original input')
        before=p.lstat()
        raw=originals.pinned(row)
        after=p.lstat()
        need(type(raw) is bytes and len(raw)==row['bytes'] and sha(raw)==row['sha256']
             and stat.S_ISREG(before.st_mode) and before.st_nlink==1
             and meta(before)==meta(after),'original input bytes or metadata changed')
        record=dict(row,metadata=meta(before))
        need(str(p) not in used or used[str(p)]==record,'original input changed during audit')
        used[str(p)]=record
        return raw
    root=strict(read(plan['root_plan']))
    need(root['label']==LABEL and root['nonce']==NONCE and root['case_id']=='NEG-01'
         and root['package']==RUNTIME_MANIFEST and root['source_package']==CHAIN_MANIFEST,
         'fixed diag02 Root plan/package changed')
    request=read(root['request'])
    previous=strict(read(root['previous']))
    preserved=strict(read(root['preserved_draft']))
    resolution_raw=read(root['sender_retirement_resolution'])
    need(root['previous']==PREVIOUS
         and previous['terminal']['status']=='provider_failed'
         and previous['component_qualified'] is False
         and previous['known_all_dispatched_tools_confirmed_terminal'] is True
         and previous['automatic_replay'] is False,'actual previous6077 original differs')
    identity=previous['identity']; digest=previous['request_sha256']
    need(type(identity) is dict and set(identity)=={'session_id','profile_id','task_id','turn_id','turn_stream_id'}
         and isinstance(digest,str) and HASH.fullmatch(digest),'previous native binding differs')
    draft=base64.b64decode(preserved['exact_utf8_b64'],validate=True)
    draft.decode('utf-8');request.decode('utf-8')
    need(bool(draft) and sha(draft)==preserved['utf8_sha256'] and draft!=request,
         'nonempty original draft binding differs')
    idx=strict(read(plan['sender_index']))
    raws,names,controls,remote,export_raw=retained_sender_originals(originals,read,idx)
    verify_retention_steps(read,idx,remote,export_raw)
    def value(name):
        need(name in raws,'required original sender receipt absent')
        return strict(raws[name])
    actor_raw=read(ACTOR); actor_tree,assign=source_top_assignments(actor_raw)
    need({k:assign[k] for k in ('label','expected','preserved_draft','previous_identity','previous_digest','evidence_mode')}
         =={'label':LABEL,'expected':request.decode(),'preserved_draft':draft.decode(),
            'previous_identity':identity,'previous_digest':digest,'evidence_mode':'component'}
         and assign['previous_status']=='provider_failed'
         and assign['known_all_prior_tools_confirmed'] is True
         and assign['reset_probe'] is False,'generated actor original bound inputs differ')
    order=source_send_order(actor_tree)
    component=assign['component_binding']; retirement=assign['retirement_binding']
    need(type(component) is dict and component['contract']['nonce']==NONCE
         and component['contract']['owner_request_sha256']==sha(request)
         and retirement['resolution_sha256']==sha(resolution_raw),
         'generated actor component/retirement binding differs')
    once=strict(read(ONCE))
    need(once==dict(task=LABEL,prompt=request.decode(),prompt_sha256=sha(request),
         previous_identity=identity,previous_digest=digest,
         retirement_resolution_sha256=sha(resolution_raw),
         retirement_prior_admission=assign['retirement_prior'],evidence_root_mode='component',
         supplied_app_commands=False,supplied_app_coordinates=False,automatic_replay=False),
         'original local once intent differs')
    host_raw=read(SEND_RESULT);host=strict(host_raw)
    need(set(host)=={'rc','stdout','stderr'} and type(host['rc']) is int and host['rc']==2
         and host['stderr']=='' and isinstance(host['stdout'],str),
         'original SSH return receipt must be known rc2')
    lines=host['stdout'].strip().splitlines()
    need(len(lines)==1,'one actual original actor terminal required')
    terminal=strict(lines[0])
    need(terminal==dict(state='PRE_SEND_OR_ACTOR_FAILURE',native_status=None,out=P4,
         route=[5037,'23'],prompt_sha256=sha(request),
         draft_restore=dict(state='ORIGINAL_DRAFT_RESTORED',restore_attempts=1,original_draft_submitted=False),
         send_attempt_count=0,automatic_replay=False,business_success_verified=False,
         independent_collector_required=True,retirement_resolution_sha256=sha(resolution_raw)),
         'original actor terminal is not the exact no-Send failure')
    manifest=strict(read(RUNTIME_MANIFEST))
    source_rows={x['path']:x for x in manifest['files']}
    need(len(source_rows)==len(manifest['files'])==32,'actual current source manifest differs')
    def package_source(name,pin):
        row=source_rows[name]
        need((row['bytes'],row['sha256'])==pin,'fixed current source row differs')
        return read(descriptor(RUNTIME/name,*pin))
    sender_source=package_source('source/send_new_native_guard_task_r10_r4.py',SENDER_PIN)
    need(read(descriptor(B/'send_new_native_guard_task_r10_r4.py',*SENDER_PIN))==sender_source,
         'actual sender alias differs from original package source')
    decoder_raw=package_source('reference/decode_client_state.py',DECODER_PIN)
    chain=strict(read(CHAIN_MANIFEST))
    rows={x['path']:x for x in chain['files']}
    c=rows['source/run_component_root_once.py']
    need((c['bytes'],c['sha256'])==COORDINATOR_PIN,'original coordinator source row differs')
    read(descriptor(ROOT_CHAIN/c['path'],*COORDINATOR_PIN))
    sender_text=sender_source.decode()
    ordered=["result = subprocess.run(ssh, input=source.encode(), capture_output=True, timeout=600)",
             "receipt = {'rc': result.returncode",
             "with (BASE / (label + '.send-result.json')).open('x') as out:",
             "print(json.dumps(receipt, ensure_ascii=False, indent=2))"]
    positions=[sender_text.index(x) for x in ordered]
    need(positions==sorted(positions) and len(set(positions))==4,
         'actual original SSH-return/source persistence order differs')
    prepared=value('COMPONENT-PREPARED-NO-SEND.json')
    need(prepared['schema']=='hepta.native-guard.sender-prepared.v1' and prepared['state']=='PREPARED_NO_SEND'
         and prepared['nonce']==NONCE and prepared['owner_request_sha256']==sha(request)
         and prepared['contract_sha256']==component['contract_sha256']
         and prepared['provider_source_sha256']==component['source_sha256']
         and prepared['ready_path']==component['phone_ready_path']
         and prepared['provider_started_by_sender'] is False
         and prepared['socket_connections']==prepared['send_attempt_count']==0,
         'actual original no-Send rendezvous differs')
    ready_names=[name for name in names if re.fullmatch(r'COMPONENT-READY-[0-9]{4}\.original-read\.json',name)]
    need(ready_names==['COMPONENT-READY-%04d.original-read.json'%i for i in range(1,55)],
         'all fifty-four original rendezvous reads required')
    command='/data/adb/magisk/busybox timeout -s TERM -k 1 6 /data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -I -B -c '+shlex.quote(assign['COMPONENT_READY_PROBE_SOURCE'])
    command='/debug_ramdisk/su -c '+shlex.quote(command)
    last_end=prepared['prepared_monotonic_ns']
    for index,name in enumerate(ready_names,1):
        observation=value(name); wire=observation['original_wire_receipt']
        need(set(observation)=={'read_start_monotonic_ns','read_end_monotonic_ns','original_wire_receipt',
             'observation','read_only','socket_connections','service_launches'}
             and observation['read_only'] is True
             and observation['socket_connections']==observation['service_launches']==0
             and all(type(observation[k]) is int for k in ('read_start_monotonic_ns','read_end_monotonic_ns'))
             and last_end<=observation['read_start_monotonic_ns']<=observation['read_end_monotonic_ns']
             and wire['command']==command and wire['route']==[5037,'23'],
             'actual component readiness wire/time binding differs')
        last_end=observation['read_end_monotonic_ns']
        if index<54:
            result=observation['observation']
            need(type(wire['rc']) is int and wire['rc']==0 and wire['stderr']==''
                 and strict(wire['stdout'])==result and result['state']=='waiting_for_ready'
                 and result['nonce']==NONCE and result['owner_request_sha256']==sha(request)
                 and result['contract_sha256']==component['contract_sha256']
                 and result['claim_absent'] is True and result['ended_absent'] is True,
                 'original preceding rendezvous read was not waiting without a claim')
        else:
            need(type(wire['rc']) is int and wire['rc']==1 and wire['stdout']==''
                 and wire['stderr']==READY54_STDERR and observation['observation'] is None,
                 'actual final readiness failure was not before Send')
    need(value('ACTOR-FAILURE.json')==dict(error_type='AssertionError',
         error='Fixed component ready observation failed; no Send',automatic_send_retry=False),
         'actual actor failure branch differs')
    original_draft=value('PRESERVED-USER-DRAFT.json')
    need(original_draft['exact_text'].encode()==draft
         and original_draft['utf8_sha256']==sha(draft)
         and original_draft['restore_required'] is True
         and original_draft['submitted_original_draft'] is False,
         'actual preserved user draft differs')
    restore=value('DRAFT-RESTORE-RESULT.json')
    need(restore==dict(state='ORIGINAL_DRAFT_RESTORED',utf8_sha256=sha(draft),
         original_draft_submitted=False,model_business_credit=False,restore_attempts=1),
         'original draft restoration was not completed exactly once')
    restore_proof=unicode_wire(value('PRESERVED-DRAFT-RESTORE.original.json'),
         'root-restore-'+LABEL,draft,(b'',request,draft))
    input_wire=value('OPERATOR-CHINESE-PROMPT-INPUT.json')
    input_proof=unicode_wire(input_wire,'root-prompt-'+LABEL,request,(b'',draft,request))
    module=types.ModuleType('reviewed_diag02_identity_decoder')
    module.__file__=str(RUNTIME/'reference/decode_client_state.py')
    exec(compile(decoder_raw,module.__file__,'exec',optimize=0),module.__dict__)
    selected_names=['FINAL-PRE-SEND-SELECTED.original-read.json',
                    'RESTORE-SELECTED.original-read.json','RESTORE-SELECTED-FINAL.original-read.json']
    for name in selected_names:
        wire=value(name)
        need(type(wire['rc']) is int and wire['rc']==0 and wire['stderr']=='',
             'selected-identity original wire was not complete')
        raw=base64.b64decode(''.join(wire['stdout'].split()),validate=True)
        selected=module.decode_client_state(raw)
        need(selected['checksum_valid'] is True
             and all(selected[k]==identity[k] for k in ('session_id','task_id','turn_id'))
             and selected['turn_request_sha256']==digest,
             'actual previous6077 selected identity changed')
    need(len({raws[name] for name in selected_names})==1,
         'the three exact original selected-state receipts differ')
    gate=value('RESTORE-GLOBAL-GATE.original-read.json')
    wire=gate['original_wire_receipt'];g=strict(wire['stdout'])
    need(gate['read_only'] is True and gate['no_retry'] is True
         and type(wire['rc']) is int and wire['rc']==0 and wire['stderr']==''
         and g.get('state')=='original_retirement_verified'
         and g.get('global_action_gate_clear') is True
         and g.get('resolution_sha256')==sha(resolution_raw),
         'restoration bypassed the original global action gate')
    host_closed=strict(read(plan['host_sender_closure']))
    need(host_closed==idx,'the fixed original retention/absence result differs')
    verify_original_sender_capture(originals,read,root,controls,host_raw,idx)
    observations=host_closed['independent_mac_absence_observations']
    need(type(observations) is list and len(observations)==2,
         'two independent complete Mac process censuses required')
    last=0
    for index,observation in enumerate(observations):
        need(observation['original_pid']==observation['original_pgid']==50521
              and observation['original_wait_claimed'] is False
             and observation['returncode']==0
             and observation['matching_pid_or_pgid_rows']==[]
             and type(observation['read_start_monotonic_ns']) is int
             and type(observation['read_end_monotonic_ns']) is int
             and last<observation['read_start_monotonic_ns']<=observation['read_end_monotonic_ns'],
             'independent Mac absence observation order differs')
        last=observation['read_end_monotonic_ns']
        need(observation['stdout']==idx['steps'][index*2]['stdout']
              and observation['stderr']==idx['steps'][index*2]['stderr']
              and observation['numeric_pid_rows']==(717,718)[index],
             'exact original Mac census stream paths differ')
        raw=read(observation['stdout']);need(read(observation['stderr'])==b'','Mac ps original error')
        rows=[]
        for line in raw.decode('ascii').splitlines():
            fields=line.split()
            need(len(fields)==4 and all(re.fullmatch(r'[0-9]+',v) for v in fields[:3])
                 and fields[3] and len(fields[3])<=16,'complete Mac process row differs')
            pid,ppid,pgid=map(int,fields[:3])
            need(pid>0 and ppid>=0 and pgid>=0,'Mac process identity invalid')
            rows.append((pid,ppid,pgid,fields[3]))
        need(0<len(rows)<=16384 and len({x[0] for x in rows})==len(rows)
             and any(x[0]==1 for x in rows)
             and len(rows)==observation['numeric_pid_rows']
             and all(row[0]!=50521 and row[2]!=50521 for row in rows),
             'the original sender PID or owned group remains present')
    read(ROOT_FAILURE)
    originals.recheck(); recheck_sender_directories(originals)
    return {'schema':'hepta.native-guard.diag02.sender-no-send-proof.v1',
        'state':'ORIGINAL_SENDER_NO_SEND_AND_DRAFT_RESTORATION_VERIFIED',
        'label':LABEL,'nonce':NONCE,'verifier_source_sha256':source_sha,
        'source_actor':ACTOR,'source_sender':descriptor(RUNTIME/'source/send_new_native_guard_task_r10_r4.py',*SENDER_PIN),
        'source_decoder':descriptor(RUNTIME/'reference/decode_client_state.py',*DECODER_PIN),
        'original_sender_ssh_returncode':2,'original_actor_terminal_state':'PRE_SEND_OR_ACTOR_FAILURE',
        'host_parent_wait_receipt_available':False,'host_child_wait_returned_claimed':False,
        'mac_sender_pid':50521,'mac_sender_group_absence_observations':2,
        'host_sender_process_absent_twice':True,'original_output_capture_wait_returned':False,
        'complete_sender_retention':INDEX,'read_only_retention_steps_joined':3,
        'native_status':None,'native_scope_created':False,'send_attempt_count':0,
        'original_sender_files':82,'original_sender_total_bytes':2224064,
        'full_source_catalog_and_export_equal':True,'source_send_order':order,
        'complete_reader_source':READER,'actual5937_last_two_originals_equal':True,
        'readiness_waiting_original_count':53,'final_original_readiness_returncode':1,
        'selected_previous6077_checksum_and_identity_verified':True,
        'selected_previous6077_original_count':3,'exact_original_draft_restored':True,
        'draft_restore_attempts':1,'original_draft_submitted':False,
        'original_input_CAS':input_proof,'original_restore_CAS':restore_proof,
        'original_UI_activity_performed':True,'UI_zero_claimed':False,
        'UI_effect_count_claimed':False,'business_qualified':False,'component_qualified':False,
        'phone_calls_by_verifier':0,'native_submissions_by_verifier':0,'signals_by_verifier':0,
        'private_values_or_inner_digests_disclosed':False,
        'input_originals':[used[path] for path in sorted(used)],
        'directory_originals':dict(getattr(originals,'sender_no_send_directories',{})),
        'independent_phone_lifecycle_closure_still_required':True}
