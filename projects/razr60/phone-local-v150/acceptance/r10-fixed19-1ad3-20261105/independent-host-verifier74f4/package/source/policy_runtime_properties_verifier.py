#!/usr/bin/env python3
"""Independent host verification of the captured runtime-property live02 transition.

The applied verifier remains the exact captured 5cd source. This independently
reviewed source has its own identity and is never substituted into phone originals.

All original bytes enter through an explicit read_pinned callback. This module
does not read the device, open a socket, write a file, run a command or adopt a
policy. A reviewed original is not a claim that a screenshot now succeeds.
"""
import ast
import base64
import hashlib
import io
import json
from pathlib import PurePosixPath
import re
import shlex
import tarfile
import zlib

BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
BASE = '/var/lib/trillionnium/owner-open/phone-local-v150'
NATIVE_BASE = '/data/trillionnium/owner-open/state/phone-local-v150'
CODE_NAME = 'policy-runtime-properties-r10-live-code-r2'
OUT_NAME = 'policy-runtime-properties-r10-live-02'
APPLIED_VERIFIER = {'bytes': 124306, 'sha256': '5cd18af19e1cd4cbe98542996fa41960bc36f697c6687ce201312b8ceda91c00'}
INDEPENDENT_VERIFIER_SOURCE_PATH = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/policy-runtime-properties-r10-independent-host-verifier-r1-candidate01/source/policy_runtime_properties_verifier.py'
PACKAGE_ROOT = BASE+'/native-guard-r10-r1/root-r10-neg01-20261105-08/package'
DECISION = {'bytes':24830,'sha256':'5a08041da77eeec9168c869ae76adae0a117a5e34872aa07a1a096bc06a36132'}
PARENT = {'bytes':2667608,'sha256':'50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7'}
PARENT_ADOPTION = {'bytes':146368,'sha256':'a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5'}
RETIREMENT = 'b139e096969f5a860f5e7cb9e3e988db3d0b2e868528dd4c38b8c9411df4fb90'
RETIREMENT_DESCRIPTOR = {'bytes':2220,'sha256':'e3c8411f3d85440018392597d4f9f8795cfd7a60c44fc1680068a60949d20999'}
RETIREMENT_HOST_CLOSURE = {'bytes':2489,'sha256':'14c4bfeb4932067b682cc47b0472f3f2e994cac6ae72a33662ad702b73a4a906'}
PACKAGE = {'bytes':13446,'sha256':'683481bdb653bd7cb97bd6171d6b14f6ecaf4f9948ed2691c7b7c420fea5fe3c'}
COMBINATION_SHA256 = 'ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837'
BOUNDARY_DESCRIPTOR = {'bytes':367,'sha256':'724d7d54679299433498654530ad3dc082c107aa76fde9de54b0ed6c0ad3de08'}
# The following literal is generated only from the retained Python-read raw
# full-nine descriptors, never from a JavaScript numeric serialization.
CLOSED_HISTORY = [{'attempt': '08', 'nonce': '2b0b103ee6de7a422064b9571266bf5d', 'boundary': {'bytes': 9373, 'metadata': [65086, 153711, 33152, 0, 0, 1, 9373, 1793853757339925229, 1793853757339925229], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/2b0b103ee6de7a422064b9571266bf5d.json', 'sha256': 'eca941303197228ebe03561e612bfe41eb0518c590ff21253444db25a11adc10'}, 'closure': {'bytes': 54785, 'metadata': [65086, 157036, 33152, 0, 0, 1, 54785, 1793853752099925231, 1793853752099925231], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/2b0b103ee6de7a422064b9571266bf5d/CLOSURE.original.json', 'sha256': '7e42ed77926bdf3bc728e4aef5009ffb23d50adfe1f6ce6b9e236fc621aa17cb'}, 'inventory': {'bytes': 849854, 'metadata': [65086, 156653, 33152, 0, 0, 1, 849854, 1793853752103925231, 1793853752103925231], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/2b0b103ee6de7a422064b9571266bf5d/AFTER-INVENTORY.original.json', 'sha256': '80b8a56ee78055c19caf3b342af5bc5e479180843b0f3bc223751649188b7fc4'}, 'package_sha256': '683481bdb653bd7cb97bd6171d6b14f6ecaf4f9948ed2691c7b7c420fea5fe3c', 'combination_sha256': 'ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837', 'actual_native_calls': 1}, {'attempt': '07', 'nonce': '16805e43f9787c44c262d5b6c6d8ed95', 'boundary': {'bytes': 9078, 'metadata': [65086, 155387, 33152, 0, 0, 1, 9078, 1793851076499926252, 1793851076499926252], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/16805e43f9787c44c262d5b6c6d8ed95.json', 'sha256': '46b03cd66426395198b4a3093117659d5cfb128cc981815934fc1ea695c97be0'}, 'closure': {'bytes': 25716, 'metadata': [65086, 155749, 33152, 0, 0, 1, 25716, 1793851073491926253, 1793851073491926253], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/16805e43f9787c44c262d5b6c6d8ed95/CLOSURE.original.json', 'sha256': 'd5a6433d473ced291328536664497d9fa9861b42f126ecf9ad189df497520a57'}, 'inventory': {'bytes': 776988, 'metadata': [65086, 155685, 33152, 0, 0, 1, 776988, 1793851073491926253, 1793851073491926253], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/16805e43f9787c44c262d5b6c6d8ed95/AFTER-INVENTORY.original.json', 'sha256': '32726cebc8d85dc7086073ba9d6494248a3ec625826a5ed635cffa6715811432'}, 'package_sha256': '683481bdb653bd7cb97bd6171d6b14f6ecaf4f9948ed2691c7b7c420fea5fe3c', 'combination_sha256': 'ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837', 'actual_native_calls': 0}, {'attempt': '06', 'nonce': '154588e3a15591a21ec18950d18e3ecd', 'boundary': {'bytes': 8774, 'metadata': [65086, 156811, 33152, 0, 0, 1, 8774, 1793845849603928245, 1793845849603928245], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/154588e3a15591a21ec18950d18e3ecd.json', 'sha256': 'eca628a18327146b7710a478fc2c2f716f79d55907b2821666828a0795e2060f'}, 'closure': {'bytes': 54878, 'metadata': [65086, 156683, 33152, 0, 0, 1, 54878, 1793845847051928246, 1793845847051928246], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/154588e3a15591a21ec18950d18e3ecd/CLOSURE.original.json', 'sha256': '8fc9d05e877d91f6706558968276848e252784414983ea026b5c9ef00a8deb2a'}, 'inventory': {'bytes': 737114, 'metadata': [65086, 156758, 33152, 0, 0, 1, 737114, 1793845847051928246, 1793845847051928246], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/154588e3a15591a21ec18950d18e3ecd/AFTER-INVENTORY.original.json', 'sha256': 'fcd752b17eed7d36718f81e61a0f81d22554aa1a478180371619de1c10d98759'}, 'package_sha256': '4dd75caa1d77f4698fba5084689b84c99a91c388219fd546d84906d869f23f8e', 'combination_sha256': 'ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837', 'actual_native_calls': 1}, {'attempt': '04', 'nonce': 'c705647dd4ebb5d421be1041a9c41ca6', 'boundary': {'bytes': 4748, 'metadata': [65086, 149437, 33152, 0, 0, 1, 4748, 1793828404835934900, 1793828404835934900], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/c705647dd4ebb5d421be1041a9c41ca6.json', 'sha256': '3216ab18adcafa0dda95e8a93ad35a2070e7aec286d7a518794918068ce31d12'}, 'closure': {'bytes': 49087, 'metadata': [65086, 152153, 33152, 0, 0, 1, 49087, 1793828403499934901, 1793828403499934901], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/c705647dd4ebb5d421be1041a9c41ca6/CLOSURE.original.json', 'sha256': '559f2440fdd1c9f43c64399351f3fda0be95890d21cbde4aea211751e5f9aa81'}, 'inventory': {'bytes': 633600, 'metadata': [65086, 153196, 33152, 0, 0, 1, 633600, 1793828403499934901, 1793828403499934901], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/c705647dd4ebb5d421be1041a9c41ca6/AFTER-INVENTORY.original.json', 'sha256': 'e48c39003bd26f65dde74958f0081a89c23027da19a11afd4fc2a81414c5c349'}, 'package_sha256': '1cd57949621b36e46dc72d3df55e6ec3814fa76fb046c15ae71524463e3e8996', 'combination_sha256': '7f5929ae709239f8a5d92314146d2b63151bb06746d160da7961a3de29c486af', 'actual_native_calls': 1}, {'attempt': '03', 'nonce': '88d68d88130d3c74e6c950a6346357c1', 'boundary': {'bytes': 5003, 'metadata': [65086, 151071, 33152, 0, 0, 1, 5003, 1793826667027935563, 1793826667027935563], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/88d68d88130d3c74e6c950a6346357c1.json', 'sha256': 'ee008c3b2adec701be4c0bdfd38ca7ac0d650da9b7783f51d3fe4638bfdc5b58'}, 'closure': {'bytes': 119753, 'metadata': [65086, 152047, 33152, 0, 0, 1, 119753, 1793826665711935563, 1793826665711935563], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/88d68d88130d3c74e6c950a6346357c1/CLOSURE.original.json', 'sha256': 'b8a27617eaff8dda0f1c61b5aa14a89d7014a157e0b33280b14162c7591bcaa3'}, 'inventory': {'bytes': 563365, 'metadata': [65086, 150632, 33152, 0, 0, 1, 563365, 1793826665711935563, 1793826665711935563], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/88d68d88130d3c74e6c950a6346357c1/AFTER-INVENTORY.original.json', 'sha256': '145d5937cd328ed568b1af9c73f7d331211d1c44cfad8ecf960b47d91f308eee'}, 'package_sha256': 'd09489d965b3bc8adca12a7403b87baf5ec2e333e983fbc2b911992e9f25e65f', 'combination_sha256': '7f5929ae709239f8a5d92314146d2b63151bb06746d160da7961a3de29c486af', 'actual_native_calls': 0}]
BOUNDARY = CLOSED_HISTORY[0]['boundary']
BOUNDARY_CLOSURE = {k:CLOSED_HISTORY[0]['closure'][k] for k in ('bytes','sha256')}
BOUNDARY_INVENTORY = {k:CLOSED_HISTORY[0]['inventory'][k] for k in ('bytes','sha256')}
PARENT_RULE = {'bytes':14130,'sha256':'aeda92123f1d043de2c53dd345dd7372b98da7b776299d57bda531dda868e4a1'}
FULL_RULE = {'bytes': 17284, 'sha256': '424e1c680d37583f039c8cc5e2727200b3f9ad8fd29d35616173a5102b0218d1'}
PARSER = {'bytes':2630712,'sha256':'68154a7adabfada7940572f95477885dd6da01ea8b1f3e95abef9495a066382c'}
WORKER = 'trillionnium_owner_open_phone_worker'
PROPERTY_TYPES = ('build_attestation_prop','dalvik_config_prop','dalvik_dynamic_config_prop',
    'dalvik_runtime_prop','default_prop','odsign_prop','persist_debug_prop','qemu_sf_lcd_density_prop',
    'radio_prop','system_prop','vendor_mot_hw_prop')
ROWS = [(WORKER,target,'file',['getattr','open','read','map']) for target in PROPERTY_TYPES]
ATOMS = [['allow',src,target,kind,perm] for src,target,kind,perms in ROWS for perm in perms]
RULE = ''.join(' '.join(atom)+'\n' for atom in ATOMS).encode('utf-8')
ARGV = ['/data/adb/magisk/magiskpolicy','--live','--apply',NATIVE_BASE+'/'+OUT_NAME+'/runtime-properties.delta.rule']
APPROVAL = {'maximum_apply_attempts':1,'apply_timeout_seconds':45,'kill_grace_seconds':5,
    'automatic_retry':False,'automatic_rollback':False,'automatic_policy_adoption':False,
    'post_live_complete_comparison_required':True,'service_start_admitted':False}
COMPONENT_SOURCE_MEMBERS = {
    'source/component_common.py':'closed-source-component_common.original.py',
    'source/native_proc_profile.py':'closed-source-native_proc_profile.original.py',
    'source/component_lifecycle.py':'closed-source-component_lifecycle.original.py',
    'source/component_snapshot.py':'closed-source-component_snapshot.original.py',
    'source/late_boundary.py':'closed-source-late_boundary.original.py',
    'reference/component_common_r5.py':'closed-reference-component_common_r5.original.py',
    'reference/environment_parent_late_boundary_r6.py':'closed-reference-environment_parent_late_boundary_r6.original.py',
    'reference/policy_parent_late_boundary_r4.py':'closed-reference-policy_parent_late_boundary_r4.original.py',
    'reference/non_native_attempt05.py':'closed-reference-non_native_attempt05.original.py',
    'reference/attempt05-SIDE-PROOF.original.json':'closed-reference-attempt05-SIDE-PROOF.original.json',
    'reference/attempt05-CLOSURE.original.json':'closed-reference-attempt05-CLOSURE.original.json',
    'reference/attempt05-AFTER-INVENTORY.original.json':'closed-reference-attempt05-AFTER-INVENTORY.original.json'}
COMPONENT_SOURCE_PINS = {'source/component_common.py': {'bytes': 19138, 'sha256': '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'}, 'source/native_proc_profile.py': {'bytes': 4633, 'sha256': '12719e58d2e3e1a1e86b8a6a9dc9587e37bfcb36c4c3b26b023138752bb3e67b'}, 'source/component_lifecycle.py': {'bytes': 40261, 'sha256': '144836347482b8871703b882283ffac63d5df480e3333a9bd631409f890fc1c2'}, 'source/component_snapshot.py': {'bytes': 24187, 'sha256': '2d624aaafb7df75ad3c78b35e866a44022ee4f5205b20aaeb4515458e05eaffa'}, 'source/late_boundary.py': {'bytes': 62434, 'sha256': '3c710779e79870e4fefdedb8a24163118b2de814d7fcd3e97bb8971eec6113fd'}, 'reference/component_common_r5.py': {'bytes': 18133, 'sha256': '8ad9a3b17e7475555af7dd9a113025740447fcebdf0400d984d8a9e84accfb02'}, 'reference/environment_parent_late_boundary_r6.py': {'bytes': 53502, 'sha256': '1fd24e0a6799ed3fb02014567764cce4c0de884e78ccd5b663e63fe69230041c'}, 'reference/policy_parent_late_boundary_r4.py': {'bytes': 35730, 'sha256': 'bcbe7d03567684ca23bd0985c14df49b021e1ac2e53e76dfda94262d7ad3516b'}, 'reference/non_native_attempt05.py': {'bytes': 19740, 'sha256': 'a4ec44ac1f09fc7919dce17acf46e6db83ca468f58f53ad7622b520b557d04e4'}, 'reference/attempt05-SIDE-PROOF.original.json': {'bytes': 4650, 'sha256': '1bf6bca5ae5aaa5d5803b708070680e92d3f072f9541f38b09783787cfae7b9c'}, 'reference/attempt05-CLOSURE.original.json': {'bytes': 164095, 'sha256': 'd464bac786ef208d8fa0390587bd3bb7616a13985fb064716a209aa2394458f6'}, 'reference/attempt05-AFTER-INVENTORY.original.json': {'bytes': 664638, 'sha256': '87103089914885fff5632781f18fbe36895ed181f01997eac6c3b49449b5579e'}}
NON_NATIVE_BINDING = {'closure': {'bytes': 164095, 'metadata': [65086, 153455, 33152, 0, 0, 1, 164095, 1793843548839929123, 1793843548839929123], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/e4c3ccb0b2d706be3b7bf105ae772405/CLOSURE.original.json', 'sha256': 'd464bac786ef208d8fa0390587bd3bb7616a13985fb064716a209aa2394458f6'}, 'component_qualified': False, 'component_role_identities': {'provider': [23913, 23913, 23913, 18133299], 'sidecar': [23911, 23911, 23911, 18133265], 'supervisor': [23779, 23779, 23779, 18132959]}, 'inventory': {'bytes': 664638, 'metadata': [65086, 143754, 33152, 0, 0, 1, 664638, 1793843548843929123, 1793843548843929123], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/e4c3ccb0b2d706be3b7bf105ae772405/AFTER-INVENTORY.original.json', 'sha256': '87103089914885fff5632781f18fbe36895ed181f01997eac6c3b49449b5579e'}, 'native_case_count': 0, 'native_predecessor': {'bytes': 4748, 'metadata': [65086, 149437, 33152, 0, 0, 1, 4748, 1793828404835934900, 1793828404835934900], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/c705647dd4ebb5d421be1041a9c41ca6.json', 'sha256': '3216ab18adcafa0dda95e8a93ad35a2070e7aec286d7a518794918068ce31d12'}, 'nonce': 'e4c3ccb0b2d706be3b7bf105ae772405', 'preserved_roots': ['/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/evidence', '/var/lib/trillionnium/owner-open/phone-local-v150/component-probe-r6/evidence', '/var/lib/trillionnium/owner-open/phone-local-v150/client-receipts', '/var/lib/trillionnium/owner-open/phone-local-v150/executor-r6', '/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/health-contracts/bindings', '/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/task-contracts/bindings', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03', '/proc/1/root/data/local/tmp/hepta-native-guard-88d68d88130d3c74e6c950a6346357c1', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04', '/proc/1/root/data/local/tmp/hepta-native-guard-c705647dd4ebb5d421be1041a9c41ca6', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05', '/proc/1/root/data/local/tmp/hepta-native-guard-e4c3ccb0b2d706be3b7bf105ae772405'], 'private_roots': ['/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05/executor', '/proc/1/root/data/local/tmp/hepta-native-guard-e4c3ccb0b2d706be3b7bf105ae772405'], 'proof': {'bytes': 4650, 'metadata': [65086, 147519, 33152, 0, 0, 1, 4650, 1793843550651929122, 1793843550651929122], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/e4c3ccb0b2d706be3b7bf105ae772405/SIDE-PROOF.original.json', 'sha256': '1bf6bca5ae5aaa5d5803b708070680e92d3f072f9541f38b09783787cfae7b9c'}, 'schema': 'hepta.native-guard.non-native-sidebranch-binding.v1'}
CAPTURE_MEMBER_NAMES = ('ACTUAL-RETIREMENT-INPUTS.original.json', 'APPLY-INTENT.json', 'BINDING.original.json', 'CLOSED-COMPONENT-PACKAGE.original.json', 'COMMAND-RETURN.json', 'GLOBAL-GATE-post.json', 'GLOBAL-GATE-pre.json', 'LATEST-BOUNDARY-DESCRIPTOR.original.json', 'OFFLINE-COMPLETE-COMPARISON.original.json', 'ORIGINAL-SOURCE-PATHS.json', 'PARENT-ADOPTION-HISTORY.original.json', 'POLICY-APPLY.json', 'PRECHECK.json', 'RETIREMENT-HOST-CLOSURE.original.json', 'RETIREMENT-OPERATOR.original.json', 'RETIREMENT-SERVICE-RECORDS.original.tsv', 'ROOT-SCOPE-DECISION.original.json', 'STAGE-COMPLETE.original.json', 'STAGE-INTENT.original.json', 'apply_runtime_properties_once.original.sh', 'closed-03-BOUNDARY.original.json', 'closed-03-CLOSURE.original.json', 'closed-03-INVENTORY.original.json', 'closed-04-BOUNDARY.original.json', 'closed-04-CLOSURE.original.json', 'closed-04-INVENTORY.original.json', 'closed-06-BOUNDARY.original.json', 'closed-06-CLOSURE.original.json', 'closed-06-INVENTORY.original.json', 'closed-07-BOUNDARY.original.json', 'closed-07-CLOSURE.original.json', 'closed-07-INVENTORY.original.json', 'closed-08-BOUNDARY.original.json', 'closed-08-CLOSURE.original.json', 'closed-08-INVENTORY.original.json', 'closed-reference-attempt05-AFTER-INVENTORY.original.json', 'closed-reference-attempt05-CLOSURE.original.json', 'closed-reference-attempt05-SIDE-PROOF.original.json', 'closed-reference-component_common_r5.original.py', 'closed-reference-environment_parent_late_boundary_r6.original.py', 'closed-reference-non_native_attempt05.original.py', 'closed-reference-policy_parent_late_boundary_r4.original.py', 'closed-source-component_common.original.py', 'closed-source-component_lifecycle.original.py', 'closed-source-component_snapshot.original.py', 'closed-source-late_boundary.original.py', 'closed-source-native_proc_profile.original.py', 'full-candidate.rule', 'guard_live_runtime_properties.original.py', 'live-policy-after.bin', 'live-policy-before.bin', 'parent-candidate.rule', 'policy.stderr', 'policy.stdout', 'policy_runtime_properties_verifier.original.py', 'retirement-bound_inputs.original', 'retirement-disabled_flag.original', 'retirement-preflight.original', 'retirement-probe.original', 'retirement-proof.original', 'runtime-properties.delta.rule', 'service-business-qualification.original', 'service-exit-code.original', 'service-intent.original', 'service-model-binding-complete.original', 'service-model-binding-intent.original', 'service-model-binding.stderr.original', 'service-model-binding.stdout.original', 'service-model-qualification.original', 'service-model-runtime-directory.original', 'service-model.admit.original', 'service-model.exec-identity.original', 'service-model.identity.original', 'service-model.spawn-intent.original', 'service-model.spawn-pid.original', 'service-model.started.original', 'service-model.stderr.original', 'service-model.stdout.original', 'service-model.stop.original', 'service-module-path.original', 'service-native-profile.original', 'service-provider.admit.original', 'service-provider.exec-identity.original', 'service-provider.identity.original', 'service-provider.spawn-intent.original', 'service-provider.spawn-pid.original', 'service-provider.started.original', 'service-provider.stderr.original', 'service-provider.stdout.original', 'service-provider.stop.original', 'service-runtime-location.original', 'service-services-started.original', 'service-sidecar-log-directory.original', 'service-sidecar.admit.original', 'service-sidecar.exec-identity.original', 'service-sidecar.identity.original', 'service-sidecar.spawn-intent.original', 'service-sidecar.spawn-pid.original', 'service-sidecar.started.original', 'service-sidecar.stop.original', 'service-start-utc.original', 'service-supervisor.identity.original', 'service-terminal-scope.original', 'service-worker-qualification.original')
# Unpublished dependencies cannot be supplied or overridden by a caller.
REVIEWED_OFFLINE_COMPARISON = {'bytes': 378604, 'sha256': '149c5063d98b3b7674364e34b98465c387d8f187fe1f26d3060ebf0e75c739cf'}
REVIEWED_COMPARISON_SOURCES = {'candidate_av_source': {'bytes': 17720, 'path': '/home/alex/razr60-local-model-v150/policy-runtime-properties-r10-r1/offline-candidate01/reference/policy_av_query.original.c', 'sha256': '262b264c79d12c1cd2af146808ac1c5998f6aa0159515a17796c381e12630a3c'}, 'candidate_av_tool': {'bytes': 34976, 'path': '/home/alex/razr60-local-model-v150/sepol-offline-query-r1-20261104/build-01/policy_av_query', 'sha256': '86f6d18eab7271d9a5688e5f7b03ed5b55740b9679e7dd078661573ad67f0c90'}, 'comparator': {'bytes': 61615, 'path': '/home/alex/razr60-local-model-v150/policy-runtime-properties-r10-r1/offline-candidate01/source/full_policy_compare_runtime_properties.py', 'sha256': 'd8acacb496fbc1ff1af20a85daa8d03d1552fcbaeed1f837bfa65c1d4cd42871'}, 'existing_tools': {'bytes': 19446, 'path': '/home/alex/razr60-local-model-v150/policy-runtime-properties-r10-r1/offline-candidate01/reference/EXISTING-PRIVATE-POLICY-TOOLS.original.json', 'sha256': 'b41918ef19a0c00b0ab2295c278f204b8d66c654e8dacad05db0dea232fbd288'}, 'image_comparator': {'bytes': 302816, 'path': '/home/alex/razr60-local-model-v150/policy-runtime-properties-r10-r1/offline-candidate01/actual-01/policy_runtime_properties_image', 'sha256': '048d3621e2143dff2c073c73180e4a1cc86c687ae5eaa0e820339352ab76afb2'}, 'image_comparator_source': {'bytes': 22838, 'path': '/home/alex/razr60-local-model-v150/policy-runtime-properties-r10-r1/offline-candidate01/source/policy_runtime_properties_image.c', 'sha256': 'da60ee90209a26216f053064a7ca47ebcb73c4730b4e00378886b5d653de09aa'}}
REVIEWED_POST_COMPARATOR_SOURCE = {'bytes': 65251, 'sha256': '85f325f9525c3470b2fbfe1bf7167f80a54febcffd87d08d2e6cbcdde4597471'}
REVIEWED_COMPARISON_RUNNERS = {'offline_candidate': {'bytes': 21915, 'sha256': '434f954b493c1aadc90929dbc8bba894ffec8acb5f17420746cc520aecac94e9'}, 'post_live_export': {'bytes': 9767, 'sha256': '0793b960f8aed79421097cc8be5ab465ce49a080af1231fbcd9b51e6a4209d6e'}}
REVIEWED_PARENT_READ_AV_PINS = ['5d3c1bc4ef9f799880c530700d7db6065d3c5b3772fbc2b18e02f8940d4f3baf', '8998d0d4797cbc42e3fa6ed347d11ec3bc68c148de7e80300cf0da01bbc13fcd', 'b56b37b7cdc39a5b9f12751ada3e379d896365e764502e987fa3a917c2561cc5', 'd405f388bdcfd78ecbf9c46e14a1d53f93423d74eb3f069bacc58169a6969a8c', 'db3c8b1addf98f370229cc71c37d6bbe09cc67c6c187e13f83d4d46b638c825a', '433c5cd49c3d8e8f2183ed230c30f3064cc408ea8fb21a9a3bb43f744320b4ee', '310ee62c1747b6d8e9870f2d397dde04fbe6ddd0f5a4e4cb44b1716d3b34507a', 'c08fa538cc91dc8ed0a15e1550d478694a5269cbc359155971f83f3f847d44d6', 'b63d9c430d0ad3c92b60fccc9d0d14d131fb209daf7ece0e434458122901bf0a', '9ccb9cd491adbdef4e7a32b4ea39744f42081bd829edd03cd689e452cb844593', '7c1be139ba444d9919ce6d3112e50ad788a9121c8721e2adad7d9c57d8b08c3e']
REVIEWED_PARENT_SET_AV_PINS = ['7ebd6a8d40ef761f98523dea81c9baddecbf6dedea67b831d6627e02d0b6b2da', '296344c44ebbeb2146cc37cab349efdd5de2e8b7577f16cb12292d35cd94f857', '0c0386666b5bd476b93477564be40a520bb4f4d8093bce976780e6ad8a6d932d', 'a689fe2461b430b65a2d47ff0938c9801bea7e6619198091e7ee08b0a58bd955', '99176f65e11969ba1086eddd5136e5c8e5c1bfcf916ecb79f126a1499292e90a', 'bcfd498d482c8a526f71387d5e57f99d08ceaf26cfa67c5a935e63383c64ee3a', 'ccf3e962eb52e488217d30b2b7a09a3d2ded0d482aa8a16f6ea2636d54dd42a2', '319e5dfc5058e7e0d5a4a3577c5679c00ef80fde180c79e16b59f684834168ad', '1a767a6edf976157d715450cb2853e4e882208aca338c320ee6c7ab43e954375', 'a36424018985d2936bfa3d9564d146a1431a4d95980e3ba3affd4f1b25595c28', '964b5b8a36e2eab91df989af00bb669c984ec77c5fcb75b27cfce7e83ecdbaf9']
ROOT_DRIVER = {'bytes': 19616, 'sha256': '574e639f52a3b99dc2ea6d6f82a7455d445fdb4d758bc486cf877df316921ebb'}
ROOT_SOURCE_PACKAGE = {'bytes': 452, 'sha256': '534fa9485da7ae9732714be05db62c5888acdbc9fe399fdfecdac2775580928d'}
ROOT_TRANSPORT_SOURCE = {'bytes':43438,'sha256':'860aaf747e89411efa993783b950f709b1d8ac5d7b606575065bdff74ef98e22'}

def need(ok,message):
    if not ok: raise ValueError(message)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def descriptor(raw):
    need(type(raw) is bytes,'original bytes required')
    return {'bytes':len(raw),'sha256':sha(raw)}
def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode('utf-8')
def strict(raw):
    need(type(raw) is bytes,'strict JSON requires original bytes')
    def pairs(items):
        out={}
        for k,v in items:
            need(k not in out,'duplicate JSON key');out[k]=v
        return out
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def exact(value,expected):
    need(isinstance(value,dict) and all(k in value and type(value[k]) is type(v) and value[k]==v
        for k,v in expected.items()),'exact expected fields differ')
def byte_pin(row,*,maximum=32*1024*1024,allow_empty=False):
    need(isinstance(row,dict) and set(row)=={'bytes','sha256'}
        and type(row['bytes']) is int and (0 if allow_empty else 1)<=row['bytes']<=maximum
        and isinstance(row['sha256'],str) and re.fullmatch('[0-9a-f]{64}',row['sha256']),
        'bounded explicit byte pin required')
    return row
def file_descriptor(row,*,maximum=32*1024*1024):
    need(isinstance(row,dict) and set(row)=={'path','bytes','sha256'},'exact host original descriptor required')
    p=PurePosixPath(row['path']);need(p.is_absolute() and str(p)==row['path'] and '..' not in p.parts
        and '\0' not in row['path'],'canonical absolute original path required')
    byte_pin({k:row[k] for k in ('bytes','sha256')},maximum=maximum,allow_empty=True)
    return row
def bytes_match(raw,row):
    need(descriptor(raw)=={k:row[k] for k in ('bytes','sha256')},'original byte pin differs')
    return raw

def root_scope(raw):
    bytes_match(raw,DECISION);v=strict(raw)
    exact(v,{'schema':'hepta.root.runtime-properties.policy-scope-decision.v1',
        'state':'FORTY_FOUR_ATOM_HOST_CANDIDATE_SELECTED_LIVE_APPLY_PENDING_SOURCE_REVIEW',
        'permission_atom_count':44,'property_type_count':11,
        'existing_native5_twelve_atoms_retained':True,'existing_native5_permission_atom_count':12,
        'property_service_set_remains_denied_for_all_eleven_types':True,
        'capture_and_production_zero_stderr_gates_unchanged':True,
        'live_policy_writes':0,'native_qualification':False,'business_qualification':False})
    need([(r['source'],r['target'],r['class'],r['permissions']) for r in v['rows']]==ROWS
        and v['approved_rule_atoms']==ATOMS,'Root selected exactly eleven types and forty-four read atoms')
    need({k:v['parent_policy'][k] for k in ('bytes','sha256')}==PARENT
        and {k:v['parent_adoption_history'][k] for k in ('bytes','sha256')}==PARENT_ADOPTION
        and v['latest_boundary']==BOUNDARY,
        'Root original parent policy/adoption/latest boundary differs')
    return v

def validate_complete_comparison(report,*,expected_kind,root_scope_decision):
    """Check the complete new report schema, not a renamed historical PASS."""
    need(expected_kind in ('offline_candidate','post_live_export'),'explicit comparison kind')
    decision=root_scope(root_scope_decision)
    exact(report,{'schema':'hepta.runtime-properties-r10.complete-policy-comparison.v1',
        'state':'EXACT_APPROVED_RUNTIME_PROPERTY_READ_DELTA_VERIFIED','comparison_kind':expected_kind,
        'approved_rule_atoms':ATOMS,'phone_operations':0,'active_policy_writes':0,
        'live_policy_adoption_authorized':False,'business_qualified':False})
    for key in ('parent','candidate','root_scope_decision','parent_adoption_history'):
        file_descriptor(report[key])
    need({k:report['parent'][k] for k in ('bytes','sha256')}==PARENT
        and {k:report['root_scope_decision'][k] for k in ('bytes','sha256')}==DECISION
        and {k:report['parent_adoption_history'][k] for k in ('bytes','sha256')}==PARENT_ADOPTION,
        'complete comparison is for another policy/decision/history')
    exact(report['semantic_delta'],{'added_atoms':ATOMS,'removed_atoms':[],
        'all_raw_TE_counter_delta_bound':True,'unconditional_only':True})
    exact(report['coverage'],{'all_TE_rules_enumerated':True,'multiplicity_preserved':True,
        'conditional_expression_and_branch_preserved':True,'explicit_xperm_type_and_all_integers':True,
        'actual_conditional_list_empty':True,'actual_conditional_avtab_count':0,
        'unsupported_rule_kinds':[],'errors':[]})
    full=report['full_image_comparison']
    exact(full,{'all_enumerated_roundtrip_semantics_preserved':True,
        'all_orbit_members_structurally_and_semantically_verified':True})
    image=full['result']
    exact(image,{'schema':'hepta.official-libsepol-runtime-properties-full-image-comparison.v1',
        'complete_input_consumption':True,'cycle_bound':4,'all_cycles_close_at_first_image':True,
        'all_cycle_representatives_stable':True,
        'normalization':'lexicographic-minimum-complete-official-serialization-cycle',
        'only_approved_delta_full_image_equal':True,'negative_missing_atom_rejected':True,
        'negative_unapproved_binder_change_rejected':True,'negative_unknown_handling_rejected':True})
    exact(image,{'approved_rule_atoms':ATOMS,'approved_permission_atom_count':44,
        'baseline_conditional_list_empty':True,'candidate_conditional_list_empty':True,
        'baseline_boolean_count':0,'candidate_boolean_count':0,
        'baseline_conditional_avtab_nodes':0,'candidate_conditional_avtab_nodes':0})
    need(type(image['approved_new_allow_nodes']) is int and 0<=image['approved_new_allow_nodes']<=11,
        'unexpected compiled allow-key expansion')
    orbits=image['serialization_orbits']
    need(isinstance(orbits,list) and [r.get('name') for r in orbits]==
        ['parent','candidate','expected','negative-handle-unknown','negative-binder-change'],
        'complete official serialization cycle set differs')
    for r in orbits:
        need(set(r)=={'name','length','selected_index'} and type(r['length']) is int
            and 1<=r['length']<=4 and type(r['selected_index']) is int
            and 1<=r['selected_index']<=r['length'],'bounded complete serialization cycle differs')
    need(type(image['raw_serializer_idempotent']) is bool
        and image['raw_serializer_idempotent']==all(r['length']==1 for r in orbits),
        'raw idempotence may not be invented')
    av=report['full_av_checks']
    exact(av,{'all_compiled_AV_nodes_validated':True,'all_symbolic_AV_permission_atoms_compared':True,
        'parent_original_query_reexecuted':False,'candidate_complete_compute_av_verified':True,
        'candidate_approved_permission_count':44,'existing_apex_search_unchanged':True,
        'existing_fd_use_preserved_by_complete_TE_counter':True})
    need(len(av['parent_original_compute_av'])==len(av['candidate_complete_compute_av'])==11,
        'all eleven approved read AV edges required')
    for (src,target,cl,perms),row in zip(ROWS,av['candidate_complete_compute_av']):
        exact(row,{'schema':'hepta.offline-policy-av.v1','state':'COMPLETE_OFFLINE_AV_QUERY',
            'denied_requested':'0x00000000','denial_reason_mask':0})
        context=('u:r:' if cl=='binder' else 'u:object_r:')+target+':s0'
        query=row['query']
        need(set(query)=={'source','target','class','class_value','source_type_value','target_type_value',
            'source_policy_permissive','source_policy_neveraudit'}
            and {k:query[k] for k in ('source','target','class')}==
                {'source':'u:r:'+src+':s0','target':context,'class':cl}
            and all(type(query[k]) is int and query[k]>0 for k in
                ('class_value','source_type_value','target_type_value'))
            and query['source_policy_permissive'] is False and query['source_policy_neveraudit'] is False
            and row['policy']['sha256']==report['candidate']['sha256']
            and row['policy']['bytes']==report['candidate']['bytes']
            and row['policy']['input_unchanged'] is True
            and [p['name'] for p in row['permissions']]==perms
            and all(p['policy_allowed'] is True and p['denial_reason_mask']==0 for p in row['permissions']),
            'actual candidate full AV does not allow exactly the approved query')

    need(av.get('all_reviewed_property_set_denials_unchanged') is True
        and len(av['parent_original_set_av'])==len(av['candidate_complete_set_av'])==11,
        'all eleven actual setter-denial originals are required')
    for (src,target,_,_),row in zip(ROWS,av['candidate_complete_set_av']):
        exact(row,{'schema':'hepta.offline-policy-av.v1','state':'COMPLETE_OFFLINE_AV_QUERY',
            'denial_reason_mask':1})
        q=row['query']
        need(q['source']=='u:r:'+src+':s0' and q['target']=='u:object_r:'+target+':s0'
            and q['class']=='property_service' and q['source_policy_permissive'] is False
            and q['source_policy_neveraudit'] is False
            and row['policy']['sha256']==report['candidate']['sha256']
            and row['policy']['bytes']==report['candidate']['bytes']
            and row['policy']['input_unchanged'] is True and row['requested']==row['denied_requested']
            and len(row['permissions'])==1 and row['permissions'][0]['name']=='set'
            and row['permissions'][0]['policy_allowed'] is False
            and row['permissions'][0]['denial_reason_mask']==1,'candidate setter must remain TE denied')
    checks=report['checks']
    need(isinstance(checks,list) and len(checks)==16
        and all(isinstance(x,dict) and x.get('passed') is True for x in checks)
        and type(report['check_count']) is type(report['passed_count']) is int
        and report['check_count']==report['passed_count']==len(checks),'complete comparison checks did not all pass')
    need(len({row['name'] for row in checks})==16
        and any(row['name']=='approved-property-service-set-remains-identical-deny' for row in checks),
        'the independently named setter-denial check is missing or duplicated')
    if expected_kind=='offline_candidate':
        need(report['construction_original_semantic_delta_flag_preserved'] is False,
            'construction-only original flag must remain false')
    return report

def verified_offline(raw,decision_raw):
    need(isinstance(REVIEWED_OFFLINE_COMPARISON,dict) and isinstance(REVIEWED_COMPARISON_SOURCES,dict),
        'actual independent comparison/source review pins are not frozen')
    bytes_match(raw,REVIEWED_OFFLINE_COMPARISON)
    v=validate_complete_comparison(strict(raw),expected_kind='offline_candidate',root_scope_decision=decision_raw)
    need(v['sources']==REVIEWED_COMPARISON_SOURCES,'actual reviewed comparator sources differ')
    return v


def reviewed_source_sha256():
    value=globals().get('__reviewed_source_sha256__')
    need(isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value),
        'caller must inject the digest of the exact reviewed verifier raw bytes')
    return value


def component_source_rows(package_raw):
    bytes_match(package_raw,PACKAGE);manifest=strict(package_raw)
    rows={row['path']:row for row in manifest['files']}
    need(len(rows)==len(manifest['files'])==31 and set(COMPONENT_SOURCE_MEMBERS)<=set(rows),
        'actual R7 source manifest or closed-reader dependency set differs')
    need(manifest['current_combination_sha256']==COMBINATION_SHA256
        and manifest['current_policy_sha256']==PARENT['sha256']
        and manifest['explicit_policy_adoption_sha256']==PARENT_ADOPTION['sha256']
        and manifest['non_native_sidebranch']==NON_NATIVE_BINDING,
        'actual closed package policy/combination/sidebranch differs')
    out={}
    for name in COMPONENT_SOURCE_MEMBERS:
        expected=COMPONENT_SOURCE_PINS[name]
        need({k:rows[name][k] for k in ('bytes','sha256')}==expected,
            'fixed closed-reader source manifest pin differs')
        out[name]={'path':PACKAGE_ROOT+'/'+name,**expected}
    return out


def closed_reader_from_originals(files,package_raw):
    """Compile only the fixed pure readers with a complete explicit raw map.

    Historical readers cannot fall back to phone paths. No reader main,
    publication, snapshot, current-inventory or device observation is called.
    """
    import sys
    import types
    rows=component_source_rows(package_raw)
    supplied={name:bytes_match(files[member],rows[name]) for name,member in COMPONENT_SOURCE_MEMBERS.items()}
    names=('component_common','late_boundary')
    saved={name:sys.modules.get(name) for name in names}
    old_path=sys.path[:];old_dwb=sys.dont_write_bytecode
    modules={}
    try:
        sys.dont_write_bytecode=True
        for name in names:
            path='source/'+name+'.py';module=types.ModuleType(name)
            module.__file__=PACKAGE_ROOT+'/'+path
            module.__reviewed_source_sha256__=rows[path]['sha256']
            module.__reviewed_package_sources__=supplied
            sys.modules[name]=module
            exec(compile(supplied[path],module.__file__,'exec'),module.__dict__)
            modules[name]=module
        return modules['late_boundary']
    finally:
        sys.path[:]=old_path;sys.dont_write_bytecode=old_dwb
        for name in names:
            if saved[name] is None:sys.modules.pop(name,None)
            else:sys.modules[name]=saved[name]


def verify_closed_history(files,package_raw):
    """Verify the five exact native originals and the separate zero-case05."""
    L=closed_reader_from_originals(files,package_raw);rows=[]
    for index,record in enumerate(CLOSED_HISTORY):
        tag=record['attempt'];raws={}
        for kind in ('boundary','inventory','closure'):
            raws[kind]=bytes_match(files['closed-'+tag+'-'+kind.upper()+'.original.json'],record[kind])
        boundary,inventory,closure=L.closed_boundary_originals(raws['boundary'],raws['inventory'],raws['closure'],
            original_descriptor=record['boundary'],combination_sha256=COMBINATION_SHA256,
            package_sha256=PACKAGE['sha256'])
        next_row=CLOSED_HISTORY[index+1]['boundary'] if index+1<len(CLOSED_HISTORY) else None
        need(boundary['prior_boundary']==next_row and boundary['nonce']==record['nonce']
            and boundary['boot_id']==BOOT and boundary['component_qualified'] is False
            and boundary['native_status']=='provider_failed'
            and boundary['actual_native_calls']==record['actual_native_calls']
            and boundary['combination_sha256']==record['combination_sha256']
            and boundary['package_sha256']==record['package_sha256']
            and boundary['inventory']==record['inventory'] and boundary['closure']==record['closure'],
            'a fixed native failure was omitted, reinterpreted or reordered')
        need(closure['component_qualified'] is False and closure['unknown_effects']==0,
            'a failed ancestor was credited or left unknown')
        L.inventory_value(inventory);rows.append((boundary,inventory,closure))
    need([r['attempt'] for r in CLOSED_HISTORY]==['08','07','06','04','03'],
        'the fixed native prefix/tail changed')
    L.require_failed_ancestor_tail([r[0] for r in rows])
    for later,earlier in zip(rows,rows[1:]):
        need(set(earlier[0]['roots'])<=set(later[0]['roots']),
            'later cumulative inventory omitted an older private root')
    side=L.non_native_sidebranch()
    need(side['binding']==NON_NATIVE_BINDING and rows[0][0]['non_native_sidebranch']==NON_NATIVE_BINDING
        and NON_NATIVE_BINDING['native_case_count']==0 and NON_NATIVE_BINDING['component_qualified'] is False,
        'the separate non-native05 proof was dropped or given native credit')
    L.preserve_non_native_private(rows[0][1],side)
    roles=[identity for boundary,_,_ in rows for identity in boundary['component_role_identities'].values()]
    roles+=list(side['binding']['component_role_identities'].values())
    need(len(roles)==len({tuple(r) for r in roles})==18,
        'the complete actual native/sidebranch role union differs')
    return {'chain':rows,'latest':rows[0][0],'inventory':rows[0][1],
        'non_native_sidebranch':side['binding'],'component_role_identities':roles}


def check_capture_members(files,*,allow_failed=False):
    names=set(files)-{'CAPTURE.json'};expected=set(CAPTURE_MEMBER_NAMES)
    if names==expected:return True
    need(allow_failed and names==expected-{'GLOBAL-GATE-post.json'},
        'the complete exact capture member set differs')
    report=strict(files['POLICY-APPLY.json'])
    need(isinstance(report.get('postcheck_error'),dict)
        and report.get('postchecks')=={} and report.get('clean_apply_observed') is False,
        'only a real failed postcheck before its gate may omit that unproduced original')
    return True


def decode_original_archive(raw,caprow,binding_sha):
    need(type(raw) is bytes and 0<len(raw)<=8*1024*1024,'bounded actual original archive required')
    z=zlib.decompressobj(31);data=z.decompress(raw,26*1024*1024+1)
    need(len(data)<=26*1024*1024 and z.eof and not z.unconsumed_tail and not z.unused_data,
        'complete bounded gzip required')
    files={}
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as tf:
        members=tf.getmembers();need(15<=len(members)<=113,'bounded original member count')
        for m in members:
            need(m.isfile() and not m.issym() and not m.islnk()
                and re.fullmatch('[A-Za-z0-9_.-]{1,100}',m.name) and m.name not in ('.','..')
                and m.name not in files and 0<=m.size<=8*1024*1024 and m.uid==m.gid==0
                and m.mode==0o600 and not m.pax_headers,'exact regular original tar member required')
            stream=tf.extractfile(m);need(stream is not None,'missing member body')
            b=stream.read(m.size+1);need(len(b)==m.size,'incomplete member body');files[m.name]=b
    need('CAPTURE.json' in files and descriptor(files['CAPTURE.json'])==caprow,'capture raw bytes differ')
    cap=strict(files['CAPTURE.json'])
    exact(cap,{'schema':'hepta.runtime-properties-r10.live-original-capture.v1','state':'CAPTURED_EXISTING_APPLY_ORIGINALS',
        'binding_sha256':binding_sha,'new_effects':0,'policy_adoption_authorized':False,'business_qualified':False})
    rows=cap['files']
    need(isinstance(rows,list) and len({r['path'] for r in rows})==len(rows)==cap['file_count']
        and set(files)=={r['path'] for r in rows}|{'CAPTURE.json'},'complete original inventory differs')
    total=0
    for row in rows:
        need(set(row)=={'path','original_path','bytes','sha256','metadata'}
            and row['original_path']==BASE+'/'+OUT_NAME+'/'+row['path'],'original source path differs')
        b=bytes_match(files[row['path']],row);m=row['metadata']
        need(isinstance(m,list) and len(m)==9 and all(type(x) is int and x>=0 for x in m)
            and m[2]==0o100600 and m[3:6]==[0,0,1] and m[6]==len(b),'actual private metadata differs')
        total+=len(b)
    need(total==cap['total_bytes'] and total<=24*1024*1024,'complete archive byte budget differs')
    check_capture_members(files,allow_failed=True)
    return files,cap


MANDATORY_LIVE_FILES = {'ACTUAL-RETIREMENT-INPUTS.original.json','APPLY-INTENT.json','BINDING.original.json','CLOSED-COMPONENT-PACKAGE.original.json','COMMAND-RETURN.json','LATEST-BOUNDARY-DESCRIPTOR.original.json','OFFLINE-COMPLETE-COMPARISON.original.json','ORIGINAL-SOURCE-PATHS.json','PARENT-ADOPTION-HISTORY.original.json','POLICY-APPLY.json','PRECHECK.json','RETIREMENT-HOST-CLOSURE.original.json','ROOT-SCOPE-DECISION.original.json','STAGE-COMPLETE.original.json','STAGE-INTENT.original.json','apply_runtime_properties_once.original.sh','closed-03-BOUNDARY.original.json','closed-03-CLOSURE.original.json','closed-03-INVENTORY.original.json','closed-04-BOUNDARY.original.json','closed-04-CLOSURE.original.json','closed-04-INVENTORY.original.json','closed-06-BOUNDARY.original.json','closed-06-CLOSURE.original.json','closed-06-INVENTORY.original.json','closed-07-BOUNDARY.original.json','closed-07-CLOSURE.original.json','closed-07-INVENTORY.original.json','closed-08-BOUNDARY.original.json','closed-08-CLOSURE.original.json','closed-08-INVENTORY.original.json','closed-reference-attempt05-AFTER-INVENTORY.original.json','closed-reference-attempt05-CLOSURE.original.json','closed-reference-attempt05-SIDE-PROOF.original.json','closed-reference-component_common_r5.original.py','closed-reference-environment_parent_late_boundary_r6.original.py','closed-reference-non_native_attempt05.original.py','closed-reference-policy_parent_late_boundary_r4.original.py','closed-source-component_common.original.py','closed-source-component_lifecycle.original.py','closed-source-component_snapshot.original.py','closed-source-late_boundary.original.py','closed-source-native_proc_profile.original.py','full-candidate.rule','guard_live_runtime_properties.original.py','live-policy-after.bin','live-policy-before.bin','parent-candidate.rule','policy.stderr','policy.stdout','policy_runtime_properties_verifier.original.py','runtime-properties.delta.rule'}


def verify_apply_originals(files,binding_sha):
    need(MANDATORY_LIVE_FILES<=set(files),'complete original policy transaction files missing')
    raw=files['BINDING.original.json'];need(sha(raw)==binding_sha,'actual binding raw differs')
    b=validate_binding(raw,decision_raw=files['ROOT-SCOPE-DECISION.original.json'],
        comparison_raw=files['OFFLINE-COMPLETE-COMPARISON.original.json'],
        retirement_raw=files['ACTUAL-RETIREMENT-INPUTS.original.json'],
        parent_adoption_raw=files['PARENT-ADOPTION-HISTORY.original.json'],
        boundary_descriptor_raw=files['LATEST-BOUNDARY-DESCRIPTOR.original.json'],
        package_raw=files['CLOSED-COMPONENT-PACKAGE.original.json'])
    for name,key in (('guard_live_runtime_properties.original.py','guard_source'),
                     ('policy_runtime_properties_verifier.original.py','verifier_source'),
                     ('apply_runtime_properties_once.original.sh','shell_source')):
        bytes_match(files[name],b[key])
    bytes_match(files['policy_runtime_properties_verifier.original.py'],APPLIED_VERIFIER)
    need(b['verifier_source']==APPLIED_VERIFIER,'actual apply used another applied verifier source')
    check_capture_members(files)
    history=verify_closed_history(files,files['CLOSED-COMPONENT-PACKAGE.original.json'])
    latest=history['latest']
    need(b['component_sources']==component_source_rows(files['CLOSED-COMPONENT-PACKAGE.original.json']),
        'actual raw component source binding differs')
    need(files['runtime-properties.delta.rule']==RULE
        and files['full-candidate.rule']==files['parent-candidate.rule']+RULE,
        'rule bytes are not the complete retained parent plus exactly forty-four approved atoms')
    bytes_match(files['parent-candidate.rule'],PARENT_RULE);bytes_match(files['full-candidate.rule'],FULL_RULE)
    bytes_match(files['live-policy-before.bin'],PARENT)
    pre=strict(files['PRECHECK.json']);intent=strict(files['APPLY-INTENT.json']);ret=strict(files['COMMAND-RETURN.json'])
    report=strict(files['POLICY-APPLY.json'])
    exact(pre,{'schema':'hepta.runtime-properties-r10.live-precheck.v1','state':'LATEST_CLOSED_BOUNDARY_VERIFIED_FOR_SINGLE_APPLY',
        'binding_sha256':binding_sha,'boot_id':BOOT,'parent_policy':PARENT,'root_scope_decision':DECISION,
        'approved_rule':descriptor(RULE),'policy_apply_attempts':0,'automatic_retry':False,'automatic_rollback':False})
    exact(intent,{'schema':'hepta.runtime-properties-r10.single-apply-intent.v1','binding_sha256':binding_sha,
        'precheck_sha256':sha(files['PRECHECK.json']),'argv':ARGV,'maximum_apply_attempts':1,
        'root_scope_decision_sha256':DECISION['sha256'],'pre_policy_boundary_sha256':BOUNDARY['sha256'],
        'apply_timeout_seconds':45,'kill_grace_seconds':5,'automatic_retry':False,
        'automatic_rollback':False,'automatic_policy_adoption':False})
    exact(ret,{'schema':'hepta.runtime-properties-r10.actual-command-return.v1','return_code':0,
        'argv':ARGV,'binding_sha256':binding_sha,'apply_attempts':1,'maximum_apply_attempts':1,
        'apply_timeout_seconds':45,'kill_grace_seconds':5,'automatic_retry':False,'automatic_rollback':False})
    exact(report,{'schema':'hepta.runtime-properties-r10.actual-live-apply.v1',
        'state':'ACTUAL_SINGLE_APPLY_REQUIRES_INDEPENDENT_LIVE_COMPARISON','binding_sha256':binding_sha,
        'return_code':0,'apply_attempts':1,'maximum_apply_attempts':1,'argv':ARGV,
        'apply_timeout_seconds':45,'kill_grace_seconds':5,'parent_policy':PARENT,'approved_rule_atoms':ATOMS,
        'delta_rule':descriptor(RULE),'full_rule':FULL_RULE,'root_scope_decision':DECISION,
        'pre_policy_boundary':BOUNDARY,'actual_parser_sha256':PARSER['sha256'],
        'boot_id':BOOT,'enforcing':True,'postcheck_error':None,'clean_apply_observed':True,
        'automatic_retry':False,'automatic_rollback':False,'policy_adoption_authorized':False,
        'independent_live_complete_comparison_required':True,'service_start_admitted':False,
        'model_requests':0,'task_submissions':0,'ui_actions':0,'service_starts':0,'service_stops':0,'business_qualified':False})
    need(report['offline_candidate']==b['offline_candidate']
        and report['complete_offline_comparison']==b['complete_offline_comparison']
        and report['actual_live_policy']==descriptor(files['live-policy-after.bin'])
        and report['actual_live_policy']!=PARENT and files['policy.stdout']==files['policy.stderr']==b''
        and report['stdout']==report['stderr']==descriptor(b'')
        and report['precheck_sha256']==sha(files['PRECHECK.json'])
        and report['intent_sha256']==sha(files['APPLY-INTENT.json']), 'actual apply/streams/export originals disagree')
    need(type(report['live_bytes_equal_offline_candidate']) is bool
        and report['live_bytes_equal_offline_candidate']==(report['actual_live_policy']==b['offline_candidate']),
        'kernel export equality is an observation, never a precondition')
    post=report['postchecks']
    exact(post,{'complete_original_state_equal':True,'complete_service_records_equal':True,
        'original_UI_adbd_rootfs_mounts_preserved':True,'old_module_disabled':True,
        'old_retirement_current_equality_claimed':False})
    prestate=pre['pre_policy_boundary_verification'];poststate=post['pre_policy_boundary_verification']
    for state in (prestate,poststate):
        exact(state,{'schema':'hepta.runtime-properties-r10.pre-policy-boundary-verification.v1',
            'state':'EXACT_LATEST08_NATIVE_CHAIN_AND_NON_NATIVE05_ORIGINALS_UNCHANGED',
            'previous_boundary':BOUNDARY,'closed_components':5,
            'non_native_sidebranch':NON_NATIVE_BINDING,'native_case_credit_for_sidebranch':0,
            'component_role_identities':history['component_role_identities'],'inventory_sha256':BOUNDARY_INVENTORY['sha256'],
            'original_retirement_sha256':RETIREMENT,'old_retirement_current_equality_claimed':False,
            'original_retirement_rewritten':False,'phone_tool_calls':0,'model_requests':0,'signals':0,'writes':0})
        need(state['roots']==latest['roots'] and len(state['absence_observations'])==2,
            'complete latest roots and two group absences required')
        for absence in state['absence_observations']:
            need(absence['members']==[] and absence['kernel_group_absence'] is True,'owned role absence incomplete')
    need({k:v for k,v in prestate.items() if k not in ('absence_observations','endpoints')}==
         {k:v for k,v in poststate.items() if k not in ('absence_observations','endpoints')},
         'original cumulative state changed across apply')
    origins=strict(files['ORIGINAL-SOURCE-PATHS.json'])
    for state in (prestate,poststate):
        source_rows=state['component_source_originals']
        need(set(source_rows)==set(COMPONENT_SOURCE_MEMBERS),'all closed-source full identities are required')
        for name,member in COMPONENT_SOURCE_MEMBERS.items():
            row=source_rows[name]
            need(set(row)=={'path','bytes','sha256','metadata'}
                and {k:row[k] for k in ('path','bytes','sha256')}==b['component_sources'][name]
                and row==origins[member],'closed-source identity bookends differ')
            m=row['metadata'];need(len(m)==9 and all(type(n) is int and n>=0 for n in m)
                and m[2]==0o100600 and m[3:6]==[0,0,1] and m[6]==row['bytes'],
                'closed source private full-nine identity differs')
        for record in CLOSED_HISTORY:
            for kind in ('boundary','inventory','closure'):
                name='closed-'+record['attempt']+'-'+kind.upper()+'.original.json'
                need(origins[name]==record[kind],'native raw origin full identity differs')
    for gate in (pre['global_gate'],post['global_gate']):
        need(gate['exit_code']==0 and gate['read_only'] is True,'global pending gate failed')
    need(pre['locks']==post['locks'] and all(x['exclusive_nonblocking_acquired'] is True for x in post['locks']),
         'original journal/claim locks differ or are held')
    need(type(pre['observed_monotonic_ns']) is type(intent['issued_monotonic_ns']) is type(ret['observed_monotonic_ns']) is int
        and 0<pre['observed_monotonic_ns']<=intent['issued_monotonic_ns']<=ret['observed_monotonic_ns'],
        'actual phone operation ordering differs')
    return b,report


def expectation_value(binding_raw,*,binding_descriptor,decision_descriptor,comparison_descriptor):
    file_descriptor(binding_descriptor);file_descriptor(decision_descriptor);file_descriptor(comparison_descriptor)
    bytes_match(binding_raw,binding_descriptor);b=strict(binding_raw)
    need(b['schema']=='hepta.runtime-properties-r10.live-apply-binding.v1' and b['root_approval']==APPROVAL
        and b['root_scope_decision']==DECISION and b['pre_policy_boundary']==BOUNDARY
        and b['parent_policy']==PARENT and b['approved_rule_atoms']==ATOMS
        and b['parent_adoption_history']==PARENT_ADOPTION and b['component_package']==PACKAGE
        and b['pre_policy_boundary_descriptor']==BOUNDARY_DESCRIPTOR
        and b['native_history']==CLOSED_HISTORY and b['non_native_sidebranch']==NON_NATIVE_BINDING,
        'actual reviewed binding is required before expectation')
    need({k:decision_descriptor[k] for k in ('bytes','sha256')}==DECISION
        and {k:comparison_descriptor[k] for k in ('bytes','sha256')}==b['complete_offline_comparison'],
        'expectation source original pins differ')
    return {'schema':'hepta.runtime-properties-r10.policy-pre-live-expectation.v1','release_id':'v150-r10-r1',
        'boot_id':BOOT,'binding':binding_descriptor,'root_scope_decision':decision_descriptor,
        'offline_comparison':comparison_descriptor,'parent_policy':PARENT,'offline_candidate':b['offline_candidate'],
        'comparison_route':'verified_semantic_export','expected_live_export':None,'approved_rule':descriptor(RULE),
        'retirement_sha256':RETIREMENT,'prior_boundary_sha256':BOUNDARY['sha256'],
        'parent_adoption_sha256':PARENT_ADOPTION['sha256'],'policy_adoption_authorized':False,
        'service_start_admitted':False,'phone_calls':0,'policy_writes':0}


def verify_pre_live_expectation(expectation_raw,*,read_pinned):
    v=strict(expectation_raw)
    binding=read_pinned(file_descriptor(v['binding']));bytes_match(binding,v['binding'])
    decision=read_pinned(file_descriptor(v['root_scope_decision']));root_scope(decision)
    comparison=read_pinned(file_descriptor(v['offline_comparison']));verified_offline(comparison,decision)
    need(strict(binding)['verifier_source']==APPLIED_VERIFIER,
        'pre-live expectation is bound to another applied verifier source')
    need(v==expectation_value(binding,binding_descriptor=v['binding'],decision_descriptor=v['root_scope_decision'],
        comparison_descriptor=v['offline_comparison']),'explicit pre-load semantic/null expectation differs')
    return v


def descriptor_key(row):
    file_descriptor(row);return (row['path'],row['bytes'],row['sha256'])


def original_process(value,get,*,argv,outer=False):
    """Read the actual original streams; no child is run by this verifier."""
    exact(value,{'argv':argv,'returncode':0,'timed_out':False,
        'captured_streams_complete':True,'automatic_retry':False})
    if outer:
        exact(value,{'phone_operations':0,'active_policy_writes':0})
        need(value['input_originals_before']==value['input_originals_after']
            and type(value['started_epoch_ns']) is type(value['ended_epoch_ns']) is int
            and 0<value['started_epoch_ns']<=value['ended_epoch_ns'],
            'original host execution input or timestamp bookends differ')
        need(type(value['elapsed_seconds']) in (int,float) and 0<=value['elapsed_seconds']<=900,
            'bounded original host elapsed time required')
    else:exact(value,{'host_only':True})
    need(get(value['stderr'])==b'','original comparison child stderr is not empty')
    return strict(get(value['stdout']))


def verify_comparison_proof(index_raw,*,expected_kind,read_pinned,decision_raw,live_summary=None,live_inputs_raw=None):
    """Verify the retained source/process proof without rerunning policy parsers.

    The official image cycle is retained separately. This gate reads its raw C
    output and the actual audited comparator output, not every cycle image.
    Original P4 paths are resolved only through the explicit origin map.
    """
    index=strict(index_raw)
    fields={'schema','comparison_kind','report','plan','process','execution','files','origin_map',
        'complete_archive','complete_archive_manifest',
        'complete_comparison_outputs_retained_elsewhere','all_orbit_images_embedded',
        'phone_operations','active_policy_writes'}
    need(set(index)==fields,'explicit complete proof-index fields differ')
    exact(index,{'schema':'hepta.runtime-properties-r10.adoption-proof-inputs.v1',
        'comparison_kind':expected_kind,'complete_comparison_outputs_retained_elsewhere':True,
        'all_orbit_images_embedded':False,'phone_operations':0,'active_policy_writes':0})
    # These references preserve the separately retained complete evidence.
    # Their orbit images are not implicitly copied into the runtime bundle.
    file_descriptor(index['complete_archive'],maximum=256*1024*1024)
    file_descriptor(index['complete_archive_manifest'])
    rows=index['files'];need(isinstance(rows,list) and 4<=len(rows)<=512,'bounded complete proof file set')
    retained={};by_path={};total=0
    for row in rows:
        key=descriptor_key(row);need(row['path'] not in by_path,'duplicate retained proof path')
        raw=bytes_match(read_pinned(row),row);retained[key]=raw;by_path[row['path']]=row;total+=len(raw)
    need(total<=16*1024*1024,'bounded small proof original set required')
    mappings=index['origin_map'];need(isinstance(mappings,list) and len(mappings)==len(rows),
        'one explicit original-to-retained mapping per proof original required')
    original={};reverse={};original_paths=set()
    for item in mappings:
        need(set(item)=={'original','retained'},'exact original/retained mapping required')
        a,b=item['original'],item['retained'];ka,kb=descriptor_key(a),descriptor_key(b)
        need(a['path'] not in original_paths and ka not in original and kb in retained and kb not in reverse
            and a['bytes']==b['bytes'] and a['sha256']==b['sha256'],
            'explicit original copy mapping is missing, duplicated, or changed')
        original_paths.add(a['path']);original[ka]=retained[kb];reverse[kb]=a
    def get(row):
        key=descriptor_key(row);need(key in original,'required original absent from explicit proof map')
        return original[key]
    top={}
    for key in ('report','plan','process','execution'):
        identity=descriptor_key(index[key]);need(identity in retained and identity in reverse,'top proof original is not indexed')
        top[key]=(reverse[identity],retained[identity])
    report_raw=top['report'][1];report=validate_complete_comparison(strict(report_raw),
        expected_kind=expected_kind,root_scope_decision=decision_raw)
    if expected_kind=='offline_candidate':verified_offline(report_raw,decision_raw)
    else:
        need(isinstance(REVIEWED_POST_COMPARATOR_SOURCE,dict),'reviewed post-comparator source is not frozen')
        need({k:report['sources']['comparator'][k] for k in ('bytes','sha256')}==REVIEWED_POST_COMPARATOR_SOURCE,
            'actual post report uses another source revision')
    sources=report['sources'];plan=strict(top['plan'][1]);process=strict(top['process'][1]);execution=strict(top['execution'][1])
    for key in ('root_scope_decision','parent','candidate'):
        need(plan[key]==report[key],'comparison plan/report input differs')
    need(plan['parent_adoption']==report['parent_adoption_history'],'comparison history input differs')
    bytes_match(get(plan['root_scope_decision']),DECISION);bytes_match(get(plan['parent_adoption']),PARENT_ADOPTION)
    need(get(plan['delta_rule'])==RULE and get(plan['full_rule'])==get(plan['parent_rule'])+RULE,
        'proof rules are not exact approved bytes')
    bytes_match(get(plan['parent_rule']),PARENT_RULE);bytes_match(get(plan['full_rule']),FULL_RULE)
    for name in ('comparator','image_comparator','image_comparator_source','existing_tools','candidate_av_tool','candidate_av_source'):
        get(sources[name])
    common_sources={k:v for k,v in sources.items() if k not in ('comparator','live_provenance_verifier','applied_verifier_source','image_build_result')}
    need(isinstance(REVIEWED_COMPARISON_SOURCES,dict) and all(
        {q:v[q] for q in ('bytes','sha256')}=={q:REVIEWED_COMPARISON_SOURCES[k][q] for q in ('bytes','sha256')}
        for k,v in common_sources.items()),'complete comparator binary/tool source pins differ')
    for name,key in [('image_comparator','image_comparator'),('image_comparator_source','image_comparator_source'),
        ('existing_tools','tool_inventory'),('candidate_av_tool','candidate_av_tool'),('candidate_av_source','candidate_av_source')]:
        need(sources[name]==plan[key],'report source does not identify original plan input')
    output=str(PurePosixPath(top['report'][0]['path']).parent)
    argv=['/usr/bin/python3','-I','-B',sources['comparator']['path'],'--plan',top['plan'][0]['path'],
        '--plan-sha256',top['plan'][0]['sha256'],'--out',output,'--execute-host-only']
    result=original_process(process,get,argv=argv,outer=True)
    exact(result,{'state':report['state'],'checks':16,'result':top['report'][0],
        'new_atoms':44,'removed_atoms':0,'phone_operations':0,'active_policy_writes':0})
    need(isinstance(REVIEWED_COMPARISON_RUNNERS,dict) and expected_kind in REVIEWED_COMPARISON_RUNNERS,
        'reviewed actual host comparison runner source is not frozen')
    bytes_match(get(execution['source']),REVIEWED_COMPARISON_RUNNERS[expected_kind])
    exact(execution,{'schema':'hepta.runtime-properties.actual-host-execution.v1',
        'plan':top['plan'][0],'comparison_process':top['process'][0],'report':top['report'][0],
        'root_scope_decision':plan['root_scope_decision'],'parent':plan['parent'],'candidate':plan['candidate'],
        'returncode':0,'timed_out':False,'captured_streams_complete':True,'automatic_retry':False,
        'all_originals_rechecked':True,'check_count':16,'passed_count':16,'phone_operations':0,
        'active_policy_writes':0,'live_policy_adoption_authorized':False,'business_qualified':False})
    wanted_state=('ACTUAL_HOST_CONSTRUCTION_AND_COMPLETE_COMPARISON_FINISHED' if expected_kind=='offline_candidate'
        else 'ACTUAL_HOST_POST_LIVE_COMPLETE_COMPARISON_FINISHED')
    need(execution['state']==wanted_state,'actual comparison execution kind differs')
    proof_rows=report['retained_originals'];need(isinstance(proof_rows,list),'complete original child index required')
    children={}
    for row in proof_rows:
        name=PurePosixPath(row['path']).name;need(name not in children,'duplicate original child filename');children[name]=row
    def child(label,argv):
        row=children.get(label+'.PROCESS.json');need(row is not None,'missing actual original child terminal')
        value=strict(get(row));need(value['stdout']==children.get(label+'.stdout.original')
            and value['stderr']==children.get(label+'.stderr.original'),'child index and terminal streams differ')
        return original_process(value,get,argv=argv)
    image=child('complete-image',[plan['image_comparator']['path'],'--compare-reviewed-runtime-properties',
        plan['parent']['path'],plan['candidate']['path'],output+'/normalized'])
    need(image==report['full_image_comparison']['result'],'complete C image output differs from report')
    parent_rows=plan['parent_av_originals'];need(parent_rows==report['full_av_checks']['parent_original_compute_av']
        and len(parent_rows)==11,'original eleven-type read AV input set differs')
    need(isinstance(REVIEWED_PARENT_READ_AV_PINS,list) and len(REVIEWED_PARENT_READ_AV_PINS)==11,
        'actual reviewed parent read-AV original pins are not frozen')
    expected_parent_hashes=REVIEWED_PARENT_READ_AV_PINS
    for i,((src,target,kind,perms),old_desc) in enumerate(zip(ROWS,parent_rows)):
        old_raw=get(old_desc);need(sha(old_raw)==expected_parent_hashes[i],'original parent complete-AV output differs')
        old=strict(old_raw);context=('u:r:' if kind=='binder' else 'u:object_r:')+target+':s0'
        cmd=[plan['candidate_av_tool']['path'],'--policy',plan['candidate']['path'],'--sha256',plan['candidate']['sha256'],
            '--source','u:r:'+src+':s0','--target',context,'--class',kind]
        for perm in perms:cmd+=['--perm',perm]
        new=child('candidate-complete-av-%02d'%(i+1),cmd)
        need(new==report['full_av_checks']['candidate_complete_compute_av'][i] and new['query']==old['query'],
            'complete AV original full query or result changed')
        before={r['name']:r for r in old['permissions']}
        need(len(before)==len(old['permissions']) and all(before[n]['policy_allowed'] is False
            and before[n]['denial_reason_mask']==1 for n in perms),'original approved parent bits were not TE denied')
        for item in new['permissions']:
            need(all(item[k]==before[item['name']][k] for k in
                ('name','bit','auditallow_bit','auditdeny_bit','denied_with_auditdeny_clear')),
                'AV identity/audit behavior changed outside exact policy bits')
        need(all(new[k]==old[k] for k in ('decided','auditallow','auditdeny')),'AV audit/decision vector changed')

    parent_set_rows=plan['parent_set_av_originals']
    need(parent_set_rows==report['full_av_checks']['parent_original_set_av']
        and len(parent_set_rows)==11 and isinstance(REVIEWED_PARENT_SET_AV_PINS,list)
        and len(REVIEWED_PARENT_SET_AV_PINS)==11,
        'all original setter-denial inputs and reviewed pins are required')
    set_keys=('query','requested','allowed','denied_requested','denial_reason_mask','decided',
              'auditallow','auditdeny','permissions','constraint_explanation','reason_flag_definitions')
    for i,((src,target,_,_),old_desc) in enumerate(zip(ROWS,parent_set_rows)):
        old_raw=get(old_desc);need(sha(old_raw)==REVIEWED_PARENT_SET_AV_PINS[i],
            'original parent setter denial differs')
        old=strict(old_raw)
        exact(old,{'schema':'hepta.offline-policy-av.v1','state':'COMPLETE_OFFLINE_AV_QUERY',
            'denial_reason_mask':1})
        need(old['policy']['sha256']==PARENT['sha256'] and old['policy']['bytes']==PARENT['bytes']
            and old['policy']['input_unchanged'] is True
            and old['query']['source']=='u:r:'+src+':s0'
            and old['query']['target']=='u:object_r:'+target+':s0'
            and old['query']['class']=='property_service'
            and old['query']['source_policy_permissive'] is False
            and old['query']['source_policy_neveraudit'] is False
            and len(old['permissions'])==1 and old['permissions'][0]['name']=='set'
            and old['permissions'][0]['policy_allowed'] is False
            and old['permissions'][0]['denial_reason_mask']==1
            and old['requested']==old['denied_requested'],'actual parent set must be TE denied')
        cmd=[plan['candidate_av_tool']['path'],'--policy',plan['candidate']['path'],'--sha256',plan['candidate']['sha256'],
            '--source','u:r:'+src+':s0','--target','u:object_r:'+target+':s0',
            '--class','property_service','--perm','set']
        new=child('candidate-property-set-deny-%02d'%(i+1),cmd)
        need(new==report['full_av_checks']['candidate_complete_set_av'][i]
            and all(new[k]==old[k] for k in set_keys),'setter decision or audit behavior changed')

    apex_raw=get(plan['parent_apex_original']);need(sha(apex_raw)=='34fc5fe1e5278b07ff80b80de8b0cf3c8a4bbaaf5ca3518a9095a2e3ed78d6b7',
        'actual original APEX query differs')
    apex=child('candidate-existing-apex-search',[plan['candidate_av_tool']['path'],'--policy',plan['candidate']['path'],
        '--sha256',plan['candidate']['sha256'],'--source','u:r:'+WORKER+':s0',
        '--target','u:object_r:apex_mnt_dir:s0','--class','dir','--perm','search'])
    before=strict(apex_raw)
    need(all(apex[k]==before[k] for k in ('query','requested','allowed','denied_requested','denial_reason_mask',
        'decided','auditallow','auditdeny','permissions')),'existing APEX permission changed')
    if expected_kind=='offline_candidate':
        receipt=strict(get(plan['construction_receipt']));need(plan['construction_receipt']==report['construction_original']
            and execution['construction_receipt']==plan['construction_receipt'],'original construction linkage differs')
        exact(receipt,{'schema':'hepta.runtime-properties.offline-construction-receipt.v1',
            'state':'COMPLETE_OFFLINE_CANDIDATE_CONSTRUCTION','parent':plan['parent'],'candidate':plan['candidate'],
            'root_scope_decision':plan['root_scope_decision'],'semantic_delta_verified':False,
            'phone_operations':0,'active_policy_writes':0,'input_originals_unchanged':True})
        need(receipt['image_constructor']==plan['image_comparator']
            and receipt['image_constructor_source']==plan['image_comparator_source']
            and execution['build']==receipt['build_result'],'actual construction source/build linkage differs')
        build_desc=receipt['build_result']
        constructed=original_process(strict(get(receipt['process'])),get,argv=[plan['image_comparator']['path'],
            '--construct-reviewed-runtime-properties',plan['parent']['path'],str(PurePosixPath(plan['candidate']['path']).parent)],outer=True)
        exact(constructed,{'schema':'hepta.official-libsepol-runtime-properties-candidate-construction.v1',
            'state':'CANDIDATE_CONSTRUCTED_NOT_YET_SEMANTICALLY_VERIFIED','approved_rule_atoms':ATOMS,
            'approved_permission_atom_count':44,'parent_bytes':PARENT['bytes'],'candidate_bytes':plan['candidate']['bytes'],
            'complete_input_consumption':True,'semantic_delta_verified':False,'phone_operations':0,'active_policy_writes':0})
    else:
        need(live_summary is not None and type(live_inputs_raw) is bytes,'actual independent live-chain proof required')
        fields={'schema','root_scope_decision','parent_adoption','parent','candidate','image_build_result',
            'live_provenance_inputs','live_verifier_source','applied_verifier_source','input_original_map',
            'delta_rule','full_rule','parent_rule','tool_inventory','image_comparator','image_comparator_source',
            'parent_av_originals','parent_set_av_originals','parent_apex_original','candidate_av_tool',
            'candidate_av_source','secondary_observation'}
        need(set(plan)==fields and plan['schema']==
            'hepta.runtime-properties-r10.post-live-complete-policy-comparison-plan.v2','exact independent post plan required')
        build_desc=plan['image_build_result'];proof=report['post_live_originals']
        need(sources['image_build_result']==build_desc and sources['live_provenance_verifier']==plan['live_verifier_source']
            and sources['applied_verifier_source']==plan['applied_verifier_source'],
            'post independent/applied source input linkage differs')
        bytes_match(get(plan['applied_verifier_source']),APPLIED_VERIFIER)
        need(sha(get(plan['live_verifier_source']))==reviewed_source_sha256()
            and get(plan['live_provenance_inputs'])==live_inputs_raw,'post used another verifier or live original input')
        exact(proof,{'schema':'hepta.runtime-properties.post-live-originals-recheck.v2',
            'live_provenance_inputs':plan['live_provenance_inputs'],'input_original_map':plan['input_original_map'],
            'live_provenance_raw_sha256':sha(live_inputs_raw),'live_provenance_verifier':plan['live_verifier_source'],
            'applied_verifier_source':plan['applied_verifier_source'],
            'independent_verifier_source':plan['live_verifier_source'],
            'independent_reviewed_verifier_source_executed':True,'actual_applied_verifier_source_preserved':True,
            'actual_original_parent':live_summary['parent'],
            'actual_original_candidate':live_summary['candidate'],'binding_sha256':live_summary['binding_sha256'],
            'host_capture_sha256':live_summary['host_capture_sha256'],
            'provenance_inputs_canonical_sha256':live_summary['provenance_inputs_sha256'],
            'root_transaction':live_summary['root_transaction'],'image_build_result':build_desc,
            'phone_operations':0,'active_policy_writes':0,'policy_adoption_authorized':False})
        # The post process retained a separate P4 copy of each original Mac
        # input. Its explicit map must be consistent with this proof map.
        map_rows=plan['input_original_map'];need(isinstance(map_rows,list) and 1<=len(map_rows)<=512,
            'bounded post live-original map required')
        by_original={}
        for row in map_rows:
            need(set(row)=={'original','retained'},'post live original mapping fields differ')
            a,b=row['original'],row['retained'];key=descriptor_key(a);file_descriptor(b)
            need(key not in by_original and a['bytes']==b['bytes'] and a['sha256']==b['sha256'],
                'post original mapping duplicated or changed')
            by_original[key]=b
        for name,field in [('parent','parent'),('candidate','candidate'),('root_scope_decision','root_scope_decision'),
            ('parent_adoption_history','parent_adoption'),
            ('applied_verifier_source','applied_verifier_source'),
            ('independent_verifier_source','live_verifier_source')]:
            need(by_original.get(descriptor_key(live_summary[name]))==plan[field],
                'actual live original does not map to exact independently parsed bytes')
    build=strict(get(build_desc))
    exact(build,{'schema':'hepta.runtime-properties.actual-host-build.v1','returncode':0,
        'source':plan['image_comparator_source'],'binary':plan['image_comparator']})
    need(get(build['stdout'])==get(build['stderr'])==b'','actual original compiler streams differ')
    need(build['static_library']['sha256']=='2174eb5cfde7050e7c82e7805675a45c62cc54e27547ea62517b3e4d2e96400b'
        and build['runtime_library']['sha256']=='c1e965eaae791bc4abc1fc2336a5433d7c483e5117778dbd06234b3fa9172092',
        'complete-image official library provenance differs')
    return {'report':report,'report_descriptor':index['report'],'original_report_descriptor':top['report'][0],
        'plan':plan,'execution':execution,'proof_index_sha256':sha(index_raw),
        'small_originals_read':len(rows),'small_original_bytes':total,'all_orbit_images_read_by_consumer':False}


ADOPTION_FIELDS={'schema','release_id','boot_id','root_scope_decision','parent_adoption_history',
    'parent_policy','actual_export','offline_candidate','delta_rule','parent_rule','full_rule',
    'retirement_descriptor','retirement_host_closure','pre_policy_boundary_descriptor','pre_policy_boundary',
    'offline_comparison','post_live_comparison','offline_proof_inputs','post_live_proof_inputs',
    'live_provenance','pre_live_expectation','verification_originals','root_decision'}


def adoption_decision(value,live):
    return {'schema':'hepta.root.runtime-properties-policy-adoption-decision.v1',
        'decision':'ADOPT_INDEPENDENTLY_VERIFIED_ACTUAL_EXPORTED_POLICY',
        'actual_policy_sha256':value['actual_export']['sha256'],'root_scope_decision_sha256':DECISION['sha256'],
        'post_live_comparison_sha256':value['post_live_comparison']['sha256'],
        'actual_live_binding_sha256':live['binding_sha256'],
        'pre_live_expectation_sha256':value['pre_live_expectation']['sha256'],
        'prior_boundary_sha256':BOUNDARY['sha256'],'permission_atoms':ATOMS,
        'automatic_adoption':False,'service_start_admitted':False,'component_qualified':False}


def validate_adoption_value(value,*,read_pinned,require_root_decision=True):
    need(isinstance(value,dict) and set(value)==ADOPTION_FIELDS,'exact new adoption fields required')
    exact(value,{'schema':'hepta.runtime-properties-r10.policy-adoption.v1','release_id':'v150-r10-r1','boot_id':BOOT,
        'parent_policy':PARENT,'pre_policy_boundary':BOUNDARY})
    pool=value['verification_originals'];need(isinstance(pool,list) and 1<=len(pool)<=1024,
        'bounded explicit verification-original inventory required')
    originals={};paths={};used=set();total=0
    for row in pool:
        key=descriptor_key(row);need(row['path'] not in paths,'duplicate verification-original path')
        paths[row['path']]=row;originals[key]=row;total+=row['bytes']
    need(total<=32*1024*1024,'adoption verification-original raw byte bound')
    def get(row):
        key=descriptor_key(row);need(key in originals,'verification depends on an unlisted original')
        raw=bytes_match(read_pinned(row),row);used.add(key);return raw
    raw={k:get(value[k]) for k in ('root_scope_decision','parent_adoption_history','actual_export',
        'delta_rule','parent_rule','full_rule','retirement_descriptor','retirement_host_closure',
        'pre_policy_boundary_descriptor','offline_comparison','post_live_comparison','offline_proof_inputs',
        'post_live_proof_inputs','live_provenance','pre_live_expectation')}
    root_scope(raw['root_scope_decision']);bytes_match(raw['parent_adoption_history'],PARENT_ADOPTION)
    bytes_match(raw['retirement_descriptor'],RETIREMENT_DESCRIPTOR)
    bytes_match(raw['retirement_host_closure'],RETIREMENT_HOST_CLOSURE)
    bytes_match(raw['pre_policy_boundary_descriptor'],BOUNDARY_DESCRIPTOR)
    need(strict(raw['pre_policy_boundary_descriptor'])==BOUNDARY,'adoption prior full-nine boundary differs')
    need(raw['delta_rule']==RULE and raw['full_rule']==raw['parent_rule']+RULE,
        'adoption full policy rule source differs')
    bytes_match(raw['parent_rule'],PARENT_RULE);bytes_match(raw['full_rule'],FULL_RULE)
    live_inputs=strict(raw['live_provenance']);live=verify_live_capture(live_inputs,read_pinned=get)
    need(live_inputs['pre_live_expectation']==value['pre_live_expectation']
        and live['candidate']==value['actual_export']
        and descriptor(raw['actual_export'])==live['actual_after_policy'],
        'adoption actual-export/pre-expectation source differs from live originals')
    need(value['offline_candidate']==live['binding']['offline_candidate'],'offline candidate pin was rewritten')
    offline=verify_comparison_proof(raw['offline_proof_inputs'],expected_kind='offline_candidate',
        read_pinned=get,decision_raw=raw['root_scope_decision'])
    post=verify_comparison_proof(raw['post_live_proof_inputs'],expected_kind='post_live_export',
        read_pinned=get,decision_raw=raw['root_scope_decision'],live_summary=live,live_inputs_raw=raw['live_provenance'])
    need(offline['report_descriptor']==value['offline_comparison']
        and post['report_descriptor']==value['post_live_comparison'], 'adoption proof report identity differs')
    need(descriptor(raw['offline_comparison'])==live['binding']['complete_offline_comparison']
        and {k:post['report']['candidate'][k] for k in ('bytes','sha256')}==live['actual_after_policy'],
        'independent comparisons do not identify actual approved before/after bytes')
    decision=adoption_decision(value,live)
    if require_root_decision:need(value['root_decision']==decision,'explicit Root actual-export adoption is missing')
    else:need(value['root_decision'] is None,'preview inputs cannot contain a prewritten adoption decision')
    need(set(originals)==used,'verification-original inventory contains unconsumed or unrelated originals')
    return {'runtime_policy':live['actual_after_policy'],'full_rule':value['full_rule'],
        'applied_verifier_source':live['applied_verifier_source'],
        'independent_verifier_source':live['independent_verifier_source'],
        'retirement_sha256':RETIREMENT,'prior_boundary_sha256':BOUNDARY['sha256'],
        'root_scope_decision_sha256':DECISION['sha256'],'parent_adoption_sha256':PARENT_ADOPTION['sha256'],
        'actual_live_binding_sha256':live['binding_sha256'],'root_decision':decision,
        'parent_policy':PARENT,'current_policy_adoption':{'schema':value['schema'],'boot_id':BOOT},
        'offline_proof':{k:offline[k] for k in ('proof_index_sha256','small_originals_read','small_original_bytes','all_orbit_images_read_by_consumer')},
        'post_live_proof':{k:post[k] for k in ('proof_index_sha256','small_originals_read','small_original_bytes','all_orbit_images_read_by_consumer')},
        'verification_original_count':len(used),'verification_original_bytes':total,
        'service_start_admitted':False,'component_qualified':False,'phone_calls':0,'policy_writes':0}


def verify_adoption(adoption_raw,*,read_pinned):
    """Read only raw reviewed originals; an explicit Root decision is mandatory."""
    value=strict(adoption_raw);summary=validate_adoption_value(value,read_pinned=read_pinned)
    summary['current_adoption_sha256']=sha(adoption_raw)
    summary['current_policy_adoption']={**summary['current_policy_adoption'],**descriptor(adoption_raw)}
    return summary


def verify_live_capture(live_inputs,*,read_pinned):
    """Independent post-comparison input gate; it never requires its own post report."""
    need(isinstance(live_inputs,dict) and set(live_inputs)=={'schema','prepared','host_capture',
        'original_operation','actor_wrapper','archive','capture_manifest','pre_live_expectation','originals',
        'root_plan','root_intent','root_execution','independent_verifier_source'},
        'explicit complete live provenance fields differ')
    need(live_inputs['schema']=='hepta.runtime-properties-r10.live-provenance-inputs.v2','live provenance schema differs')
    def get(row):
        file_descriptor(row);raw=read_pinned(row);return bytes_match(raw,row)
    independent=live_inputs['independent_verifier_source']
    file_descriptor(independent,maximum=131072);independent_raw=get(independent)
    need(independent['path']==INDEPENDENT_VERIFIER_SOURCE_PATH
        and 0<len(independent_raw)<=131072 and sha(independent_raw)==reviewed_source_sha256(),
        'actual independent host verifier raw identity differs')
    values={key:get(live_inputs[key]) for key in ('prepared','host_capture','original_operation',
        'actor_wrapper','archive','capture_manifest','pre_live_expectation','root_plan','root_intent','root_execution')}
    prepared=strict(values['prepared']);host=strict(values['host_capture']);op=strict(values['original_operation'])
    wrapper=strict(values['actor_wrapper'])
    exact(prepared,{'schema':'hepta.runtime-properties-r10.live-host-preparation.v1',
        'state':'ACTUAL_INPUTS_BOUND_HOST_PREPARED_NOT_EXECUTED','phone_calls':0,'policy_apply_attempts':0,
        'automatic_retry':False,'automatic_rollback':False,'policy_adoption_authorized':False})
    binding_sha=prepared['binding']['sha256']
    need(set(op)=={'actor_rc','wrapper_sha256','wrapper'} and type(op['actor_rc']) is int and op['actor_rc']==0
        and op['wrapper_sha256']==sha(values['actor_wrapper']) and op['wrapper']==wrapper,
        'independent original actor wrapper differs from host operation')
    ph=wrapper.get('phone');need(isinstance(ph,dict) and type(ph.get('rc')) is int and ph['rc']==0
        and isinstance(ph.get('stdout'),str) and ph.get('stderr')=='','actual phone command did not complete cleanly')
    output=strict(ph['stdout'].encode('utf-8'));need(set(output)=={'report','export'},'single complete actual stdout JSON required')
    export=output['export']
    exact(export,{'schema':'hepta.runtime-properties-r10.live-original-export.v1','state':'ORIGINAL_EXPORT_COMPLETE',
        'binding_sha256':binding_sha,'automatic_retry':False,'policy_adoption_authorized':False,'business_qualified':False})
    need(export['archive']['path']==BASE+'/'+OUT_NAME+'/ORIGINALS.tar.gz'
        and descriptor(values['archive'])=={k:export['archive'][k] for k in ('bytes','sha256')}
        and descriptor(values['capture_manifest'])==export['capture'],'actual export archive/index bytes differ')
    files,cap=decode_original_archive(values['archive'],export['capture'],binding_sha)
    need(files['CAPTURE.json']==values['capture_manifest'],'original capture manifest differs')
    originals=live_inputs['originals'];need(isinstance(originals,dict) and set(originals)==MANDATORY_LIVE_FILES,
        'exact mandatory live original descriptor map required')
    for name,row in originals.items():need(get(row)==files[name],'host original copy is not the actual archive member')
    binding,report=verify_apply_originals(files,binding_sha)
    need(report==output['report'] and descriptor(files['BINDING.original.json'])==prepared['binding'],
        'original report or binding differs from actual executed transaction')
    exact(host,{'schema':'hepta.runtime-properties-r10.host-original-capture.v1',
        'state':'ORIGINALS_CAPTURED_PENDING_INDEPENDENT_LIVE_COMPARISON','binding_sha256':binding_sha,
        'original_operation_sha256':sha(values['original_operation']),'wrapper_sha256':sha(values['actor_wrapper']),
        'actor_rc':0,'phone_rc':0,'archive':descriptor(values['archive']),'capture':export['capture'],
        'clean_apply_observed':True,'actual_live_policy':descriptor(files['live-policy-after.bin']),
        'policy_adoption_authorized':False,'independent_live_complete_comparison_required':True,
        'service_start_admitted':False,'business_qualified':False,'phone_calls':0,'policy_apply_attempts':0,
        'automatic_retry':False,'automatic_rollback':False})
    need(host['files']==len(files) and host['original_live_policy_path']==originals['live-policy-after.bin']['path']
        and host['original_parent_policy_path']==originals['live-policy-before.bin']['path'],
        'host capture actual export paths differ')
    expectation=verify_pre_live_expectation(values['pre_live_expectation'],read_pinned=read_pinned)
    need({k:expectation['binding'][k] for k in ('bytes','sha256')}==descriptor(files['BINDING.original.json'])
        and expectation['offline_candidate']==binding['offline_candidate'],'pre-load expectation bound another transaction')
    root_transaction=verify_root_transaction(live_inputs,values,prepared,expectation,files,get)
    return {'parent':originals['live-policy-before.bin'],'candidate':originals['live-policy-after.bin'],
        'applied_verifier_source':originals['policy_runtime_properties_verifier.original.py'],
        'independent_verifier_source':independent,
        'root_scope_decision':originals['ROOT-SCOPE-DECISION.original.json'],
        'parent_adoption_history':originals['PARENT-ADOPTION-HISTORY.original.json'],
        'binding_sha256':binding_sha,'host_capture_sha256':sha(values['host_capture']),
        'provenance_inputs_sha256':sha(encoded(live_inputs)),'live_report':report,
        'original_files':files,'capture':cap,'binding':binding,'pre_live_expectation':expectation,
        'root_transaction':root_transaction,'actual_before_policy':PARENT,'actual_after_policy':descriptor(files['live-policy-after.bin']),
        'comparison_route':'verified_semantic_export','expected_live_export':None,
        'policy_adoption_authorized':False,'phone_calls':0}


def verify_stage_program(source_raw,*,phase,stage):
    """Inspect the actual raw stage program; no stage code is executed here."""
    text=source_raw.decode('utf-8');tree=ast.parse(text)
    is_final=phase=='runtimeprops2-stage-final'
    names=['BOOT','PARENT','STAGE'] if is_final else ['BOOT','PARENT','STAGE','INDEX','PART_BASE64']
    values={}
    for name,node in zip(names,tree.body):
        need(isinstance(node,ast.Assign) and len(node.targets)==1
            and isinstance(node.targets[0],ast.Name) and node.targets[0].id==name,
            'stage code changed its literal declaration boundary')
        values[name]=ast.literal_eval(node.value)
    expected=ast.parse(STAGE_BASE+(STAGE_FINAL if is_final else STAGE_PART))
    observed=ast.Module(body=tree.body[len(names):],type_ignores=[])
    need(ast.dump(observed,include_attributes=False)==ast.dump(expected,include_attributes=False),
        'actual stage code is not the reviewed limited file staging program')
    need(values['BOOT']==BOOT and values['PARENT']==PARENT['sha256'] and values['STAGE']==stage,
        'stage code constants do not bind the actual single stage identity')
    if is_final:return None
    index=int(phase.rsplit('-',1)[1]);need(type(values['INDEX']) is int and values['INDEX']==index,'stage prefix order differs')
    raw=base64.b64decode(values['PART_BASE64'],validate=True)
    need(base64.b64encode(raw).decode('ascii')==values['PART_BASE64'] and len(raw)<=24576,
        'canonical bounded stage part required')
    bytes_match(raw,stage['parts'][index]);return raw



PRIOR_FAILED_TRANSACTION = {'bytes': 3715, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/policy-runtime-properties-r10-live-01/FAILED-PREFLIGHT-RECONCILIATION-01/RESULT.json', 'sha256': 'c52efc070658e5f05f47e3e5f57acf4272f5556a8ab32c6bc615b8f57c4f0cb4'}
PRIOR_FAILURE_EVIDENCE = {'root_failure': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/policy-runtime-properties-r10-live-01/ROOT-FAILURE.json', 'bytes': 9936, 'sha256': '257a50a34f3e2d2667efe50b0bea06f301aa717c6c70ccb9ab5d3416d40fa03d'}, 'root_plan': {'bytes': 3537, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/policy-runtime-properties-r10-live-01/ROOT-POLICY-PLAN.original.json', 'sha256': '115f82470e62fe8ef0d3aec14f74f199b4784ce4f60c314a3885387263ce0d83'}, 'root_intent': {'bytes': 2045, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/policy-runtime-properties-r10-live-01/ROOT-LIVE-INTENT.json', 'sha256': '28bc325220b3a0e469debbb0ba6906ca127ad6804c5d97d1db6b68b20d46b683'}, 'binding': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/policy-runtime-properties-r10-live-preparation-01/tree/BINDING.json', 'bytes': 25562, 'sha256': '79d190a46ebfbb63fdddfc1e6944ae0481f22f0b74fcc2b446896653f5bf8f3e'}, 'driver_source': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/root-runtime-properties-live-driver-r1-candidate01/source/run_runtime_properties_policy_once.py', 'bytes': 18590, 'sha256': 'e57d5df7d77b2742e5b0bb610d89c82b1cd3466d774d475f5d003ab4125d45ec'}, 'prepared': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/policy-runtime-properties-r10-live-preparation-01/PREPARED.json', 'bytes': 4240, 'sha256': '1bd33d4deeed0e8971bc167dc26365f58a275323461a9119ec07ea89d6e10d51'}, 'host_apply_result': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/policy-runtime-properties-r10-live-01/phone-runtimeprops-live-apply/RESULT.json', 'bytes': 790, 'sha256': 'a577f27567aafe8ae07690f92ba66b9393a2dac733c2225ec1bd32aa996412bf'}, 'operation': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/policy-runtime-properties-r10-live-01/phone-runtimeprops-live-apply/stdout.original', 'bytes': 4789, 'sha256': '0129bbe9a38f15c65d5e6454a6697fcf22c0a832aa1264c33298a62384355234'}, 'host_apply_stderr': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/policy-runtime-properties-r10-live-01/phone-runtimeprops-live-apply/stderr.original', 'bytes': 0, 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, 'actor_wrapper': {'bytes': 4733, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/policy-runtime-properties-r10-live-01/FAILED-PREFLIGHT-RECONCILIATION-01/FAILED-ACTOR-WRAPPER.original.json', 'sha256': '5e8345b5dbf6f24608d45c417d9852917f791cb7e7c9fe93c3ab90dd6fa435c3'}, 'phone_observation': {'bytes': 9348, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/policy-runtime-properties-r10-live-01/FAILED-PREFLIGHT-RECONCILIATION-01/PHONE-OBSERVATION.original.json', 'sha256': '76643fa9e8dec89a16b7a851b62511b16b869af30da5f1cbb8f3706f29837e0b'}, 'guard_source': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/policy-runtime-properties-r10-live-operator-r1-candidate03/source/guard_live_runtime_properties.py', 'bytes': 44223, 'sha256': '8bdfa0a0d67e32bedcc53f4217ce15945d5f7d6c43e9624b7fd983b3f38c61b2'}, 'apply_script': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/policy-runtime-properties-r10-live-preparation-01/tree/apply_runtime_properties_once.sh', 'bytes': 2482, 'sha256': 'c5ed9d83a316dabe0b161be1bda04f35bc70798c130a27730320e26273ba2e64'}, 'failed_terminal': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/root-r9-r2-acceptance-20261104-r1/ROOT-CHECKPOINT38-ORIGINAL-RECORDS-20261105-01/original-live01-failed.json', 'bytes': 726, 'sha256': '003b5c998ec6e79462e9deb0fd84904455972485f14efe24322f9a889c7f99a5'}, 'reconciliation_terminal': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/root-r9-r2-acceptance-20261104-r1/ROOT-CHECKPOINT38-ORIGINAL-RECORDS-20261105-01/failed-preflight-readonly-reconciliation.json', 'bytes': 731, 'sha256': 'b8d6ce631e7a521cc5f8fab8142c89fa5f9903c61432b6501bb768b29634127f'}}

def verify_prior_failed_transaction(raw,read_pinned):
    """Bind only the actual terminal live01 preflight failure; never replay it."""
    bytes_match(raw,PRIOR_FAILED_TRANSACTION)
    value=strict(raw)
    need(value['schema']=='hepta.root.runtime-properties.failed-preflight-reconciliation.v1'
         and value['state']=='KNOWN_PREFLIGHT_TIMEOUT_ZERO_POLICY_INVOCATIONS_OUTPUT_NAMESPACE_ABSENT',
         'only the reconciled runtime-properties live01 predecessor is accepted')
    need(value['actual_magiskpolicy_invocations']==0 and value['policy_apply_command_dispatches']==1
         and value['diagnostic_phone_operations']==1 and value['diagnostic_policy_writes']==0
         and value['new_adoption'] is False and value['new_native_case_nonce'] is False
         and value['replayed_apply'] is False and value['staged_namespace_retained'] is True
         and value['staged_source_files_retained']==24 and value['old_output_namespace_absent'] is True
         and value['original_shell_set_e_exits_before_magiskpolicy'] is True
         and value['original_guard_timeout_precedes_D_mkdir_and_APPLY_INTENT'] is True,
         'predecessor effect or original preservation classification differs')
    def checked(row):
        file_descriptor(row,maximum=2*1024*1024)
        original=read_pinned(row)
        need(type(original) is bytes,'prior failure callback must return original bytes')
        return bytes_match(original,row)
    originals={name:checked(row) for name,row in PRIOR_FAILURE_EVIDENCE.items()}
    def obj(name):return strict(originals[name])
    for name,job,rc in (('failed_terminal','1a1aa66baf5-fc05-427f',1),
                       ('reconciliation_terminal','1a1aa6d945d-fc05-42ee',0)):
        terminal=obj(name)
        need(terminal['job_id']==job and type(terminal['exit_code']) is int and terminal['exit_code']==rc
             and terminal['state']==('failed' if rc else 'succeeded')
             and terminal['output_complete'] is True and terminal['output_durable'] is True
             and terminal['terminal_publication_confirmed'] is True
             and terminal['automatic_retry'] is False and terminal['timed_out'] is False
             and terminal['cancelled'] is False and all(v is False for v in terminal['log_truncated'].values()),
             'prior original controller job is not durably terminal')
    failure=obj('root_failure');plan=obj('root_plan');intent=obj('root_intent')
    phases=['runtimeprops-stage-'+str(i).zfill(2) for i in range(8)]+['runtimeprops-stage-final','runtimeprops-live-apply']
    need(failure['schema']=='hepta.root.runtime-properties-live-failure.v1'
         and failure['state']=='ORIGINAL_TRANSACTION_STOPPED_NO_REPLAY'
         and failure['error_type']=='ValueError'
         and failure['detail']=='original apply produced no structured export; reconcile original stderr without replay'
         and failure['policy_apply_calls']==1 and failure['phone_phase_names']==phases
         and failure['root_plan']==PRIOR_FAILURE_EVIDENCE['root_plan']
         and failure['root_intent']==PRIOR_FAILURE_EVIDENCE['root_intent']
         and failure['automatic_retry'] is False and failure['automatic_rollback'] is False
         and failure['automatic_policy_adoption'] is False
         and failure['native_case_sends']==failure['new_native_case_nonces']==0,
         'the actual stopped Root transaction differs')
    need(plan['schema']=='hepta.root.runtime-properties-live-plan.v1'
         and plan['boot_id']=='f8019f83-20a7-4f18-bea1-51c980621e4d'
         and plan['out'].endswith('/policy-runtime-properties-r10-live-01')
         and plan['binding']==PRIOR_FAILURE_EVIDENCE['binding']
         and plan['driver_source']==PRIOR_FAILURE_EVIDENCE['driver_source']
         and plan['prepared']==PRIOR_FAILURE_EVIDENCE['prepared']
         and intent['schema']=='hepta.root.runtime-properties-live-intent.v1'
         and intent['plan_sha256']==PRIOR_FAILURE_EVIDENCE['root_plan']['sha256']
         and intent['binding']==plan['binding'] and intent['maximum_apply_attempts']==1
         and intent['automatic_retry'] is False and intent['automatic_rollback'] is False
         and intent['automatic_policy_adoption'] is False
         and intent['native_case_sends']==intent['new_native_case_nonces']==0,
         'old plan or durable intent is not the failed live01 transaction')
    operation=obj('operation');wrapper=obj('actor_wrapper');host=obj('host_apply_result')
    need(host['state']=='ORIGINAL_HOST_CHILD_JOINED' and host['phase']=='phone-runtimeprops-live-apply'
         and host['returncode']==0 and host['automatic_retry'] is False
         and host['stdout']==PRIOR_FAILURE_EVIDENCE['operation']
         and host['stderr']==PRIOR_FAILURE_EVIDENCE['host_apply_stderr']
         and originals['host_apply_stderr']==b'',
         'failed original apply host join differs')
    need(set(operation)=={'actor_rc','wrapper_sha256','wrapper'} and operation['actor_rc']==0
         and operation['wrapper']==wrapper and operation['wrapper_sha256']==sha(originals['actor_wrapper'])
         and value['original_operation']==PRIOR_FAILURE_EVIDENCE['operation']
         and value['independent_actor_wrapper']==PRIOR_FAILURE_EVIDENCE['actor_wrapper'],
         'independent failed actor wrapper is not the original operation')
    phone=wrapper['phone']
    need(wrapper['schema']=='hepta.phone-local.operator-result.v150.1'
         and wrapper['status']=='command_exited'
         and wrapper['label']=='ng-c705647dd4ebb5d421be1041a9c41ca6-runtimeprops-live-apply'
         and wrapper['model_decision'] is False and wrapper['native_task_result'] is False
         and phone['rc']==1 and phone['stdout']==''
         and 'TimeoutError: bounded read-only guard deadline' in phone['stderr']
         and 'state,inventory,boundary_copies,boundary_origins=preserved(binding)' in phone['stderr']
         and 'verify_closed_history' in phone['stderr'],
         'failed phone was not stopped in the first read-only history verification')
    steps=failure['steps']
    need(type(steps) is list and len(steps)==10 and [r['phase'] for r in steps]==['phone-'+p for p in phases],
         'failed Root phase history differs')
    for index,row in enumerate(steps):
        need(row['state']=='ORIGINAL_HOST_CHILD_JOINED' and row['returncode']==0
             and row['automatic_retry'] is False and checked(row['stderr'])==b'',
             'prior stage/dispatch is not a joined original')
        stage_raw=checked(row['stdout']);stage=strict(stage_raw)
        if index==9:
            need(stage_raw==originals['operation'],'failed final phase original changed')
        else:
            need(stage['actor_rc']==0 and stage['wrapper']['phone']['rc']==0
                 and stage['wrapper']['phone']['stderr']=='',
                 'old staging did not finish successfully before the failed preflight')
    observation=obj('phone_observation')
    old={'bytes':2667608,'sha256':'50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7'}
    need(value['phone_observation']==PRIOR_FAILURE_EVIDENCE['phone_observation']
         and value['current_policy']==old
         and observation['schema']=='hepta.root.runtime-properties.failed-preflight-readonly-observation.v1'
         and observation['boot_id']==plan['boot_id'] and observation['enforcing'] is True
         and observation['policy_before']==observation['policy_after']==old
         and observation['all_original_bytes_and_full9_bookended'] is True
         and observation['old_parent_still_observed'] is True
         and observation['policy_output_namespace_absent'] is True
         and observation['business_calls']==observation['model_calls']==observation['signals_sent']==observation['diagnostic_policy_writes']==0,
         'independent reconciliation does not establish the unchanged parent')
    base='/var/lib/trillionnium/owner-open/phone-local-v150/'
    need(observation['gnu_output']=={'exists':False,'path':base+'policy-runtime-properties-r10-live-01'}
         and observation['native_output']=={'exists':False,'path':'/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/policy-runtime-properties-r10-live-01'}
         and observation['stage_directory']==base+'policy-runtime-properties-r10-live-code-r1',
         'failed output/staging namespace differs')
    staged=observation['staged_originals']
    need(type(staged) is list and len(staged)==24 and len({r['path'] for r in staged})==24,
         'complete old stage originals not retained')
    for row in staged:
        need(set(row)=={'path','bytes','sha256','metadata'}
             and row['path'].startswith(observation['stage_directory']+'/')
             and type(row['metadata']) is list and len(row['metadata'])==9
             and all(type(n) is int and n>=0 for n in row['metadata'])
             and row['metadata'][2]==33152 and row['metadata'][3:6]==[0,0,1]
             and row['metadata'][6]==row['bytes'],'old stage full9 record differs')
    staged_by_name={r['path'][len(observation['stage_directory'])+1:]:r for r in staged}
    for name,key in (('guard_live_runtime_properties.py','guard_source'),
                     ('apply_runtime_properties_once.sh','apply_script'),('BINDING.json','binding')):
        need({k:staged_by_name[name][k] for k in ('bytes','sha256')}==
             {k:PRIOR_FAILURE_EVIDENCE[key][k] for k in ('bytes','sha256')},
             'failed execution source was not the observed immutable stage source')
    shell=originals['apply_script'].decode('utf-8')
    need(shell.startswith('#!/system/bin/sh\nset -eu\n')
         and shell.index('--preflight-once\n')<shell.index('\nset +e\n')<
             shell.index(' /data/adb/magisk/magiskpolicy --live --apply ')
         and shell.count(' /data/adb/magisk/magiskpolicy --live --apply ')==1,
         'original shell does not stop before the sole policy command')
    guard=originals['guard_source'].decode('utf-8')
    preflight=guard.split('def preflight(binding_sha):\n',1)[1].split('\ndef export_originals(',1)[0]
    need(preflight.index('preserved(binding)')<preflight.index('D.mkdir(')<preflight.index("record('APPLY-INTENT.json'"),
         'original first history check was not before output and apply intent')
    reconcile_steps=value['steps']
    need(len(reconcile_steps)==2 and [r['phase'] for r in reconcile_steps]==[
        'original-failed-apply-wrapper','phone-runtimeprops-failure-state01'],
        'original independent reconciliation phases differ')
    for row in reconcile_steps:
        need(row['state']=='ORIGINAL_HOST_CHILD_JOINED' and row['returncode']==0
             and row['automatic_retry'] is False and checked(row['stderr'])==b'',
             'reconciliation original is not joined')
        result_raw=checked(row['stdout'])
        if row['phase']=='phone-runtimeprops-failure-state01':
            result=strict(result_raw);observed_phone=result['wrapper']['phone']
            need(result['actor_rc']==0 and observed_phone['rc']==0 and observed_phone['stderr']==''
                 and observed_phone['stdout'].encode('utf-8')==originals['phone_observation'],
                 'readonly observation does not match its original operation')
    return {'schema':'hepta.runtime-properties-r10.failed-predecessor-verification.v1',
            'state':'ACTUAL_LIVE01_FAILED_BEFORE_POLICY_INVOCATION',
            'original_failed_job':'1a1aa66baf5-fc05-427f','actual_magiskpolicy_invocations':0,
            'parent_policy':old,'old_stage_preserved':True,'old_output_absent':True,
            'automatic_retry':False,'replayed_apply':False}

def verify_root_transaction(live,values,prepared,expectation,files,get):
    plan=strict(values['root_plan']);intent=strict(values['root_intent']);execution=strict(values['root_execution'])
    fields={'schema','boot_id','prepared','stage_requests','apply_request','binding','pre_live_expectation',
        'capture_source','verifier_source','transport_root_plan','source_package','driver_source','out','prior_failed_transaction'}
    need(set(plan)==fields,'actual Root live plan fields differ')
    exact(plan,{'schema':'hepta.root.runtime-properties-live-plan.v2','boot_id':BOOT})
    need(plan['prior_failed_transaction']==PRIOR_FAILED_TRANSACTION,
        'only the reconciled zero-effect live01 predecessor is accepted')
    prior_failure=verify_prior_failed_transaction(get(plan['prior_failed_transaction']),read_pinned=get)
    need(plan['prepared']==live['prepared'] and plan['pre_live_expectation']==live['pre_live_expectation']
        and plan['binding']==expectation['binding'] and plan['stage_requests']==prepared['stage_requests']
        and plan['apply_request']==prepared['apply_request'],'Root plan is not the one actual prepared request set')
    need(isinstance(ROOT_DRIVER,dict) and isinstance(ROOT_SOURCE_PACKAGE,dict),
        'the reviewed actual Root transaction source package is not frozen')
    bytes_match(get(plan['driver_source']),ROOT_DRIVER);bytes_match(get(plan['source_package']),ROOT_SOURCE_PACKAGE)
    source_package=strict(get(plan['source_package']));base=PurePosixPath(plan['source_package']['path']).parent
    exact(source_package,{'schema':'hepta.root.runtime-properties-live-source-package.v1'})
    expected={'source/run_runtime_properties_policy_once.py':ROOT_DRIVER,
        'reference/run_component_root_once.r4.original.py':ROOT_TRANSPORT_SOURCE}
    need(len(source_package['files'])==2 and {r['path'] for r in source_package['files']}==set(expected),
        'Root driver source package fields differ')
    for row in source_package['files']:
        need({k:row[k] for k in ('bytes','sha256')}==expected[row['path']], 'Root original source revision differs')
        retained={'path':str(base/row['path']),**expected[row['path']]};get(retained)
    need({k:plan['verifier_source'][k] for k in ('bytes','sha256')}==descriptor(files['policy_runtime_properties_verifier.original.py']),
        'Root selected another actual verifier source')
    # This source is retained as a host original; the decoded archive is also
    # independently reconstructed by this verifier, rather than trusting it.
    get(plan['capture_source']);get(plan['transport_root_plan'])
    exact(intent,{'schema':'hepta.root.runtime-properties-live-intent.v2',
        'state':'ONE_EXPLICIT_POLICY_APPLY_DECLARED_BEFORE_PHONE_PHASES',
        'plan_sha256':sha(values['root_plan']),'pre_live_expectation':plan['pre_live_expectation'],
        'binding':plan['binding'],'prior_failed_transaction':plan['prior_failed_transaction'],
        'source_package':plan['source_package'],'driver_source':plan['driver_source'],
        'verifier_source':plan['verifier_source'],'maximum_apply_attempts':1,
        'automatic_retry':False,'automatic_rollback':False,'automatic_policy_adoption':False,
        'new_native_case_nonces':0,'native_case_sends':0})
    same={'root_plan':live['root_plan'],'root_intent':live['root_intent'],
        'prior_failed_transaction':plan['prior_failed_transaction'],
        **{k:plan[k] for k in ('prepared','binding','pre_live_expectation','source_package','driver_source','verifier_source','capture_source')},
        **{k:live[k] for k in ('original_operation','actor_wrapper','host_capture')}}
    exact(execution,{'schema':'hepta.root.runtime-properties-live-execution.v2',
        'state':'ORIGINAL_POLICY_APPLY_CAPTURED_PENDING_INDEPENDENT_COMPARISON',
        **same,'policy_apply_calls':1,'policy_apply_phase':'runtimeprops2-live-apply',
        'automatic_retry':False,'automatic_rollback':False,'automatic_policy_adoption':False,
        'new_native_case_nonces':0,'native_case_sends':0,'known_apply_error':None})
    stages=strict(get(plan['stage_requests']));provenance=strict(get(prepared['stage_request_provenance']))
    need(isinstance(stages,list) and 2<=len(stages)<=9 and isinstance(provenance,list)
        and len(stages)==len(provenance)==execution['stage_phase_count'], 'bounded exact stage original count')
    wanted=['runtimeprops2-stage-%02d'%i for i in range(len(stages)-1)]+['runtimeprops2-stage-final']
    need([r['phase'] for r in stages]==wanted and all(set(r)=={'phase','request'} for r in stages),
        'exact original stage request order differs')
    stage_raw=files['STAGE-INTENT.original.json'];stage=strict(stage_raw);complete=strict(files['STAGE-COMPLETE.original.json'])
    need(sha(stage_raw)==prepared['stage_identity_sha256']==complete['stage_identity_sha256'],
        'actual stage completion is not bound to preparation')
    actual_parts=[]
    for row,source_row in zip(stages,provenance):
        need(set(source_row)=={'phase','request','source','adb_service_bytes'}
            and row=={k:source_row[k] for k in ('phase','request')},'stage provenance mapping differs')
        request=strict(get(row['request']));source=get(source_row['source'])
        exact(request,{'kind':'shell','root':True,'timeout_seconds':40})
        need(set(request)=={'kind','root','timeout_seconds','command'}
            and request['command']==STAGE_ENV_PREFIX+'-c '+shlex.quote(source.decode('utf-8')),
            'actual stage request is not the exact reviewed bounded program')
        wire=('shell,v2,raw:/debug_ramdisk/su -c '+shlex.quote(request['command'])).encode('utf-8')
        need(len(wire)<65536 and len(wire)==source_row['adb_service_bytes'],'actual fixed transport wire bound differs')
        part=verify_stage_program(source,phase=row['phase'],stage=stage)
        if part is not None:actual_parts.append(part)
    compressed=b''.join(actual_parts);bytes_match(compressed,stage['compressed'])
    need(len(compressed)<=196608 and 0<stage['plain']['bytes']<=2097152,'bounded full stage envelope')
    z=zlib.decompressobj(31);plain=z.decompress(compressed,stage['plain']['bytes']+1)
    need(z.eof and not z.unconsumed_tail and not z.unused_data,'complete original stage gzip')
    bytes_match(plain,stage['plain']);envelope=strict(plain)
    aliases={'BINDING.json':'BINDING.original.json','guard_live_runtime_properties.py':'guard_live_runtime_properties.original.py',
        'policy_runtime_properties_verifier.py':'policy_runtime_properties_verifier.original.py','apply_runtime_properties_once.sh':'apply_runtime_properties_once.original.sh'}
    expected_names={'BINDING.json','guard_live_runtime_properties.py','policy_runtime_properties_verifier.py','apply_runtime_properties_once.sh',
        'ROOT-SCOPE-DECISION.original.json','PARENT-ADOPTION-HISTORY.original.json','ACTUAL-RETIREMENT-INPUTS.original.json',
        'RETIREMENT-HOST-CLOSURE.original.json','LATEST-BOUNDARY-DESCRIPTOR.original.json',
        'CLOSED-COMPONENT-PACKAGE.original.json','OFFLINE-COMPLETE-COMPARISON.original.json',
        'runtime-properties.delta.rule','parent-candidate.rule','full-candidate.rule'}
    need(set(envelope)==set(stage['files'])==expected_names and complete['files']==stage['files'],
        'actual stage envelope file set differs')
    for name,value in envelope.items():
        raw=base64.b64decode(value,validate=True);bytes_match(raw,stage['files'][name])
        need(raw==files[aliases.get(name,name)],'actual executed file differs from bound stage envelope')
    apply=strict(get(plan['apply_request']))
    need(apply=={'kind':'shell','root':True,'timeout_seconds':240,'command':'/data/adb/magisk/busybox sh '+NATIVE_BASE+'/'+CODE_NAME+
        '/apply_runtime_properties_once.sh --execute-reviewed-single-runtime-properties-apply '+plan['binding']['sha256']},
        'actual single policy request differs')
    phases=execution['phone_phase_names'];need(isinstance(phases,list) and len(phases)==len(set(phases))
        and type(execution['phone_calls']) is int and len(phases)==execution['phone_calls']
        and phases[:len(wanted)+1]==wanted+['runtimeprops2-live-apply'],'actual phone operation sequence differs')
    remaining=phases[len(wanted)+1:]
    need(remaining==['runtimeprops2-export-%02d'%i for i in range(len(remaining))] and len(remaining)<=16,
        'only bounded existing-archive read chunks may follow the one apply')
    steps=execution['steps'];need(isinstance(steps,list) and len(steps)==len(phases)+2,
        'all phone/independent wrapper/capture host original terminals required')
    needed=['phone-'+p for p in wanted+['runtimeprops2-live-apply']]+['runtimeprops2-wrapper-original']+[
        'phone-'+p for p in remaining]+['runtimeprops2-host-capture']
    need([s['phase'] for s in steps]==needed,'actual original host step sequence differs')
    for step in steps:
        exact(step,{'state':'ORIGINAL_HOST_CHILD_JOINED','returncode':0,'automatic_retry':False})
        need(type(step['pid']) is int and step['pid']>0,'actual joined host child identity required')
        out=get(step['stdout']);need(get(step['stderr'])==b'','actual host step stderr is not empty')
        value=strict(out)
        if step['phase'].startswith('phone-'):
            need(type(value.get('actor_rc')) is int and value['actor_rc']==0
                and value['wrapper']['phone']['rc']==0 and value['wrapper']['phone']['stderr']=='',
                'actual stage/apply/chunk original did not complete cleanly')
    return {'schema':'hepta.runtime-properties-r10.root-transaction-recheck.v1','root_plan_sha256':sha(values['root_plan']),
        'root_intent_sha256':sha(values['root_intent']),'root_execution_sha256':sha(values['root_execution']),
        'driver_source_sha256':ROOT_DRIVER['sha256'],
        'prior_failed_transaction':plan['prior_failed_transaction'],
        'prior_failed_transaction_verification':prior_failure,
        'pre_expectation_declared_before_phone_by_exact_source':True,
        'exact_stage_programs_and_payload_rebuilt':True,'policy_apply_calls':1,'automatic_retry':False,
        'native_case_sends':0,'new_native_case_nonces':0}

def validate_binding(raw,*,decision_raw,comparison_raw,retirement_raw,parent_adoption_raw,boundary_descriptor_raw,package_raw):
    v=strict(raw)
    fields={'schema','boot_id','root_scope_decision','parent_adoption_history','retirement_descriptor',
        'retirement_host_closure','pre_policy_boundary_descriptor','pre_policy_boundary','component_package',
        'component_sources','native_history','non_native_sidebranch','complete_offline_comparison',
        'approved_rule_atoms','parent_policy','offline_candidate','delta_rule','parent_rule','full_rule',
        'guard_source','verifier_source','shell_source','root_approval'}
    need(set(v)==fields,'explicit runtime-property live binding fields differ')
    exact(v,{'schema':'hepta.runtime-properties-r10.live-apply-binding.v1','boot_id':BOOT,'approved_rule_atoms':ATOMS,
        'parent_policy':PARENT,'retirement_descriptor':RETIREMENT_DESCRIPTOR,
        'retirement_host_closure':RETIREMENT_HOST_CLOSURE,'root_scope_decision':DECISION,
        'parent_adoption_history':PARENT_ADOPTION,'pre_policy_boundary_descriptor':BOUNDARY_DESCRIPTOR,
        'pre_policy_boundary':BOUNDARY,'component_package':PACKAGE,'native_history':CLOSED_HISTORY,
        'non_native_sidebranch':NON_NATIVE_BINDING,'delta_rule':descriptor(RULE),
        'parent_rule':PARENT_RULE,'full_rule':FULL_RULE,'root_approval':APPROVAL})
    root_scope(decision_raw);bytes_match(parent_adoption_raw,PARENT_ADOPTION)
    history=strict(parent_adoption_raw)
    need(history['schema']=='hepta.native5-r10.policy-adoption.v1'
        and {k:history['actual_export'][k] for k in ('bytes','sha256')}==PARENT
        and history['root_decision']['decision']=='ADOPT_INDEPENDENTLY_VERIFIED_ACTUAL_EXPORTED_POLICY'
        and history['root_decision']['actual_policy_sha256']==PARENT['sha256'],
        'immutable actual parent adoption does not identify this live policy')
    bytes_match(retirement_raw,RETIREMENT_DESCRIPTOR);bytes_match(package_raw,PACKAGE)
    bytes_match(boundary_descriptor_raw,BOUNDARY_DESCRIPTOR)
    need(strict(boundary_descriptor_raw)==BOUNDARY,'full-nine latest boundary descriptor differs')
    comparison=verified_offline(comparison_raw,decision_raw)
    need(v['complete_offline_comparison']==descriptor(comparison_raw)
        and v['offline_candidate']=={k:comparison['candidate'][k] for k in ('bytes','sha256')},
        'actual complete offline comparison is not bound')
    for key in ('guard_source','verifier_source','shell_source'):byte_pin(v[key],maximum=262144)
    need(v['verifier_source']==APPLIED_VERIFIER,
        'binding names another exact applied verifier revision')
    need(v['component_sources']==component_source_rows(package_raw),
        'all raw dependencies must identify the actual closed08 package')
    return v

# Literal reviewed stage programs; parsed only, never executed by this verifier.
STAGE_BASE = "\nfrom pathlib import Path\nimport base64,hashlib,json,os,stat,zlib\nB=Path('/var/lib/trillionnium/owner-open/phone-local-v150')\nC=B/'policy-runtime-properties-r10-live-code-r2';A=Path('/proc/1/root')\ndef need(ok,msg):\n if not ok:raise ValueError(msg)\ndef sha(raw):return hashlib.sha256(raw).hexdigest()\ndef enc(v):return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False)+'\\n').encode()\ndef sync(p):\n fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)\n try:os.fsync(fd)\n finally:os.close(fd)\ndef private(p):\n s=p.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700 and p.resolve(strict=True)==p,'private canonical stage directory')\ndef read(p,limit):\n fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)\n try:\n  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_uid==a.st_gid==0 and stat.S_IMODE(a.st_mode)==0o600 and 0<=a.st_size<=limit,'private bounded stage original')\n  with os.fdopen(fd,'rb',closefd=False) as f:r=f.read(limit+1)\n  z,n=os.fstat(fd),p.lstat();keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')\n  need(len(r)==a.st_size and all(getattr(a,k)==getattr(z,k)==getattr(n,k) for k in keys),'stage original raced')\n  return r\n finally:os.close(fd)\ndef put(p,b):\n fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)\n with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())\n sync(p.parent);need(read(p,len(b))==b,'stage readback differs')\nneed(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'Root credentials')\nneed(Path('/proc/self/attr/current').read_bytes().rstrip(b'\\0\\n')==b'u:r:magisk:s0','Root domain')\nneed(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==BOOT,'fixed boot')\nneed((A/'sys/fs/selinux/enforce').read_bytes() in (b'1',b'1\\n'),'Enforcing')\np=(A/'sys/fs/selinux/policy').read_bytes();need(len(p)==2667608 and sha(p)==PARENT,'actual parent50f')\nprivate(B);os.umask(0o077)\n"
STAGE_PART = "\nneed(type(INDEX) is int and 0<=INDEX<len(STAGE['parts'])<=8,'bounded exact chunk index')\nif INDEX==0:\n C.mkdir(mode=0o700);sync(B);private(C)\n n=A/'data/trillionnium/owner-open/state/phone-local-v150'/C.name\n need((n.stat().st_dev,n.stat().st_ino)==(C.stat().st_dev,C.stat().st_ino),'GNU/native mapping')\n (C/'.stage-parts').mkdir(mode=0o700);sync(C)\n put(C/'STAGE-INTENT.json',enc(STAGE))\nelse:\n private(C);need(read(C/'STAGE-INTENT.json',65536)==enc(STAGE),'same original stage identity')\nneed(sorted(p.name for p in C.iterdir())==['.stage-parts','STAGE-INTENT.json'],'stage namespace has unexpected contents')\nQ=C/'.stage-parts';private(Q)\nneed(sorted(p.name for p in Q.iterdir())==['part-%02d.bin'%i for i in range(INDEX)],'stage parts are not the exact unreplayed prefix')\ndata=base64.b64decode(PART_BASE64,validate=True);row=STAGE['parts'][INDEX]\nneed(len(data)==row['bytes']<=24576 and sha(data)==row['sha256'],'stage chunk bytes')\nput(Q/('part-%02d.bin'%INDEX),data)\nprint(json.dumps({'schema':'hepta.runtime-properties-r10.live-stage-part.v1','state':'EXACT_PART_STAGED_NO_POLICY_APPLY',\n 'binding_sha256':STAGE['binding_sha256'],'stage_identity_sha256':sha(enc(STAGE)),'index':INDEX,\n 'bytes':len(data),'sha256':sha(data),'policy_apply_attempts':0,'automatic_retry':False},sort_keys=True))\n"
STAGE_FINAL = "\nprivate(C);need(read(C/'STAGE-INTENT.json',65536)==enc(STAGE),'same original stage identity')\nneed(sorted(p.name for p in C.iterdir())==['.stage-parts','STAGE-INTENT.json'],'unconsumed code namespace required')\nQ=C/'.stage-parts';private(Q)\nneed(sorted(p.name for p in Q.iterdir())==['part-%02d.bin'%i for i in range(len(STAGE['parts']))],'complete exact stage chunk set')\npieces=[]\nfor i,row in enumerate(STAGE['parts']):\n b=read(Q/('part-%02d.bin'%i),24576);need(len(b)==row['bytes'] and sha(b)==row['sha256'],'original stage chunk differs');pieces.append(b)\ncompressed=b''.join(pieces)\nneed(len(compressed)==STAGE['compressed']['bytes']<=196608 and sha(compressed)==STAGE['compressed']['sha256'],'compressed stage bytes')\nz=zlib.decompressobj(31);raw=z.decompress(compressed,STAGE['plain']['bytes']+1)\nneed(len(raw)==STAGE['plain']['bytes']<=2097152 and z.eof and not z.unconsumed_tail and not z.unused_data and sha(raw)==STAGE['plain']['sha256'],'complete bounded stage envelope')\ndef pairs(items):\n v={}\n for k,x in items:need(k not in v,'duplicate stage key');v[k]=x\n return v\nvalue=json.loads(raw,object_pairs_hook=pairs)\nneed(set(value)==set(STAGE['files']),'exact reviewed staged file set')\nfiles={k:base64.b64decode(v,validate=True) for k,v in value.items()}\nfor name,b in files.items():\n need('/' not in name and name not in ('.','..') and '\\0' not in name,'stage file name')\n row=STAGE['files'][name];need(len(b)==row['bytes'] and sha(b)==row['sha256'],'staged file original bytes')\nneed(sha(files['BINDING.json'])==STAGE['binding_sha256'],'stage binding')\nfor name,b in sorted(files.items()):put(C/name,b)\ncomplete={'schema':'hepta.runtime-properties-r10.live-code-stage.v1','state':'CREATE_ONLY_CODE_STAGED_NO_POLICY_APPLY',\n 'files':STAGE['files'],'binding_sha256':STAGE['binding_sha256'],'stage_identity_sha256':sha(enc(STAGE)),\n 'policy_apply_attempts':0,'phone_service_changes':0,'automatic_retry':False}\nput(C/'STAGE-COMPLETE.json',enc(complete));print(json.dumps(complete,sort_keys=True))\n"
STAGE_ENV_PREFIX = '/data/adb/magisk/busybox env -i PATH=/usr/bin:/bin:/usr/libexec/trillionnium PYTHONHOME=/usr PYTHONDONTWRITEBYTECODE=1 LD_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu/android:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu LANG=C.UTF-8 LC_ALL=C.UTF-8 TMPDIR=/var/lib/trillionnium/owner-open/tmp NO_COLOR=1 TERM=dumb /data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -I -B '
