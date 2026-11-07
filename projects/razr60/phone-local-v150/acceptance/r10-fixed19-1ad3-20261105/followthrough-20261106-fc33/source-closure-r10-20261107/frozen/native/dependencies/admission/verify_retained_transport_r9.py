"""One fixed complete retained R9 first-push failure proof.

The archive contains exact retained originals plus separately pinned, plain
pure-reader source modules. The original reused-start gap and unknowns remain.
Only observe_current_absence performs device reads, when called explicitly by
the already bounded current runtime; it cannot submit a task or send a signal.
"""
import ast
import base64
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import tarfile
import time
import types
import zlib

MANIFEST_SCHEMA='hepta.r9.retained-transport-failure-manifest.v1'
RESULT_SCHEMA='hepta.r9.retained-transport-failure-verification.v1'
RESULT_STATE='EXACT_FAILED_R9_FIRST_PUSH_ORIGINALS_RECONCILED_UNKNOWN_RETAINED'
ABSENCE_SCHEMA='hepta.r9.retained-transport-current-absence.v1'
LABEL='root-r10-neg01-fc33-r9-bound01'
NONCE='299483481a678cbd589aeba54ed8b68f'
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
BASE='/var/lib/trillionnium/owner-open/phone-local-v150'
PHONE_ROOT=BASE+'/native-guard-nonnative-boundaries-r10-r1/'+NONCE
MAX_ORIGINAL=16*1024*1024
MAX_COMPRESSED=4*1024*1024
EXPECTED_PINS={'host_actor_stderr': {'bytes': 0, 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, 'host_actor_stdout': {'bytes': 347, 'sha256': '44ec3468942cd857929f7b761e4ed21d2ae3c30435dcaa354c157535f553f1cb'}, 'host_actual_read': {'bytes': 6235, 'sha256': 'f47800e2048a41d91195b31761db83ed9bfd33893f50c2bbc38eb94875a4f5ea'}, 'host_actual_request': {'bytes': 705, 'sha256': '1f039339bedc1e452d2b75456597e143179b23c57301f986d3420957a67768a9'}, 'host_actual_start': {'bytes': 2492, 'sha256': 'aec8b90b1e4b4817cc8206ad40a6c84f0fb6b605a5cee2f7773f5b976610e8a1'}, 'host_actual_status': {'bytes': 951, 'sha256': '18d41186b3313e23d91924b2468c9267bfa27c512d059613b0a0aeb3253dcb73'}, 'host_chain_intent': {'bytes': 367, 'sha256': 'f69d44b2a9c0efbb16b0f258b11196368d42e1ff8c319e615dce5ae7c78d6429'}, 'host_durable_child': {'bytes': 87, 'sha256': '17d6362c2aeb9b6e76ce94c8c7de0b12c5a75ff038bd18d6c8395543b1b5a536'}, 'host_durable_exit': {'bytes': 500, 'sha256': '9e2984e8170e4839e542c136341a5e6758a646ab7344cdc38084bed979624569'}, 'host_durable_exit_witness': {'bytes': 207, 'sha256': '193d110ab07e98375dd5839d32573139e34926c34efea33a7bbd00e5da19cfa8'}, 'host_durable_launch': {'bytes': 166, 'sha256': 'e62abb1bc29ba29ecfc1a1f1bebe57893746f15135c5642fcea52bb62e5cf531'}, 'host_durable_launch_lock': {'bytes': 0, 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, 'host_durable_owner_intent': {'bytes': 270, 'sha256': 'cece407a988511314ef16ccd859ee81a2bb86e2f0404ea0102d24abe72c07418'}, 'host_durable_owner_lock': {'bytes': 0, 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, 'host_durable_request': {'bytes': 1263, 'sha256': '0e62b8985dac343c8630a3f4b4e0dae6d0aa81ba5c1b3fd98dde15096370ab94'}, 'host_durable_runner': {'bytes': 40463, 'sha256': '65564ce756f3a341def2cf34b2c0d54ef3e75960923c6002c4c56db13564ebf1'}, 'host_durable_started': {'bytes': 270, 'sha256': 'cece407a988511314ef16ccd859ee81a2bb86e2f0404ea0102d24abe72c07418'}, 'host_durable_stderr': {'bytes': 1888, 'sha256': '086d5523918d73dfb38f63ccd387452badf98f9a2d6cf73e553cc97907338849'}, 'host_durable_stdout': {'bytes': 0, 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, 'host_host_stage_material_capture': {'bytes': 2529, 'sha256': '86d2a8a35e028fdc695f56ca5f0e22a4e950983b21f6ace40f32b60a7ae880eb'}, 'host_host_stage_material_child': {'bytes': 905, 'sha256': '89c696a7bf7327222b71495100b58be83e550f061cce983dca0ee9e92916dc66'}, 'host_host_stage_material_intent': {'bytes': 964, 'sha256': 'e4fa02c1df53b7dde09c659656c7737119c7f6c31bb2b2684533df01141eaaa4'}, 'host_host_stage_material_result': {'bytes': 810, 'sha256': '1ee3ceb2d9d9d43dffa72d6c5457d28ef46fe14ad1bffd37eeb17dd052b42fdf'}, 'host_host_stage_material_stderr': {'bytes': 0, 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, 'host_host_stage_material_stdout': {'bytes': 8903, 'sha256': '17eabdea7e2e7a8544e09d2e9ec5c6a19a5cc7b6e669da7629c0584b980e94aa'}, 'host_lease': {'bytes': 2506, 'sha256': 'c56261e8a905de9a3e12d81d16c2a9fb15e90103a4fc0324d6f93c74ec5a6c17'}, 'host_mac_export_result': {'bytes': 2424, 'sha256': '9a8ddd275a2afcf390b68e8dc09e78ab246f79f9490161018825697a2b9b13d5'}, 'host_mac_index': {'bytes': 124962, 'sha256': 'aa6198bf96f85f350bc18d91690796954b1521d55764d1e6e7193a416e5cfa8e'}, 'host_operation_intent': {'bytes': 678, 'sha256': 'c387c37747dc711446cb4fe2b3a1fd8f2d126518a027bfef2f464e3eeba26f90'}, 'host_operation_result': {'bytes': 367, 'sha256': '373101f57589c2e76f7c3f87d209a9923ac7e274646413196e9e125e0ff914d3'}, 'host_p4_export_result': {'bytes': 2156, 'sha256': '40f56914676d1361b7923a3521d187301921f6d4e39a1e55e281d100911bfd9c'}, 'host_p4_index': {'bytes': 71569, 'sha256': 'c5ed229c24fff30b2c143854c5ba81412263cc90f908c505de9f357b7e548fb2'}, 'host_p4_operation': {'bytes': 509, 'sha256': 'd209f8eada114cf626a8d68ede2f00829466b1e2e13aa37af92a089c2b6f7150'}, 'host_phone_push_material_capture': {'bytes': 2533, 'sha256': '1df9b306fd553e6d73dee5aea9341db3dd2fa53793947753a250669461a3bf9c'}, 'host_phone_push_material_child': {'bytes': 912, 'sha256': '2316a32715cc336896cf6694f938eb1e9dfa81ddc9e82935353a875d558a2baf'}, 'host_phone_push_material_intent': {'bytes': 965, 'sha256': '2ec1ba8249ab72163b6ecd5dd7fa47600748e7d5b33e6408090e54de21940a7d'}, 'host_phone_push_material_result': {'bytes': 809, 'sha256': 'bd0ffb8a6edb9c23d3487dba5eaa454630f13936cc1f1c50e72c57aff071cd11'}, 'host_phone_push_material_stderr': {'bytes': 0, 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, 'host_phone_push_material_stdin': {'bytes': 2565, 'sha256': '0cc2998ca2522c4b0fa6d496c104f6ad3952a2ba090d4ce0b16a496d92195219'}, 'host_phone_push_material_stdout': {'bytes': 461, 'sha256': 'd4b4ac918ec27232b701b457f2fcf8621171b384ef00c1b7c6f7895207b74c29'}, 'host_plan': {'bytes': 5185, 'sha256': '796226a2bb72e3e48465b21339e3918ba74ed70e18ceb8de4e087e5b76c1e590'}, 'host_prepare_material_capture': {'bytes': 2521, 'sha256': '07c677b59eb6b9dd75a4c1ec5e630fe21d1c5daa61165ffe5a766a3cf4c1befc'}, 'host_prepare_material_child': {'bytes': 906, 'sha256': '5c44277ca15967f6ebdc60e76c275d9beab5aa32d77f783f0c699b05d86cca35'}, 'host_prepare_material_intent': {'bytes': 4349, 'sha256': '102e73fb03811d54b82956f3fa3fd50ea59060ddcbf76ffdd49ae7f47a9654c7'}, 'host_prepare_material_result': {'bytes': 801, 'sha256': 'a6135df7b35b0d141c2f7d379705aab9202989a46df1b5e51695c50f50064324'}, 'host_prepare_material_stderr': {'bytes': 0, 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, 'host_prepare_material_stdout': {'bytes': 2909, 'sha256': 'ca9b1e930c293340e1a1e95f5f4416cd8bd31659a1a990ac8802f8ada2e5cdb3'}, 'host_prepared': {'bytes': 2909, 'sha256': 'ca9b1e930c293340e1a1e95f5f4416cd8bd31659a1a990ac8802f8ada2e5cdb3'}, 'host_preserved_draft': {'bytes': 282, 'sha256': '9d801d675a461de996206b1bdc911309aeb40df599c49860ddc9699779d4e741'}, 'host_previous': {'bytes': 1426, 'sha256': 'fcdf8a456f663d6963d3cd9caf231a210aad92d8f5e192a71917381d10ea10f0'}, 'host_prior_boundary': {'bytes': 29342, 'sha256': '39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047'}, 'host_push_request': {'bytes': 367, 'sha256': 'a0dd1d0c859e8bff432de0cf31e942bf3e34f442c072dede7d62e6a846ce86b9'}, 'host_request_text': {'bytes': 317, 'sha256': '6888bda7c65087d63417975cca696437ebb3ee7b239a9eda3971e645d184ddb2'}, 'host_root_failure': {'bytes': 3274, 'sha256': '29b5b67cc99280b36c3250d87aaf3ecfeec8a19a79d22e715338447bd6095763'}, 'host_root_manifest': {'bytes': 62265, 'sha256': '7d99108d4160c4ea2775759950f63e4a50ae3c17266ef474c2e182adada82917'}, 'host_root_plan_copy': {'bytes': 5185, 'sha256': '796226a2bb72e3e48465b21339e3918ba74ed70e18ceb8de4e087e5b76c1e590'}, 'host_runtime_manifest': {'bytes': 73225, 'sha256': 'bcabd6171f84738300b1a1e1bbac5263356339f9d9c5e9ee3079db16ca820734'}, 'host_source_actor': {'bytes': 7581, 'sha256': 'bc024b5fcdf5cc31d55224b0bd176d7860ac161a1eff7fe600932f9d3abe7c7b'}, 'host_source_config': {'bytes': 2416, 'sha256': '310dd82101f2ab309cd790d03f0c01e40cbdfef7064510ea4120327aaac72fef'}, 'host_source_helper': {'bytes': 25791, 'sha256': '06cab5903387dd10c29ea6fbddb6e4f4e6ceb6e2e3e835de1148619d89e139e0'}, 'host_source_root': {'bytes': 83705, 'sha256': '68fbb8c6f94f30a6c09946e5965355c9c3c61ea2644ed1109b3a34c6fd0947f0'}, 'scope_controller_reader': {'bytes': 16570, 'sha256': 'be2b96db92bb456a798c3f8be6c1425a81e3afeadf782940bd695cf4cb3c714a'}, 'scope_library_attempt05': {'bytes': 19740, 'sha256': 'a4ec44ac1f09fc7919dce17acf46e6db83ca468f58f53ad7622b520b557d04e4'}, 'scope_library_common': {'bytes': 19138, 'sha256': '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'}, 'scope_library_diag02': {'bytes': 29504, 'sha256': '296f5e22485712fff6641082ab0ffdee78d2d2951bcb8f53a1da5f0c374c2de6'}, 'scope_library_late': {'bytes': 218894, 'sha256': '9adcd6a865875f209bf56cfadc952b40cf4984889cb3450837446b6b95dcbd54'}, 'scope_library_lifecycle': {'bytes': 48643, 'sha256': 'eb43d1f5df1b0e4295770c82328fd17e09b9eaa766861f3803928a0b1f9f4e18'}, 'scope_library_manifest': {'bytes': 65655, 'sha256': '654f8b0ad50a4d930d7beff9421b5e9f988ecb74b55badc70cec9efeaa63130c'}, 'scope_library_native_profile': {'bytes': 4633, 'sha256': '12719e58d2e3e1a1e86b8a6a9dc9587e37bfcb36c4c3b26b023138752bb3e67b'}, 'scope_observer_actor': {'bytes': 7578, 'sha256': 'c74aec49cd4fa84238194242653d5d3798b7f5cdc4659f90bcb50ec0c424902f'}, 'scope_observer_config': {'bytes': 2416, 'sha256': '18600d15ae02724db5e630a39a310b2449c5d7fb162a73239bd7f8045164e1a6'}, 'scope_observer_profile': {'bytes': 4383, 'sha256': '325e36d77472700fc9aab5d3149d7e56e267185d56a4ee11a6362ce6d85c1806'}, 'scope_scope_host_request': {'bytes': 34843, 'sha256': '3abf8649800b30d9cd5012b554f27eb60720521119b1907c862723d60dc8745f'}, 'scope_scope_outer': {'bytes': 2420400, 'sha256': 'e6ec9a6d3812c6801cb2f0b2aa44c9fb51db0ea1b68c7f83762f1cbda660f795'}, 'scope_scope_phone_request': {'bytes': 22529, 'sha256': 'de19b265e7bf8f0a963a8863331847da9d9c9ae9f01fe4f23b030323b9b21d84'}, 'scope_scope_read': {'bytes': 1239, 'sha256': '12f5ba79434e858e2425d019737392a6f12cbcf1d51442351ce4035da4971322'}, 'scope_scope_source': {'bytes': 56762, 'sha256': 'ed02a304a97815991d2a5366ca2df45e3f28a2c18652eac6662404de53ff75a2'}, 'scope_scope_start': {'bytes': 35960, 'sha256': 'fda4af684b32892286431096f5b60ee2a21c3cee23de674002e24a97dfa83c00'}, 'scope_scope_status': {'bytes': 952, 'sha256': '73717463e2118e48061e07149807b714ffc070d1473f4643e89268ac0561d23a'}}
MODULE_PINS={'durable': {'bytes': 17081, 'sha256': '03e100c5a4a05e31f0392a81e72a5be8f3d2e06372c30f4af893cfa13f4f0750'}, 'host': {'bytes': 60308, 'sha256': 'a80abec475b3affdb9bbc25d53282cba5729d6112b93520cdf2ac607ddb2ef9c'}, 'scope': {'bytes': 37788, 'sha256': 'f59bae34d9acc80d2c28cd5636b53e13b68d911d2121735883dc7b001e57779f'}}
INPUT_MAPS={'host': {'actor_stderr': 'originals/host_actor_stderr', 'actor_stdout': 'originals/host_actor_stdout', 'actual_read': 'originals/host_actual_read', 'actual_request': 'originals/host_actual_request', 'actual_start': 'originals/host_actual_start', 'actual_status': 'originals/host_actual_status', 'chain_intent': 'originals/host_chain_intent', 'durable_child': 'originals/host_durable_child', 'durable_exit': 'originals/host_durable_exit', 'durable_exit_witness': 'originals/host_durable_exit_witness', 'durable_launch': 'originals/host_durable_launch', 'durable_launch_lock': 'originals/host_durable_launch_lock', 'durable_owner_intent': 'originals/host_durable_owner_intent', 'durable_owner_lock': 'originals/host_durable_owner_lock', 'durable_reader': 'modules/durable.py', 'durable_request': 'originals/host_durable_request', 'durable_runner': 'originals/host_durable_runner', 'durable_started': 'originals/host_durable_started', 'durable_stderr': 'originals/host_durable_stderr', 'durable_stdout': 'originals/host_durable_stdout', 'host_stage_material_capture': 'originals/host_host_stage_material_capture', 'host_stage_material_child': 'originals/host_host_stage_material_child', 'host_stage_material_intent': 'originals/host_host_stage_material_intent', 'host_stage_material_result': 'originals/host_host_stage_material_result', 'host_stage_material_stderr': 'originals/host_host_stage_material_stderr', 'host_stage_material_stdout': 'originals/host_host_stage_material_stdout', 'lease': 'originals/host_lease', 'mac_export_result': 'originals/host_mac_export_result', 'mac_index': 'originals/host_mac_index', 'operation_intent': 'originals/host_operation_intent', 'operation_result': 'originals/host_operation_result', 'p4_export_result': 'originals/host_p4_export_result', 'p4_index': 'originals/host_p4_index', 'p4_operation': 'originals/host_p4_operation', 'phone_push_material_capture': 'originals/host_phone_push_material_capture', 'phone_push_material_child': 'originals/host_phone_push_material_child', 'phone_push_material_intent': 'originals/host_phone_push_material_intent', 'phone_push_material_result': 'originals/host_phone_push_material_result', 'phone_push_material_stderr': 'originals/host_phone_push_material_stderr', 'phone_push_material_stdin': 'originals/host_phone_push_material_stdin', 'phone_push_material_stdout': 'originals/host_phone_push_material_stdout', 'plan': 'originals/host_plan', 'prepare_material_capture': 'originals/host_prepare_material_capture', 'prepare_material_child': 'originals/host_prepare_material_child', 'prepare_material_intent': 'originals/host_prepare_material_intent', 'prepare_material_result': 'originals/host_prepare_material_result', 'prepare_material_stderr': 'originals/host_prepare_material_stderr', 'prepare_material_stdout': 'originals/host_prepare_material_stdout', 'prepared': 'originals/host_prepared', 'preserved_draft': 'originals/host_preserved_draft', 'previous': 'originals/host_previous', 'prior_boundary': 'originals/host_prior_boundary', 'push_request': 'originals/host_push_request', 'request_text': 'originals/host_request_text', 'root_failure': 'originals/host_root_failure', 'root_manifest': 'originals/host_root_manifest', 'root_plan_copy': 'originals/host_root_plan_copy', 'runtime_manifest': 'originals/host_runtime_manifest', 'source_actor': 'originals/host_source_actor', 'source_config': 'originals/host_source_config', 'source_helper': 'originals/host_source_helper', 'source_root': 'originals/host_source_root'}, 'scope': {'controller_reader': 'originals/scope_controller_reader', 'library_attempt05': 'originals/scope_library_attempt05', 'library_common': 'originals/scope_library_common', 'library_diag02': 'originals/scope_library_diag02', 'library_late': 'originals/scope_library_late', 'library_lifecycle': 'originals/scope_library_lifecycle', 'library_manifest': 'originals/scope_library_manifest', 'library_native_profile': 'originals/scope_library_native_profile', 'observer_actor': 'originals/scope_observer_actor', 'observer_config': 'originals/scope_observer_config', 'observer_profile': 'originals/scope_observer_profile', 'scope_host_request': 'originals/scope_scope_host_request', 'scope_outer': 'originals/scope_scope_outer', 'scope_phone_request': 'originals/scope_scope_phone_request', 'scope_read': 'originals/scope_scope_read', 'scope_source': 'originals/scope_scope_source', 'scope_start': 'originals/scope_scope_start', 'scope_status': 'originals/scope_scope_status', 'source_helper': 'originals/host_source_helper'}}
ARCHIVE={'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/299483481a678cbd589aeba54ed8b68f/ORIGINALS.zlib', 'bytes': 2174339, 'sha256': '18da9626e5ae687adb4087b5a5484d9d2a8dc8885fdaabfd57b829ec02d20fd3'}
RAW_ARCHIVE={'bytes': 3788800, 'sha256': 'ca76e0854be12cb004bef057df668374b851c0a2a90604f1ae7c8ea422b368d6'}
INVENTORY_PIN={'bytes': 1403290, 'sha256': 'bb8cfb6dd2f108046e8296956e514f7b3eec0ea5aaac5794ad86c70174478609'}
R7_ARCHIVE={'path':BASE+'/native-guard-nonnative-boundaries-r10-r1/4808fbf1e81fd1542e7ffb60d7f57ca6/ORIGINALS.zlib',
 'bytes':3000200,'sha256':'4010779b9a3810dc7d0d51072dc76dd52be2327301b857df2b04ddb004a5edca'}
R8_MANIFEST={'path':BASE+'/native-guard-nonnative-boundaries-r10-r1/aa06c3b8d035dcd0c0047105f620b3bf/RETENTION-INPUTS.json',
 'bytes':409,'sha256':'247ebf979d69cfd5b9b55b5cdbe55b2d1a57c481d3ceb67ef5e4ece91f7d78f6'}
R8_ARCHIVE={'path':BASE+'/native-guard-nonnative-boundaries-r10-r1/aa06c3b8d035dcd0c0047105f620b3bf/ORIGINALS.zlib',
 'bytes':2066079,'sha256':'d66d286bfb7890e0b32358326b669ac4a47d5f4ba43c524bc3f129f5bf631e93'}
R8_READER={'path':BASE+'/native-guard-nonnative-boundaries-r10-r1/aa06c3b8d035dcd0c0047105f620b3bf/verify_retained_staged_r8.py',
 'bytes':96088,'sha256':'614f44d6eb75f47b02e32b463f18534e2d0bc5a3e8fd928535e7da17909679ae'}
EXTERNAL_INPUTS=(R7_ARCHIVE,R8_MANIFEST,R8_ARCHIVE,R8_READER)
FAILURE_SEMANTICS={'first_launch_receipt_gap':True,'original_start_reused':True,
 'original_retried_launch':False,'original_wrapper_status':'failed_or_unknown_no_retry',
 'historical_failed_route_callsite':None,'historical_failed_listener_identity':None,
 'baseline_device_shell_wire_dispatched':None,'global_unknown_effect_count':None,'native_terminal':None,
 'native_case_credit':0,'component_qualified':False,'business_qualified':False,
 'standalone_execution_authorized':False,'original_nonce_consumed':True,'replay_authorized':False,
 'new_nonce_authorized':False,'remote_cleanup_proven':False}
TARGET_PATHS=[
 '/proc/1/root/data/local/tmp/hepta-phone-local-v150-r1/hepta-native-guard-'+LABEL+'.tar.gz',
 '/proc/1/root/data/local/tmp/hepta-phone-local-v150-r1/hepta-native-guard-'+LABEL+'.stage.py',
 BASE+'/native-guard-staging-r10-r1/'+LABEL+'.tar.gz',
 BASE+'/native-guard-staging-r10-r1/'+LABEL+'.stage.py',
 BASE+'/native-guard-r10-r1/'+LABEL,
 '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/'+LABEL,
 '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/'+LABEL+'/executor',
 '/proc/1/root/data/local/tmp/hepta-native-guard-'+NONCE,
 BASE+'/native-guard-boundaries-r10-r1/'+NONCE+'.json',
 BASE+'/native-guard-boundaries-r10-r1/'+NONCE]

def need(value,why):
    if not value:raise ValueError(why)
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def enc(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()
def strict(raw):
    def pairs(rows):
        value={}
        for key,item in rows:
            need(key not in value,'duplicate JSON key');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def descriptor(value):
    need(type(value)is dict and set(value)=={'path','bytes','sha256'}and type(value['path'])is str
         and Path(value['path']).is_absolute()and str(Path(value['path']))==value['path']
         and'..'not in Path(value['path']).parts and type(value['bytes'])is int
         and 0<value['bytes']<=MAX_COMPRESSED and type(value['sha256'])is str
         and re.fullmatch('[0-9a-f]{64}',value['sha256']),'one bounded canonical complete descriptor')
    return value
def same_semantics(value):
    need(all(type(value.get(k))is type(v)and value[k]==v for k,v in FAILURE_SEMANTICS.items()),
         'all original failed R9 semantics, missing receipt and unknowns must be preserved')

def verify_retained_transport_archive(archive_descriptor,*,read_pinned):
    need(type(EXPECTED_PINS)is dict and type(MODULE_PINS)is dict and type(INPUT_MAPS)is dict
         and type(ARCHIVE)is dict and type(RAW_ARCHIVE)is dict and type(INVENTORY_PIN)is dict,
         'complete exact retained R9 proof must be bound before any read')
    need(callable(read_pinned)and descriptor(archive_descriptor)==ARCHIVE
         and ARCHIVE['path']==PHONE_ROOT+'/ORIGINALS.zlib','exact canonical R9 archive entrypoint')
    seen_external=[]
    def read_exact(row):
        need(row==ARCHIVE or row in EXTERNAL_INPUTS,'only this archive and four fixed old dependencies')
        descriptor(row);data=read_pinned(row)
        need(type(data)is bytes and pin(data)=={k:row[k]for k in ('bytes','sha256')},
             'complete exact external original read')
        seen_external.append(row);return data
    packed=read_exact(ARCHIVE)
    codec=zlib.decompressobj();archive=codec.decompress(packed,MAX_ORIGINAL+1)
    need(codec.eof and not codec.unused_data and not codec.unconsumed_tail
         and pin(archive)==RAW_ARCHIVE and len(archive)<=MAX_ORIGINAL,
         'one exact bounded complete proof archive, no trailing member')
    files={};modules={}
    expected={'originals/'+k:('original',k,p)for k,p in EXPECTED_PINS.items()}
    expected.update({'modules/'+k+'.py':('module',k,p)for k,p in MODULE_PINS.items()})
    need(len(expected)==len(EXPECTED_PINS)+len(MODULE_PINS),'disjoint source and historical-original member names')
    offset=0
    with tarfile.open(fileobj=io.BytesIO(archive),mode='r:')as tf:
        members=tf.getmembers()
        need([m.name for m in members]==sorted(expected),'entire exact canonical member list')
        for row in members:
            category,key,p=expected[row.name]
            need(row.type==tarfile.REGTYPE and row.linkname==''and row.pax_headers=={}
                 and row.uid==row.gid==row.mtime==0 and row.uname==row.gname==''
                 and row.mode==0o400 and row.size==p['bytes']and row.offset==offset and row.offset_data==offset+512,
                 'exact immutable ordinary retained member')
            stream=tf.extractfile(row);need(stream is not None,'complete original archive stream')
            data=stream.read(MAX_ORIGINAL+1);need(pin(data)==p,'complete exact retained member '+row.name)
            (files if category=='original'else modules)[key]=data
            offset+=512+((row.size+511)//512)*512
    need(len(archive)==((offset+1024+10239)//10240)*10240 and archive[offset:]==bytes(len(archive)-offset),
         'complete exact tar terminator and zero padding')
    need(set(modules)=={'host','scope','durable'},'separate three reviewed plain pure modules')
    need(set(INPUT_MAPS)=={'host','scope'},'two exact pure input projections')
    for key,mapping in INPUT_MAPS.items():
        need(type(mapping)is dict and all(type(n)is str and type(v)is str for n,v in mapping.items()),
             'explicit original input mapping')
    def projected(name):
        result={}
        for key,member in INPUT_MAPS[name].items():
            if member.startswith('originals/'):
                result[key]=files[member[len('originals/'):]]
            else:
                need(member=='modules/durable.py'and name=='host'and key=='durable_reader',
                     'only the separately reviewed durable module is a host reader input')
                result[key]=modules['durable']
        return result
    def load(name,source):
        module=types.ModuleType(name);module.__file__='<retained-r9-'+name+'>'
        exec(compile(source,module.__file__,'exec'),module.__dict__);return module
    h=load('host',modules['host']);s=load('scope',modules['scope'])
    host=h.verify_failed_r9_host(projected('host'));same_semantics(host)
    prior_reader=load('exact_old_r8_reader',read_exact(R8_READER))
    need(prior_reader.R7_ARCHIVE==R7_ARCHIVE,'unchanged exact prior R7 external dependency')
    retained=prior_reader.verify_retained_staged_archive(R8_MANIFEST,read_pinned=read_exact)
    need(retained['retained_failed_staged_binding']==host['retained_failed_staged_binding']
         and retained['retained_preaccept_binding']==host['retained_preaccept_binding'],
         'unchanged complete prior proofs agree with original failed host')
    scope_inputs=projected('scope')
    failed_lease=s.literal(scope_inputs['scope_source'],'FAILED_LEASE')
    need(enc(failed_lease['value'])==projected('host')['lease'],
         'the scope source consumes the byte-exact retained failed host lease value')
    scope=s.verify_failed_r9_scope(scope_inputs,retained=retained,host=host)
    summary=scope['summary']
    need(summary['inventory']==INVENTORY_PIN and pin(enc(scope['inventory_value']))==INVENTORY_PIN
         and summary['current_R9_private_roots']==[]and summary['current_R9_component_role_identities']=={}
         and summary['current_absence_observations']['boot_id']==BOOT
         and summary['complete_old49_preserved']is True,'actual whole retained scope, no invented added roots')
    evidence={'archive':{k:ARCHIVE[k]for k in ('bytes','sha256')},'raw_archive':RAW_ARCHIVE}
    verified={'schema':RESULT_SCHEMA,'state':RESULT_STATE,'label':LABEL,'nonce':NONCE,'boot_id':BOOT,
      **FAILURE_SEMANTICS,'package':host['package'],'combination':host['combination'],'lease':host['lease'],
      'inventory_value':scope['inventory_value'],'inventory_roots':scope['inventory_roots'],'inventory':INVENTORY_PIN,
      'private_roots':[],'component_role_identities':{},
      'original_native_predecessor':host['original_native_predecessor'],
      'original_root_namespace_anchor':host['original_root_namespace_anchor'],
      'retained_preaccept_binding':retained['retained_preaccept_binding'],
      'retained_failed_staged_binding':retained['retained_failed_staged_binding'],
      'evidence_archive':evidence,'host':host,'scope':summary,
      'original_input_count':len(EXPECTED_PINS),'verified_module_count':len(MODULE_PINS),
      'all_original_and_module_pins_verified':True,'external_reads':seen_external,
      'phone_scope_verified':True,'retirement_accepted':False,
      'actual_consumer_publication':False,'current_kernel_ESRCH_asserted':False}
    verified['retained_failed_transport_binding']={'schema':'hepta.r9.retained-transport-failure-binding.v1',
      **{key:verified[key]for key in ('label','nonce','boot_id','package','combination','lease',
        'evidence_archive','inventory','private_roots','component_role_identities',
        'original_native_predecessor','original_root_namespace_anchor',
        'retained_preaccept_binding','retained_failed_staged_binding')},
      **FAILURE_SEMANTICS,'same_boot_complete_scope_original':summary['complete_phone_original'],
      'first_push_scope_only':True,'current_kernel_ESRCH_asserted':False}
    return verified

def validate_private_preservation(verified,current_inventory,*,inventory_reader):
    need(type(verified)is dict and verified.get('schema')==RESULT_SCHEMA and verified.get('state')==RESULT_STATE
         and verified.get('label')==LABEL and verified.get('nonce')==NONCE
         and verified.get('private_roots')==[]and verified.get('component_role_identities')=={}
         and verified.get('inventory')==INVENTORY_PIN,'exact already verified retained failure')
    same_semantics(verified)
    old=verified['inventory_value']
    need(pin(enc(old))==INVENTORY_PIN and old['roots']==verified['inventory_roots']and len(old['roots'])==49,
         'same complete actual49 retained inventory')
    inventory_reader(old);inventory_reader(current_inventory)
    need(set(old['roots'])<=set(current_inventory['roots']),'all actual old49 roots remain')
    roots=set(old['roots']);prefixes=tuple(p+'/'for p in roots)
    selected={p:row for p,row in current_inventory['entries'].items()
              if p in roots or p.startswith(prefixes)}
    need(selected==old['entries'],'all old49 originals/topology preserved without added private members')
    need(all(path not in current_inventory['roots']and path not in current_inventory['entries']for path in TARGET_PATHS),
         'failed R9 observed-absent paths are not invented inventory roots or entries')
    return True

def _validate_absence_rows(rows):
    need(type(rows)is list and len(rows)==len(TARGET_PATHS),'all ten exact failed R9 targets')
    for row,path in zip(rows,TARGET_PATHS):
        need(type(row)is dict and set(row)=={'path','parent_path','parent_metadata','parent_names','state','errno',
             'missing_path','missing_component_index','untraversed_components','leaf_itself_observed_absent',
             'historical_execution_inferred'}and row['path']==path,'complete fixed current absence row')
        p=Path(path)
        if p.parts[:4]==('/','proc','1','root'):anchor=Path('/proc/1/root');parts=p.parts[4:]
        else:anchor=Path('/');parts=p.parts[1:]
        i=row['missing_component_index']
        need(type(i)is int and 0<=i<len(parts),'actual missing component index')
        parent=anchor.joinpath(*parts[:i]);missing=parent/parts[i]
        need(row['state']=='CURRENT_FIRST_MISSING_COMPONENT_ENOENT'and type(row['errno'])is int and row['errno']==2
             and row['historical_execution_inferred']is False and row['parent_path']==str(parent)
             and row['missing_path']==str(missing)and row['untraversed_components']==list(parts[i+1:])
             and row['leaf_itself_observed_absent']is(i==len(parts)-1),'exact current leaf or missing ancestor only')
        metadata=row['parent_metadata'];names=row['parent_names']
        need(type(metadata)is list and len(metadata)==9 and all(type(v)is int and v>=0 for v in metadata)
             and stat.S_ISDIR(metadata[2]),'original actual directory full9')
        need(type(names)is list and names==sorted(set(names))and len(names)<=20000
             and all(type(n)is str and n not in ('','.','..')and'/'not in n and'\0'not in n for n in names)
             and parts[i]not in names,'complete stable current parent excludes the missing component')
    return True

def validate_absence_observations(value,*,expected_boot_id):
    need(type(value)is dict and set(value)=={'schema','boot_id','began_monotonic_ns','ended_monotonic_ns',
         'targets_before','targets_after','scan_complete','historical_execution_inferred','kernel_ESRCH_asserted'}
         and value['schema']==ABSENCE_SCHEMA and value['boot_id']==expected_boot_id==BOOT
         and value['scan_complete']is True and value['historical_execution_inferred']is False
         and value['kernel_ESRCH_asserted']is False,'complete same-boot current absence only')
    a,b=value['began_monotonic_ns'],value['ended_monotonic_ns']
    need(type(a)is int and type(b)is int and 0<a<=b and b-a<30*10**9,'original shared30s observation bound')
    need(value['targets_before']==value['targets_after'],'two current complete fixed scope bookends')
    _validate_absence_rows(value['targets_before'])
    return value

def observe_current_absence(*,common_module,deadline):
    """Read only these ten failed paths, with the caller's remaining total30s."""
    C=common_module
    need(type(deadline)in (int,float)and math.isfinite(deadline)
         and 0<deadline-time.monotonic()<=30,'existing shared remaining30s deadline required')
    def tick():need(time.monotonic()<deadline,'original shared retained inventory deadline')
    def boot():
        tick();fd=os.open('/proc/sys/kernel/random/boot_id',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
        try:
            need(stat.S_ISREG(os.fstat(fd).st_mode),'regular original boot pseudo-file')
            raw=bytearray()
            while True:
                tick();chunk=os.read(fd,min(128-len(raw)+1,128))
                if not chunk:break
                raw.extend(chunk);need(len(raw)<=128,'bounded original boot read')
        finally:os.close(fd)
        need(bytes(raw)==(BOOT+'\n').encode(),'same original failed R9 boot');return BOOT
    def observed(path):
        tick();path=Path(path)
        if path.parts[:4]==('/','proc','1','root'):current=Path('/proc/1/root');parts=path.parts[4:]
        else:current=Path('/');parts=path.parts[1:]
        fd=os.open(current,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        try:
            for index,name in enumerate(parts):
                tick();before=C.metadata(os.fstat(fd));names=sorted(os.listdir(fd))
                need(len(names)<=20000 and len(names)==len(set(names)),'bounded complete target parent names')
                missing=False
                try:child=os.stat(name,dir_fd=fd,follow_symlinks=False)
                except FileNotFoundError as failure:
                    need(failure.errno==2,'only original component ENOENT');missing=True
                need(before==C.metadata(os.fstat(fd))and names==sorted(os.listdir(fd)),'target parent changed')
                if missing:
                    check,leaf=C.parent_fd(current/name)
                    try:
                        need(leaf==name and C.metadata(os.fstat(check))==before and sorted(os.listdir(check))==names,
                             'target canonical parent replaced')
                        try:os.stat(leaf,dir_fd=check,follow_symlinks=False)
                        except FileNotFoundError as failure:need(failure.errno==2,'exact second current ENOENT')
                        else:raise ValueError('failed R9 target appeared during read')
                    finally:os.close(check)
                    need(name not in names,'complete parent contains allegedly missing child')
                    return {'path':str(path),'parent_path':str(current),'parent_metadata':before,'parent_names':names,
                     'state':'CURRENT_FIRST_MISSING_COMPONENT_ENOENT','errno':2,'missing_path':str(current/name),
                     'missing_component_index':index,'untraversed_components':list(parts[index+1:]),
                     'leaf_itself_observed_absent':index==len(parts)-1,'historical_execution_inferred':False}
                need(index<len(parts)-1 and stat.S_ISDIR(child.st_mode)and not stat.S_ISLNK(child.st_mode),
                     'failed R9 path is present or a symlink/special ancestor')
                nxt=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                need(C.metadata(os.fstat(nxt))==C.metadata(child),'target ancestor changed during open')
                os.close(fd);fd=nxt;current=current/name
            raise ValueError('missing-component observation required')
        finally:os.close(fd)
    began=time.monotonic_ns();same_boot=boot()
    first=[observed(p)for p in TARGET_PATHS];second=[observed(p)for p in TARGET_PATHS]
    need(boot()==same_boot,'same current original boot bookend');tick()
    value={'schema':ABSENCE_SCHEMA,'boot_id':same_boot,'began_monotonic_ns':began,'ended_monotonic_ns':time.monotonic_ns(),
       'targets_before':first,'targets_after':second,'scan_complete':True,
       'historical_execution_inferred':False,'kernel_ESRCH_asserted':False}
    return validate_absence_observations(value,expected_boot_id=same_boot)
