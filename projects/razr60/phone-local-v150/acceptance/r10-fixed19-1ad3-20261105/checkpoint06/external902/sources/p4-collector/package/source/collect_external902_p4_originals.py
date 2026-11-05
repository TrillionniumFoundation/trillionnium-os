#!/usr/bin/env python3
"""Collect fixed original P4 trees without executing any retained source or device operation."""
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import time

P4_BASE = Path('/home/alex')
OUT = Path('/home/alex/codex-hepta-external902-7c907661-originals-1ad3-01')
LABEL = 'root-r10-neg01-7c907661-01'
NONCE = '902e851c3ca1f90deab3d880ab993774'
FIXED_TREES = {'sender-originals': '/home/alex/codex-hepta-natural-root-r10-neg01-7c907661-01-root-v150', 'setup-fixture-originals': '/home/alex/codex-hepta-native-guard-fixtures-r10-r1/902e851c3ca1f90deab3d880ab993774/setup', 'material-originals': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material'}
MATERIAL_FILES = {'tree/LEASE.json': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/LEASE.json', 'bytes': 2496, 'sha256': '31688136fbcb7ae520c096decc11c9c36a67a304172401c3aab6c14e7848c736'}, 'tree/inputs/COMBINATION.json': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/inputs/COMBINATION.json', 'bytes': 4702, 'sha256': '54b1d9aef4c16ebc0989b3e13345238bfbd4e400e5bfc9a97e27648a2385057e'}, 'tree/inputs/PRIOR-BOUNDARY.original.json': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/inputs/PRIOR-BOUNDARY.original.json', 'bytes': 9373, 'sha256': 'eca941303197228ebe03561e612bfe41eb0518c590ff21253444db25a11adc10'}, 'tree/inputs/SOURCE-SEAL.original.json': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/inputs/SOURCE-SEAL.original.json', 'bytes': 2341, 'sha256': 'a41a317d9ba3317b4c3bf66b66fb574f47f9bf15b1dc67201cea30d9ae0a9229'}, 'tree/inputs/configuration.original.json': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/inputs/configuration.original.json', 'bytes': 1493, 'sha256': '780754928709871d3e70f432acb6a021c6c97ab822aaf7c32c887c132cac8c34'}, 'tree/inputs/production/action_ledger.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/inputs/production/action_ledger.py', 'bytes': 15587, 'sha256': '50620b2e27334b7cf311bd6b1c743d71c19c32887e5ed31a07fdf54dac0e7907'}, 'tree/inputs/production/daily_phone_local.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/inputs/production/daily_phone_local.py', 'bytes': 22059, 'sha256': 'f42fa1f3268d2a2c00e49610d356b440d1e32722fbe2af877580fb6eb180f712'}, 'tree/inputs/production/health_contracts.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/inputs/production/health_contracts.py', 'bytes': 11439, 'sha256': '00adea791c00eaac52f65716cb158ee73f38bdded96f1718578ec92f5091d32d'}, 'tree/inputs/production/ledger_round_evidence.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/inputs/production/ledger_round_evidence.py', 'bytes': 15135, 'sha256': '87d2b8731883dd06806a45851867332c568fe02deb2b9b8952094b86822e678d'}, 'tree/inputs/production/model_health.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/inputs/production/model_health.py', 'bytes': 8251, 'sha256': '105b401fbab1c151e890a3e6e4774322eb62a9e7799744b4d3cef01b6e1c0f80'}, 'tree/inputs/production/model_slot_cleanup.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/inputs/production/model_slot_cleanup.py', 'bytes': 37375, 'sha256': '9144bc864e245d63186f6b37760562e3b42554fdcc42ed792c9081761f315183'}, 'tree/inputs/production/phone_local_http_worker.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/inputs/production/phone_local_http_worker.py', 'bytes': 10453, 'sha256': 'a1f1c94f2e78ced93cbde2113f508d756507249133f71c6dbe9a82a58a232d4d'}, 'tree/inputs/production/phone_local_tools.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/inputs/production/phone_local_tools.py', 'bytes': 13813, 'sha256': '0302a8bac9dac18234c9493aa512e1efcf43d7cc5eaab884882dad42c2182c54'}, 'tree/inputs/production/phone_observation_tools.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/inputs/production/phone_observation_tools.py', 'bytes': 38774, 'sha256': 'f16c77c1b4509babcea5fc2e8d0a7ae8ab43b3cd58e6640441b44ecd4bccb6df'}, 'tree/inputs/production/phone_task_guards.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/inputs/production/phone_task_guards.py', 'bytes': 22825, 'sha256': '87d88e0e9f93b31cf69bf0e4cdb9c62fd20e03c2192a0ffec621eb84c26bba86'}, 'tree/inputs/production/provider_codex_host.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/inputs/production/provider_codex_host.py', 'bytes': 41510, 'sha256': 'cbdeaaf819ef2fa2d67d3d9707dae86eac6303d6caa4bf194b37cd0816177039'}, 'tree/inputs/production/provider_openai_compatible.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/inputs/production/provider_openai_compatible.py', 'bytes': 17730, 'sha256': '337c83284fece94c0dd477a30029c63017b7eb00aab55a747b89b193823820bc'}, 'tree/inputs/production/provider_phone_local.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/inputs/production/provider_phone_local.py', 'bytes': 70237, 'sha256': '082b02a473dc4d75d46a895895b64b96cf25ae24fc61795cb292fc70fd8d9ad6'}, 'tree/inputs/production/retirement_recovery.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/inputs/production/retirement_recovery.py', 'bytes': 9802, 'sha256': 'c1f5a77e32264f5f638f62f005f57c66fffeb60cf288ad036848ac4fceb74827'}, 'tree/inputs/production/task_postconditions.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/inputs/production/task_postconditions.py', 'bytes': 23211, 'sha256': 'd4984cce3e25609d0bc3ef97475edfe74d4795244722e654eb654df3b6e6ceb3'}, 'tree/inputs/service-inputs.original.json': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/inputs/service-inputs.original.json', 'bytes': 10635, 'sha256': '2739a0af53650363e065bb71a448481998c68fc8b8632e61262c319dae6b586a'}, 'tree/owner-request.txt': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/owner-request.txt', 'bytes': 317, 'sha256': '526568aa9d2c95f333caf396f9873deaf8baca2df841e7a94100e04b28bb93eb'}, 'tree/package/MANIFEST.json': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/MANIFEST.json', 'bytes': 16808, 'sha256': '31da1d92d2d9c833cd053db15b0cc40824e750705d315a320206a2f7a52a6bfb'}, 'tree/package/reference/REVIEWED-PRODUCTION-PINS.json': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/reference/REVIEWED-PRODUCTION-PINS.json', 'bytes': 1438, 'sha256': '73963fdcea527cdbc3628bdeff5918f7106afbaf095fb183e4b199391e46a7a5'}, 'tree/package/reference/attempt05-AFTER-INVENTORY.original.json': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/reference/attempt05-AFTER-INVENTORY.original.json', 'bytes': 664638, 'sha256': '87103089914885fff5632781f18fbe36895ed181f01997eac6c3b49449b5579e'}, 'tree/package/reference/attempt05-CLOSURE.original.json': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/reference/attempt05-CLOSURE.original.json', 'bytes': 164095, 'sha256': 'd464bac786ef208d8fa0390587bd3bb7616a13985fb064716a209aa2394458f6'}, 'tree/package/reference/attempt05-SIDE-PROOF.original.json': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/reference/attempt05-SIDE-PROOF.original.json', 'bytes': 4650, 'sha256': '1bf6bca5ae5aaa5d5803b708070680e92d3f072f9541f38b09783787cfae7b9c'}, 'tree/package/reference/component_common_r5.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/reference/component_common_r5.py', 'bytes': 18133, 'sha256': '8ad9a3b17e7475555af7dd9a113025740447fcebdf0400d984d8a9e84accfb02'}, 'tree/package/reference/component_core.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/reference/component_core.py', 'bytes': 13238, 'sha256': '705b982a46de0fd4427cd6a233687381c592ef74459f9818f3da15e20c03916f'}, 'tree/package/reference/component_once_r9.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/reference/component_once_r9.py', 'bytes': 30647, 'sha256': '1c27b548e42c91391e12db125c23608a2d5fb9e28ae2713df17c271bddc58fa2'}, 'tree/package/reference/decode_client_state.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/reference/decode_client_state.py', 'bytes': 4116, 'sha256': 'a3e619926a4688ebfefd55ad1074cb386240f9828613781b7fd547bcf0c70073'}, 'tree/package/reference/environment_parent_late_boundary_r6.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/reference/environment_parent_late_boundary_r6.py', 'bytes': 53502, 'sha256': '1fd24e0a6799ed3fb02014567764cce4c0de884e78ccd5b663e63fe69230041c'}, 'tree/package/reference/native_guard_session.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/reference/native_guard_session.py', 'bytes': 28109, 'sha256': '77dacc52468de95b68f30baafbb1cbf7dd7452c3d9ce652980dbb4af0ca62d8b'}, 'tree/package/reference/native_journal_audit.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/reference/native_journal_audit.py', 'bytes': 6701, 'sha256': 'da47d875addc32c0f7f30d178de95d8ebd956a6cb10b59813705feeb7811f0cf'}, 'tree/package/reference/non_native_attempt05.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/reference/non_native_attempt05.py', 'bytes': 19740, 'sha256': 'a4ec44ac1f09fc7919dce17acf46e6db83ca468f58f53ad7622b520b557d04e4'}, 'tree/package/reference/policy_parent_late_boundary_r4.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/reference/policy_parent_late_boundary_r4.py', 'bytes': 35730, 'sha256': 'bcbe7d03567684ca23bd0985c14df49b021e1ac2e53e76dfda94262d7ad3516b'}, 'tree/package/reference/property_parent_late_boundary_r7.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/reference/property_parent_late_boundary_r7.py', 'bytes': 62434, 'sha256': '3c710779e79870e4fefdedb8a24163118b2de814d7fcd3e97bb8971eec6113fd'}, 'tree/package/reference/send_new_native_task_r5.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/reference/send_new_native_task_r5.py', 'bytes': 40788, 'sha256': '5ab04019e94adb989e9909ae3a9aa10db0689de62821ec549db8beb3ec4d0281'}, 'tree/package/reference/tool_client_r6.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/reference/tool_client_r6.py', 'bytes': 17390, 'sha256': '500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f'}, 'tree/package/source/close_component.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/source/close_component.py', 'bytes': 99120, 'sha256': '9025acca896c501aef584a92e93af833a342c48731161a6ec10a4a1cae4278d1'}, 'tree/package/source/component_common.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/source/component_common.py', 'bytes': 19138, 'sha256': '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'}, 'tree/package/source/component_lifecycle.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/source/component_lifecycle.py', 'bytes': 40261, 'sha256': '144836347482b8871703b882283ffac63d5df480e3333a9bd631409f890fc1c2'}, 'tree/package/source/component_listener.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/source/component_listener.py', 'bytes': 38823, 'sha256': 'ad345c0080cbfd89f1378bb6e8583f43e1fa4af0a5928d7ecbf4ccc8d4f04c52'}, 'tree/package/source/component_snapshot.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/source/component_snapshot.py', 'bytes': 24187, 'sha256': '2d624aaafb7df75ad3c78b35e866a44022ee4f5205b20aaeb4515458e05eaffa'}, 'tree/package/source/late_boundary.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/source/late_boundary.py', 'bytes': 74287, 'sha256': '396da713d4b7cab45d0eda80b65df82d7b570440a9c9ea1f74f342b81031ec97'}, 'tree/package/source/native_guard_session_r2.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/source/native_guard_session_r2.py', 'bytes': 28878, 'sha256': '5fe50be4dccbe655a39124876d1f9c2199de20d80ec0a84f08a63d88e7f1a931'}, 'tree/package/source/native_proc_profile.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/source/native_proc_profile.py', 'bytes': 4633, 'sha256': '12719e58d2e3e1a1e86b8a6a9dc9587e37bfcb36c4c3b26b023138752bb3e67b'}, 'tree/package/source/prepare_component.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/source/prepare_component.py', 'bytes': 14259, 'sha256': '46a28fd77dc64d94ccdd4c1f3e12912e22ebb39defc29b69991df831d75afc7d'}, 'tree/package/source/root_fixture_once.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/source/root_fixture_once.py', 'bytes': 18728, 'sha256': 'bb70017c4f184efc0c9372ab072fa2d11a1cf7cbd3276257fa7b3605a426e0d1'}, 'tree/package/source/root_fixture_originals.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/source/root_fixture_originals.py', 'bytes': 39149, 'sha256': 'c1cd1402888de5bc4176255269014995e9d39dc658912d3c28a117ec51010f9e'}, 'tree/package/source/run_root_fixture_phase.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/source/run_root_fixture_phase.py', 'bytes': 10498, 'sha256': 'bf65791c252d0b4d9416717ffca44fe43c9021211c2f2189be5553ab8967a6b2'}, 'tree/package/source/send_new_native_guard_task_r10_r4.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/source/send_new_native_guard_task_r10_r4.py', 'bytes': 40952, 'sha256': 'aafd40345c6dc35b7b7d34ab8b04c860ebf17d326d842ed733d0404cd0a051ad'}, 'tree/package/source/sender_native_guard_ready_r10_r4.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/source/sender_native_guard_ready_r10_r4.py', 'bytes': 18666, 'sha256': 'f3b83e55a07edd370946c40cec8694f310c9713082604646d264b625e7314d99'}, 'tree/package/source/stage_component.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/source/stage_component.py', 'bytes': 19116, 'sha256': '4d4692a284ddce37aae383fc537cac1e49e2fbb05ede4321f57d8f022dd62340'}, 'tree/package/source/witness_bundle.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/package/source/witness_bundle.py', 'bytes': 18137, 'sha256': 'f949ae3d6cec26bf98448fd0ac20b1f46472190be022d6532b1973177e0edfca'}, 'tree/sender-contract.json': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/material/tree/sender-contract.json', 'bytes': 679, 'sha256': 'da172945efb35cf105296add4e01eb9e7b4bbf3a756de4c53d820499074e1901'}}
ADDITIONAL_FIXED_FILES = {'sibling-input-originals/request.original': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/inputs/request.original', 'bytes': 317, 'sha256': '526568aa9d2c95f333caf396f9873deaf8baca2df841e7a94100e04b28bb93eb'}, 'sibling-input-originals/previous.original': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/inputs/previous.original', 'bytes': 1428, 'sha256': '9133e2511a66a809be647cb8bb49e3afb351825db5e465f75b1f2f0b6d9d88f4'}, 'sibling-input-originals/preserved_draft.original': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/inputs/preserved_draft.original', 'bytes': 282, 'sha256': '9d801d675a461de996206b1bdc911309aeb40df599c49860ddc9699779d4e741'}, 'sibling-input-originals/component-inputs.tar.gz': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/inputs/component-inputs.tar.gz', 'bytes': 471979, 'sha256': '989a78d8c9a844ea0f06859a9e9e2b66bafeacd4702a9b8388d6a031b7775afb'}, 'sibling-input-originals/stage_component.py': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/inputs/stage_component.py', 'bytes': 19116, 'sha256': '4d4692a284ddce37aae383fc537cac1e49e2fbb05ede4321f57d8f022dd62340'}, 'setup-plan-originals/ROOT-SETUP-PLAN.json': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/plans/setup/ROOT-SETUP-PLAN.json', 'bytes': 6402, 'sha256': '824880935f6bfe854d4b1f096f7c7c593db7bb85d200153ddca3daea291f1607'}, 'setup-plan-originals/BOUND-CONTRACT.json': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/plans/setup/BOUND-CONTRACT.json', 'bytes': 1842, 'sha256': '5b34b08df6897149afc321508481b755ac2e68d439131075ff8bb4f7e37c6b3b'}, 'setup-plan-originals/ACCEPTED.json': {'path': '/home/alex/codex-native-guard-chain-r10-r1/902e851c3ca1f90deab3d880ab993774/plans/setup/ACCEPTED.json', 'bytes': 552, 'sha256': 'a3e0cdace4d9eb2f875beddd9556b8ee94f38820f086bc15387386660b6bb603'}}
SETUP_TERMINAL = {'bytes': 24411, 'path': '/home/alex/codex-hepta-native-guard-fixtures-r10-r1/902e851c3ca1f90deab3d880ab993774/setup/HOST-TERMINAL.json', 'sha256': '82b4faebc69bae4d2e917af81300d82483f0183b7d3f357aa594c57cd6926ff6'}
RUNTIME_MANIFEST_SHA = '31da1d92d2d9c833cd053db15b0cc40824e750705d315a320206a2f7a52a6bfb'
MAC_MATERIAL_REFERENCE = {'original_component_archive': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/material/component-inputs.tar.gz', 'bytes': 471979, 'sha256': '989a78d8c9a844ea0f06859a9e9e2b66bafeacd4702a9b8388d6a031b7775afb'}, 'selected_complete_gzip_whole_sha_verified': True, 'whole_outer_xz_or_239_member_verification_claimed_here': False, 'selection_origin': 'Complete member from native-version-pinned XZ prefix, independently matched to exact PREPARED archive pin', 'original_root_plan': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/ROOT-PLAN.original.json', 'bytes': 4783, 'sha256': '9a94108ffc737133ba879bd9cccd70c7ec3ae2f3da17eb689e5b1d5610789d58'}, 'original_prepared': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-01/material/PREPARED.json', 'bytes': 2873, 'sha256': 'a8b8b355a9bde5db21123cf503be5f62a24d55226e154ce5ed95a428347d1898'}}
META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
MAX_FILES = 2048
MAX_DIRECTORIES = 512
MAX_BYTES = 64 * 1024 * 1024
MAX_SECONDS = 100


def need(value, reason):
    if not value:
        raise ValueError(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def enc(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False) + '\n').encode('utf-8')

def strict(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))

def metadata(value):
    return [getattr(value, key) for key in META]

def descriptor(path, raw):
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}

def relative(value):
    need(type(value) is str and '\0' not in value, 'plain relative path required')
    path = PurePosixPath(value)
    need(value and not path.is_absolute() and str(path) == value
         and all(p not in ('', '.', '..') for p in path.parts), 'canonical relative path required')
    return path

def check_time(started):
    # Cooperative only: filesystem/compression syscalls are not preempted.
    need(time.monotonic() - started < MAX_SECONDS, 'collector observation budget exhausted')

def open_directory(path, parent=None, leaf=None):
    need(path.is_absolute() and path.resolve(strict=True) == path, 'canonical directory required')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path if parent is None else leaf, flags, dir_fd=parent)
    try:
        value = os.fstat(fd)
        need(stat.S_ISDIR(value.st_mode) and metadata(value) == metadata(path.lstat()),
             'directory path/held identity differs')
        return fd, metadata(value)
    except BaseException:
        os.close(fd)
        raise

def check_directory(path, fd, expected, full=True):
    need(path.resolve(strict=True) == path, 'held directory path became noncanonical')
    held, named = metadata(os.fstat(fd)), metadata(path.lstat())
    need(held == named, 'held directory path identity differs')
    need(held == expected if full else held[:5] == expected[:5], 'directory changed across observation')

def read_file(path, parent_fd, leaf, expected=None):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(leaf, flags, dir_fd=parent_fd)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 <= before.st_size <= MAX_BYTES, 'bounded single-link original file required')
        if expected is not None:
            need(metadata(before) == expected, 'original file identity changed before re-read')
        chunks = []
        total = 0
        while total <= before.st_size:
            part = os.read(fd, min(65536, before.st_size + 1 - total))
            if not part:
                break
            chunks.append(part)
            total += len(part)
        raw = b''.join(chunks)
        need(len(raw) == before.st_size and metadata(before) == metadata(os.fstat(fd))
             == metadata(os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False))
             == metadata(path.lstat()), 'original file bytes/identity raced')
        return raw, metadata(before)
    finally:
        os.close(fd)


def collect_tree(started, handles):
    files, directories = {}, {}
    total = 0

    def retain(path, name, parent_key, parent_fd, leaf, expected=None):
        nonlocal total
        relative(name)
        need(name not in files and len(files) < MAX_FILES, 'unique bounded original file required')
        info = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        need(stat.S_ISREG(info.st_mode), 'only regular original files are collected')
        raw, original_metadata = read_file(path, parent_fd, leaf, metadata(info))
        if expected is not None:
            need(descriptor(path, raw) == expected, 'fixed additional original differs')
        total += len(raw)
        need(total <= MAX_BYTES, 'combined P4 original byte budget exceeded')
        files[name] = {'raw': raw, 'metadata': original_metadata, 'parent': parent_key,
                       'leaf': leaf, 'descriptor': descriptor(path, raw)}
        check_time(started)

    def visit(path, name, parent_fd=None, leaf=None):
        check_time(started)
        relative(name)
        need(name not in handles and len(handles) < MAX_DIRECTORIES, 'unique bounded directory required')
        fd, first = open_directory(path, parent_fd, leaf)
        handles[name] = (path, fd, first)
        names = sorted(os.listdir(fd))
        need(len(names) <= MAX_FILES + MAX_DIRECTORIES, 'directory child count exceeded')
        directories[name] = {'path': str(path), 'archive_prefix': name, 'scope': 'complete_tree',
                             'metadata': first, 'names': names}
        for child in names:
            need(child not in ('', '.', '..') and '/' not in child and '\0' not in child,
                 'single direct child name required')
            child_name = name + '/' + child
            relative(child_name)
            info = os.stat(child, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                visit(path / child, child_name, fd, child)
            else:
                retain(path / child, child_name, name, fd, child)
            check_time(started)
        need(sorted(os.listdir(fd)) == names, 'directory child set changed during scan')
        check_directory(path, fd, first)

    for prefix, path in FIXED_TREES.items():
        visit(Path(path), prefix)
    parent_keys = {}
    for archive_name, pin in ADDITIONAL_FIXED_FILES.items():
        path = Path(pin['path'])
        need(path.is_absolute() and path.resolve(strict=True) == path and P4_BASE in path.parents,
             'fixed sibling original path must stay inside /home/alex')
        parent = path.parent
        if parent not in parent_keys:
            key = 'pinned-parent-' + str(len(parent_keys))
            need(key not in handles and len(handles) < MAX_DIRECTORIES, 'pinned parent handle budget exceeded')
            fd, first = open_directory(parent)
            handles[key] = (parent, fd, first)
            names = sorted(os.listdir(fd))
            need(len(names) <= MAX_FILES + MAX_DIRECTORIES, 'pinned parent child-name budget exceeded')
            directories[key] = {'path': str(parent), 'archive_prefix': None,
                'scope': 'parent_identity_and_child_names_only_not_all_child_contents',
                'metadata': first, 'names': names}
            parent_keys[parent] = key
        key = parent_keys[parent]
        _, fd, first = handles[key]
        retain(path, archive_name, key, fd, path.name, pin)
        check_directory(parent, fd, first)
        need(sorted(os.listdir(fd)) == directories[key]['names'], 'pinned parent child set changed')
    return files, directories


def recheck_tree(files, directories, handles, started):
    check_time(started)
    for name, row in sorted(files.items()):
        relative(name)
        path = Path(row['descriptor']['path'])
        parent_path, parent_fd, parent_metadata = handles[row['parent']]
        need(path.parent == parent_path and path.name == row['leaf'], 'held original parent binding differs')
        check_directory(parent_path, parent_fd, parent_metadata)
        raw, current_metadata = read_file(path, parent_fd, row['leaf'], row['metadata'])
        need(raw == row['raw'] and current_metadata == row['metadata'],
             'original file changed across full observation bookend')
        check_time(started)
    for name, row in directories.items():
        path, fd, first = handles[name]
        check_directory(path, fd, first)
        need(sorted(os.listdir(fd)) == row['names'], 'observed directory child set changed')
    return {'checked_file_count': len(files), 'checked_directory_count': len(directories),
            'completed_unix_ns': time.time_ns(), 'completed_monotonic_ns': time.monotonic_ns()}


def put_new(directory_fd, path, raw):
    need(type(raw) is bytes and len(raw) <= MAX_BYTES + 4 * 1024 * 1024, 'bounded new evidence output required')
    fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=directory_fd)
    try:
        first = os.fstat(fd)
        need(stat.S_ISREG(first.st_mode) and first.st_nlink == 1 and first.st_size == 0
             and first.st_uid == os.geteuid() and stat.S_IMODE(first.st_mode) == 0o600,
             'new private regular evidence inode required')
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:offset + 65536])
            need(count > 0, 'new evidence short write')
            offset += count
        os.fsync(fd)
        final = metadata(os.fstat(fd))
        need(final[:5] == metadata(first)[:5] and final == metadata(path.lstat()),
             'created evidence inode replaced')
        os.lseek(fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        count = 0
        while count <= len(raw):
            block = os.read(fd, min(65536, len(raw) + 1 - count))
            if not block:
                break
            digest.update(block)
            count += len(block)
        need(count == len(raw) and digest.hexdigest() == sha(raw)
             and final == metadata(os.fstat(fd)) == metadata(path.lstat()),
             'new evidence readback differs')
        os.fsync(directory_fd)
        return {**descriptor(path, raw), 'metadata': final}
    finally:
        os.close(fd)


def verify_fixed_scope(files):
    material = {name: row for name, row in files.items()
                if name.startswith('material-originals/')}
    expected = {'material-originals/' + name for name in MATERIAL_FILES}
    need(set(material) == expected, 'complete P4 material tree differs from original Mac material tree')
    for name, pin in MATERIAL_FILES.items():
        row = material['material-originals/' + name]
        need(row['descriptor'] == pin, 'original material byte pin differs: ' + name)
    for name, pin in ADDITIONAL_FIXED_FILES.items():
        need(files[name]['descriptor'] == pin, 'fixed sibling input/plan original differs')
    terminal = files['setup-fixture-originals/HOST-TERMINAL.json']
    need(terminal['descriptor'] == SETUP_TERMINAL, 'fixed setup fixture terminal differs')
    need(strict(terminal['raw'])['state'] == 'OWNED_ROOT_FIXTURE_CHILD_JOINED',
         'fixed original setup terminal state differs')
    sender_names = {name[len('sender-originals/'):] for name in files
                    if name.startswith('sender-originals/')}
    required = {'SEND.once.json', 'SEND.MONOTONIC-INTENT.json',
                'SEND.MONOTONIC-WINDOW.json', 'SEND-NATIVE-LATENCY.json'}
    need(required <= sender_names, 'original native sender records incomplete')
    branch = sender_names & {'SEND.result.json', 'SEND.unknown.json'}
    need(len(branch) == 1, 'exactly one retained native send result branch required')
    lease = strict(material['material-originals/tree/LEASE.json']['raw'])
    contract = strict(material['material-originals/tree/sender-contract.json']['raw'])
    need(lease['label'] == contract['label'] == LABEL
         and lease['nonce'] == contract['nonce'] == NONCE
         and lease['case_id'] == contract['case_id'] == 'NEG-01'
         and lease['package_sha256'] == contract['package_sha256'] == RUNTIME_MANIFEST_SHA,
         'fixed material lease and sender contract identities differ')
    return {'scope': 'Original byte identities and closed file sets only',
        'material_reference': MAC_MATERIAL_REFERENCE,
        'material_regular_files': len(material),
        'material_whole_closed_set_matches_original_host_material': True,
        'fixed_sibling_originals': ADDITIONAL_FIXED_FILES,
        'setup_original_terminal': SETUP_TERMINAL,
        'sender_regular_files': len(sender_names),
        'sender_named_records_present': sorted(name for name in sender_names if name.startswith('SEND')),
        'sender_result_branch': sorted(branch)[0],
        'sender_native_result_independently_qualified_here': False,
        'original_mac_sender_pid': 54589,
        'original_mac_parent_joined': False,
        'original_mac_stdout_eof': False, 'original_mac_stderr_eof': False,
        'later_records_retrofit_original_parent_join_or_EOF': False,
        'native_process_cleanup_verified_here': False,
        'boundary_publication_verified_here': False}


def main():
    started = time.monotonic()
    start_unix_ns = time.time_ns()
    handles = {}
    parent_fd = out_fd = None
    out_identity = None
    try:
        need(type(COLLECTOR_SOURCE) is bytes and len(COLLECTOR_SOURCE) <= 65536,
             'exact controller-retained collector source required')
        need(OUT.parent == P4_BASE and all(Path(path).is_absolute() for path in FIXED_TREES.values()),
             'fixed independent P4 paths required')
        files, directories = collect_tree(started, handles)
        scope_proof = verify_fixed_scope(files)
        before_write = recheck_tree(files, directories, handles, started)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, row in sorted(files.items()):
                member = tarfile.TarInfo(str(relative(name)))
                member.size = len(row['raw'])
                member.mode = 0o600
                member.uid = member.gid = 0
                member.mtime = 0
                archive.addfile(member, io.BytesIO(row['raw']))
        tar_raw = buffer.getvalue()
        need(len(tar_raw) <= MAX_BYTES + 4 * 1024 * 1024, 'archive framing budget exceeded')
        packed = lzma.compress(tar_raw, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64, preset=6)
        need(lzma.decompress(packed) == tar_raw, 'lossless original archive differs')
        check_time(started)
        parent_fd, parent_identity = open_directory(P4_BASE)
        need(not os.path.lexists(OUT), 'new independent evidence directory required; no retry or overwrite')
        os.mkdir(OUT.name, mode=0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
        out_fd, out_identity = open_directory(OUT, parent_fd, OUT.name)
        need(out_identity[3] == os.geteuid() and stat.S_IMODE(out_identity[2]) == 0o700,
             'new private evidence directory required')
        collector_row = put_new(out_fd, OUT / 'COLLECTOR.original.py', COLLECTOR_SOURCE)
        archive_row = put_new(out_fd, OUT / 'EXTERNAL902-P4-ORIGINALS.tar.xz', packed)
        counts = {prefix: sum(name.startswith(prefix + '/') for name in files)
                  for prefix in FIXED_TREES}
        total_bytes = sum(len(row['raw']) for row in files.values())
        manifest = {'schema': 'hepta.root.external902-p4-originals-manifest.v1',
            'state': 'EXACT_THREE_P4_TREES_AND_PINNED_SIBLING_ORIGINALS_READ_ONLY_BYTE_COPY',
            'label': LABEL, 'nonce': NONCE, 'complete_source_roots': FIXED_TREES,
            'additional_fixed_files': ADDITIONAL_FIXED_FILES,
            'started_unix_ns': start_unix_ns, 'first_full_recheck': before_write,
            'files': [{**row['descriptor'], 'archive_member': name, 'metadata': row['metadata']}
                      for name, row in sorted(files.items())],
            'directories': [row for _, row in sorted(directories.items())],
            'complete_tree_file_counts': counts, 'fixed_sibling_file_count': len(ADDITIONAL_FIXED_FILES),
            'total_original_files': len(files), 'observed_directories': len(directories),
            'total_original_file_bytes': total_bytes,
            'archive': archive_row, 'tar_plaintext': {'bytes': len(tar_raw), 'sha256': sha(tar_raw)},
            'archive_regular_members': len(files), 'collector_source': collector_row,
            'original_scope_checks': scope_proof,
            'same_instant_as_failure': False, 'atomic_filesystem_snapshot': False,
            'observation_scope': 'Later three complete P4 trees plus eight individually fixed sibling files, full9/bytes/child-name bookends',
            'mac_actor_py_in_this_archive': False,
            'originals_modified': False, 'phone_calls': 0, 'subprocesses': 0, 'network_calls': 0,
            'signals_sent': 0, 'process_census_performed': False,
            'case_pass': False, 'component_qualified': False, 'business_qualified': False}
        manifest_row = put_new(out_fd, OUT / 'ORIGINALS-MANIFEST.json', enc(manifest))
        after_copy = recheck_tree(files, directories, handles, started)
        check_directory(P4_BASE, parent_fd, parent_identity, full=False)
        check_directory(OUT, out_fd, out_identity, full=False)
        result = {'schema': 'hepta.root.external902-p4-originals-collection.v1',
            'state': 'EXTERNAL902_THREE_P4_TREES_AND_PINNED_SIBLING_ORIGINALS_ARCHIVED',
            'label': LABEL, 'nonce': NONCE, 'out': str(OUT),
            'complete_source_roots': FIXED_TREES, 'additional_fixed_files': ADDITIONAL_FIXED_FILES,
            'archive': archive_row, 'manifest': manifest_row, 'collector_source': collector_row,
            'complete_tree_file_counts': counts, 'fixed_sibling_file_count': len(ADDITIONAL_FIXED_FILES),
            'total_original_files': len(files), 'observed_directories': len(directories),
            'total_original_file_bytes': total_bytes,
            'after_copy_full_recheck': after_copy,
            'original_mac_sender_pid': 54589,
            'original_sender_join_or_EOF_retrofitted': False,
            'native_cleanup_or_boundary_publication_verified_here': False,
            'mac_actor_py_in_this_archive': False,
            'same_instant_as_failure': False, 'atomic_filesystem_snapshot': False,
            'originals_modified': False, 'phone_calls': 0, 'subprocesses': 0, 'network_calls': 0,
            'signals_sent': 0, 'process_census_performed': False,
            'case_pass': False, 'component_qualified': False, 'business_qualified': False,
            'automatic_retry': False, 'filesystem_or_compression_hard_deadline': False}
        result_row = put_new(out_fd, OUT / 'RESULT.json', enc(result))
        final_check = recheck_tree(files, directories, handles, started)
        check_directory(P4_BASE, parent_fd, parent_identity, full=False)
        check_directory(OUT, out_fd, out_identity, full=False)
        need(sorted(os.listdir(out_fd)) == ['COLLECTOR.original.py', 'EXTERNAL902-P4-ORIGINALS.tar.xz',
            'ORIGINALS-MANIFEST.json', 'RESULT.json'], 'new evidence output inventory differs')
        print(enc({'state': result['state'], 'result': result_row, 'archive': archive_row,
            'manifest': manifest_row, 'complete_tree_file_counts': counts,
            'fixed_sibling_file_count': len(ADDITIONAL_FIXED_FILES),
            'total_original_files': len(files), 'total_original_file_bytes': total_bytes,
            'last_full_recheck': final_check, 'original_unjoined_sender_pid': 54589,
            'original_sender_join_or_EOF_retrofitted': False, 'case_pass': False,
            'phone_calls': 0, 'subprocesses': 0, 'network_calls': 0,
            'same_instant_as_failure': False, 'atomic_filesystem_snapshot': False}).decode(), end='')
        return 0
    except BaseException as error:
        if out_fd is not None:
            try:
                put_new(out_fd, OUT / 'FAILED-OR-UNKNOWN.json', enc({
                    'state': 'EVIDENCE_COLLECTION_FAILED_OR_UNKNOWN_RETAIN_EXISTING_OUTPUTS',
                    'error_type': type(error).__name__, 'detail': str(error)[:2000],
                    'out': str(OUT), 'case_pass': False, 'automatic_retry': False,
                    'originals_modified': False, 'phone_calls': 0, 'subprocesses': 0,
                    'network_calls': 0, 'signals_sent': 0}))
            except BaseException:
                pass
        raise
    finally:
        if out_fd is not None:
            os.close(out_fd)
        if parent_fd is not None:
            os.close(parent_fd)
        for _, fd, _ in handles.values():
            os.close(fd)


if __name__ == '__main__':
    raise SystemExit(main())
