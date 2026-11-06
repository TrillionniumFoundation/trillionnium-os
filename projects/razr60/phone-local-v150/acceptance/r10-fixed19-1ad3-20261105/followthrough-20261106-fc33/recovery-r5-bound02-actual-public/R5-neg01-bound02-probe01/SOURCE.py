#!/usr/bin/env python3
"""Actual bound02 unstarted scope: complete read-only preservation, no recovery."""
import base64,errno,fcntl,hashlib,io,json,os,signal,stat,sys,tarfile,time,zlib
from pathlib import Path
INPUTS_RAW = b'{"android_home":"/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-bound02","archive_members":[{"bytes":2500,"relative_path":"LEASE.json","sha256":"d7aaa71acd3025aea4d193cf44301e8bd36ceef24fa9356dc55c40ab844c2814"},{"bytes":4695,"relative_path":"inputs/COMBINATION.json","sha256":"7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411"},{"bytes":29342,"relative_path":"inputs/PRIOR-BOUNDARY.original.json","sha256":"39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047"},{"bytes":2341,"relative_path":"inputs/SOURCE-SEAL.original.json","sha256":"b8ace9d8c6cd7f1a6dbeab83f20ccb3675dff76e47bc445c5d2c286eba58681a"},{"bytes":1493,"relative_path":"inputs/configuration.original.json","sha256":"5ff00467e8432d7119ba72a700ce07cb20f16555d3dc0c90de7cbfc388103f48"},{"bytes":15587,"relative_path":"inputs/production/action_ledger.py","sha256":"50620b2e27334b7cf311bd6b1c743d71c19c32887e5ed31a07fdf54dac0e7907"},{"bytes":22059,"relative_path":"inputs/production/daily_phone_local.py","sha256":"a16be75d5a47a86a7c0d222dc95e8b2373017b3291ce644864e2dd3b763447b8"},{"bytes":11439,"relative_path":"inputs/production/health_contracts.py","sha256":"00adea791c00eaac52f65716cb158ee73f38bdded96f1718578ec92f5091d32d"},{"bytes":15135,"relative_path":"inputs/production/ledger_round_evidence.py","sha256":"87d2b8731883dd06806a45851867332c568fe02deb2b9b8952094b86822e678d"},{"bytes":8251,"relative_path":"inputs/production/model_health.py","sha256":"105b401fbab1c151e890a3e6e4774322eb62a9e7799744b4d3cef01b6e1c0f80"},{"bytes":37375,"relative_path":"inputs/production/model_slot_cleanup.py","sha256":"9144bc864e245d63186f6b37760562e3b42554fdcc42ed792c9081761f315183"},{"bytes":10453,"relative_path":"inputs/production/phone_local_http_worker.py","sha256":"a1f1c94f2e78ced93cbde2113f508d756507249133f71c6dbe9a82a58a232d4d"},{"bytes":13927,"relative_path":"inputs/production/phone_local_tools.py","sha256":"2d0c9cc8f1ff0c643aab3daeef07c12e84541f1c2f0bfd13c8043c5c8fa58930"},{"bytes":55981,"relative_path":"inputs/production/phone_observation_tools.py","sha256":"4f95178996a2d7a604ae56eecd0f7725657222783f5cab5a7ff868f85a8cd086"},{"bytes":22825,"relative_path":"inputs/production/phone_task_guards.py","sha256":"87d88e0e9f93b31cf69bf0e4cdb9c62fd20e03c2192a0ffec621eb84c26bba86"},{"bytes":41618,"relative_path":"inputs/production/provider_codex_host.py","sha256":"0ea72f9e38307055ead790aa5828143c4ba431ae33c8e44e19c5893073ade5fa"},{"bytes":17730,"relative_path":"inputs/production/provider_openai_compatible.py","sha256":"337c83284fece94c0dd477a30029c63017b7eb00aab55a747b89b193823820bc"},{"bytes":70303,"relative_path":"inputs/production/provider_phone_local.py","sha256":"0c04bbd0f2d8f88a0795776a23a6cb34bf5f9a88aabc09e8aa3c3ff34c534bee"},{"bytes":9802,"relative_path":"inputs/production/retirement_recovery.py","sha256":"c1f5a77e32264f5f638f62f005f57c66fffeb60cf288ad036848ac4fceb74827"},{"bytes":23211,"relative_path":"inputs/production/task_postconditions.py","sha256":"d4984cce3e25609d0bc3ef97475edfe74d4795244722e654eb654df3b6e6ceb3"},{"bytes":10654,"relative_path":"inputs/service-inputs.original.json","sha256":"273db17098e5de6c67ded208e120e3910531ab1c7a778faa76824d453ddddd58"},{"bytes":317,"relative_path":"owner-request.txt","sha256":"82f65012bdb2e8081c2035601fc0aff06a90fc294e381abab7c97ad6960dae15"},{"bytes":57078,"relative_path":"package/MANIFEST.json","sha256":"990c726a1fff139761494cc19cf091deb269201f27ea947dda4a5833e3a72f2a"},{"bytes":1438,"relative_path":"package/reference/REVIEWED-PRODUCTION-PINS.json","sha256":"5fcfe9e0eb3c1dfaed39532bb727e3ea3829b39adbca4565f1b19300d4f7e07f"},{"bytes":664638,"relative_path":"package/reference/attempt05-AFTER-INVENTORY.original.json","sha256":"87103089914885fff5632781f18fbe36895ed181f01997eac6c3b49449b5579e"},{"bytes":164095,"relative_path":"package/reference/attempt05-CLOSURE.original.json","sha256":"d464bac786ef208d8fa0390587bd3bb7616a13985fb064716a209aa2394458f6"},{"bytes":4650,"relative_path":"package/reference/attempt05-SIDE-PROOF.original.json","sha256":"1bf6bca5ae5aaa5d5803b708070680e92d3f072f9541f38b09783787cfae7b9c"},{"bytes":18133,"relative_path":"package/reference/component_common_r5.py","sha256":"8ad9a3b17e7475555af7dd9a113025740447fcebdf0400d984d8a9e84accfb02"},{"bytes":13238,"relative_path":"package/reference/component_core.py","sha256":"705b982a46de0fd4427cd6a233687381c592ef74459f9818f3da15e20c03916f"},{"bytes":30647,"relative_path":"package/reference/component_once_r9.py","sha256":"1c27b548e42c91391e12db125c23608a2d5fb9e28ae2713df17c271bddc58fa2"},{"bytes":4116,"relative_path":"package/reference/decode_client_state.py","sha256":"a3e619926a4688ebfefd55ad1074cb386240f9828613781b7fd547bcf0c70073"},{"bytes":1031582,"relative_path":"package/reference/diag02-AFTER-INVENTORY.original.json","sha256":"10fe1e2d389cf8aa4928593abb207406ae63e84519339da25c722b03bee9c67d"},{"bytes":253127,"relative_path":"package/reference/diag02-CLOSURE.original.json","sha256":"e25d415963eabab1fdc08704623dec88cc3ad88b9a9c228072e1138d41f8b035"},{"bytes":8439,"relative_path":"package/reference/diag02-SIDE-PROOF.original.json","sha256":"a76283b76f1f12e08378662131b0375ffec95f1333d190deb3f1f90280dcc2bd"},{"bytes":53502,"relative_path":"package/reference/environment_parent_late_boundary_r6.py","sha256":"1fd24e0a6799ed3fb02014567764cce4c0de884e78ccd5b663e63fe69230041c"},{"bytes":28109,"relative_path":"package/reference/native_guard_session.py","sha256":"77dacc52468de95b68f30baafbb1cbf7dd7452c3d9ce652980dbb4af0ca62d8b"},{"bytes":6701,"relative_path":"package/reference/native_journal_audit.py","sha256":"da47d875addc32c0f7f30d178de95d8ebd956a6cb10b59813705feeb7811f0cf"},{"bytes":19740,"relative_path":"package/reference/non_native_attempt05.py","sha256":"a4ec44ac1f09fc7919dce17acf46e6db83ca468f58f53ad7622b520b557d04e4"},{"bytes":29504,"relative_path":"package/reference/non_native_diag02.py","sha256":"296f5e22485712fff6641082ab0ffdee78d2d2951bcb8f53a1da5f0c374c2de6"},{"bytes":35730,"relative_path":"package/reference/policy_parent_late_boundary_r4.py","sha256":"bcbe7d03567684ca23bd0985c14df49b021e1ac2e53e76dfda94262d7ad3516b"},{"bytes":62434,"relative_path":"package/reference/property_parent_late_boundary_r7.py","sha256":"3c710779e79870e4fefdedb8a24163118b2de814d7fcd3e97bb8971eec6113fd"},{"bytes":62662,"relative_path":"package/reference/retained_unstarted_stage_final02.py","sha256":"bc6faf1c7ae2b7e3d44be3d4fe19e4272073073f8df283397ef37c177ca25850"},{"bytes":40788,"relative_path":"package/reference/send_new_native_task_r5.py","sha256":"5ab04019e94adb989e9909ae3a9aa10db0689de62821ec549db8beb3ec4d0281"},{"bytes":153138,"relative_path":"package/reference/source_parent_late_boundary_r4.py","sha256":"27350db238c5ca31796af91c77b5c2fdb9d02b838d35140f759df907903d4fa4"},{"bytes":17390,"relative_path":"package/reference/tool_client_r6.py","sha256":"500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f"},{"bytes":107822,"relative_path":"package/source/close_component.py","sha256":"0249db62b262226dd7fa87f0829f25eb1353f8d5f254c60e37577ca4bf0c1268"},{"bytes":19138,"relative_path":"package/source/component_common.py","sha256":"1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab"},{"bytes":40451,"relative_path":"package/source/component_lifecycle.py","sha256":"99fd57b058e6e49ea4a8a9f7145641752acd3a4bc7727d7ba34710cb48aa8ae7"},{"bytes":39012,"relative_path":"package/source/component_listener.py","sha256":"6db4eb9f55bc3313b635bdd05584901706213a9d47ac2f48b81a28cdb91313ec"},{"bytes":27776,"relative_path":"package/source/component_snapshot.py","sha256":"1478e2f9c77a0e02145cb4b5172ad561f17cf3ea8668e96d56997547f209ea41"},{"bytes":181669,"relative_path":"package/source/late_boundary.py","sha256":"0a9f52cf8fb71177d0816f561cce279811a7182e986c12912d9431bde5997cda"},{"bytes":29110,"relative_path":"package/source/native_guard_session_r2.py","sha256":"f55cd1c25962d0cc1ccc76fc921f6bac116a670fbdf5779305efd6d3d00ef718"},{"bytes":4633,"relative_path":"package/source/native_proc_profile.py","sha256":"12719e58d2e3e1a1e86b8a6a9dc9587e37bfcb36c4c3b26b023138752bb3e67b"},{"bytes":14256,"relative_path":"package/source/prepare_component.py","sha256":"96bd29f1e98615f26ea43e2c6101a555c72eff7268ce318151a4ab1f667174f4"},{"bytes":18725,"relative_path":"package/source/root_fixture_once.py","sha256":"5d78ad21fede0044c6b4d7dd1def5df005008ed994116ea61332ed064abd1870"},{"bytes":39144,"relative_path":"package/source/root_fixture_originals.py","sha256":"e55b93e4d1adfa14819f626f9ba44a5ae6fcd0a9721b2db1c581617c9b1f7418"},{"bytes":10498,"relative_path":"package/source/run_root_fixture_phase.py","sha256":"bf65791c252d0b4d9416717ffca44fe43c9021211c2f2189be5553ab8967a6b2"},{"bytes":41080,"relative_path":"package/source/send_new_native_guard_task_r10_r4.py","sha256":"53a6e9149cf768211c3c8ba74d3c422f95d78f14efdb8751af1ac55d1a9225d5"},{"bytes":25040,"relative_path":"package/source/sender_native_guard_ready_r10_r4.py","sha256":"97b28afd910280bbdb7a1061218f4d72fc4b9024669b1aba10b0bfdb6caf13b2"},{"bytes":19085,"relative_path":"package/source/stage_component.py","sha256":"e87dcf806f66a87ffbf4cbdfb00bac9280fb220268a9f3ee5e17f53ee35f07b9"},{"bytes":18143,"relative_path":"package/source/witness_bundle.py","sha256":"8e8e1aa967ba9fd96d9bae80eb40c6322763ba1109b015b399e4c08ad14d5557"},{"bytes":680,"relative_path":"sender-contract.json","sha256":"ab9e0aa37fd1e9774494b982778124933ef03b8c7d26e9d884e3fa3353df49e4"}],"archive_path":"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-staging-r10-r1/root-r10-neg01-fc33-bound02.tar.gz","baseline":{"bytes":1345535,"metadata":[65086,159230,33152,0,0,1,1345535,1793954243803886896,1793954243803886896],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843/AFTER-INVENTORY.original.json","sha256":"4bd70b72d2a92a6c963912159d9e978fc681a35ddb30c03a2c741700bf47cde4"},"baseline_roots":["/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/evidence","/var/lib/trillionnium/owner-open/phone-local-v150/component-probe-r6/evidence","/var/lib/trillionnium/owner-open/phone-local-v150/client-receipts","/var/lib/trillionnium/owner-open/phone-local-v150/executor-r6","/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/health-contracts/bindings","/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/task-contracts/bindings","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03","/proc/1/root/data/local/tmp/hepta-native-guard-88d68d88130d3c74e6c950a6346357c1","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04","/proc/1/root/data/local/tmp/hepta-native-guard-c705647dd4ebb5d421be1041a9c41ca6","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05","/proc/1/root/data/local/tmp/hepta-native-guard-e4c3ccb0b2d706be3b7bf105ae772405","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06","/proc/1/root/data/local/tmp/hepta-native-guard-154588e3a15591a21ec18950d18e3ecd","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07","/proc/1/root/data/local/tmp/hepta-native-guard-16805e43f9787c44c262d5b6c6d8ed95","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08","/proc/1/root/data/local/tmp/hepta-native-guard-2b0b103ee6de7a422064b9571266bf5d","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01","/proc/1/root/data/local/tmp/hepta-native-guard-902e851c3ca1f90deab3d880ab993774","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag01/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag01","/proc/1/root/data/local/tmp/hepta-native-guard-6077fc8f045572edc4acfb13ed7e09a8","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag02/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag02","/proc/1/root/data/local/tmp/hepta-native-guard-8daaaad6a322963e87973613c1fac762","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-sides01/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-sides01","/proc/1/root/data/local/tmp/hepta-native-guard-82012c7447c5f35d97c832d1d9481860","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-a1055-v3stack01/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-a1055-v3stack01","/proc/1/root/data/local/tmp/hepta-native-guard-a493b853566d68099f7dbc0a124aff50","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-a1055-final02","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-a1055-final02/executor","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-a1055-final04/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-a1055-final04","/proc/1/root/data/local/tmp/hepta-native-guard-ac03e3864c1798742c472957b06ca843"],"boundary":{"bytes":29342,"metadata":[65086,154717,33152,0,0,1,29342,1793954246107886895,1793954246107886895],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843.json","sha256":"39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047"},"deletion_authorized":false,"expected_directories":["/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-bound02","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-bound02/claims","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-bound02/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-bound02/inputs","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-bound02/inputs/production","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-bound02/operator","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-bound02/package","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-bound02/package/reference","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-bound02/package/source"],"fixture":"/proc/1/root/data/local/tmp/hepta-native-guard-4fce1e327941e723a4f1d4c838acf684","historical_remote_PID_not_invented":true,"label":"root-r10-neg01-fc33-bound02","lease":{"android_journal":"/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-bound02/executor","boot_id":"f8019f83-20a7-4f18-bea1-51c980621e4d","case_id":"NEG-01","combination":{"bytes":4695,"sha256":"7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411"},"expires_unix_ms":1793995626355,"label":"root-r10-neg01-fc33-bound02","nonce":"4fce1e327941e723a4f1d4c838acf684","owner_request_sha256":"82f65012bdb2e8081c2035601fc0aff06a90fc294e381abab7c97ad6960dae15","package_sha256":"990c726a1fff139761494cc19cf091deb269201f27ea947dda4a5833e3a72f2a","prior_boundary":{"bytes":29342,"metadata":[65086,154717,33152,0,0,1,29342,1793954246107886895,1793954246107886895],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843.json","sha256":"39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047"},"retirement":{"bound_inputs":{"bytes":848888,"metadata":[65086,148812,33152,0,0,1,848888,0,1793807681115942806],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/module-r10-r1-retirement-code-r1/BOUND-INPUTS.json","sha256":"607f832e4f1b0904a67e1102c3653543961aa71e55aa7a309cd6911c6234ec61"},"disabled_flag":{"bytes":0,"metadata":[65086,154139,33152,0,0,1,0,1793807685267942804,1793807685267942804],"path":"/proc/1/root/data/adb/modules/trillionnium_hepta_phone_local_v150_r9_r2/disable","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},"preflight":{"bytes":703888,"metadata":[65086,154138,33152,0,0,1,703888,1793807685235942804,1793807685235942804],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/module-retire-r9-r2-for-r10-r1-01/PREFLIGHT.json","sha256":"5205cd79b2f117d775c5574c63110b33e9b55f7cb69f5e212e034b8c4e9c9254"},"probe":{"bytes":766658,"metadata":[65086,154037,33152,0,0,1,766658,0,1793807681127942806],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/module-r10-r1-retirement-code-r1/retirement_probe.py","sha256":"d1fe1478ee9699b5a1199aa4c2b96a2a405f7cafd0b5707071cfd2238dbe5df4"},"proof":{"bytes":37869,"metadata":[65086,151157,33152,0,0,1,37869,1793807690051942802,1793807690051942802],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/module-retire-r9-r2-for-r10-r1-01/RETIREMENT.json","sha256":"b139e096969f5a860f5e7cb9e3e988db3d0b2e868528dd4c38b8c9411df4fb90"}},"schema":"hepta.native-guard.lease.v1","selected_profile_id":"owner-open","selected_session_id":"session-ee897738-8fc2-4d3e-a916-5fe368b340ef"},"lease_sha256":"d7aaa71acd3025aea4d193cf44301e8bd36ceef24fa9356dc55c40ab844c2814","nonce":"4fce1e327941e723a4f1d4c838acf684","package_sha256":"990c726a1fff139761494cc19cf091deb269201f27ea947dda4a5833e3a72f2a","parent_paths":["/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-staging-r10-r1","/proc/1/root/data/local/tmp/hepta-phone-local-v150-r1","/proc/1/root/data/local/tmp"],"phone_home":"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-bound02","phone_scope_current_state_not_yet_observed":true,"preservation":{"BASELINE44.original.json":{"bytes":1345535,"metadata":[66306,39846838,33152,1000,1000,1,1345535,1793996358443897720,1793996358443897720],"path":"/home/alex/razr60-local-model-v150/fc33-neg01-bound02-probe-inputs01/BASELINE44.original.json","sha256":"4bd70b72d2a92a6c963912159d9e978fc681a35ddb30c03a2c741700bf47cde4"},"HOST-ORIGINALS.PRIVATE.json":{"bytes":403121,"metadata":[66306,39846836,33152,1000,1000,1,403121,1793996358441434661,1793996358441434661],"path":"/home/alex/razr60-local-model-v150/fc33-neg01-bound02-probe-inputs01/HOST-ORIGINALS.PRIVATE.json","sha256":"88b0e473da053e1387116e3d8ecd62db5f0b7316d7aebd9574b59a754c9e9969"},"SENDER-ORIGINALS.PRIVATE.json.gz":{"bytes":275964,"metadata":[66306,39846837,33152,1000,1000,1,275964,1793996358442294049,1793996358442294049],"path":"/home/alex/razr60-local-model-v150/fc33-neg01-bound02-probe-inputs01/SENDER-ORIGINALS.PRIVATE.json.gz","sha256":"a8f987d6886a405550050e0ade474971f7e4b81773b4f4d81eee8861237d41c9"},"STAGE-COMPLETE.original.json":{"bytes":36342,"metadata":[66306,39846835,33152,1000,1000,1,36342,1793996358440891193,1793996358440891193],"path":"/home/alex/razr60-local-model-v150/fc33-neg01-bound02-probe-inputs01/STAGE-COMPLETE.original.json","sha256":"b83628c0d23a200d2d3375a2ed309a12ed3d5a4c774bf29f4c8b0d2c8be679f6"},"component-inputs.tar.gz":{"bytes":808866,"metadata":[66306,39846833,33152,1000,1000,1,808866,1793996358428906795,1793996358428906795],"path":"/home/alex/razr60-local-model-v150/fc33-neg01-bound02-probe-inputs01/component-inputs.tar.gz","sha256":"a250f2505466f17eac1d20028661b8eb6750c912312934fdb8401476ed9205dc"},"stage_component.original.py":{"bytes":19085,"metadata":[66306,39846834,33152,1000,1000,1,19085,1793996358440359408,1793996358440359408],"path":"/home/alex/razr60-local-model-v150/fc33-neg01-bound02-probe-inputs01/stage_component.original.py","sha256":"e87dcf806f66a87ffbf4cbdfb00bac9280fb220268a9f3ee5e17f53ee35f07b9"}},"runtime_files":[{"bytes":1438,"path":"reference/REVIEWED-PRODUCTION-PINS.json","sha256":"5fcfe9e0eb3c1dfaed39532bb727e3ea3829b39adbca4565f1b19300d4f7e07f"},{"bytes":664638,"path":"reference/attempt05-AFTER-INVENTORY.original.json","sha256":"87103089914885fff5632781f18fbe36895ed181f01997eac6c3b49449b5579e"},{"bytes":164095,"path":"reference/attempt05-CLOSURE.original.json","sha256":"d464bac786ef208d8fa0390587bd3bb7616a13985fb064716a209aa2394458f6"},{"bytes":4650,"path":"reference/attempt05-SIDE-PROOF.original.json","sha256":"1bf6bca5ae5aaa5d5803b708070680e92d3f072f9541f38b09783787cfae7b9c"},{"bytes":18133,"path":"reference/component_common_r5.py","sha256":"8ad9a3b17e7475555af7dd9a113025740447fcebdf0400d984d8a9e84accfb02"},{"bytes":13238,"path":"reference/component_core.py","sha256":"705b982a46de0fd4427cd6a233687381c592ef74459f9818f3da15e20c03916f"},{"bytes":30647,"path":"reference/component_once_r9.py","sha256":"1c27b548e42c91391e12db125c23608a2d5fb9e28ae2713df17c271bddc58fa2"},{"bytes":4116,"path":"reference/decode_client_state.py","sha256":"a3e619926a4688ebfefd55ad1074cb386240f9828613781b7fd547bcf0c70073"},{"bytes":1031582,"path":"reference/diag02-AFTER-INVENTORY.original.json","sha256":"10fe1e2d389cf8aa4928593abb207406ae63e84519339da25c722b03bee9c67d"},{"bytes":253127,"path":"reference/diag02-CLOSURE.original.json","sha256":"e25d415963eabab1fdc08704623dec88cc3ad88b9a9c228072e1138d41f8b035"},{"bytes":8439,"path":"reference/diag02-SIDE-PROOF.original.json","sha256":"a76283b76f1f12e08378662131b0375ffec95f1333d190deb3f1f90280dcc2bd"},{"bytes":53502,"path":"reference/environment_parent_late_boundary_r6.py","sha256":"1fd24e0a6799ed3fb02014567764cce4c0de884e78ccd5b663e63fe69230041c"},{"bytes":28109,"path":"reference/native_guard_session.py","sha256":"77dacc52468de95b68f30baafbb1cbf7dd7452c3d9ce652980dbb4af0ca62d8b"},{"bytes":6701,"path":"reference/native_journal_audit.py","sha256":"da47d875addc32c0f7f30d178de95d8ebd956a6cb10b59813705feeb7811f0cf"},{"bytes":19740,"path":"reference/non_native_attempt05.py","sha256":"a4ec44ac1f09fc7919dce17acf46e6db83ca468f58f53ad7622b520b557d04e4"},{"bytes":29504,"path":"reference/non_native_diag02.py","sha256":"296f5e22485712fff6641082ab0ffdee78d2d2951bcb8f53a1da5f0c374c2de6"},{"bytes":35730,"path":"reference/policy_parent_late_boundary_r4.py","sha256":"bcbe7d03567684ca23bd0985c14df49b021e1ac2e53e76dfda94262d7ad3516b"},{"bytes":62434,"path":"reference/property_parent_late_boundary_r7.py","sha256":"3c710779e79870e4fefdedb8a24163118b2de814d7fcd3e97bb8971eec6113fd"},{"bytes":62662,"path":"reference/retained_unstarted_stage_final02.py","sha256":"bc6faf1c7ae2b7e3d44be3d4fe19e4272073073f8df283397ef37c177ca25850"},{"bytes":40788,"path":"reference/send_new_native_task_r5.py","sha256":"5ab04019e94adb989e9909ae3a9aa10db0689de62821ec549db8beb3ec4d0281"},{"bytes":153138,"path":"reference/source_parent_late_boundary_r4.py","sha256":"27350db238c5ca31796af91c77b5c2fdb9d02b838d35140f759df907903d4fa4"},{"bytes":17390,"path":"reference/tool_client_r6.py","sha256":"500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f"},{"bytes":107822,"path":"source/close_component.py","sha256":"0249db62b262226dd7fa87f0829f25eb1353f8d5f254c60e37577ca4bf0c1268"},{"bytes":19138,"path":"source/component_common.py","sha256":"1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab"},{"bytes":40451,"path":"source/component_lifecycle.py","sha256":"99fd57b058e6e49ea4a8a9f7145641752acd3a4bc7727d7ba34710cb48aa8ae7"},{"bytes":39012,"path":"source/component_listener.py","sha256":"6db4eb9f55bc3313b635bdd05584901706213a9d47ac2f48b81a28cdb91313ec"},{"bytes":27776,"path":"source/component_snapshot.py","sha256":"1478e2f9c77a0e02145cb4b5172ad561f17cf3ea8668e96d56997547f209ea41"},{"bytes":181669,"path":"source/late_boundary.py","sha256":"0a9f52cf8fb71177d0816f561cce279811a7182e986c12912d9431bde5997cda"},{"bytes":29110,"path":"source/native_guard_session_r2.py","sha256":"f55cd1c25962d0cc1ccc76fc921f6bac116a670fbdf5779305efd6d3d00ef718"},{"bytes":4633,"path":"source/native_proc_profile.py","sha256":"12719e58d2e3e1a1e86b8a6a9dc9587e37bfcb36c4c3b26b023138752bb3e67b"},{"bytes":14256,"path":"source/prepare_component.py","sha256":"96bd29f1e98615f26ea43e2c6101a555c72eff7268ce318151a4ab1f667174f4"},{"bytes":18725,"path":"source/root_fixture_once.py","sha256":"5d78ad21fede0044c6b4d7dd1def5df005008ed994116ea61332ed064abd1870"},{"bytes":39144,"path":"source/root_fixture_originals.py","sha256":"e55b93e4d1adfa14819f626f9ba44a5ae6fcd0a9721b2db1c581617c9b1f7418"},{"bytes":10498,"path":"source/run_root_fixture_phase.py","sha256":"bf65791c252d0b4d9416717ffca44fe43c9021211c2f2189be5553ab8967a6b2"},{"bytes":41080,"path":"source/send_new_native_guard_task_r10_r4.py","sha256":"53a6e9149cf768211c3c8ba74d3c422f95d78f14efdb8751af1ac55d1a9225d5"},{"bytes":25040,"path":"source/sender_native_guard_ready_r10_r4.py","sha256":"97b28afd910280bbdb7a1061218f4d72fc4b9024669b1aba10b0bfdb6caf13b2"},{"bytes":19085,"path":"source/stage_component.py","sha256":"e87dcf806f66a87ffbf4cbdfb00bac9280fb220268a9f3ee5e17f53ee35f07b9"},{"bytes":18143,"path":"source/witness_bundle.py","sha256":"8e8e1aa967ba9fd96d9bae80eb40c6322763ba1109b015b399e4c08ad14d5557"}],"schema":"hepta.fc33.bound02.unstarted-readonly-inputs.v1","sender_public_original":{"bytes":27864,"metadata":[66306,39846816,33152,1000,1000,1,27864,1793995557972161087,1793995557972161087],"path":"/home/alex/razr60-local-model-v150/fc33-neg01-bound02-sender-preservation01/PUBLIC-OBSERVATION.json","sha256":"79b261a4e6c65b747f983bda939d32ef3aed7a6be523f1d85db5796e8a67a1b2"},"sender_terminal_proof":{"bytes":757,"metadata":[66306,39846839,33152,1000,1000,1,757,1793996358451394921,1793996358451394921],"path":"/home/alex/razr60-local-model-v150/fc33-neg01-bound02-probe-inputs01/SENDER-TERMINAL-PROOF.json","sha256":"34f282b3c84948ac837c616c027960e5ea9aceddb2f6fb63ec554404e1101d6b"},"sender_xml":[{"bytes":9630,"command_source":{"bytes":11019,"metadata":[66306,38959374,33152,1000,1000,1,11019,1793995097105304692,1793995097105304692],"path":"/home/alex/codex-hepta-natural-root-r10-neg01-fc33-bound02-root-v150/INITIAL.json","sha256":"d1bae7b329e317e2293176114e6e58eee203e91e36d947463e0bc108cce79163"},"path":"/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg01-fc33-bound02-v150-1.xml","pin_basis":"exact UTF-8 recorded stdout suffix after one XML declaration","sequence":1,"sha256":"e14c0e88c04509d8c8407e398f07f1fda5d1df516fc70ab0a8555d37bca40129"},{"bytes":6490,"command_source":{"bytes":7537,"metadata":[66306,38958456,33152,1000,1000,1,7537,1793995099640929831,1793995099640929831],"path":"/home/alex/codex-hepta-natural-root-r10-neg01-fc33-bound02-root-v150/DRAFT.json","sha256":"b70e238f197a9f93a26bdd4b763e99ea5dc3d1ad5ba3bd9808de1a80a4a659d0"},"path":"/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg01-fc33-bound02-v150-2.xml","pin_basis":"exact UTF-8 recorded stdout suffix after one XML declaration","sequence":2,"sha256":"74b4a68dd9ce8108bb29a061325de4fcd457e4264907622c9f0cbbd5fc6eeeec"},{"bytes":20280,"command_source":{"bytes":22733,"metadata":[66306,38959378,33152,1000,1000,1,22733,1793995101871926386,1793995101871926386],"path":"/home/alex/codex-hepta-natural-root-r10-neg01-fc33-bound02-root-v150/CONNECT-MENU.json","sha256":"6727b7202799c1d5c20a7068241807156fa18861a0dd0f66a089f1214d4de077"},"path":"/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg01-fc33-bound02-v150-3.xml","pin_basis":"exact UTF-8 recorded stdout suffix after one XML declaration","sequence":3,"sha256":"af100e2502584c375063ef1bbb0d3f3c120a01730b20b5221b927022bb68e303"},{"bytes":8802,"command_source":{"bytes":10077,"metadata":[66306,38959377,33152,1000,1000,1,10077,1793995104594363076,1793995104594363076],"path":"/home/alex/codex-hepta-natural-root-r10-neg01-fc33-bound02-root-v150/CURRENT-CONNECTION.json","sha256":"7e07d4dabf05f42a2186e8a17430b38092b5e6c0826361892d9a258c35b2ca20"},"path":"/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg01-fc33-bound02-v150-4.xml","pin_basis":"exact UTF-8 recorded stdout suffix after one XML declaration","sequence":4,"sha256":"35a6a3028aca6ebc38e11c500f8a3f3e989bb6c99be9dcbf82907fd08235143f"},{"bytes":10751,"command_source":{"bytes":12254,"metadata":[66306,38959380,33152,1000,1000,1,12254,1793995106816995519,1793995106816995519],"path":"/home/alex/codex-hepta-natural-root-r10-neg01-fc33-bound02-root-v150/TASK-CONTROLS.json","sha256":"66a74072758423787361974d4fc48ce87e4f6e7a7023d771b36bf7357d390789"},"path":"/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg01-fc33-bound02-v150-5.xml","pin_basis":"exact UTF-8 recorded stdout suffix after one XML declaration","sequence":5,"sha256":"35cc404b028aa402c94061bdf997bd89c7ad47baf7579aac67ee5ee9dc74974d"},{"bytes":12872,"command_source":{"bytes":14258,"metadata":[66306,38959379,33152,1000,1000,1,14258,1793995110379821998,1793995110379821998],"path":"/home/alex/codex-hepta-natural-root-r10-neg01-fc33-bound02-root-v150/READBACK.json","sha256":"a4596c868eb4f067fffc185d8916e87621a24af72151545da77095ec8ce01530"},"path":"/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg01-fc33-bound02-v150-6.xml","pin_basis":"exact UTF-8 recorded stdout suffix after one XML declaration","sequence":6,"sha256":"637ede0bc4e7468e8646509ce727000375b26a07ea6c0f81c2482cb6859e9aab"},{"bytes":20280,"command_source":{"bytes":22733,"metadata":[66306,38959382,33152,1000,1000,1,22733,1793995112622090908,1793995112622090908],"path":"/home/alex/codex-hepta-natural-root-r10-neg01-fc33-bound02-root-v150/DETAILS-MENU.json","sha256":"7cac6f9d405ba6589cbdd9ddca0729ab5883210324ec5d215a3d043144b173bd"},"path":"/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg01-fc33-bound02-v150-7.xml","pin_basis":"exact UTF-8 recorded stdout suffix after one XML declaration","sequence":7,"sha256":"af100e2502584c375063ef1bbb0d3f3c120a01730b20b5221b927022bb68e303"},{"bytes":104139,"command_source":{"bytes":106067,"metadata":[66306,38959381,33152,1000,1000,1,106067,1793995115217610340,1793995115217610340],"path":"/home/alex/codex-hepta-natural-root-r10-neg01-fc33-bound02-root-v150/RAW-DETAILS.json","sha256":"c74bd1660be4b197a4680e10f0e6c81f3d791049c73683ce6e95175d8d8d6f4c"},"path":"/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg01-fc33-bound02-v150-8.xml","pin_basis":"exact UTF-8 recorded stdout suffix after one XML declaration","sequence":8,"sha256":"7e027582479ec5fc86fe8d8b5abb9da228feb25e7ed4195cb8a6cb8e6f23ec67"},{"bytes":104166,"command_source":{"bytes":106094,"metadata":[66306,38959372,33152,1000,1000,1,106094,1793995117703267597,1793995117703267597],"path":"/home/alex/codex-hepta-natural-root-r10-neg01-fc33-bound02-root-v150/CLOSE-DETAILS-0.json","sha256":"359754f5f549dab64dcb0e535339d4ed7a2d53658ac8684b8ce4164cfcb5fd10"},"path":"/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg01-fc33-bound02-v150-9.xml","pin_basis":"exact UTF-8 recorded stdout suffix after one XML declaration","sequence":9,"sha256":"a77ac94b58448f65d77ec54f4201a64048a17af155f55a109a03d2bdb8404383"},{"bytes":20280,"command_source":{"bytes":22737,"metadata":[66306,38959383,33152,1000,1000,1,22737,1793995119915690595,1793995119915690595],"path":"/home/alex/codex-hepta-natural-root-r10-neg01-fc33-bound02-root-v150/CLOSE-DETAILS-1.json","sha256":"d6ddebef87356e365ae2fe67ddc0d687c6bc8c091546d03e447b241651905a66"},"path":"/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg01-fc33-bound02-v150-10.xml","pin_basis":"exact UTF-8 recorded stdout suffix after one XML declaration","sequence":10,"sha256":"af100e2502584c375063ef1bbb0d3f3c120a01730b20b5221b927022bb68e303"},{"bytes":9944,"command_source":{"bytes":11337,"metadata":[66306,38959393,33152,1000,1000,1,11337,1793995122725738787,1793995122725738787],"path":"/home/alex/codex-hepta-natural-root-r10-neg01-fc33-bound02-root-v150/RESTORE-INITIAL.json","sha256":"14658e96c6bbe5a985e8c5ce400b420eb4b25d2f1bae4a674231811be02f8713"},"path":"/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg01-fc33-bound02-v150-11.xml","pin_basis":"exact UTF-8 recorded stdout suffix after one XML declaration","sequence":11,"sha256":"c0caad226d9083407bca5616b60cff449bda213c3fd7b912958844ccbf8a2213"}],"stage_complete":{"bytes":36342,"sha256":"b83628c0d23a200d2d3375a2ed309a12ed3d5a4c774bf29f4c8b0d2c8be679f6"},"stage_directory_identity":[{"metadata":[65086,159966,16832,0,0,2,3452,1793995093155871314,1793995093155871314],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-bound02","selinux":null},{"metadata":[65086,156230,16832,0,0,2,3452,1793995093163871314,1793995093163871314],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-bound02/inputs","selinux":null},{"metadata":[65086,161231,16832,0,0,2,3452,1793995093171871314,1793995093171871314],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-bound02/inputs/production","selinux":null},{"metadata":[65086,117921,16832,0,0,2,3452,1793995093207871314,1793995093207871314],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-bound02/package","selinux":null},{"metadata":[65086,113190,16832,0,0,2,3452,1793995093211871314,1793995093211871314],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-bound02/package/reference","selinux":null},{"metadata":[65086,136052,16832,0,0,2,3452,1793995093275871313,1793995093275871313],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-bound02/package/source","selinux":null},{"metadata":[65086,159979,16832,0,0,2,3452,1793995093295871313,1793995093295871313],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-bound02/claims","selinux":null},{"metadata":[65086,158344,16832,0,0,2,3452,1793995093295871313,1793995093295871313],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-bound02/operator","selinux":null},{"metadata":[65086,157974,16832,0,0,2,3452,1793995093295871313,1793995093295871313],"path":"/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-bound02/executor","selinux":"u:object_r:trillionnium_owner_open_phone_executor_data_file:s0"}],"transport":[{"bytes":808866,"metadata":[65086,158110,33152,0,0,1,808866,1793995029263871338,1793995029263871338],"owner":[0,0,[384]],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-staging-r10-r1/root-r10-neg01-fc33-bound02.tar.gz","sha256":"a250f2505466f17eac1d20028661b8eb6750c912312934fdb8401476ed9205dc"},{"bytes":808866,"owner":[2000,2000,[438]],"path":"/proc/1/root/data/local/tmp/hepta-phone-local-v150-r1/hepta-native-guard-root-r10-neg01-fc33-bound02.tar.gz","sha256":"a250f2505466f17eac1d20028661b8eb6750c912312934fdb8401476ed9205dc"},{"bytes":19085,"owner":[0,0,[384]],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-staging-r10-r1/root-r10-neg01-fc33-bound02.stage.py","sha256":"e87dcf806f66a87ffbf4cbdfb00bac9280fb220268a9f3ee5e17f53ee35f07b9"},{"bytes":19085,"owner":[2000,2000,[438]],"path":"/proc/1/root/data/local/tmp/hepta-phone-local-v150-r1/hepta-native-guard-root-r10-neg01-fc33-bound02.stage.py","sha256":"e87dcf806f66a87ffbf4cbdfb00bac9280fb220268a9f3ee5e17f53ee35f07b9"}]}\n'
INPUTS_SHA = '9f208e160b9f11de65e758b8f060991a2ea64427d50e851ea1a7b1522e13d11d'
BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
LABEL = 'root-r10-neg01-fc33-bound02'
NONCE = '4fce1e327941e723a4f1d4c838acf684'
LEASE_SHA = 'd7aaa71acd3025aea4d193cf44301e8bd36ceef24fa9356dc55c40ab844c2814'
PACKAGE_SHA = '990c726a1fff139761494cc19cf091deb269201f27ea947dda4a5833e3a72f2a'
BASELINE_FILE_BYTES = 44353573
MAX_FILE = 16777216
MAX_READ_BYTES = 167772160
MAX_BLOB_BYTES = 16777216
MAX_PRIVATE_TREE_BYTES = 16777216
MAX_PACKET = 33554432
MAX_OUTPUT = 8388608
MAX_SECONDS = 45
MAX_ENTRIES = 30000
STATE = None
INPUTS = json.loads(INPUTS_RAW)
assert hashlib.sha256(INPUTS_RAW).hexdigest() == INPUTS_SHA
SCOPE_HOME=Path(INPUTS["phone_home"])
ANDROID_HOME=Path(INPUTS["android_home"])
ANDROID=Path("/proc/1/root")
JOURNAL=ANDROID_HOME/"executor"
FIXTURE=Path(INPUTS["fixture"])

def need(ok, reason):
    if not ok:
        raise ValueError(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(',', ':'), allow_nan=False) + '\n').encode()

def strict(raw):
    def pairs(rows):
        out = {}
        for key, value in rows:
            need(key not in out, 'duplicate JSON key')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))

def metadata(s):
    return [getattr(s, name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
        'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')]

def parent_fd(path):
    """Walk directory FDs without links; only /proc/1/root is an explicit anchor.

    The GNU chroot cannot resolve that Android magic link lexically. Runtime
    startup separately binds the init PID namespace and the anchor inode.
    """
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and 2 <= len(path.parts) <= 64,
         'bounded absolute path required')
    if path.parts[:4] == ('/', 'proc', '1', 'root'):
        fd = os.open(ANDROID, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        parts = path.parts[4:]
    else:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        parts = path.parts[1:]
    need(parts, 'file path required')
    try:
        for name in parts[:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = child
        return fd, parts[-1]
    except BaseException:
        os.close(fd); raise

def stat_identity(raw, pid, *, census=False):
    need(type(census) is bool, 'explicit proc census mode required')
    head, tail = raw.rsplit(b') ', 1); fields = tail.split()
    need(head.startswith(str(pid).encode() + b' (') and len(fields) >= 20, 'proc stat shape')
    row = {'pid': pid, 'state': fields[0].decode(), 'ppid': int(fields[1]),
           'pgid': int(fields[2]), 'sid': int(fields[3]), 'start_ticks': int(fields[19])}
    if census:
        # A valid early process can start in tick zero. It still participates in
        # exact generation and PGID/SID membership checks; zero is not absence.
        need(row['start_ticks'] >= 0, 'proc census start ticks negative')
    else:
        need(row['start_ticks'] > 0 or (pid == 1 and row['start_ticks'] == 0), 'proc generation absent')
    return row

def check_time():
    need(time.monotonic() < STATE['deadline'], 'cause capture total deadline')

def read_fd(fd, maximum):
    check_time()
    need(type(maximum) is int and 0 <= maximum <= MAX_FILE, 'per-file read budget')
    chunks = []
    count = 0
    while True:
        check_time()
        remaining = MAX_READ_BYTES - STATE['read_bytes']
        need(remaining > 0, 'whole capture read budget exhausted before confirmed EOF')
        part = os.read(fd, min(65536, maximum + 1 - count, remaining))
        if not part:
            break
        chunks.append(part)
        count += len(part)
        STATE['read_bytes'] += len(part)
        need(STATE['read_bytes'] <= MAX_READ_BYTES, 'whole capture file-read byte budget')
        need(count <= maximum, 'complete original exceeds read bound')
    return b''.join(chunks)

def blob(raw):
    return {'bytes': len(raw), 'sha256': sha(raw), 'base64': base64.b64encode(raw).decode()}

def absent_or_error(path, error):
    row = {'path': str(path), 'observed_monotonic_ns': time.monotonic_ns(),
           'exception_type': type(error).__name__, 'errno': getattr(error, 'errno', None)}
    if isinstance(error, OSError) and error.errno == errno.ENOENT:
        row.update(state='OBSERVED_ENOENT', no_effect_inferred=False)
    else:
        row.update(state='READ_ERROR_UNKNOWN', detail=str(error)[:1024])
        STATE['errors'].append(dict(row))
    return row

def directory(path):
    check_time()
    parent = fd = None
    partial = {'path': str(path)}
    try:
        parent, name = parent_fd(path)
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(fd)
        partial['metadata_before'] = metadata(before)
        label = os.getxattr(fd, 'security.selinux')
        partial['selinux_raw_b64'] = base64.b64encode(label).decode()
        names = sorted(os.listdir(fd))
        partial['names'] = names
        need(len(names) <= 20000, 'cause directory entry count bound')
        after = os.fstat(fd)
        partial['metadata_after'] = metadata(after)
        need(metadata(before) == metadata(after) == metadata(os.stat(name, dir_fd=parent, follow_symlinks=False))
             and os.getxattr(fd, 'security.selinux') == label, 'cause directory changed within listing')
        return {'state': 'COMPLETE_DIRECTORY_LISTING', 'path': str(path), 'metadata': metadata(before),
                'names': names, 'selinux_raw_b64': base64.b64encode(label).decode(),
                'observed_monotonic_ns': time.monotonic_ns()}
    except (OSError, ValueError) as error:
        result = absent_or_error(path, error)
        if 'metadata_before' in partial:
            result['partial_directory_observation'] = partial
            result['stable_directory_qualified'] = False
        return result
    finally:
        if fd is not None:
            os.close(fd)
        if parent is not None:
            os.close(parent)

def proc_bytes(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        return read_fd(fd, maximum)
    finally:
        os.close(fd)

def original(path, maximum, *, expected=None, owner=None, preserve=True):
    """One complete no-follow read; byte/full9/label bookends stay mandatory."""
    check_time()
    parent = fd = None
    path = str(path)
    started = time.monotonic_ns()
    try:
        parent, name = parent_fd(path)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 <= before.st_size <= maximum <= MAX_FILE, 'bounded regular single-link original: '+path)
        if owner is not None:
            uid, gid, modes = owner
            need(before.st_uid == uid and before.st_gid == gid and stat.S_IMODE(before.st_mode) in modes,
                 'original ownership/mode: '+path)
        label = os.getxattr(fd, 'security.selinux')
        raw = read_fd(fd, maximum)
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        need(len(raw) == before.st_size and metadata(before) == metadata(after) == metadata(named)
             and os.getxattr(fd, 'security.selinux') == label, 'original full read raced: '+path)
        second, leaf = parent_fd(path)
        try:
            need(leaf == name and metadata(os.stat(leaf, dir_fd=second, follow_symlinks=False)) == metadata(before),
                 'original canonical path changed: '+path)
        finally:
            os.close(second)
        row = {'kind':'file', 'path':path, 'metadata':metadata(before), 'bytes':len(raw), 'sha256':sha(raw),
               'selinux_raw_b64':base64.b64encode(label).decode()}
        if expected is not None:
            for key in ('bytes','sha256','metadata','selinux_raw_b64'):
                if key in expected:
                    need(row[key] == expected[key], 'pinned original differs '+key+': '+path)
        if preserve:
            add_blob(raw)
        STATE['complete_file_reads'] += 1
        STATE['last_complete_read'] = {'path':path, 'bytes':len(raw), 'sha256':sha(raw)}
        return row, raw
    finally:
        if fd is not None:
            os.close(fd)
        if parent is not None:
            os.close(parent)

def add_blob(raw):
    digest = sha(raw)
    previous = STATE['blobs'].get(digest)
    if previous is not None:
        need(previous['bytes'] == len(raw) and base64.b64decode(previous['base64'],validate=True) == raw,
             'original hash collision')
        return digest
    need(STATE['blob_bytes'] + len(raw) <= MAX_BLOB_BYTES, 'complete private original output budget')
    STATE['blobs'][digest] = {'bytes':len(raw), 'base64':base64.b64encode(raw).decode()}
    STATE['blob_bytes'] += len(raw)
    return digest

def project_directory(row):
    need(row['state'] == 'COMPLETE_DIRECTORY_LISTING', 'complete directory required: '+row['path'])
    return {k:row[k] for k in ('path','metadata','names','selinux_raw_b64')}

def exact_absence(path):
    """Fresh ENOENT using a held and independently reopened parent."""
    parent, name = parent_fd(path)
    try:
        before = os.fstat(parent)
        label = os.getxattr(parent, 'security.selinux')
        for _ in range(2):
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except OSError as error:
                need(error.errno == errno.ENOENT, 'absence is unknown: '+str(path))
            else:
                need(False, 'expected absent original is present: '+str(path))
        after = os.fstat(parent)
        need(metadata(before) == metadata(after) and os.getxattr(parent,'security.selinux') == label,
             'absence parent changed: '+str(path))
        second, leaf = parent_fd(path)
        try:
            need(leaf == name and metadata(os.fstat(second)) == metadata(before)
                 and os.getxattr(second,'security.selinux') == label, 'absence canonical parent changed')
            try:
                os.stat(leaf, dir_fd=second, follow_symlinks=False)
            except OSError as error:
                need(error.errno == errno.ENOENT, 'second absence is unknown')
            else:
                need(False, 'absent original appeared')
        finally:
            os.close(second)
        return {'kind':'absent','path':str(path),'absence':'ENOENT','parent_metadata':metadata(before),
                'parent_selinux_raw_b64':base64.b64encode(label).decode(),
                'observed_monotonic_ns':time.monotonic_ns(),'no_effect_inferred':False}
    finally:
        os.close(parent)

def tree(roots, *, preserve, absent_fixtures):
    """Complete recursive listing and bytes, never glob-based selective evidence."""
    result = {}
    byte_count = 0
    fixtures = set(absent_fixtures)
    for root in roots:
        need(root not in result, 'duplicate tree root')
        parent, name = parent_fd(root)
        try:
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except OSError as error:
                need(error.errno == errno.ENOENT and root in fixtures, 'tree root missing/unknown: '+root)
                result[root] = exact_absence(root)
                continue
        finally:
            os.close(parent)
        stack = [root]
        while stack:
            check_time()
            path = stack.pop()
            need(path not in result and len(result) < MAX_ENTRIES, 'tree entry duplicate/budget')
            parent, name = parent_fd(path)
            try:
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            finally:
                os.close(parent)
            fixture = any(path == p or path.startswith(p+'/') for p in fixtures)
            owner = (2000,2000,(0o700,0o600,0o400)) if fixture else (0,0,(0o700,0o600))
            if preserve:
                need(info.st_uid == owner[0] and info.st_gid == owner[1]
                     and stat.S_IMODE(info.st_mode) in owner[2], 'tree private ownership/mode: '+path)
            if stat.S_ISDIR(info.st_mode):
                row = project_directory(directory(path))
                need(metadata(info) == row['metadata'], 'tree directory identity raced')
                row['kind'] = 'directory'
                need(all(type(n) is str and n not in ('.','..') and '/' not in n and '\0' not in n
                         for n in row['names']), 'directory child grammar')
                stack.extend(path+'/'+n for n in reversed(row['names']))
            else:
                need(stat.S_ISREG(info.st_mode), 'special/link tree member: '+path)
                row, _raw = original(path, MAX_FILE, owner=owner if preserve else None, preserve=preserve)
                need(metadata(info) == row['metadata'], 'tree file identity raced')
                byte_count += row['bytes']
                need(byte_count <= (MAX_PRIVATE_TREE_BYTES if preserve else BASELINE_FILE_BYTES), 'tree byte budget')
            result[path] = row
        # Every directory is re-opened after its entire descendants have been read.
        for path,row in list(result.items()):
            if (path == root or path.startswith(root+'/')) and row['kind'] == 'directory':
                need(project_directory(directory(path)) == {k:row[k] for k in ('path','metadata','names','selinux_raw_b64')},
                     'directory bookend changed: '+path)
    return {'roots':list(roots),'entries':result,'file_bytes_hashed':byte_count}

def legacy_projection(observed):
    rows = {}
    for path,row in observed['entries'].items():
        if row['kind'] == 'absent':
            rows[path] = {'kind':'absent','absence':'ENOENT'}
        elif row['kind'] == 'directory':
            rows[path] = {k:row[k] for k in ('kind','metadata','names')}
        else:
            rows[path] = {k:row[k] for k in ('kind','metadata','bytes','sha256')}
    return rows

def stable_tree_projection(observed):
    # Only the measurement time of a proved ENOENT is excluded. Full parent
    # metadata, label and every present file/directory field remain exact.
    rows = {p:({k:v for k,v in r.items() if k != 'observed_monotonic_ns'}
               if r['kind'] == 'absent' else r) for p,r in observed['entries'].items()}
    return {'roots':observed['roots'],'entries':rows,'file_bytes_hashed':observed['file_bytes_hashed']}

def compare_baseline(observed, baseline):
    need(observed['roots'] == baseline['roots'] and legacy_projection(observed) == baseline['entries']
         and observed['file_bytes_hashed'] == baseline['file_bytes_hashed'], 'original44 full inventory differs')

def archive_members(raw):
    need(0<len(raw)<=8*1024*1024,'compressed archive size bound')
    decoder=zlib.decompressobj(31);plain=decoder.decompress(raw,16*1024*1024+1)
    need(len(plain)<=16*1024*1024 and decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data,
         'gzip archive is oversized, incomplete or concatenated')
    files={}
    with tarfile.open(fileobj=io.BytesIO(plain),mode='r:') as archive:
        for row in archive:
            p=Path(row.name)
            need(len(files)<80 and str(p)==row.name and not p.is_absolute() and '..' not in p.parts
                 and '\0' not in row.name and '\\' not in row.name and row.name not in files
                 and row.isreg() and not row.pax_headers and row.uid==row.gid==0 and row.mode==0o600
                 and row.mtime==0 and 0<=row.size<=8*1024*1024,'archive member type/path/metadata/size bound')
            source=archive.extractfile(row);need(source is not None,'archive original absent')
            data=source.read(row.size+1);need(len(data)==row.size,'archive member incomplete')
            files[row.name]=data
    need(sum(map(len,files.values()))<=8*1024*1024,'archive content byte bound')
    canonical=io.BytesIO()
    with tarfile.open(fileobj=canonical,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        for name,data in sorted(files.items()):
            row=tarfile.TarInfo(name);row.mode=0o600;row.uid=row.gid=0;row.mtime=0;row.size=len(data)
            archive.addfile(row,io.BytesIO(data))
    need(plain==canonical.getvalue(),'noncanonical tar metadata/order/trailing content')
    return files

"""Exactly one previously staged, never launched scope. Read only, no closure."""
PROBE_STATE=None

def acquire_unstarted_locks(baseline):
    aliases={p:r for p,r in baseline['entries'].items() if r['kind']=='file' and (p.rsplit('/',1)[-1]=='lock' or p.endswith('.lock'))}
    need(len(aliases)==26 and len({tuple(r['metadata'][:2]) for r in aliases.values()})==14,'original44 exact26 aliases/14 inode groups')
    groups={};acquired=[];observations=[]
    try:
        for path,expected in sorted(aliases.items(),key=lambda x:(x[1]['metadata'][0],x[1]['metadata'][1],x[0])):
            row,_=original(path,65536,expected=expected,owner=(0,0,(0o600,)),preserve=False)
            parent,name=parent_fd(path)
            try:fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            finally:os.close(parent)
            try:
                need(metadata(os.fstat(fd))==row['metadata'] and base64.b64encode(os.getxattr(fd,'security.selinux')).decode()==row['selinux_raw_b64'],'lock descriptor changed')
                key=tuple(row['metadata'][:2])
                if key not in groups:
                    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);groups[key]=fd;acquired.append(fd);fd=None
                else:need(metadata(os.fstat(groups[key]))==row['metadata'],'lock aliases differ')
                observations.append(row)
            finally:
                if fd is not None:os.close(fd)
        need(len(groups)==14 and len(observations)==26,'exact original14 lock set, no new scope lock exists')
        STATE['lock_fds']=acquired
        return {'alias_count':26,'inode_group_count':14,'lock_mode':'LOCK_EX|LOCK_NB on existing O_RDONLY descriptors','aliases':observations,'lock_files_created':0,'held_through_both_windows':True}
    except BaseException:
        for fd in reversed(acquired):os.close(fd)
        raise

def root_identity():
    need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'actual Root read-only collector credentials')
    boot=proc_bytes('/proc/sys/kernel/random/boot_id',128).decode().strip();domain=proc_bytes('/proc/self/attr/current',4096)
    need(boot==BOOT and domain.rstrip(b'\0\n')==b'u:r:magisk:s0','same boot and Root domain')
    raw=proc_bytes('/proc/1/stat',8192);init=stat_identity(raw,1,census=True);gnu=os.stat('/');android=os.stat(ANDROID)
    need(init['pid']==1 and init['start_ticks']==0 and (gnu.st_dev,gnu.st_ino)!=(android.st_dev,android.st_ino),'actual native init and distinct GNU/Android anchors')
    return {'boot_id':boot,'domain_raw_b64':base64.b64encode(domain).decode(),'init':init,'init_stat_original':blob(raw),'gnu_root_metadata':metadata(gnu),'android_root_metadata':metadata(android),'collector_pid':os.getpid()}

def canonical_private(path):
    a=str(ANDROID_HOME);g=str(SCOPE_HOME)
    return g+path[len(a):] if path==a or path.startswith(a+'/') else path

def parents():
    rows=[project_directory(directory(p)) for p in INPUTS['parent_paths']]
    need(len(rows)==5 and {k:rows[0][k] for k in ('metadata','names','selinux_raw_b64')}=={k:rows[1][k] for k in ('metadata','names','selinux_raw_b64')},'complete shared GNU/Android parent aliases')
    need(LABEL in rows[0]['names'] and rows[0]['metadata'][3:5]==[0,0] and stat.S_IMODE(rows[0]['metadata'][2])==0o700,'exact staged home in actual private shared parent')
    return rows

def home_aliases():
    rows=[project_directory(directory(p)) for p in (str(SCOPE_HOME),str(ANDROID_HOME))]
    need({k:rows[0][k] for k in ('metadata','names','selinux_raw_b64')}=={k:rows[1][k] for k in ('metadata','names','selinux_raw_b64')},'complete staged home aliases')
    return rows

def exact_archive(raw):
    files=archive_members(raw)
    need(len(files)==62 and [{'relative_path':n,'bytes':len(b),'sha256':sha(b)} for n,b in sorted(files.items())]==INPUTS['archive_members'],'all62 immutable original members')
    lease_raw=files['LEASE.json'];manifest_raw=files['package/MANIFEST.json'];lease=strict(lease_raw);manifest=strict(manifest_raw)
    need(sha(lease_raw)==LEASE_SHA and lease==INPUTS['lease'] and sha(manifest_raw)==PACKAGE_SHA and manifest['files']==INPUTS['runtime_files'] and len(manifest['files'])==38,'exact original lease and runtime38')
    expected={'LEASE.json','owner-request.txt','sender-contract.json','package/MANIFEST.json','inputs/COMBINATION.json','inputs/SOURCE-SEAL.original.json','inputs/configuration.original.json','inputs/service-inputs.original.json','inputs/PRIOR-BOUNDARY.original.json'}
    expected.update('package/'+r['path'] for r in manifest['files']);reviewed=strict(files['package/reference/REVIEWED-PRODUCTION-PINS.json'])
    need(len(reviewed)==15,'exact original reviewed15 production members');expected.update('inputs/production/'+n for n in reviewed)
    need(set(files)==expected,'complete declared stage archive namespace')
    for r in manifest['files']:need(len(files['package/'+r['path']])==r['bytes'] and sha(files['package/'+r['path']])==r['sha256'],'each runtime byte pin')
    for name,h in reviewed.items():need('/' not in name and name.endswith('.py') and sha(files['inputs/production/'+name])==h,'each production source byte pin')
    need(lease['label']==LABEL and lease['nonce']==NONCE and lease['boot_id']==BOOT and lease['package_sha256']==PACKAGE_SHA and lease['prior_boundary']==INPUTS['boundary'],'exact original unstarted scope')
    return files

def private_shape(observed,files):
    rows=observed['entries'];canonical={};aliases={}
    for path,row in rows.items():
        if path==str(FIXTURE):continue
        p=canonical_private(path);need(p==str(SCOPE_HOME) or p.startswith(str(SCOPE_HOME)+'/'),'only exact owned scope in private tree')
        value={k:v for k,v in row.items() if k!='path'}
        if p in canonical:need(canonical[p]==value,'all private alias content/full9/label fields agree')
        canonical[p]=value;aliases.setdefault(p,[]).append(path)
    expected_files={str(SCOPE_HOME/n) for n in files}|{str(SCOPE_HOME/'STAGE-COMPLETE.json')}
    actual_files={p for p,r in canonical.items() if r['kind']=='file'};actual_dirs={p for p,r in canonical.items() if r['kind']=='directory'}
    need(actual_files==expected_files and len(actual_files)==63 and actual_dirs==set(INPUTS['expected_directories']) and len(actual_dirs)==9,'complete current tree is exact63 files and9 unique directories')
    members=[]
    for name,raw in sorted(files.items()):
        path=str(SCOPE_HOME/name);row=rows[path]
        need(row['kind']=='file' and row['bytes']==len(raw) and row['sha256']==sha(raw) and base64.b64decode(STATE['blobs'][row['sha256']]['base64'],validate=True)==raw,'full current stage original differs '+name)
        members.append({'relative_path':name,'path':path,'bytes':len(raw),'sha256':sha(raw),'metadata':row['metadata']})
    stage_row=rows[str(SCOPE_HOME/'STAGE-COMPLETE.json')]
    need(all(stage_row[k]==INPUTS['stage_complete'][k] for k in ('bytes','sha256')),'actual successful STAGE-COMPLETE original')
    stage=strict(base64.b64decode(STATE['blobs'][stage_row['sha256']]['base64'],validate=True))
    need(stage['state']=='PRIVATE_COMPONENT_INPUTS_STAGED_NO_ROLES' and stage['members']==62 and stage['lease_sha256']==LEASE_SHA and stage['package_sha256']==PACKAGE_SHA and stage['archive_sha256']==INPUTS['transport'][0]['sha256'] and stage['service_launches']==stage['model_requests']==stage['native_tasks']==0,'original stage no-role result exact scope')
    need(stage['created_directories']==INPUTS['stage_directory_identity'],'same original created-directory identities')
    for created in stage['created_directories']:
        path=canonical_private(created['path']);row=canonical[path]
        need(row['metadata'][:5]==created['metadata'][:5],'exact originally created directory identity/mode/owner')
        if created['selinux'] is not None:need(base64.b64decode(row['selinux_raw_b64'],validate=True).rstrip(b'\0').decode()==created['selinux'],'original explicit directory label')
    for name in ('claims','operator','executor'):
        need(rows[str(SCOPE_HOME/name)]['names']==[],'unstarted scope requires empty '+name)
    fixture=rows[str(FIXTURE)];need(fixture['kind']=='absent' and fixture['absence']=='ENOENT','exact never-created fixture currently absent')
    need(type(INPUTS['lease']['expires_unix_ms']) is int and 0<INPUTS['lease']['expires_unix_ms']<time.time_ns()//1000000,'original scope lease expired, no extension')
    return {'archive_member_count':62,'runtime_file_count':38,'current_home_file_count':63,'unique_private_directory_count':9,'all_current_archive_bytes_exact':True,'all_runtime_bytes_exact':True,'members':members,'canonical_aliases':aliases,'claims_operator_executor_empty':True,'original_lease_expired':True,'process_liveness_measured':False,'role_generation_invented':False}

def capture_window(index,baseline,first=None):
    window={'index':index,'started_monotonic_ns':time.monotonic_ns(),'parents_before':parents(),'home_aliases_before':home_aliases(),'transport':[],'xml':[],'private':None,'baseline':None,'stage_members':None,'pinned_input_bookends':[]}
    PROBE_STATE['windows'].append(window)
    archive_raw=None
    for i,pin in enumerate(INPUTS['transport']):
        owner=pin['owner'];expected=pin if first is None else first['transport'][i]
        row,raw=original(pin['path'],MAX_FILE,expected=expected,owner=(owner[0],owner[1],tuple(owner[2])))
        need(row['bytes']==pin['bytes'] and row['sha256']==pin['sha256'],'same original transport bytes');window['transport'].append(row)
        if pin['path']==INPUTS['archive_path']:archive_raw=raw
    need(archive_raw is not None,'exact GNU archive original');files=exact_archive(archive_raw)
    for i,pin in enumerate(INPUTS['sender_xml']):
        expected=pin if first is None else first['xml'][i]
        row,_=original(pin['path'],262144,expected=expected,owner=(2000,2000,(0o666,)))
        need(row['bytes']==pin['bytes'] and row['sha256']==pin['sha256'],'exact original sender XML bytes');window['xml'].append(row)
    private=tree([str(SCOPE_HOME),str(JOURNAL),str(FIXTURE)],preserve=True,absent_fixtures=[str(FIXTURE)])
    window['private']=private;window['stage_members']=private_shape(private,files)
    fixtures=[p for p in baseline['roots'] if p.startswith('/proc/1/root/data/local/tmp/hepta-native-guard-')]
    current=tree(baseline['roots'],preserve=False,absent_fixtures=fixtures);compare_baseline(current,baseline);window['baseline']=current
    window['parents_after']=parents();window['home_aliases_after']=home_aliases()
    need(window['parents_before']==window['parents_after'] and window['home_aliases_before']==window['home_aliases_after'],'complete parent/home alias bookends')
    absence=private['entries'][str(FIXTURE)];tmp=window['parents_after'][-1]
    need(absence['parent_metadata']==tmp['metadata'] and absence['parent_selinux_raw_b64']==tmp['selinux_raw_b64'],'same current complete tmp parent for fixture absence and XML')
    for pin in (INPUTS['baseline'],INPUTS['boundary']):
        row,_=original(pin['path'],MAX_FILE,expected=pin,owner=(0,0,(0o600,)))
        window['pinned_input_bookends'].append(row)
    if first is not None:
        for field in ('parents_before','parents_after','home_aliases_before','home_aliases_after','transport','xml','stage_members','pinned_input_bookends'):need(first[field]==window[field],'complete two-window field differs '+field)
        need(stable_tree_projection(first['private'])==stable_tree_projection(private),'private complete byte/full9/label tree differs between windows')
        need(stable_tree_projection(first['baseline'])==stable_tree_projection(current),'original44 complete byte/full9/label tree differs between windows')
    window['finished_monotonic_ns']=time.monotonic_ns()
    return window

def capture_bound02():
    PROBE_STATE['collector_identity']=root_identity()
    row,raw=original(INPUTS['baseline']['path'],MAX_FILE,expected=INPUTS['baseline'],owner=(0,0,(0o600,)))
    baseline=strict(raw);need(baseline['schema']=='hepta.native-guard.complete-inventory.v1' and baseline['roots']==INPUTS['baseline_roots'] and len(baseline['roots'])==44 and len(baseline['entries'])==3823 and baseline['file_bytes_hashed']==BASELINE_FILE_BYTES,'exact original44 complete inventory')
    PROBE_STATE['baseline_original']=row
    row,_=original(INPUTS['boundary']['path'],MAX_FILE,expected=INPUTS['boundary'],owner=(0,0,(0o600,)));PROBE_STATE['boundary_original']=row
    PROBE_STATE['locks']=acquire_unstarted_locks(baseline)
    first=capture_window(0,baseline);capture_window(1,baseline,first)
    need(not STATE['errors'] and proc_bytes('/proc/sys/kernel/random/boot_id',128).decode().strip()==BOOT,'same boot and no unknown observations')

def probe_main():
    global STATE,PROBE_STATE
    started=time.monotonic();initial_fds=sorted(os.listdir('/proc/self/fd'))
    STATE={'deadline':started+MAX_SECONDS,'read_bytes':0,'complete_file_reads':0,'errors':[],'evidence':{},'blobs':{},'blob_bytes':0,'lock_fds':[],'last_complete_read':None}
    PROBE_STATE={'schema':'hepta.fc33.bound02.unstarted-readonly.v1','state':'PARTIAL_READONLY_CAPTURE_UNKNOWN_REMAINS','scope':{'label':LABEL,'nonce':NONCE,'lease_sha256':LEASE_SHA,'runtime_sha256':PACKAGE_SHA,'boot_id':BOOT},'inputs_sha256':INPUTS_SHA,'windows':[],'terminal_error':None,'file_writes':0,'file_deletes':0,'signals_to_other_processes':0,'ui_calls':0,'model_requests':0,'native_dispatches':0,'endpoint_connections':0,'target_programs_imported_or_executed':0,'process_liveness_measured':False,'role_generation_invented':False,'scope_closure':False,'deletion_authorized':False,'component_qualified':False,'business_qualified':False,'automatic_retry':False,'historical_native_effect_count_inferred':None,'private_request_and_XML_original_bodies_do_not_publish':True}
    previous=signal.getsignal(signal.SIGALRM);need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'existing timer cannot be replaced')
    def expired(_s,_f):raise TimeoutError('bounded unstarted-scope read-only deadline')
    signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,MAX_SECONDS);rc=0
    try:
        try:capture_bound02();PROBE_STATE['state']='COMPLETE_FRESH_UNSTARTED_SCOPE_CAPTURE_NO_CLOSURE'
        except BaseException as exc:rc=1;PROBE_STATE['terminal_error']={'type':type(exc).__name__,'detail':str(exc)[:1024]}
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous);errors=[]
        for fd in reversed(STATE['lock_fds']):
            try:os.close(fd)
            except OSError as exc:errors.append({'errno':exc.errno})
        PROBE_STATE['resources']={'initial_fd_names':initial_fds,'final_fd_names':sorted(os.listdir('/proc/self/fd')),'closed_lock_descriptors':len(STATE['lock_fds']),'close_errors':errors}
        if errors or PROBE_STATE['resources']['initial_fd_names']!=PROBE_STATE['resources']['final_fd_names']:
            rc=1;PROBE_STATE['state']='READONLY_RESOURCE_FINALIZATION_UNKNOWN'
    PROBE_STATE.update(original_blobs=STATE['blobs'],read_bytes=STATE['read_bytes'],complete_file_reads=STATE['complete_file_reads'],preserved_unique_original_bytes=STATE['blob_bytes'],errors=STATE['errors'],last_complete_read=STATE['last_complete_read'],elapsed_seconds=time.monotonic()-started)
    try:
        raw=encoded(PROBE_STATE);need(len(raw)<=MAX_PACKET,'complete private evidence packet bound');compressed=zlib.compress(raw,9)
        wire=encoded({'schema':'hepta.fc33.bound02.unstarted-readonly.packet.v1','private_originals':True,'qualification_granted':False,'packet':{'encoding':'zlib-base64','bytes':len(raw),'sha256':sha(raw),'compressed_bytes':len(compressed),'compressed_sha256':sha(compressed),'base64':base64.b64encode(compressed).decode()}})
        need(len(wire)<=MAX_OUTPUT,'complete8MiB output bound');sys.stdout.buffer.write(wire);sys.stdout.buffer.flush()
    except BaseException as exc:
        rc=1;sys.stderr.buffer.write(encoded({'schema':'hepta.fc33.bound02.readonly-output-unknown.v1','state':'FULL_ORIGINALS_OUTPUT_UNKNOWN','error':type(exc).__name__+':'+str(exc)[:512],'automatic_retry':False,'qualification_granted':False}));sys.stderr.buffer.flush()
    return rc

if __name__=="__main__":raise SystemExit(probe_main())
