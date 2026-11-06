#!/usr/bin/env python3
"""One exact failed final05 scope: read-only preservation, never cleanup/qualification."""
import base64
import errno
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import sys
import tarfile
import time
import zlib

INPUTS_RAW = b'{"archive_path":"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-staging-r10-r1/root-r10-neg02-a1055-final05.tar.gz","baseline":{"bytes":1345535,"metadata":[65086,159230,33152,0,0,1,1345535,1793954243803886896,1793954243803886896],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843/AFTER-INVENTORY.original.json","sha256":"4bd70b72d2a92a6c963912159d9e978fc681a35ddb30c03a2c741700bf47cde4"},"baseline_roots":["/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/evidence","/var/lib/trillionnium/owner-open/phone-local-v150/component-probe-r6/evidence","/var/lib/trillionnium/owner-open/phone-local-v150/client-receipts","/var/lib/trillionnium/owner-open/phone-local-v150/executor-r6","/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/health-contracts/bindings","/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/task-contracts/bindings","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03","/proc/1/root/data/local/tmp/hepta-native-guard-88d68d88130d3c74e6c950a6346357c1","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04","/proc/1/root/data/local/tmp/hepta-native-guard-c705647dd4ebb5d421be1041a9c41ca6","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05","/proc/1/root/data/local/tmp/hepta-native-guard-e4c3ccb0b2d706be3b7bf105ae772405","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06","/proc/1/root/data/local/tmp/hepta-native-guard-154588e3a15591a21ec18950d18e3ecd","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07","/proc/1/root/data/local/tmp/hepta-native-guard-16805e43f9787c44c262d5b6c6d8ed95","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08","/proc/1/root/data/local/tmp/hepta-native-guard-2b0b103ee6de7a422064b9571266bf5d","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01","/proc/1/root/data/local/tmp/hepta-native-guard-902e851c3ca1f90deab3d880ab993774","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag01/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag01","/proc/1/root/data/local/tmp/hepta-native-guard-6077fc8f045572edc4acfb13ed7e09a8","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag02/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag02","/proc/1/root/data/local/tmp/hepta-native-guard-8daaaad6a322963e87973613c1fac762","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-sides01/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-sides01","/proc/1/root/data/local/tmp/hepta-native-guard-82012c7447c5f35d97c832d1d9481860","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-a1055-v3stack01/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-a1055-v3stack01","/proc/1/root/data/local/tmp/hepta-native-guard-a493b853566d68099f7dbc0a124aff50","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-a1055-final02","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-a1055-final02/executor","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-a1055-final04/executor","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-a1055-final04","/proc/1/root/data/local/tmp/hepta-native-guard-ac03e3864c1798742c472957b06ca843"],"boundary":{"bytes":29342,"metadata":[65086,154717,33152,0,0,1,29342,1793954246107886895,1793954246107886895],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843.json","sha256":"39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047"},"foreign_server_lock":{"bytes":0,"metadata":[65086,135888,33152,0,0,1,0,1793981792703876387,1793981792703876387],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9waG9uZV9leGVjdXRvcl9kYXRhX2ZpbGU6czAA","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},"historical_root_failure":{"bytes":13831,"path":"/workspace/scratch/fc33eac909ab/review/R5-stage-parent-diagnosis01/foreign-final05/ROOT-FAILURE.json","sha256":"1e8e43e90551df4638cb2853754557243bb902547b4923ca2991083cdb9f0cbf"},"historical_sender_original":{"bytes":678,"path":"/workspace/scratch/fc33eac909ab/review/R5-stage-parent-diagnosis01/foreign-final05/sender-execute/stdout.original","sha256":"20f7ba2dd1b701fdaba15bd15e228653cad2feed61a691aba748923d54d74816"},"inspect_absence_names":["provider.SPAWN-INTENT.json","provider.SPAWNED.json","provider.barrier.json","provider.ADMIT.json","provider.TERM-INTENT.json","provider.JOINED.json","provider.stdout","provider.stderr","SIDECAR-HEALTH.original.json","BOUND-CONTRACT.json","PROVIDER-HEALTH.original.json","READY.json","CONNECTION-ACCEPTED.json","ACCEPTED.json","PROVIDER-ENDED.json","ROOT-SETUP-PLAN.json"],"known_originals":{"/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/executor/server.lock":{"bytes":0,"metadata":[65086,135888,33152,0,0,1,0,1793981792703876387,1793981792703876387],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9waG9uZV9leGVjdXRvcl9kYXRhX2ZpbGU6czAA","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},"/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/executor/sidecar.stderr":{"bytes":0,"metadata":[65086,159225,33152,0,0,1,0,1793981792383876387,1793981792383876387],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9waG9uZV9leGVjdXRvcl9kYXRhX2ZpbGU6czAA","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},"/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/executor/sidecar.stdout":{"bytes":0,"metadata":[65086,159161,33152,0,0,1,0,1793981792383876387,1793981792383876387],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9waG9uZV9leGVjdXRvcl9kYXRhX2ZpbGU6czAA","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/DETACHED-LAUNCH-INTENT.json":{"bytes":2098,"metadata":[65086,159651,33152,0,0,1,2098,1793981759499876400,1793981759499876400],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9zdGF0ZV9maWxlOnMwAA==","sha256":"59fed2da6cc373cf7420d8e10761bf77406bf5108189b2860ec419bece60c608"},"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/DETACHED-LAUNCH-RESULT.json":{"bytes":411,"metadata":[65086,158993,33152,0,0,1,411,1793981759507876400,1793981759507876400],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9zdGF0ZV9maWxlOnMwAA==","sha256":"1dd10dad4b5381b660cc6f0e49fdb750157b179794df625ebee347dd942ea0b9"},"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/LEASE.json":{"bytes":2502,"metadata":[65086,137520,33152,0,0,1,2502,1793981690515876426,1793981690515876426],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9zdGF0ZV9maWxlOnMwAA==","sha256":"0ca3450a01d18a73a93f127098847c68bb6cceb0d9a2b197d3bdc32b9fcf67ab"},"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/LIFECYCLE-ATTEMPT.json":{"bytes":450,"metadata":[65086,156571,33152,0,0,1,450,1793981759759876400,1793981759759876400],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9zdGF0ZV9maWxlOnMwAA==","sha256":"01eb0734e60b24ce4551ca13ade0a614530851921336cbab7e9f4ea882e3bb22"},"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/LIFECYCLE-ENDED.json":{"bytes":865,"metadata":[65086,157364,33152,0,0,1,865,1793981792747876387,1793981792747876387],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9zdGF0ZV9maWxlOnMwAA==","sha256":"692fda24cbe9be3acd1d7e69bd50d5b22843869283d8a45dbdf663f6e9d3a4ac"},"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/LIFECYCLE-FAILURE.json":{"bytes":53,"metadata":[65086,137263,33152,0,0,1,53,1793981792699876387,1793981792699876387],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9zdGF0ZV9maWxlOnMwAA==","sha256":"8af9672a05fac9bc4acc282a4e132d663d79b06eac7e578b56ce6ff24bbb240b"},"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/PORT-RESERVED.json":{"bytes":111,"metadata":[65086,151204,33152,0,0,1,111,1793981792375876387,1793981792375876387],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9zdGF0ZV9maWxlOnMwAA==","sha256":"51dc890ff96c782e2caccf57e6d61f9062ef0b8e1c47c5b91831efc2c7386634"},"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/SUPERVISOR.json":{"bytes":1032,"metadata":[65086,138978,33152,0,0,1,1032,1793981759767876400,1793981759767876400],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9zdGF0ZV9maWxlOnMwAA==","sha256":"d85a24c74de547aa1a7a258994426baed086c3a2fc53464db8b363e943405717"},"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/package/MANIFEST.json":{"bytes":46685,"metadata":[65086,157768,33152,0,0,1,46685,1793981690559876426,1793981690559876426],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9zdGF0ZV9maWxlOnMwAA==","sha256":"72d6dcb4c20547549debad6ef55001aa5c8d115574ac222312b158f9722e2515"},"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/package/source/component_common.py":{"bytes":19138,"metadata":[65086,160205,33152,0,0,1,19138,1793981690647876426,1793981690647876426],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9zdGF0ZV9maWxlOnMwAA==","sha256":"1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab"},"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/package/source/component_lifecycle.py":{"bytes":40451,"metadata":[65086,137331,33152,0,0,1,40451,1793981690647876426,1793981690647876426],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9zdGF0ZV9maWxlOnMwAA==","sha256":"b4d876939121798f07d2a64ee46caf86a97d872b4d399ac4b96264c25725b626"},"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/package/source/component_listener.py":{"bytes":39012,"metadata":[65086,137202,33152,0,0,1,39012,1793981690651876426,1793981690651876426],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9zdGF0ZV9maWxlOnMwAA==","sha256":"6db4eb9f55bc3313b635bdd05584901706213a9d47ac2f48b81a28cdb91313ec"},"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/package/source/native_proc_profile.py":{"bytes":4633,"metadata":[65086,154390,33152,0,0,1,4633,1793981690659876426,1793981690659876426],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9zdGF0ZV9maWxlOnMwAA==","sha256":"12719e58d2e3e1a1e86b8a6a9dc9587e37bfcb36c4c3b26b023138752bb3e67b"},"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/sidecar.ADMIT.json":{"bytes":188,"metadata":[65086,159723,33152,0,0,1,188,1793981792639876387,1793981792639876387],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9zdGF0ZV9maWxlOnMwAA==","sha256":"75148017ed73a0d10a870855e3ff525d2c5f872896951cd7355b59d2fee0fb7a"},"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/sidecar.JOINED.json":{"bytes":425,"metadata":[65086,161495,33152,0,0,1,425,1793981792743876387,1793981792743876387],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9zdGF0ZV9maWxlOnMwAA==","sha256":"50c2e9b23256318cc99f6eb0cd65a27f5934e2c8bc19158205c8349d510234a7"},"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/sidecar.SPAWN-INTENT.json":{"bytes":173,"metadata":[65086,160305,33152,0,0,1,173,1793981792379876387,1793981792379876387],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9zdGF0ZV9maWxlOnMwAA==","sha256":"f171a8e266adf73a19cc14df1f18b318531fcdaabde39ea53b9fa002173ea6b4"},"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/sidecar.SPAWNED.json":{"bytes":718,"metadata":[65086,159763,33152,0,0,1,718,1793981792383876387,1793981792383876387],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9zdGF0ZV9maWxlOnMwAA==","sha256":"8725aba635e370757dbb53d8b11b1f1dc3553e64bf96cc9427730e9152ca2e32"},"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/sidecar.TERM-INTENT.json":{"bytes":134,"metadata":[65086,161229,33152,0,0,1,134,1793981792703876387,1793981792703876387],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9zdGF0ZV9maWxlOnMwAA==","sha256":"da5e3459c80dcf6dea508d90613d4dbb5b55eb416ba1b8dc687ec74dd97f849f"},"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/sidecar.barrier.json":{"bytes":146,"metadata":[65086,158500,33152,0,0,1,146,1793981792607876387,1793981792607876387],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9zdGF0ZV9maWxlOnMwAA==","sha256":"4fa101098597a22827e74d2dea9af17e435d5d760becbf597fae13f146ebc24c"},"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/supervisor.stderr":{"bytes":0,"metadata":[65086,159457,33152,0,0,1,0,1793981759503876400,1793981759503876400],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9zdGF0ZV9maWxlOnMwAA==","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/supervisor.stdout":{"bytes":0,"metadata":[65086,161097,33152,0,0,1,0,1793981759503876400,1793981759503876400],"selinux_raw_b64":"dTpvYmplY3Rfcjp0cmlsbGlvbm5pdW1fb3duZXJfb3Blbl9zdGF0ZV9maWxlOnMwAA==","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}},"lease":{"android_journal":"/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05/executor","boot_id":"f8019f83-20a7-4f18-bea1-51c980621e4d","case_id":"NEG-02","combination":{"bytes":4695,"sha256":"02c2a26af79e367afe48cb1bc378808f3c5a32800548498a0262ea0265c9f708"},"expires_unix_ms":1793982242471,"label":"root-r10-neg02-a1055-final05","nonce":"9b37081161d7bcbc3adf76d2e6ec7841","owner_request_sha256":"99dc5822937e8d50b604e39bd9da678d4ae80d2fab8cf3d32d61fd27ebe5ac8f","package_sha256":"72d6dcb4c20547549debad6ef55001aa5c8d115574ac222312b158f9722e2515","prior_boundary":{"bytes":29342,"metadata":[65086,154717,33152,0,0,1,29342,1793954246107886895,1793954246107886895],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843.json","sha256":"39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047"},"retirement":{"bound_inputs":{"bytes":848888,"metadata":[65086,148812,33152,0,0,1,848888,0,1793807681115942806],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/module-r10-r1-retirement-code-r1/BOUND-INPUTS.json","sha256":"607f832e4f1b0904a67e1102c3653543961aa71e55aa7a309cd6911c6234ec61"},"disabled_flag":{"bytes":0,"metadata":[65086,154139,33152,0,0,1,0,1793807685267942804,1793807685267942804],"path":"/proc/1/root/data/adb/modules/trillionnium_hepta_phone_local_v150_r9_r2/disable","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},"preflight":{"bytes":703888,"metadata":[65086,154138,33152,0,0,1,703888,1793807685235942804,1793807685235942804],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/module-retire-r9-r2-for-r10-r1-01/PREFLIGHT.json","sha256":"5205cd79b2f117d775c5574c63110b33e9b55f7cb69f5e212e034b8c4e9c9254"},"probe":{"bytes":766658,"metadata":[65086,154037,33152,0,0,1,766658,0,1793807681127942806],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/module-r10-r1-retirement-code-r1/retirement_probe.py","sha256":"d1fe1478ee9699b5a1199aa4c2b96a2a405f7cafd0b5707071cfd2238dbe5df4"},"proof":{"bytes":37869,"metadata":[65086,151157,33152,0,0,1,37869,1793807690051942802,1793807690051942802],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/module-retire-r9-r2-for-r10-r1-01/RETIREMENT.json","sha256":"b139e096969f5a860f5e7cb9e3e988db3d0b2e868528dd4c38b8c9411df4fb90"}},"schema":"hepta.native-guard.lease.v1","selected_profile_id":"owner-open","selected_session_id":"session-ee897738-8fc2-4d3e-a916-5fe368b340ef"},"original_cause_operation":{"bytes":202392,"path":"/workspace/scratch/fc33eac909ab/review/R5-stage-parent-diagnosis01/foreign-final05/LIFECYCLE-CAUSE-OPERATION.original.json","sha256":"c66ff14cbc1dd93f171b6013c303192fdbef67273431b42d759fdabed2273bef"},"original_cause_packet":{"bytes":489216,"path":"/workspace/scratch/fc33eac909ab/review/R5-stage-parent-diagnosis01/foreign-final05/LIFECYCLE-CAUSE-PACKET.original.json","sha256":"fdaaa78d9694d6d4e6d287330d8adfc37c52ec3fe380c97f0765f1e5c8304951"},"parent_paths":["/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1","/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1","/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-staging-r10-r1","/proc/1/root/data/local/tmp/hepta-phone-local-v150-r1"],"role_identities":{"sidecar":[30384,30384,30384,32404591],"supervisor":[29207,29207,29207,32401303]},"runtime_files":[{"bytes":1438,"path":"reference/REVIEWED-PRODUCTION-PINS.json","sha256":"970e33dedeebcf4d996160374df04d4e8dc42a3ea3895c368152f6c608e4c2ab"},{"bytes":664638,"path":"reference/attempt05-AFTER-INVENTORY.original.json","sha256":"87103089914885fff5632781f18fbe36895ed181f01997eac6c3b49449b5579e"},{"bytes":164095,"path":"reference/attempt05-CLOSURE.original.json","sha256":"d464bac786ef208d8fa0390587bd3bb7616a13985fb064716a209aa2394458f6"},{"bytes":4650,"path":"reference/attempt05-SIDE-PROOF.original.json","sha256":"1bf6bca5ae5aaa5d5803b708070680e92d3f072f9541f38b09783787cfae7b9c"},{"bytes":18133,"path":"reference/component_common_r5.py","sha256":"8ad9a3b17e7475555af7dd9a113025740447fcebdf0400d984d8a9e84accfb02"},{"bytes":13238,"path":"reference/component_core.py","sha256":"705b982a46de0fd4427cd6a233687381c592ef74459f9818f3da15e20c03916f"},{"bytes":30647,"path":"reference/component_once_r9.py","sha256":"1c27b548e42c91391e12db125c23608a2d5fb9e28ae2713df17c271bddc58fa2"},{"bytes":4116,"path":"reference/decode_client_state.py","sha256":"a3e619926a4688ebfefd55ad1074cb386240f9828613781b7fd547bcf0c70073"},{"bytes":1031582,"path":"reference/diag02-AFTER-INVENTORY.original.json","sha256":"10fe1e2d389cf8aa4928593abb207406ae63e84519339da25c722b03bee9c67d"},{"bytes":253127,"path":"reference/diag02-CLOSURE.original.json","sha256":"e25d415963eabab1fdc08704623dec88cc3ad88b9a9c228072e1138d41f8b035"},{"bytes":8439,"path":"reference/diag02-SIDE-PROOF.original.json","sha256":"a76283b76f1f12e08378662131b0375ffec95f1333d190deb3f1f90280dcc2bd"},{"bytes":53502,"path":"reference/environment_parent_late_boundary_r6.py","sha256":"1fd24e0a6799ed3fb02014567764cce4c0de884e78ccd5b663e63fe69230041c"},{"bytes":28109,"path":"reference/native_guard_session.py","sha256":"77dacc52468de95b68f30baafbb1cbf7dd7452c3d9ce652980dbb4af0ca62d8b"},{"bytes":6701,"path":"reference/native_journal_audit.py","sha256":"da47d875addc32c0f7f30d178de95d8ebd956a6cb10b59813705feeb7811f0cf"},{"bytes":19740,"path":"reference/non_native_attempt05.py","sha256":"a4ec44ac1f09fc7919dce17acf46e6db83ca468f58f53ad7622b520b557d04e4"},{"bytes":29504,"path":"reference/non_native_diag02.py","sha256":"296f5e22485712fff6641082ab0ffdee78d2d2951bcb8f53a1da5f0c374c2de6"},{"bytes":35730,"path":"reference/policy_parent_late_boundary_r4.py","sha256":"bcbe7d03567684ca23bd0985c14df49b021e1ac2e53e76dfda94262d7ad3516b"},{"bytes":62434,"path":"reference/property_parent_late_boundary_r7.py","sha256":"3c710779e79870e4fefdedb8a24163118b2de814d7fcd3e97bb8971eec6113fd"},{"bytes":62662,"path":"reference/retained_unstarted_stage_final02.py","sha256":"bc6faf1c7ae2b7e3d44be3d4fe19e4272073073f8df283397ef37c177ca25850"},{"bytes":40788,"path":"reference/send_new_native_task_r5.py","sha256":"5ab04019e94adb989e9909ae3a9aa10db0689de62821ec549db8beb3ec4d0281"},{"bytes":17390,"path":"reference/tool_client_r6.py","sha256":"500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f"},{"bytes":107528,"path":"source/close_component.py","sha256":"5b145819502951fe37e56ceb1bd2e04a6be19deef2f210590c1711e5fe401655"},{"bytes":19138,"path":"source/component_common.py","sha256":"1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab"},{"bytes":40451,"path":"source/component_lifecycle.py","sha256":"b4d876939121798f07d2a64ee46caf86a97d872b4d399ac4b96264c25725b626"},{"bytes":39012,"path":"source/component_listener.py","sha256":"6db4eb9f55bc3313b635bdd05584901706213a9d47ac2f48b81a28cdb91313ec"},{"bytes":27762,"path":"source/component_snapshot.py","sha256":"a3a2e9b7527b81d65daf5a6311b200c179c7bfcdeba33c2972e1a2031d42f1f0"},{"bytes":153138,"path":"source/late_boundary.py","sha256":"27350db238c5ca31796af91c77b5c2fdb9d02b838d35140f759df907903d4fa4"},{"bytes":28878,"path":"source/native_guard_session_r2.py","sha256":"5fe50be4dccbe655a39124876d1f9c2199de20d80ec0a84f08a63d88e7f1a931"},{"bytes":4633,"path":"source/native_proc_profile.py","sha256":"12719e58d2e3e1a1e86b8a6a9dc9587e37bfcb36c4c3b26b023138752bb3e67b"},{"bytes":14256,"path":"source/prepare_component.py","sha256":"2259eb2684ae207f27f3d40cfaaa8f28efb8d392f2bfaa27fee1183d699e6c3e"},{"bytes":18725,"path":"source/root_fixture_once.py","sha256":"605f9cfd6170bf7a1dccd73345fbafb785de8f7956a4af091a59ca4a398d3cf1"},{"bytes":39144,"path":"source/root_fixture_originals.py","sha256":"f9285a2cdac4895358671a19ada0d41c7da14832e6857c5de611fda8bf0678a9"},{"bytes":10498,"path":"source/run_root_fixture_phase.py","sha256":"bf65791c252d0b4d9416717ffca44fe43c9021211c2f2189be5553ab8967a6b2"},{"bytes":41080,"path":"source/send_new_native_guard_task_r10_r4.py","sha256":"16363414b952637f61367c51ab313187a37af632528a62207752e60f93caf6d6"},{"bytes":25040,"path":"source/sender_native_guard_ready_r10_r4.py","sha256":"a6fa2690dea61134cd51b162d86453e064c547571241959ad45f660905a542b6"},{"bytes":19085,"path":"source/stage_component.py","sha256":"ab60dc3303f14a4d979d1aa98b9990fd1496b7607f78611f26a3bb6134df4328"},{"bytes":18143,"path":"source/witness_bundle.py","sha256":"8e8e1aa967ba9fd96d9bae80eb40c6322763ba1109b015b399e4c08ad14d5557"}],"schema":"hepta.fc33.failed-final05-readonly-inputs.v1","transport":[{"bytes":763828,"metadata":[65086,136171,33152,0,0,1,763828,1793981646883876443,1793981646883876443],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-staging-r10-r1/root-r10-neg02-a1055-final05.tar.gz","sha256":"3ad5766236a2c02533a911a357ffd29c4c4ff778eb00df86dbe27cd3be7ecc0b"},{"bytes":763828,"metadata":[65086,147027,33206,2000,2000,1,763828,0,1793981645747876443],"path":"/proc/1/root/data/local/tmp/hepta-phone-local-v150-r1/hepta-native-guard-root-r10-neg02-a1055-final05.tar.gz","sha256":"3ad5766236a2c02533a911a357ffd29c4c4ff778eb00df86dbe27cd3be7ecc0b"},{"bytes":19085,"metadata":[65086,160895,33152,0,0,1,19085,1793981648943876442,1793981648943876442],"path":"/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-staging-r10-r1/root-r10-neg02-a1055-final05.stage.py","sha256":"ab60dc3303f14a4d979d1aa98b9990fd1496b7607f78611f26a3bb6134df4328"},{"bytes":19085,"metadata":[65086,154743,33206,2000,2000,1,19085,0,1793981647835876443],"path":"/proc/1/root/data/local/tmp/hepta-phone-local-v150-r1/hepta-native-guard-root-r10-neg02-a1055-final05.stage.py","sha256":"ab60dc3303f14a4d979d1aa98b9990fd1496b7607f78611f26a3bb6134df4328"}]}\n'
INPUTS_SHA = '9aa2afb7a43ef6bef379bf1d473ed1b19e964a0eacec08ba44ac91c0e549f6ef'
INPUTS = json.loads(INPUTS_RAW)
assert hashlib.sha256(INPUTS_RAW).hexdigest() == INPUTS_SHA
BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
LABEL = 'root-r10-neg02-a1055-final05'
NONCE = '9b37081161d7bcbc3adf76d2e6ec7841'
LEASE_SHA = '0ca3450a01d18a73a93f127098847c68bb6cceb0d9a2b197d3bdc32b9fcf67ab'
PACKAGE_SHA = '72d6dcb4c20547549debad6ef55001aa5c8d115574ac222312b158f9722e2515'
SCOPE_HOME = Path('/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05')
ANDROID_HOME = Path('/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg02-a1055-final05')
ANDROID = Path('/proc/1/root')
JOURNAL = ANDROID_HOME/'executor'
FIXTURE = ANDROID/'data/local/tmp'/('hepta-native-guard-'+NONCE)
BASELINE_FILE_BYTES = 44353573
MAX_FILE = 16*1024*1024
MAX_READ_BYTES = 160*1024*1024
MAX_BLOB_BYTES = 16*1024*1024
MAX_PRIVATE_TREE_BYTES = 16*1024*1024
MAX_PACKET = 32*1024*1024
MAX_OUTPUT = 8*1024*1024
MAX_SECONDS = 45
MAX_ENTRIES = 30000
MAX_PIDS = 4096
CENSUS_SECONDS = 2
STATE = None

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

def generation(row):
    return [row[k] for k in ('pid', 'pgid', 'sid', 'start_ticks')]

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

def complete_row(raw):
    return {'state': 'COMPLETE_PROC_FILE_READ', **blob(raw)}

def inspect_pid(pid, expected):
    result = {'pid': pid, 'original_identities': expected, 'started_monotonic_ns': time.monotonic_ns(),
              'failed_sample_reconstructed': False}
    try:
        before_raw = proc_bytes('/proc/%d/stat' % pid, 8192)
        before = stat_identity(before_raw, pid, census=True)
        result['stat_before'] = complete_row(before_raw)
        result['identity_before'] = before
    except (OSError, ValueError) as error:
        result['stat_before'] = absent_or_error('/proc/%d/stat' % pid, error)
        result['finished_monotonic_ns'] = time.monotonic_ns()
        return result
    for name, maximum in [('status', 65536), ('attr/current', 4096), ('cmdline', 65536)]:
        try:
            raw = proc_bytes('/proc/%d/%s' % (pid, name), maximum)
            result[name] = complete_row(raw)
            if name == 'cmdline':
                result['current_cmdline_gate_components'] = {
                    'nonempty': len(raw) > 0, 'within_65536': len(raw) <= 65536,
                    'ends_NUL': raw.endswith(b'\0'), 'observed_bytes': len(raw),
                    'observation_is_the_historical_failed_sample': False}
        except (OSError, ValueError) as error:
            result[name] = absent_or_error('/proc/%d/%s' % (pid, name), error)
    try:
        result['exe'] = {'state': 'READLINK_OBSERVED', 'value': os.readlink('/proc/%d/exe' % pid)}
    except OSError as error:
        result['exe'] = absent_or_error('/proc/%d/exe' % pid, error)
    try:
        after_raw = proc_bytes('/proc/%d/stat' % pid, 8192)
        after = stat_identity(after_raw, pid, census=True)
        result['stat_after'] = complete_row(after_raw)
        result['identity_after'] = after
        result['same_generation_and_parent_in_this_window'] = generation(before) == generation(after) and before['ppid'] == after['ppid']
        result['matches_an_original_generation'] = generation(before) in expected and generation(after) in expected
    except (OSError, ValueError) as error:
        result['stat_after'] = absent_or_error('/proc/%d/stat' % pid, error)
        result['same_generation_and_parent_in_this_window'] = None
        result['matches_an_original_generation'] = None
    result['finished_monotonic_ns'] = time.monotonic_ns()
    return result

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


def acquire_locks(baseline):
    aliases = {p:r for p,r in baseline['entries'].items()
               if r['kind'] == 'file' and (p.rsplit('/',1)[-1] == 'lock' or p.endswith('.lock'))}
    need(len(aliases) == 26 and len({tuple(r['metadata'][:2]) for r in aliases.values()}) == 14,
         'original44 exact lock alias/group count')
    for p in (str(SCOPE_HOME/'executor/server.lock'),str(JOURNAL/'server.lock')):
        need(p not in aliases, 'foreign lock overlaps original44')
        aliases[p] = INPUTS['foreign_server_lock']
    groups = {}
    acquired = []
    observations = []
    try:
        for path, expected in sorted(aliases.items(),key=lambda x:(x[1]['metadata'][0],x[1]['metadata'][1],x[0])):
            row, _ = original(path,65536,expected=expected,owner=(0,0,(0o600,)),preserve=False)
            parent, name = parent_fd(path)
            try:
                fd = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            finally:
                os.close(parent)
            try:
                need(metadata(os.fstat(fd)) == row['metadata']
                     and base64.b64encode(os.getxattr(fd,'security.selinux')).decode() == row['selinux_raw_b64'],
                     'lock descriptor changed')
                key = tuple(row['metadata'][:2])
                if key not in groups:
                    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    groups[key] = fd
                    acquired.append(fd)
                    fd = None
                else:
                    need(metadata(os.fstat(groups[key])) == row['metadata'], 'lock aliases differ')
                observations.append(row)
            finally:
                if fd is not None:
                    os.close(fd)
        need(len(groups) == 15 and len(observations) == 28, 'exact original14 plus foreign1 lock set')
        STATE['lock_fds'] = acquired
        return {'alias_count':28,'inode_group_count':15,'old_inode_group_count':14,
                'lock_mode':'LOCK_EX|LOCK_NB on existing O_RDONLY descriptors','aliases':observations,
                'lock_files_created':0,'held_through_both_windows':True}
    except BaseException:
        for fd in reversed(acquired):
            os.close(fd)
        raise


def archive_members(raw):
    """Exact original stage archive grammar, with no extraction or target execution."""
    need(0 < len(raw) <= 8*1024*1024, 'compressed archive size bound')
    decoder = zlib.decompressobj(31)
    plain = decoder.decompress(raw,16*1024*1024+1)
    need(len(plain) <= 16*1024*1024 and decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data,
         'gzip archive incomplete/oversized/concatenated')
    files = {}
    with tarfile.open(fileobj=io.BytesIO(plain),mode='r:') as archive:
        for row in archive:
            p = Path(row.name)
            need(len(files) < 80 and str(p) == row.name and not p.is_absolute() and '..' not in p.parts
                 and '\0' not in row.name and '\\' not in row.name and row.name not in files
                 and row.isreg() and not row.pax_headers and row.uid == row.gid == 0 and row.mode == 0o600
                 and row.mtime == 0 and 0 <= row.size <= 8*1024*1024, 'original archive member differs')
            stream = archive.extractfile(row)
            need(stream is not None, 'archive member absent')
            data = stream.read(row.size+1)
            need(len(data) == row.size, 'archive member incomplete')
            files[row.name] = data
    need(sum(map(len,files.values())) <= 8*1024*1024 and len(files) == 61, 'exact61 stage members required')
    canonical = io.BytesIO()
    with tarfile.open(fileobj=canonical,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        for name,data in sorted(files.items()):
            row = tarfile.TarInfo(name)
            row.mode = 0o600; row.uid = row.gid = 0; row.mtime = 0; row.size = len(data)
            archive.addfile(row,io.BytesIO(data))
    need(plain == canonical.getvalue(), 'noncanonical archive metadata/order/trailing content')
    return files


def immutable_stage_members(files, observed):
    lease_raw = files['LEASE.json']; manifest_raw = files['package/MANIFEST.json']
    need(sha(lease_raw) == LEASE_SHA and sha(manifest_raw) == PACKAGE_SHA, 'stage lease/package pins')
    lease = strict(lease_raw); manifest = strict(manifest_raw)
    need(lease == INPUTS['lease'] and manifest['files'] == INPUTS['runtime_files'], 'exact old scope/37 file set')
    expected = {'LEASE.json','owner-request.txt','sender-contract.json','package/MANIFEST.json',
                'inputs/COMBINATION.json','inputs/SOURCE-SEAL.original.json','inputs/configuration.original.json',
                'inputs/service-inputs.original.json','inputs/PRIOR-BOUNDARY.original.json'}
    expected.update('package/'+r['path'] for r in manifest['files'])
    reviewed = strict(files['package/reference/REVIEWED-PRODUCTION-PINS.json'])
    need(len(reviewed) == 15, 'original production pin count')
    expected.update('inputs/production/'+name for name in reviewed)
    need(set(files) == expected and len(manifest['files']) == 37, 'stage61/runtime37 exact namespaces')
    for r in manifest['files']:
        b = files['package/'+r['path']]
        need(len(b) == r['bytes'] and sha(b) == r['sha256'], 'archived runtime file pin')
    for name,digest in reviewed.items():
        need('/' not in name and name.endswith('.py') and sha(files['inputs/production/'+name]) == digest,
             'archived production original differs')
    rows = []
    for name,raw in sorted(files.items()):
        path = str(SCOPE_HOME/name); row = observed['entries'].get(path)
        need(row is not None and row['kind'] == 'file' and row['bytes'] == len(raw)
             and row['sha256'] == sha(raw) and base64.b64decode(STATE['blobs'][row['sha256']]['base64'],validate=True) == raw,
             'current staged member no longer exact: '+name)
        rows.append({'relative_path':name,'path':path,'bytes':len(raw),'sha256':sha(raw),'metadata':row['metadata']})
    return {'archive_member_count':61,'runtime_file_count':37,'all61_current_bytes_equal_original_archive':True,
            'all37_current_bytes_equal_original_manifest':True,'members':rows}


def process_window(index):
    """Two known identities only; signal zero queries cannot terminate a process."""
    started = time.monotonic_ns()
    identities = INPUTS['role_identities']
    result = {'index':index,'started_monotonic_ns':started,'original_identities':identities,
              'process_observations':[], 'census':{}, 'kernel_group_queries':[]}
    STATE['evidence'].setdefault('process_windows',[]).append(result)
    for role,identity in sorted(identities.items()):
        item = inspect_pid(identity[0],[identity]); item['role'] = role
        result['process_observations'].append(item)
    names = sorted((n for n in os.listdir('/proc') if n.isdecimal()),key=int)
    need(len(names) <= MAX_PIDS, 'proc PID count budget')
    limit = min(STATE['deadline'],time.monotonic()+CENSUS_SECONDS)
    rows = {}; members = []; disappeared = []
    ids = {tuple(v) for v in identities.values()}
    groups = {v[1] for v in identities.values()}
    sessions = {v[2] for v in identities.values()}
    for name in names:
        check_time();need(time.monotonic() < limit, 'proc census deadline; absence unknown')
        pid = int(name)
        try:
            raw = proc_bytes('/proc/%d/stat'%pid,8192)
        except OSError as error:
            need(error.errno == errno.ENOENT, 'proc census unknown I/O')
            disappeared.append(pid)
            rows[name] = {'state':'OBSERVED_ENOENT','errno':errno.ENOENT}
            continue
        row = stat_identity(raw,pid,census=True)
        rows[name] = {'state':'COMPLETE_PROC_STAT','identity':row,**blob(raw)}
        if tuple(generation(row)) in ids or row['pgid'] in groups or row['sid'] in sessions:
            members.append(row)
    need(time.monotonic() < limit, 'proc census deadline; absence unknown')
    result['census'] = {'complete':True,'numeric_pid_count':len(names),'names':names,'stat_originals':rows,
                        'disappeared_while_reading':disappeared,'members':members}
    # Do not send any nonzero signal. A live/reused group or EPERM is UNKNOWN,
    # never a permission to kill or a successful absence observation.
    for role,identity in sorted(identities.items()):
        pgid = identity[1]
        need(identity[:3] == [identity[0]]*3 and all(type(v) is int and v > 1 for v in identity), 'exact session identity')
        row = {'role':role,'identity':identity,'syscall':'kill','pid_argument':-pgid,'signal':0,
               'observed_monotonic_ns':time.monotonic_ns()}
        try:
            os.kill(-pgid,0)
        except OSError as error:
            row['errno'] = error.errno
            row['state'] = 'ESRCH' if error.errno == errno.ESRCH else 'UNKNOWN_ERROR'
        else:
            row['errno'] = None;row['state'] = 'GROUP_EXISTS'
        result['kernel_group_queries'].append(row)
    result['finished_monotonic_ns'] = time.monotonic_ns()
    result['known_groups_absent_in_this_window'] = not members and all(r['state'] == 'ESRCH' for r in result['kernel_group_queries'])
    need(result['known_groups_absent_in_this_window'], 'original known process group absence not established')
    return result


def require_known_originals(observed):
    for path,pin in INPUTS['known_originals'].items():
        row = observed['entries'].get(path)
        need(row is not None and row['kind'] == 'file', 'known lifecycle original absent: '+path)
        for key in ('bytes','sha256','metadata','selinux_raw_b64'):
            need(row[key] == pin[key], 'known lifecycle original changed '+key+': '+path)


def capture():
    need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0, 'actual Root credentials')
    boot = proc_bytes('/proc/sys/kernel/random/boot_id',128).decode().strip()
    domain = proc_bytes('/proc/self/attr/current',4096)
    need(boot == BOOT and domain.rstrip(b'\0\n') == b'u:r:magisk:s0', 'same boot/native Root domain')
    init_raw = proc_bytes('/proc/1/stat',8192);init = stat_identity(init_raw,1,census=True)
    gnu_root = os.stat('/');android_root = os.stat(ANDROID)
    need(init['pid'] == 1 and init['start_ticks'] == 0
         and (gnu_root.st_dev,gnu_root.st_ino) != (android_root.st_dev,android_root.st_ino), 'native init/anchor binding')
    STATE['evidence']['collector_identity'] = {'pid':os.getpid(),'boot_id':boot,'domain_raw_b64':base64.b64encode(domain).decode(),
        'init':init,'init_stat_original':blob(init_raw),'gnu_root_metadata':metadata(gnu_root),'android_root_metadata':metadata(android_root)}
    baseline_row,baseline_raw = original(INPUTS['baseline']['path'],MAX_FILE,expected=INPUTS['baseline'],owner=(0,0,(0o600,)))
    baseline = strict(baseline_raw)
    need(baseline['schema'] == 'hepta.native-guard.complete-inventory.v1'
         and baseline['roots'] == INPUTS['baseline_roots'] and len(baseline['roots']) == 44
         and len(baseline['entries']) == 3823 and baseline['file_bytes_hashed'] == BASELINE_FILE_BYTES,
         'exact original44 inventory shape')
    boundary_row,_ = original(INPUTS['boundary']['path'],MAX_FILE,expected=INPUTS['boundary'],owner=(0,0,(0o600,)))
    STATE['evidence']['baseline_original'] = baseline_row;STATE['evidence']['boundary_original'] = boundary_row
    STATE['evidence']['locks'] = acquire_locks(baseline)
    # Known roles must already be absent before any bulk capture.
    process_window(0)
    parents_before = [project_directory(directory(p)) for p in INPUTS['parent_paths']]
    aliases_before = [project_directory(directory(p)) for p in (str(SCOPE_HOME),str(ANDROID_HOME))]
    need({k:aliases_before[0][k] for k in ('metadata','names','selinux_raw_b64')} ==
         {k:aliases_before[1][k] for k in ('metadata','names','selinux_raw_b64')}, 'GNU/Android private home aliases differ')
    transport_rows = []
    archive_raw = None
    for pin in INPUTS['transport']:
        owner = (pin['metadata'][3],pin['metadata'][4],(stat.S_IMODE(pin['metadata'][2]),))
        row,raw = original(pin['path'],MAX_FILE,expected=pin,owner=owner)
        transport_rows.append(row)
        if pin['path'] == INPUTS['archive_path']:
            archive_raw = raw
    need(archive_raw is not None, 'one exact GNU stage archive')
    files = archive_members(archive_raw)
    STATE['evidence']['transport'] = transport_rows
    fixtures = [p for p,r in baseline['entries'].items() if r['kind'] == 'absent']
    need(all(p in baseline['roots'] and p.startswith('/proc/1/root/data/local/tmp/hepta-native-guard-') for p in fixtures),
         'only exact historical fixture roots may be absent')
    # All fixture namespaces also need their original UID2000 file semantics.
    fixtures = [p for p in baseline['roots'] if p.startswith('/proc/1/root/data/local/tmp/hepta-native-guard-')]
    before = tree(baseline['roots'],preserve=False,absent_fixtures=fixtures)
    compare_baseline(before,baseline);STATE['evidence']['baseline_before'] = before
    private_before = tree([str(SCOPE_HOME),str(JOURNAL),str(FIXTURE)],preserve=True,absent_fixtures=[str(FIXTURE)])
    require_known_originals(private_before)
    STATE['evidence']['private_before'] = private_before
    STATE['evidence']['stage_members'] = immutable_stage_members(files,private_before)
    stage_row = private_before['entries'][str(SCOPE_HOME/'STAGE-COMPLETE.json')]
    need(stage_row['bytes'] == 36354 and stage_row['sha256'] == '409d65f2167f704fcc380bcd11c42536b141763e232210d2f039d12ab8e1adc0',
         'original successful stage record differs')
    # Repeat every private byte/full9 and every original44 hash under the same locks.
    private_after = tree([str(SCOPE_HOME),str(JOURNAL),str(FIXTURE)],preserve=True,absent_fixtures=[str(FIXTURE)])
    need(stable_tree_projection(private_after) == stable_tree_projection(private_before), 'private complete tree changed between windows')
    after = tree(baseline['roots'],preserve=False,absent_fixtures=fixtures)
    compare_baseline(after,baseline)
    need(stable_tree_projection(after) == stable_tree_projection(before), 'original44 complete tree changed between windows')
    STATE['evidence']['private_after'] = private_after;STATE['evidence']['baseline_after'] = after
    process_window(1)
    parents_after = [project_directory(directory(p)) for p in INPUTS['parent_paths']]
    aliases_after = [project_directory(directory(p)) for p in (str(SCOPE_HOME),str(ANDROID_HOME))]
    need(parents_before == parents_after and aliases_before == aliases_after, 'parent/private alias bookends changed')
    STATE['evidence']['parents_before'] = parents_before;STATE['evidence']['parents_after'] = parents_after
    STATE['evidence']['home_aliases_before'] = aliases_before;STATE['evidence']['home_aliases_after'] = aliases_after
    rereads = []
    for pin in [INPUTS['baseline'],INPUTS['boundary']]+INPUTS['transport']:
        owner = (pin['metadata'][3],pin['metadata'][4],(stat.S_IMODE(pin['metadata'][2]),))
        row,_ = original(pin['path'],MAX_FILE,expected=pin,owner=owner)
        rereads.append(row)
    STATE['evidence']['pinned_input_bookends'] = rereads
    need(proc_bytes('/proc/sys/kernel/random/boot_id',128).decode().strip() == BOOT, 'boot changed')
    # These are current observations, not a reconstructed historical native count.
    rows = private_before['entries'];presence = {}
    for name in INPUTS['inspect_absence_names']:
        path = str(SCOPE_HOME/name)
        if path in rows:
            presence[name] = {'state':'PRESENT','row':rows[path]}
        else:
            need('/' not in name, 'only directly enumerated home leaf absence')
            presence[name] = {'state':'ABSENT_FROM_COMPLETE_HOME_LISTING'}
    claims = rows[str(SCOPE_HOME/'claims')]
    actions = rows.get(str(JOURNAL/'actions'))
    STATE['evidence']['bounded_current_presence'] = {'home_records':presence,'claims_directory':claims,
        'actions_directory':actions,'fixture_root':rows[str(FIXTURE)],
        'historical_native_or_effect_count_inferred':None,'closure_granted':False}


def output_packet(value):
    raw = encoded(value)
    need(len(raw) <= MAX_PACKET, 'full raw evidence packet bound')
    compressed = zlib.compress(raw,9)
    wire = encoded({'schema':'hepta.fc33.failed-scope-readonly.packet.v1','qualification_granted':False,
        'packet':{'encoding':'zlib-base64','bytes':len(raw),'sha256':sha(raw),'compressed_bytes':len(compressed),
                  'compressed_sha256':sha(compressed),'base64':base64.b64encode(compressed).decode()}})
    need(len(wire) <= MAX_OUTPUT, 'complete packet exceeds unchanged8MiB output cap')
    return wire


def main():
    global STATE
    started = time.monotonic()
    STATE = {'deadline':started+MAX_SECONDS,'read_bytes':0,'complete_file_reads':0,'errors':[],
             'evidence':{},'blobs':{},'blob_bytes':0,'lock_fds':[],'last_complete_read':None}
    previous = signal.getsignal(signal.SIGALRM)
    need(signal.getitimer(signal.ITIMER_REAL) == (0.0,0.0), 'existing timer cannot be replaced')
    def expired(_signum,_frame):
        raise TimeoutError('fresh read-only scope deadline')
    signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,MAX_SECONDS)
    error = None;rc = 0;output_started = False
    try:
        try:
            capture()
            need(not STATE['errors'], 'one or more read observations unknown')
        except BaseException as exc:
            error = {'type':type(exc).__name__,'detail':str(exc)[:1024]};rc = 1
        value = {'schema':'hepta.fc33.failed-scope-readonly.v1',
            'state':'COMPLETE_FRESH_READONLY_SCOPE_CAPTURE_NO_CLOSURE' if error is None else 'PARTIAL_READONLY_CAPTURE_UNKNOWN_REMAINS',
            'scope':{'label':LABEL,'nonce':NONCE,'lease_sha256':LEASE_SHA,'runtime_sha256':PACKAGE_SHA,'boot_id':BOOT},
            'inputs_sha256':INPUTS_SHA,'evidence':STATE['evidence'],'original_blobs':STATE['blobs'],
            'errors':STATE['errors'],'terminal_error':error,'last_complete_read':STATE['last_complete_read'],
            'read_bytes':STATE['read_bytes'],'complete_file_reads':STATE['complete_file_reads'],
            'preserved_unique_original_bytes':STATE['blob_bytes'],'elapsed_before_output':time.monotonic()-started,
            'file_writes':0,'file_deletes':0,'nonzero_signals_to_other_processes':0,'ui_inputs':0,'model_requests':0,
            'native_dispatches':0,'endpoint_connections':0,'target_programs_imported_or_executed':0,
            'scope_closure':False,'qualified_source_parent':False,'deletion_authorized':False,
            'historical_failed_cmdline_reconstructed':False,'historical_scope_effect_count_inferred':None,
            'host_sender_or_draft_current_state_proven':False,'automatic_retry':False,
            'locks_release':'all existing descriptors closed in finally after output'}
        try:
            wire = output_packet(value);check_time();output_started = True
            sys.stdout.buffer.write(wire);sys.stdout.buffer.flush()
        except BaseException as exc:
            rc = 1
            fallback = encoded({'schema':'hepta.fc33.failed-scope-readonly.output-failure.v1',
                'state':'FULL_PACKET_NOT_PUBLISHED_OR_OUTPUT_UNKNOWN','error':type(exc).__name__+':'+str(exc)[:512],
                'label':LABEL,'qualification_granted':False,'retry_automatic':False})
            stream = sys.stderr.buffer if output_started else sys.stdout.buffer
            stream.write(fallback);stream.flush()
    finally:
        for fd in reversed(STATE['lock_fds']):
            os.close(fd)
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
    return rc


if __name__ == '__main__':
    raise SystemExit(main())
