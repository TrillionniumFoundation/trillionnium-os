# Init / Agent endpoint observer preflight — 2026-08-23

This record is a bounded, read-only observation after the local dogfood OTA and
USB reverse-tether setup.  It is not a Codex turn, an effect receipt, an ADB
custody claim, or permission to activate a service.  No `setprop`, `start`,
`stop`, `input`, `install`, `push`, reboot, or partition operation was issued.

## Live values observed on `ZY32JLVHGN`

The device was reachable as `adb get-state = device`.  The fixed property and
service reads returned:

```text
sys.trillionnium.rootlinux.prepare=
sys.trillionnium.agentd.desired=
sys.trillionnium.agent_egress_guard=
init.svc.trillionnium_root_linux_bootstrap=stopped
init.svc.trillionnium_root_linux_daemon=stopped
init.svc.trillionnium_direct_operation_custody_high_water=stopped
ro.build.type=userdebug
ro.boot.verifiedbootstate=orange
ro.boot.vbmeta.device_state=unlocked
```

The shell observer also saw Android-side processes `org.trillionnium.aishell`
and `org.trillionnium.aiauthority`, but no `trillionniumd`, `agentd`, `codex`,
or Root-Linux daemon process.  A bounded `/proc/net/unix` read showed these
abstract endpoints:

```text
@trillionnium-agent-gateway-v1
@trillionnium_system_api
@trillionnium_system_api_replay_control
```

These endpoints are consistent with the Android-side source contracts.  Their
peer credentials, SELinux domains, request/response exchange, durable ACK, and
replay authority were not established by this observer.  In particular, an
abstract socket row is not proof that an authenticated Root-Linux Agent Host is
connected or that a state-changing call can be safely dispatched.

## Qualification decision

`init activation / Agent API socket`: **HOLD**.

The Android endpoint surface is present, but the expected root-owned lifecycle
state is not active and no freshness-bound target contract is available to pin
the live files.  The source bootstrap does contain the root-owned
`publish_rootlinux_prepare_complete` producer; manually writing its property
would bypass that producer and is therefore prohibited.  The strict
`tools/android_p01_device_conformance.py` collector was not run because no
fresh, hash-pinned P0.1 expectation contract was produced from an exact-clean
target-files/BOM chain; creating one from stale metadata would be synthetic
evidence.

The next admissible step is an exact-clean rebuild with the source-BOM binding
embedded in target-files, followed by a hash-pinned read-only conformance
collection.  Only a successful observer receipt can authorize evaluating a
single Codex turn and a bounded System API/shell effect.  The current device
remains userdebug/test-keys and orange/unlocked.

## Static checks run alongside the observer

The source-side checks remained green in this worktree:

- `tools.tests.test_android_p01_device_conformance`: 30/30;
- `vendor/trillionnium/prebuilt/common/tests/trillionnium_receipt_stage_verify_test.py`: 57/57;
- `rootfs_bootstrap_v9_branch_contract_test.sh`: PASS;
- `agent_direct_product_contract_test.sh`: PASS (source/product declarations;
  artifact/device still explicitly held);
- `agentd_peer_identity_contract_test.sh`: PASS (exact system_ext source
  identity contract; artifact/device still explicitly held).

These are source and host conformance results.  They do not turn the live
abstract socket rows into a peer-authenticated Agent Host or authorize a
state-changing request.

## Why the existing target-files ZIP cannot supply the observer contract

The active OUT also contains an older target-files archive at
`target/product/fogos/obj/PACKAGING/target_files_intermediates/trillionnium_fogos-target_files.zip`
(3,311,305,066 bytes, mtime 2026-08-14).  It contains the staged system_ext
manifest and receipt-stage artifacts, but it does not contain an
`org.trillionnium.android-p01-device-conformance-contract.v1` expectation
contract or a source-BOM binding member.  Its embedded manifest explicitly
records `agent_accessibility_epoch_activation=absent_product_hold`,
`agent_accessibility_replay_sync_binary=absent_product_hold`,
`agent_adb_transport=unavailable_fail_closed`, and journal v3 hotpath disabled.
The embedded receipt-stage source-BOM projection is the historical
`d9cbeee4970a6829bffd58ed94431ea26b78f87c144021084ac298cef9ada636` / resolved
manifest `9a0c8be03881096bde3e4413e58429c90f9c11dc06d3a2a5407d1b234828732d`
generation, while current source edits are later and dirty.  It is therefore
useful for diagnosis only; deriving a new expectation contract from it would
cross-splice generations.

## Post-gateway read-only recheck (22:36 CST)

After the gateway restart, the authorized device was still reachable and the
USB reverse-tether was restored.  A new read-only snapshot returned the same
empty `rootlinux.prepare`, `agentd.desired`, and `agent_egress_guard` values,
with both Root-Linux services still `stopped`; `tun0` was `10.0.0.2/32`.
The Android-side `aiauthority`, `aishell`, and health/livedisplay processes
remain present, and the three abstract socket names remain present, but no
`trillionniumd`, Codex runtime, or Root-Linux daemon is running.  Socket
presence remains endpoint evidence only: no authenticated peer, effect,
durable ACK, or replay receipt was sent or inferred.  Restoring the relay and
collecting this snapshot did not change device state.

## Post-hardening host contract recheck (22:xx CST)

The source-only contracts were rerun without activating any init service or
opening an Agent API peer:

```text
rootfs_bootstrap_v9_branch_contract_test.sh                                PASS
agent_direct_product_contract_test.sh                                      PASS
agentd_peer_identity_contract_test.sh                                      PASS (artifact/device HOLD)
agent_operation_epoch_replay_product_hold_contract_test.py                 7/7 PASS
agentd_payload_epoch_high_water_test.py                                    8/8 PASS
```

The bounded `agentd_production_tcb_test.sh` source/self-test gate subsequently
completed with PASS for its measured source TCB, tar-filter checks, and
target-files verifier self-tests.  Its own result keeps physical target-files
materialization as `HOLD/SOURCE_ONLY`; it therefore does not provide a fresh
init manifest, an Android daemon binary, or a live peer identity for this
device.

The isolated `agentd_no_rootfs_mutation_test.sh` also completed with PASS.  It
used a temporary synthetic rootfs, verified that the startup path leaves it
byte-for-byte unchanged, and rejected unsafe `/run` and AgentManifest inputs.
The temporary mount/rootfs was cleaned up; this is a host contract test, not a
device activation or a live Root-Linux proof.

The six root-owned shell entrypoints (bootstrap, rootfs runner, EROFS
admission, daemon, P0.1 daemon wrapper, and egress guard) also pass `bash -n`.
Parsing success does not imply that any of them is installed or active in the
current device image.

These results cover fail-closed declarations and fixture behavior only.  A
later bounded run of `rootfs_bootstrap_transaction_test.sh` completed with
PASS, but that still does not materialize a target or activate a service.  The
live qualification remains **HOLD**: no authenticated
Root-Linux or Android direct-turn peer, Codex effect, durable ACK, replay
receipt, or freshness-pinned expectation contract was observed.  No `adb`
write, `setprop`, `start`, `stop`, mount, install, input, or reboot command
was issued during this recheck.

The latest read-only connectivity/status snapshot still shows `wlan0` on the
host LAN (`192.168.0.10/24`) and the Gnirehtet `tun0` (`10.0.0.2/32`); ADB
reports `device`, while `sys.trillionnium.rootlinux.prepare` and
`sys.trillionnium.agentd.desired` remain empty and the Root-Linux daemon is
`stopped`.  Network reachability does not alter the activation gate.
