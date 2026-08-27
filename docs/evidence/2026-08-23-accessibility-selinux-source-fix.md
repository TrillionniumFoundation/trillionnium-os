# Accessibility bind SELinux source fix

Date: 2026-08-23 (Asia/Shanghai)

The reversible live probe on `ZY32JLVHGN` showed an enforcing denial while the
explicitly selected Accessibility service completed its framework bind:

```text
avc: denied { find } ...
scontext=u:r:trillionnium_agent_accessibility:s0
tcontext=u:object_r:activity_service:s0
permissive=0
```

The canonical Android sepolicy source now contains one narrow discovery edge
in `device/trillionnium/sepolicy/common/private/trillionnium_agent_accessibility.te`:

```te
allow trillionnium_agent_accessibility activity_service:service_manager find;
```

This grants only ServiceManager lookup. It does not grant a Binder call to
ActivityManager, settings writes, input, network access, or generic service
manager access. The service still requires explicit per-user authorization and
keeps its replay/ACK and authorization gates before any socket or UI effect.

Source checks after the change:

```text
replay_sync_policy_contract_test.py: 11 passed
capability_lease_broker_policy_contract_test.py: 7 passed
git diff --check: PASS
```

The currently running device and the v28 target CIL were built before this
source edit; no policy was pushed and no device was rebooted or flashed. A
future exact-clean rebuild must compile this rule and then re-run the live bind
probe. This source fix therefore removes one host-side SELinux contract gap,
but it does not manufacture user authorization, KeyMint/Verified-Boot or
rollback attestation, OS-held-key ADB custody, replay/receipt/ACK closure, or
production `user`/`release-keys` signing evidence. The release gate remains
`HOLD`.

An incremental Soong `sepolicy` attempt was made with the canonical versioned
`OUT_DIR` and the explicit `trillionnium_fogos`/`bp4a`/`userdebug` variables. The
source finder remained in external-disk `getdents` wait for more than six
minutes, so it was interrupted cleanly; the target CIL timestamp stayed at the
pre-edit build. This is an I/O-bound verification stop, not a policy compile
failure, and no source or device state was reverted.
