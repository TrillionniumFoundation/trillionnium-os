# Live Accessibility adapter snapshot (reversible diagnostic)

Date: 2026-08-23 (Asia/Shanghai)

Device: `ZY32JLVHGN` (`trillionnium_fogos` / `fogos`)

This is a bounded, reversible diagnostic of the system Accessibility binding.
It is not production ownership, a replay/receipt/ACK proof, or an authority
grant. The device was already an unlocked `userdebug`/`test-keys` build. No
APK was installed, no UI input or shell effect was dispatched, and no reboot,
fastboot, flash, or private-key operation occurred.

## Before state

With the ADB server started only for this probe:

```text
enabled_accessibility_services=null
accessibility_enabled=0
Bound services:{}
Enabled services:{}
Binding services:{}
Crashed services:{}
```

The only component selected for the temporary probe was the preinstalled
system-ext service:

```text
org.trillionnium.agentaccessibility/.AgentAccessibilityService
```

## Temporary bind and observation

The shell settings writes returned exit code 0:

```text
settings put secure enabled_accessibility_services \
  org.trillionnium.agentaccessibility/.AgentAccessibilityService
settings put secure accessibility_enabled 1
```

The settings service accepted the values and ActivityManager started the
service process. The Accessibility manager reported:

```text
enabled_accessibility_services=org.trillionnium.agentaccessibility/.AgentAccessibilityService
accessibility_enabled=1
Bound services:{}
Enabled services:{{org.trillionnium.agentaccessibility/org.trillionnium.agentaccessibility.AgentAccessibilityService}}
Binding services:{{org.trillionnium.agentaccessibility/org.trillionnium.agentaccessibility.AgentAccessibilityService}}
Crashed services:{}
```

The live process immediately hit SELinux denials while looking up the Activity
service:

```text
avc: denied { find } ...
scontext=u:r:trillionnium_agent_accessibility:s0
tcontext=u:object_r:activity_service:s0
permissive=0
```

No protocol v2 snapshot, replay receipt, or Android ACK was emitted or
observed. In particular, `Bound services:{}` remained empty; an enabled
setting and a pending bind are not a usable adapter closure.

## Exact restore

The original values were restored immediately:

```text
settings delete secure enabled_accessibility_services  # exit 0
settings put secure accessibility_enabled 0            # exit 0
```

Readback after the restore was:

```text
enabled_accessibility_services=null
accessibility_enabled=0
Bound services:{}
Enabled services:{}
Binding services:{}
Crashed services:{}
```

The ADB server was then stopped. A stale diagnostic `ConnectionRecord` was
visible briefly in `dumpsys activity services`; it did not correspond to an
enabled or bound Accessibility service after restoration.

## Decision

This probe proves only that the installed component can be selected by the
debug settings path and that the current SELinux policy prevents it from
forming a live bound adapter. It does **not** clear the production blocker.
The release gate remains `HOLD` pending a production-owned service/domain,
measured protocol/replay and receipt/ACK evidence, real KeyMint/Verified-Boot
and rollback attestation, OS-held-key ADB transport, and legitimate
`user`/`release-keys` signing material.
