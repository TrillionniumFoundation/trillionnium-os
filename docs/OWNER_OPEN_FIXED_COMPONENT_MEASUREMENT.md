# Fixed Android components and ordinary application service discovery

This is a new source candidate based on owner `63e48ac`. It does not modify,
reclassify or qualify the installed R54 candidate. Its selected Android runtime
profile is version 5 with revision
`2026-10-09-leap-api37-client-api-fixed-measurement`. The Root Linux provider and
owner-client control wire protocols are unchanged.

The actual R54 owner application failed before Activity `onCreate`, at
`ActivityThread.attach` calling a null `ActivityManager.getService()`. An
independent host query of the exact strict combined policy `c923923b…` found the
client in `appdomain`, with Binder calls to servicemanager and system_server
allowed, but no `find` permission for activity, activity_task, package or window.
The primary `app_domain` macro does not grant these service lookups; ordinary
`untrusted_app_all` separately receives `app_api_service:service_manager find`.
The change adds that public application API lookup to the existing dedicated
client domain. It does not change its ordinary UID, assign `platform_app`, grant
service registration, or add `system_api_service` or `service_manager_type`
lookup. Android service method permissions remain enforced by their servers.
This source-policy gap matches the observed null service, without claiming a
sample of the crashing process's runtime domain or an observed phone AVC.

Bootstrap retains its three existing digest components and adds five fixed
files under `/system_ext`:

| Relative file | New digest property suffix | Maximum bytes |
| --- | --- | ---: |
| `etc/build.prop` | `system_ext_build_prop_sha256` | 1,048,576 |
| `bin/trillionnium-owner-open-ingress` | `ingress_sha256` | 33,554,432 |
| `bin/trillionnium-owner-open-emergency-stop` | `emergency_stop_sha256` | 8,388,608 |
| `app/TrillionniumOwnerOpenShell/TrillionniumOwnerOpenShell.apk` | `shell_apk_sha256` | 67,108,864 |
| `etc/init/trillionnium-sun-btfm-modprobe.rc` | `btfm_init_sha256` | 1,048,576 |

The property prefix is `trillionnium.owner_open.measurement.`. Each new property
is an exact string entry under the existing typed property label. Values contain
only lowercase SHA256 digests; no file contents, state, credentials or arbitrary
path are exported. The two dedicated executable labels gain only bootstrap
`getattr/open/read`, not mapping, execution or mutation. Existing system-file
reads cover the other three files. No shell or client permission is expanded to
read broker credentials or set mechanism properties.

Bootstrap first attempts `valid=0` and clears all eight digest fields, including
after an individual clear fails. A failed clear returns HOLD. The fixed path
walker rejects symlinks at each parent and leaf, group/other-writable parents, nonregular,
empty, multiply linked, group/other-writable or oversized leaves. Nonblocking leaf open
allows a substituted FIFO to be refused before reading. Each file is hashed
through its descriptor with stable before/after metadata; all descriptors stay
open and are checked against their current fixed pathname again before final
publication. All digest writes must succeed and the held file identities and
root directory must still match before `valid=1` is written. Failure attempts a
complete clear and returns HOLD. This is not a guarantee that a failed platform
property API physically changed the property store.

Consumers must require all eight canonical digests, both valid observations and
the same independently captured boot, and compare them to the newly admitted
candidate. These are sequential fixed-component observations. They do not
establish a hardware attestation, whole partition digest, atomic filesystem
snapshot, producer epoch, semantic request identity, effect completion, or
readiness by themselves. The regular descriptor and byte bounds do not impose a
hard deadline on every kernel or storage syscall.

The host fixture executes the production descriptor walker and hashing code on
actual files, symlinks, hard links, FIFOs, sparse oversized files and metadata or
inode substitutions. A deterministic wrapper performs a real file size mutation
between the production hash's before/after descriptor snapshots. The property
setter fixture checks every clear/write failure and malformed digest, without
claiming to run Android's property service. It also runs the actual native JSON
measurement-profile validator against selected and deliberately changed inputs.

Admission remains pending: full Soong build, strict neverallow-enabled combined
policy with no permissive domains, exact permission comparison preserving prior
denials, source freeze, image generation, AVB/FEC/package audit and a root-owned
bounded phone trial. The existing R54 crash and three protected runtime digests
remain failure or UNKNOWN evidence, respectively.

The same selected source candidate includes the explicit SystemUI tile entry.
The version-5 source profile binds all nine tile, manifest, resource, overlay
and conditional-product source files by literal SHA256. The overlay is selected
only for the enabled native profile, separately from the common package list.
The tile opens the existing workspace after an explicit click and any required
unlock. It does not connect, send, clear inhibition or resume work. Signature,
idmap, SystemUI/client Binder permissions and physical lock/fold entry behavior
still require the newly compiled and admitted candidate.
