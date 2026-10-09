# Razr API37 Codex host relay candidate

The selected owner-open-core graph keeps Codex as the sole semantic principal.
The phone runs the real Rust R5 Host/Core, Python broker/supervisor, shell and ADB.
Codex and its long-lived authentication remain on the authorized host. This is
an explicit dogfood device variant; the older phone-Codex thirteen-path profile
and Authority/Lease/P01/typed Accessibility graph remain unselected and false.

Select `TRILLINNIUM_LEAP_OWNER_OPEN_PROFILE=codex-host-relay-v1` with
`trillionnium_leap-cp2a-userdebug`. Runtime is disabled unless
`TRILLINNIUM_LEAP_OWNER_OPEN_RUNTIME_ENABLED=true` is deliberately supplied.
The source JSON claims remain conservative; actual compile, inclusion and
physical-device observations belong to separately hash-bound receipts.

## Kernel and lifecycle

The measured XT2551-3 kernel supports EROFS, xattrs and loop devices with 4K
pages, but has CONFIG_SQUASHFS disabled. This variant consumes a genuine EROFS
LZ4HC image with default zero-padding. It does not change boot or kernel.

`build_owner_open_erofs_release.py` consumes the exact staged manifest, creates
two independent normalized copies, builds both with a pinned mkfs hash, and
requires identical image bytes. Each inode has uid/gid0 and explicit mode and
SELinux label. Immutable directories/configs use payload_file; executable
regular files use payload_exec. EROFS per-inode xattrs preserve this split,
avoiding forbidden mounton of an exec_type directory or context= overriding it.
The measured payload inode times are epoch0 (source normalization and
SOURCE_DATE_EPOCH clamping), rather than inferring inode times from -T alone.

Only Android init creates/chmods/restores the private directories and owns
EROFS, state, same-PID-namespace proc and device bind mounts and teardown.
Bootstrap has no mount/unshare/loop operations or SYS_ADMIN. It verifies the
hash inventory, filesystem/flags and bind inode identities before chroot.
Run-mounted never chmods a read-only lower. Readiness requires this exact new
supervisor PID/session, private broker socket/token, the current broker and Rust
Host process generations and the actual Host hello.ack with runtime_ready=true.
The ADB relay must have published its actual loopback listener descriptor with
a matching live process generation. Readiness uses no semantic provider probe.

The R52 ordinary-client emergency control first fences normal writes in ingress,
then requests the fixed typed stop property. Android init clears readiness and
stops its tracked bootstrap service before executing the helper, which fsyncs
the inhibit file and its parent. It never reads a persisted PID or signals a
numeric PGID. The result keeps process quiescence and prior effects unknown
until separately observed. Bootstrap retains its child
with waitid WNOWAIT while forwarding signals, blocks forwarding before reaping,
and clears the PID before signals resume. The supervisor's durable session fence
requires offline reconciliation after uncertain cleanup; it does not replay an
accepted effect. Unknown accepted calls/jobs stay unknown on journal recovery.

The new source generation and the best-effort local preference limitations are
specified in [R52 ordinary ownerclient emergency stop](r52-owner-client-emergency.md).

## Provider transport

`provider_host_relay.py` connects once to explicit IPv4 loopback port18080. The
authorized host supplies the trusted SSH/ADB loopback chain. The adapter checks
bounded, unique-key JSONL and per-direction sequence/terminal order and preserves
the exact accepted bytes. It has no semantic dispatcher, key, fallback endpoint,
reconnection or automatic effect retry. A partial/broken stream ends nonzero
without fabricating a terminal. No executable named codex is placed on phone.

The selected ADB relay listens only on 127.0.0.1:15038 and forwards only to
127.0.0.1:15037. This payload includes the genuine ADB client, not adbd and not an
ADB server service. It does not generate phone ADB keys or open a LAN listener.
The upstream server/Android transport, authorization and any key generation or
persistence require separate explicit device qualification; they are not
implemented or claimed by this candidate. No default listener on LAN port5555
is created. A RootLinux state-file action is a first phone execution probe, not
proof of Android business control.
The provider relay and ADB relay are separate endpoint contracts. Platform
compile and a host Codex loop do not establish phone ADB routing or hardware
qualification.

## Evidence boundary

The 2026-10-08 host run passed 368 locked offline Rust tests (two additional
ignored subprocess fixtures are invoked by their integration tests), a genuine
static AArch64 Host/Core release build, API37 native module linking and full
platform neverallow policy checks. Real ARM64 Python standard-library imports,
ADB version and dash execution ran under user-owned QEMU. The 931-file payload
plus embedded manifest passed independent kernel EROFS full hash/UID/mode/xattr
verification; all403 ARM64 ELF dependency closures passed.

Separate authenticated Codex acceptance ran actual x86_64 Rust Host/Core,
effect/result readback and durable journals, including cancellation before/after
dispatch and terminal-journal failure/restart without repeated execution. This
is host evidence. Whole new Android image inclusion, final mounted-image split
policy/signing, phone startup, UI, cancellation and physical hardware require
their own exact receipts and stay unqualified until observed.

## Dated candidate identities — 2026-10-10

Historical deployment and source candidates retain separate identities. R41 was
an actually deployed temporary engineering DSU. R49 owner
`acf931a7b0c4581fe552a67c04db32b67e86f63b` produced an unsigned system_ext
filesystem (`5ba3986a4c9acc247a8b68f99792fb558201f54f33cd5fa4ef3a5ac6c089c8f5`);
it was not signed, packaged or installed. Later results do not replace those
historical receipts.

The R55 guest, BOOT `85fecdeb-fd79-4a34-987e-11107163f779`, used owner
`082498058e9230a074e770b89a9b737312364d1d` and freeze
`fada3f964f9a211b3df93ea7ec6da3541ed02c2b0a6989b5fc8943e04c8ab8e8`.
Its qualified firstboot/full8 observation did not establish AI acceptance:
the ordinary client's MCS-labelled connection to ingress was denied by MLS,
with zero Send/model requests at that observation. R55 was subsequently returned
to stock, BOOT `bf95778e-63da-48f3-8502-52d8e5683f16`; actual return receipt
`85d90404de53f92ad4d53e1300519cd2afa5adf097b0206f8cf4e4c5be58c8b1`
records that completed return. R55 is a retained runtime generation, not the
current candidate's runtime qualification.

The independent R56 build is owner
`1f776e2ad822984a4dc8e4461c4c8bdbe98ad665`, freeze
`9c87e82d7c44686baa6ecfda04c3c85b35f641a8ab244db8feb6e87314d0927d`.
It adds MLS trust to ingress while the client retains ordinary MCS isolation.
The actual host image audit
`daf660b547051176ad6346042f0d8a69ce7fd52720a34cb34cb2287738f9b0c5`
passed all 17 static gates; its image-derived strict policy is
`848916924a41345c628013d3caec9178ce2940fe57af03ac94f82459a73af15e`.
The device source remains `b8eabdc0ac9e8301871c19084eb0785f4f28b000` and the
platform policy base remains `1ac08940de7b0a82cce8b043cebad81e76559dab`;
Soong `8226dae6633b305e96a0b8a33996f2365ec4402c` and framework_base
`48fe68e00b946ec46b6ecd334e6daf31f5bd65f1` are also fixed build inputs.

The actual engineering signing receipt is
`f645abfe91c0ce88d790994c6ecf6add9ece7b22e9a4aac308f38d1188293bf6`;
independent signed-byte audit
`0d2aaa92f046fa35afdb6c22bb1f8b393aafbae32b79aaec050aca83da8d6bc6`
and canonical four-part package receipt
`20d0b32948ba3fd2c5d6ec7c733211b55dd95b11e33541daa695f7a632c5c24d`
bind ZIP `7f29690f3f39d5f436e1fa6352ab0f4056927b20d2c2845d77f45900676c9c3e`
(3,668,161,104 bytes). Qualification
`1e19287c5c5940eeba9ab16f05a7d4b3f815208915737d206e753d15cf63ccd6`
admits a limited temporary DSU trial; it does not establish OEM trust or P1.
One R56 install and activation reached new BOOT
`83f059a4-170b-40b6-8240-f49131c8ffd9`. Actual firstboot handoff
`897d501df925467ed4719b837d4711db918b0a4a8e5db7fc7a35993ba8e8a8a4`
records completed firstboot, all eight fixed components, the product feature and
property chain, and the 180-second stable process cohort. At this cutoff no
normal Send/model request or AI-driven effect has been performed. AI, remaining
hardware, physical cold start, startup interruption recovery and final Stop
acceptance remain open; this firstboot handoff keeps phone-all-P1 and physical
coldboot false. Permanent flashing remains NO-GO.

The built artifacts remain bound to owner `1f776e2a…`, including after a later
documentation-only commit publishes this dated status. Such a commit does not
rebuild or relabel the signed images. Host, phone and source CI results retain
their exact-generation scope.

## API37 process observation and evidence retention

Only this explicit native profile passes --same-domain-proc-observation. It
requires the exact bootstrap SELinux label at entry. Configured payload
executables have execute_no_trans; ordinary configured carriers inherit that
domain. The supervisor binds each unreaped original-group anchor's PID, PGID,
SID and starttime. An unreadable/mismatched anchor remains HOLD. Non-anchor
EACCES/EPERM observations are counted and skipped within a bounded scan. The
receipt explicitly claims only visible same-domain original-group observation;
escaped or cross-domain descendant absence remains false, including a possible
platform crash_dump transition. It does not add proc access to all Android
process domains. Final init-cgroup cleanup needs actual device proof.

The native ADB relay's output arguments reserve a literal carrier_instance
placeholder under the private state/carriers prefix. The supervisor creates
session/name/random-launch directories with private descriptor-relative mkdir
and parent fsync, preserving prior output files across clean carrier restart.
The placeholder is not shell or environment evaluation and cannot change the
executable. Status binds the exact current instance directory; native readiness
validates the expected session/name/hex prefix and descriptor process identity.
An uncertain retained supervisor session still requires offline reconciliation.

The r3 payload uses the absolute /usr/bin/python3 provider shebang. It consumes
exact staged source hashes, with SOURCE_DATE_EPOCH=0 and normalized inode epoch0
recorded explicitly in the image manifest. Earlier r2 artifact evidence is
retained, but r2 cannot be used as this candidate's direct-exec payload.

## Product integration contract

The canonical default source catalog remains `owner-open-core`. This Android
variant is selected by its explicit product make fragment and runtime profile
configuration, not by an unvalidated extra field in the default profile catalog.

The Razr device product explicitly inherits
`vendor/trillionnium/owner-open/product-codex-host-relay-v1.mk` only when
`TRILLINNIUM_LEAP_OWNER_OPEN_PROFILE=codex-host-relay-v1`. This remains a
userdebug/eng development lane. Runtime selection is an independent explicit
`TRILLINNIUM_LEAP_OWNER_OPEN_RUNTIME_ENABLED=true` value; merely packaging the
modules does not enable or qualify the runtime.

The Android owner client is `TrillionniumOwnerOpenShell`. Its minimal
send/cancel/inspect/reconnect UI is an ingress client of the same provider turn.
Package inclusion, activity launch and launcher/HOME selection are distinct
observations. A compiled client does not establish a phone request/effect/raw
readback/durable-receipt loop. Authority, Capability Lease, P01 and the former
AI Shell are not required predecessors of this selected product. Typed System
API and Accessibility remain in `sealed-typed-android-extensions` with
`activation_allowed=false`; neither a retained source directory nor a successful
legacy test activates them.

The device repository owns the cross-repository integration manifest and
restricted target artifact anchors. That manifest binds the owner source, the
Razr device source, the exact AOSP platform SELinux base and patch, and each
candidate generation separately. The official AOSP remote is never a target for
the local device policy patch. Source patch/bundle custody belongs to the private
device integration change. Proprietary firmware, signing keys, credentials and
raw target/user logs stay outside the public source change.

A deployed engineering userspace candidate, an unsigned host-built filesystem
candidate and a future signed package are separate identities. Changing source
or image bytes invalidates an earlier identity or runtime claim. No historical
boot, source CI or static init-contract result qualifies a replacement image.
Installed-byte measurement, a complete platform boot, registered audio, retained
state across startup/recovery, and same-turn phone effects require separately
reviewed exact-generation receipts. L4/L5 dogfood and L6 release remain open until
those checks pass; `public_release=false` and `automatic_redispatch=false` remain
in force.
