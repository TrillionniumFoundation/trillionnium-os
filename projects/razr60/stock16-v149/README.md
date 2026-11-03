# razr60 · Stock Android 16 · v149 source and build record

This snapshot binds the current HEPTA application, native Android control programs,
GNU backend source overlay, Magisk integration, host provider and phone helpers.
It is a source and reproduction record for the **stock Android 16** development
line. The old Android 17 DSU/SystemUI experiments and the separate mechanical
RAZR-SLIDE repository do not define this version.

The application is `org.trillionnium.owneropen`, version code **49**, version name
**1.4.3**, minimum SDK **36**, target SDK **37**. Its placement in `system_ext` does
not mean that the Motorola SystemUI or launcher was replaced by this snapshot.

## Composition and fresh verification

| Component | Source in this snapshot | Fresh result on 2026-11-03 |
|---|---|---|
| Bootstrap, owner ingress, emergency stop | `native/api36/source` | Three independent API36 builds match the installed ELF SHA256 values exactly; 12 compiler/link/strip/readelf commands pass. |
| HEPTA49 Android app | `android/hepta49` | Fresh unsigned build passes. 18 of 19 uncompressed APK members match the installed signed APK. `classes.dex` differs by four compiler-generated enum bridge methods; **not bit-identical**. |
| Desktop entry sidecar v145 | `android/desktop-sidecar-v145` | Fresh unsigned build; all 7 payload members, including DEX/resources/manifest, match the signed installed baseline. |
| Unicode helper v148-r2 | `android/unicode-v148r2` | Fresh DEX JAR exactly matches the installed JAR SHA256. |
| Screenshot codec v148-r1 | `android/screen-codec-v148r1` | Fresh DEX JAR exactly matches the installed JAR SHA256. |
| Visual test probe v148-r1 | `android/visual-probe-v148r1` | Fresh unsigned build; all 3 payload members match the signed reference APK. This is a qualification probe, not the main application. |
| Mac provider v148-r5 | `provider/baseline-v148r5` | Exact prior deployed source retained as baseline. |
| Mac task provider v149-r1 | `provider/v149-r1` | Frozen source manifest and 156 offline checks supplied with the candidate. Root independently reran 157 checks on the Mac, including one additional legacy codec case, then switched the daily provider to this version. |
| GNU owner-open backend | `backend/frozen-intake-v142` and the complete pinned upstream commit | Captured source preserved, with the four production/test overlays explicitly bound. **No fresh GNU core or full rootfs rebuild is claimed.** |
| Magisk module v145 integration | `integration/magisk-v145` | Current service/config/policy sources preserved; generated APK/ELF/rootfs payloads are represented by hashes rather than included. |

The offline provider results establish source-level behavior. They do not establish
a fresh successful end-to-end model task. Root issued one new live health request
after the switch: it completed with `observed_unavailable / usage_limit_exceeded`
in about 9.117 seconds and issued zero phone tools. The original 15 claim hashes
were preserved. Model quota/health and actual phone task acceptance are separate
live gates owned by the deployment record. A process
running, a successful compile, and a completed user task are distinct findings.

## Installed payload identities

| Payload | SHA256 |
|---|---|
| HEPTA49 signed APK | `56c4e302cbe7448dffc9a0d8cfa8db2c2cb019fcb055fab36b815105dd55592f` |
| Desktop sidecar signed APK | `b3da2d3835534b95669429d59488e0edc3a47bab4af4ab95aa68afd1c0810239` |
| Bootstrap API36 ELF | `4ebfa93024056d46c597f4479d53a08335f031d30ca3ca789de73bffc69837b5` |
| Owner ingress API36 ELF | `465b7f964106dc301d485118e5dc6256f94a291687a9425868878fb26a76fbba` |
| Emergency stop API36 ELF | `4ff94cde7050eb4bf67c74a777df2e43f46eb1fc697bef73ae59bfd80416f6f5` |
| Unicode input JAR | `0dedcab0d1a0edcd87e0023bf6809366afb4b6f02f3354db8828ed1b3ecbadc2` |
| Screenshot codec JAR | `bb1176b7707d1a2a67bcfd2bc9bd1b5db16036c3929f8eb1d8820b927ef62639` |
| Existing rootfs EROFS, 40,198,144 bytes | `5b17d4e356525e02ebd9354e74b4a5334678837ccc5a1895b3507eaa01264cda` |
| GNU r5 core inside the retained runtime | `7046846404871ceffe1cc3241fc6aa2da6c281eb8832595dc26b283e307b4031` |
| v149-r1 daily provider source | `44b2f708846447b57cee3a8da0c9c0aee1d250d7e123337fb08d0156b9a31ccc` |

The native source is C++, with API36 targeting and stock16 link libraries. Its
build still uses retained AOSP17 headers. It is not a newly rewritten Rust Android
bootstrap. The GNU Rust core, host process, Python broker and Linux runtime form
another layer, whose source lineage and existing binary identities are recorded
separately.

## HEPTA49 reproducibility limitation

The original signed application's source inventory digest is
`45921011babe2edbb8d09a37d22694c0b54f2661db59e662f95962c261d34b3e`,
which matches the frozen source used for the new build. The original javac
system image (`core-all-system-modules`) had SHA256
`0c6b79c98ed6415dc44fdec2c4741a2b598a75dc75fe69ef61a3d26713633729`.
Its historical Soong output path was absent. A bounded search of the retained
libcore output trees did not locate an equivalent image or core-all JAR.

`prepare_system_modules.py` therefore constructs a new javac system image from
the pinned public `core-for-system-modules.jar` and JDK21 using the AOSP module
construction steps. The new build preserves the original application sources,
resource processing, javac flags and D8 9.3.27. Its DEX SHA256 is
`64c60afd22dc4527332b0f66c37e5a80d70623b6ed9f06b476a38221b0067e1b`,
whereas the installed DEX SHA256 is
`1f81d08c7d45ef0eae47d24d94ff0ae1d846f2818edcef34c33953e7dce2c5dc`.

Normalized disassembly shows four `compareTo(Object)` synthetic bridges present
in the installed DEX and absent from the fresh DEX: `CursorDomain`, `Failure`,
`Role`, and `Kind`. The remaining normalized instructions and source positions
match. This isolates the observed difference; it does not turn the build into
an exact binary reproduction or substitute for runtime qualification. The full
member comparison, original build binding and normalized difference are in
`verification/`.

## Complete backend source boundary

The upstream repository is
`https://github.com/TrillionniumFoundation/trillionnium-os`, frozen at
`4b687742fca939bc32122857f21067ec28d30a23`.

`backend/frozen-intake-v142/source7` is the captured 2026-11-02 intake subset.
It preserves the owner-open default members, but its root Cargo workspace also
names 13 members that are outside that subset. **Do not run a standalone Cargo
build from that subset and call it a complete source checkout.** Use the complete
upstream commit, then apply the exact four overlays in `gnu-core-proposed`.
`backend/prepare_workspace.py` implements that source preparation against a local
Git object database without fetching or modifying the supplied checkout.

The existing rootfs image has a 931-entry image manifest, retained under the
Magisk integration source. This work freshly hashes that existing image and
preserves the source overlay and historical build provenance. It does **not**
rebuild or independently requalify all 931 runtime files. The historical GNU
build script still depends on measured GNU sysroot, Rust toolchain, dynamic
libraries and runtime inputs outside this small snapshot.

## Deployment configuration and privacy boundary

Frozen production source deliberately retains its original bytes. The bridge
contains deployment-specific private-network routing, SSH aliases and selected
device identity defaults; original provenance records contain operator paths.
These are environment bindings. This snapshot is not a claim that another host
can immediately run the deployed system without configuring its own routes,
device selection and independently supplied tools.

No private signing key, credential file, SSH configuration, user session input,
claim ledger, live state database, screenshot capture, or large third-party
rootfs/toolchain is included. Public signing-certificate hashes are retained for
payload identity. Signed APK byte identity is never claimed for unsigned
rebuilds, and this archive does not provide signing authority.

## How to use the record

1. Read `BUILD.md` and the dependency pins before selecting a build host.
2. Check `SOURCE-MANIFEST.json` for the final file list, size and SHA256 of every
   delivered file. The three `*-SOURCE-PART-MANIFEST.json` files preserve the
   earlier source intake identities; the final manifest also covers the new
   reproduction scripts, verification records and v149 provider.
3. Use the dedicated build drivers with a new output directory. Rebuilds do not
   install anything or contact a phone.
4. Review `VERSION.json` and the root deployment evidence before attributing a
   runtime result to a source version. The old frozen upstream CI and historical
   receipts are not current-device acceptance.

The new source drivers are checked separately from the frozen production source.
The native driver was executed successfully; both helper relocation wrappers
were executed and reproduced the installed JAR hashes; the HEPTA relocation
driver was executed and reproduced the fresh r2 payload member-for-member.
Complete GNU source preparation was also freshly executed: 1,453 source files,
407 matching baseline manifest hashes, four applied overlays and 24 Cargo
workspace members. Offline locked Cargo metadata returned all 24 packages and
left Cargo.lock unchanged. This source check does not itself compile GNU code.

The separate provider/v149-r1/qa addendum fixes 19 future acceptance cases:
four real model scenarios, one direct component scenario and 14 negative cases.
It has executed zero cases and performs no automatic scheduling or replay.
