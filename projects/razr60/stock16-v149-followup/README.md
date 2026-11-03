# RAZR60 stock Android 16 — v149 validation follow-up

This directory adds validation and cleanup evidence to the frozen v149 source
snapshot. It does not replace that snapshot or change production source.

The source commit is
`029ec7e095865805d6e7e491c4ebabc17c3dee73`; the adjacent
`../stock16-v149/SOURCE-MANIFEST.json` remains
`fe7f23464f535393c3ecead82e33c8a02b458fe43110ae96797b6c8bdc2af8f8`.
That archive contains 344 listed source, build, provenance and QA files, plus its
manifest. Its publication was independently fetched from the public Git branch
into a new checkout and verified 344/344, including all four backend overlays.

## What the new evidence establishes

| Area | Observed result | Qualification |
| --- | --- | --- |
| GNU core reproduction | The fifth isolated attempt compiled the core in 33.772 seconds, passed three QEMU fixtures and produced the exact installed ELF SHA-256 `7046846404871ceffe1cc3241fc6aa2da6c281eb8832595dc26b283e307b4031` | Host compilation and QEMU fixtures; no deployment and no full rootfs rebuild |
| Model failure delivery | An actual new native task ended with `provider_failed` and the explicit `usage_limit_exceeded` classification; no task phone tool was dispatched | Demonstrates error classification and terminal delivery; model availability is still blocked |
| UI cancellation | A fresh task sent and cancelled through the real HEPTA UI produced accepted, cancel.accepted and cancelled terminal records; the child was waited for and its process group was absent | Actual cancellation before any task phone action; cancellation latency was not independently measured |
| Unicode and explicit return | One fresh 33-codepoint / 51-byte input, confirmation and two public UI text views matched exactly; typed return reached HEPTA on display 0 | Direct operator component check with zero model calls |
| Stale action guards | Actual focus, same-app pixel and rotation changes returned exit codes 70, 71 and 68 through pre-input branches | Actual exit receipts plus source control-flow inspection; no independent hardware event counter |
| Preservation | Final read-only checks confirmed the stock Android 16/API36 baseline, source seals, mounted components and restored UI state | A timestamped final-state observation; historical 56-item launcher layout evidence was not freshly re-counted |

The full fixed acceptance set contains 19 prepared cases. **Zero cases have yet
run under that protocol.** The separate component and native lifecycle checks in
this addendum are not retroactively counted as fixed-set successes. No new
successful model-guided business task is claimed.

## GNU build chain

[`gnu-rebuild/README.md`](gnu-rebuild/README.md) describes the existing input
discovery, exact locked dependency recovery, isolation and reproduction procedure.
Its 52 content files are sealed by
[`gnu-rebuild/GNU-REBUILD-MANIFEST.json`](gnu-rebuild/GNU-REBUILD-MANIFEST.json),
SHA-256 `37ebe5149f7f8efc7d44f23fc77eb08e883af870554d01a597c545c9c81db1f2`.

The first three offline attempts stopped at missing locked crate archives. Five
small exact-version archives, totaling 423,738 bytes, were restored into a new
owned registry overlay after their Cargo.lock hashes were verified. The original
registry and source stayed read-only. These failures remain in the evidence.

Attempt four compiled successfully and passed three QEMU fixtures, but its ELF
was not byte-identical to the installed core. The difference was traced to
embedded Cargo-home path strings and alignment. Attempt five restored the
historical path only inside the isolated namespace, without changing the source,
compiler/linker flags or output bytes after compilation. It produced the exact
installed 2,757,408-byte ELF. The original host path remained absent before and
after; real writes were limited to the new session directory. All 1,455 source
files remained unchanged. The historical GNU tree, target standard library and
host-tool identities passed, and the whole tool-input manifest matched.

The current rootfs binding checks the core and eight relevant runtime library
files, representing seven distinct library names. It does not establish a fresh
rebuild of all 931 rootfs entries or of the separate r5 host component. No fresh
core or rootfs was installed during these host checks.

## Phone and host observations

[`live-validation-summary.json`](live-validation-summary.json) contains the
Root-reviewed public summary and hashes of the retained private proof files.
It excludes prompts, unsent draft contents and hashes, claim values, task/session
identifiers, raw phone captures, credentials and the device serial.

The 9.117487-second model-failure measurement runs from the provider model-attempt
start to observation of the structured model error. It is not a UI-click-to-native
terminal measurement. A separate approved direct CLI health request also failed
with the same quota classification after 12.301 seconds and performed no phone
operation. Neither request establishes model recovery.

At the recorded host snapshot, the provider, bridge and watcher were running;
eight provider files matched their seal and two CLI hashes were unchanged. There
were 17 claims, with the original 15 values preserved. All accepted tasks had a
terminal record and all 60 historical plus current spawn rounds were joined; 60
is a cumulative history count, not a count of new tests.

The final phone check confirmed the original boot and enforcing SELinux, with
13 mounted components matching their existing pins. The installed HEPTA49 app,
desktop entry APK and two helper JARs matched their respective existing pins.
HEPTA was foreground on display 0 at 1224 by 2992, rotation 0, with the recorded
rotation and stay-on settings restored. The original unsent draft was preserved
and independently read back without sending it. The Motorola default HOME and
the original 19 quick settings entries plus HEPTA were retained.

The guard checks are conservative: clock, animation or caret changes can cause a
safe rejection. There is still a time-of-check/time-of-use interval between the
last guard and the input command. The evidence demonstrates the observed guard
branches, without claiming hardware-wide zero events or eliminating that race.

Five auditor preparation or parsing corrections are listed transparently in the
summary. They did not change production code and are not mixed into a product
success or failure denominator.

## Measurements and remaining qualification

The three selected processes had single-time RSS samples of 17,552 KiB for the
provider, 16,640 KiB for the bridge and 4,832 KiB for the watcher. These are not
deduplicated physical memory, total-system usage or per-task peaks. Token count,
cost, battery change, per-task peak resources and independently measured
cancellation latency remain unknown (`null`).

The next successful model-guided acceptance run must use the existing approved
channel after its availability returns, fresh per-task challenge/nonce text,
explicit business postconditions and the fixed 19-case recording protocol.
The prepared QA collection does not schedule itself. No account, route or quota
workaround is introduced by this addendum.

## Cleanup and source preservation

The [final cleanup ledger](cleanup/a17_cleanup_sanitized_summary.md) reports
`PASS_FIXED_SCOPE_CLOSED`: 4,763 exact targets covering 3,611,735 filesystem files
were removed across six hosts. Their measured allocation was 173,518,000,128
bytes (161.601 GiB). The fixed inventory has zero remaining unclassified items;
1,677 distinct retained content pins were rechecked with zero changes.

The retained source/assets/configuration and current Android 16 inputs, original
toolchain inputs, source preservation receipts and post-deletion checks are in
the [machine-readable ledger](cleanup/a17_cleanup_sanitized_summary.json).
New audit and preservation storage occupied 1,139,609,600 allocated bytes at the
recorded snapshots. Removed-file allocation and the accounting balance after
that cost are distinct from measured net filesystem free-space growth. One
early batch lacks a final `df` measurement; its value remains `null`. The closure
covers the known project and explicitly bounded development roots, rather than
every unrelated file on every machine.

Old host-runtime or original-device analysis copies are identified as captured
copies, rather than being described as binaries compiled by the A17 project.
Unique source, resources and configuration inside mixed containers are preserved
before a container is eligible for deletion. Actual installed tooling, active
HEPTA state and the current phone are outside that deletion scope.

## Integrity and documentation correction

[`SOURCE-ERRATA.md`](SOURCE-ERRATA.md) clarifies the frozen deployment-preparation
README's test wording. No file in the frozen source snapshot was edited to make
that correction.

From a checkout containing both adjacent directories, run:

```sh
python3 -B projects/razr60/stock16-v149/verify_sources.py
python3 -B projects/razr60/stock16-v149-followup/verify_followup.py
```

The first command verifies the frozen 344-file source snapshot. The second checks
this follow-up's exact membership, byte sizes, SHA-256 hashes, content-tree digest
and binding to the frozen source manifest. Neither executes production code,
model requests or phone actions.
