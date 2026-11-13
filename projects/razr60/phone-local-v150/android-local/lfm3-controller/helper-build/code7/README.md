# Helper 7 paired source and evidence contract

This directory contains the complete helper7 application source (44 runtime files, 42 Java sources), unchanged observer asset, build input pins and test input closure. The main application compiles only its own `src/`; this helper is a separate package with the original signature permission and separate ordinary App UID.

## Reproduce the Android artifact

Run `python3 build_helper.py --output /new/empty/output`. The script accepts optional location overrides for the JDK, SDK Android jar, AAPT2, R8 and the runtime jar root; the original byte hashes remain mandatory. It performs fresh AAPT linking, javac and D8 and refuses any mismatch from the exact helper7 unsigned artifact:

- 1,375,299 bytes; SHA-256 `f8e623bc95c78c72e3b5af2bc2ba91421667b44be9b666e9ee028df9e886d399`.
- Version code 7; name `0.7.0-web-evidence-v4`; package `org.trillionnium.hepta.webhelper`.
- Original observer `assets/readonly_dom.js` remains SHA-256 `05bb7c1e4e1929b961c42af1e5c0e01918bf6ff64f153132ca11c7d85873e705`.

The 370 unchanged resource/runtime ZIP members are preserved in a hash-bound resource seed. No old application DEX or native library is in that seed. The original resource table is retained, and all seven freshly generated R source files must equal the original pinned resource contract. Three compiled dependency resource archives and all fourteen runtime jar pins are explicit. This is a source build with pinned binary Android/AndroidX build dependencies, not a claim that the Android framework or dependency jars were rebuilt from source.

The original existing signing key was used outside this repository. No private key is included. `SIGNED-APK.json` records the actual qualified signed APK, original certificate and build/signing receipts. The main application's `WebHelperIdentity` checks that exact helper APK hash after reading the installed package bytes; it does not pin its own APK to a circular self-hash.

## ACK authority and cleanup

The main controller saves and synchronizes the complete original request, capture raw bytes and verified reply, then re-reads their identities and hashes before creating a durable transfer proof. Only then can it request retirement of the helper's corresponding redundant capture. The helper binds that ACK to the same task, session, lease, original capture nonce, byte length and hash, and requires the consumed ACK wire hash in its durable lease journal before deleting exactly one typed capture leaf and synchronizing its parent. Unacknowledged or unknown files and lease/close records remain.

ACK does not create an action permit, reset page/lease authority, clear the current in-memory successful capture, or extend the original task or 128-request budgets. The actual client-to-journal-to-helper host test continues through capture → ACK → the original observed-link ARM/action callbacks → a new capture, including the first-capture dual-null expected instance/epoch bootstrap. All Android transport, UID, WebView and directory-fsync doubles are disclosed in the test receipt. These host results do not establish Android fsync durability or business completion.

## Tests and provenance

The main component's `tests/web-capture-ack/` contains the 39/92 ACK chain, 27/113 parser replay and 8 artifact-pin cases. The original helper suites preserve all 87 cases / 754 assertions. Their test source closure is in `tests/retained/` and `tests/installed-identity/`. The one synthetic version fixture follows the current compiled protocol; original phone bytes are never relabelled as helper7.

`tests/actual-helper6-captures.tar.gz` preserves 22 actual helper6 raw captures and their original request/reply triples plus task binding (67 files). Its inventory names the original task and helper/controller versions. They are regression inputs and are not current helper7 action authority.

`provenance/BASE-SOURCE-INVENTORY.json`, the seven exact old changed-source preimages and the original helper6 build receipt bind the 43-file baseline. Helper7 has exactly eight production source changes, including the newly shared ACK proof class. The baseline helper was captured by its complete build inventory; no Git commit identity is invented for it.

All phone installation, migration and acceptance are separate operations and are not performed by these build/test programs.
