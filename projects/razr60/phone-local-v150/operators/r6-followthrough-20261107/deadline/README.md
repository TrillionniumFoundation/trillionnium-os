# R6 shell-observation deadline source successor

This package is a source-only successor to the exact PR112 inputs. It has not been staged, installed, or adopted into frozen R6. Its actual runtime sender rejects `--execute-once` before opening the request, component plan, preserved draft or retirement input. Removing that lock changes the source hash and requires a separate source revision and complete admission review.

That enforced lock covers the selected runtime sender's `--execute-once` path. It is not a global interception mechanism for arbitrary helper entry points: the retained complete helper sources still contain their existing executable code. Only the selected, locked sender is an entry for this candidate package.

## Exact source selection

The source/evidence base is `22e6105c2effe102c0f120a906752003aedfb37d` in `TrillionniumFoundation/trillionnium-os`. The three original inputs below are already public source files in that exact commit. `DERIVATION.json` records their complete paths, sizes and SHA256 values. `FOLLOWTHROUGH.patch` contains the complete derivation.

| Input | Original SHA256 | Repository source under the followthrough directory |
| --- | --- | --- |
| Socket/route helper | `6d7597e55af1ba8330029352076b2c6715172056e6ea28dea97b57c7775fd35b` | `verification-20261107/navigation/dependencies/preserved_ui_package_phase_r7.py` |
| UI helper | `ca200ab35d39ec42232e853c785ab298958858cb4f03e2092231d1ccc638fc70` | `verification-20261107/navigation/dependencies/control_send_once.py` |
| Actual current runtime sender | `de6c90187ad15995cbd85c662fb7d0a0ee40809bc54d9c1a51c46e164d75b354` | `checkpoint10/R6-root-final01/runtime/source/send_new_native_guard_task_r10_r4.py` |

The complete repository prefix for those paths is `projects/razr60/phone-local-v150/acceptance/r10-fixed19-1ad3-20261105/followthrough-20261106-fc33/`. The socket candidate itself is the unchanged PR112 file at `verification-20261107/navigation/candidate/preserved_ui_package_phase_r7.py`, SHA256 `06cab5903387dd10c29ea6fbddb6e4f4e6ceb6e2e3e835de1148619d89e139e0`.

The runtime sender's inherited SSH target strings and the UI helper's inherited static `expected` example are present in those original public files. They are not newly collected private configuration, a preserved user draft, or the bound02 REQUEST. The actual runtime sender extracts the UI prefix before `expected=` and supplies its separately validated request. This package contains no raw transport configuration, private request, preserved draft, retirement certificate, or original runtime result. Do not execute the UI helper as a standalone program; it is a pinned source dependency.

## What changes

The exact socket candidate carries one monotonic observation deadline through route checks, connect, send, handshakes and frame reads. The UI helper points to a separate prospective helper directory and pins that exact source. It opens the existing transport configuration once with `O_NOFOLLOW`, rejects non-regular, multiply linked, unowned or wrong-size files, reads at most the pinned size plus one byte, and compares full descriptor/name identity before use. It verifies the exact byte length and SHA256, then passes the same verified byte object to `json.loads`. Configuration failure occurs before embedded helper execution and the first route call.

The actual `de6c9018…` runtime sender pins the new UI helper and prospective Mac path. Its source-only CLI lock is explicit; preview output is confined to the new source directory. The separate business sender `f90c6ffb…` is not substituted for the actual runtime entry.

The current transport config pin is 2,416 bytes, SHA256 `310dd82101f2ab309cd790d03f0c01e40cbdfef7064510ea4120327aaac72fef`. The retained read-before/read-after metadata version is `66306:37113588:2416:1793522995998023296:1793522995998023296`, uid/gid 1000, mode `0664`, nlink 1. Only metadata is published here. Those metadata observations describe the original file read; the isolated actor-prefix controls use a temporary filesystem fixture.

No command payload, effect count, model request, one-attempt rule, retirement/draft/selection condition or numeric budget is widened. The inherited SSH subprocess timeout is **660 seconds in component mode and 600 seconds in production mode**. The socket default remains 120 seconds, route probes 5 seconds, UI shell calls 25 seconds, individual wire reads 6 seconds with an 8-second observation alarm, component pre-Send 240 seconds, production pre-Send 150 seconds, and native terminal monitoring 335 seconds. The unchanged source fragments, and both SSH timeout branches, are checked directly.

## Focused controls

Run the following from this directory, using a checkout containing the exact PR112 source references:

```bash
python -I -B check_deadline_candidate.py --repo-root /absolute/repo/root --out /absolute/new-result.json
```

The controls exercise wrong config content/size, symlinks, hard links, file replacement, descriptor identity changes, ownership and regular-file checks, same-byte parsing after a later path change, first-route ordering, and refusal of `--execute-once` before runtime input reads. They also invoke the existing five socket deadline controls and two full-route controls with local socketpair fixtures. No ADB daemon, SSH target, model or phone is contacted.

An optional `--private-config-mcp /absolute/private/original-read.json` runs the unchanged actor prefix against the exact previously read config bytes in a local temporary file. It stops at the first route sentinel and records only hashes, counts and booleans. It does not read the real remote file again, contact the phone, or publish the private body. The synthetic positive control changes only the declared fixture pin; it is identified separately from this original-byte control.

The ordinary G1 `tools/tests/test*.py` discovery wrapper can run these controls without changing any workflow or governance requirement. The package exposes `load_suite(repo_root)` returning a standard `unittest.TestSuite`, for the combined `tools/tests/test_razr60_r6_followthrough.py` entry. A local result remains source evidence; CI on the resulting exact branch head is separate.

## Remaining execution boundary

`EXECUTION-LOCK.json` is blocked. Complete runtime manifest/dependency rebinding, accepted settlement or disposition of original bound02, fresh single-owner admission, and the exact next REQUEST/PLAN/owner remain required. The actual BUILD, installation and four-role READY readers have not qualified this successor. There is no new fixed19, business, physical, cold-boot or USB-independent qualification.

The `137/Killed` cause remains unknown. A local timeout or socket closure does not prove remote process-group cleanup, settle an unknown effect, or authorize replay. This helper does not claim a whole-actor hard deadline.
