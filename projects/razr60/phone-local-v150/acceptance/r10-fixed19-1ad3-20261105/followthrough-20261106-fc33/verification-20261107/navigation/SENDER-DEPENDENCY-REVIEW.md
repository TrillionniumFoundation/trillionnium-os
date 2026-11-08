# R6 sender dependency and deadline source review

## Result

The exact external UI helper has now been read, independently hashed, and retained. Its next code dependency is already archived in the pinned GitHub source tree and matches the helper's embedded SHA256. A separate, reproducible total-deadline defect was found in that socket helper. A local candidate fixes this property without changing wire commands, numeric budgets, routes, retries, or the frozen R6 source binding.

The original bound01 `137/Killed` cause remains **UNKNOWN**. No new actor or task was launched. No Mac or device was written. This work grants **zero fixed19 credit**.

## Exact dependency chain

Reference Git commit: `ca3f26100c57579bcb740488e4a7f9ec8b912e4d`.

| Layer | Exact source | SHA256 |
| --- | --- | --- |
| R6 business sender | `checkpoint10/R6-business-sender-01/candidate/send_new_native_task_r5_fc33_r6.py` in the followthrough archive | `f90c6ffbf3278b22bf3a48bf055c5ca1cf43c3073c5cc7a852dd09a4cf2eab73` |
| Actual external UI helper | `/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-control-check-Root-v146-r1/control_send_once.py` | `ca200ab35d39ec42232e853c785ab298958858cb4f03e2092231d1ccc638fc70` |
| Pinned socket/route helper | `/home/alex/codex-preserved-ui-root12-materials-20261101-01/preserved_ui_package_phase_r7.py` | `6d7597e55af1ba8330029352076b2c6715172056e6ea28dea97b57c7775fd35b` |

The UI helper is 6,301 bytes. Its actual complete read and file version are in `dependencies/control_send_once.read.original.json`; its byte-for-byte body is `dependencies/control_send_once.py`.

The socket helper is 24,731 bytes and has Git blob `9b9f019ff279ec5a2cf482c389d8b8c9d3cf4dcb`. An exact complete copy is already in:

`projects/razr60/phone-local-v150/acceptance/r10-fixed19-1ad3-20261105/physical-fault-final01/package/reference/preserved_ui_package_phase_r7.py`

The same source is also retained under the followthrough physical-neg03-09 plan reference. The physical-fault source manifest binds its exact size and SHA256. Both the manifest and checkpoint11 public catalog have been retained beside the dependency for review.

The UI helper's computed Git blob `5bb0ab40b1a55ca7b7e018bb1414cb7ff7760f5a` has no standalone match in the non-truncated recursive `projects/razr60` tree `c2b0ad858b6b100c83746509d38846f2940c903a`. This is a claim about the checked Git tree, not proof of absence from every compressed or private archive. Checkpoint11 explicitly publishes a partial source subset and excludes complete launcher graphs and private runtime inputs. Full public runtime dependency closure is therefore not established.

The helper also reads `/home/alex/codex-preserved-ui-root12-materials-20261101-01/preserved-ui-package-config.json` without an embedded content pin. That runtime input was not retrieved. No further custom code is imported in the inspected shell/route path; it uses Python standard-library socket and subprocess APIs.

## What `137/Killed` actually establishes

The sender extracts the pinned UI helper's `sh` and `dump` definitions. Its two literal transformations give the actual initial command:

```text
test ! -e <owned XML path> && uiautomator dump <owned XML path> && cat <owned XML path>
```

`sh` calls `f.shell(..., timeout=25)` once and asserts `rc == 0` before `dump` saves a successful observation or parses XML. The local original-source control confirms that a synthetic `rc=137, stderr=Killed` raises with the same failure object, makes one call, and produces no successful dump receipt. It does not reconstruct a new phone observation.

The socket helper reads the shell-v2 exit frame and returns its payload as `rc`. A local socket timeout raises an exception; the code does not synthesize `137`. Thus the recorded `137` came through the shell exit channel. It does not identify which process was killed, by whom, or why. OOM, external signals, platform timeout, and other explanations were not established and are not claimed.

Neither this helper nor the generated `sh`/`dump` fragment owns or verifies a remote process group. The socket context closes on return or error. That is not a proof that remote `uiautomator` and descendants have exited. No remote PID, PGID, kill, or join evidence was obtained here.

## Reproduced defect and isolated candidate

The original helper applies `timeout` to a socket, then repeatedly calls `recv`. Every successful partial read permits another wait. The route precheck also precedes that socket timeout. Consequently, the argument does not bound the complete shell observation.

The isolated socketpair fixture never connects to an ADB daemon. It streams one small frame every 0.1 seconds with a requested 0.2-second budget. The exact original helper returns success after about 0.405 seconds. The retained baseline report records the complete original result and timing.

The candidate starts one monotonic deadline before the route check and carries it through listener observations, existing-server protocol checks, connect, send, handshake, header/payload reads, and final return. Remaining time is capped by the original per-operation maximum. The existing default `120`, UI caller `25`, route probe `5`, command payloads, ports, and retry count are unchanged.

The candidate is `candidate/preserved_ui_package_phase_r7.py`, SHA256:

`06cab5903387dd10c29ea6fbddb6e4f4e6ceb6e2e3e835de1148619d89e139e0`

`candidate/SHELL-DEADLINE.patch` and `candidate/DERIVATION.json` describe the change. Original source bytes remain in `dependencies/` and existing repo archive copies remain unchanged. No caller hash, runtime manifest, sender pin, BUILD, READY, or source adoption has been altered.

The patch tightens local observation lifetime only. It does not establish remote process cleanup, cancel an accepted effect, resolve bound02 UNKNOWN, or authorize replay. Standalone legacy `route(c)` calls outside `shell` retain their existing behavior; the candidate does not claim to impose a whole-actor deadline.

## Controls and repeatability

| Control group | Result | Scope |
| --- | --- | --- |
| Original navigation conditions | 17 passed | Exact launch/Activity/focus/top-resumed parser and local failure-command fixtures |
| New entry integrity | 2 passed | Source mismatch rejected before import; existing result not overwritten |
| Exact sender dump failure | 1 passed | Original pinned `sh`/`dump` failure flow; synthetic exit137 only |
| Socket deadline candidate | 5 passed | Drip, silence, success, exit137 preservation, expired-route zero connection |
| Full route/host path candidate | 2 passed | Original route/services unchanged; slow route reaches deadline before shell request |

All groups are source controls. Their counts are separate from the product's fixed19 case count.

Navigation rerun, against any checkout or retained source root containing the four exact pinned files:

```bash
python -I -B check_navigation_source_v2.py --repo-root /absolute/repo/root --out /absolute/new-result.json
```

The script verifies all four fixed sizes and SHA256 values first. It then executes only the two required modules from those same verified in-memory bytes, so a later file reread cannot evade the pin. It records source-reference identity without claiming the current checkout HEAD. Outputs are exclusive-create. The original `check_navigation_source.py` and `NAVIGATION-SOURCE-CONTROLS.json` are unchanged; their original hashes are recorded in `evidence-v2/NAVIGATION-ENTRY-INTEGRITY.json`.

Deadline rerun:

```bash
python -I -B reproduce_sender_timeout.py --original dependencies/preserved_ui_package_phase_r7.py --candidate candidate/preserved_ui_package_phase_r7.py --candidate-sha256 06cab5903387dd10c29ea6fbddb6e4f4e6ceb6e2e3e835de1148619d89e139e0 --out /absolute/new-timeout-result.json
python -I -B check_route_deadline.py --candidate candidate/preserved_ui_package_phase_r7.py --out /absolute/new-route-result.json
```

The baseline and candidate run in isolated module namespaces with socketpair peers. Source pins are checked before execution; no source main is invoked. The fixture threads join and all fixture sockets close. These are local resources only.

## Retained state

Only one HeptaRuntime read_multiple_files call was made, for the exact Mac UI helper. There were no HeptaRuntime execution or mutation calls, no phone calls, and no GitHub writes. Bound01's previous wake/collapse/Activity effects remain part of its history. Bound02's unknown outcome remains unresolved and was not redispatched.
