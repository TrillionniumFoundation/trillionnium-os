# HEPTA provider v149-r2: bind the actual CLI executable

Status: the code and local process fixtures are qualified on main (macOS) and
pocket4 (Linux). This candidate has not been deployed. No phone or model call was
made for this change, and it does not qualify a complete model-driven phone task.

## Why this change is needed

The deployed v149-r1 provider pins the 328-byte Codex launcher and checks its
metadata before each round. That launcher delegates to a 267754128-byte bundled
program. An application update can replace the program without changing the
launcher, so the previous guard does not bind a decision to a fixed executable.

The added regression uses a real disposable local process. It leaves the launcher
unchanged and changes the program behind it. The final regression fails against
the frozen v149-r1 source because the changed program is launched. It passes
against this candidate with zero launches and the service marked to stop accepting.

## Runtime behavior

At startup, qualify both the selected launcher and its bundled program by SHA-256,
with file identity checked before and after hashing. The fixed, already reviewed
launcher determines the program path. Before each model round, check both files'
device, inode, size, modification time and change time. A missing or changed file
stops admission before recording a spawn intent or issuing a model attempt.

Invoke the qualified program directly with the existing arguments, account,
selected model, sandbox, feature restrictions and timeouts. Record both the
requested argument digest and the actual argument digest, plus the complete CLI
binding, in each spawn intent. The ready record exposes the same binding while
retaining its transport-only readiness scope.

The binding is an operational source/version control, not a protection against a
privileged actor replacing a file in the interval between the final metadata check
and execution. The original process-group cleanup, cancellation, quota
classification, at-most-once claims and one-use task contracts remain active.

| Input | Fixed value |
| --- | --- |
| Base source snapshot | TrillionniumFoundation/trillionnium-os at 0152dc425b6eec188dfd0efdd62aa004b59c76c5 |
| Original provider prefix | projects/razr60/stock16-v149/provider/v149-r1 |
| Original source publication | 029ec7e095865805d6e7e491c4ebabc17c3dee73 |
| Launcher SHA-256 | 50ab38ba21d0d9f8346f32f41848382f15b556190f3c7a07e885a4fb73e379c8 |
| Bundled executable SHA-256 | 58a91f6ea19bea477ae3a2ec48d619f0039afe75d3476260747e11d201fa7cea |
| Candidate daily_provider.py SHA-256 | f14dad67147fd9c66dc42ad36222c94da35418fee64761e9843871abdfbdf3bb |
| Approved model | gpt-6.1-sol |

The main host verified both actual installed entrypoints with bounded --version
calls. Both returned codex-cli 0.166.0-alpha.5.1. These calls made no model request.
The other seven production source files retain their original bytes and pins.
The original source/follow-up manifests and their frozen directories are unchanged.

## Validation and retained failures

Run from this directory:

    python3 -B tests/test_cli_binding.py
    python3 -B tests/offline_v149_checks.py
    python3 -B tests/offline_phone_tools_checks.py
    python3 -B tests/offline_capacity_race_checks.py

Both hosts passed the 9 new tests and all 96 + 35 + 25 original offline checks.
The image fixture uses macOS sips or Pillow on Linux. These are synthetic local
fixtures, with zero real model calls and zero phone calls.

The new controls cover a replaced underlying program, a changed launcher, a
missing program, exact direct-program argv and receipt binding, wrong startup
hashes, a change during hashing, an unqualified argv program, and cancellation
before launch. The original quota-stream fixture only gains the explicit fake
program identity that the production startup now supplies.

The evidence retains the final-test baseline RED result and the first candidate
attempt. That first attempt exposed test-fixture mistakes: macOS /var versus
/private/var canonical paths and a bytes-hash helper called with a Path. The
fixtures were corrected; the production implementation did not change after that
attempt. The final test file was then rerun against the original source to confirm
the same RED result, and against the candidate on both hosts to obtain GREEN.

An initial main-host Git fetch timed out after its original 600-second bound with
no log output. Source materialization then used the GitHub connector at the exact
commit, and independently verified all 13 fetched Git blob identities before
testing. No credentials or global Git configuration were changed. That fetch is
not counted as a successful checkout.

## Deployment boundary

Deploy all eight source files together under a new version, preserving the current
state directories, all 17 retained identities, task bindings and original receipts.
The single phone/mainline coordinator must verify there are no unfinished rounds
before switching the provider and bridge source pins to the new version. Never
delete a claim or replay an accepted task to make a restart pass.

If the installed launcher or program changes, the new candidate must be reviewed
and qualified with new explicit pins. Do not update these constants automatically.
A provider restart does not imply that the approved model has quota.

The last observed model availability remains usage_limit_exceeded. The fixed
19-case live acceptance set, new complete visual/Unicode model tasks, native
in-flight recovery scenarios, and wider display/posture support remain separate
gates. This executable-binding fix supplies no new PASS for those gates.
