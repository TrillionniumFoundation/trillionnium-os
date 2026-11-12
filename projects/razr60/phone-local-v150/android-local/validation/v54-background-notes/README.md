# v54 ordinary-Start background Notes acceptance

Prepared host tooling for one bounded Moto Notes task. **No v54 device task has
been qualified by preparing or testing these files.** The driver requires the
actual signed v54 APK and uses the ordinary visible **开始任务** button. It does
not use `auto_task`, a private nonce, direct broker IPC, or host-generated Notes
actions. The existing foreground navigation driver and its scoring are unchanged.

## Identity and proof scope

The target is versionCode **54**, `0.54.0-local-unified-observation`, with the
frozen controller SOURCE-MANIFEST SHA256
`312140bc0cfd2bc617b32bc7821eaf49a24a4f524c5326c25e955081d4b8bd4f`:
1,362 source members and 186 Android compilation inputs. Production source is
commit `79266ea9ac54e184b69088489f89b5e40fbc95da`, tree
`ad7c0d73899cdaeced03df91bbed524d925fd547`. The Mac compilation receipt names
`824d73ed2e9dc57bc9ecfc6eff340b45cf1d81bd`; that commit only added the independent
host workflow to the same controller inputs. These scripts live beside the
controller and do not change its manifest or compilation identity.

The phone path verifies the signed assembly receipt, APK/UID identity, exact
current LFM3-1.7B QAD Q4_0 / NPU / 8192-context / 4-thread configuration, local
request/session evidence, the real parent `notes.create`, and its bounded
non-model child actions. It replays the observed editor → unique complete list
item → same-item reopen → stable body chain. The final controller terminal,
native process close, broker close, absent journal, and two system observations
must agree. A successful pure replay alone always has `phone_qualified: false`.

This is a Notes qualification with the **main screen idle**. It does not qualify
shopping, cart changes, flights, Stop under load, or simultaneous main-screen
typing/scrolling/app switching. Sequential system snapshots cannot exclude a
transient focus interruption. Persistent database bytes, a new database item
identity, screenshot visual review, and hardware execution counters remain
unverified. The permitted 40-LF editor suffix is restricted to the pinned
observed single-base Moto Notes APK; arbitrary whitespace is not normalized.

## Offline checks

`background_notes_v54_oracle_tests.py` imports only the pure replay API. It
blocks subprocess launches and network connection helpers, mutates temporary
copies, and verifies that the original fixture and harness bytes did not change.
It does not call the monitor or contact a phone.

The recorded validation of harness SHA256
`604f72e2654b777adc4a2a5b079dfcf455873f42681ee780a597994b2fbd86ae`
passed **94 checks**: one unmodified fixture emitted by the real v54 Java
controller under explicit fake Android/native IO, three declared synthetic
positive variants for 40-LF and derived list-summary branches, and 90 rejection
cases. The synthetic variants recompute UTF-16 length fields, body hashes,
descendant-source fingerprints, and parent bindings; they are not phone samples.

The original fixture comes from the strict-host artifact of
[run 43126741363](https://github.com/TrillionniumFoundation/trillionnium-os/actions/runs/43126741363).
Its ZIP SHA256 is
`334cc14b2db745354e073360ed9321ed2e25940b7823c38142e0c57d6dea37a2`.
No fixture or private phone evidence is included here. After obtaining and
verifying that artifact, provide its extracted root explicitly:

```bash
python3 -B background_notes_v54_oracle_tests.py \
  --harness /absolute/path/to/background_notes_v54_acceptance.py \
  --ci-evidence-root /absolute/path/to/extracted-strict-host-artifact \
  --output /absolute/new/oracle-result.json
```

For a newly generated production-method fixture, use `--positive-fixture` with
its exact task directory and `--ci-artifact-sha256` with its reviewed archive
digest. The report records actual paths and every fixture file's SHA256/size;
the test runner does not download or revalidate the source ZIP. The default
positive requires the natural Notes OWNER form with UTF-16 body spans. The
optional legacy-OWNER flag is for a verifier that explicitly supports that
additional form; this narrow phone harness deliberately does not.

The separate author-side API/source/native validation passed 47 checks on the
same harness bytes. Those included the actual exported v51 request/session
receipts and synthetic display-release cases. They did not execute the driver
or qualify v54 on the device. Do not add these host counts to the 103 controller
gate stages as if they were unique phone tests.

## Preconditions for a future device run

The operator must first establish a real handoff from the current owner. For
the existing owner-12 session, the closure receipt is
`/home/alex/hepta-local-007f-20261111/owner-12/OWNER-CLOSED.json`.
The driver does not interpret that handoff receipt. It independently acquires
the existing `/home/alex/.local/state/hepta/razr-operation.lock` using
`O_RDONLY` and `LOCK_EX | LOCK_NB`, and checks the same held file before each
ADB command. A busy lock causes failure before phone contact; it is never
created, replaced, waited on, or forcefully acquired.

Use a **pristine extraction of the frozen controller component** for `--source`,
not a build checkout containing `out`, bytecode caches, or extra generated
files. The source check verifies exact membership, including absence of extras.
The signed assembly RESULT and its actual SHA256 must already be reviewed.
No APK installation, model/configuration change, permission grant, existing
scope deletion, or process cleanup is performed by this driver.

First prepare a new harmless request entirely on the host:

```bash
python3 -B background_notes_v54_acceptance.py prepare \
  --out /absolute/new/notes-request.json
```

Through the ordinary Hepta UI, enter the generated instruction, select the
background option, select only Moto Notes, and select it as the initial app.
Existing root authorization and the formal accessibility service must already
be valid. Notes must have no preexisting task, and all prior Hepta work must be
known idle and cleaned up. Preparation never presses Start.

Run the following only with freshly observed device/ADB/UID values and actual
reviewed files; the placeholders are deliberately not runnable defaults:

```bash
python3 -B background_notes_v54_acceptance.py preflight \
  --source /absolute/pristine-controller \
  --assembly-result /absolute/completed-assembly/RESULT.json \
  --assembly-result-sha256 REVIEWED_ASSEMBLY_RESULT_SHA256 \
  --request /absolute/new/notes-request.json \
  --runtime-config /absolute/current-runtime-config.json \
  --adb /absolute/adb --adb-host 127.0.0.1 \
  --adb-port OBSERVED_PORT --serial OBSERVED_SERIAL \
  --expected-uid OBSERVED_HEPTA_UID --notes-uid OBSERVED_NOTES_UID \
  --existing-su-authorized --out /absolute/new/preflight-evidence
```

For a fresh run, use the same reviewed arguments with `monitor` and a new
output directory. The default waits for the operator to press the existing
visible Start button once. An optional `--start-tap X Y` requires an exact
visually reviewed `--prepared-screen-sha256`; screenshot capture and tap age
also have bounded freshness checks. Neither mode inserts text or acts in Notes.
The request receives a create-only `.armed.json` marker before a possible Start
and cannot be retried. A new request is required after a prior arming, even when
the previous tap outcome is uncertain.

## Failures and limits

The normal monitor allows a 90-second Start window and a 560-second task window
by default, with bounded individual ADB commands. It does not turn a host
deadline into proof that the phone stopped. Unknown terminal state, cancelled or
failed tasks, pending observation work, changed identity/configuration, absent
evidence, or incomplete cleanup leave `qualified: false`. Native `ValueError`,
`UnicodeError`, and `OSError` from invalid evidence also fail closed.

The driver never retries an uncertain action, kills the phone process, or
synthesizes a successful terminal. If the host exits without a RESULT, treat
the outcome as unknown. Use the normal visible Stop if required, retain the
evidence, and confirm cleanup before any next case. Do not run another ADB
operator or `uiautomator` concurrently. Phone output directories can contain
private app data and must not be committed or uploaded as public fixtures.
