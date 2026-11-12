# v55 forward integration: strict host and Android build evidence

This packet records strict host checks and unsigned Android compilation for the frozen component tree
`baa8fc181f3fe28063bb1e7bbc8e836c745c7eec`. The source manifest SHA256 is
`1caa51fbbbced802cdea93be8395433a29839743fd16b1c2204ba9bf3f1d711d`.
It is not an assembled/signed APK, installation or phone qualification. Separate
Android compilation passed for this exact source. Original-signer assembly was
still in progress when this packet was published; the phone had not been deployed
with this source. The original host-test receipts retain their host-only scope.

## Inputs

The integration uses v53 at `7dee83d838b2c76b3abe3a3e61d7837316f40853`,
the exact PR #145 helper-identity correction at
`78c464e27133c07d7b74392d18773581e6f182ae`, and PR #144's observer/configuration/
completion changes at `7079f2eb499368c302aac00ca38099239a89519e`.
The source manifest covers 1,376 members excluding itself, with 201 production
build inputs. The local component-only integration commit recorded in the
receipts is not a full-repository GitHub commit; the component tree binds the
source across publication.

`SOURCE-PRESERVATION.json` verifies that all 45 v53 native members are unchanged,
all 23 v53-added members remain, the only changed v53-added member is the exact
PR #145 WebHelperIdentity blob, and the v54 observer-worker section is unchanged.
`PATCH-REPLAY.json` records independent Git-index replay of both supplied base
patches to that same component tree.

## Results and scope

`HOST-CHECKS.json` is the exact original aggregate receipt: 105 top-level checks,
all exit 0, with a complete map of 406 host inputs. It used the existing complete
JDK 17 (`javac 17.0.21.0.3`); the full gate ran for 217.55 seconds. Source closure
passed both before and after. `HOST-INTEGRATION-RESULT.json` is the original
driver receipt; `HOST-DRIVER.py` is the exact host-only driver that executed it.
Host paths in these originals identify their actual execution environment.
There are no private phone tasks, screenshots, prompts, user-app captures or
model/runtime binaries in this packet.

The observer fixture passed 31 cases, including simultaneous Web/observer
admission fences and combined observer/display/Web recovery requirements. Its
Android graph, screenshot, Web-state and callback IO are explicit fakes; actual
production admission/recovery and observer methods execute unchanged.

The broker fixture passed 208 assertions: four supported plans admitted and 48
unsupported mode/flag combinations refused before Intent mutation or a fake
launch endpoint. `LAUNCH-CALLSITE-NEGATIVE.stderr` records the expected assertion
when exactly one real production `requireIsolatedTaskLaunch(taskPolicy)` call
was removed in a separate two-file source projection. Both variants used
`--release 8 -Xlint:all -Werror`. The task metadata counterexample is synthetic;
no Android task migration was reproduced on a phone.

Owned-worker cancellation passed 11 cases and 67 assertions. The real synthetic
host child exited after 4,315 ms with exit 143, one termination call and no force
call. No proprietary SDK, model, accelerator or Android process was executed by
that test. The C native checks use the existing host fixtures, not the phone SDK.

The aggregate's legacy non-Web tests use a type-only WebFlightDomain fixture.
They do not qualify Web business providers. Complete source retention and host
checks are not a substitute for the separate actual Android/Web gates.

## Unsigned Android compilation

`ANDROID-BUILD-RESULT.json` and `MAC-BUILD-RECEIPT.json` are the exact separate
macOS build originals. The build completed with exit 0 in 22.826 seconds and
201 production inputs; every input hash matches the frozen component. Source
closure passed before and after. The complete 98,545,327-byte GenieX archive
and its 16 selected libraries were verified before and after linking.
`ANDROID-BUILD.stderr` contains only two deprecated-API notes, not a compile error.

The actual NDK is r28b / 28.1.13356709 according to its source properties; the
retained directory name 28.2.13676358 is not the toolchain revision. The build
used the existing complete JDK 17, Android platform 34 and build-tools 34.0.0.
No dependencies were downloaded by this build.

| Fresh unsigned output | Bytes | SHA256 |
| --- | ---: | --- |
| DEX | 882264 | `bd89d731a3c3f1360c0f59f321e39154cf8fc221b7de54b605486b3c2007d269` |
| Resource base APK | 3408 | `b3f14e4e04983f30b2aae8a7eb52290e5c32978696c0b84122d4a8bf85bf77f9` |
| arm64 native worker | 59952 | `eeded3063bcbd28ce560ce11295391495e42a6b3b7a8a3e4abe6e5478a103ab5` |

The compiler receipt SHA256 is
`c0345e6bb9997baa0d73490d4f06ef175a3ac74c77c5ef94a1c68d42198d7402`.
These outputs still require complete runtime packaging and original-signer
assembly. Compilation does not demonstrate model/SDK execution, acceleration,
healthy cancellation or phone effects.

## Reproduction and remaining acceptance

From the frozen component, with an existing complete JDK 17, Python 3.10+ and C
compiler, run `python3 -B tools/verify_source.py`, then
`python3 -B tools/run_host_checks.py --out /absolute/new/output`, then verify
source closure again. The standalone driver records the original seed/overlay
verification and negative mutation; it is environment-specific execution evidence,
not a deployment tool.

The old installer, current installed-APK pins, ownership lock and private phone
state were not modified. Same-signer assembly and the ordinary operation owner
lease remain required before any phone upgrade.

Phone acceptance remains open for this exact source: Notes completion,
accelerator placement, SDK/native and Web cleanup, interruption/display loss,
cold reopening, and concurrent main-screen typing/scrolling/app switching.
Flight-result and shopping completion providers are still absent. Action-side
graph/identity/Binder checks remain synchronous on the main looper and can still
delay Stop. The stricter launch gate narrows supported launch modes and does not
establish isolation for later target-app launches or same-app user races.
