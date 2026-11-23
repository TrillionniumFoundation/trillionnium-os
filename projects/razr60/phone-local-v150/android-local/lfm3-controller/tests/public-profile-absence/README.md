# Public profile current-absence recovery

This gate exercises the narrowly scoped recovery of an expired public display
lease for managed profile user 10 before business dispatch. It preserves the
original failure, including `cleanup_known=false`. It does not establish that
the old broker never created a virtual display.

## Production contract

The ordinary **清理上一次后台空间** button remains the only app entry. Its existing
main-thread recovery epoch, serial session writer and drained service checks
exclude ordinary Start and unfinished observation/action/native cancellation
work. A separate typed receipt handles public recovery; the original private
prelaunch and postlaunch receipt branches remain private.

The request binds seven complete original byte strings: the current lease,
owner, bootstrap, final cleanup, final task result, broker output receipt and
broker output bytes. Immutable task/OWNER/profile/public-scope/UID/generation/
boot/deadline facts must agree. The original producer must have observed the
broker's owned Java Process exit and complete bounded output. The final task
records must show no model process, model/action steps, app launch, permission
preparation, submit/fixed-intent attempt, or unfinished task work. The early
bootstrap record's process-exit observation can legitimately be false; the
later final cleanup record supplies the observed exit.

The new checker owns only read operations. It uses the existing complete `/proc`
census, fixed boot-count command, PackageManager identity reads, Binder root-task
arrays, complete Binder recents dumps and public physical-display audit. It takes
two resource samples and verifies physical displays 0 and 1 during this recovery
interval. An unknown/partial/mismatched sample rejects. A same-name display at
any ID, any user-10 live task, a target-app recent task, an active or ambiguous
foreign user-10 recent task, a visible old creator, a changed physical projection,
a changed installation or an expired request rejects.

The v2 proof distinguishes owned-resource absence from an empty profile history.
Complete recents dumps are reparsed through the public-only
`PublicProfileRecentHistory` policy. Dormant foreign user-10 history may remain,
and its actual `profile_empty` value is retained. Both full raw dumps and derived
identity fields are bound. All nonowned history, record order, hidden labels,
tokens, task IDs, user/UID, root/display, components, affinity, flags, activities,
and absolute `lastActiveTime` must be preserved. Only naturally increasing
relative inactivity age may differ, bounded by the actual two-sample monotonic
interval plus two seconds for integer reporting boundaries. No record is filtered away to manufacture
an empty profile. Old v1 proofs cannot enter the v2 receipt path. The original
private profile policy remains unchanged.

The current recovery APK's PM UID, canonical APK bytes and signing identities are
bound separately from historical broker records. No current APK path is used to
reconstruct the historical broker command digest. The compressed request has a
bounded decoder and canonical re-encoding; the client additionally limits the
entire root command to less than 60,000 bytes so the unchanged 65,536-byte proc
cmdline census can inspect its own checker and su parent without truncation.

A successful owned checker exit/EOF is not sufficient by itself. The app first
archives every original byte string and a distinct recovery receipt, rereads
them, repeats the ordinary UI epoch/service checks, and compares the current
lease's file identity and complete bytes with the captured lease. Only then does
it retire that background lease. The original task result, bootstrap, cleanup,
broker output, runtime configuration and other leases are not rewritten.
Existing normal close behavior remains available before the lease expires.

The receipt states `historical_creation_unknown=true`,
`current_absence_verified=true`, and
`recovery_interval_physical_unchanged=true`, and
`foreign_dormant_history_preserved=true`. It does not synthesize a broker
RELEASED response or grant automatic resume. The separate existing interruption
acknowledgement flow must still prove its own model/session cleanup before a new
idle session can be installed.

If the new checker fails, a separate bounded attempt record preserves its actual
output/exit/EOF and any validated diagnostic error code. That record explicitly
has `cleanup_known=false` and `lease_retired=false`.

The final byte comparison is a compare-and-retire operation within the existing
single app writer protocol. It is not claimed to be an atomic transaction against
an unrelated privileged external writer. No arbitrary shell command or package
mutation parameter is accepted by the new checker.

## Host gate

```sh
python3 tests/public-profile-absence/run_host.py \
  --source /absolute/candidate/source \
  --java-home /absolute/jdk17 \
  --json-jar /absolute/json-20240303.jar \
  --output /absolute/new-output-directory \
  --actual-originals /absolute/archived-task-and-history-fixture
```

The default gate compiles the actual policy/client/lease code with `--release 8`
and the pinned org.json jar. The original producer records are real archived
8311 bytes; the framework resource samples, current installed-controller identity,
Android transport, PackageManager and clock are explicitly synthetic. They are
never counted as phone or Android runtime qualification. The optional
`--java8-syntax-only` flag is only for a draft JRE compiler without `ct.sym`; a
final gate must omit it.

The producer fixture filenames are `background-session.json`, `owner.json`,
`background-bootstrap.json`, `background-cleanup.json`, `result.json`, and the
original `background-broker-<generation>.json` and `.bin`. The seven original
digests are recorded in the result. The same directory additionally contains
`before-recents.txt` and `after-recents.txt`, two complete archived 9,654-byte
recents observations with separately pinned hashes. Their foreign dormant task
is retained; they are not claims about a fresh runtime observation. These are
external private audit inputs; their files are not embedded into the source tree.

The tests cover a valid current-absence result despite historical creation
remaining unknown, source/owner/scope/target changes, task/model/native effects,
TTL/boot/deadline, partial resource samples, retained tasks/processes/displays,
physical changes, private/public receipt separation, old-generation/request
replay, EOF/exit/output failures, durable receipt and archive failures,
same-bytes inode replacement, changed lease after receipt persistence, failed
unlink, and each independent service worker/web admission gate. The unchanged
legacy profile and proc-census cases run alongside the new tests. The original
generic background gate retains its original JSON fixture and runner.

The v2 cases also reject old whole-profile-empty proof schemas, missing history
preservation, raw/derived history tampering, changed foreign task tokens,
absolute activity-time changes, active foreign profile tasks, and reverse
or excessive inactivity age. The archived observations show four seconds of age
growth; the fixture therefore uses an explicit synthetic 4,008 ms sample interval,
within the unchanged 12-second request lifetime. A complete proof made from the actual archived history must
fit the existing bounded checker output; oversized history is refused.

Successful host tests are necessary review evidence. The installed app's normal
UI must still obtain a fresh real checker result and durable receipt on the
phone before any lease is considered recovered.
