# R52 ordinary ownerclient emergency stop

This source change depends on the R51 owner integration at
`21c8274758d2c0af258aa529111a44ec8c43055b` (PR #99). It does not replace the
R51 frozen source, images, controller, or phone. The selected v4 runtime profile
has the explicit new revision `2026-10-09-leap-api37-owner-client-emergency`.
Its compilation, packaging, signing, and physical-device evidence must be bound
to a new candidate generation before deployment.

## User action and protocol

The ordinary, non-privileged OwnerOpenShell has three separate controls:

* **Emergency stop** asks for confirmation and creates a new operation ID. It
  immediately inhibits local normal operations and submits one bounded control
  request. A later, separately confirmed press creates another ID and requests
  another mechanical stop, without repeating a model request or prior effect.
* **Stop status** sends a read-only correlated status request. Recreation,
  disconnection, timeout, or status never resends the saved Stop request.
* **Allow new turns** initializes missing or unreadable local control state only
  after an exact correlated native status reports no inhibit and no memory
  fence, followed by a successful local preference commit. It cannot clear a
  known local emergency intent or the native inhibit file. It sends no turn and
  requires a separate Reconnect before normal communication.

All selected normal clients now send `ingress.connect` as their first frame.
The native ingress accepts only the existing dedicated ownerclient SELinux
domain (including valid MCS suffixes), with kernel `SO_PEERCRED` UID >=10000.
Control uses the same admitted socket, not a shell property setter or a private
state-file read. The first control frame has schema
`org.trillionnium.owner-open.ingress-control.v1`, version integer 1, and a
4096-byte bound including its newline. Duplicate, unknown, wrongly typed, empty
operation-ID, or malformed fields fail closed. IDs are `[a-z0-9-]{1,96}`.

There are 32 normal connection slots and 64 independently bounded pending
handshake/control slots. A full normal pool does not consume the reserved
control pool; the bounded control pool can itself be exhausted. The client has
independent single-worker Stop and Status queues, each with one waiting slot,
and one five-second deadline after descriptor creation across connect/write/read.
This deadline does not include time waiting in the Stop queue. Queue
rejection, timeout, or process death leaves delivery unknown; there is no retry.
The deadline shuts down both socket directions before closing.

## Memory fence, persistence, and cancellation

The native Stop path takes the short admission lock and publishes its memory
fence first. It requests the fixed typed Android stop property before storage
publication. Filesystem observation/fsync does not hold the send-fence lock.
Normal writes check the fence again inside that lock; bytes already forwarded
before Stop remain an unknown prior outcome.

Each new explicit operation ID can make one property attempt per ingress
process. The 4096-entry deduplication set is bounded and never evicts IDs.
Duplicates or capacity exhaustion cannot trigger another property attempt.
Status never requests the property. Deduplication is process-local, so the
protocol is not an exactly-once durable cancellation journal; an ordinary
client never replays a stored request after restart. A new explicit Stop can
retry mechanical cancellation even if a previous property attempt failed and
the inhibit leaf already exists.

Android init handles the typed property in this exact order: clear readiness,
stop its tracked bootstrap service, execute the emergency helper, then reset
the request property. The ingress remains available while runtime readiness is
false and after Stop. The ordinary client cannot set any property directly.
No service order, mount, extra service, or policy grant is admitted by the exact
source/profile gate. The selected profile binds all five policy source hashes.

The shared store publishes the fixed root-owned `0600` leaf
`/data/trillionnium/owner-open/state/emergency-stop` below a verified root-owned
`0700` directory, using no-follow/create-only operations and file plus directory
fsync. It never unlinks or replaces a malformed leaf. Any present leaf,
including partial creation or a symlink, inhibits admission; inaccessible state
is unknown and also inhibits admission. Bootstrap observes this fence on
restart. There is no ordinary resume or marker-removal endpoint.

The result always reports `process_quiescence=unknown` and
`prior_effect_outcome=unknown`. `stop_requested=true` means the property request
returned success; it does not prove Android cgroup cleanup, provider cleanup,
rollback, or completion of an already accepted effect. Durable inhibit is
reported only when the publication checks/fsync succeeded. A status observation
of a present leaf does not by itself prove successful mechanical cancellation.

## Activity and process limitations

Confirmed Stop runs on a process-level executor so Activity destruction does
not discard a queued request. Short in-process locks fence a concurrent normal
dispatch and prevent an older initialization callback from replacing a stopped
client or clearing its operation ID. Folding during pending initialization
restores an unavailable local state, not the temporary initialization token;
explicit refresh can expose already committed initialization without sending.

Local Stop preference persistence is deliberately **best effort** and runs
separately from the urgent request. It can fail, block, be rejected by its
bounded queue, or be interrupted by process death. If an older durable `armed`
preference survives a failed Stop commit and the process dies without its
Bundle, the next process can read `armed`. Therefore local preferences do not
guarantee cross-process delivery or inhibition. A successfully published native
inhibit still independently refuses that process's normal connection. If both
local persistence and native delivery/publication are unknown, the product
must preserve that uncertainty and require manual coordination; this change
does not manufacture a durable cross-process Stop transaction.

Missing preferences, read exceptions, or missing/untrusted control status fail
closed until explicit initialization. Saved Activity identity/history does not
authorize effect replay. Session/task/turn/draft/history currently use the
Android saved-state Bundle; durable semantic identity and event cursor across
process death are a separate P1 gap.

A minimal follow-up should store only versioned session/task/turn and a
validated durable event cursor, keep unacknowledged outcomes unknown, and
provide explicit inspect/reconnect recovery. It must not store a broker token
or long-lived credential, infer success from transport delivery, reuse a saved
turn for a new user message, or automatically replay an accepted effect. That
follow-up requires its own reviewed source and receipt binding.

## Host evidence and reproduction

Run the source/behavior fixtures with a JDK, C++ compiler, JsonCpp development
headers/library, and libselinux development headers/library:

```sh
python3 -m unittest -v \
  tools.tests.test_verify_owner_open_android_source_closure \
  tools.tests.test_owner_open_bootstrap_manifest_contract \
  tools.tests.test_owner_open_ingress_contract \
  tools.tests.test_owner_open_android_client_reconnect \
  tools.tests.test_owner_open_android_shell_state \
  tools.tests.test_owner_open_emergency_control \
  tools.tests.test_owner_open_android_emergency_client \
  tools.tests.test_owner_open_host_relay_emergency_disconnect
python3 tools/verify-owner-open-android-source-closure.py --json
```

The native control fixture executes production C++ with real files/socketpairs
and explicit host substitutes for Android properties. It covers strict parsing,
Java-to-native first frames, native-to-Java initialization status, concurrent
Stop deduplication, partial/malformed leaves, property failure plus a new
explicit mechanical retry, persistent fence recovery, bounded reservations,
and storage stalls after the memory fence. Java fixtures compile the actual
Activity/Client/Frame, but substitute Android mechanics and preferences.
One case explicitly demonstrates the old-armed/failed-commit/process-death
limitation rather than claiming guaranteed persistence.

The optional real accept/Pump fixture is excluded from the default CI source
matrix. On an explicitly trusted host with passwordless sudo, opt in with:

```sh
OWNER_OPEN_RUN_TRUSTED_ROOT_PUMP=1 \
  python3 -m unittest -v tools.tests.test_owner_open_emergency_pump
```

It copies production ingress with four isolated fixture addresses, uses true
kernel UID0/9999 rejection and UID10001 acceptance, and separately labels
UID10002 as an untrusted peer through an explicit host SELinux-context stub.
It observes 32 actual broker-authenticated sockets and 32 EOFs after Stop.
Its Android property substitute kills only its owned host broker fixture.
An additional same-process direct Pump pauses broker hello, blocks fsync, and
observes counters `normal/pending = 1/0 -> 0/1 -> 0/0`. Forked production-main
cases explicitly do not claim observations of their child's private counters.
These measurements qualify transport/fence mechanics, not Android policy,
init/cgroup behavior, Host/Core effects, or a phone.

The host relay fixture uses the real adapter with a finite host fixture child
instead of Codex. Transport EOF terminates that owned child, retains the
accepted semantic claim, and refuses its redispatch on a replacement stream.
No fixture invokes a model, reads Codex credentials, or performs an external
effect. The API37 receipt checks aapt resources, public Android classes, and
Java source compatibility using `javac --release 17` with the host JDK's
`java.base`; it does not check Soong's core bootclasspath or D8/desugaring.
Separate SDK resource/Java and isolated ARM64 object compilation receipts are
narrower than a linked Soong APK/native-module build.

## Physical qualification still required

Before any R52 deployment, create a new frozen source generation and perform
full Soong/native linkage, platform policy compilation, APK signing, image
inclusion, and the existing hash-bound admission/rollback process. The R51
candidate and its approval remain separate.

Phone qualification must observe the exact new package/profile and unchanged
strict policy, then test explicit controls while unready and ready, wrong
UID/domain and obsolete client refusal, an in-flight reversible task, true
bootstrap/provider termination, lost response, storage fault, disconnect, fold,
Activity recreation, and process restart. Stop status must not replay; a second
confirmed Stop must have a new ID. Readiness, marker persistence, and process
quiescence need separate evidence. Keep uncertain journals for reconciliation
and prove no automatic model/effect redispatch. Removing a native inhibit or
claiming reversal of a prior effect is outside this ordinary-client protocol.
