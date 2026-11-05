# Bounded native epoch proposal after actual 902

**Status: design for review only. No epoch code, nonce, lease, reservation, phone
write, new runtime qualification, or case execution is authorized by this
document.** The codec source previews `de120154` / `c48a7637` / `6046772e` and
pure verifier `72450728` remain unchanged. A capacity implementation must be a
separate candidate with its own complete delta, manifest and review.

## Decision and reason

The existing single-chain protocol cannot admit two more completed native
component cases. Actual 902 retains six native boundaries plus non-native 05:
27 inventory roots, including seven fixture roots. Each new native case adds a
case home, an Android executor journal and a fixture root. The first would reach
eight fixtures; the second would reach nine and fail the original inventory
gate. An explicitly absent fixture still consumes its declared root. The native
chain limit of eight would not be the first limit reached.

Neither the constructor, final consumer, source seal nor material builder has a
rollover interface. The existing publisher only creates a directory and record
for a unique nonce. That is not a global head compare-and-swap or a capacity
reservation protocol. Merely changing source pins, taking a new inventory,
deleting an empty fixture, or starting another output directory cannot release
capacity.

The proposed protocol has **one fixed historical epoch and one active epoch**.
It permits no recursive anchors, third epoch, automatic rollover or automatic
retry. This is an explicit change from a globally bounded single chain to a
bounded two-domain history. The old single-chain API continues to reject a ninth
fixture. The new API would separately admit the fixed seven historical fixtures
and at most eight active reservations, while enforcing one global resource
budget over the complete union. It must not be described as “all gates unchanged.”

## Exact historical anchor and its trust boundaries

The anchor is data derived only from completed actual evidence. It names:

1. Actual 902 boundary `6e1d4a34`, closure `ffe4cc50`, inventory `b9da7fdf`,
   runtime `31da1d92`, original reader `396da713`, original closer `9025acca`,
   combination `54b1d9ae`, unchanged policy `f8219f9c` and adoption `52737477`.
2. The entire six-boundary native chain, non-native 05, original five retirement
   records, all historical source identities, all original role identities and
   all 27 complete inventory roots. No historical boundary is rewritten or
   relabelled as qualified.
3. The actual independent host recomputation: all 49 original closure fields,
   137 original host input identities and 160 actual guarded reads, with the
   `6bb0cb51` byte-equality report, `0aba0024` caller receipt, exact audited source
   and real controller termination. This proves the recorded P4 host check; a
   phone reader must not claim to have re-read those P4 paths.
4. The completed 582a/ba515 current-head observation and all wrapper/controller
   originals. The decoded 1,413,595-byte observation `ae3ced37` is an input, not
   sufficient proof without its enclosing complete result. The actual snapshot
   has 2,623 entries, 19,424,531 hashed bytes and 27 roots. These measured values
   are not future capacity guarantees.
5. The separately sealed failed-prelaunch admissions: old e78d/e85 for external
   09 and our first attempt, and the independent Root02 admission for
   `bc0573ad459cecae9884d6a46568621b`. The latter is never substituted by the old
   two-attempt admission. Required phone-side retained failed-attempt paths must
   be enumerated explicitly and charged to the resource pool; they are not
   silently treated as part of the 27-root native inventory.

The dependency order is acyclic: old actual proofs → immutable anchor → new
source manifest → reservation/lease → actual new boundary. The anchor cannot
contain a future new-runtime hash that depends on the anchor itself. The new
runtime pins the anchor bytes; each later lease pins that runtime and anchor.

Every operation must verify the anchor's exact bytes and source identities and
re-read the applicable live originals. Host source execution uses the real,
already verified old material directory; the phone uses the real old case
package. Embedded proof bytes must never masquerade as a file at an old path.

## Preservation of the six shared roots

The six shared roots are mutable during legitimate later cases. Their complete
old inventory cannot remain byte-equal forever. The anchor also cannot become
a manifest that is trusted without live verification.

The comparison is therefore explicit:

- The 21 historical private roots retain their complete subtrees, full file
  identities, directory membership and explicit absence records. No active
  scope may write into them.
- Every old shared file remains present with the same complete row: bytes,
  digest and all nine metadata fields. Old directory identity and old child
  membership remain present. An unchanged child set requires the unchanged
  directory row; a changed set is accepted only for independently accounted
  additions.
- New shared entries must be derived from actual, verified reservation,
  provider/ledger/native/client originals for a particular active scope.
  “Under the shared root” or “under a familiar prefix” is not authorization.
  The complete captured subtree and its closed file set must correspond to the
  verified scope. No missing old file, altered old leaf, unexplained directory
  entry, alien nonce or unclosed writer is accepted.
- The existing `close_component.preserve_inventory` algorithm is a useful
  unchanged primitive: it preserves old file rows and checks every added child
  through `allowed_new`. Its caller must supply the exact admitted addition
  set and retain the existing native, client and ledger original checks. A broad
  always-true predicate would invalidate the protocol.

The next operation compares the current complete union against the last
committed complete union, and also verifies cumulative preservation from the
fixed historical anchor. Shared roots are scanned once per global observation.
Private domains, control records and failed-attempt retained objects have
explicit disjoint membership; aliases cannot be used to avoid scanning data.

## Hard resource limits

| Domain | Proposed bound | Meaning |
| --- | ---: | --- |
| Total epochs | 2 | Fixed actual history plus one active epoch; no third epoch |
| Legacy fixtures / native boundaries | exactly 7 / exactly 6 | Actual fixed original identities |
| Active reservations | 8 | All started reservations, including failed and unknown attempts |
| Active fixture roots / native boundaries | at most 8 / at most 8 | Each is bounded by consumed reservations |
| Combined fixture roots / native boundaries | at most 15 / at most 14 | An explicit new global semantic limit, not the old single-chain API |
| Complete root union | at most 64 | Includes all declared extra retained/control roots; never reset per epoch |
| Ordinary native roots at eight active cases | at most 51 | `6 + 3 * (7 + 8)`; not a substitute for enumerating actual extra roots |
| Complete inventory entries | 30,000 | One counter over the complete union |
| Complete inventory bytes | 512 MiB | One byte counter over all actual file bodies read for the inventory |
| Inventory file / directory | 64 MiB / 20,000 children | Original per-object limits remain |
| Inventory elapsed deadline | 30 seconds | One monotonic deadline; no per-epoch, page or retry reset |
| Snapshot retained files / bytes | 8,192 / 64 MiB | All stored copies and new epoch proof files count |
| Snapshot file / tree depth | 16 MiB / 12 | Original limits remain |
| Snapshot soft / hard deadline | 55 / 75 seconds | New epoch work is inside these existing bounds |
| Native scan / line | 128 MiB / 4 MiB | Original scan limits remain |
| Consumer original / bundle | 16 MiB / 32 MiB | Lossless encoding cannot enlarge decoded allowance |
| Runtime / Root source members | 32 / 3 | No hidden additional executable dependency |
| Consumer source | 131,072 bytes | Reject an oversized derived consumer before publication |
| Role identities / process census | 64 / 4,096 PIDs | Full union, not one independent allowance per epoch |
| Each original process census | 2 seconds | Existing two union censuses and two retired-role censuses remain |
| Lease / listener / prelaunch reserve | 600 / 420 / strictly more than 510 seconds | No extensions |

At eight active native boundaries the role union can reach 49 identities
(`4 + 6*3 + 1*3 + 8*3`). Two union censuses plus the original two retired-role
censuses can perform up to 106 successful signal-zero absence checks. The old
head observation's count of 58 must not be retained as a constant for the new
protocol. The existing limit of 64 identities still applies.

The measured legacy chain verification took 21.4158 seconds; the complete old
observer took 24.6491 seconds. Inventory walking alone took approximately
0.8678 seconds. Therefore the legacy chain must not be re-verified recursively
once per active record inside the same operation. A possible optimization is an
operation-local verification context over exact immutable input bytes, reused
only after complete verification and protected by the original path/FD/full9
bookends. It must not cache live observations across operations, mutate original
modules, skip source pins or suppress final re-reads. This requires its own
review; these timings do not promise that eight active cases fit every phase.

Before dispatch, the preparer must account for the exact current footprint and
the bounded resources reserved for the next scope. If an upper bound sufficient
for the required remaining qualification cases cannot fit the unchanged global
limits, it must refuse before dispatch. Dividing the inventory into two calls
that each receive 30 seconds or 512 MiB is prohibited.

## Reservation, failure and atomic publication

The proposed global protocol uses a fixed epoch namespace and ordinals 1–8.
It introduces no replaceable `HEAD` pointer. A source-reviewed allocator first
checks the complete control directory, the last committed predecessor, global
capacity and the actual current head, then claims the unique next ordinal with
an atomic create-only directory/file operation through a held canonical parent
FD. All contenders calculate the same next ordinal. Only the winner may start
case writes. Existing output, an incomplete claim, a changed parent, an unknown
writer or an unexpected extra ordinal causes refusal, not selection of another
ordinal or nonce.

This allocation serializes only writers implementing the reviewed new epoch
protocol. Old publishers do not understand its registry, so the ordinal claim
must not be advertised as locking out an unmodified legacy workflow. Complete
current-inventory, source/role/endpoint, frontier and original bookends remain
required before each accepted phase. Any foreign write or new old-generation
boundary causes failure/unknown preservation and independent reconciliation;
it is not absorbed as an allowed active addition. The existing actual phone
actor ownership and any existing journal locks still apply, but they are not
substitutes for these checks.

Read-only preflight accepts no fresh externally supplied case nonce. The
atomic ordinal allocation happens before case-nonce generation and binds only
already known data: source generation, boot, exact predecessor, resource
reservation and the real authorizing controller-request identity. After the
ordinal is owned, the coordinator generates one case nonce and writes a
separate create-only IDENTITY record containing that nonce and its exact
nonce-bearing owner request. If allocation loses a race, no nonce has yet been
generated. A crash before IDENTITY still consumes the ordinal and blocks later
work; it never authorizes generating a replacement identity on a retry. A
provided nonce is accepted only for read-only reconciliation of the same
already durable identity, never as an untracked fresh request.

The actual native scope does not exist before HEPTA accepts the request. It is
not filled into the initial reservation or invented from the nonce. The first
real ACCEPTED original establishes a separate create-only SCOPE-BINDING record
that cross-binds the reservation, identity, request and actual accepted scope.
Every later native terminal or publication must prove exactly that one scope
binding. An attempt that never reached acceptance requires independent
prelaunch reconciliation and must not claim a native scope.

All directories and files use no-follow, exclusive creation, owned mode checks,
FD/path identity checks and fsync. A crash after reservation consumes that slot
and blocks further work until the same attempt is formally reconciled. An
unknown outcome never becomes a free slot, an automatic replay, or evidence of
no effect.

A terminal record is published last, after all immutable originals and the
independent closure are durable, by exclusive creation under the claimed
ordinal. The terminal record binds their complete file set and exact hashes.
Failed-but-reconciled attempts remain consumed and retained. A prelaunch failure
may leave no native boundary; it still consumes its reserved ordinal, retains
its actual staged artifacts and requires independent causal and absence proof.
The next native predecessor remains the last real published boundary. No fake
zero-effect native boundary is generated.

The protocol must test two publishers racing for the same ordinal, a replaced
canonical parent while an FD is held, a renamed evidence file, a substituted
inode with identical contents, a pre-existing terminal target and a crash
between body fsync and terminal creation. No ordinary overwriting `rename` or
`replace` is an acceptable fallback for exclusivity. Existing production NEG14
rename and capacity rejection tests continue to run on the actual new daily
source; epoch publication does not count as those tests having passed.

## Source and schema changes that are genuinely required

This cannot safely be implemented only as a pure boundary-reader exception.
At minimum it needs explicit, reviewable changes to:

1. Preparation and admission: exact anchor/source/control schema, complete
   historical and failed-attempt inputs, capacity preflight before identity
   generation, and global exclusive reservation before any case effect.
2. Lifecycle inventory: one shared deadline/counter implementation for the
   complete union. The old public single-domain call and its ninth-fixture
   refusal remain separately testable.
3. Snapshot: two explicitly named chain domains, full retained root union,
   shared once-only capture and all new proof objects in the same capture pool.
   Its original `prior roots <=64` and depth/bytes/deadline checks remain global.
4. Closure: `verify_prior_chain`, `verify_ledger_inventory`, fixture validation
   and capture-origin checks must all consume the explicit epoch structure.
   Reuse the original preservation primitive rather than dropping old roots.
5. Late-boundary reading and publication: a distinct epoch boundary schema,
   active chain bounded at eight, fixed legacy anchor validation, full role and
   nonce unions, and the new reservation/terminal protocol. The old six-record
   native chain remains an original, independently checked domain.
6. Root and host plan preparation: exact source/anchor/generation bindings,
   old admission as history plus independent Root02/current-head admission,
   current material generation and explicit rejection of a missing capacity
   proof. No old “seven literal” inverse claim may hide these semantic edits.
7. Constructor, consumer, source seal, installer and READY inputs: preserve
   both domains and the complete shared17 source/material proof. The consumer
   must independently re-evaluate the epoch relation and union, not trust a
   caller's `capacity_ok` or a normalized historical manifest.

The current codec runtime's three-member delta and 29 unchanged members are
only true for its preserved preview. An epoch runtime will change additional
members and must name them honestly. Its proof view may retain the exact old
67dc/31da history, but that view can never be used as the executed runtime.

## Source revisions after an active failure

The codec change preserves the codec's failed output value; it does not yet fix
the original exit72 cause. A future active attempt may therefore fail.

The epoch may accommodate a later explicitly reviewed source revision without
starting another epoch, but only through a finite, create-only generation
admission record. That record must bind the actual closed failure, its original
package, source files, closure, full evidence and independently verified
preservation, then enumerate the exact successor source delta and its original
reader context. Historical records always use their own real source identities.
No dynamic arbitrary package hash, patched old globals, fabricated `__file__`,
automatic source upgrade or automatic retry is allowed. The number of admitted
active generations cannot exceed the eight consumed reservations. No unknown
future fix is filled into this design.

## Full19 slot consumption and handoff

| Cases | Native epoch slots for their current normal or failed runner path | Actual domain |
| --- | ---: | --- |
| NEG01 and NEG02 component qualification | One per reserved attempt, including failure/unknown | Native component lifecycle, fixture triple and boundary protocol |
| COMP01 and NEG03 | 0 | Sealed release, direct-return/physical-rotation component evidence |
| E2E01–04 | 0 | Sealed production task registration, sender, capture and host closure |
| Physical NEG04/05/07 | 0 | Sealed production task plus fault watcher/actor/original capture |
| Physical NEG08/09 | 0 | Sealed production task plus cancel actor and CPU/original closure |
| Host NEG06 and NEG10–14 | 0 | Isolated host harness namespaces and exact production source generation |

Only the two native qualification paths consume this fixture-chain capacity in
the current fixed19 runner set. Eight active reservations provide bounded room
for those two successes plus up to six failed attempts; they do not authorize
those retries. A read-only preflight refusal creates no case nonce and consumes
no epoch slot. Fresh externally supplied identities are rejected before entering
the attempt protocol. Once an ordinal is allocated, every failure consumes that
slot, including failure before IDENTITY or fixture creation. Every generated
nonce must have its durable IDENTITY record; historical failed nonces remain
forbidden through the separately verified bounded admission inputs. No
unbounded rejected-nonce registry or memory-only prohibition is introduced.

The zero-slot runners still create real provider/client/ledger/executor or
component evidence. Zero slots does not mean zero effects, preservation of a
forever-unchanged old shared inventory, or readiness of their old source pins.
After both native qualifications and final sealing, the active epoch is closed
to further native admission when the sealed production release is activated.
Later acceptance runs use their existing bounded active-release proofs; a new
native case cannot be smuggled back through the old epoch after those writes.
Any later native re-entry needs a separately reviewed transition, not another
automatic epoch.

All downstream source pin filters must accept the reviewed codec generation
explicitly. In particular the old active-runtime wrapper still pins config
`7807` and service `2739` and its old derivation permits only four other
dependency changes. It must receive a separately reviewed two-pin extension
for new config `30f4` and service `c51f`; a zero-slot classification does not
make that old wrapper executable with the new generation.

## Review gates and unresolved implementation work

Before implementation is frozen, review must resolve the exact phone-side
failed-attempt readset and additional roots, the control-namespace transition
schema, the exact source-generation admission schema, and the complete
cross-domain budget reservation. All aliases, extra retained roots and proof
copies must fit the one global pool. Before any target dispatch, source tests
must demonstrate capacity rejection, topology completeness, immutable old leaf
preservation, unauthorized additions, generation mismatch, source-codec bounds,
deadline exhaustion, concurrent reservation and atomic-publication races on the
actual candidate functions.

This design therefore offers a bounded route for the fixed19 workflow; it does
not assert that an implementation exists, that the old gates already accept it,
or that the next native qualification will succeed. The current execution gate
remains closed.
