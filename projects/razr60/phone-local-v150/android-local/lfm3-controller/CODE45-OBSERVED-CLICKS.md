# v45: observable text for the ordinary controller's clicks

Base: frozen v44 `180a7ab55f5a479c14c202fdbe33a1a4734cecfd`.
Candidate: versionCode 45, `0.45.0-local-observed-clicks`.

## Concrete failure

The saved phone observation `tests/text-only-click/fixtures/v43-note-step05-before.json`
has SHA-256 `a9e83eb50aabfd71ec967ba74b98ebe60176002700380e68b81775cccc076d75`.
It records a clickable `n10` with no text, description, child text or view ID.
Node class is unavailable in this saved JSON; the replay does not invent it.
The phone run later displayed an audio attachment rather than evidence of the
requested save/list/reopen sequence. This fixture is a failure observation,
not successful Notes evidence.

The earlier controller exposed raw clickable nodes to a text-only model even
when their action labels were empty. An exact empty `(node_label,node_id)` pair
could pass the older pair-binding policy. Geometry or a widget class cannot
establish the purpose of an icon when the model receives no image.

## Restricted click domain

`PromptActionDomain.textOnlyClickLabel` checks the actual 36 UTF-16 label prefix.
Visible letters, numbers, punctuation and symbols remain eligible, including
Chinese labels, calculator `+`, `×`, `=`, `−`, `÷`, and visible emoji. Whitespace,
Unicode format/control characters, isolated combining marks, private-use or
unassigned characters, Hangul fillers and the blank Braille cell do not supply
a visible label. An ellipsis inserted by label truncation is excluded from the
test; a literal observed ellipsis remains an observed symbol.

For a label derived from descendants, `ObservedChildText.Result` retains the
positions of actual child text fragments in the existing assembled label.
Eligibility checks only characters from those fragments that are inside the
visible prefix. The collector's inserted ` · ` separators and truncation ellipses
cannot create a click target from otherwise invisible child text. A middle dot
actually present in a child's own text remains valid. The existing combined
label, source hashes, fingerprint, node JSON and observation identity are not
changed. Missing fragment provenance cannot grant a click.

The ordinary `LocalTaskController` applies this restriction after its existing
package, enabled/password, repetition and owner-authorization checks. The same
final set supplies prompt `c` flags, the GBNF click pairs, and an immutable
`PromptFrame.clickNodeIds`. Independent checks after parsing and immediately
before `awaitAction` require membership in that set and the exact current
observation/package/label/ID pair. A model output that ignores the grammar cannot
dispatch an excluded click.

All raw node facts and existing structural control hints remain available;
`view_id`, class or bounds never become a semantic label. This restriction is
only on the ordinary controller's no-image-input click path. It does not alter
the general accessibility executor or give any visual-model path new authority.
The SYSTEM message explicitly explains the absence of blank click targets.

## Preserved behavior and limits

The restriction does not remove type from an empty editable field, an already
observed query submit, an observed scroll direction, or system back. Actual own
text, content descriptions and properly observed child labels can still grant
click subject to all previous gates. Existing fixed intents and one-shot
dispatch ledgers remain unchanged.

Back remains an action, not save proof. In Notes it may first hide the input
method. The unchanged completion gate still requires actual editor/list/reopen
evidence, and unsupported goals remain partial. No asynchronous completion or
list-provider change is included. This patch makes no claim of new phone,
background, shopping, flight-query or model-quality acceptance.

## Verification

The existing exact production prompt fixture now also exposes its immutable
click set and dispatch guard. Its extraction verifies both real call sites.
`TextOnlyClickHostTest` replays the exact saved failure observation and tests
independent postparse rejection of `n10`, retained real labeled nodes, stale or
substituted pairs, immutable membership, Unicode/truncation boundaries,
artificial versus actual child punctuation, empty editor type/submit, scroll,
and calculator symbols. The new GBNF recognizer checks 16 positive and negative
outputs against the actual grammars produced by that controller fixture.

The existing observation-hints regression still checks unchanged node order,
labels, bounds, structural hints, original owner and exact budgeting, while
explicitly expecting the removed blank `c` flags. The full host runner hashes
the new saved fixture as an input. Existing release-8, Android build and actual
phone acceptance gates remain separate; their run receipts establish results.
