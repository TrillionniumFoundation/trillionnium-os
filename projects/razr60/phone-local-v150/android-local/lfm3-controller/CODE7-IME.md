# Code 7: observe input-method window changes

A system Back can dismiss the input-method window while leaving an app's node
tree unchanged. The previous repeated-action guard could therefore treat that
real effect as no progress and refuse a subsequent Back. This change observes
the missing window state. It does not exempt Back from repeated-action checks
or add app-specific navigation rules.

## Window metadata only

The Accessibility service already declares `canRetrieveWindowContent` and
`FLAG_RETRIEVE_INTERACTIVE_WINDOWS` both in XML and at service connection. Code 7
also subscribes to `TYPE_WINDOWS_CHANGED`; the callback still performs no
action. Each graph read obtains `getWindows()` and inspects window ID, type,
display ID and bounds only. It never obtains an input-method root or reads
input-method node text, key labels, composing text or typed content.

The screenshot and target observation use the default display. An interactive
`TYPE_INPUT_METHOD` window on that same display with nonempty bounds is visible;
floating, handwriting and candidate windows are not excluded by focus, position,
height or whether the app resizes. The target app's exact window ID must also
appear in the snapshot. Only a complete valid list containing that target and
no input-method window establishes hidden. Missing capability/flag, empty or
unavailable list, missing target, invalid entry, empty input-method bounds or
query failure produces unknown.

`ime_visible` is always present in the private observation and model projection:
`true`, `false`, or explicit JSON `null` for unknown. It means an input-method
window was observed, not that a particular keyboard layout or content was read.
The prompt explains that Back may first dismiss this window and another
navigation decision may still be necessary. Recent action evidence carries
before/after values.

## Separate exact freshness and progress identity

The app-tree digest keeps the previous package/window/rotation/bounds/node
definition. A separate overall graph digest binds that digest and the exact
three-state input-method observation, so fresh screenshot and action checks can
notice an input-method transition. Existing same-window checks remain unchanged.

Progress is known when the app tree changes or when both input-method states
are known and differ. If the app tree is equal and either input-method state is
unknown, progress is unknown, not a claimed appearance/disappearance. The
repeated-action guard clears only on known positive progress; false or unknown
progress retains rejection of the same effect. The action key, read-only
discovery preservation, wait reset, other action reset rules, and blocked-open
candidate behavior remain unchanged. Legacy String-only callers retain the
previous app-tree comparison semantics.

The private JSON includes the original app-tree hash and combined observation
state hash for audit. Completion and node-sensitive actions retain exact graph
freshness; this change does not relax their dispatch checks.

## Validation boundary

The host regression runs the actual state and repeat-guard classes. It covers
Back closing a visible input method on an identical app tree, the subsequent
Back remaining allowed, unchanged Back remaining rejected, all nine three-state
transition pairs, unknown-to-known conservatism, real app-tree changes, and
blocked-open behavior. Full Android compilation checks the real API references.
Actual window reporting and goal completion still require ordinary-app-UID
device evidence. Code 6 source, APK and its original failed result are retained.

References: Android public
[`AccessibilityService.getWindows()`](https://developer.android.com/reference/android/accessibilityservice/AccessibilityService#getWindows()),
[`AccessibilityWindowInfo.TYPE_INPUT_METHOD`](https://developer.android.com/reference/android/view/accessibility/AccessibilityWindowInfo#TYPE_INPUT_METHOD),
[`FLAG_RETRIEVE_INTERACTIVE_WINDOWS`](https://developer.android.com/reference/android/accessibilityservice/AccessibilityServiceInfo#FLAG_RETRIEVE_INTERACTIVE_WINDOWS)
and [`TYPE_WINDOWS_CHANGED`](https://developer.android.com/reference/android/view/accessibility/AccessibilityEvent#TYPE_WINDOWS_CHANGED).
The API may retain a focused window even if a modal window occludes it. Thus this
field describes the observed interactive input-method window inventory; it does
not claim every pixel or key is exposed, or that no hidden window instance exists.
