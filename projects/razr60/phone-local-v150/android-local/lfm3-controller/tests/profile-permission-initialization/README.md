# Profile permission initialization host checks

`tools/run_host_checks.py` runs the original permission transient gate and then
these two additional strict Java 8 API gates. Their runners accept `--source`,
`--output` (a new directory), and `--java-home` (an existing full JDK). They never
download dependencies, contact a phone, launch a privileged process, grant a
permission, or claim Android accessibility adapter qualification.

The core gate retains the three original ownership test files byte for byte. It
adds 59 permission state/authorization/retirement cases with 210 assertions and
23 physical-display-fence/protocol cases with 35 assertions. These cover forged
or stale proof, mismatched profile/task/display/UID/generation, unknown or
incomplete windows, input reuse, cancelled work, publication failure, physical
task/focus/recents changes, and the narrow optional-location rejection route.

The adjacent `profile-permission-ui` gate executes the real worker and core with
inert Android, accessibility, transport and file IO substitutes. Its 15 cases
and 72 assertions cover hidden optional-location rejection, hidden manual-input
refusal, actual owner-choice identity, lost focus, late receipts, no replay, and
cancellation while a real host worker remains blocked. It does not render an
Android Activity or execute the real accessibility adapter.

Durable preview publication is recorded separately from visible pixels.
Automatic rejection requires a fresh authenticated PermissionController window
for the same owned task and an original explicit city route that needs no GPS.
The real fine/coarse selection structure must be present. Unknown requests stop;
the business model never sees a system prompt or acquires permission authority.
The only system input is a unique actual standard Deny button. Manual rejection
requires the current ordinary owner UI choice and loses authority on focus loss.

Real-device qualification still needs the authenticated Binder/AX adapter,
physical displays 0/1 remaining unchanged, retained-token cleanup, and timing
within the existing 2-second freshness and 12-second preparation deadline.
Synthetic host timing is not device latency evidence. These tests do not alter
the production display policy or qualify a locked-screen display experiment.
