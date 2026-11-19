# Own-display screen lease

This gate executes the production `PublicOwnGroupScreenLease` with explicit power,
display-census and monotonic-clock ports. The 8-second timeout is a host model of
the observed device policy; it is not a claim that Android power APIs ran here.

The positive path holds only the isolated created display beyond that timeout,
then releases at the original absolute session deadline. Negative cases cover
physical and shared groups, unknown census values, wrong identity and flags,
an already sleeping display, expiration, attempted renewal, display-id reuse,
and a real concurrent late acquire versus cleanup. Release uncertainty remains
uncertainty and never proves task cleanup or business success.

The runner also pins the exact production lifecycle and three-argument Android
API call sites. Android SDK compilation and real phone qualification remain
separate requirements. Existing scope, ownership, task, physical-display and
cleanup gates retain their assertions.
