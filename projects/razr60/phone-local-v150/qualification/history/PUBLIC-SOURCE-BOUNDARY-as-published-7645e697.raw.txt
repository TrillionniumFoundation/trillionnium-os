# Public source and evidence boundary

This tree preserves exact frozen production source where the publication index says
exact_original_bytes: true. A .PUBLIC.json file is an explicit projection of
a private sealed artifact. Its original SHA identifies the reviewed private input;
the projection has a different SHA and cannot replace that sealed runtime input.

Some operator scripts and module launch sources use /operator-workspace/... or
<INSTANCE_BINDING_SHA256_REQUIRED> placeholders. Their original and projected
hashes are both listed. They are reviewable source, not ready-to-install launchers.
Other approved module and parent-supervisor sources retain instance-specific
inode, boot or process constants; they also are not general installers.

Actual owner text, draft text or hashes, screenshot bytes, raw native histories,
claims, private keys or their content digests, model weights, executable binaries
and full SELinux policy binaries are excluded. The original private records and
sealed artifacts are retained by the operator; publication does not modify them.

Historical stages remain historical. A host check, runtime READY, component
cleanup or health PASS gives no business or daily-use qualification. The current
health checkpoint records one bounded native health task; the fixed 19 business
and fault cases remain a separate denominator at that cutoff.
