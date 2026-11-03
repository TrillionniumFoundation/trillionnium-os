# Component parent r3 — public source projection

This directory is a source-only public projection of the separately sealed component-parent-r6-r3 package. The four shell files are byte-identical to the reviewed private originals. They retain the exact instance-specific device/inode/PID/start bindings needed to review the admission logic. They are not a generic installer.

The private package seal is SHA256 `f7ae9584378dd954a59bd3c31f89bcc20782430187e613a5a13ad721ecffe3e4`. This projection is a different artifact and never represents that original bundle.

The only substantive new admission code binds the original r1 failed startup and r2 zero-action ready/retirement records, keeps the existing empty actions directory and lock inode, and exclusively creates a new owner-supervisor-r3 evidence directory. Old records and logs are never deleted or opened for writing. The child, observer and supervisor lifecycle differs from r2 only in the fixed CODE path and comments; the 600-second lease, outer 660-second timeout/20-second grace and genuine same-parent wait semantics are unchanged.

The sources deliberately fail without the private SHA256SUMS and the exact original installed input/evidence files. Those inputs, private original records, captured logs, device-policy snapshot, full private manifest and transfer archive are omitted. This directory does not provide permission to start a service or replay a task.

Host shell syntax/evidence integrity and independent focused source review passed at the recorded pins. This does not establish a new physical r3 startup, native component result, worker cleanup, model health or business qualification. Separate actual evidence is required. Parent/group retirement also does not itself prove cleanup of workers in independent sessions. Unknown identity or incomplete cleanup remains UNKNOWN.

The earlier public r1/r2 projection remains unchanged. No user text, model requests, API-key content, private recovery proof or raw phone evidence is included. Publication remains an independent Root decision after the actual checkpoint.
