# External902 fixed P4 original collection

This is a source-only candidate. No collector, P4 process, phone command, or target module was executed while preparing it.

The collector reads the complete fixed sender, setup-fixture, and material directories, plus eight explicitly pinned sibling input/plan files. The material tree must match all 56 original Mac member pins. The setup fixture remains limited to the already consumed setup phase.

The source uses O_RDONLY/O_NOFOLLOW reads, held file and directory identities, full nine-field metadata and byte rechecks, bounded membership, and three full observation bookends. It creates one new evidence directory and uses O_EXCL, fsync, and readback for all outputs. It never overwrites or removes prior evidence. The original P4 trees may have changed since the failed case; this is a later non-atomic observation.

A successful evidence collection requires the actual controller to finish with return code zero, complete durable stdout/stderr, and a final stdout receipt after the last full recheck. RESULT.json alone does not establish success.

The original Mac sender PID 54589 remains NOT_JOINED with both EOF flags false. Later P4 records do not change that historical fact. This package performs no process census, cleanup, device operation, native qualification, or boundary publication. The Mac generated actor is outside this P4 collection and requires its own exact read.
