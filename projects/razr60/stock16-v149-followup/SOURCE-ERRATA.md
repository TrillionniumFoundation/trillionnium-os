# Source record clarification

This note accompanies the source archive published in commit
`029ec7e095865805d6e7e491c4ebabc17c3dee73` under
`projects/razr60/stock16-v149`. The frozen archive's 344 manifest-listed files
and `SOURCE-MANIFEST.json` remain unchanged. Its manifest SHA256 is
`fe7f23464f535393c3ecead82e33c8a02b458fe43110ae96797b6c8bdc2af8f8`.

## Deployment preparation script

The `ops/v149/README.md` table describes `prepare_candidate.py` as also rerunning
the offline checks. The script itself compiles and pins the candidate sources
and prepares the host installation plan. Root ran the offline checks separately
before the host switch. The recorded 156 candidate checks and 157 independent
Mac checks are separate validation results, not actions performed by that
preparation script.

This clarification changes no production source, build receipt, deployment
action or acceptance result. The historical operator scripts remain bound to
the reviewed v148-r5 to v149-r1 transition and are not an instruction to replay
that transition against a running system.

## Reading subsequent evidence

Evidence added in a sibling directory is dated and qualified separately from the
frozen source snapshot. Host compilation, host QEMU fixtures, direct operator
phone component checks and real model tasks have separate acceptance scopes.
New evidence must not retroactively turn an unrun fixed acceptance case, a
model quota failure or a preserved historical result into a successful model
task.
