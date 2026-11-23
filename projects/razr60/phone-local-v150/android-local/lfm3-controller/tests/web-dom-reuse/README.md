# Bound private capture reuse

This follow-up starts from source commit 2b46214. It reduces repeated controller
processing of verified webpage capture data. It does not extend task, RPC or
observation deadlines, accept an old frame, or replay a tool action.

Each receipt retains a private snapshot produced by the strict capture parser.
Its original FD bytes and task binding remain hash verified. Accessors return
detached copies. Read-only shopping eligibility can reuse its immutable own-pair
proof only when every candidate field, type and original DOM string still matches
the private snapshot. Cross-capture DOM, region, geometry and count checks still
run. Owned native admission independently replays the complete proof and fresh
native snapshots. No cache is shared across receipts or tasks.

Canonical equality validates both complete inputs in the original order using
immutable normalized tokens. Canonical serialization is unchanged. Projections
validate every original field, including omitted fields, before producing a
detached object from checked tokens. Original objects and Numbers are not read
twice. All depth, count, type, Unicode, number and output budgets remain.

The host gate has 1,560 comparison, 1,215 projection and 21 ownership cases.
Ownership fixtures exercise a synthetic private-constructor boundary, not formal
capture or native authority. Separate real-receipt replay reads unchanged saved
phone bytes. An explicit host JSONObject(Map) null-retention boundary matches
Android without changing authority comparison or original evidence.

The five price captures retain their own-proof hashes and both rejected pairs:
changed DOM membership, and non-recommendation semantic change. The earlier
four-capture sample retains its accepted proof hash and rejected pair. Host
latency is not phone latency; independent stage times cannot be added together.

This revision also integrates bounded Notes reopen observation and paired
seven/eight-image flight carousel support. Their separate receipts describe
coverage. A fresh phone regression is required before claiming task success.

Run with existing pinned dependencies:

    python3 -B tests/web-dom-reuse/run_host.py --source . --output /tmp/hepta-reuse-new --java-home "$HEPTA_JAVA_HOME" --json-jar "$HEPTA_JSON_JAR"

Full shopping, readiness, completion, native workflow and complete host suites
remain separate gates. Public receipts contain hashes and allowlisted metadata,
not private page bodies, note text, screenshots or signing material.
