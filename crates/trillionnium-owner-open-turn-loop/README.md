# trillionnium-owner-open-turn-loop

This R5 source slice binds one semantic provider turn to the reviewed
owner-open call registry and direct process bridge.

It proves at source level that a provider can:

1. emit model/status events;
2. invoke command-string shell, exact argv shell, or ordinary ADB argv;
3. receive raw runtime events and a truthful terminal observation;
4. continue in the same provider turn after a non-zero tool exit; and
5. finish with exactly one turn terminal.

Exact duplicate calls attach to the existing registry entry and do not spawn a
second local process. A conflicting call ID/request binding fails. The crate
contains no plan, Authority, approval, risk classifier, typed ADB action table,
or sealed shell broker dependency.

Current claim ceiling: **SOURCE_IMPLEMENTED / L0** until Rust 1.93 formatting,
unit tests, clippy, and spawned-process integration execute on the exact commit.
