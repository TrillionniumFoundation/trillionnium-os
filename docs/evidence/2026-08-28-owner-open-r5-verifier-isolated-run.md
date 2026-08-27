# Owner-open R5 verifier isolated regression execution

Date: **2026-08-28**  
Evidence class: **L0 isolated verifier regression**  
Claim ceiling: **verifier logic executed; exact repository checkout and Rust closure not executed**

## Environment

```text
Python 3.13.5
Linux 6.18.35 x86_64
```

The execution environment had no `rustc` or `cargo`, and network/DNS access was
not available for installing the repository's Rust 1.93 toolchain.

## Scope

The current `tools/verify-owner-open-r5.py` and
`tools/tests/test_verify_owner_open_r5.py` logic was materialized into an
isolated temporary directory and executed with the self-contained fixture
created by the test suite.

This was not a byte-for-byte Git checkout of the complete branch. It therefore
proves the verifier's regression behavior only. It does not prove that every
current repository file satisfies the verifier, and it does not prove Rust
formatting, compilation, tests, clippy, Host behavior, Android integration or a
device effect.

## Commands

```sh
python3 -m py_compile \
  tools/verify-owner-open-r5.py \
  tools/tests/test_verify_owner_open_r5.py

python3 -m unittest tools.tests.test_verify_owner_open_r5 -v
```

## Result

```text
test_android_hold_is_warning_then_strict_error ... ok
test_clean_fixture_passes ... ok
test_default_graph_drift_fails ... ok
test_host_autobins_drift_fails ... ok
test_legacy_dependency_fails ... ok
test_source_marker_fails ... ok
test_superseded_host_path_cannot_be_selected ... ok
test_unreviewed_internal_edge_fails ... ok

Ran 8 tests in 0.071s
OK
```

The suite exercised:

- clean exact-default fixture acceptance;
- forbidden default-member rejection;
- unreviewed owner-open internal-edge rejection;
- forbidden legacy dependency rejection;
- forbidden source-marker rejection;
- Host `autobins` drift rejection;
- superseded Host entrypoint rejection; and
- Android legacy marker warning versus strict failure.

## Negative claims

This evidence does **not** claim:

- the current Git head passes `tools/verify-owner-open-r5.py` against every
  actual branch file;
- a reviewed `Cargo.lock`;
- Rust 1.93 formatting, compilation, tests or clippy;
- the active-control Host process tests;
- live Codex, real ADB, Android image, physical device, fault or release
  qualification.
