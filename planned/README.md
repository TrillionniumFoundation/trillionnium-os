# Planned G1 mechanical modules

This is a deliberately separate Cargo workspace.  The modules here are
source-complete candidates for the G1 shadow/baseline stage, but are not part
of the installed owner-open binary graph until an exact-head review promotes
their APIs.  They contain no semantic command interpretation and do not
redispatch uncertain effects.

The control candidate uses bounded lease, observation and module-instance
indexes (4096 each by default); deployments may lower those limits with
`ControllerLimits`/`ModuleInstanceRegistry`, while expired leases are
reclaimed only when a later timestamp is observed.  Module registration is
epoch/fencing checked and heartbeat updates are monotonic.  Shadow decisions
can be recorded in a bounded hash-chained `DecisionAuditLog`; rollback appends
an auditable marker and never erases history or grants semantic authority.

The telemetry candidate includes bounded module read models and sorted,
content-addressed cost curves in addition to the WL-01..WL-12 baseline
projection.  Read-model updates are monotonic and exact retransmits are
idempotent; conflicting timestamps and over-capacity curves fail closed.

Run the source checks with:

```text
cargo fmt --manifest-path planned/Cargo.toml --all -- --check
cargo test --locked --manifest-path planned/Cargo.toml --workspace --all-targets
cargo clippy --locked --manifest-path planned/Cargo.toml --workspace --all-targets -- -D warnings
python3 -m unittest tools.tests.test_run_global_baseline -v
```

The host baseline probe can be emitted for review with an explicit output
path, for example `python3 tools/perf/run_global_baseline.py --output
/tmp/g1-baseline.json --repetitions 3`.  Its result remains
`SOURCE_EVIDENCE_ONLY`; installed Root Linux, Android, device and fault
evidence are required before any higher-level claim.
