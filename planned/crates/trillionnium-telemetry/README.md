# trillionnium-telemetry

This component belongs to [MOD-TELEMETRY](../../../docs/modules/MOD-TELEMETRY.md).
It is selected only by the isolated `planned/Cargo.toml` workspace, outside the
root product default closure. Telemetry stores bounded derived metric windows and objective/cost projections; observations never authorize effects.

Its public Rust library is the design and source-test boundary. A successful
source test does not integrate it into the Host or enable installed active
control. Changes must preserve module ownership, epoch/fencing and bounded input
contracts; installation and performance still require qualified L2 evidence.

Run from the repository root:

```sh
cargo test --locked --manifest-path planned/Cargo.toml -p trillionnium-telemetry --all-targets
```

See the linked module contract for state ownership, compatibility and recovery.
No source fixture grants Android, physical-device, signing or release authority.
