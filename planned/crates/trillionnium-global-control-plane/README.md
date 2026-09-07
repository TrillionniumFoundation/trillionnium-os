# trillionnium-global-control-plane

This component belongs to [MOD-GLOBAL-CONTROL](../../../docs/modules/MOD-GLOBAL-CONTROL.md).
It is selected only by the isolated `planned/Cargo.toml` workspace, outside the
root product default closure. The controller evaluates bounded resource proposals in observe/shadow mode and refuses active control.

Its public Rust library is the design and source-test boundary. A successful
source test does not integrate it into the Host or enable installed active
control. Changes must preserve module ownership, epoch/fencing and bounded input
contracts; installation and performance still require qualified L2 evidence.

Run from the repository root:

```sh
cargo test --locked --manifest-path planned/Cargo.toml -p trillionnium-global-control-plane --all-targets
```

See the linked module contract for state ownership, compatibility and recovery.
No source fixture grants Android, physical-device, signing or release authority.
