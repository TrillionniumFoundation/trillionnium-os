# Init → Agent API host contract — 2026-08-24

The new host-only verifier (`tools/verify_init_agent_activation.py`) was run
against the canonical Android source tree and the current Rust control tree.
It returned `PASS_SOURCE_GRAPH_DEVICE_HOLD` (exit 0).  The result is a source
contract result, not a live activation claim.

Source checks passed for:

- init bootstrap/daemon/readiness edges;
- daemon socket and manifest service contracts;
- Agent API ABI, `SO_PEERCRED`/`SO_PEERSEC`/channel-binding checks; and
- replay/ACK source markers.

The verifier keeps the runtime boundaries explicit:

- `live_activation`: `HOLD_NOT_OBSERVED`;
- `authenticated_peer`: `HOLD_NOT_OBSERVED`;
- `codex_turn`: `HOLD_NOT_RUN`;
- `effect_authority`: `DISABLED`;
- target-files: `HOLD` (`target_files_not_supplied`).

Safety flags were all false: no ADB invocation, device mutation, init start,
effect, Codex turn, reboot, or flash.  Evidence digest of the verifier output:
`29ea764b9c50767d6b502d5cd55668ff82b8f0daf815075f780e5607c4e9f810`.

The current device therefore cannot be promoted from source-contract PASS to
live Agent API/effect authority until a matching target is observed and the
authenticated peer/replay prerequisites are independently verified.

