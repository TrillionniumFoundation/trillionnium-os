# Model semantic input is separated from the backend wire envelope at source

Date: 2026-07-24

## Verdict

The control plane now implements priority-plan item 3 as a source-integrated
slice for the System API and Accessibility direct tools. Model-visible input
contains only an action and bounded semantic parameters. Protocol, Android
user, backend request ID, binding, risk and lease material are not model
fields.

The Android System API v1 and Accessibility v2 wire ABIs are unchanged. No
Android repository, provider artifact, Root Linux builder/tool input, device,
flash, release signing, activation boolean or release receipt was changed by
this slice.

## Rust adapter boundary

- `SystemApiSemanticRequest` and `AccessibilitySemanticRequest` are closed
  serde types with `deny_unknown_fields`.
- The existing `SystemApiRequest` and `AccessibilityRequest` remain the backend
  wire types.
- `semantic` one-shot mode and MCP deserialize only the semantic types. The
  adapter fixes the backend protocol and fixes System API to Android user 0
  before emitting the existing wire JSON.
- `BackendRequestIdentityAuthor` is the injected identity boundary. Under the
  trusted-context path, the durable operation journal still authors the
  backend `op:` identity before effect. The ordinary source/dev compatibility
  path uses `getrandom(2)` for a process epoch plus a checked local sequence and
  hashes the semantic request.
- Raw no-argument one-shot mode remains the explicit backend-wire compatibility
  lane.

The compatibility author is intentionally not restart-stable. It removes
model authority over request IDs but does not supply durable exactly-once
recovery.

## OpenClaw and Codex consumers

OpenClaw's registered System API and Accessibility schemas contain no
`protocol`, `request_id` or `user`. Their fixed executable invocation uses the
single literal `semantic` argument. Direct-call evidence hashes the validated
semantic request and obtains the backend request ID from the measured adapter's
validated response. A semantic caller cannot request an ambiguous retry by
inventing or replaying an ID.

The Codex terminal sanitizer rejects semantic arguments containing
`protocol`, `request_id`, `user`, `binding`, `risk` or `lease`. It validates the
fixed backend protocol, validates the request ID returned in structured
backend content, and hashes that returned ID. The model arguments are hashed as
the semantic request without deleting or trusting an envelope field.

## Remaining HOLDs

- The default product ARM64 build still omits `trusted-context-hotpath`.
- Secure first-use construction of the durable operation journal remains
  source-only and unavailable to production callers.
- The kernel-random compatibility author has no cross-process retry authority.
  Response loss or ambiguous completion must remain HOLD until the durable
  journal is product-enabled; generating another ID is not a recovery action.
- Existing AArch64/root candidate hashes and preflash evidence predate this
  source slice. No candidate artifact or pin was refreshed, so they are not
  evidence for these changed binaries.
- No claim is made for production persistence, Android target-files identity,
  installation, physical-device durability or release activation.

## Validation

Focused validation completed in the canonical control-plane source tree:

```text
cargo test -p trillionnium-agent-direct-tools --lib --tests
  127 library tests passed; 2 default MCP integration tests passed

cargo test -p trillionnium-agent-direct-tools --features dev-overrides --test mcp_stdio
  5 tests passed, including semantic -> unchanged System API wire conversion

cargo check -p trillionnium-agent-direct-tools --all-targets --features trusted-context-hotpath
  PASS

cargo test -p trillionnium-tool-runtime
  124 library tests and 1 production-direct-only integration test passed

python3 -m unittest discover -s packaging/openclaw-android/tests -p 'test_*.py'
  42 tests passed

cargo fmt --all -- --check
  PASS
```

The source remains an uncommitted dirty-tree checkpoint. These results are
engineering validation only, not release evidence.
