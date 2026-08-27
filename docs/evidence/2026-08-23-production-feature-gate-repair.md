# Production feature-gate contract repair

Date: 2026-08-23 (Asia/Shanghai)

## Scope

This source-only repair addresses a stale host policy contract.  `Cargo.toml`
already listed `crates/trillionnium-shell-exec`, but
`tools/production_agent_feature_gate.py` did not include that member in its
allowlisted workspace map.  The gate therefore stopped at
`workspace_member_contract_drift` before it could evaluate the production
feature graph.

## Repair

- Added the existing `crates/trillionnium-shell-exec` member to the ordered
  workspace manifest map.
- Changed retired-token matching to identifier-boundary matching.  The
  retired package token `trillionnium-shell` remains rejected, while the
  distinct current package `trillionnium-shell-exec` is audited normally.
- Added a regression covering both sides of that boundary.

No product feature, authority flag, transport, key, signing path, device
state, or release decision was changed by this repair.

## Verification

```text
python3 -m unittest tools.test_production_agent_feature_gate -q
14 tests: OK

python3 tools/production_agent_feature_gate.py --workspace . --cargo cargo
PASS_PRODUCTION_AGENT_FEATURE_GRAPH
activated_forbidden_features=[]
public_release_allowed=false
```

The Android production/release blockers remain independent and unchanged:
OS-held-key transport, hardware KeyMint/Verified-Boot and rollback evidence,
production Accessibility replay/ACK closure, and legitimate signed
`user`/`release-keys` inputs are still required before signing or device
mutation.
