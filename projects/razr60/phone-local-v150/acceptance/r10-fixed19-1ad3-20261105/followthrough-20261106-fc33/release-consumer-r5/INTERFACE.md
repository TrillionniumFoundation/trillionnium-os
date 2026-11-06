# Additional originals for the two new current closures

The top-level `hepta.r10.component-boundary-inputs.v10` schema and `COMPONENT_FIELDS` are unchanged. The existing `originals` array carries two additional entries: one exact original `LEASE.json` for each newly closed current NEG-01 and NEG-02.

For each already verified new closure:

1. Read `closure.lease_source_path` and require a canonical `BASE/native-guard-r10-r1/<label>/LEASE.json` path.
2. Select that exact path in the already verified complete `inventory.entries` object. It must be a regular single-link root-owned mode-0600 file. Build the phone descriptor from the entry's exact `bytes`, `sha256` and nine-integer `metadata`, adding only that exact path.
3. Take the complete original bytes from the component capture's `home/LEASE.json`. Require the original byte length and SHA256 to match both the inventory entry and `closure.lease_sha256`. Preserve the original bytes without JSON reserialization.
4. Add the normal original-copy row: `{"phone": <exact phone descriptor>, "copy": <exact host path/bytes/SHA256 descriptor>}`. The existing bundle reader verifies the host copy, and `body()` checks the exact phone descriptor and records its use. Existing unused-original rejection remains in force.

No descriptor values are supplied here because the two new actual closed cases have not occurred. Do not create new nonces, labels, phone metadata, lease bytes or qualification identities from control fixtures.

The callback is passed to:

```python
validate_final_component_prefix(
    chain, late, retained,
    read_pinned=body,
    combination_descriptor=descriptor(combination_raw),
)
```

The combination descriptor is computed from the same complete original `combination_raw` that the enclosing consumer has already verified. A caller-provided digest alone cannot replace it.

The pure helper verifies the full original lease schema used by `prepare_component.py`. It checks selected session/profile against the closed scope and checks all closed boot/nonce/case/owner/package/retirement/prior values with type-preserving encoding. Expiry is checked only as the original positive integer. It then derives, in the actual inventory append order:

- `/proc/1/root` plus the lease's exact Android journal path;
- the exact component home bound to the validated label;
- `/proc/1/root/data/local/tmp/hepta-native-guard-` plus the validated nonce.

The input roots must equal the source-parent inventory's full ordered roots followed by the new NEG-01 three roots and then the new NEG-02 three roots. The existing whole-boundary reader remains responsible for canonical body identity, complete inventory topology, predecessor continuity, scope/nonce uniqueness, independent closure, retained-stage preservation and actual current qualification before this predicate runs.

Historical source-parent and failed-ancestor originals retain their previous input interface. Their original qualification values and original source/package identities are preserved. They cannot fill either new current-case position.

## Public source literals

| Literal | Selected unbound value | Source |
| --- | --- | --- |
| `PACKAGE_SHA` | `None` | Await actual independently reviewed runtime freeze |
| `PACKAGE_FILE_COUNT` | 38 | Complete observed candidate manifest member set |
| `CURRENT_COMBINATION_SHA` | `7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411` | Exact actual shared combination original |
| `CURRENT_COMPONENT_CHAIN_LENGTH` | 12 | 9 fixed failures + 1 actual source parent + 2 new prefix positions |
| `COMPONENT_ROLE_BUDGET` | 42 | 3 roles per native chain member + 2 fixed non-native branches |

The constant values are checked against the reviewed LATE APIs and actual manifest. The reader does not substitute a fixed 47, 44 or 50 for root identity checks.
