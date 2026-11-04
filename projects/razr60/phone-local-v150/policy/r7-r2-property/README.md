# r7-r2 servicemanager property read permission

The recorded live-policy audit passed all 26 checks. The only added permission atoms are getattr, open, read and map from trillionnium_owner_open_phone_worker to servicemanager_prop:file. Existing types, attributes, permissive flags, remaining TE permissions and transitions, and the remaining policy tables stayed unchanged. Enforcing remained enabled.

The file servicemanager-prop-read-only.rule is a public projection of the single added statement. The historical candidate comments were replaced; its bytes therefore have a separate digest. POLICY-PUBLIC-SUMMARY.json records the original full-rule and delta hashes, the actual live-policy and audit hashes, the frozen combination hash, and the 26 check names with their actual outcomes.

The offline candidate and actual live snapshot differ at the byte level. Both independently match the same exact four-permission change and unchanged remaining symbolic tables. Existing service-manager discovery and Binder permissions were preserved, including the absent reverse servicemanager-to-worker Binder grant.

This evidence closes the policy change and its semantic audit. It does not establish the sole cause of earlier timeouts or qualify ordinary phone use. Earlier task failures remain failures. A new deployed combination needs its own bounded health request, business results and recovery evidence.

## Candidate contents

- POLICY-PUBLIC-SUMMARY.json: selected verified fields and content hashes.
- servicemanager-prop-read-only.rule: one-rule projection.
- README.md: scope and interpretation.

The adjacent PUBLIC-ALLOWLIST.json seals these three candidate files for the designated publisher. Raw device records, policy binaries and operation identifiers are outside this public candidate.
