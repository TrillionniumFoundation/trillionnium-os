# Epoch reservation v2 preparer adaptation

This candidate fixes the preparer replay of a v2 reservation. The v2 protocol
stores the complete authorization text with its origin and a structured resource
reservation. The old preparer incorrectly sent both values to the file
descriptor reader, rejecting every valid v2 record.

The candidate retains the actual common reservation validator and stage resource
validator. It additionally binds the resource generation, the source-fixed
authorization origin, the resource/identity case, and the exact UTF-8 owner
request after the single reviewed nonce substitution. Chinese, emoji and newline
bytes remain exact. This does not validate the separate business E2E02 case.

Replay now includes `ALLOCATION-ADMISSION.json` and `ROLE-LAUNCH-INTENT.json` in
its closed slot record set. It calls the actual stage validators with the
already verified initialization, claim, identity, generation, staged lease,
complete input index and original bytes. Later phases cannot precede either
required admission. The stage and existing lifecycle/native/fixture checks are
retained. Missing optional records in a partially written current slot do not
become permission to advance to a new slot.

The nonce denial set now calls the common module's existing
`epoch_forbidden_nonces` helper, including all four fixed historical domains.
No new nonce, current frontier, policy adoption or execution authority is bound.

The complete source is 130,365 bytes, below the unchanged 131,072-byte source
limit. Space was recovered by shortening 39 diagnostic strings in the local
replay section and three documentation strings. Conditions, limits and control
flow were not removed to reduce size. The full reversible edit list and unified
diff are in `validation/`; the inverse restores the complete original
130,768-byte `b5cfdd8a…` preparer.

## Local verification

Run `python3 -I -B run_regressions.py` from any working directory. It uses the
actual unchanged common/resource/allocation/launch pure validators and the
actual candidate replay control flow. The test context is explicitly synthetic.
It supplies the independent upstream manifest, anchor, initialization and
catalog boundary, and spies on the separate preclaim-observation and existing
stage-binding dependencies. It does not replace the validators under test.

The report names those boundaries and exclusions explicitly. It verifies valid
v2 structure; the old mismatch; authorization/source/generation changes;
UTF-8 owner mismatch; resource arithmetic and limits; bool/int confusion;
missing/late admission records; exact launch intent; unknown directory entries;
all four nonce domains; and complete source reversibility. These are source and
interface regressions, with zero phone calls and zero acceptance case credit.

The source still requires final whole32 integration and independent review. It
is not an installed or qualified runtime.
