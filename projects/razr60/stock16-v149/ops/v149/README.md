# Historical v149 deployment operators

These four scripts record the reviewed **single v148-r5 → v149-r1 transition**
on the configured Mac. They are preserved production-operations source, not a
portable installer and not a command to repeat on a running device.

| Script | Recorded purpose and boundary |
|---|---|
| `prepare_candidate.py` | Build the fixed candidate from the reviewed source set, rerun offline checks and prepare the host install plan. |
| `upgrade_host_once.py` | Perform the reviewed host-only daily-provider switch with the exact prior service identity, source pins and claim-count preconditions. It retains existing claims and does not start a new phone task. |
| `stock_phone.py` | Existing single-dispatch operator transport adapter with boot, fingerprint, USB and SELinux checks. |
| `component_probe.py` | Root-owned bounded phone component verification through an external operator transport. It deliberately distinguishes non-native/non-model component checks from actual provider task acceptance. |

The scripts bind the original Mac account, paths, service labels, prior watcher
identity and the observed 15-claim precondition. Their source contains no claim
values or private keys. The actual claim ledger, retained-claim copies, generated
plans/plists, screenshots, phone inputs, component decisions and execution-state
records are excluded from this archive.

`component_probe.py` imports the included `stock_phone.py`. The adapter still
requires the external pinned `preserved_ui_package_phase_r7.py`, its separately
held route configuration and the live boot-state manifest. These runtime inputs
are not archived, so the probe remains deployment-bound rather than standalone.
Do not replace them with unreviewed adapters or infer successful phone control
from the presence of the scripts. Root's deployment result is referenced only by
path and hash in `VERSION.json`; sensitive live-state contents are not copied.

The build instructions at the top level do not invoke these operators. Reuse
requires establishing a new, concrete transition plan against the actual current
host and device state, rather than replaying the historical preconditions.
