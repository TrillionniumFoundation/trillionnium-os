# Two-epoch inventory core — unbound source candidate

This package is **source-only, unbound, and not ready for a phone or runtime entrypoint**. `EPOCH_INVENTORY_EXTRA_ROOTS` is exactly `None`; every new public inventory API refuses the incomplete binding before traversal. The complete lifecycle file intentionally retains the old executable entrypoint and all original functions. Do not invoke its old main as a substitute for the new protocol. No original runtime callsite has been rewired by this package.

## Exact change

One inserted fragment adds `inventory_epoch_spec_value`, `inventory_epoch`, and `verify_epoch_inventory_observation`. Removing the complete insertion restores the 40,261-byte `14483634…` lifecycle byte for byte, including all 15 original functions, imports, constants and main. The original single-domain `inventory` still rejects a ninth fixture. The new API requires the exact fixed 902 legacy anchor with seven fixtures and an explicit active reservation registry of at most eight consumed ordinals; it never treats splitting arbitrary roots into two lists as admission.

## One budget and explicit projections

The complete union uses one internal 30-second cooperative clock, 64 root/object limit, 30,000 entries, 512 MiB file-body read pool, 64 MiB per file, and 20,000 children per directory. No external clock or budget can be supplied. Every alias view is read and charged separately. Business and present-retained trees return the original complete-inventory v1 shape. Present control trees return a separate v1 object, or explicit null. Positive nonfixture absences and fixed flat transfer-file originals remain in the epoch observation. They are still fully charged; they cannot be dropped to reduce the pool or placed in the old business inventory to bypass its schema.

The fixed legacy aliases are 55 complete pairs. The retained two failed attempts add exactly two empty executor-directory pairs, independently reconstructed from their actual stage-observation outputs: 134 rows, 114 files, 20 directory views, 4,179,162 body bytes. The future exact binding must retain all 57 fixed pairs and verify each in the fresh observation. An undeclared alias, a third view, unequal full-nine-field rows, or an omitted declared pair is rejected. Active aliases must have the exact same relative path under that actual identity's GNU executor and Android journal, derived by the upper protocol from phase originals.

All files use no-follow/nonblocking read FDs, full metadata and canonical-path bookends, strict regular-file ownership rules, whole SHA-256, and final union bookends. Only explicitly pinned old transfer leaves may retain the observed shell-owned 0666 form; generic private files remain root-owned 0600. Parent names/full metadata for flat leaves do not claim the rest of that shared parent subtree was read. The one clock is cooperative: it does not promise preemption of a blocked kernel call.

## Retained local checks and limits

Run01 retains 25 successful checks and two environment-blocked checks: this executor denies `/proc/1/root` for a real alias fixture and rejects `chown(2000)` with EINVAL. These failures remain in the original report. Run01 actually read a 512 MiB sparse-file boundary across two domains and exercised 30,001 real entries. Run02 has 27 successful checks for the current fragment, including exact flat control files, omissions, identity drift, parent observations, race rejection and projections. The shared budget class is byte-identical to the one used for the large Run01 checks; those expensive checks were not rerun for the small control-leaf increment. Neither run establishes physical NEG14 or new-runtime qualification.

The 27 local checks, all source/whole-byte inverse checks, and actual retained-data reconstruction performed no remote call, target-runtime import, target main, phone action, signal, nonce or lease creation. The tests execute only extracted new helpers with isolated temporary data; the `None` binding is never changed in this source.

## Remaining integration and capacity gates

The upper native protocol must independently derive the complete reservation/identity/acceptance/phase root subsets, verify the legacy history and exact allowed additions, preserve failed-prelaunch evidence, implement the control state machine, bind actual fresh failed-tree and twelve flat-leaf full identities, and provide the reviewed new transport writers. Null control inventory is not authority to initialize a registry. The pure verifier reports structural observation only and explicitly does not claim original provenance, cross-operation preservation, a case result, or lease authorization.

The included capacity worksheet is a known subtotal, not a dispatch guarantee: 26,538,593 bytes of historical/content-bound fixed data plus 3,531,944 bytes for two initial runtime32 body copies after this lifecycle insertion. It excludes changing final-generation sources, snapshot and consumer duplicates, control state and producer output growth. In particular the original role stdout/stderr files have no producer byte cap. No alias or compressed-payload discount is used. Exact new copy accounting and fresh resource admission remain mandatory before any actual qualification attempt.
