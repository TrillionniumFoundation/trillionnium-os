# Material builder directory publication v2

This package preserves the reviewed source-only publisher change from 324e2a0c to 2102adcc. The independent 18-control process was job 1a1b16a9075-fc05-7884, with authoritative exit 0, complete durable stdout 2636 bytes, and empty stderr. It did not read R4 originals, derive an actual material graph, freeze a runtime, build a release, operate a phone or qualify READY.

The source change inserts a held-directory-FD publisher, removes early path-based directory creation, and publishes DERIVATION.json last. Full inverse reconstruction recovers every parent source byte. The unchanged material derivation algorithm still requires actual source descriptors and independently bookends all originals.

## Reproduce source and publisher controls

From the package directory, choose a fresh absolute results directory:

```sh
python3 -I -B validation/verify_exact_source_derivation.py
python3 -I -B validation/run_publisher_controls.py source/derive_reviewed_source_material_v2.py /absolute/fresh/material-controls
```

The second command performs 18 controls against real host temporary files, including nested byte readback, terminal-last order, closed file descriptors, existing-directory rejection, invalid paths, root/nested symlink swaps, unknown I/O, payload corruption, and a late directory-sync error after the terminal filename has appeared. The tests do not invoke the actual source graph derivation entry point.

A successful filename is not an authoritative execution outcome. Late publication I/O may leave DERIVATION.json present while the original process failed or its durability is unknown. Consumers require the original successful process plus complete verified outputs.

## Actual material operation is separate

Root subsequently reported an actual source-material derivation using this exact v2 builder, job 1a1b16ec976-fc05-78ae, under followthrough-20261106-fc33-shared-material-v2-01. Its actual originals are retained separately by Root and are not the publisher test result in this package. That source graph is a candidate, not runtime adoption, a BUILD result or installation qualification. The source and test evidence here do not bind any future cleanup closure, inventory count, acceptance nonce or READY role.
