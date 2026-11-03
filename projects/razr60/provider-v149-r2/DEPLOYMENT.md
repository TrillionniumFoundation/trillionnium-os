# Provider v149-r2 deployment receipt

The host provider and bridge were switched to source commit `038f33f85e6b2e4796c369d310ed4e256e23ca78` (tree `57c557f3dd5e05478f64293378a1db8d2dae904a`) on 2026-11-03 at 13:25 UTC. The current recorded state is in [deployment/CURRENT-STATE-V149-R2.json](deployment/CURRENT-STATE-V149-R2.json).

## Installed identity

The provider entry SHA-256 is `f14dad67147fd9c66dc42ad36222c94da35418fee64761e9843871abdfbdf3bb`. The complete CLI bundle was copied from the previously qualified application into the private version directory, verified file by file (46 regular files; 362165709 bytes), had write bits removed, passed the original code signature verification, and returned the same bounded version result from both entry points. The original application was unchanged. The executable SHA-256 is `58a91f6ea19bea477ae3a2ec48d619f0039afe75d3476260747e11d201fa7cea`; the wrapper SHA-256 is `50ab38ba21d0d9f8346f32f41848382f15b556190f3c7a07e885a4fb73e379c8`. The executable bundle is retained only on the operator host; this repository contains its manifest.

All 17 original accepted claim files retain their original hashes. The shared state path and retained-claims manifest were preserved. Deployment made zero model calls and zero phone calls. The model-health record retains two issued attempts, the original usage_limit_exceeded observation, and no successful business verification.

## Original failed switch and recovery

The first attempt at 13:21:28 UTC unloaded the bridge and provider, then failed because launchctl returned before the old process released its daemon lock. Immediate restoration also met the still-unloading label. This attempt changed no source directory or plist. Read-only reconciliation confirmed that both old PIDs and service labels had gone and the daemon lock was free. The subsequent distinct resume installed the prepared version and both plists, then observed provider READY at 13:25:49 and a running bridge at 13:25:53. The original failed attempt and successful resume are both retained in [deployment/deployment-events.jsonl](deployment/deployment-events.jsonl). There was a service interruption; the receipt does not claim zero downtime.

## Qualification boundary

Main macOS and independent pocket4 Linux each passed all 9 new regression tests and all 156 original checks before this switch. Passive observation after the switch binds the bridge SSH child and remote READY to the same current transport generation. READY continues to mean transport readiness only. The approved model remains unavailable because of the original account quota; the fixed 19-case live task qualification has not been rerun or marked passed.

The original README and source MANIFEST describe the earlier, immutable code-verification snapshot. This later deployment packet records the host change without rewriting those historical results, frozen v149 sources, old receipts, or failures. Broad repository G1 checks on the source candidate exposed broker generated-artifact drift and an existing Rust formatting difference; those failures remain visible while being repaired.
