# Code16 same-version phone model comparison

Both retained runs used APK SHA256
`6f8cfa51abbb388a010ed1c222fd230de94956390dd3fef8870320acd4afbae3`,
versionCode 16, the original nine task cases, core driver and strict assertions.
Both configurations selected Hexagon NPU, 4096 context and four CPU helper
threads. The original failed verdicts remain unchanged.

| Configuration | Strict result | Native calls | Complete native/App calls | Positive HTP calls |
|---|---:|---:|---:|---:|
| Nemotron 3.5 Bolt E4B Q4_K_M | 6 pass / 3 fail | 58 | 57 | 58 |
| Gemma 4 E4B QAT Q4_0 | 7 pass / 2 fail | 64 | 62 | 63 |

The remaining calls were cancelled at task termination, not silently removed
or filled with zero timing. Gemma's recorded layer-count set includes 0 and
43; this table preserves its actual 63 positive offload calls. Positive HTP
offload does not prove that every operator ran on the NPU or establish
hardware utilization.

## Retained original summaries

- [Bolt](BOLT-SANITIZED-SUMMARY.json), 13,986 bytes, SHA256
  `c9dc4ae6656dc2b47bd122b4188f8a14b76668c7637d68b04c06540825bf3622`.
- [Gemma](GEMMA-SANITIZED-SUMMARY.json), 10,233 bytes, SHA256
  `d02e9521b37ea4ecff673893a6ed62036cee05dc3f865fde6646442bb620f236`.

Both files are byte-for-byte copies of their already sanitized independent
statistics. Their input/statistics digests bind the retained private originals;
neighboring raw statistics, complete input manifests and phone traces are
not exported.

The two runs had different initial screen/thermal states and generated
actions. The result supports a bounded practical comparison for this APK
and these nine tasks, not a general model ranking. The Gemma run did not
have an independently bound thermal monitor; no Bolt temperatures are
borrowed for it. Bolt's resource sampling began during the third case,
so its temperatures and available-memory range do not cover the first two.

Both offline wrappers completed with verified restoration. Network snapshots
are not packet capture. These private test-request runs do not qualify the
ordinary Start button, independent Stop/restart behavior, screen-off/locked
operation, visual reasoning or every installed application.
