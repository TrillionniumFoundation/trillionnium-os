## Fixed GenieX CI transport

Runs [42565206107](https://github.com/TrillionniumFoundation/trillionnium-os/actions/runs/42565206107) and [42569728212](https://github.com/TrillionniumFoundation/trillionnium-os/actions/runs/42569728212) passed the original 46 host gates and fresh MNN producer, then failed with HTTP 504 at the official GenieX download. Both failures remain evidence.

This adapter makes at most two attempts against the original official release URL and then at most two against fixed official asset API 683271197. The original archive size, SHA256, and libgeniex.so SHA256 stay fixed. No mirror, latest-version lookup, or authorization-token forwarding is used. An archive size/digest mismatch, unexpected response host, or TLS certificate failure stops without fallback.

The exact frozen fetch module is checked by SHA256 and executed from those verified bytes. Only its isolated network-response dependency is replaced with an already verified temporary stream. Its original URL, constants, create-only destination, bounded tar extraction, independent archive verification, and core-library check execute unchanged. Temporary storage is bounded by the fixed 98,545,327-byte archive size plus one rejection byte. No on-disk application source is changed.

A separate create-only receipt records every real attempt and final result. CI preserves it with the original dependency receipt. The helper checks its own four-file closure before network access. The network-free regression suite covers retry/fallback, exhausted transport, integrity and TLS failures, unexpected URLs, changed source, and original-delegate handoff. Fixture tests do not prove an external download works; the full workflow provides that evidence.

At introduction the unchanged app-source manifest is 3f7602f4c9ff73adfaabfdcf93496c043c10b59e6b5b75304bc13c473d3a2074. No phone is contacted, no model is downloaded, and the MNN source-head/run/attempt/payload bindings stay intact.
