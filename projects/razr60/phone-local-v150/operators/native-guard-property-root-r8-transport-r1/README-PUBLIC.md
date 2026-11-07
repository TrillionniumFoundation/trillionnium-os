# R8 transport repair: explicit public source projection

This directory contains a review-only public projection of an r8 host coordinator and its transport repair. The source is not an installable package. It requires private bindings that are deliberately absent, and the original seven `None` execution guards remain unchanged.

## Source identities

| Source | Full original source SHA-256 | Public projection SHA-256 |
| --- | --- | --- |
| Baseline | `5263e9a19c8f6d2f7a60d560db7cce3a1c234ca79c77c04c3465323bc0bd9ca2` | `3eacd09518e4a729bab879fa63dff327a6e3e192d89722dc27d955333c7cce8d` |
| Transport candidate | `033b8351450946392fdfb0cea14775af726eb4d1dfb2e70a0f8b54fd44ddbb27` | `88a37c17ceda4664e1d8a1b6d5f14351526cd8288ceed7bc00b863084ef095da` |

Only these whole-source original identities are retained from the private source mapping. The published seal is a new public projection seal; it is not the private source manifest, policy manifest, adoption record, or deployment identity.

`PROJECTION-RULES.PUBLIC.json` describes one identical set of explicit substitutions applied to both sources. Required placeholders replace the private workspace, device runtime paths and execution environment, SSH hosts, boot identity, remote workspaces, retained predecessor namespace and byte-size bindings, history labels, and all 13 embedded digest bindings. The removed values and their digests are not included in the rules. No hardcoded process instance was found in the pinned source; process identifiers in the code are read at runtime, and no process records are published here.

`TRANSPORT.PUBLIC.patch` is generated from the two public sources. The original private review patch is excluded. The projection builder checked that the helpers, process method, cleanup method and actual sender join segment used by the host tests have the same AST as the corresponding private source. This is a bounded source-equivalence statement, not a claim that placeholder-bearing orchestration can run on a device.

## Transport behavior

The repair gives the child a retained, checked, read-only regular-file descriptor for stdin, avoiding a blocking parent pipe write before child identity is recorded. It retains the actual child handle before fallible identity persistence, closes each owned parent stream independently, and preserves failure evidence even when CHILD or UNKNOWN persistence fails.

A single monotonic budget runs from immediately before Popen through the actual join, including child input consumption and identity publication. The asynchronous sender joins against that same original deadline. A late observed join fails rather than receiving within-budget credit. File preparation before launch, blocking OS calls, filesystem persistence and cleanup are not represented as preemptible hard realtime operations. Timeout does not authorize a signal, retry or replay, and closing parent file descriptors does not prove that a remote process has stopped.

The asynchronous return remains `(child, directory, stdout, stderr)`. The actual caller and outer failure path retain process ownership and close all parent outputs. A successful host exit is only a transport observation; it does not prove business success or absence of Android effects.

## Public host tests

`HOST-TEST-SUMMARY.PUBLIC.json` records one Linux run against these exact projected sources: **31 candidate regressions passed, plus 2 checks confirming the original baseline defects; 33 checks total, zero failures**. The fixture inputs are synthetic. No phone, SSH, API, deployment, native history, model, key or policy binary is used by these tests. The test children are short local processes that exit naturally and are joined; no signals or automatic replay are used.

Coverage includes both original 2 MiB pipe failures, exact input readback, empty and absent stdin, early closure, startup and identity errors, CHILD/UNKNOWN persistence faults, input-content/inode/permission changes, output fsync failures, consumed deadlines and late joins, the asynchronous ABI, the actual sender join segment and outer failure cleanup. The summary intentionally excludes raw process identifiers, effect or native-history records, absolute workspace paths, raw fixture files, and hashes of those excluded records.

The harness SHA-256 is `141a67e624f97ddc2ab911b50efbb6e1090a80176a83adf202f130b956488c6a`. It uses structural AST matching rather than formatted `ast.unparse` text. Descriptor inventory uses `/proc/self/fd` when available, otherwise `/dev/fd`; each listed descriptor is checked with `os.fstat`, transient directory descriptors are excluded, and the existing stream-closure and EBADF assertions remain. A host without either readable inventory interface is rejected before the first child; checks are not silently skipped. The projected source was executed for these tests on Linux.

The summary separately records a pinned original-source crosscheck on macOS with Python 3.9.6 and `/dev/fd`: 31 candidate regressions and 2 baseline defect reproductions, all passing their expected assertions. That observation belongs to original full candidate SHA `033b8351450946392fdfb0cea14775af726eb4d1dfb2e70a0f8b54fd44ddbb27`, not to a macOS execution of these public projections. Only the platform, counts, and four synthetic reproduction timings and booleans are exported. The macOS raw paths, process records and raw-result digest are excluded. Neither host result receives phone, business or fixed-19 acceptance credit.

From this directory, with Python 3.9 or later:

```sh
python3 -I -B ./test_transport_public.py
```

Inputs resolve relative to the test script. By default the generated raw fixtures and local raw result stay in a unique directory under the OS temporary directory. Set `RAZR_TRANSPORT_TEST_OUTPUT` to a new, nonexistent local directory if a specific destination is required. Those generated files are not part of this publish set and must not be added to a publication. No orchestration `main` or device-facing entry point is executed by the test harness.

## Publication boundary

The source boundary is the repository's `PUBLIC-SOURCE-BOUNDARY.md`. `SOURCE-SEAL.PUBLIC.json` pins this projection and the compact public test summary. `PUBLISH-ALLOWLIST.PUBLIC.json` is the exact file allowlist and intended repository mapping. The seal preserves missing-binding refusal; it does not transfer any physical-device acceptance credit, fixed-19 result, business qualification, policy adoption, daily-use qualification or release readiness to this source.

Private requests, fresh nonces, draft contents and their digests, actual claims, native histories, keys or key-content digests, private runtime bindings, model weights, binaries, full SELinux policies, deployment archives, raw test results and repeated fixture inputs are excluded. This directory contains no installer or activation script.
