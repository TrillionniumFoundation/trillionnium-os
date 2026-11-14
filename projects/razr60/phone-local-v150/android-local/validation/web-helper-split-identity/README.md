# Web-helper split APK identity regression

Base commit: `7dee83d838b2c76b3abe3a3e61d7837316f40853`.
Production file: `lfm3-controller/src/org/trillionnium/hepta/local/WebHelperIdentity.java`.
The baseline Git blob is `698dabac7acb63006a338c3bd25bd278fb96e0c8`.

`paths()` already treats null and empty arrays as equivalent missing split
metadata. Its later `if (splits != null)` nevertheless enters the nonempty
validation for `splitSourceDirs=[] / splitNames=null` and rejects that valid
base-only representation. The production patch adds only `splits.length > 0`
to that later branch. Nonempty identity checks remain intact.

## Actual regression results

The runner extracts and compiles the complete production `paths()` method.
Explicit `ApplicationInfo` field and assertion stubs stand in for Android IO;
the acceptance/mapping logic comes verbatim from the actual supplied source.

Pocket4's existing complete JDK17 ran both versions with
`--release 8 -encoding UTF-8 -Xlint:all -Werror`. Durable host job
`1a1ce450177-2564-15e2` completed with exit 0 and complete persisted logs.
Both Java compilations returned 0. The unmodified source failed only the
`no_splits_empty_null` case (24/25); the patched source passed 25/25.
`STRICT-RESULT.json` preserves the actual pair report from that job's stdout;
the two case logs match the actual remote output hashes below.

| Original case output | SHA256 |
| --- | --- |
| `baseline-cases.stdout` | `bb204b4408820baa0d2dd16b25888f25b59e1a86879730bbb3028162d67d220c` |
| `candidate-cases.stdout` | `0ec5fd3caeec02381390dd38a3b164a2e7294147764edc32499eb29c458a5400` |

Coverage includes all four null/empty combinations, exact one/32-split mappings,
name/order preservation, the 120-character accepted name boundary, missing base,
one-sided metadata, unequal lengths, 33 splits, null paths/names, empty/invalid
names, the 121-character rejected boundary, and duplicate names. Empty string
path handling retains the existing later filesystem-validation responsibility.

Run from the repository root using an existing complete JDK:

```sh
python3 -B projects/razr60/phone-local-v150/android-local/validation/web-helper-split-identity/run_regression.py \
  --source projects/razr60/phone-local-v150/android-local/lfm3-controller/src/org/trillionnium/hepta/local/WebHelperIdentity.java \
  --output /absolute/new/host-evidence \
  --java /existing/jdk17/bin/java --javac /existing/jdk17/bin/javac
```

For the negative control, provide the exact baseline file through `--source` and
a different new output directory; exit 1 and the single recorded failure are
expected. The stripped container JDK's actual release8 refusal and separately
labeled supplemental source/target8 runs are local diagnostics; the passing
strict result above comes from the complete host JDK17.

## Integration boundary

The patch has no phone/ADB execution, Android compilation, APK signing or
installation evidence, and does not establish that the phone ever supplied this
metadata combination. It leaves business completion, tool scope and runtime
selection unchanged. Existing v53 APK results belong to their original bytes.

The inherited `SOURCE-MANIFEST.json` at the exact baseline contains historical
code30 metadata and omits this pre-existing Web helper source. This narrowly
scoped patch preserves that inherited inventory; complete source closure must
be regenerated from the actual full integration tree before a new build can be
qualified. The 25-case regression is not full source-closure qualification.
