# v36 build and phone validation continuation

This directory records the state at the HeptaRuntime tunnel interruption on 2026-11-10. The application source that actually passed the build is commit `1af05baf1e5313a0f5f7eb65107fb3bee305d65b`. Later documentation, retained receipts and prepared validation scripts do not change that provenance or represent another build.

## Assembly is unresolved

- Host: `pocket4`.
- Existing request idempotency key: `razr-background-v36-assembly-bff66-r2-01`.
- Runner: `build-runners/v36_assembly.py`, SHA-256 `872f1189057ab71cd440094359ce335f89eeb3cedea2774ca73cd9b475d1df2d`.
- Remote root: `/home/alex/razr-background-bff66-20261110/v36-r2`.
- Expected execution report: `assembly-r1/RESULT.json` under that root.
- Expected APK, only if the report and independent static checks pass: `out/hepta-local-0.36.0.apk` under that root.

The first `h_pty_start` call timed out. Reconciliation of the same request could not reach the connector because it returned `tunnel_client_not_connected`. Do not start a second assembly with a new key or infer success/absence from the timeout. First restore the existing tunnel, reconcile the original request, and inspect the report and actual signed APK. The source runner has no ADB or installation operation.

The exact existing request is retained in the session checkpoint. If that checkpoint is unavailable, inspect the original request/session and remote report before reconstructing any execution. Do not manufacture a new successful receipt from these summary files.

## Source and completed host receipts

`source-inventory.json` records the exact 434-file source subset used by the build. Its SHA-256 is `0c0a493f424168860535f4585585633af2556f7b56a91ac10b88319df2de3f7b`.

`build-receipts/` preserves the exact bytes of the read-back Pocket4 and Mac stage receipts and client/broker reports. The original remote directories also retain compiler/host stdout, stderr, input inventories and generated outputs. These reports cover host execution and Android compilation only. The 45 client cases and 43 protocol cases are included within the 87 host check records; these counts are at different levels and must not be added as independent suites.

The compiled six-member archive was transferred from Mac to Pocket4 with verified length 355230 bytes and SHA-256 `e2786c8059157fd3232a0508abc7fa83f008a9b94562e72e7e15c7d94b1cec2c`. This archive is compiler output, not a signed or installed APK.

## Prepared phone validation

`phone-tests/r2/` preserves the frozen acceptance driver, README, pure parser fixtures and preparation receipt. The README describes the original workspace layout; its parent-relative references to retained r1 and private audit evidence are historical locations, not claims that those artifacts are included here. Do not substitute r1 for r2. The driver entry has not run.

For a future run, provide the exact helper in `phone-tests/helpers/v35_identity.py` and the unchanged `tools/phone_acceptance.py`, `tools/warm_receipts.py`, and `tools/model_profiles.py` from the built controller source. The identity helper retains its original v35 build-verification functions; the prepared v36 driver uses its reviewed operation-lock and ADB functions, not its v35 APK identity constants as v36 identity. The driver checks the supplied actual candidate APK SHA independently. Its four helper pins are not to be loosened.

The latest phone read still showed another live cooperative lock owner and a scope-state discrepancy. Reconcile the current owner, scope, model/session idle state and formal Accessibility binding, and use the existing owner's normal handoff/close path. Do not delete, replace or steal the shared lock, re-run an already reserved scope removal, or overwrite old failed results.

After the candidate is actually installed and its identity checked, run the ordinary UI-started local-model background calculator test, then the failure/cleanup cases, model comparison and business tasks described in RESULTS.md. A prepared candidate runtime configuration is not an activated phone configuration.
