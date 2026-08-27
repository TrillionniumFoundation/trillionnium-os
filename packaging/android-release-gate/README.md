# Android release/flash preflight

`verify_android_release.py` is a source-only, read-only preflight for an
Android `target_files` ZIP.  It does not build, sign, install, flash, invoke
ADB/fastboot, or open private-key material.  It returns exit status `0` only
when all of the following are true:

* every discovered Android build type is `user` and every build tag set is
  exactly `release-keys` (userdebug/eng/test-keys/dev-keys are held);
* `META/otakeys.txt` exists and is non-empty;
* the target is an A/B AVB product with an explicit rollback index on every
  AVB footer argument, and a detached rollback-evidence JSON covers exactly
  that index set and asserts hardware anti-rollback proof; and
* a detached signed-metadata JSON is explicitly marked `signed`, binds the
  exact target-files SHA-256, identifies a `user`/`release-keys` build, and
  carries a non-empty signature and signing key id.

The detached documents are public attestations.  The verifier checks their
shape and digest binding; it does not possess a private key and does not claim
to replace cryptographic signature verification or device-side locked/green
and rollback checks.  Evidence and target paths are opened read-only with
`O_NOFOLLOW` on every path component; symlinked parent directories are held.
`ELIGIBLE` therefore means “eligible for the next release preflight step”,
never “flash now”.

Example evidence shapes:

```json
{
  "schema": "org.trillionnium.android-release-signed-metadata.v1",
  "target_files_sha256": "<64 hex characters>",
  "signed": true,
  "build_type": "user",
  "build_tags": ["release-keys"],
  "signing_key_id": "release-key-2026",
  "signature": {"algorithm": "external-attestation", "value": "<signature>"}
}
```

```json
{
  "schema": "org.trillionnium.android-rollback-evidence.v1",
  "target_files_sha256": "<same 64 hex characters>",
  "hardware_antirollback_proven": true,
  "evidence_id": "device-attestation-2026-08-22",
  "indices": {
    "vbmeta": {"rollback_index": 29, "rollback_index_location": 0},
    "vbmeta_system": {"rollback_index": 29, "rollback_index_location": 2}
  }
}
```

Run it with:

```text
python3 verify_android_release.py TARGET_FILES.zip \
  --signed-metadata signed-metadata.json \
  --rollback-evidence rollback-evidence.json
```

The current v28 `target_files` output is intentionally held: it is
`userdebug/test-keys`, has an empty `META/otakeys.txt`, and has no detached
rollback or signed-release metadata.

## Source-BOM binding (strict target-files gate)

`verify_source_bom_binding.py` defines the additive provenance member that the
target-files builder may embed as
`META/trillionnium-source-bom-binding.json`.  The closed v1 shape carries the
source-BOM receipt id and digest, source-set and resolved-manifest digests,
and the receipt-stage identity.  Its `binding_id` is a SHA-256 content
identifier over the canonical JSON preimage (with `binding_id` omitted); it is
not a signing key, release authorization, or device attestation.  The binding
does not contain a target-files digest, avoiding a circular self-reference;
the later OTA/release receipt binds the target-files and OTA bytes.

Existing target-files fixtures remain compatible because member absence is
optional by default.  A future gate can opt in without changing the default
`verify_android_bom_preflight.py` behavior:

```python
from verify_source_bom_binding import validate_target_files_source_bom_binding

report = validate_target_files_source_bom_binding(
    target_files,
    require_binding=True,
    expected_bom_bytes=source_bom_bytes,
)
if not report["valid"]:
    raise RuntimeError(report["holds"])
```

The existing preflight CLI exposes the same opt-in without changing its
default behavior.  The host OTA planner exposes the same two flags and checks
the binding before signing/tool inventory work:

```text
python3 verify_android_bom_preflight.py --bom source-bom.json \
  --target-files target-files.zip \
  --require-source-bom-binding \
  --source-bom-binding-bom source-bom.json
```

```text
python3 ../../tools/android_release_ota.py --android-root /path/to/android \
  --target-files target-files.zip \
  --require-source-bom-binding \
  --source-bom-binding-bom source-bom.json --dry-run
```

The host-only producer for this member is
`tools/materialize_android_source_bom_binding.py`.  It requires a PASS source
BOM and the exact source-set, resolved-manifest, and receipt-stage bytes; it
rejects stale/mismatched inputs and publishes a new binding file only.  For
example:

```text
python3 tools/materialize_android_source_bom_binding.py \
  --source-bom OUT/.../evidence/source-bom.v2.json \
  --source-set tools/p0-cross-repo-source-set.v2.json \
  --resolved-manifest OUT/.../evidence/resolved-manifest.xml \
  --receipt-stage OUT/.../receipt-stage.v1.json \
  --output OUT/.../trillionnium-source-bom-binding.json
```

The Android `build/make` target-files recipe consumes that output only when
`TRILLINNIUM_SOURCE_BOM_BINDING_JSON` is explicitly set; the empty default is
unchanged.  Both the producer and validator are read-only with respect to
source inputs and do not install, sign, invoke ADB/fastboot, or write a device.
A fresh exact-clean target-files build is still required; these changes do not
claim freshness completion by themselves.  The active OUT currently remains
held because its target-files archive is an older userdebug/test-keys artifact
without the binding member.
