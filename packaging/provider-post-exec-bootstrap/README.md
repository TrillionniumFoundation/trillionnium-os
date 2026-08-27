# Codex provider post-exec bootstrap

This package builds and verifies one exact-source AArch64 Codex payload for the
Trillionnium OS agent control plane. The provider registry is a closed
singleton: codex. Unknown provider names fail before download, container
launch, source preparation, receipt verification or reconciliation.

The output is deliberately non-authorizing. Builder and reproducibility
receipts keep product_active, listener_backend_wired, admission_wired and
confers_effect_authority fixed to false. Product admission remains a separate
fail-closed boundary.

## Frozen inputs

provider-payload-recipe-v1.json pins:

- the Codex source tag, commit and source-tree identities;
- the exact Cargo lock transformation and complete vendored dependency set;
- the pinned Rust, Zig and multi-architecture container base identities;
- the AArch64 musl target, controlled entry object and freestanding bootstrap;
- the prebuilt rusty_v8 artifacts and their measured checksum contract; and
- two independent builder profiles, amd64-cross and arm64-native.

The deterministic build context contains only the builder, recipe,
Containerfile, public bootstrap header, freestanding core and controlled-entry
assembly source.

## Commands

    python3 build_provider_payload.py verify-recipe
    python3 build_provider_payload.py plan \
      --provider codex \
      --builder-profile amd64-cross
    python3 build_provider_payload.py build \
      --provider codex \
      --builder-profile amd64-cross \
      --output-dir /absolute/output/codex-amd64 \
      --cache-dir /absolute/cache
    python3 build_provider_payload.py reconcile \
      --builder-output /absolute/output/codex-amd64 \
      --builder-output /absolute/output/codex-arm64 \
      --output-dir /absolute/output/codex-reconciled

Public commands expose no binary, source-tree, compiler, sysroot, flag or
environment override. Container execution is digest-pinned, network-isolated,
uses a read-only cache, and is supervised through retained descriptors and a
one-shot cgroup lifecycle.

## Verification boundary

The verifier reopens artifacts beneath a fixed root, rejects aliases and
mutable path substitution, checks the retained source/dependency closure,
re-inspects the final ELF and requires byte-equal results from both builder
profiles. The final payload must be an unstripped static AArch64 ET_EXEC with
the controlled entry, exact bootstrap/filter binding, no interpreter or dynamic
segment, no writable-executable load and no executable stack.

Run the local regression suite with:

    python3 tests/test_build_provider_payload.py
    python3 tests/test_provider_build_supervisor.py
