#!/usr/bin/env bash
set -euo pipefail

PROVENANCE_BASE_SHA="3fae18209e3b4627fab28141b0ed1e3354e6d570"
TARGET_BASE_SHA="b681cd856fccac1189496576f25d259752d2dcce"
TARGET_BASE_TREE="f96f88a9749c61b3ce0dde7167303c8261788f22"
CANDIDATE_BRANCH="codex/executable-module-contracts-v3-main-20260910"
CARRIER_B64_BYTES="20968"
CARRIER_B64_SHA256="7ad6edd6696b7ebc2047952d6723426eaab4357a2d9ed304220e61db1d3bfcf9"
CARRIER_XZ_SHA256="96dbc9a46bb632915f4c80d0588c443d60f771d80a9f77e4ac3e54a2030eb88f"
CARRIER_TAR_SHA256="c3d175853a44194beeb1a4739f036f8e05fff48965d0b38f4ac6bd131149e28f"
CARRIER_MANIFEST_SHA256="19d5d89864d2ff0fdbfec825dae588ed032392bc2f0befaa7bd5b525b920c689"

export PROVENANCE_BASE_SHA TARGET_BASE_SHA TARGET_BASE_TREE CANDIDATE_BRANCH
export CARRIER_B64_BYTES CARRIER_B64_SHA256 CARRIER_XZ_SHA256 CARRIER_TAR_SHA256
export CARRIER_MANIFEST_SHA256 PYTHONDONTWRITEBYTECODE=1 CARGO_TERM_COLOR=always

controller_root="$(pwd -P)"
test "$(git --no-replace-objects rev-parse HEAD)" = "${GITHUB_SHA:?}"
git --no-replace-objects merge-base --is-ancestor "$PROVENANCE_BASE_SHA" HEAD

observed="$(git --no-replace-objects diff --name-only "$PROVENANCE_BASE_SHA"...HEAD | LC_ALL=C sort)"
expected="$(printf '%s\n' \
  '.github/workflows/tmp-module-contracts-v3-carrier-diagnostic.yml' \
  '.github/workflows/tmp-module-contracts-v3-main-preflight-v2.yml' \
  '.github/workflows/tmp-module-contracts-v3-main-preflight-v3.yml' \
  '.github/workflows/tmp-module-contracts-v3-preflight.yml' \
  '.github/workflows/tmp-module-contracts-v3-template-inspect.yml' \
  'ops/module-contracts-v3-main-preflight-v3.sh' \
  'ops/module-contracts-v3-source.tar.xz.b64.00' \
  'ops/module-contracts-v3-source.tar.xz.b64.01' \
  'ops/module-contracts-v3-source.tar.xz.b64.02' \
  'ops/module-contracts-v3-source.tar.xz.b64.03' | LC_ALL=C sort)"
test "$observed" = "$expected"

for pair in 00:10000 01:5500 02:5500 03:4468; do
  suffix="${pair%%:*}"
  expected_bytes="${pair##*:}"
  path="ops/module-contracts-v3-source.tar.xz.b64.${suffix}"
  test -f "$path"
  test ! -L "$path"
  test "$(wc -c < "$path" | tr -d ' ')" = "$expected_bytes"
done

if git ls-remote --exit-code --heads origin "refs/heads/${CANDIDATE_BRANCH}" >/dev/null 2>&1; then
  echo "candidate branch already exists; absence lease refused" >&2
  exit 1
fi

bundle_root="${RUNNER_TEMP:?}/module-contracts-v3-source"
carrier_b64="${RUNNER_TEMP:?}/module-contracts-v3-source.tar.xz.b64"
carrier_xz="${RUNNER_TEMP:?}/module-contracts-v3-source.tar.xz"
carrier_tar="${RUNNER_TEMP:?}/module-contracts-v3-source.tar"
mkdir -m 0700 "$bundle_root"
head -c 5500 -- ops/module-contracts-v3-source.tar.xz.b64.00 > "$carrier_b64"
cat -- \
  ops/module-contracts-v3-source.tar.xz.b64.01 \
  ops/module-contracts-v3-source.tar.xz.b64.02 \
  ops/module-contracts-v3-source.tar.xz.b64.03 >> "$carrier_b64"
test "$(wc -c < "$carrier_b64" | tr -d ' ')" = "$CARRIER_B64_BYTES"
printf '%s  %s\n' "$CARRIER_B64_SHA256" "$carrier_b64" | sha256sum --check --strict

python3 - "$carrier_b64" "$carrier_xz" <<'PY'
from pathlib import Path
import base64
import binascii
import sys

source, target = map(Path, sys.argv[1:])
raw = source.read_bytes()
if any(byte in b" \t\r\n" for byte in raw):
    raise SystemExit("carrier contains whitespace")
try:
    decoded = base64.b64decode(raw, validate=True)
except binascii.Error as exc:
    raise SystemExit(f"invalid base64 carrier: {exc}") from exc
target.write_bytes(decoded)
PY

printf '%s  %s\n' "$CARRIER_XZ_SHA256" "$carrier_xz" | sha256sum --check --strict
xz --test -- "$carrier_xz"
xz --decompress --stdout -- "$carrier_xz" > "$carrier_tar"
printf '%s  %s\n' "$CARRIER_TAR_SHA256" "$carrier_tar" | sha256sum --check --strict

python3 - "$carrier_tar" "$bundle_root" <<'PY'
from pathlib import Path, PurePosixPath
import hashlib
import json
import os
import sys
import tarfile

archive, destination = map(Path, sys.argv[1:])
with tarfile.open(archive, mode="r:") as tar:
    members = tar.getmembers()
    names = [member.name for member in members]
    expected = ["MANIFEST.json", "generator.py", "test_module_contracts.py"]
    if names != expected or len(names) != len(set(names)):
        raise SystemExit(f"controller bundle inventory differs: {names!r}")
    for member in members:
        pure = PurePosixPath(member.name)
        if pure.is_absolute() or member.name != pure.as_posix() or "." in pure.parts or ".." in pure.parts:
            raise SystemExit(f"unsafe controller member: {member.name}")
        if not member.isfile() or member.issym() or member.islnk():
            raise SystemExit(f"unsupported controller member: {member.name}")

    manifest_raw = tar.extractfile("MANIFEST.json").read()
    if hashlib.sha256(manifest_raw).hexdigest() != os.environ["CARRIER_MANIFEST_SHA256"]:
        raise SystemExit("controller manifest digest differs")
    manifest = json.loads(manifest_raw)
    if manifest.get("schema") != "org.trillionnium.module-contract-v3-controller-bundle.v1":
        raise SystemExit("controller schema differs")
    if manifest.get("base_commit") != os.environ["PROVENANCE_BASE_SHA"]:
        raise SystemExit("controller provenance base differs")
    if manifest.get("automatic_redispatch") is not False:
        raise SystemExit("automatic redispatch ceiling differs")
    if manifest.get("public_release") is not False:
        raise SystemExit("public-release ceiling differs")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) != 2:
        raise SystemExit("controller entries differ")
    for entry in entries:
        name = entry["path"]
        if name not in {"generator.py", "test_module_contracts.py"}:
            raise SystemExit(f"unexpected controller source: {name}")
        raw = tar.extractfile(name).read()
        if len(raw) != entry["bytes"] or hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise SystemExit(f"controller source identity differs: {name}")
        target = destination / name
        target.write_bytes(raw)
        os.chmod(target, int(entry["mode"], 8))
PY

test -x "$bundle_root/generator.py"
test -r "$bundle_root/test_module_contracts.py"
test "$(git --no-replace-objects rev-parse "$TARGET_BASE_SHA^{tree}")" = "$TARGET_BASE_TREE"

worktree="${RUNNER_TEMP:?}/module-contracts-v3-worktree"
git worktree add --detach "$worktree" "$TARGET_BASE_SHA"
test "$(git -C "$worktree" --no-replace-objects rev-parse HEAD)" = "$TARGET_BASE_SHA"
test "$(git -C "$worktree" --no-replace-objects rev-parse HEAD^{tree})" = "$TARGET_BASE_TREE"
test -z "$(git -C "$worktree" status --porcelain=v1 --untracked-files=all --ignore-submodules=none)"

cd "$worktree"
mkdir -p tools/tests
cp "$bundle_root/test_module_contracts.py" tools/tests/test_module_contracts.py
chmod 0644 tools/tests/test_module_contracts.py
python3 "$bundle_root/generator.py" --root "$PWD" --prepare --install

python3 - tools/contracts/generate_module_contracts.py <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
replacements = [
    (
        '    println!("{}", serde_json::to_string(&value).expect("serialize schemars bundle"));\n',
        '    println!(\n'
        '        "{}",\n'
        '        serde_json::to_string(&value).expect("serialize schemars bundle")\n'
        '    );\n',
    ),
    (
        'use super::{decode_strict_value, MechanicalLimits, ProtocolError};\n',
        'use super::{MechanicalLimits, ProtocolError, decode_strict_value};\n',
    ),
    (
        '            return Err(invalid("module contract ordering or fencing identity is invalid"));\n',
        '            return Err(invalid(\n'
        '                "module contract ordering or fencing identity is invalid",\n'
        '            ));\n',
    ),
    (
        'use serde_json::{json, Value};\n',
        'use serde_json::{Value, json};\n',
    ),
    (
        'use trillionnium_owner_open_types::module_contract::{\n'
        '    parse_module_api, parse_module_error, parse_module_state, ModuleApiEnvelopeV1,\n'
        '    ModuleErrorEnvelopeV1, ModuleStateEnvelopeV1,\n'
        '};\n',
        'use trillionnium_owner_open_types::module_contract::{\n'
        '    ModuleApiEnvelopeV1, ModuleErrorEnvelopeV1, ModuleStateEnvelopeV1, parse_module_api,\n'
        '    parse_module_error, parse_module_state,\n'
        '};\n',
    ),
    (
        '    let expected = read_json(\n'
        '        &repository_root().join("schemas/modules/_shared/envelopes-v1.schemars.json"),\n'
        '    );\n',
        '    let expected =\n'
        '        read_json(&repository_root().join("schemas/modules/_shared/envelopes-v1.schemars.json"));\n',
    ),
    (
        '        if !directory.is_dir() || directory.file_name().and_then(|v| v.to_str()) == Some("_shared") {\n',
        '        if !directory.is_dir() || directory.file_name().and_then(|v| v.to_str()) == Some("_shared")\n'
        '        {\n',
    ),
    (
        '            let name = path.file_name().and_then(|value| value.to_str()).expect("name");\n',
        '            let name = path\n'
        '                .file_name()\n'
        '                .and_then(|value| value.to_str())\n'
        '                .expect("name");\n',
    ),
]
for index, (old, new) in enumerate(replacements, start=1):
    if text.count(new) == 1 and text.count(old) == 0:
        continue
    if text.count(old) != 1 or text.count(new) != 0:
        raise SystemExit(f"template repair anchor {index} differs")
    text = text.replace(old, new, 1)
path.write_text(text, encoding="utf-8")
print(f"template_repairs={len(replacements)}")
PY

cargo fmt --all
cargo fmt --all -- --check
cargo generate-lockfile
cargo fetch --locked
schemars="${RUNNER_TEMP:?}/module-contract-schemars.json"
cargo run --locked --quiet -p trillionnium-owner-open-types \
  --bin generate_module_contract_schemas > "$schemars"
test -s "$schemars"

python3 tools/contracts/generate_module_contracts.py --write --schemars-file "$schemars"
python3 tools/contracts/generate_module_contracts.py --check
python3 tools/contracts/generate_module_contracts.py --verify
python3 tools/contracts/check_module_contract_compatibility.py --base-ref "$TARGET_BASE_SHA"
python3 android-integration/module-contracts/verify_vectors.py
python3 -m unittest tools.tests.test_module_contracts -v
cargo fmt --all -- --check
cargo test --locked -p trillionnium-owner-open-types --all-targets
cargo clippy --locked -p trillionnium-owner-open-types --all-targets -- -D warnings
python3 tools/docs/generate_global_docs.py
python3 tools/docs/generate_global_docs.py --check
python3 tools/docs/verify_global_docs.py
python3 tools/docs/verify_repository_authority.py
git diff --check

git config user.name 'Qian QI'
git config user.email '102159240+ProfHepta@users.noreply.github.com'
git add -A
test -n "$(git diff --cached --name-only)"
test -z "$(git diff --cached --name-only | grep -E '^(ops/|\.github/workflows/tmp-)' || true)"
git diff --cached --check
git commit -m 'feat(contracts): generate executable module API state and error contracts' \
  -m 'Resolve all 16 module labels to Rust-schemars-derived JSON Schema, byte-locked compatibility metadata, and shared Python/Rust/Android valid and hostile vectors. Preserve no-default, no-alias, no-automatic-redispatch and L1-only claim boundaries.'
test "$(git --no-replace-objects rev-parse HEAD^)" = "$TARGET_BASE_SHA"
test -z "$(git status --porcelain=v1 --untracked-files=all --ignore-submodules=none)"

python3 tools/contracts/generate_module_contracts.py --check
python3 tools/contracts/generate_module_contracts.py --verify
python3 tools/contracts/check_module_contract_compatibility.py --base-ref "$TARGET_BASE_SHA"
python3 tools/docs/generate_global_docs.py --check
python3 tools/docs/verify_global_docs.py
python3 tools/docs/verify_repository_authority.py
python3 -m unittest discover -s tools/tests -p 'test*.py' -v
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --manifest-path planned/Cargo.toml --all -- --check
cargo test --locked --manifest-path planned/Cargo.toml --workspace --all-targets
cargo clippy --locked --manifest-path planned/Cargo.toml --workspace --all-targets -- -D warnings
test -z "$(git status --porcelain=v1 --untracked-files=all --ignore-submodules=none)"

final="$(git --no-replace-objects rev-parse HEAD)"
tree="$(git --no-replace-objects rev-parse HEAD^{tree})"
test "$(git --no-replace-objects rev-parse HEAD^)" = "$TARGET_BASE_SHA"
git push --force-with-lease="refs/heads/${CANDIDATE_BRANCH}:" \
  origin "HEAD:refs/heads/${CANDIDATE_BRANCH}"

receipt="${RUNNER_TEMP:?}/module-contract-v3-candidate.env"
{
  printf 'candidate_head=%s\n' "$final"
  printf 'candidate_tree=%s\n' "$tree"
  printf 'target_base_head=%s\n' "$TARGET_BASE_SHA"
  printf 'target_base_tree=%s\n' "$TARGET_BASE_TREE"
  printf 'controller_head=%s\n' "$GITHUB_SHA"
  printf 'carrier_b64_sha256=%s\n' "$CARRIER_B64_SHA256"
  printf 'carrier_xz_sha256=%s\n' "$CARRIER_XZ_SHA256"
  printf 'carrier_tar_sha256=%s\n' "$CARRIER_TAR_SHA256"
  printf 'module_count=16\n'
  printf 'android_valid_vectors=48\n'
  printf 'android_invalid_vectors=224\n'
  printf 'shared_contract_tests=8\n'
  printf 'automatic_redispatch=false\n'
  printf 'public_release=false\n'
} | tee "$receipt"

cd "$controller_root"
