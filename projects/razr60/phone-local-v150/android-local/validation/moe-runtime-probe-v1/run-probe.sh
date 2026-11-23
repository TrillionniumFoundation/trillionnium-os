#!/system/bin/sh
# Only launches this probe. It does not install, start activities, or issue input.
set -eu
if [ "$#" -lt 1 ]; then
  echo "usage: sh run-probe.sh /absolute/runtime/lib [probe arguments]" >&2
  exit 64
fi
probe_runtime=$1
shift
case "$probe_runtime" in /*) ;; *) echo "runtime path must be absolute" >&2; exit 64;; esac
probe_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
unset LD_PRELOAD LD_AUDIT
LD_LIBRARY_PATH="$probe_runtime:$probe_runtime/llama_cpp"
export LD_LIBRARY_PATH
exec "$probe_root/bin/moe-runtime-probe-android-arm64" --runtime-lib-dir "$probe_runtime" "$@"
